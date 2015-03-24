#!/usr/bin/env python
#-*-coding:utf-8 -*-
import os
import sys
import hashlib
import exported_components

sys.path.append("..")
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.core.bytecodes.api_permissions import DVM_PERMISSIONS_BY_PERMISSION, DVM_PERMISSIONS_BY_ELEMENT

import chilkat
import re

SGN = "^META-INF/(.*)\.(R|D)SA$"
URL = "(.*)://(.*)"
IPADDRESS = "(.*)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}(.*)"


def checkPara():
	'''
	first return value is whether the file exists
	second return value is the full path of the file
	'''
	f = sys.argv[1]
	return (True, f)
	'''
	if len(sys.argv) == 2 or len(sys.argv) == 3:
		f = sys.argv[1]
		if not os.path.exists(f):
			f = os.path.join(os.path.dirname(__file__), f)
			if not os.path.exists(f):
				return (False, 0)
			else:
				return (True, f)
		else:
			return (True, f)
	else:
		return (False, 0)
	'''

def cal_filehash(filepath):
	'''
	calculate the md5 & sha1 of file
	'''
	with open(filepath, 'rb') as f:
		fb = f.read()
		hashSHA1 = hashlib.sha1(fb)
		hashMD5 = hashlib.md5()
		hashMD5.update(fb)
		#hashSHA1.update(f.read())
		return (hashMD5.hexdigest(), hashSHA1.hexdigest())

def cal_filesize(f):
	'''
	calculate the file size
	'''
	size = os.path.getsize(f)
	size = round(size / 1000.0, 2)
	unit = 'KB'
	if size > 1000:
		size = round(size / 1000.0, 2)
		unit = 'MB'
	return str(size) + ' ' + unit




def parse_APK(APKFile):
	'''
	parse apk to a data-structure
	'''
	a = apk.APK(APKFile)
	d = dvm.DalvikVMFormat(a.get_dex())
	dx = analysis.VMAnalysis(d)
	return (a, d, dx)


def basic_information(a, d, dx):
	'''
	package name, mini sdk, max sdk, target sdk, version name, version code
	'''
	package = a.get_package()
	fileName = a.get_filename()
	minSDK = a.get_min_sdk_version()
	maxSDK = a.get_max_sdk_version()
	tarSDK = a.get_target_sdk_version()
	versionname = a.get_androidversion_name()
	versioncode = a.get_androidversion_code()
	libraries = a.get_libraries()

	OutStream.write("===========APK BASIC INFORMATION=============\n")
	OutStream.write("Package name: " + package + '\n')
	OutStream.write("min SDK version: " + str(minSDK) + '\n')
	OutStream.write("max SDK version: " + str(maxSDK) + '\n')
	OutStream.write("target SDK version: " + str(tarSDK) + '\n')
	OutStream.write("version name: " + versionname + '\n')
	OutStream.write("version code: " + versioncode + '\n')
	if len(libraries) > 0:
		OutStream.write("Library:\n")
		for lib in libraries:
			OutStream.write(lib + "\n")





def write_Path(p, cm, wf):
    if isinstance(p, analysis.PathVar):
        wf.write("API: %s;%s %s\n" % (p.get_dst(cm)[0], p.get_dst(cm)[1],p.get_dst(cm)[2]))
    else:
		if not hasattr(p,'get_access_flag'):
			wf.write("------------in: %s%s %s\n" % (p.get_src(cm)[0], p.get_src(cm)[1], p.get_src(cm)[2]))
		else:
			if p.get_access_flag() == analysis.TAINTED_PACKAGE_CALL:
				wf.write("API: %s;%s %s\n" % (p.get_dst(cm)[0], p.get_dst(cm)[1], p.get_dst(cm)[2]))
				wf.write("------------in: %s%s %s\n" % (p.get_src(cm)[0], p.get_src(cm)[1], p.get_src(cm)[2]))
        #else:
		#	pass

def write_Path2(path, cm, wf):
	if isinstance(path, analysis.PathVar):
		dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
		info_var = path.get_var_info()
		wf.write("%s %s (0x%x) ---> %s->%s%s\n" % (path.get_access_flag(),
											  info_var,
											  path.get_idx(),
											  dst_class_name,
											  dst_method_name,
											  dst_descriptor) )
	else :
		if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL :
			src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
			dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

			wf.write("%d %s->%s%s (0x%x) ---> %s->%s%s\n" % (path.get_access_flag(), 
														src_class_name,
														src_method_name,
														src_descriptor,
														path.get_idx(),
														dst_class_name,
														dst_method_name,
														dst_descriptor) )
		else :
			src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
			wf.write("%d %s->%s%s (0x%x)\n" % (path.get_access_flag(), 
										  src_class_name,
										  src_method_name,
										  src_descriptor,
										  path.get_idx()) )


def write_Paths(Paths, cm, wf) :
    for p in Paths:
        write_Path(p, cm, wf)



def print_permissions(a):
	permissions = a.get_permissions()
	OutStream.write("***Permissions***\n")
	if len(permissions) == 0:
		OutStream.write("None\n")
	else:
		for p in permissions:
			OutStream.write(p + '\n')

def fillComponetName(p, c):
	'''
	if a component name begin with '.', it means to omit the package name
	'''
	#print c
	if c[0] == '.':
		c = p + c
	return c

def print_exported_comp(a):
	'''
	#if either targetSDK or miniSDK is 16 or lower 
	tarSDK = a.get_target_sdk_version()
	minSDK = a.get_min_sdk_version()
	providerDefaultExported = False
	if tarSDK <= 16 or minSDK <= 16:
		providerDefaultExported = True
	'''
	pn = a.get_package()
	exported_comp = exported_components.find_exported_components(a)

	OutStream.write("***exported components***\n")
	OutStream.write("Activity:\n")
	for item in exported_comp.activity:
		OutStream.write(fillComponetName(pn,item[0]) + '\n')
		if item[1] != "null":
			OutStream.write("Permission: " + item[1] + '\n')
	OutStream.write("Service:\n")
	for item in exported_comp.service:
		OutStream.write(fillComponetName(pn,item[0]) + '\n')
		if item[1] != "null":
			OutStream.write("Permission: " + item[1] + '\n')
	OutStream.write("Receiver:\n")
	for item in exported_comp.receiver:
		OutStream.write(fillComponetName(pn,item[0]) + '\n')
		if item[1] != "null":
			OutStream.write("Permission: " + item[1] + '\n')
	OutStream.write("Provider:\n")
	for item in exported_comp.provider:
		OutStream.write(fillComponetName(pn,item[0]) + '\n')
		if item[1] != "null":
			OutStream.write("Read Permission: " + item[1] + '\n')
		if item[2] != "null":
			OutStream.write("Write Permission: " + item[2] + '\n')

def get_cert(a):
	signature = ""
	for rsc in a.get_files():
		if re.match(SGN, rsc):
			signature = rsc
	if signature != "":
		return (a.get_certificate(signature))
	else:
		return (False, "")

def print_certificate(a):
	success,cert = get_cert(a)

	if success == True:
		OutStream.write("***Certificate***\n")
		OutStream.write("serial number: %s\n" % cert.serialNumber())
        OutStream.write("SHA1: %s\n" % cert.sha1Thumbprint())
        OutStream.write("Issuer: %s\n" % cert.issuerDN())
        OutStream.write("Subject: %s\n" % cert.subjectDN())

def print_specialAPI(dx):
	vm = dx.get_vm()
	cm = vm.get_class_manager()
	print_dynLoad(dx,cm)
	print_reflection(dx,cm)
	print_JSExecute(dx, cm)
	print_crypto(dx, cm)
	print_perm_API(dx, cm)

def print_sensitive_str(d):
	OutStream.write("***interesting strings***\n")
	constStr = d.get_strings()
	for s in constStr:
		if re.match(URL, s) or re.match(IPADDRESS, s):
			OutStream.write(s + '\n')

def print_JSExecute(dx,cm):
	paths = dx.get_tainted_packages().search_methods( "Landroid/webkit/WebView;", "addJavascriptInterface", ".")
	if len(paths) > 0:
		OutStream.write("***potential JS exploit***\n")
		write_Paths(paths, cm, OutStream)

def print_reflection(dx,cm):
	if analysis.is_reflection_code(dx) == True:
		OutStream.write("***reflection code***\n")
		paths = dx.get_tainted_packages().search_methods( "Ljava/lang/reflect/Method;", ".", ".")
		write_Paths(paths, cm, OutStream)	

def print_dynLoad(dx, cm):
	if analysis.is_dyn_code(dx) == True:
		OutStream.write("***dynamic code loading***\n")
		paths = dx.get_tainted_packages().search_methods( "Ldalvik/system/DexClassLoader;", ".", ".")
		write_Paths(paths, cm, OutStream)

def print_crypto(dx, cm):
	OutStream.write("***crypto code loading***\n")
	if analysis.is_crypto_code(dx) == True:
		paths1 = dx.get_tainted_packages().search_methods("Ljavax/crypto/.",".",".")
		write_Paths(paths1, cm, OutStream)
		paths = dx.get_tainted_packages().search_methods("Ljava/security/spec/.",".",".")
		write_Paths(paths, cm, OutStream)
		OutStream.write("True\n")
	else:
		OutStream.write("False\n")
		
def print_specific_method(dx, cm, class_name, method_name):
	paths = dx.get_tainted_packages().search_methods( class_name, method_name, ".")
	if len(paths) > 0:
		write_Paths(paths, cm, sys.stdout)

def print_perm_API(dx, cm):
	p = dx.get_permissions( [] )
	if len(p) > 0:
		OutStream.write("***sensitive behavior***\n")

	for i in p :
		OutStream.write(i+":\n")
		for j in p[i] :
			write_Path2(j, cm, OutStream)


def security_information(a, d, dx):
	OutStream.write("===========APK SECURITY PROBLEM===============\n")
	print_permissions(a)
	print_exported_comp(a)
	print_certificate(a)
	print_sensitive_str(d)
	print_specialAPI(dx)
	

def platform(a, APKFile):
	p = a.get_package()
	os.system("echo 'FS,IPC,PREF,URI,SSL,WEBVIEW,CUSTOM HOOKS,SQLite (NO DB),_ STACK TRACES,_ NO DB' > introspy.config")
	#os.system("adb push introspy.config /data/data/" + p + "/")

	


def static_analysis(APKFile):
	#os.system("adb install -f " + APKFile)
	a, d, dx = parse_APK(APKFile)
	#platform(a, APKFile)
	basic_information(a, d, dx)
	security_information(a, d, dx)



def dynamic_analysis(APKFile):
	pass
	

if __name__ == '__main__':
	OutStream = sys.stdout
	
	fileExists, APKFile = checkPara()
	if fileExists == True:
		fileMD5, fileSHA1 = cal_filehash(APKFile)
		fileSize = cal_filesize(APKFile)
		
		
		#ndir = "./"+fileMD5
		
		if len(sys.argv) == 3:
			OutStream = open(sys.argv[2],'w')
		else:
			if len(sys.argv) == 2:
				ndir = os.path.join(os.path.dirname(__file__), fileMD5)
				if not os.path.exists(ndir):
					os.makedirs(ndir)
				OutStream = open(ndir+"/static",'w')

		#print os.path.dirname(__file__)
		#print outputFile
		#OutStream = open(outputFile,'w')
		OutStream.write("===========FILE BASIC INFORMATION===============\n")	
		OutStream.write("MD5: " + fileMD5 + '\n')
		OutStream.write("SHA1: " + fileSHA1 + '\n')
		OutStream.write("Size: " + fileSize + '\n')
		static_analysis(APKFile)
		#dynamic_analysis(APKFile)
	else:
		print ("no filename")
	OutStream.close()
