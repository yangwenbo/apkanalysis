#!/usr/bin/env python

import binascii
import re, os, sys
sys.path.append("/home/ywb/tools/androguard/")
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from perm_description import PERM_DESCRIPTION

APKFile = sys.argv[1]
path = sys.argv[2]
SPECIAL_PERMS = ['READ_SMS', 'WRITE_SMS', 'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALENDAR', 'WRITE_CALENDAR']
FUNCPATTERN = '^instUid \d+\|\|(.*);\|\|(.*)\|\|(.*)'
permap={}
result=[]

def returnMethod(path, cm):
	if isinstance(path, analysis.PathVar):
		dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
		#print dst_class_name+ dst_method_name
		return dst_class_name + dst_method_name
	else :
		if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL :
			dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

			return dst_class_name + dst_method_name
		else :
			return 0

def whetherSpecial(i):
	c = i.split("||")[1]
	m = i.split("||")[2]
	l = ["Landroid/content/ContentResolver;","Landroid/content/ContentProvider;","Landroid/content/ContentProviderClient;"]
	if c in l or (c == "Landroid/net/Uri;" and m == "parse") :
		return True
	return False

def behave(n):
	if n.find("content://sms") != -1:
		result.append("SMS")
	elif n.find("content://com.android.calendar")!=-1:
		result.append("CALENDAR")
	elif n.find("content://com.android.contacts") != -1:
		result.append("CONTACTS")


def initStatic(APKFile):
	a = apk.APK(APKFile)
	d = dvm.DalvikVMFormat(a.get_dex())
	dx = analysis.VMAnalysis(d)
	vm = dx.get_vm()
	cm = vm.get_class_manager()
	per = a.get_permissions()
	pa = dx.get_permissions([])
	USE = [p for p in SPECIAL_PERMS if "android.permission."+p in per]
	specialPath = dx.get_tainted_packages().search_methods( "Landroid/content/ContentResolver;", ".", ".")
	specialPath += dx.get_tainted_packages().search_methods( "Landroid/content/ContentProvider;", ".", ".")
	specialPath += dx.get_tainted_packages().search_methods( "Landroid/content/ContentProviderClient;", ".", ".")
	specialPath += dx.get_tainted_packages().search_methods( "Landroid/net/Uri;", "parse", ".")
	if len(specialPath) > 0 and len(USE) > 0:
		for i in USE:
			pa[i] = specialPath
	
	for i in pa:
		if i in PERM_DESCRIPTION:
			met = set()
			for j in pa[i]:
				t = returnMethod(j, cm)
				if t != 0:
					met.add(t)
			permap[i] = met

	execPath = dx.get_tainted_packages().search_methods( "Ljava/lang/Runtime;", "exec", ".")
	if len(execPath) > 0:
		met=set()
		for j in execPath:
			t = returnMethod(j, cm)
			if t != 0:
				met.add(t)
		permap['CMD_EXEC'] = met


def readDyn(path):
	pa = path + "/parseRes"
	for filename in os.listdir(pa):
		if filename.startswith("func"):
			f = open(pa+"/"+filename,"r")
			a = f.readlines()
			a.append("==end==")
			x = iter(a)
			try:
				cu = x.next()
				while True:
					if re.match(FUNCPATTERN, cu):
						if whetherSpecial(cu):
							cu = x.next()
							while cu != "==end==" and (not re.match(FUNCPATTERN,cu)):
								behave(cu)
								cu = x.next()
						else:
							m = cu.split("||")[1] + cu.split("||")[2]
							for pe in permap:
								if m in permap[pe]:
									result.append(pe)
							cu = x.next()
					else:
						cu = x.next()

			except StopIteration:
				pass
			f.close()


def writeRes(result,path):
	fn = path+"/parseRes/behavior"
	with open(fn,'w') as d:
		for r in result:
			d.write(r+"\n")

	


initStatic(APKFile)
#print permap
#readDyn("/home/dev/tools/androguard/tstc/dynam_out/0b982427125d5d1a4d6db07afa2c2c1c/data")
readDyn(path)
writeRes(result,path)
print result
