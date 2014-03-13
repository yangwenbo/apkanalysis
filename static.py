#!/usr/bin/env python

import os
import sys
import hashlib
sys.path.append("..")
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
import chilkat
import re



def checkPara():
	'''
	first return value is whether the file exists
	second return value is the full path of the file
	'''
	if len(sys.argv) == 2:
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

def cal_filehash(filepath):
	'''
	calculate the md5 & sha1 of file
	'''
	with open(filepath, 'rb') as f:
		hashMD5 = hashlib.md5()
		hashMD5.update(f.read())
		hashSHA1 = hashlib.sha1()
		hashSHA1.update(f.read())
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

	OutStream.write("===========APK BASIC INFORMATION=============\n")
	OutStream.write("Package name: " + package + '\n')
	OutStream.write("min SDK version: " + str(minSDK) + '\n')
	OutStream.write("max SDK version: " + str(maxSDK) + '\n')
	OutStream.write("target SDK version: " + str(tarSDK) + '\n')
	OutStream.write("version name: " + versionname + '\n')
	OutStream.write("version code: " + versioncode + '\n')


def security_information(a, d, dx):
	permissions = a.get_permissions()


	OutStream.write("===========APK SECURITY PROBLEM===============\n")
	OutStream.write("***Permissions***\n")
	if len(permissions) == 0:
		OutStream.write("None\n")
	else:
		for p in permissions:
			OutStream.write(p + '\n')

def static_analysis(APKFile):
	a, d, dx = parse_APK(APKFile)
	basic_information(a, d, dx)
	security_information(a, d, dx)




	



if __name__ == '__main__':
	OutStream = sys.stdout
	fileExists, APKFile = checkPara()
	if fileExists == True:
		fileMD5, fileSHA1 = cal_filehash(APKFile)
		fileSize = cal_filesize(APKFile)
		outputFile = os.path.join(os.path.dirname(__file__), fileMD5)
		#print os.path.dirname(__file__)
		#print outputFile
		#OutStream = open(outputFile,'w')
		OutStream.write("===========FILE BASIC INFORMATION===============\n")	
		OutStream.write("MD5: " + fileMD5 + '\n')
		OutStream.write("SHA1: " + fileSHA1 + '\n')
		OutStream.write("Size: " + fileSize + '\n')
		static_analysis(APKFile)
	else:
		print ("no filename")
	OutStream.close()
