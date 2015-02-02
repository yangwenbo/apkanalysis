#!/usr/bin/env python

import os
import sys
import subprocess
import hashlib
sys.path.append("/home/dev/tools/androguard")
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
import conf
#adbPath = "adb "
adbPath = conf.adbPath

if __name__ == '__main__':
	APKFile = sys.argv[1]
	a = apk.APK(APKFile)
	p = a.get_package()
	with open(APKFile, 'rb') as f:
		hashMD5 = hashlib.md5()
		hashMD5.update(f.read())
		fileMD5 = hashMD5.hexdigest()
	
	ndir = "../dynam_out/"+fileMD5
	if len(sys.argv) == 3:
		dataDir = sys.argv[2]
	if len(sys.argv) == 2:
		dataDir = ndir + "/data" 
	if not os.path.exists(dataDir):
		os.makedirs(dataDir)
	os.popen(adbPath + "pull /data/data/"+p + " " + dataDir)
	subprocess.call(["./parseIndroidRes.py",dataDir])
	subprocess.call(["./parseMal.py",APKFile,dataDir])
	#x = os.popen("./parseIndroidRes.py "+dataDir)
	#print type(x)
	#os.popen("./parseMal.py "+APKFile+" "+dataDir)