#!/usr/bin/env python
import subprocess
import sys
import os
import conf
sys.path.append("/home/ywb/tools/androguard/")
from androguard.core.bytecodes import apk

adbPath = conf.adbPath
option = conf.autoconf
'''
option can be perms, apis, all, def.
perms: monitor sensitive permissions api
apis: monitor specific apis which can be configure in 'sensitive_api/sensitive_method'
all: monitor all methods in apks(which may cause heavy overhead
def: just monitor function call and object
'''

APKFile = sys.argv[1]
os.popen(adbPath + "install " + APKFile)
os.popen(adbPath + "shell chmod 664 /data/system/packages.list")
a = apk.APK(APKFile)
p = a.get_package()
os.popen("./indroidconf.py " + option + " " + APKFile + " "+ p)
ma = a.get_main_activity()
os.popen(adbPath + "shell am start "+p+"/"+ma)
os.popen(adbPath + "shell monkey -p " + p + "  -s 500 --monitor-native-crashes -v -v -v 1000")
if len(sys.argv) == 3:
	path = sys.argv[2]
	os.popen("./pullfile.py "+APKFile+" "+path)
	os.popen("zip -r download.zip "+path)
else:
	os.popen("./pullfile.py "+APKFile)
os.popen(adbPath + "uninstall " + p)

