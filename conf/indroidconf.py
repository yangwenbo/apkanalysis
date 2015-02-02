#!/usr/bin/env python
import os
import sys
import conf
#adbPath = "adb -s emulator-5554 "
adbPath = conf.adbPath 
opt = sys.argv[1]
APKFile = sys.argv[2]
package = sys.argv[3]
'''
perms,apis,all,def,mal
'''

#os.chdir("./config")
#os.popen("./gen_class_dlist.sh "+sys.argv[1]+" " + sys.argv[2])
conf_dir = opt+"_classmethod/"
if not opt.startswith("def"):
	os.popen("./gen_cm_"+opt+".py " + APKFile)
	os.popen(adbPath + "push "+conf_dir+package+"_method.dlist /data/data/"+package+"/method.dlist")
	os.popen(adbPath + "push "+conf_dir+package+"_class.dlist /data/data/"+package+"/class.dlist")
else:
	os.popen("./gen_cm_all.py "+ APKFile)
	os.popen(adbPath + "push all_classmethod/"+package+"_class.dlist /data/data/"+package+"/class.dlist")
os.popen(adbPath + "push ./config/flag.dlist /data/data/"+package+"/")
os.popen(adbPath + "push ./config/object.dlist /data/data/"+package+"/")

