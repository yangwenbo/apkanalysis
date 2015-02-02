#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append("/home/dev/tools/androguard/")
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
import re
'''
generate all classes&methods
'''

FILTER = "^(Landroid/support/v4/)";
apkFile = sys.argv[1]
directory = "./all_classmethod/"


a = apk.APK(apkFile)
d = dvm.DalvikVMFormat(a.get_dex())
dx = analysis.VMAnalysis(d)

vm = dx.get_vm()
cm = vm.get_class_manager()
p = a.get_package()
if not os.path.exists(directory):
	os.makedirs(directory)

ClassFile = open(directory + p + "_class.dlist", "w" )
MethodFile = open(directory + p + "_method.dlist", "w")

for i in d.get_classes_names():
    if not re.match(FILTER, i):
        ClassFile.write(i+"\n")

for i in vm.get_methods():
    if not re.match(FILTER, i.get_class_name()):
        MethodFile.write(i.get_class_name() + i.get_name()+"\n")


