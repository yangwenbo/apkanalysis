#!/usr/bin/env python
import sys
import os
sys.path.append("/home/tstcadmin/Documents/androguard/")
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
'''
generate class&method according to a APIs file
'''

inputFile = "./sensitive_api/sensitive_method"
apkFile = sys.argv[1]
directory = "./apis_classmethod/"

a = apk.APK(apkFile)
d = dvm.DalvikVMFormat(a.get_dex())
dx = analysis.VMAnalysis(d)

package = a.get_package()
output = directory + package
if not os.path.exists(directory):
	os.makedirs(directory)
wClass = open(output + "_class.dlist", 'w')
wMethod = open(output + "_method.dlist", 'w')

vm = dx.get_vm()
cm = vm.get_class_manager()

sClass = set()
sMethod = set()


def write_Paths(Paths, cm) :
    for p in Paths:
        write_Class_Path(p, cm)
        write_Method_Path(p, cm)
        
def write_Class_Path(p, cm):
	if isinstance(p, analysis.PathVar):
		sClass.add(p.get_dst(cm)[0])
	else:
		sClass.add(p.get_src(cm)[0])

def write_Method_Path(p, cm):
	if isinstance(p, analysis.PathVar):
		sMethod.add(p.get_dst(cm)[0] + p.get_dst(cm)[1])
	else:
		if p.get_access_flag() == analysis.TAINTED_PACKAGE_CALL:
			sMethod.add(p.get_dst(cm)[0] + p.get_dst(cm)[1])

inFile = open(inputFile)
lines = inFile.readlines()
inFile.close()
for el in lines:
	el = el.strip('\n')
	ell = el.split(";")
	paths = dx.get_tainted_packages().search_methods( ell[0]+';', ell[1], ".")
	write_Paths(paths, cm)

for s in sClass:
	wClass.write(s + '\n')
for s in sMethod:
	wMethod.write(s + '\n')

wClass.close()
wMethod.close()

