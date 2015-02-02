#!/usr/bin/env python
import sys
import os
sys.path.append("/home/tstcadmin/Documents/androguard/")
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
'''
generate class&method according to dangerous permissions' API
'''

apkFile = sys.argv[1]
directory = "./perms_classmethod/"

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

permissions = []
per = a.get_permissions()
dp = a.get_details_permissions()
for p in per:
	if dp[p][0] != "normal":
		permissions.append(p)

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

pa = dx.get_permissions([])
for i in pa:
	if ("android.permission." + i) in permissions:
		for j in pa[i]:
			write_Class_Path(j,cm)
			write_Method_Path(j,cm)

'''
if analysis.is_dyn_code(dx) == True:
    paths = dx.get_tainted_packages().search_methods( "Ldalvik/system/DexClassLoader;", ".", ".")
    write_Paths(paths, cm)

if analysis.is_reflection_code(dx) == True:
    paths = dx.get_tainted_packages().search_methods( "Ljava/lang/reflect/Method;", ".", ".")
    write_Paths(paths, cm)

if analysis.is_native_code(dx) == True:
    for i in vm.get_methods():
        if i.get_access_flags() & 0x100:
            sClass.add(i.get_class_name())
            sMethod.add(i.get_class_name() + i.get_name())
'''

for s in sClass:
	wClass.write(s + '\n')
for s in sMethod:
	wMethod.write(s + '\n')

wClass.close()
wMethod.close()
