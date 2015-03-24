#!/usr/bin/env python
#-*-coding:utf-8 -*-
import sys
import os
sys.path.append("/home/ywb/tools/androguard/")
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from perm_description import PERM_DESCRIPTION
'''
generate class&method according to malicious API
'''
'''
SPECIAL permission use ContentResolver->query to access sensitive data
while is not included in DEFAULT Androguard API_PERMISSIONS
'''
SPECIAL_PERMS = ['READ_SMS', 'WRITE_SMS', 'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALENDAR', 'WRITE_CALENDAR']

def write_Path2(path, cm, wf):
	if isinstance(path, analysis.PathVar):
		dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
		info_var = path.get_var_info()
		wf.write("%s ---> %s->%s%s\n" % (	info_var,
											dst_class_name,
											dst_method_name,
											dst_descriptor) )
	else :
		if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL :
			src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
			dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

			wf.write(" %s->%s%s ---> %s->%s%s\n" % (	src_class_name,
														src_method_name,
														src_descriptor,
														dst_class_name,
														dst_method_name,
														dst_descriptor) )
		else :
			src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
			wf.write("%s->%s%s\n" % (	src_class_name,
										src_method_name,
										src_descriptor,
									) )

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




apkFile = sys.argv[1]
directory = "./mal_classmethod/"

a = apk.APK(apkFile)
d = dvm.DalvikVMFormat(a.get_dex())
dx = analysis.VMAnalysis(d)

package = a.get_package()
output = directory + package
if not os.path.exists(directory):
	os.makedirs(directory)
wClass = open(output + "_class.dlist", 'w')
wMethod = open(output + "_method.dlist", 'w')
wDes = open(output + "_description",'w')

vm = dx.get_vm()
cm = vm.get_class_manager()

sClass = set()
sMethod = set()

permissions = []
per = a.get_permissions()
wDes.write("=============声明权限=============\n")
for p in per:
	wDes.write(p+'\n')


vtres = os.popen("./vtlite.py -s -v "+ apkFile)
wDes.write("==============VirusTotal结果==============\n")
wDes.write(vtres.read())


#find whether APK permissions contain SPECIAL PERMISSIONS
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
	if i in PERM_DESCRIPTION :
		wDes.write("**********"+PERM_DESCRIPTION[i][1]+"****************\n")
		for j in pa[i]:
			write_Class_Path(j,cm)
			write_Method_Path(j,cm)
			write_Path2(j,cm, wDes)


execPath = dx.get_tainted_packages().search_methods( "Ljava/lang/Runtime;", "exec", ".")
if len(execPath) > 0:
	wDes.write("**********命令执行****************\n")
	for j in execPath:
		write_Class_Path(j,cm)
		write_Method_Path(j,cm)
		write_Path2(j,cm, wDes)


for s in sClass:
	wClass.write(s + '\n')
for s in sMethod:
	wMethod.write(s + '\n')


wClass.close()
wMethod.close()
wDes.close()
