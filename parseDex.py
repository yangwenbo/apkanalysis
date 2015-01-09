#!/usr/bin/env python

import sys
import os
sys.path.append("..")
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes import apk
from androguard.core import bytecode
from androguard.util import read
from androguard.core.analysis import analysis
import re


def access_dex_header(dex):
	dexHeader = dex.get_header_item()
	dexHeader.show()

def print_classes_name(dex, classNameFilter):
	classlist = dex.get_classes()
	for each_class in classlist:
		name = each_class.get_name()
		if re.match(classNameFilter, name):
			print name

def access_classes(dex, classNameFilter):
	classlist = dex.get_classes()
	for each_class in classlist:
		name = each_class.get_name()
		if re.match(classNameFilter, name):
			access_class(dex, name)


def access_class(dex, class_name):
	c = dex.get_class(class_name)
	c.show()

	# get fields
	fields = c.get_fields()
	print "********fields number: %d" %len(fields)
	for each_field in fields:
		each_field.pretty_show()

	#get methods
	methods = c.get_methods()
	print "********methods number: %d" %len(methods)
	for each_method in methods:
		each_method.show_info()
	print "\n"
		#print each_method.get_information()
		#each_method.pretty_show()
		#each_method.show()



def print_methods_name(dex, methodNameFilter):
	methodlist = dex.get_methods()
	for each_method in methodlist:
		completeName = each_method.get_class_name()+each_method.get_name()
		if re.match(methodNameFilter, completeName):
			print completeName

def access_methods_name(dex, methodNameFilter):
	methodlist = dex.get_methods()
	for each_method in methodlist:
		completeName = each_method.get_class_name()+each_method.get_name()+each_method.get_descriptor()
		if re.match(methodNameFilter, completeName):
			access_method_descriptor(dex, each_method.get_class_name(), each_method.get_name(), each_method.get_descriptor())


def access_method_descriptor(dex, class_name, method_name, descriptor):
	m = dex.get_method_descriptor(class_name, method_name, descriptor)
	access_method(m)

def access_methods_descriptor(dex, class_name, method_name):
	ms = dex.get_methods_descriptor(class_name,method_name)
	for m in ms:
		access_method(m)

def access_methods_class(dex, class_name):
	ms = dex.get_methods_class(class_name)
	for m in ms:
		access_method(m)


def access_method(methodObj):
	methodObj.pretty_show()
	print "\n"

def print_specific_method(dex, class_name, method_name):
	dx = analysis.VMAnalysis(dex)
	cm = dex.get_class_manager()
	import static
	static.print_specific_method(dx, cm, class_name, method_name)

def whole_dexdump(dex):
	access_dex_header(dex)
	print "\n"
	classlist = dex.get_classes()
	for each_class in classlist:
		each_class.show()
		print

		fields = each_class.get_fields()
		print "********fields number: %d" %len(fields)
		for each_field in fields:
			each_field.pretty_show()
			print

		print 

		methods = each_class.get_methods()
		print "********methods number: %d" %len(methods)
		for each_method in methods:
			each_method.pretty_show()
			print 

	print "\n\n\n"
		

		



isAPK = True

if isAPK:
	apkFile = sys.argv[1]
	a = apk.APK(apkFile)
	dex = dvm.DalvikVMFormat( a.get_dex() )
else:
	DEXFile = sys.argv[1]
	dex = dvm.DalvikVMFormat( read(DEXFile) )


'''
	access_dex_header(dex)

	print_classes_name(dex, classNameFilter)
	access_classes(dex, classNameFilter)
	access_class(dex, class_name)

	print_methods_name(dex, methodNameFilter)
	access_methods_name(dex, methodNameFilter)
	access_methods_descriptor(dex, class_name, method_name)
	access_methods_class(dex, class_name)
	access_method(methodObj)

	/* 
	 search specific API invoked
	 crypto, dynamic loading, reflection can be analyzed in static.py
	*/
	print_specific_method(dex, class_name, method_name)

	whole_dexdump(dex)


'''

ClassNameFilter = "^(?!Landroid/support)"
ClassNameFilter = ".*"

MethodNameFilter = "^(?!Landroid/support)"

ClassName = "Lcom/example/test/MainActivity;"
MethodName = "run"

#access_dex_header(dex)

#print_classes_name(dex,ClassNameFilter)
#access_class(dex, ClassName)
#access_classes(dex, ClassNameFilter)

#print_methods_name(dex, methodNameFilter)
#access_methods_name(dex,MethodNameFilter)
#access_methods_descriptor(dex,ClassName,MethodName)
#access_methods_class(dex, ClassName)

#print_specific_method(dex, "Landroid/webkit/WebView;", "addJavascriptInterface")
whole_dexdump(dex)













