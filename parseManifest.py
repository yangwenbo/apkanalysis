#!/usr/bin/env python

import sys
import os
sys.path.append("..")
from androguard.core.bytecodes import apk
from androguard.util import read
import xml.dom.minidom

isAPK = True

if isAPK:
	apkFile = sys.argv[1]
	a = apk.APK(apkFile)
	manifest = a.get_android_manifest_xml()
	print manifest.toprettyxml()
else:
	axml = sys.argv[1]
	#apk.AXMLPrinter(read(axml))
	manifest = apk.AXMLPrinter(read(axml)).get_xml()
	print manifest



#print manifest.toprettyxml()
#out.write(manifest.toprettyxml())
#out.close()

