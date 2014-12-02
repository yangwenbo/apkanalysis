#!/usr/bin/env python
import sys
sys.path.append("..")
from androguard.core.bytecodes import apk
from xml.sax import *
import StringIO


class ManifestHandler(ContentHandler):
    is_in_activity = False
    is_in_service = False
    is_in_receiver = False
    
    is_in_intent_filter = False
    
    component_name_added = False    
    component_name = ""
    provider_default = True
    permission_r = "null"
    permission_w = "null"
    
    activity = []
    provider = []
    service = []
    receiver = []
    def startElement(self, name, attrs):
        if name == "uses-sdk":
            if attrs.has_key("android:minSdkVersion") and attrs.has_key("android:targetSdkVersion"):
                if int(attrs["android:minSdkVersion"]) > 17 and int(attrs["android:targetSdkVersion"]) > 17:
                    self.provider_default = False

        if name == "provider":
            if attrs.has_key("android:exported"):
                if attrs["android:exported"] == "true":
                    if attrs.has_key("android:permission"):
                        self.permission_r = attrs["android:permission"]
                        self.permission_w = attrs["android:permission"]
                    if attrs.has_key("android:readPermission"):
                        self.permission_r = attrs["android:readPermission"]
                    if attrs.has_key("android:writePermission"):
                        self.permission_w = attrs["android:writePermission"]   
                    self.provider.append([attrs["android:name"],self.permission_r,self.permission_w])
            else:
                if self.provider_default == True:
                    if attrs.has_key("android:permission"):
                        self.permission_r = attrs["android:permission"]
                        self.permission_w = attrs["android:permission"]
                    if attrs.has_key("android:readPermission"):
                        self.permission_r = attrs["android:readPermission"]
                    if attrs.has_key("android:writePermission"):
                        self.permission_w = attrs["android:writePermission"]   
                    self.provider.append([attrs["android:name"],self.permission_r,self.permission_w])


        if name == "service":
            if attrs.has_key("android:permission"):
                self.permission_r = attrs["android:permission"]
            if attrs.has_key("android:exported"):
                if attrs["android:exported"] == "true":
                    self.service.append([attrs["android:name"],self.permission_r])
            else:
                self.is_in_service = True
                self.component_name = attrs["android:name"]

        if name == "receiver":
            if attrs.has_key("android:permission"):
                self.permission_r = attrs["android:permission"]
            if attrs.has_key("android:exported"):
                if attrs["android:exported"] == "true":
                    self.receiver.append([attrs["android:name"],self.permission_r])
            else:
                self.is_in_receiver = True
                self.component_name = attrs["android:name"]


        if name == "activity":
            if attrs.has_key("android:permission"):
                self.permission_r = attrs["android:permission"]
            if attrs.has_key("android:exported"):
                if attrs["android:exported"] == "true":
                    self.activity.append([attrs["android:name"],self.permission_r])
            else:
                self.is_in_activity = True
                self.component_name = attrs["android:name"]

        if name == "intent-filter":
            if self.is_in_activity or self.is_in_service or self.is_in_receiver:
                self.is_in_intent_filter = True

        if name == "action":
            if self.is_in_intent_filter and (not self.component_name_added):
                if self.is_in_activity:
                    self.activity.append([self.component_name,self.permission_r])
                elif self.is_in_receiver:
                    self.receiver.append([self.component_name,self.permission_r])
                elif self.is_in_service:
                    self.service.append([self.component_name,self.permission_r])                    
                self.component_name_added = True

    def endElement(self, name):
        if name == "intent-filter":
            if (self.is_in_activity or self.is_in_receiver or self.is_in_service) and self.is_in_intent_filter:
                self.is_in_intent_filter = False

        if name == "activity":
            if self.is_in_activity:
                self.is_in_activity = False
                self.component_name = ""
                self.component_name_added = False
                self.permission_r = "null"
        if name == "service":
            if self.is_in_service:
                self.is_in_service = False
                self.component_name = ""
                self.component_name_added = False
                self.permission_r = "null"
        if name == "receiver":
            if self.is_in_receiver:
                self.is_in_receiver = False
                self.component_name = ""
                self.component_name_added = False
                self.permission_r = "null"

        if name == "provider":
            self.component_name_added = False
            self.permission_r = "null"
            self.permission_w = "null"


def find_exported_components(a):
	manifest = a.get_android_manifest_axml()
	p = make_parser()
	handler = ManifestHandler()
	p.setContentHandler(handler)
	p.parse(StringIO.StringIO(manifest.get_xml()))
	return handler
	
