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
    
    activity = []
    provider = []
    service = []
    receiver = []
    def startElement(self, name, attrs):
        if name == "provider":
            if attrs.has_key("android:exported"):
                if attrs["android:exported"] == "true":
                    self.provider.append(attrs["android:name"])
            else:
                self.provider.append(attrs["android:name"])

        if name == "service":
            if attrs.has_key("android:exported"):
                if attrs["android:exported"] == "true":
                    self.service.append(attrs["android:name"])
            else:
                self.is_in_service = True
                self.component_name = attrs["android:name"]

        if name == "receiver":
            if attrs.has_key("android:exported"):
                if attrs["android:exported"] == "true":
                    self.receiver.append(attrs["android:name"])
            else:
                self.is_in_receiver = True
                self.component_name = attrs["android:name"]


        if name == "activity":
            if attrs.has_key("android:exported"):
                if attrs["android:exported"] == "true":
                    self.activity.append(attrs["android:name"])
            else:
                self.is_in_activity = True
                self.component_name = attrs["android:name"]

        if name == "intent-filter":
            if self.is_in_activity or self.is_in_service or self.is_in_receiver:
                self.is_in_intent_filter = True

        if name == "action":
            if self.is_in_intent_filter and (not self.component_name_added):
                if self.is_in_activity:
                    self.activity.append(self.component_name)
                elif self.is_in_receiver:
                    self.receiver.append(self.component_name)
                elif self.is_in_service:
                    self.service.append(self.component_name)                    
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
        if name == "service":
            if self.is_in_service:
                self.is_in_service = False
                self.component_name = ""
                self.component_name_added = False
        if name == "receiver":
            if self.is_in_receiver:
                self.is_in_receiver = False
                self.component_name = ""
                self.component_name_added = False


def find_exported_components(a):
	manifest=a.get_android_manifest_axml()
	p = make_parser()
	handler = ManifestHandler()
	p.setContentHandler(handler)
	p.parse(StringIO.StringIO(manifest.get_xml()))
	return handler
	