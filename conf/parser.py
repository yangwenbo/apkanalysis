#!/usr/bin/env python

import binascii
from sys import argv
import re

PATTER1 = '^instUid \d+ #(.*) 0x'
PATTER2 = '^--(.*) #(.*) 0x'
PATTER3 = '^p[\d+]: '
STRTYPE = '#Ljava/lang/String;'
flag = False
first = False
strlist = []

rFile, wFile = argv[1], argv[2]

rf = open(rFile,'rb')
wf = open(wFile,'wb')

allLines = rf.readlines()

for l in allLines:
	if re.match(PATTER1,l) or re.match(PATTER2,l) or re.match(PATTER3,l):
		if flag == True:
			if strlist[-1][-1]=='\x0a':
				strlist[-1] = strlist[-1][:-1]+'\n'.encode('utf-16')
			for sl in strlist:
				wf.write(sl)	
			strlist = []
		flag = False
		wf.write(l.encode('utf-16'))
		if STRTYPE in l:
			flag = True
			first = True
	if flag == True:
		if first == True:
			if l[0] == '\x20' or l[0] == '\x00':
				l = l[1:]
			first = False	
		strlist.append(l)
rf.close()
wf.close()
