#!/usr/bin/env python

import binascii
from sys import argv
import re
import os

PATTER1 = '^instUid \d+ #(.*) 0x'
PATTER2 = '^--(.*) #(.*) 0x'
PATTER3 = '^p\[\d+\]: '
PATTER4 = '^instUid \d+\|\|(.*);\|\|(.*)\|\|(.*)'
STRTYPE = '#Ljava/lang/String;'
#INTERESTING = "(.*)(\.|\/)(.*)"
OBJBIN = "^obj_\d+.bin$"
FUNCBIN = "^func_\d+.bin$"

path = argv[1]

def trans(infile,outfile):
	flag = False
	s = set()
	rf = open(infile,'rb')
	wf = open(outfile,'wb')
	allLines = rf.readlines()

	for l in allLines:
		if re.match(PATTER1,l) or re.match(PATTER2,l) or re.match(PATTER3,l) or re.match(PATTER4,l):
			flag = False
			wf.write(l.encode('utf-8'))
			if STRTYPE in l:
				flag = True
		else:
			if flag == True:
				if l[0] == '\x20' or l[0] == '\x00':
					l = l[1:]
				if l[-1] == '\x0a':
					l = l[:-1] + '\n'.encode('utf-16')
				wf.write(l.decode('utf-16').encode('utf-8'))
				#if re.match(INTERESTING, l):
				#	s.add(l)
			else:
				#if re.match(INTERESTING, l):
				#	s.add(l.encode('utf-16'))
				wf.write(l.encode('utf-8'))
	#for si in s:
	#	wf.write(si)
	rf.close()
	wf.close()

'''
i = 0
strpath = path+"/parseRes"
if not os.path.exists(strpath):
	os.makedirs(strpath)
for filename in os.listdir(path):
	if re.match(OBJBIN,filename):
		trans(path+"/"+filename, strpath+"/str"+str(i))
		i = i + 1
#trans(path,"out")
j = 0
for filename in os.listdir(path):
	if re.match(FUNCBIN,filename):
		trans(path+"/"+filename, strpath+"/func"+str(j))
		j = j + 1
'''

trans(path,"xxxxx")