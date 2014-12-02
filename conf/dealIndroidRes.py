#!/usr/bin/env python
import sys
import os
import re
import shutil

CONFFILE = "(method|class|flag|object).dlist"
RESULTFILE = "(obj|func|reg|opcode|opcodeSet)_\d+.bin"


path = sys.argv[1]
indroidRel = path+"/indroidRelated"
os.makedirs(indroidRel)
for filename in os.listdir(path):
	if re.match(CONFFILE, filename) or re.match(RESULTFILE,filename):
		shutil.move(filename,indroidRel)