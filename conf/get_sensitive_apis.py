#!/usr/bin/env python

import sys
import re
p = "/home/tstcadmin/Documents/androguard/androguard/core/bytecodes/api_permissions.py"
PERM = "(.*)(READ_SMS|WRITE_SMS|RECEIVE_SMS|SEND_SMS|CALL_PHONE|READ_CONTACTS|WRITE_CONTACTS|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|ACCESS_MOCK_LOCATION|INTERNET)"
#PERM = "(.*)(INTERNET)"

s = set()
w = open("sensitive_method", 'w')
f = open(p)
ln = 1
for l in f:
	if ln > 2751:
		if re.match(PERM, l):
			ll = l.split('-')
			s.add(ll[0].split('"')[1]+ll[1])
	ln = ln + 1
for e in s:
	w.write(e+"\n")
f.close()
w.close()
