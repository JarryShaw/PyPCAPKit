# -*- coding: utf-8 -*-


import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://www.iana.org/assignments/hip-parameters/hip-parameters-4.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

def rename(name, code):
    if re.match(r'Reserved|Unassigned|Deprecated|Experimental', name, re.IGNORECASE):
        if 0 <= code <= 1023 or 61440 <= code <= 65535:
            name = f'{name} [{code}] (IETF Review)'
        elif 1024 <= code <= 32767 or 49152 <= code <= 61439:
            name = f'{name} [{code}] (Specification Required)'
        elif 32768 <= code <= 49151:
            name = f'{name} [{code}] (Reserved for Private Use)'
        else:
            name = f'{name} [{code}]'
    return name

lidb = list()
for item in reader:
    long = item[1]
    plen = item[2]
    rfcs = item[3]

    match = re.match(r'(\w*) *(\(.*\))*', long)
    group = match.groups()
    
    name = group[0]
    cmmt = f' {group[1]}' if group[1] else ''
    plen = f' {plen}' if re.match(r'\d+', plen) else ''

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if 'RFC' in rfc:
            temp.append(f'[{rfc[:3]} {rfc[3:]}]')
        else:
            temp.append(f'[{rfc}]')
    lrfc = f" {''.join(temp)}" if rfcs else ''

    try:
        code = int(item[0])
        renm = rename(name, code)
        lidb.append(f"{code:>5} : '{renm}',".ljust(80) + (f"#{lrfc}{plen}{cmmt}" if lrfc or cmmt or plen else ''))
        # print(code, name, ''.join(temp))
    except ValueError:
        start, stop = map(int, item[0].split('-'))
        for code in range(start, stop+1):
            renm = rename(name, code)
            lidb.append(f"{code:>5} : '{renm}',".ljust(80) + (f"#{lrfc}{plen}{cmmt}" if lrfc or cmmt or plen else ''))
            # print(code, name, ''.join(temp))

with open(os.path.join(ROOT, '../_common/hip_para.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# HIP Parameter Types\n')
    file.write('_HIP_PARA = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
