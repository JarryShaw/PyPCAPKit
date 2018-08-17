# -*- coding: utf-8 -*-


import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

def rename(name, code):
    if re.match(r'Reserved|Unassigned|Deprecated|Experimental', name, re.IGNORECASE):
        name = f'{name} [{code}]'
    return name

lidb = list()
for item in reader:
    flag = item[3]
    if flag != 'Y': continue

    name = item[1]
    rfcs = item[4]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if 'RFC' in rfc:
            temp.append(f'[{rfc[:3]} {rfc[3:]}]')
        else:
            temp.append(f'[{rfc}]')
    lrfc = re.sub(r'( )( )*', ' ', f" {''.join(temp)}".replace('\n', ' ')) if rfcs else ''

    subd = re.sub(r'( )( )*', ' ', item[2].replace('\n', ' '))
    desc = f' {subd}' if item[2] else ''

    split = name.split(' (', 1)
    if len(split) == 2:
        name = split[0]
        cmmt = f" ({split[1]}"
    else:
        name, cmmt = name, ''

    try:
        code = int(item[0])
        if name == '':
            name, desc = f'{item[2]} [{code}]', ''
        renm = rename(name, code)
        lidb.append(f"\t'{renm}',".ljust(80) + (f"#{lrfc}{desc}{cmmt}" if lrfc or desc or cmmt else ''))
        # print(code, name, ''.join(temp))
    except ValueError:
        start, stop = map(int, item[0].split('-'))
        if name == '':
            name, desc = item[2], ''
        for code in range(start, stop+1):
            renm = rename(name, code)
            lidb.append(f"\t'{renm}',".ljust(80) + (f"#{lrfc}{desc}{cmmt}" if lrfc or desc or cmmt else ''))
            # print(code, name, ''.join(temp))

with open(os.path.join(ROOT, '../_common/ipv6_ext_hdr.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# IPv6 Extension Header Types\n')
    file.write('EXT_HDR = (\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n)\n')
