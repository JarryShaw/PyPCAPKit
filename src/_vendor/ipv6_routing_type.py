# -*- coding: utf-8 -*-


import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters-3.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

def rename(name, code):
    if re.match(r'Reserved|Unassigned|Deprecated|Experimental', name, re.IGNORECASE):
        name = f'{name} [{code}]'
    return name

lidb = list()
for item in reader:
    long = item[1]
    rfcs = item[2]

    split = long.split(' (')
    if len(split) == 2:
        name = re.sub(r'\[\d+\]', '', split[0]).strip()
        cmmt = f' {split[1][:-1]}'
    else:
        name, cmmt = re.sub(r'\[\d+\]', '', long).strip(), ''

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
        lidb.append(f"{code:>5} : '{renm}',".ljust(80) + (f"#{lrfc}{cmmt}" if lrfc or cmmt else ''))
        # print(code, name, ''.join(temp))
    except ValueError:
        start, stop = map(int, item[0].split('-'))
        for code in range(start, stop+1):
            renm = rename(name, code)
            lidb.append(f"{code:>5} : '{renm}',".ljust(80) + (f"#{lrfc}{cmmt}" if lrfc or cmmt else ''))
            # print(code, name, ''.join(temp))

with open(os.path.join(ROOT, '../_common/ipv6_routing_type.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# IPv6 Routing Types\n')
    file.write('_ROUTING_TYPE = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
