# -*- coding: utf-8 -*-


import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://www.iana.org/assignments/ip-parameters/ip-parameters-1.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

lidb = list()
for item in reader:
    code = item[3]
    dscp = item[4]
    rfcs = item[5]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if re.match(r'\d+', rfc):   continue
        if 'RFC' in rfc:
            temp.append(f'[{rfc[:3]} {rfc[3:]}]')
        else:
            temp.append(f'[{rfc}]')
    desc = f" {''.join(temp)}" if rfcs else ''

    abbr, name = re.split(r'\W+-\W+', dscp)
    temp = re.sub(r'\[\d+\]', '', name)
    name = f' {temp}' if temp else ''
    lidb.append(f"{code:>5} : '{abbr or ('Unassigned ['+code+']')}',".ljust(80) + (f'#{desc}{name}' if desc or name else ''))

with open(os.path.join(ROOT, '../_common/ipv4_opt_type.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# IP Option Numbers\n')
    file.write('OPT_TYPE = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
