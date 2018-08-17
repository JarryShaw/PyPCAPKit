# -*- coding: utf-8 -*-


import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters-3.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

def rename(name, code):
    if re.match(r'Reserved|Unassigned|Deprecated|Experimental', name, re.IGNORECASE):
        if 1 <= code <= 127:
            name = f'{name} [{code}] (Standards Action)'
        elif 128 <= code <= 255:
            name = f'{name} [{code}] (Reserved)'
        else:
            name = f'{name} [{code}]'
    return name

lidb = list()
for item in reader:
    name = item[1]
    rfcs = item[2]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if 'RFC' in rfc:
            temp.append(f'[{rfc[:3]} {rfc[3:]}]')
        else:
            temp.append(f'[{rfc}]')
    desc = f"# {''.join(temp)}" if rfcs else ''

    try:
        code = int(item[0])
        renm = rename(name, code)
        lidb.append(f"{code:>5} : '{renm}',".ljust(80) + desc)
        # print(code, name, ''.join(temp))
    except ValueError:
        start, stop = map(int, item[0].split('-'))
        for code in range(start, stop+1):
            renm = rename(name, code)
            lidb.append(f"{code:>5} : '{renm}',".ljust(80) + desc)
            # print(code, name, ''.join(temp))

with open(os.path.join(ROOT, '../_common/ospf_type.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# OSPF Packet Types\n')
    file.write('TYPE = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
