# -*- coding: utf-8 -*-


import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://www.iana.org/assignments/http2-parameters/frame-type.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

def rename(name, code):
    if re.match(r'Reserved|Unassigned|Deprecated|Experimental', name, re.IGNORECASE):
        name = f'{name} [0x{hex(code)[2:].upper().zfill(2)}]'
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
    desc = f"# {''.join(temp)}" if rfcs else ''

    try:
        code = int(item[0], base=16)
        renm = rename(name, code)
        lidb.append(f"\t0x{hex(code)[2:].upper().zfill(2)} : '{renm}',".ljust(80) + desc)
        # print(code, name, ''.join(temp))
    except ValueError:
        start, stop = map(lambda s: int(s, base=16), item[0].split('-'))
        for code in range(start, stop+1):
            renm = rename(name, code)
            lidb.append(f"\t0x{hex(code)[2:].upper().zfill(2)} : '{renm}',".ljust(80) + desc)
            # print(code, name, ''.join(temp))

with open(os.path.join(ROOT, '../_common/http_type.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# HTTP/2 Frame Type\n')
    file.write('_HTTP_TYPE = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
