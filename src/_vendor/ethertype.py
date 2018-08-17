# -*- coding: utf-8 -*-


import collections
import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)
record = collections.defaultdict(int)
for item in reader:
    name = item[4]
    try:
        code = int(item[1], base=16)
        record[item[4]] += 1
    except ValueError:
        start, stop = map(lambda x: int(x, base=16), item[1].split('-'))
        for code in range(start, stop+1):
            record[item[4]] += 1

def rename(name, code):
    if record[name] > 1:
        name = f'{name} [0x{hex(code)[2:].upper().zfill(4)}]'
    return name

reader = csv.reader(data)
header = next(reader)

lidb = list()
for item in reader:
    name = item[4]
    rfcs = item[5]

    temp = list()
    for rfc in filter(None, re.split(r'\[|\]', rfcs)):
        if 'RFC' in rfc:
            temp.append(f'[{rfc[:3]} {rfc[3:]}]')
        else:
            temp.append(f'[{rfc}]')
    desc = re.sub(r'( )( )*', ' ', f"# {''.join(temp)}".replace('\n', ' ')) if rfcs else ''

    try:
        code = int(item[1], base=16)
        renm = re.sub(r'( )( )*', ' ', rename(name, code).replace('\n', ' '))
        ln_1 = f"\t0x{hex(code)[2:].upper().zfill(4)} : '{renm}',".ljust(80)
        ln_2 = f"\n{' '*83}{desc}" if len(ln_1) > 80 else desc
        lidb.append(f'{ln_1}{ln_2}')
        # print(code, name, ''.join(temp))
    except ValueError:
        start, stop = map(lambda x: int(x, base=16), item[1].split('-'))
        for code in range(start, stop+1):
            renm = re.sub(r'( )( )*', ' ', rename(name, code).replace('\n', ' '))
            ln_1 = f"\t0x{hex(code)[2:].upper().zfill(4)} : '{renm}',".ljust(80)
            ln_2 = f"\n{' '*80}{desc}" if len(ln_1) > 80 else desc
            lidb.append(f'{ln_1}{ln_2}')
            # print(code, name, ''.join(temp))

with open(os.path.join(ROOT, '../_common/ethertype.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# Ethertype IEEE 802 Numbers\n')
    file.write('ETHERTYPE = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
