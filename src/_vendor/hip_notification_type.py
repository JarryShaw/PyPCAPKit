# -*- coding: utf-8 -*-


import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://www.iana.org/assignments/hip-parameters/hip-parameters-9.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

def rename(name, code):
    if re.match(r'Reserved|Unassigned|Deprecated|Experimental', name, re.IGNORECASE):
        if 1 <= code <= 50:
            name = f'{name} [{code}] (IETF Review)'
        elif 51 <= code <= 8191:
            name = f'{name} [{code}] (Specification Required; Error Type)'
        elif 8192 <= code <= 16383:
            name = f'{name} [{code}] (Reserved for Private Use; Error Type)'
        elif 16384 <= code <= 40959:
            name = f'{name} [{code}] (Specification Required; Status Type)'
        elif 40960 <= code <= 65535:
            name = f'{name} [{code}] (Reserved for Private Use; Error Type)'
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
    desc = f"# {''.join(temp)}" if rfcs else ''

    try:
        code = int(item[0])
        renm = rename(name, code)
        lidb.append(f"{code:>5} : '{renm}',".ljust(100) + desc)
        # print(code, name, ''.join(temp))
    except ValueError:
        start, stop = map(int, item[0].split('-'))
        for code in range(start, stop+1):
            renm = rename(name, code)
            lidb.append(f"{code:>5} : '{renm}',".ljust(100) + desc)
            # print(code, name, ''.join(temp))

with open(os.path.join(ROOT, '../_common/hip_notification_type.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# Notify Message Types\n')
    file.write('_NOTIFICATION_TYPE = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
