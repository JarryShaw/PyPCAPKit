# -*- coding: utf-8 -*-


import csv
import os
import re

import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

defaultdict = '''\
class defaultdict(dict):
    def __missing__(self, code):
        if isinstance(code, int):
            return f'Reserved for Experimental Use [0x{hex(code)[2:].upper().zfill(8)}]'
        raise KeyError(code)


'''

page = requests.get('https://www.iana.org/assignments/http2-parameters/error-code.csv')
data = page.text.strip().split('\r\n')

reader = csv.reader(data)
header = next(reader)

def rename(name, code):
    if re.match(r'Reserved|Unassigned|Deprecated|Experimental', name, re.IGNORECASE):
        name = f'{name} [0x{hex(code)[2:].upper().zfill(8)}]'
    return name

with open(os.path.join(ROOT, '../_common/http_error_code.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write(defaultdict)
    file.write('# HTTP/2 Error Code\n')
    file.write('_ERROR_CODE = defaultdict({\n')

    for item in reader:
        name = item[1]
        dscp = item[2]
        rfcs = item[3]

        temp = list()
        for rfc in filter(None, re.split(r'\[|\]', rfcs)):
            if 'RFC' in rfc:
                temp.append(f'[{rfc[:3]} {rfc[3:]}]')
            else:
                temp.append(f'[{rfc}]')
        desc = f" {''.join(temp)}" if rfcs else ''
        dscp = f' {dscp}' if dscp else ''

        try:
            code = int(item[0], base=16)
            renm = rename(name, code)
            file.write((f"\t0x{hex(code)[2:].upper().zfill(8)} : '{renm}',".ljust(80) + (f'#{desc}{dscp}' if desc or dscp else '')).rstrip() + '\n')
            # print(code, name, ''.join(temp))
        except ValueError:
            continue
            # start, stop = map(lambda s: int(s, base=16), item[0].split('-'))
            # for code in range(start, stop+1):
            #     print(f'0x{hex(code)[2:].upper().zfill(8)}')
            #     renm = rename(name, code)
            #     file.write((f"\t0x{hex(code)[2:].upper().zfill(8)} : '{renm}',".ljust(80) + (f'#{desc}{dscp}' if desc or dscp else '')).rstrip() + '\n')
                # print(code, name, ''.join(temp))
    file.write('})\n')

# with open(os.path.join(ROOT, '../_common/http_error_code.py'), 'w') as file:
#     file.write('# -*- coding: utf-8 -*-\n\n\n')
#     file.write('# HTTP/2 Error Code\n')
#     file.write('_ERROR_CODE = {\n')
#     file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
#     file.write('\n}\n')
