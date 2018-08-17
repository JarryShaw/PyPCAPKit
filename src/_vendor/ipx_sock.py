# -*- coding: utf-8 -*-


import collections
import os
import re

import bs4
import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number')
soup = bs4.BeautifulSoup(page.text, 'html5lib')

table = soup.find_all('table', class_='wikitable')[3]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)

head = next(content)
lidb = list()
used = list()
enum = list()
for item in content:
    line = item.find_all('td')

    pval = ' '.join(line[0].stripped_strings)
    dscp = ' '.join(line[1].stripped_strings)

    data = list(filter(None, map(lambda s: s.strip(), re.split(r'\W*,|\(|\)\W*', dscp))))
    if len(data) == 2:
        name, desc = data
    else:
        name, desc = dscp, ''

    try:
        code = int(pval, base=16)
        used.append(code)
        lidb.append(f"\t'{hex(code)[2:].upper().zfill(4)}' : '{name}',".ljust(80) + (f'# {desc}' if desc else ''))
    except ValueError:
        enum.append((pval, name, desc))

for pval, name, desc in enum:
    start, stop = map(lambda s: int(s, base=16), pval.split('-'))
    for code in range(start, stop+1):
        if code in used:    continue
        hexd = hex(code)[2:].upper().zfill(4)
        lidb.append(f"\t'{hexd}' : '{name} [0x{hexd}]',".ljust(80) + (f'# {desc}' if desc else ''))

with open(os.path.join(ROOT, '../_common/ipx_sock.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# Socket Types\n')
    file.write('SOCK = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
