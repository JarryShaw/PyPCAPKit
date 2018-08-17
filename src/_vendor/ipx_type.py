# -*- coding: utf-8 -*-


import os
import re

import bs4
import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure')
soup = bs4.BeautifulSoup(page.text, 'html5lib')

table = soup.find_all('table', class_='wikitable')[1]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)

head = next(content)
lidb = list()
for item in content:
    line = item.find_all('td')

    pval = ''.join(line[0].stripped_strings)
    desc = ''.join(line[1].stripped_strings)

    split = desc.split(' (', 1)
    if len(split) == 2:
        name = split[0]
        cmmt = re.sub(r'(RFC \d+)', r'[\1]', re.sub(r',([^ ])', r', \1', split[1].replace(')', '', 1)))
    else:
        name, cmmt = desc, ''

    lidb.append(f"{pval:>5} : '{name}',".ljust(80) + (f'# {cmmt}' if cmmt else ''))
    # print(pval, name, cmmt)

with open(os.path.join(ROOT, '../_common/ipx_type.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# IPX Packet Types\n')
    file.write('TYPE = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
