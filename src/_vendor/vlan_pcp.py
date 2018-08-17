# -*- coding: utf-8 -*-


import os
import re

import bs4
import requests


ROOT = os.path.dirname(os.path.abspath(__file__))

page = requests.get('https://en.wikipedia.org/wiki/IEEE_P802.1p#Priority_levels')
soup = bs4.BeautifulSoup(page.text, 'html5lib')

table = soup.find_all('table', class_='wikitable')[0]
content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)

head = next(content)
lidb = list()
for item in content:
    line = item.find_all('td')

    pval = ' '.join(line[0].stripped_strings)
    prio = ' '.join(line[1].stripped_strings)
    abbr = ' '.join(line[2].stripped_strings)
    desc = ' '.join(line[3].stripped_strings)

    match = re.match(r'(\d) *(\(.*\))*', prio)
    group = match.groups()
    lidb.append(f"\t'{bin(int(pval))[2:].zfill(3)}' : '{abbr}',".ljust(80) + f"# {group[0]} - {desc} {group[1] or ''}")
    # print(bin(int(pval))[2:].zfill(3), abbr, desc, group)

with open(os.path.join(ROOT, '../_common/vlan_pcp.py'), 'w') as file:
    file.write('# -*- coding: utf-8 -*-\n\n\n')
    file.write('# priority levels defined in IEEE 802.1p\n')
    file.write('_PCP = {\n')
    file.write('\n'.join(map(lambda s: s.rstrip(), lidb)))
    file.write('\n}\n')
