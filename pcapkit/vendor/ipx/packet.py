# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
"""IPX Packet Types"""

###############################################################################
import sys
path = sys.path.pop(0)
###############################################################################

import re

import bs4

from pcapkit.vendor.default import Vendor

###############################################################################
sys.path.insert(0, path)
###############################################################################

__all__ = ['Packet']


class Packet(Vendor):
    """IPX Packet Types"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    LINK = 'https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure'

    def count(self, data):
        pass

    def request(self, text):  # pylint: disable=signature-differs
        return bs4.BeautifulSoup(text, 'html5lib')

    def process(self, soup):  # pylint: disable=arguments-differ
        table = soup.find_all('table', class_='wikitable')[1]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)  # pylint: disable=filter-builtin-not-iterating
        next(content)  # header

        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [%d]' % value, value)",
            'return cls(value)'
        ]
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

            pres = "{}[{!r}] = {}".format(self.NAME, name, pval)
            sufs = '# {}'.format(cmmt) if cmmt else ''

            if len(pres) > 74:
                sufs = "\n{}{}".format(' '*80, sufs)

            enum.append('{}{}'.format(pres.ljust(76), sufs))
        return enum, miss


if __name__ == "__main__":
    Packet()
