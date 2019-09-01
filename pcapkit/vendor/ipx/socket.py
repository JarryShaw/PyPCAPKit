# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
"""IPX Socket Types"""

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

__all__ = ['Socket']


class Socket(Vendor):
    """Socket Types"""

    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    LINK = 'https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number'

    def count(self, data):
        pass

    def request(self, text):  # pylint: disable=signature-differs
        return bs4.BeautifulSoup(text, 'html5lib')

    def process(self, soup):  # pylint: disable=arguments-differ
        table = soup.find_all('table', class_='wikitable')[3]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)  # pylint: disable=filter-builtin-not-iterating
        next(content)  # header

        enum = list()
        miss = list()
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
                code, _ = pval, int(pval, base=16)

                pres = "{}[{!r}] = {}".format(self.NAME, name, code)
                sufs = '# {}'.format(desc) if desc else ''

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = pval.split('–')

                miss.append('if {} <= value <= {}:'.format(start, stop))
                if desc:
                    miss.append('    # {}'.format(desc))
                miss.append(
                    "    extend_enum(cls, '{} [0x%s]' % hex(value)[2:].upper().zfill(4), value)".format(name))
                miss.append('    return cls(value)')
        return enum, miss


if __name__ == "__main__":
    Socket()
