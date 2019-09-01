# -*- coding: utf-8 -*-
"""Link-Layer Header Type Values"""

import re

from pcapkit.vendor.default import Vendor

__all__ = ['LinkType']


class LinkType(Vendor):
    """Link-Layer Header Type Values"""

    FLAG = 'isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF'
    LINK = 'http://www.tcpdump.org/linktypes.html'

    def count(self, data):
        pass

    def request(self, text):  # pylint: disable=signature-differs
        table = re.split(r'\<[/]*table.*\>', text)[1]
        return re.split(r'\<tr valign=top\>', table)[1:]

    def process(self, data):
        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned [%d]' % value, value)",
            'return cls(value)'
        ]
        for content in data:
            item = content.strip().split('<td>')
            name = item[1].strip('</td>')[9:]
            temp = item[2].strip('</td>')
            desc = item[3].strip('</td>')

            try:
                code, _ = temp, int(temp)

                pres = "{}[{!r}] = {}".format(self.NAME, name, code)
                sufs = "# {}".format(desc)

                if len(pres) > 74:
                    sufs = "\n{}{}".format(' '*80, sufs)

                enum.append('{}{}'.format(pres.ljust(76), sufs))
            except ValueError:
                start, stop = map(int, temp.split('-'))
                for code in range(start, stop+1):
                    name = 'USER{}'.format(code-start)
                    desc = 'DLT_USER{}'.format(code-start)

                    pres = "{}[{!r}] = {}".format(self.NAME, name, code)
                    sufs = "# {}".format(desc)

                    if len(pres) > 74:
                        sufs = "\n{}{}".format(' '*80, sufs)

                    enum.append('{}{}'.format(pres.ljust(76), sufs))
        return enum, miss


if __name__ == "__main__":
    LinkType()
