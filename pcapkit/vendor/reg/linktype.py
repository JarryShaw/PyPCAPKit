# -*- coding: utf-8 -*-
"""Link-Layer Header Type Values"""

import re

from pcapkit.vendor.default import Vendor

__all__ = ['LinkType']


class LinkType(Vendor):
    """Link-Layer Header Type Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF'
    #: Link to registry.
    LINK = 'http://www.tcpdump.org/linktypes.html'

    def count(self, data):
        """Count field records."""

    def request(self, text):  # pylint: disable=signature-differs
        """Fetch registry table.

        Args:
            text (str): Context from :attr:`~LinkType.LINK`.

        Returns:
            List[str]: Rows (``tr``) from registry table (``table``).

        """
        table = re.split(r'\<[/]*table.*\>', text)[1]
        return re.split(r'\<tr valign=top\>', table)[1:]

    def process(self, data):
        """Process registry data.

        Args:
            data (List[str]): Registry data.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned_%d' % value, value)",
            'return cls(value)'
        ]
        for content in data:
            item = content.strip().split('<td>')
            name = item[1].strip('</td>')[9:]
            temp = item[2].strip('</td>')
            desc = item[3].strip('</td>')

            try:
                code, _ = temp, int(temp)

                pres = f"{name} = {code}"
                sufs = f"#: ``{desc}``"

                # if len(pres) > 74:
                #     sufs = f"\n{' '*80}{sufs}"

                # enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = map(int, temp.split('-'))
                for code in range(start, stop+1):
                    name = f'USER_{code-start}'
                    desc = f'DLT_USER_{code-start}'

                    pres = f"{name} = {code}"
                    sufs = f"#: ``{desc}``"

                    # if len(pres) > 74:
                    #     sufs = f"\n{' '*80}{sufs}"

                    # enum.append(f'{pres.ljust(76)}{sufs}')
                    enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == "__main__":
    LinkType()
