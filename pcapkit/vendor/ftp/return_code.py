# -*- coding: utf-8 -*-
"""FTP Server Return Code"""

import bs4

from pcapkit.vendor.default import Vendor

__all__ = ['ReturnCode']

LINE = lambda NAME, DOCS, FLAG, ENUM: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{DOCS}"""

from aenum import IntEnum, extend_enum

__all__ = ['{NAME}']

#: Response kind; whether the response is good, bad or incomplete.
KIND = {{
    '1': 'Positive Preliminary',
    '2': 'Positive Completion',
    '3': 'Positive Intermediate',
    '4': 'Transient Negative Completion',
    '5': 'Permanent Negative Completion',
    '6': 'Protected',
}}

#: Grouping information.
INFO = {{
    '0': 'Syntax',
    '1': 'Information',
    '2': 'Connections',
    '3': 'Authentication and accounting',
    '4': 'Unspecified',                     # [RFC 959]
    '5': 'File system',
}}


class {NAME}(IntEnum):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return {NAME}(key)
        if key not in {NAME}._member_map_:  # pylint: disable=no-member
            extend_enum({NAME}, key, default)
        return {NAME}[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        code = str(value)
        kind = KIND.get(code[0], 'Reserved')
        info = INFO.get(code[1], 'Reserved')
        extend_enum(cls, '%s - %s [%s]' % (kind, info, value), value)
        return cls(value)
'''


class ReturnCode(Vendor):
    """FTP Server Return Code"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 100 <= value <= 659'
    #: Link to registry.
    LINK = 'https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes'

    def request(self, text):  # pylint: disable=signature-differs
        """Fetch registry data.

        Args:
            text (str): Context from :attr:`~ReturnCode.LINK`.

        Returns:
            bs4.BeautifulSoup: Parsed HTML source.

        """
        return bs4.BeautifulSoup(text, 'html5lib')

    def context(self, soup):  # pylint: disable=arguments-differ
        """Generate constant context.

        Args:
            soup (bs4.BeautifulSoup): Parsed HTML source.

        Returns:
            str: Constant context.

        """
        enum = self.process(soup)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum))
        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM)

    def process(self, soup):  # pylint: disable=arguments-differ
        """Process registry data.

        Args:
            soup (bs4.BeautifulSoup): Parsed HTML source.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
        table = soup.find_all('table', class_='wikitable')[2]
        content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)  # pylint: disable=filter-builtin-not-iterating
        next(content)  # header

        enum = list()
        for item in content:
            line = item.find_all('td')

            code = ' '.join(line[0].stripped_strings)
            if len(code) != 3:
                continue

            #desc = f"{' '.join(line[1].stripped_strings).split('.')[0].strip()}."
            #enum.append(f'{self.NAME}[{self.rename(desc, code)!r}] = {code}')

            sufs = self.wrap_comment('. '.join(map(lambda s: s.strip(), ' '.join(line[1].stripped_strings).split('.'))))
            pref = f"CODE_{code} = {code}"

            enum.append(f'#: {sufs}\n    {pref}')
        return enum

    def count(self, soup):  # pylint: disable=arguments-differ, no-self-use
        """Count field records."""
        #table = soup.find_all('table', class_='wikitable')[2]
        #content = filter(lambda item: isinstance(item, bs4.element.Tag), table.tbody)  # pylint: disable=filter-builtin-not-iterating
        #next(content)  # header

        #temp = list()
        #for item in content:
        #    line = item.find_all('td')

        #    code = ' '.join(line[0].stripped_strings)
        #    if len(code) != 3:
        #        continue
        #    desc = f"{' '.join(line[1].stripped_strings).split('.')[0].strip()}."
        #    temp.append(desc)
        #return collections.Counter(temp)


if __name__ == "__main__":
    ReturnCode()
