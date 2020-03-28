# -*- coding: utf-8 -*-
"""Default vendor generation."""

import abc
import collections
import csv
import inspect
import os
import re
import tempfile
import warnings
import webbrowser

import requests

from pcapkit.utilities.exceptions import VendorNotImplemented
from pcapkit.utilities.validations import str_check
from pcapkit.utilities.warnings import VendorRequestWarning

__all__ = ['Vendor']

# default const file of enumerate registry from IANA CSV
LINE = lambda NAME, DOCS, FLAG, ENUM, MISS: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{DOCS}"""

from aenum import IntEnum, extend_enum


class {NAME}(IntEnum):
    """Enumeration class for {NAME}."""
    _ignore_ = '{NAME} _'
    {NAME} = vars()

    # {DOCS}
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
        {MISS}
        {'' if '        return cls(value)' in MISS.splitlines()[-1:] else 'return super()._missing_(value)'}
'''.strip()


def get_proxies():
    """Get proxy for blocked sites."""
    HTTP_PROXY = os.getenv('PCAPKIT_HTTP_PROXY')
    HTTPS_PROXY = os.getenv('PCAPKIT_HTTPS_PROXY')
    PROXIES = dict()
    if HTTP_PROXY is not None:
        str_check(HTTP_PROXY)
        PROXIES['http'] = HTTP_PROXY
    if HTTPS_PROXY is not None:
        str_check(HTTPS_PROXY)
        PROXIES['https'] = HTTPS_PROXY
    return PROXIES


class Vendor(metaclass=abc.ABCMeta):
    """Default vendor generator.

    Inherit this class with `FLAG` & `LINK` attributes,
    etc. to implement a new vendor generator.

    Macros:
     - `FLAG` -- `str`, value limit checker
     - `LINK` -- `str`, link to CSV file

    Processors:
     - `rename` -- rename duplicated fields
     - `process` -- process CSV data
     - `count` -- count field records
     - `context` -- generate constant context
     - `request` -- fetch CSV file

    """
    ###############
    # Macros
    ###############

    # NAME = None
    # DOCS = None
    FLAG = None
    LINK = None

    ###############
    # Processors
    ###############

    def rename(self, name, code, *, original=None):  # pylint: disable=redefined-outer-name
        """Rename duplicated fields.

        Args:
         - `name` -- str, field name
         - `code` -- str, field code

        Returns:
         - `str` -- revised field name

        """
        index = original or name
        if self.record[index] > 1:
            return f'{name} [{code}]'
        return name

    def process(self, data):
        """Process CSV data.

        Args:
         - `data` -- List[str], CSV data

        Returns:
         - `List[str]` -- enumeration fields
         - `List[str]` -- missing fields

        """
        reader = csv.reader(data)
        next(reader)

        enum = list()
        miss = list()
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
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

                pres = f'{self.NAME}[{renm!r}] = {code}'
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                if len(pres) > 74:
                    sufs = f"\n{' '*80}{sufs}"

                enum.append(f'{pres.ljust(76)}{sufs}')
            except ValueError:
                start, stop = item[0].split('-')
                more = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                miss.append(f'if {start} <= value <= {stop}:')
                if more:
                    miss.append(f'    {more}')
                miss.append(f"    extend_enum(cls, '{name} [%d]' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss

    def count(self, data):  # pylint: disable=no-self-use
        """Count field records.

        Args:
         - `data` -- `List[str]`, CSV data

        Returns:
         - `Counter` -- field recordings

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: item[1],  # pylint: disable=map-builtin-not-iterating
                                       filter(lambda item: len(item[0].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

    def context(self, data):
        """Generate constant context.

        Args:
         - `data` -- `List[str]`, CSV data

        Returns:
         - `str` -- constant context

        """
        enum, miss = self.process(data)

        ENUM = '\n    '.join(map(lambda s: s.rstrip(), enum))
        MISS = '\n        '.join(map(lambda s: s.rstrip(), miss))

        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, MISS)

    def request(self, text=None):  # pylint: disable=no-self-use
        """Fetch CSV file.

        Args:
         - `text` -- `str`, context from `LINK`

        Returns:
         - `List[str]` -- CSV data

        """
        return text.strip().split('\r\n')

    ###############
    # Defaults
    ###############

    def __new__(cls):
        if cls is Vendor:
            raise VendorNotImplemented('cannot initiate Vendor instance')
        return super().__new__(cls)

    def __init__(self):
        self.NAME = type(self).__name__
        self.DOCS = type(self).__doc__

        data = self._request()
        self.record = self.count(data)

        temp_ctx = list()
        orig_ctx = self.context(data)
        for line in orig_ctx.splitlines():
            if line:
                if line.strip():
                    temp_ctx.append(line.rstrip())
            else:
                temp_ctx.append(line)
        context = '\n'.join(temp_ctx)

        temp, FILE = os.path.split(os.path.abspath(inspect.getfile(type(self))))
        ROOT, STEM = os.path.split(temp)

        os.makedirs(os.path.join(ROOT, '..', 'const', STEM), exist_ok=True)
        with open(os.path.join(ROOT, '..', 'const', STEM, FILE), 'w') as file:
            print(context, file=file)

    def _request(self):
        if self.LINK is None:
            return self.request()

        try:
            page = requests.get(self.LINK)
        except requests.RequestException:
            warnings.warn('Connection failed; retry with proxies (if any)...', VendorRequestWarning, stacklevel=2)
            try:
                page = requests.get(self.LINK, proxies=get_proxies() or None)
            except requests.RequestException:
                warnings.warn('Connection failed; retry with manual intervene...', VendorRequestWarning, stacklevel=2)
                with tempfile.TemporaryDirectory(suffix='-tempdir',
                                                 prefix='pcapkit-',
                                                 dir=os.path.abspath(os.curdir)) as tempdir:
                    temp_file = os.path.join(tempdir, 'pcapkit-temp.html')

                    webbrowser.open(self.LINK)
                    print(f'Please save the page source at {temp_file}')
                    input('Press ENTER to continue...')

                    with open(temp_file) as file:
                        text = file.read()
            else:
                text = page.text
        else:
            text = page.text
        return self.request(text)
