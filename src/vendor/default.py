# -*- coding: utf-8 -*-
"""Default vendor generation."""

import abc
import collections
import csv
import inspect
import os
import re
import tempfile
import webbrowser

import requests

__all__ = ['Vendor']

# default const file of enumerate registry from IANA CSV
LINE = lambda NAME, DOCS, FLAG, ENUM, MISS: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long

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
        return super()._missing_(value)
'''


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

    def rename(self, name, code):  # pylint: disable=redefined-outer-name
        """Rename duplicated fields.

        Args:
         - `name` -- str, field name
         - `code` -- str, field code

        Returns:
         - `str` -- revised field name

        """
        if self.record[name] > 1:
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

                pres = f"{self.NAME}[{renm!r}] = {code}".ljust(76)
                sufs = re.sub(r'\r*\n', ' ', desc, re.MULTILINE)

                enum.append(f'{pres}{sufs}')
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

    def request(self):
        """Fetch CSV file.

        Returns:
         - `List[str]` -- CSV data

        """
        try:
            page = requests.get(self.LINK)
            data = page.text.strip().split('\r\n')
        except requests.RequestException:
            with tempfile.TemporaryDirectory(prefix=f'{os.path.realpath(os.curdir)}{os.path.sep}') as tempdir:
                temp_file = os.path.join(tempdir, 'index.html')

                webbrowser.open(self.LINK)
                print(f'Please save the CSV code at {temp_file}')
                input('Press ENTER to continue...')

                with open(temp_file) as file:
                    text = file.read()
            data = text.strip().split('\r\n')
        return data

    ###############
    # Defaults
    ###############

    def __init__(self):
        self.NAME = type(self).__name__
        self.DOCS = type(self).__doc__

        data = self.request()
        self.record = self.count(data)

        temp_ctx = list()
        orig_ctx = self.context(data)
        for line in orig_ctx.splitlines():
            if line:
                if line.strip():
                    temp_ctx.append(line)
            else:
                temp_ctx.append(line)
        context = '\n'.join(temp_ctx)

        temp, FILE = os.path.split(os.path.abspath(inspect.getfile(type(self))))
        ROOT, STEM = os.path.split(temp)

        os.makedirs(os.path.join(ROOT, '..', 'const', STEM), exist_ok=True)
        with open(os.path.join(ROOT, '..', 'const', STEM, FILE), 'w') as file:
            print(context, file=file)
