# -*- coding: utf-8 -*-
"""Default vendor generation."""

import abc
import collections
import contextlib
import csv
import inspect
import os
import re
import tempfile
import textwrap
import warnings
import webbrowser

import requests

from pcapkit.utilities.exceptions import VendorNotImplemented
from pcapkit.utilities.warnings import VendorRequestWarning

__all__ = ['Vendor']

#: Default constant template of enumerate registry from IANA CSV.
LINE = lambda NAME, DOCS, FLAG, ENUM, MISS: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{DOCS}"""

from aenum import IntEnum, extend_enum

__all__ = ['{NAME}']


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
        {MISS}
        {'' if '        return cls(value)' in MISS.splitlines()[-1:] else 'return super()._missing_(value)'}
'''.strip()


def get_proxies():
    """Get proxy for blocked sites.

    The function will read :envvar:`PCAPKIT_HTTP_PROXY`
    and :envvar:`PCAPKIT_HTTPS_PROXY`, if any, for the
    proxy settings of |requests|_.

    .. |requests| replace:: ``requests``
    .. _requests: https://requests.readthedocs.io

    Returns:
        Dict[str, str]: Proxy settings for |requests|_.

    """
    HTTP_PROXY = os.getenv('PCAPKIT_HTTP_PROXY')
    HTTPS_PROXY = os.getenv('PCAPKIT_HTTPS_PROXY')
    PROXIES = dict()
    if HTTP_PROXY is not None:
        PROXIES['http'] = HTTP_PROXY
    if HTTPS_PROXY is not None:
        PROXIES['https'] = HTTPS_PROXY
    return PROXIES


class Vendor(metaclass=abc.ABCMeta):
    """Default vendor generator.

    Inherit this class with :attr:`~Vendor.FLAG` &
    :attr:`~Vendor.LINK` attributes, etc. to implement
    a new vendor generator.

    """
    ###############
    # Macros
    ###############

    # NAME = None
    # DOCS = None

    #: str: Value limit checker.
    FLAG = None
    #: str: Link to registry.
    LINK = None

    ###############
    # Processors
    ###############

    @staticmethod
    def wrap_comment(text):
        """Wraps long-length text to shorter lines of comments.

        Args:
            text (str): Source text.

        Returns:
            Wrapped comments.

        """
        return '\n    #: '.join(textwrap.wrap(text.strip(), 76))

    def safe_name(self, name):
        """Convert enumeration name to :class:`enum.Enum` friendly.

        Args:
            name (str): original enumeration name

        Returns:
            str: Converted enumeration name.

        """
        temp = '_'.join(
            filter(
                None,
                re.sub(
                    r'\W',
                    '_',
                    '_'.join(
                        re.sub(
                            r'\(.*\)',
                            '',
                            name
                        ).split(),
                    ),
                ).split('_')
            )
        )
        if temp.isidentifier():
            return temp
        return f'{self.NAME}_{temp}'

    def rename(self, name, code, *, original=None):  # pylint: disable=redefined-outer-name
        """Rename duplicated fields.

        Args:
            name (str): Field name.
            code (int): Field code.

        Keyword Args:
            original (str): Original field name (extracted from CSV records).

        Returns:
            str: Revised field name.

        Example:
            If ``name`` has multiple occurrences in the source registry,
            the field name will be sanitised as ``${name}_${code}``.

            Otherwise, the plain ``name`` will be returned.

        """
        index = original or name
        if self.record[self.safe_name(index)] > 1:
            name = f'{name}_{code}'
        return self.safe_name(name)

    def process(self, data):
        """Process CSV data.

        Args:
            data (List[str]): CSV data.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

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
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', f"{name} {''.join(temp) if rfcs else ''}", re.MULTILINE))

            try:
                code, _ = item[0], int(item[0])
                renm = self.rename(name, code)

                pres = f'{renm} = {code}'
                sufs = f'#: {desc}'

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
                miss.append('    return cls(value)')
        return enum, miss

    def count(self, data):  # pylint: disable=no-self-use
        """Count field records.

        Args:
            data (List[str]): CSV data.

        Returns:
            Counter: Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[1]),  # pylint: disable=map-builtin-not-iterating
                                       filter(lambda item: len(item[0].split('-')) != 2, reader)))  # pylint: disable=filter-builtin-not-iterating

    def context(self, data):
        """Generate constant context.

        Args:
            data (List[str]): CSV data.

        Returns:
            str: Constant context.

        """
        enum, miss = self.process(data)

        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum)).strip()
        MISS = '\n        '.join(map(lambda s: s.rstrip(), miss)).strip()

        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, MISS)

    def request(self, text=None):  # pylint: disable=no-self-use
        """Fetch CSV file.

        Args:
            text (str): Context from :attr:`~Vendor.LINK`.

        Returns:
            List[str]: CSV data.

        """
        if text is None:
            return list()
        return text.strip().split('\r\n')

    ###############
    # Defaults
    ###############

    def __new__(cls):
        """Subclassing checkpoint.

        Raises:
            VendorNotImplemented: If ``cls`` is not a subclass of :class:`~pcapkit.vendor.default.Vendor`.

        """
        if cls is Vendor:
            raise VendorNotImplemented('cannot initiate Vendor instance')
        return super().__new__(cls)

    def __init__(self):
        """Generate new constant files."""
        #: str: Name of constant enumeration.
        self.NAME = type(self).__name__
        #: str: Docstring of constant enumeration.
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
        """Fetch CSV data from :attr:`~Vendor.LINK`.

        This is the low-level call of :meth:`~Vendor.request`.

        If :attr:`~Vendor.LINK` is ``None``, it will directly
        call the upper method :meth:`~Vendor.request` with **NO**
        arguments.

        The method will first try to *GET* the content of :attr:`~Vendor.LINK`.
        Should any exception raised, it will first try with proxy settings from
        :func:`~pcapkit.vendor.default.get_proxies`.

        .. note::

           Since some :attr:`~Vendor.LINK` links are from Wikipedia, etc., they
           might not be available in certain areas, e.g. the amazing PRC :)

        Would proxies failed again, it will prompt for user intervention, i.e.
        it will use :func:`webbrowser.open` to open the page in browser for you, and
        you can manually load that page and save the HTML source at the location
        it provides.

        Returns:
            List[str]: CSV data.

        Warns:
            VendorRequestWarning: If connection failed with and/or without proxies.

        See Also:
            :meth:`~Vendor.request`

        """
        if self.LINK is None:
            return self.request()

        try:
            page = requests.get(self.LINK)
        except requests.RequestException:
            warnings.warn('Connection failed; retry with proxies (if any)...', VendorRequestWarning, stacklevel=2)
            try:
                proxies = get_proxies() or None
                if proxies is None:
                    raise requests.RequestException
                page = requests.get(self.LINK, proxies=proxies)
            except requests.RequestException:
                warnings.warn('Connection failed; retry with manual intervene...', VendorRequestWarning, stacklevel=2)
                with tempfile.TemporaryDirectory(suffix='-tempdir',
                                                 prefix='pcapkit-',
                                                 dir=os.path.abspath(os.curdir)) as tempdir:
                    temp_file = os.path.join(tempdir, f'{self.NAME}.html')

                    flag = False
                    with contextlib.suppress(Exception):
                        flag = webbrowser.open(self.LINK)

                    if flag:
                        print('Please save the page source at')
                        print(f'    {temp_file}')
                    else:
                        print('Please navigate to the following address')
                        print(f'    {self.LINK}')
                        print('and save the page source at')
                        print(f'    {temp_file}')

                    while True:
                        with contextlib.suppress(Exception):
                            input('Press ENTER to continue...')  # nosec
                        if os.path.isfile(temp_file):
                            break
                        print('File not found; please save the page source at')
                        print(f'    {temp_file}')

                    with open(temp_file) as file:
                        text = file.read()
            else:
                text = page.text
        else:
            text = page.text
        return self.request(text)
