# -*- coding: utf-8 -*-
"""Base Crawler
==================

.. module:: pcapkit.vendor.default

:mod:`pcapkit.vendor.default` contains :class:`~pcapkit.vendor.default.Vendor`
only, which is the base meta class for all vendor crawlers.

"""
import abc
import collections
import contextlib
import csv
import functools
import importlib.metadata
import inspect
import os
import re
import sys
import tempfile
import textwrap
import webbrowser
from typing import TYPE_CHECKING

import requests

from pcapkit import __version__
from pcapkit.utilities.exceptions import VendorNotImplemented
from pcapkit.utilities.logging import BOOLEAN_STATES
from pcapkit.utilities.warnings import VendorRequestWarning, warn

if TYPE_CHECKING:
    from collections import Counter
    from typing import Callable, Optional

__all__ = ['Vendor']

MAX_RETRY = int(os.environ.get('PCAPKIT_VENDOR_RETRY', 5)) or 1
CI_MODE = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_CI_MODE', 'false').casefold(), False)

#: Distribution name of this package, i.e. the name its metadata is registered
#: under, which is not the import name (:mod:`pcapkit`).
DISTRIBUTION = 'pypcapkit'

#: Project URL used as the contact address in :func:`get_user_agent` when the
#: distribution metadata cannot be read, i.e. when running straight from a
#: source checkout that was never installed. Kept in step with ``repository``
#: under ``[project.urls]`` in :file:`pyproject.toml`.
PROJECT_URL = 'https://github.com/JarryShaw/PyPCAPKit'

#: Default constant template of enumerate registry from IANA CSV.
LINE = lambda NAME, DOCS, FLAG, ENUM, MISS, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['{NAME}']


class {NAME}(IntEnum):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found. The placeholder ``-1`` stands
                for *no default*, in which case an unresolvable key propagates
                the lookup error instead of falling back.

        :meta private:
        """
        if isinstance(key, int):
            try:
                return {NAME}(key)
            except ValueError:
                if default == -1:
                    raise
                return {NAME}(default)
        if key not in {NAME}._member_map_:  # pylint: disable=no-member
            return extend_enum({NAME}, key, default)
        return {NAME}[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        {MISS}
        {'' if (test := ''.join(MISS.splitlines()[-1:])).startswith('return') or test[8:].startswith('return') else 'return super()._missing_(value)'}
'''.strip()  # type: Callable[[str, str, str, str, str, str], str]


def get_proxies() -> 'dict[str, str]':
    """Get proxy for blocked sites.

    The function will read :envvar:`PCAPKIT_HTTP_PROXY`
    and :envvar:`PCAPKIT_HTTPS_PROXY`, if any, for the
    proxy settings of |requests|_.

    .. |requests| replace:: ``requests``
    .. _requests: https://requests.readthedocs.io

    Returns:
        Proxy settings for |requests|_.

    """
    HTTP_PROXY = os.getenv('PCAPKIT_HTTP_PROXY')
    HTTPS_PROXY = os.getenv('PCAPKIT_HTTPS_PROXY')
    PROXIES = {}  # type: dict[str, str]
    if HTTP_PROXY is not None:
        PROXIES['http'] = HTTP_PROXY
    if HTTPS_PROXY is not None:
        PROXIES['https'] = HTTPS_PROXY
    return PROXIES


@functools.lru_cache(maxsize=1)
def get_user_agent() -> 'str':
    """Get the ``User-Agent`` header the crawlers identify themselves with.

    Many :attr:`~Vendor.LINK` registries are Wikipedia articles, and the
    Wikimedia Foundation's User-Agent policy refuses |requests|_' default
    ``python-requests/<version>`` agent outright -- HTTP 403 with a body reading
    *"Please set a user-agent and respect our robot policy"*. What the policy
    asks for is an agent that names the tool and gives a contact address, so that
    a misbehaving client can be reached instead of simply blocked. It does
    **not** ask for a browser agent, and sending one would misrepresent what is
    making the request, so this deliberately identifies the crawler as itself.

    The string is composed from the package's own metadata -- distribution name,
    :data:`pcapkit.__version__` and the ``repository`` project URL -- rather than
    written out as a literal, so that it follows the package instead of going
    stale. Where the distribution metadata cannot be read, i.e. when running from
    a source checkout that was never installed, :data:`DISTRIBUTION` and
    :data:`PROJECT_URL` stand in for it.

    Returns:
        Value for the ``User-Agent`` request header.

    See Also:
        `Wikimedia Foundation User-Agent policy
        <https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_User-Agent_Policy>`__

    """
    name = DISTRIBUTION
    url = PROJECT_URL

    with contextlib.suppress(importlib.metadata.PackageNotFoundError):
        metadata = importlib.metadata.metadata(DISTRIBUTION)

        name = metadata.get('Name') or name
        for entry in metadata.get_all('Project-URL') or []:
            label, _, value = entry.partition(',')
            if label.strip().casefold() == 'repository' and value.strip():
                url = value.strip()
                break

    return f'{name}/{__version__} (+{url}) python-requests/{requests.__version__}'


def stdin_is_interactive() -> 'bool':
    """Whether there is somebody at a keyboard to be prompted.

    :meth:`Vendor._request`'s last resort is to ask an operator to fetch the page
    by hand, which needs a terminal: a process whose ``stdin`` is a pipe, a file,
    or :file:`/dev/null` has nobody to open a browser for and nobody who could
    ever save the file that path then waits for.

    ``stdin`` can be absent rather than merely redirected, and it can stop being
    usable while the process runs, so neither is allowed to propagate out of a
    predicate: :data:`sys.stdin` is :obj:`None` under a GUI launcher such as
    :program:`pythonw`, and one that has been closed raises :exc:`ValueError` from
    :meth:`~io.IOBase.isatty` instead of answering. Every such case counts as
    *not* interactive, which is the conservative answer -- it costs a crawler the
    manual-intervention path it could not have used anyway.

    Returns:
        Whether :data:`sys.stdin` is attached to a terminal.

    """
    stdin = getattr(sys, 'stdin', None)
    if stdin is None:
        return False
    try:
        return bool(stdin.isatty())
    except (AttributeError, ValueError, OSError):
        return False


class VendorMeta(abc.ABCMeta):
    """Meta class to add dynamic support to :class:`Vendor`.

    This meta class is used to generate necessary attributes for the
    :class:`Vendor` class. It can be useful to reduce unnecessary
    registry calls and simplify the customisation process.

    """


class Vendor(metaclass=VendorMeta):
    """Default vendor generator.

    Inherit this class with :attr:`~Vendor.FLAG` &
    :attr:`~Vendor.LINK` attributes, etc., to implement
    a new vendor generator.

    """
    ###############
    # Macros
    ###############

    #: Name of constant enumeration.
    NAME: 'str'
    #: Docstring of constant enumeration.
    DOCS: 'str'

    #: Value limit checker.
    FLAG: 'str' = None  # type: ignore[assignment]
    #: Link to registry.
    LINK: 'str' = None  # type: ignore[assignment]

    ###############
    # Processors
    ###############

    @staticmethod
    def wrap_comment(text: 'str') -> 'str':
        """Wraps long-length text to shorter lines of comments.

        Args:
            text: Source text.

        Returns:
            Wrapped comments.

        """
        return '\n    #: '.join(textwrap.wrap(text.strip(), 76))

    def safe_name(self, name: 'str') -> 'str':
        """Convert enumeration name to :class:`enum.Enum` friendly.

        Args:
            name: original enumeration name

        Returns:
            Converted enumeration name.

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

    def rename(self, name: 'str', code: 'str', *, original: 'Optional[str]' = None) -> 'str':  # pylint: disable=redefined-outer-name
        """Rename duplicated fields.

        Args:
            name: Field name.
            code: Field code.
            original: Original field name (extracted from CSV records).

        Returns:
            Revised field name.

        Example:
            If ``name`` has multiple occurrences in the source registry,
            the field name will be sanitised as ``${name}_${code}``.

            Otherwise, the plain ``name`` will be returned.

        """
        index = original or name
        if self.record[self.safe_name(index)] > 1 or self.safe_name(index).upper() in ['RESERVED', 'UNASSIGNED']:
            name = f'{name}_{code}'
        return self.safe_name(name)

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)

        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in reader:
            name = item[1]
            rfcs = item[2]

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp_split = rfc[3:].split(', ', maxsplit=1)
                    if len(temp_split) > 1:
                        temp.append(f'[:rfc:`{temp_split[0]}#{temp_split[1].lower()}`]'.replace(' ', '-'))
                    else:
                        temp.append(f'[:rfc:`{temp_split[0]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', '%s %s' % (  # pylint: disable=consider-using-f-string
                name, ''.join(temp) if rfcs else '',
            ), re.MULTILINE))

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
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
        return enum, miss

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[1]),
                                       filter(lambda item: len(item[0].split('-')) != 2, reader)))

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        enum, miss = self.process(data)

        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum)).strip()
        MISS = '\n        '.join(map(lambda s: s.rstrip(), miss)).strip()

        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, MISS, self.__module__)

    def request(self, text: 'Optional[str]' = None) -> 'list[str]':
        """Fetch CSV file.

        Args:
            text: Context from :attr:`~Vendor.LINK`.

        Returns:
            CSV data.

        """
        if text is None:
            return []
        return text.strip().split('\r\n')

    ###############
    # Defaults
    ###############

    def __new__(cls) -> 'Vendor':
        """Subclassing checkpoint.

        Raises:
            VendorNotImplemented: If ``cls`` is not a subclass of
                :class:`~pcapkit.vendor.default.Vendor`.

        """
        if cls is Vendor:
            raise VendorNotImplemented('cannot initiate Vendor instance')
        return super().__new__(cls)

    def __init__(self) -> 'None':
        """Generate new constant files."""
        #: Name of constant enumeration.
        self.NAME = type(self).__name__
        #: Docstring of constant enumeration.
        self.DOCS = type(self).__doc__  # type: ignore[assignment]

        data = self._request()
        self.record = self.count(data)

        temp_ctx = []  # type: list[str]
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
        with open(os.path.join(ROOT, '..', 'const', STEM, FILE), 'w') as file:  # pylint: disable=unspecified-encoding
            print(context, file=file)

    def _request(self) -> 'list[str]':
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

        That last resort is only taken when somebody can actually act on it, i.e.
        when :envvar:`PCAPKIT_CI_MODE` is unset *and*
        :func:`stdin_is_interactive` finds a terminal. A non-interactive run --
        under a pipe, in a container, from a scheduled job -- is failed with the
        fetch error instead, the same way :envvar:`PCAPKIT_CI_MODE` fails it,
        rather than printing instructions nobody will read. See #522.

        Returns:
            CSV data.

        Raises:
            requests.RequestException: If the registry could not be fetched and
                manual intervention is unavailable, i.e. under
                :envvar:`PCAPKIT_CI_MODE`, with no interactive ``stdin``, or where
                the prompt itself fails because ``stdin`` went away mid-wait.

        Warns:
            VendorRequestWarning: If connection failed with and/or without proxies.

        See Also:
            :meth:`~Vendor.request`

        """
        if self.LINK is None:
            return self.request()  # type: ignore[unreachable]

        # NOTE: both branches below send this. Wikimedia rejects ``requests``'
        # default agent with HTTP 403, so a crawler without it fetches 126 bytes
        # of robot-policy text and retries MAX_RETRY times against a refusal
        # that no amount of retrying will lift; see #518.
        headers = {'User-Agent': get_user_agent()}

        try:
            counter = 1
            while True:
                if counter > MAX_RETRY:
                    raise requests.exceptions.RequestException

                page = requests.get(self.LINK, headers=headers)  # nosec: B113
                if not page.ok or not page.text:
                    warn(f'Connection failed; retry for {counter}/{MAX_RETRY}...',
                         VendorRequestWarning, stacklevel=2)

                    counter += 1
                    continue
                break
        except requests.RequestException:
            warn('Connection failed; retry with proxies (if any)...',
                 VendorRequestWarning, stacklevel=2)

            try:
                proxies = get_proxies() or None
                if proxies is None:
                    raise

                counter = 1
                while True:
                    if counter > MAX_RETRY:
                        raise

                    page = requests.get(self.LINK, headers=headers, proxies=proxies)  # nosec: B113
                    if not page.ok or not page.text:
                        warn(f'Connection failed; retry with proxy for {counter}/{MAX_RETRY}...',
                             VendorRequestWarning, stacklevel=2)

                        counter += 1
                        continue
                    break
            except requests.RequestException as error:
                if CI_MODE:
                    warn('Connection failed; exit on CI mode...',
                         VendorRequestWarning, stacklevel=2)
                    raise

                if not stdin_is_interactive():
                    # NOTE: manual intervention needs an operator, and a process
                    # with no terminal has none -- nobody to read the instructions
                    # below, nobody to save the page, so the wait it ends in could
                    # only ever time out the whole run. Fail exactly as CI_MODE
                    # does rather than prompting into the void; see #522.
                    warn('Connection failed; exit as stdin is not interactive...',
                         VendorRequestWarning, stacklevel=2)
                    raise

                warn('Connection failed; retry with manual intervene...',
                     VendorRequestWarning, stacklevel=2)
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
                        try:
                            input('Press ENTER to continue...')  # nosec
                        except Exception as exc:
                            # NOTE: whatever stopped the prompt, ``input()`` is no
                            # longer waiting -- and this loop only waits because
                            # ``input()`` does, so the file it waits for can never
                            # arrive. Discarding the exception, as this used to,
                            # left a ``while True`` that printed three lines per
                            # iteration at full speed: 26.7 million lines and 2.6 GB
                            # measured in #522. The terminal this started on can
                            # still go away mid-wait -- a closed ``stdin`` raises
                            # :exc:`ValueError`, a dropped one :exc:`EOFError`, a
                            # vanished :data:`sys.stdin` :exc:`RuntimeError` -- so the
                            # check before the prompt does not make this redundant.
                            # ``KeyboardInterrupt`` is not an :exc:`Exception` and so
                            # still aborts as itself.
                            warn(f'Connection failed; cannot prompt for manual intervene ({exc})...',
                                 VendorRequestWarning, stacklevel=2)
                            raise error from exc
                        if os.path.isfile(temp_file):
                            break
                        print('File not found; please save the page source at')
                        print(f'    {temp_file}')

                    with open(temp_file) as file:  # pylint: disable=unspecified-encoding
                        text = file.read()
            else:
                text = page.text
        else:
            text = page.text
        return self.request(text)
