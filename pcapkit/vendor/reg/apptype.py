# -*- coding: utf-8 -*-
"""Application Layer Protocol Numbers
========================================

.. module:: pcapkit.vendor.reg.apptype

This module contains the vendor crawler for **Application Layer Protocol Numbers**,
which is automatically generating :class:`pcapkit.const.reg.apptype.AppType`.

"""

import collections
import csv
import keyword
import re
import sys
import textwrap
from typing import TYPE_CHECKING, Callable

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter, OrderedDict
    from typing import Callable

__all__ = ['AppType']

LINE = lambda NAME, DOCS, FLAG, ENUM, MISS, MODL: f'''\
# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""
from collections import defaultdict
from typing import TYPE_CHECKING

from aenum import IntFlag, StrEnum, auto, extend_enum

from pcapkit.utilities.compat import show_flag_values

__all__ = ['{NAME}']

if TYPE_CHECKING:
    from typing import Any, DefaultDict, Type


class TransportProtocol(IntFlag):
    """Transport layer protocol."""

    undefined = 0

    #: Transmission Control Protocol.
    tcp = auto()
    #: User Datagram Protocol.
    udp = auto()
    #: Stream Control Transmission Protocol.
    sctp = auto()
    #: Datagram Congestion Control Protocol.
    dccp = auto()

    @staticmethod
    def get(key: 'int | str') -> 'TransportProtocol':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.

        :meta private:
        """
        if isinstance(key, int):
            return TransportProtocol(key)
        if key.lower() in TransportProtocol.__members__:
            return TransportProtocol[key.lower()]  # type: ignore[misc]
        max_val = max(TransportProtocol.__members__.values())
        return extend_enum(TransportProtocol, key.lower(), max_val * 2)


class {NAME}(StrEnum):
    """[{NAME}] {DOCS}"""

    if TYPE_CHECKING:
        #: Service name.
        svc: 'str'
        #: Port number.
        port: 'int'
        #: Transport protocol.
        proto: 'TransportProtocol'

    #: Mapping of members based on transport protocol.
    __members_proto__: 'DefaultDict[TransportProtocol, dict[int, {NAME}]]' = defaultdict(dict)

    def __new__(cls, value: 'int', name: 'str' = '<null>',
                proto: 'TransportProtocol' = TransportProtocol.undefined) -> 'Type[{NAME}]':
        temp = '%s [%d - %s]' % (name, value, proto.name)

        obj = str.__new__(cls, temp)
        obj._value_ = temp

        obj.svc = name
        obj.port = value
        obj.proto = proto

        for namespace in show_flag_values(proto):
            cls.__members_proto__[TransportProtocol(namespace)][value] = obj
        if proto is TransportProtocol.undefined:
            cls.__members_proto__[proto][value] = obj

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s: %d [%s]>" % (self.__class__.__name__, self.svc, self.port, self.proto.name)

    def __str__(self) -> 'str':
        return '%s [%d - %s]' % (self.svc, self.port, self.proto.name)

    def __int__(self) -> 'int':
        return self.port

    def __lt__(self, other: '{NAME}') -> 'bool':
        return self.port < other

    def __gt__(self, other: '{NAME}') -> 'bool':
        return self.port > other

    def __le__(self, other: '{NAME}') -> 'bool':
        return self.port <= other

    def __ge__(self, other: '{NAME}') -> 'bool':
        return self.port >= other

    def __eq__(self, other: 'Any') -> 'bool':
        return self.port == other

    def __ne__(self, other: 'Any') -> 'bool':
        return self.port != other

    def __hash__(self) -> 'int':
        return hash(self.port)

    {ENUM}

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1, *,
            proto: 'TransportProtocol | str' = TransportProtocol.undefined) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.
            proto: Transport protocol of the enum item.

        :meta private:
        """
        if isinstance(key, int):
            if isinstance(proto, str):
                proto = TransportProtocol.get(proto.lower())
            temp_ns = {NAME}.__members_proto__.get(proto, {{}})
            if key in temp_ns:
                return temp_ns[key]
            try:
                ret = {NAME}._missing_(key)
                if ret is None:
                    raise ValueError
            except ValueError:

                ret = extend_enum({NAME}, 'PORT_%d_%s' % (key, proto.name), key, 'unknown', proto)
            return ret
        if key in {NAME}.__members_proto__:
            return getattr({NAME}, key)
        return extend_enum({NAME}, key, default, key)

    @classmethod
    def _missing_(cls, value: 'int') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if value in cls.__members_proto__.get(TransportProtocol.undefined, {{}}):  # type: ignore[call-overload]
            return cls.__members_proto__[TransportProtocol.undefined][value]  # type: ignore[index]
        {MISS}
        {'' if ''.join(MISS.splitlines()[-1:]).startswith('return') else 'return super()._missing_(value)'}
'''.strip()  # type: Callable[[str, str, str, str, str, str], str]


class AppType(Vendor):
    """Application Layer Protocol Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records."""
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: '[%s] %s' % (item[2], item[0].strip() or self.safe_name(item[3].strip())),
                                       filter(lambda item: len(item[1].split('-')) != 2, reader)))

    @staticmethod
    def wrap_comment(text: 'str') -> 'str':
        """Wraps long-length text to shorter lines of comments.

        Args:
            text: Source text.

        Returns:
            Wrapped comments.

        """
        return '\n    #:   '.join(textwrap.wrap(text.strip(), 76))

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        miss = []  # type: list[str]

        line = collections.OrderedDict()  # type: OrderedDict[str, list[str]]
        for item in reader:
            svc = item[0].strip().lower() or self.safe_name(item[3].strip()).lower()
            port = item[1].strip() or '-1'
            proto = 'TransportProtocol.get(%r)' % (item[2].strip().lower() or 'undefined')
            desc = item[3].strip()

            temp = []  # type: list[str]
            #for rfc in filter(lambda s: 'RFC' in s, re.split(r'\[|\]', item[8])):
            #    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
            for rfc in filter(None, map(lambda s: s.strip(), re.split(r'\[|\]', item[8]))):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    match = re.fullmatch(r'RFC(?P<rfc>\d+)(, Section (?P<sec>.*?))?', rfc)
                    if match is None:
                        temp.append(f'[{rfc}]')
                    else:
                        if match.group('sec') is not None:
                            temp.append(f'[:rfc:`{match.group("rfc")}#{match.group("sec")}`]')
                        else:
                            temp.append(f'[:rfc:`{match.group("rfc")}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            cmmt = self.wrap_comment(re.sub(r'\s+', r' ',
                                            '[%s] %s %s' % (item[2].strip().upper() or 'N/A',
                                                            desc, ''.join(temp))))  # pylint: disable=consider-using-f-string

            try:
                code, _ = port, int(port)
                if port == '-1':
                    code = 'null'
                renm = self.rename(svc, code)

                if f'{renm}_{code}' in line:
                    renm = f'{renm}_{code}'

                if renm in line:
                    if port == line[renm][1]:
                        line[renm][2] = f'{line[renm][2]} | {proto}'
                        if line[renm][3].startswith('-'):
                            line[renm][3] = f'{line[renm][3]}\n    #: - {cmmt}'
                        else:
                            line[renm][3] = f'- {line[renm][3]}\n    #: - {cmmt}'
                    else:
                        line[f'{renm}_{line[renm][1]}'] = line[renm]
                        line[f'{renm}_{code}'] = [svc, port, proto, cmmt]
                        del line[renm]
                else:
                    line[renm] = [svc, port, proto, cmmt]

                # if port == '-1':
                #     continue
                # proto_name = item[2].strip().lower()

                # if proto_name:
                #     renm = f'PORT_{code}_{proto_name}'
                # else:
                #     renm = f'PORT_{code}'
                # line[renm] = [svc, code, proto, cmmt]
            except ValueError:
                start, stop = port.split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {cmmt}')
                miss.append(f"    return extend_enum(cls, '{self.safe_name(svc)}_%d' % value, value, {svc!r}, {proto})")

        for key, (svc, code, proto, cmmt) in line.items():
            if keyword.iskeyword(key):
                key = '%s_' % key

            pres = f"{key}: 'AppType' = {code}, {svc!r}, {proto}"
            if cmmt.startswith('-'):
                sufs = f'#: {cmmt}'
            else:
                sufs = '#: %s' % cmmt.replace('    #:   ', '    #: ')

            enum.append(f'{sufs}\n    {pres}')

        return enum, miss

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


if __name__ == '__main__':
    sys.exit(AppType())  # type: ignore[arg-type]
