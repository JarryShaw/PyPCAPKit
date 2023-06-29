# -*- coding: utf-8 -*-
"""FTP Command
=================

.. module:: pcapkit.vendor.ftp.command

This module contains the vendor crawler for **FTP Command**,
which is automatically generating :class:`pcapkit.const.ftp.command.Command`.

"""
import collections
import csv
import re
import sys
from typing import TYPE_CHECKING, cast

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import OrderedDict
    from typing import Callable

__all__ = ['Command']

#: Command type.
KIND = {
    'a': 'CommandType.A',
    'p': 'CommandType.P',
    's': 'CommandType.S',
}  # type: dict[str, str]

#: Conformance requirements.
CONF = {
    'm': 'ConformanceRequirement.M',
    'o': 'ConformanceRequirement.O',
    'h': 'ConformanceRequirement.H',
}  # type: dict[str, str]

#: Default constant template of enumerate registry from IANA CSV.
LINE = lambda NAME, DOCS, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag, StrEnum, auto, extend_enum

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['{NAME}']


class FEATCode(StrEnum):
    """Keyword returned in FEAT response line for this command/extension,
    c.f., :rfc:`5797#secion-3`."""

    #: FTP standard commands [:rfc:`0959`].
    base = '<base>'
    #: Historic experimental commands [:rfc:`0775`][:rfc:`1639`].
    hist = '<hist>'
    #: FTP Security Extensions [:rfc:`2228`].
    secu = '<secu>'
    #: FTP Feature Negotiation [:rfc:`2389`].
    feat = '<feat>'
    #: FTP Extensions for NAT/IPv6 [:rfc:`2428`].
    nat6 = '<nat6>'

    def __repr__(self) -> 'str':
        return "<%s [%s]>" % (self.__class__.__name__, self._name_)

    @classmethod
    def _missing_(cls, value: 'str') -> 'FEATCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        return extend_enum(cls, value.upper(), value)


class CommandType(IntFlag):
    """Type of "kind" of command, based on :rfc:`959#section-4.1`."""

    undefined = 0

    #: Access control.
    A = auto()
    #: Parameter setting.
    P = auto()
    #: Service execution.
    S = auto()


class ConformanceRequirement(IntEnum):
    """Expectation for support in modern FTP implementations."""

    #: Mandatory to implement.
    M = auto()
    #: Optional.
    O = auto()
    #: Historic.
    H = auto()


class {NAME}(StrEnum):
    """[{NAME}] {DOCS}"""

    if TYPE_CHECKING:
        #: Feature code. Keyword returned in FEAT response line for this command/extension,
        #: c.f., :rfc:`5797#secion-2.2`.
        feat: 'Optional[FEATCode]'
        #: Brief description of command / extension.
        desc: 'Optional[str]'
        #: Type of "kind" of command, based on :rfc:`959#section-4.1`.
        type: 'CommandType'
        #: Expectation for support in modern FTP implementations.
        conf: 'ConformanceRequirement'

    def __new__(cls, name: 'str', feat: 'Optional[FEATCode]' = None,
                desc: 'Optional[str]' = None, type: 'CommandType' = CommandType.undefined,
                conf: 'ConformanceRequirement' = ConformanceRequirement.O) -> 'Type[{NAME}]':
        obj = str.__new__(cls, name)
        obj._value_ = name

        obj.feat = feat
        obj.desc = desc
        obj.type = type
        obj.conf = conf

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s: %s>" % (self.__class__.__name__, self._name_, self.desc)

    {ENUM}

    @staticmethod
    def get(key: 'str', default: 'Optional[str]' = None) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if key not in {NAME}._member_map_:  # pylint: disable=no-member
            return extend_enum({NAME}, key.upper(), default if default is not None else key)
        return {NAME}[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'str') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        return extend_enum(cls, value.upper(), value)
'''.strip()  # type: Callable[[str, str, str, str], str]


class Command(Vendor):
    """FTP Command"""

    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions-2.csv'

    def process(self, data: 'list[str]') -> 'list[str]':  # type: ignore[override]
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = collections.OrderedDict()  # type: OrderedDict[str, str]
        for item in reader:
            cmmd = item[0].strip('+')
            feat = item[1] or None
            desc = re.sub(r'{.*}', r'', item[2]).strip() or None
            kind = ' | '.join(KIND[s] for s in item[3].split('/') if s in KIND) or None
            conf = CONF.get(item[4].split()[0])

            temp = []  # type: list[str]
            #for rfc in filter(lambda s: 'RFC' in s, re.split(r'\[|\]', item[5])):
            #    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
            for rfc in filter(None, map(lambda s: s.strip(), re.split(r'\[|\]', item[5]))):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            cmmt = self.wrap_comment('%s %s' % (desc, ''.join(temp)))  # pylint: disable=consider-using-f-string

            if cmmd == '-N/A-':
                cmmd = cast('str', feat)

            if isinstance(feat, str):
                if not feat.isupper():
                    feat = f'FEATCode.{feat}'
                else:
                    feat = f'FEATCode({feat!r})'

            pres = f"{cmmd}: 'Command' = {cmmd!r}, {feat}, {desc!r}, {kind or 0}, {conf}"
            sufs = f'#: {cmmt}'

            enum[cmmd] = f'{sufs}\n    {pres}'
        return list(enum.values())

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        enum = self.process(data)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum)).strip()

        return LINE(self.NAME, self.DOCS, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(Command())  # type: ignore[arg-type]
