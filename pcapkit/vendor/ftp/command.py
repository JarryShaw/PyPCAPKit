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
    'a': 'access control',
    'p': 'parameter setting',
    's': 'service execution',
}  # type: dict[str, str]

#: Conformance requirements.
CONF = {
    'm': 'mandatory to implement',
    'o': 'optional',
    'h': 'historic',
}  # type: dict[str, str]

#: Default constant template of enumerate registry from IANA CSV.
LINE = lambda NAME, DOCS, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from typing import TYPE_CHECKING

from aenum import StrEnum, extend_enum

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['{NAME}']


class {NAME}(StrEnum):
    """[{NAME}] {DOCS}"""

    def __new__(cls, name: 'str', feat: 'Optional[str]' = None, desc: 'Optional[str]' = None,
                type: 'Optional[tuple[str, ...]]' = None, conf: 'Optional[str]' = None,
                note: 'Optional[tuple[str, ...]]' = None) -> 'Type[{NAME}]':
        obj = str.__new__(cls, name)
        obj._value_ = name

        #: Feature of command.
        obj.feat = feat
        #: Description of command.
        obj.desc = desc
        #: Type of command.
        obj.type = type
        #: Conformance of command.
        obj.conf = conf
        #: Note of command.
        obj.note = note

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s>" % (self.__class__.__name__, self._name_)

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
            extend_enum({NAME}, key.upper(), default if default is not None else key)
        return {NAME}[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'str') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        extend_enum(cls, value.upper(), value)
        return cls(value)
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
            kind = tuple(KIND[s] for s in item[3].split('/') if s in KIND) or None
            conf = CONF.get(item[4].split()[0])

            temp = []  # type: list[str]
            rfcs_temp = []  # type: list[str]
            #for rfc in filter(lambda s: 'RFC' in s, re.split(r'\[|\]', item[5])):
            #    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
            for rfc in filter(None, map(lambda s: s.strip(), re.split(r'\[|\]', item[5]))):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                    rfcs_temp.append(f'{rfc[:3]} {rfc[3:]}')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            rfcs = tuple(rfcs_temp) or None
            cmmt = self.wrap_comment('%s %s' % (desc, ''.join(temp)))  # pylint: disable=consider-using-f-string

            if isinstance(feat, str) and not feat.isupper():
                feat = f'<{feat}>'

            if cmmd == '-N/A-':
                cmmd = cast('str', feat)

            pres = f'{cmmd} = {cmmd!r}, {feat!r}, {desc!r}, {kind!r}, {conf!r}, {rfcs!r}'
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
