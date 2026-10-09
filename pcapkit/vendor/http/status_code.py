# -*- coding: utf-8 -*-
"""HTTP Status Code
======================

.. module:: pcapkit.vendor.http.status_code

This module contains the vendor crawler for **HTTP Status Code**,
which is automatically generating :class:`pcapkit.const.http.status_code.StatusCode`.

"""
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from typing import Callable

__all__ = ['StatusCode']


#: Default constant template of enumerate registry from IANA CSV.
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

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

if TYPE_CHECKING:
    from typing import Type

__all__ = ['{NAME}']


class {NAME}(EnumRegistry, IntEnum):
    """[{NAME}] {DOCS}"""

    if TYPE_CHECKING:
        #: Status message.
        message: 'str'

    def __new__(cls, value: 'int', message: 'str' = '(Unknown)') -> 'Type[{NAME}]':
        obj = int.__new__(cls, value)
        obj._value_ = value

        obj.message = message

        return obj

    def __repr__(self) -> 'str':
        return f'<{{self.__class__.__name__}} [{{self._value_}}]>'

    def __str__(self) -> 'str':
        return "[%s] %s" % (self._value_, self.message)

    {ENUM}

    @classmethod
    def _unregistered_member(cls, value: 'int', name: 'str') -> '{NAME}':
        """Build a member absent from this registry's own lookup tables.

        Reconstructs :attr:`message` the same way :meth:`__new__` would,
        rather than leaving it unset -- :meth:`~pcapkit.corekit.enum.
        EnumRegistry._unregistered_member` bypasses :meth:`__new__` entirely
        (it calls :class:`int`'s directly), so :attr:`message` would
        otherwise be missing from the result and :meth:`__str__` would raise
        on it.

        Args:
            value: Value to get enum item.
            name: Bare label for the unregistered member, per the ranged
                mint/unmint criterion.

        """
        obj = super()._unregistered_member(value, name)
        obj.message = name
        return obj

    @classmethod
    def _missing_(cls, value: 'int') -> '{NAME}':
        """Lookup function used when value is not found.

        A status code is three digits (:rfc:`9112#section-4`), so every value
        from 0 to 999 can arrive on the wire: one within the registry's range
        resolves through its unassigned ranges, any other to ``Unknown``.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 999):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if not ({FLAG}):
            #: Unknown
            return cls._unregistered_member(value, 'Unknown')
        {MISS}
        {'' if (test := ''.join(MISS.splitlines()[-1:])).startswith('return') or test[8:].startswith('return') else 'return super()._missing_(value)'}
'''.strip()  # type: Callable[[str, str, str, str, str, str], str]


class StatusCode(Vendor):
    """HTTP Status Code"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 100 <= value <= 599'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/http-status-codes/http-status-codes-1.csv'

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
            ), flags=re.MULTILINE))

            try:
                code, _ = item[0], int(item[0])
                if name != '(Unused)':
                    name = re.sub(r'\(.*\)', '', name).strip()

                pres = f'CODE_{code} = {code}, {name!r}'
                sufs = f'#: {desc}'

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = item[0].split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, {name!r})")
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
    sys.exit(StatusCode())  # type: ignore[arg-type]
