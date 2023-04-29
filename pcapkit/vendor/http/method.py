# -*- coding: utf-8 -*-
"""HTTP Method
=================

.. module:: pcapkit.vendor.http.method

This module contains the vendor crawler for **HTTP Method**,
which is automatically generating :class:`pcapkit.const.http.method.Method`.

"""
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from typing import Callable

__all__ = ['Method']

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

    if TYPE_CHECKING:
        #: Safe method.
        safe: 'bool'
        #: Idempotent method.
        idempotent: 'bool'

    def __new__(cls, value: 'str', safe: 'bool' = False,
                idempotent: 'bool' = False) -> 'Type[{NAME}]':
        obj = str.__new__(cls)
        obj._value_ = value

        obj.safe = safe
        obj.idempotent = idempotent

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s>" % (self.__class__.__name__, self._value_)

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


class Method(Vendor):
    """HTTP Method"""

    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/http-methods/methods.csv'

    def process(self, data: 'list[str]') -> 'list[str]':  # type: ignore[override]
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        for item in reader:
            meth = item[0]
            if meth == '*':
                continue

            safe = item[1]
            idem = item[2]
            rfcs = item[3]

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
                meth, ''.join(temp) if rfcs else '',
            ), re.MULTILINE))

            name = self.safe_name(meth).upper()
            safe_flag = 'True' if safe == 'yes' else 'False'
            idem_flag = 'True' if idem == 'yes' else 'False'

            pres = f"{name} = {meth!r}, {safe_flag}, {idem_flag}"
            sufs = f'#: {desc}'

            enum.append(f'{sufs}\n    {pres}')
        return enum

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
    sys.exit(Method())  # type: ignore[arg-type]
