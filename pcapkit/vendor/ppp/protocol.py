# -*- coding: utf-8 -*-
"""PPP DLL Protocol Numbers
==============================

.. module:: pcapkit.vendor.ppp.protocol

This module contains the vendor crawler for **PPP DLL Protocol Numbers**,
which is automatically generating :class:`pcapkit.const.ppp.protocol.Protocol`.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter
    from typing import Optional

__all__ = ['Protocol']


def hexlify(code: 'int') -> 'str':
    """Convert code to hex form."""
    return f'0x{code:04X}'


class Protocol(Vendor):
    """PPP DLL Protocol Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ppp-numbers/ppp-numbers-2.csv'

    #: Destination of a bare ``Protocol`` member; see
    #: :attr:`~pcapkit.vendor.default.Vendor.PROTO_DEST`.
    PROTO_DEST = (ModuleDescriptor('pcapkit.protocols.link.ppp.protocol', 'PPP'),)

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

    def rename(self, name: 'str', code: 'str', *, original: 'Optional[str]' = None) -> 'str':  # pylint: disable=redefined-outer-name
        """Rename duplicated fields.

        Args:
            name: Field name.
            code: Field code, in hex form.

        Keyword Args:
            original: Original field name (extracted from CSV records).

        Returns:
            Revised field name, suffixed with ``code`` where IANA gives several
            values one name, as ``Reserved`` or ``Ascom Timeplex``.

        """
        if self.record[self.safe_name(name)] > 1:
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
        next(reader)  # header

        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in reader:
            name = item[1]
            rfcs = item[2]

            temp = []  # type: list[str]
            for rfc in self.split_references(rfcs):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', '%s %s' % (  # pylint: disable=consider-using-f-string
                name, ''.join(temp) if rfcs else '',
            ), flags=re.MULTILINE))

            try:
                code = hexlify(int(item[0], base=16))
                renm = self.rename(name, code)

                pres = f'{renm} = {code}'
                sufs = f'#: {desc}'

                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                # NOTE: IANA writes ``028b-1exx`` for a block whose upper bound is
                # ``0x1eff``, so an ``x`` digit is read as ``f``.
                start, stop = map(lambda s: int(s.replace('x', 'f'), base=16), item[0].split('-'))

                miss.append(f'if {hexlify(start)} <= value <= {hexlify(stop)}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Protocol())  # type: ignore[arg-type]
