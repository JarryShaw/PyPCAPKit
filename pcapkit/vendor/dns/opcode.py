# -*- coding: utf-8 -*-
"""DNS OpCodes
=================

.. module:: pcapkit.vendor.dns.opcode

This module contains the vendor crawler for **DNS OpCodes**,
which is automatically generating :class:`pcapkit.const.dns.opcode.Opcode`.

The registry is IANA's ``DNS OpCodes`` table, in the ``Value, Description,
Reference`` shape :meth:`~pcapkit.vendor.default.Vendor.process` reads. A name
whose trailing parenthetical is a single upper-case mnemonic takes the
mnemonic, so ``DNS Stateful Operations (DSO)`` is ``DSO``, as
:rfc:`8490#section-1` names it; any other parenthetical is dropped, as
:meth:`~pcapkit.vendor.default.Vendor.safe_name` drops it.

"""

import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Opcode']

#: A trailing parenthetical holding a single upper-case mnemonic, e.g. ``(DSO)``.
MNEMONIC = re.compile(r'\(([A-Z]+)\)\s*$')


class Opcode(Vendor):
    """DNS OpCodes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 15'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dns-parameters/dns-parameters-5.csv'

    def safe_name(self, name: 'str') -> 'str':
        """Convert an IANA ``Name`` cell to a member identifier.

        Args:
            name: Verbatim ``Name`` cell.

        Returns:
            The mnemonic of a trailing upper-case parenthetical, or what
            :meth:`~pcapkit.vendor.default.Vendor.safe_name` gives.

        """
        match = MNEMONIC.search(name)
        return super().safe_name(match.group(1) if match is not None else name)


if __name__ == '__main__':
    sys.exit(Opcode())  # type: ignore[arg-type]
