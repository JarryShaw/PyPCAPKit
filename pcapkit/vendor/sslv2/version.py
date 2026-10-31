# -*- coding: utf-8 -*-
"""SSLv2 Protocol Version
============================

.. module:: pcapkit.vendor.sslv2.version

This module contains the vendor crawler for **SSLv2 Protocol Version**, which
is automatically generating :class:`pcapkit.const.sslv2.version.Version`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['Version']

###############################################################################
# NOTE: this crawler does not crawl. Its source is the expired Netscape SSLv2
# draft, draft-hickman-netscape-ssl-00, which is not an IANA (or any other)
# live registry a crawler could re-fetch -- there is nothing upstream of this
# module to go stale against. Per the const-vendor-pairing convention, a
# hand-maintained registry still gets a crawler, reading
# :data:`~pcapkit.vendor.sslv2.version.DATA` instead of fetching a URL -- the
# same shape as :mod:`pcapkit.vendor.linux.arphrd`,
# :mod:`pcapkit.vendor.ipx.packet` and :mod:`pcapkit.vendor.ipx.socket`.
#
# SSLv2 carries no record-layer version field; ``CLIENT-VERSION`` and
# ``SERVER-VERSION`` are handshake-body fields, which is why the registry
# below names a single value rather than a numbered range: any value other
# than ``SSL-2.0`` is not necessarily malformed -- per :rfc:`6101#appendix-E`,
# an SSLv3-capable client sends an SSLv2-framed ``CLIENT-HELLO`` whose version
# reads ``768`` (``0x0300``) -- so :meth:`~pcapkit.const.sslv2.version.Version._missing_`
# resolves any other in-range value to an unregistered member instead of
# raising.
###############################################################################

#: SSLv2 protocol version registry, transcribed from
#: draft-hickman-netscape-ssl-00 for the single value the draft defines.
#:
#: Maps the version value to the enumeration name it takes and the
#: ``SSL-*`` constant the comment above it renders. Names go through
#: :meth:`~Vendor.rename`, so the generated member is the
#: :meth:`~Vendor.safe_name` of the first element.
DATA = {
    2: ('SSLv2', '``SSL-2.0``'),
}  # type: dict[int, tuple[str, str]]


class Version(Vendor):
    """SSLv2 Protocol Version"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.sslv2.version.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, tuple[str, str]]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for name, _ in data.values())

    def process(self, data: 'dict[int, tuple[str, str]]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            "return cls._unregistered_member(value, 'Unassigned')",
        ]

        for code, (name, desc) in data.items():
            pval = str(code)
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {pval}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Version())  # type: ignore[arg-type]
