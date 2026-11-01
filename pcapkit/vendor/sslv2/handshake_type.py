# -*- coding: utf-8 -*-
"""SSLv2 Handshake Message Type
==================================

.. module:: pcapkit.vendor.sslv2.handshake_type

This module contains the vendor crawler for **SSLv2 Handshake Message Type**,
which is automatically generating :class:`pcapkit.const.sslv2.handshake_type.HandshakeType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['HandshakeType']

###############################################################################
# NOTE: this crawler does not crawl. Its source is the expired Netscape SSLv2
# draft, draft-hickman-netscape-ssl-00, which is not an IANA (or any other)
# live registry a crawler could re-fetch -- there is nothing upstream of this
# module to go stale against. Per the const-vendor-pairing convention, a
# hand-maintained registry still gets a crawler, reading
# :data:`~pcapkit.vendor.sslv2.handshake_type.DATA` instead of fetching a URL
# -- the same shape as :mod:`pcapkit.vendor.linux.arphrd`,
# :mod:`pcapkit.vendor.ipx.packet` and :mod:`pcapkit.vendor.ipx.socket`.
###############################################################################

#: SSLv2 handshake message type registry, transcribed from
#: draft-hickman-netscape-ssl-00 for the complete, closed set of ``MSG-*``
#: codes the draft defines.
#:
#: Maps a handshake message type to the enumeration name it takes and the
#: ``MSG-*`` constant the comment above it renders. Names go through
#: :meth:`~Vendor.rename`, so the generated member is the
#: :meth:`~Vendor.safe_name` of the first element.
DATA = {
    0: ('ERROR', '``MSG-ERROR``'),
    1: ('CLIENT_HELLO', '``MSG-CLIENT-HELLO``'),
    2: ('CLIENT_MASTER_KEY', '``MSG-CLIENT-MASTER-KEY``'),
    3: ('CLIENT_FINISHED', '``MSG-CLIENT-FINISHED``'),
    4: ('SERVER_HELLO', '``MSG-SERVER-HELLO``'),
    5: ('SERVER_VERIFY', '``MSG-SERVER-VERIFY``'),
    6: ('SERVER_FINISHED', '``MSG-SERVER-FINISHED``'),
    7: ('REQUEST_CERTIFICATE', '``MSG-REQUEST-CERTIFICATE``'),
    8: ('CLIENT_CERTIFICATE', '``MSG-CLIENT-CERTIFICATE``'),
}  # type: dict[int, tuple[str, str]]


class HandshakeType(Vendor):
    """SSLv2 Handshake Message Type"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.sslv2.handshake_type.DATA`).

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
    sys.exit(HandshakeType())  # type: ignore[arg-type]
