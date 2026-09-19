# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
"""Socket Types
==================

.. module:: pcapkit.vendor.ipx.socket

This module contains the vendor crawler for **Socket Types**,
which is automatically generating :class:`pcapkit.const.ipx.socket.Socket`.

"""

###############################################################################
# NOTE: fix duplicated name of ``socket```
import sys

path = sys.path.pop(0)
###############################################################################

import collections
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

###############################################################################
sys.path.insert(0, path)
###############################################################################

__all__ = ['Socket']

###############################################################################
# NOTE: this crawler no longer crawls, and the registry below is maintained by
# hand; see #507.
#
# It used to scrape the well-known-socket table out of
# https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#Socket_number,
# and two separate things broke that. Wikipedia now answers ``requests``'
# default ``python-requests/<version>`` User-Agent with HTTP 403 (measured
# 2026-09-19: 403 and 126 bytes of robot-policy text for the default agent,
# 200 and 114117 bytes for a descriptive one), so ``Vendor._request`` could not
# fetch the page at all. And the table itself was deleted from the article on
# 2026-08-25, in revision 1371327031 ("deleted some irrelevant technical
# tables"), leaving the page with a single ``wikitable`` -- the IPX header
# format one -- so that ``find_all('table', class_='wikitable')[3]`` raises
# ``IndexError`` even once the fetch is fixed.
#
# Pointing ``LINK`` at the last revision that still carries the table
# (``oldid=1368657333``) would have worked, but it buys none of what a crawler
# is for: a network fetch pinned to a frozen snapshot is all of the fragility
# with none of the freshness, and it would still be selecting the table by
# index out of a document that nothing stops from changing shape again. The
# registry itself is closed, which is what settles it -- IPX socket numbers
# were Novell's to assign, and Novell's own documentation still ends the list
# with "software developers writing NetWare applications can contact Novell to
# reserve well-known sockets". There is no longer a Novell to contact, and IPX
# will not gain new socket numbers, so there is nothing for a crawler to pick
# up on its next run.
#
# The table below is therefore transcribed from that last revision that carried
# it, row for row, and each entry names the primary source for the assignment
# where one exists.
###############################################################################

#: Socket number registry, transcribed from the last revision of the Wikipedia
#: article that still carried the table (2026-08-10),
#: https://en.wikipedia.org/w/index.php?title=Internetwork_Packet_Exchange&oldid=1368657333
#:
#: Maps a socket number to the enumeration name it takes and the comment
#: rendered above it. Names go through :meth:`~Vendor.rename`, so the generated
#: member is the :meth:`~Vendor.safe_name` of the first element.
DATA = {
    # NOTE: 0x0000 was never listed as a well-known socket in the scraped
    # registry table, but it is the IPX protocol's own default for the
    # ``dst``/``src`` socket field (an ordinary "unspecified socket"), so it
    # must be present regardless of what the registry says; see #492, #503.
    0x0000: ('Unspecified', "Unspecified socket; this is IPX's own default for the dst/src socket field."),

    # Sockets in the "Registered by Xerox" range below. The archived revision is
    # the only source found for these three names: no RFC and no Novell document
    # reachable today lists them.
    0x0001: ('Routing Information Packet', 'Routing Information Packet'),
    0x0002: ('Echo Protocol Packet', 'Echo Protocol Packet'),
    0x0003: ('Error Handling Packet', 'Error Handling Packet'),

    # Novell, *IPX Addressing*, "Table 2. NetWare Socket Numbers and
    # Processes", https://www.novell.com/documentation/nw6p/ipx_enu/data/hvvqznoa.html
    # -- 0x451 NCP, 0x452 SAP, 0x453 RIP, 0x455 Novell NetBIOS, 0x456
    # Diagnostics. That page is also the citation the article itself used.
    0x0451: ('NetWare Core Protocol', 'NetWare Core Protocol, NCP – used by Novell NetWare servers'),
    0x0452: ('Service Advertising Protocol', 'Service Advertising Protocol, SAP'),
    0x0453: ('Routing Information Protocol', 'Routing Information Protocol, RIP'),
    0x0455: ('NetBIOS', 'NetBIOS'),
    0x0456: ('Diagnostic Packet', 'Diagnostic Packet'),

    # Not in Novell's Table 2; the archived revision is the only source found.
    0x0457: ('Serialization Packet', 'Serialization Packet, used for NCP as well'),
    0x4003: ('Used by Novell NetWare Client', 'Used by Novell NetWare Client'),

    # NOTE: :rfc:`1132`, "A Standard for the Transmission of 802.2 Packets over
    # IPX Networks", reserves this one -- "The IPX socket 0x8060 has been
    # reserved by Novell for the implementation of this protocol."
    #
    # The archived table rendered the row as ``LLC [ 4 ]``, where ``[ 4 ]`` is
    # Wikipedia's own footnote marker for its citation of that RFC rather than
    # any part of the protocol name, and it leaked into the generated member
    # name. Both the name and the comment are kept verbatim so that
    # regenerating the constant file stays a no-op against the last scraped
    # output: renaming the member would break
    # :attr:`pcapkit.const.ipx.socket.Socket.LLC_4` for anyone using it, which
    # is a call for the maintainer rather than for #507.
    0x8060: ('LLC_4', 'LLC [ 4 ]'),

    # :rfc:`1791` -- "The IPX socket number 0x9091 is reserved for the TCP",
    # "UDP must send and receive the packets on IPX/IPXF socket 0x9092", and
    # "IPXF fragments are received by IPXF on the IPX socket 0x9093".
    0x9091: ('TCP over IPXF', 'TCP over IPXF'),
    0x9092: ('UDP over IPXF', 'UDP over IPXF'),
    0x9093: ('IPXF', 'IPXF, IPX Fragmentation Protocol'),
}  # type: dict[int, tuple[str, str]]

#: Socket number ranges, transcribed from the same revision as
#: :data:`~pcapkit.vendor.ipx.socket.DATA`, as ``(start, stop, name)``.
#:
#: Novell's *IPX Addressing* corroborates the last two, if not their exact
#: bounds: "socket numbers between 0x4000 and 0x7FFF are dynamic sockets" and
#: "socket numbers between 0x8000 and 0xFFFF are well-known sockets; these are
#: assigned by Novell to specific processes".
RANGES = [
    # NOTE: order is significant, and is the order the rows appeared in. The
    # generated ``_missing_`` tests these in sequence and returns on the first
    # match, so the wide ranges here mask the narrow ones that follow them --
    # reordering the list silently changes which name an unlisted socket gets.
    (0x0001, 0x0BB8, 'Registered by Xerox'),
    (0x0020, 0x003F, 'Experimental'),
    (0x0BB9, 0xFFFF, 'Dynamically Assigned'),
    (0x4000, 0x4FFF, 'Dynamically Assigned Socket Numbers'),
    (0x8000, 0xFFFF, 'Statically Assigned Socket Numbers'),
]  # type: list[tuple[int, int, str]]


class Socket(Vendor):
    """Socket Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipx.socket.DATA`).

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
        miss = []  # type: list[str]

        for code, (name, desc) in data.items():
            pval = f'0x{code:04X}'
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {pval}')

        # NOTE: the range names are emitted raw, spaces and all, rather than
        # through ``safe_name``, because that is what the scrape did and what
        # the shipped constant file contains; sanitising them here would rename
        # every member ``_missing_`` extends the enumeration with; see #507.
        for start, stop, name in RANGES:
            miss.append(f'if 0x{start:04X} <= value <= 0x{stop:04X}:')
            miss.append(f'    #: {self.wrap_comment(name)}')
            miss.append(f"    return extend_enum(cls, '{name}_0x%s' % hex(value)[2:].upper().zfill(4), value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Socket())  # type: ignore[arg-type]
