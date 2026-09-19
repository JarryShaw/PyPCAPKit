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
    #
    # That is a statement about the *scraped table*, not about the number being
    # unsourced. XSIS 028112 Appendix D (cited under RANGES below) reserves it
    # in the primary standard: "The socket numbers zero and all ones are
    # reserved to mean unknown and all, respectively." The same sentence
    # reserves all-ones -- 0xFFFF, to mean "all" -- and this table has no entry
    # for that; ``_missing_`` resolves 0xFFFF through the "Dynamically Assigned"
    # range instead. Adding it would change the generated file, so it is left as
    # a follow-up rather than done here.
    0x0000: ('Unspecified', "Unspecified socket; this is IPX's own default for the dst/src socket field."),

    # Sockets in the "Registered by Xerox" range below. These are formally
    # XNS/IDP well-known sockets that IPX inherited, and the *values* have both
    # a live registry and a primary standard behind them:
    #
    # * IANA, "Xerox Network System (XNS) Protocol Types", sub-registry
    #   "Assigned well-known socket numbers" --
    #   https://www.iana.org/assignments/xns-protocol-types -- lists 1 Routing
    #   Information, 2 Echo and 3 Router Error, each referenced to "Xerox System
    #   Integration Standard: Internet Transport Protocols. XSIS 028112,
    #   December 1981". IANA publishes the registry but does not own it: its
    #   registration procedure reads "Not assigned by IANA".
    # * That standard itself, Appendix D, "Assigned well-known socket numbers",
    #   scanned at http://www.bitsavers.org/pdf/xerox/xns/standards/XSIS_028112-Internet_Transport_Protocols_198112.pdf
    #   -- the same three functions, under a column headed "Well-Known Socket
    #   (octal)".
    #
    # The *names* are a different matter, and are the archived revision's own.
    # Both sources call socket 3 "Router Error" rather than "Error Handling
    # Packet", and neither appends "Packet" to any of the three. That suffix
    # looks like the adjacent packet-type registry bleeding in -- XSIS Appendix
    # E, "Assigned internet packet types", and the second table on the same IANA
    # page, which do use 1 Routing Information / 2 Echo / 3 Error as *packet*
    # types. The names are kept as transcribed anyway, for the same reason
    # ``LLC_4`` is kept below: changing one renames a public member.
    0x0001: ('Routing Information Packet', 'Routing Information Packet'),
    0x0002: ('Echo Protocol Packet', 'Echo Protocol Packet'),
    0x0003: ('Error Handling Packet', 'Error Handling Packet'),

    # Novell, *IPX Addressing*, "Table 2. NetWare Socket Numbers and
    # Processes", https://www.novell.com/documentation/nw6p/ipx_enu/data/hvvqznoa.html
    # -- still live. That page is also the citation the article itself used.
    #
    # NOTE: Table 2 has **seven** rows and only five of them are below. In full
    # it reads 0x451 NCP, 0x452 SAP, 0x453 RIP, 0x455 Novell NetBIOS, 0x456
    # Diagnostics, 0x9001 NLSP, 0x9004 "IPXWAN(TM) protocol". The last two have
    # never been in this enumeration, and 0x9004 is independently reserved by
    # :rfc:`1634` line 552 -- "The socket number 0x9004 is a Novell reserved
    # socket number for exclusive use with IPX WAN protocol exchange" -- and by
    # the two RFCs it obsoletes: :rfc:`1551` line 532 word for word, and
    # :rfc:`1362` line 253 with "information exchange" for "protocol exchange".
    # So they are known omissions with good sourcing, not rows nobody noticed.
    # Adding them would add members to the generated file and so give up the
    # byte-identity proof this change rests on, which makes them a follow-up
    # rather than part of #507.
    #
    # Two of the five below also depart from Novell's own wording: Novell writes
    # "Novell NetBIOS" and "Diagnostics" where this table says "NetBIOS" and
    # "Diagnostic Packet". Those are the archived revision's strings, kept for
    # the same member-renaming reason as everything else here.
    0x0451: ('NetWare Core Protocol', 'NetWare Core Protocol, NCP – used by Novell NetWare servers'),
    0x0452: ('Service Advertising Protocol', 'Service Advertising Protocol, SAP'),
    0x0453: ('Routing Information Protocol', 'Routing Information Protocol, RIP'),
    0x0455: ('NetBIOS', 'NetBIOS'),
    0x0456: ('Diagnostic Packet', 'Diagnostic Packet'),

    # These two are the only rows the archived revision alone supplies: absent
    # from Novell's Table 2, absent from the Xerox registry above, and absent
    # from every RFC swept. The sweep covered RFCs 1132, 1362, 1377, 1551, 1552,
    # 1553, 1634, 1791, 1973 and 2043, looking for the five codes 0x0001, 0x0002,
    # 0x0003, 0x0457 and 0x4003, and found 0 hits. (The first three of those five
    # turned out to be sourced after all, just not from an RFC -- see the Xerox
    # note above.)
    #
    # "0 hits" is a claim about those five codes and nothing more. Three of the
    # ten RFCs do assign an IPX socket, 0x9004, which this table lacks; see the
    # note on Novell's Table 2 above.
    #
    # 0x4003 is the weaker of the two: it falls inside Novell's own
    # 0x4000-0x7FFF *dynamic* range, which is assigned to workstations on
    # demand, so a fixed well-known name for it is inherently low-confidence.
    0x0457: ('Serialization Packet', 'Serialization Packet, used for NCP as well'),
    0x4003: ('Used by Novell NetWare Client', 'Used by Novell NetWare Client'),

    # NOTE: :rfc:`1132`, "A Standard for the Transmission of 802.2 Packets over
    # IPX Networks", reserves this one -- "The IPX socket 0x8060 has been
    # reserved by Novell for the implementation of this protocol."
    #
    # The archived table renders the row as ``LLC[4]``, where ``[4]`` is
    # Wikipedia's own footnote marker for its citation of that RFC rather than
    # any part of the protocol name -- the cell markup is an ``<a>`` reading
    # "LLC" followed by ``<sup id="cite_ref-RFC1132_4-1">``. The spaces in
    # ``LLC [ 4 ]`` are not in the page at all: they are an artefact of the
    # scrape, which joined the cell's strings with a space and so picked up the
    # ``<span class="cite-bracket">`` wrappers around the ``[`` and ``]`` as
    # separate tokens. The value is right and the explanation of it was not.
    # Both the name and the comment are kept verbatim so that
    # regenerating the constant file stays a no-op against the last scraped
    # output: renaming the member would break
    # :attr:`pcapkit.const.ipx.socket.Socket.LLC_4` for anyone using it, which
    # is a call for the maintainer rather than for #507.
    0x8060: ('LLC_4', 'LLC [ 4 ]'),

    # :rfc:`1791`, "TCP And UDP Over IPX Networks With Fixed Path MTU" -- "The
    # IPX socket number 0x9091 is reserved for the TCP", "UDP must send and
    # receive the packets on IPX/IPXF socket 0x9092", and "IPXF fragments are
    # received by IPXF on the IPX socket 0x9093".
    #
    # NOTE: the name ``TCP over IPXF`` is wrong, and it is the archived
    # revision's wording rather than the RFC's. RFC 1791 reserves 0x9091 for TCP
    # over plain **IPX**: the section that assigns it is s3, "Running TCP Over
    # IPX", which opens "Unlike UDP, TCP runs directly over IPX", and the same
    # section ends "Hence, running TCP over IPXF is not recommended." So the
    # member name describes the one arrangement the cited RFC advises against.
    # Only the name is wrong; 0x9091 is the right value for TCP. It is kept for
    # the member-renaming reason set out above, and is the strongest candidate in
    # this table for a rename with a deprecated alias.
    #
    # ``UDP over IPXF`` for 0x9092, by contrast, is accurate: "UDP must run on
    # IPXF rather than directly on IPX", and the socket is named as
    # "IPX/IPXF socket 0x9092".
    #
    # One more scruple about wording: "reserved" is the RFC's own word for
    # 0x9091 only. For 0x9092 and 0x9093 it says packets "must" be sent and
    # received on them, which amounts to the same reservation in practice but is
    # an inference rather than a quote.
    0x9091: ('TCP over IPXF', 'TCP over IPXF'),
    0x9092: ('UDP over IPXF', 'UDP over IPXF'),
    0x9093: ('IPXF', 'IPXF, IPX Fragmentation Protocol'),
}  # type: dict[int, tuple[str, str]]

#: Socket number ranges, transcribed from the same revision as
#: :data:`~pcapkit.vendor.ipx.socket.DATA`, as ``(start, stop, name)``.
#:
#: Three of the five have a primary source, and it is not the archived
#: revision. Xerox, *Internet Transport Protocols*, XSIS 028112, December 1981,
#: Appendix D: "The socket numbers zero and all ones are reserved to mean
#: unknown and all, respectively. Well-known socket numbers have the range 1 to
#: 3000 decimal. All other socket numbers are ephemeral, that is, they may be
#: dynamically assigned and reused." Its table then gives "Experimental 40-77"
#: under a column header that the scan OCRs as ``goctalf`` and which reads
#: "Well-Known Socket (octal)".
#:
#: That reproduces the first three ranges exactly, and the arithmetic confirms
#: the radix without having to trust that OCR: 3000 decimal is 0x0BB8, 3001 is
#: 0x0BB9, and octal 40-77 is 0x0020-0x003F -- all three as transcribed. Read as
#: decimal instead, 40-77 would be 0x0028-0x004D, which is not what the table
#: says. So the octal reading is settled by the numbers themselves.
#:
#: Novell's *IPX Addressing* bears on the last two, and in opposite directions.
#: ``(0x8000, 0xFFFF)`` matches it exactly -- "Socket numbers between 0x8000 and
#: 0xFFFF are well-known sockets; these are assigned by Novell to specific
#: processes." ``(0x4000, 0x4FFF)`` is *contradicted*, not merely rounded: the
#: preceding sentence reads "Socket numbers between 0x4000 and 0x7FFF are
#: dynamic sockets", so the upper bound is 0x7FFF. The transcribed 0x4FFF is
#: kept because widening it would change the generated ``_missing_``; the
#: archived table is what is wrong here, and this range is masked by
#: ``(0x0BB9, 0xFFFF)`` in any case (see the note below), so the bound has no
#: observable effect today.
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
