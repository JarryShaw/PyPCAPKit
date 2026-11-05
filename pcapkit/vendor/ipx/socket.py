# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
"""Socket Types
==================

.. module:: pcapkit.vendor.ipx.socket

This module contains the vendor crawler for **Socket Types**,
which is automatically generating :class:`pcapkit.const.ipx.socket.Socket`.

"""

###############################################################################
# NOTE: fix duplicated name of ``socket``; restored in ``finally``, so a failed
# import does not lose the entry (#2589).
import sys

path = sys.path.pop(0)
try:
    import collections
    from typing import TYPE_CHECKING

    from pcapkit.vendor.default import Vendor

    if TYPE_CHECKING:
        from collections import Counter
finally:
    sys.path.insert(0, path)
###############################################################################

__all__ = ['Socket']

###############################################################################
# NOTE: maintained by hand, not crawled (#507): the Wikipedia table is gone from
# the live article, and IPX socket numbers are a closed Novell registry.
###############################################################################

#: Socket number registry, transcribed from the last revision of the Wikipedia
#: article that still carried the table (2026-08-10),
#: https://en.wikipedia.org/w/index.php?title=Internetwork_Packet_Exchange&oldid=1368657333
#:
#: Maps a socket number to the enumeration name it takes and the comment
#: rendered above it. Names go through :meth:`~Vendor.rename`, so the generated
#: member is the :meth:`~Vendor.safe_name` of the first element.
DATA = {
    # NOTE: absent from the scraped table, but the IPX default for the ``dst``/``src``
    # socket field (#492); all-ones (0xFFFF) is left to ``_missing_``'s dynamic range.
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
    #   -- the same functions, under a column headed "Well-Known Socket
    #   (octal)".
    #
    # The *names* are a different matter, and are the archived revision's own.
    # Both sources call socket 3 "Router Error" rather than "Error Handling
    # Packet", and neither appends "Packet" to any of them. That suffix
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
    # The archived revision writes "NetBIOS" and "Diagnostic Packet" for Novell's
    # "Novell NetBIOS" and "Diagnostics", kept against renaming.
    #
    # NOTE: Table 2's 0x9001 NLSP and 0x9004 IPXWAN (:rfc:`1634#section-4`) are known
    # omissions: adding them would break the byte-identity #507 rests on.
    0x0451: ('NetWare Core Protocol', 'NetWare Core Protocol, NCP – used by Novell NetWare servers'),
    0x0452: ('Service Advertising Protocol', 'Service Advertising Protocol, SAP'),
    0x0453: ('Routing Information Protocol', 'Routing Information Protocol, RIP'),
    0x0455: ('NetBIOS', 'NetBIOS'),
    0x0456: ('Diagnostic Packet', 'Diagnostic Packet'),

    # These are the only rows the archived revision alone supplies: absent
    # from Novell's Table 2, absent from the Xerox registry above, and absent
    # from every RFC swept. The sweep covered RFCs 1132, 1362, 1377, 1551, 1552,
    # 1553, 1634, 1791, 1973 and 2043, looking for the codes 0x0001, 0x0002,
    # 0x0003, 0x0457 and 0x4003, and found 0 hits. (0x0001, 0x0002 and 0x0003
    # turned out to be sourced after all, just not from an RFC -- see the Xerox
    # note above.)
    #
    # "0 hits" is a claim about those codes and nothing more. Some of the
    # RFCs swept do assign an IPX socket, 0x9004, which this table lacks; see the
    # note on Novell's Table 2 above.
    #
    # 0x4003 is the weaker of the two: it falls inside Novell's own
    # 0x4000-0x7FFF *dynamic* range, which is assigned to workstations on
    # demand, so a fixed well-known name for it is inherently low-confidence.
    0x0457: ('Serialization Packet', 'Serialization Packet, used for NCP as well'),
    0x4003: ('Used by Novell NetWare Client', 'Used by Novell NetWare Client'),

    # NOTE: :rfc:`1132` reserves 0x8060; ``[4]`` is Wikipedia's footnote marker, kept
    # verbatim, as renaming :attr:`~pcapkit.const.ipx.socket.Socket.LLC_4` breaks it (#507).
    0x8060: ('LLC_4', 'LLC [ 4 ]'),

    # :rfc:`1791`, "TCP And UDP Over IPX Networks With Fixed Path MTU" -- "The
    # IPX socket number 0x9091 is reserved for the TCP", "UDP must send and
    # receive the packets on IPX/IPXF socket 0x9092", and "IPXF fragments are
    # received by IPXF on the IPX socket 0x9093".
    #
    # NOTE: ``TCP over IPXF`` is the archived wording, kept against renaming: RFC 1791
    # section 3 assigns 0x9091 to TCP over plain IPX and advises against IPXF.
    0x9091: ('TCP over IPXF', 'TCP over IPXF'),
    0x9092: ('UDP over IPXF', 'UDP over IPXF'),
    0x9093: ('IPXF', 'IPXF, IPX Fragmentation Protocol'),
}  # type: dict[int, tuple[str, str]]

#: Socket number ranges, transcribed from the same revision as
#: :data:`~pcapkit.vendor.ipx.socket.DATA`, as ``(start, stop, name)``.
#:
#: Some of these ranges have a primary source, and it is not the archived
#: revision. Xerox, *Internet Transport Protocols*, XSIS 028112, December 1981,
#: Appendix D: "The socket numbers zero and all ones are reserved to mean
#: unknown and all, respectively. Well-known socket numbers have the range 1 to
#: 3000 decimal. All other socket numbers are ephemeral, that is, they may be
#: dynamically assigned and reused." Its table then gives "Experimental 40-77"
#: under a column header that the scan OCRs as ``goctalf`` and which reads
#: "Well-Known Socket (octal)".
#:
#: That reproduces the Xerox ranges exactly, and the arithmetic confirms
#: the radix without having to trust that OCR: 3000 decimal is 0x0BB8, 3001 is
#: 0x0BB9, and octal 40-77 is 0x0020-0x003F -- each as transcribed. Read as
#: decimal instead, 40-77 would be 0x0028-0x004D, which is not what the table
#: says. So the octal reading is settled by the numbers themselves.
#:
#: Novell's *IPX Addressing* bears on the remaining ranges, in opposite directions.
#: ``(0x8000, 0xFFFF)`` matches it exactly -- "Socket numbers between 0x8000 and
#: 0xFFFF are well-known sockets; these are assigned by Novell to specific
#: processes." ``(0x4000, 0x4FFF)`` is *contradicted*, not merely rounded: the
#: preceding sentence reads "Socket numbers between 0x4000 and 0x7FFF are
#: dynamic sockets", so the upper bound is 0x7FFF. The transcribed 0x4FFF is
#: kept because widening it would change the generated ``_missing_``.
RANGES = [
    # NOTE: order matters: ``_missing_`` returns on the first match, so each range
    # precedes any wider one containing it (#841).
    (0x0020, 0x003F, 'Experimental'),
    (0x0001, 0x0BB8, 'Registered by Xerox'),
    (0x4000, 0x4FFF, 'Dynamically Assigned Socket Numbers'),
    (0x8000, 0xFFFF, 'Statically Assigned Socket Numbers'),
    (0x0BB9, 0xFFFF, 'Dynamically Assigned'),
]  # type: list[tuple[int, int, str]]

#: Range names from :data:`RANGES` above that name an allocation *policy* for
#: the pool (who may claim a code, or that nobody has) rather than a specific
#: assigned protocol. The maintainer's test, set in review of the branch-order
#: fix for :issue:`841`, is whether a label is the final concrete assigned name or only
#: a notation for readers; the ruling on :issue:`775` kept ``Registered by Xerox`` out
#: of this set on that test, because a proprietary protocol may expose no name
#: of its own, so the company name serves as its name. :issue:`775` settled on
#: an unregistered member for that range too, so this set does not decide
#: *whether* a range registers -- only *how its name is spelled*: these keep the
#: bare label with no hex suffix, since the label itself already says nothing
#: was assigned, while ``Registered by Xerox`` keeps a hex-suffixed name.
UNASSIGNED_RANGE_NAMES = frozenset({
    'Experimental',
    'Dynamically Assigned Socket Numbers',
    'Statically Assigned Socket Numbers',
    'Dynamically Assigned',
})


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

        # NOTE: range names are emitted raw, not through ``safe_name``, as the shipped
        # constant file has them; sanitising would rename every range member (#507).
        for start, stop, name in RANGES:
            miss.append(f'if 0x{start:04X} <= value <= 0x{stop:04X}:')
            miss.append(f'    #: {self.wrap_comment(name)}')
            if name in UNASSIGNED_RANGE_NAMES:
                miss.append(f"    return cls._unregistered_member(value, '{name}')")
            else:
                miss.append(f"    return cls._unregistered_member(value, '{name}_0x%s' % hex(value)[2:].upper().zfill(4))")
        return enum, miss


if __name__ == '__main__':
    sys.exit(Socket())  # type: ignore[arg-type]
