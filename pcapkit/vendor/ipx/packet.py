# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
"""IPX Packet Types
======================

.. module:: pcapkit.vendor.ipx.packet

This module contains the vendor crawler for **IPX Packet Types**,
which is automatically generating :class:`pcapkit.const.ipx.packet.Packet`.

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

__all__ = ['Packet']

###############################################################################
# NOTE: this crawler no longer crawls, and the registry below is maintained by
# hand; see #518. It is the same failure, on the same article and the same
# removal revision, that retired the sibling socket crawler in #507.
#
# It used to scrape the packet-type table out of
# https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange#IPX_packet_structure,
# and two separate things broke that. Wikipedia now answers ``requests``'
# default ``python-requests/<version>`` User-Agent with HTTP 403 (measured
# 2026-09-19: 403 and 126 bytes of robot-policy text for the default agent, 200
# and 114117 bytes for a descriptive one). That half is fixed in
# ``Vendor._request``, which now sends the descriptive agent
# :func:`~pcapkit.vendor.default.get_user_agent` builds -- but it only gets the
# crawler as far as a page that no longer holds the data. The table was deleted
# from the article on 2026-08-25, in revision 1371327031 ("deleted some
# irrelevant technical tables"), leaving the live page (revision 1372814585)
# with a single ``wikitable`` -- the IPX header format one, headers
# ``['Octets', 'Field']`` -- so that ``find_all('table', class_='wikitable')[1]``
# raises ``IndexError`` even once the fetch succeeds.
#
# Pointing ``LINK`` at the last revision that still carries the table
# (``oldid=1368657333``, re-measured 2026-09-19: 200, 118834 bytes, 4
# ``wikitable``s, ``table[1]`` headers ``['Value', 'Meaning/Protocol']``, 8 body
# rows) would have worked, and running the old ``process()`` against it
# reproduces the committed constant file byte for byte. It is still the wrong
# fix: a network fetch pinned to a frozen snapshot is all of the fragility of a
# crawler with none of the freshness, and it would go on selecting a table by
# index out of a document that nothing stops from changing shape again.
#
# What settles it is that the registry is closed. IPX packet types were Novell's
# to assign -- :rfc:`1362`, :rfc:`1551` and :rfc:`1634` all say "Packet Types
# also need to be assigned by Novell" -- and there is no longer a Novell to
# assign them. IPX will not gain new packet types, so there is nothing for a
# crawler to pick up on its next run.
#
# The table below is therefore transcribed from that last revision that carried
# it, row for row, and each entry names the primary source for the assignment
# where one exists.
###############################################################################

#: IPX packet type registry, transcribed from the last revision of the Wikipedia
#: article that still carried the table,
#: https://en.wikipedia.org/w/index.php?title=Internetwork_Packet_Exchange&oldid=1368657333
#:
#: Maps a packet type to the enumeration name it takes and the comment rendered
#: above it. Names go through :meth:`~Vendor.rename`, so the generated member is
#: the :meth:`~Vendor.safe_name` of the first element; comments are stored as the
#: scrape rendered them, reStructuredText markup and all, since the prose-mangling
#: the old ``process()`` did to Wikipedia's cell text has no source left to mangle.
#:
#: Every value below is independently corroborated by Wireshark's IPX dissector,
#: ``epan/dissectors/packet-ipx.h`` (fetched 2026-09-19), which defines
#: ``IPX_PACKET_TYPE_IPX 0``, ``_RIP 1``, ``_ECHO 2``, ``_ERROR 3``, ``_PEP 4``,
#: ``_SPX 5``, ``_NCP 17`` and ``_WANBCAST 20`` -- the same eight values in the
#: same order. Types 1-5 are inherited from Xerox XNS IDP, which IPX was derived
#: from; no RFC assigns them, and the notes below say so where that is the case.
DATA = {
    # NOTE: not a protocol assignment. The scraped table listed 0 as "Unknown",
    # and it doubles as the IPX protocol's own default for the ``type`` field.
    # Wireshark calls the same value plain ``IPX``. The archived revision is the
    # only source for the word "Unknown".
    0: ('Unknown', 'Unknown'),

    # :rfc:`1582` ("Extensions to RIP to Support Demand Circuits", 1994) and
    # :rfc:`2091` ("Triggered Extensions to RIP to Support Demand Circuits",
    # 1997) are the citation the article itself carried, and they do describe
    # IPX RIP -- "the Routing Information Protocol (RIP) which runs over the
    # Internetwork Packet Exchange (IPX) protocol using socket number 453h".
    # Note honestly that they extend IPX RIP rather than assign it packet type
    # 1; for the assignment they defer to Novell, "IPX Router Specification",
    # Version 1.10, October 1992, which :rfc:`1582` lists as reference [3].
    1: ('RIP', '``RIP``, Routing Information Protocol ([:rfc:`1582`], [:rfc:`2091`])'),

    # XNS IDP inheritances. The archived revision is the only source found for
    # these two names: no RFC and no Novell document reachable today lists
    # either against a packet-type number. Wireshark corroborates the values as
    # ``ECHO 2`` and ``ERROR 3``.
    2: ('Echo Packet', 'Echo Packet'),
    3: ('Error Packet', 'Error Packet'),

    # NOTE: the best-sourced row in the table, by a distance. :rfc:`1362`,
    # :rfc:`1551` and :rfc:`1634` all state "The packets use the IPX defined
    # packet type 04 defining a Packet Exchange Packet", and tabulate it as
    # ``| Packet Type | 04 | Packet Exchange Packet |``. :rfc:`1791` adds "UDP
    # over IPX uses the IPX packet type 4, a normal IPX packet type" and "TCP,
    # like UDP, uses IPX packet type 4". :rfc:`1132` gives it from the other
    # side -- "IPX packets may be unicast by setting the IPX header Packet Type
    # field to 0x04".
    4: ('PEP', '``PEP``, Packet Exchange Protocol, used for SAP (Service Advertising Protocol)'),

    # :rfc:`1553` names the protocol -- "The Sequenced Packet Exchange (SPX) is
    # the reliable connection-based transport protocol commonly used by
    # applications" -- but not its packet-type number, which rests on Wireshark
    # and the archived revision.
    5: ('SPX', '``SPX``, Sequenced Packet Exchange'),

    # :rfc:`1553` names this one too -- "the Netware Core Protocol (NCP), which
    # is used for file server access" -- and again without the number. 17
    # (0x11) rests on Wireshark and the archived revision.
    17: ('NCP', '``NCP``, NetWare Core Protocol'),

    # NOTE: :rfc:`1132`, "A Standard for the Transmission of 802.2 Packets over
    # IPX Networks", assigns this one outright: "IPX packets may be broadcast by
    # setting the IPX header Packet Type field to 0x14" -- 0x14 being 20.
    # Wireshark calls it ``WANBCAST`` / "NetBIOS Broadcast".
    #
    # The archived table rendered the row as ``Broadcast[4]``, where ``[4]`` is
    # Wikipedia's own footnote marker for its citation of that RFC rather than
    # any part of the name, and it leaked into the generated member name. Both
    # the name and the comment are kept verbatim so that regenerating the
    # constant file stays a no-op against the last scraped output: renaming the
    # member would break :attr:`pcapkit.const.ipx.packet.Packet.Broadcast_4` for
    # anyone using it, which is a call for the maintainer rather than for #518.
    # This is the same artefact, from the same article, as the ``LLC_4`` member
    # #507 flagged in :mod:`pcapkit.vendor.ipx.socket`.
    20: ('Broadcast[4]', 'Broadcast[4]'),
}  # type: dict[int, tuple[str, str]]


class Packet(Vendor):
    """IPX Packet Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.ipx.packet.DATA`).

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
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]

        for code, (name, desc) in data.items():
            pval = str(code)
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {pval}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(Packet())  # type: ignore[arg-type]
