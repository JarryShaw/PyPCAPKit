# -*- coding: utf-8 -*-
"""A dict rebuild finds the payload and the extension headers whatever the key order.

GitHub issue #2003: on PyPy, an :class:`~pcapkit.corekit.infoclass.Info`
lays its keys out as an earlier instance of the same class did, so its key
order is not CPython's. Two lookups of a rebuild from ``to_dict()`` read
structure off that order: the payload was taken to be the *last* nested key,
and the IPv6 extension header chain was walked in key order. A cut frame
rebuilt short, and so did a Hop-by-Hop, Destination, Destination chain once
``hopopt`` had moved past the upper layer.

The order of an :class:`~pcapkit.corekit.infoclass.Info` is not part of its
contract, so the payload is now found by the name of a protocol it dispatches
to, and the chain by its ``next`` fields. These tests reorder an instance's
:attr:`~object.__dict__` as PyPy does, so CPython checks the same thing.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import copy
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): a hand-picked round trip, pinning that a rebuild does not
#: depend on key order, which differs by interpreter.
__tier__ = 'ALL'

HOP, DST, FRAG, UDP = 0, 60, 44, 17
SRC6 = bytes.fromhex('20010db8' + '00' * 11 + '01')
DST6 = bytes.fromhex('20010db8' + '00' * 11 + '02')
DATAGRAM = struct.pack('!HHHH', 40000, 40000, 12, 0) + b'ping'


def options(nxt: int, mark: int) -> bytes:
    """An 8-octet options header carrying a PadN; ``mark`` tells repeats apart."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, mark])


def ipv6(first: int, body: bytes) -> bytes:
    """An IPv6 header whose Next Header is ``first``, followed by ``body``."""
    return struct.pack('!IHBB16s16s', 6 << 28, len(body), first, 64, SRC6, DST6) + body


#: Hop-by-Hop, Destination, Destination, then UDP.
HOP_DST_DST = ipv6(HOP, options(DST, 0) + options(DST, 1) + options(UDP, 2) + DATAGRAM)

#: An atomic Fragment header -- offset zero, no more fragments -- then UDP, so
#: the walk goes on to the upper layer and ``fragment`` is held beside it.
ATOMIC = ipv6(FRAG, struct.pack('!BBHI', UDP, 0, 0, 0x2003) + DATAGRAM)


def moved(info, key: str, before=None):  # type: ignore[no-untyped-def]
    """A copy of ``info`` with ``key`` moved before ``before``, or last, in its ``__dict__``.

    That is the reordering PyPy makes when an earlier instance of the class
    laid its attributes out differently. PyPy may lay the copy out its own way
    again, so the order is asserted of nothing but the rebuild.

    """
    clone = copy.copy(info)
    layout = clone.__dict__
    value = layout.pop(key)
    items = list(layout.items())
    index = len(items) if before is None else [name for name, _ in items].index(before)
    items.insert(index, (key, value))
    layout.clear()
    layout.update(items)
    return clone


class LookupByNameTests(unittest.TestCase):
    """Pin that the dict rebuild reads no structure off the key order."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def test_extension_headers_follow_next_not_key_order(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        ip6 = IPv6(HOP_DST_DST)
        self.assertEqual(len(ip6.data), len(HOP_DST_DST))

        # As PyPy laid it out: ``hopopt`` after every other key.
        exported = moved(ip6.info, 'hopopt').to_dict()
        names, chain = IPv6._lookup_exthdr(exported)
        self.assertEqual(names, ('hopopt', 'opts', 'opts'))
        self.assertEqual([parser for parser, _ in chain], [HOPOPT, IPv6_Opts, IPv6_Opts])
        self.assertEqual([parser.from_data(hdr).data for parser, hdr in chain],
                         [ext.data for _, ext in ip6.extension_headers.items(multi=True)])
        self.assertEqual(IPv6.from_data(exported).data, HOP_DST_DST)

    def test_payload_is_found_by_name_not_as_the_last_key(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.transport.udp import UDP as UDP_

        ip6 = IPv6(ATOMIC)
        self.assertIn('fragment', ip6.info)
        self.assertEqual(len(ip6.data), len(ATOMIC))

        # ``fragment`` is a nested key too, and not the payload; laid out
        # after the payload, it is the last nested key.
        info = moved(ip6.info, 'udp', before='fragment')
        exported = info.to_dict()
        names, _ = IPv6._lookup_exthdr(exported)
        self.assertEqual(names, ('frag',))
        self.assertEqual(IPv6._lookup_payload(exported, exclude=names), (UDP_, 'udp'))
        self.assertEqual(IPv6.from_data(exported).data, ATOMIC)

    def test_cut_upper_layer_is_found_ahead_of_the_headers(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities import config

        limit = config.EXTENSION_HEADER_LIMIT
        self.addCleanup(setattr, config, 'EXTENSION_HEADER_LIMIT', limit)
        config.EXTENSION_HEADER_LIMIT = 2

        # The third header is cut, and kept raw as the upper layer.
        ip6 = IPv6(HOP_DST_DST)
        self.assertIn('raw', ip6.info)
        self.assertEqual(len(ip6.data), len(HOP_DST_DST))

        # As on PyPy for #1610: ``opts`` after the upper layer.
        info = moved(moved(ip6.info, 'raw', before='opts'), 'hopopt', before='raw')
        exported = info.to_dict()
        names, _ = IPv6._lookup_exthdr(exported)
        self.assertEqual(sorted(names), ['hopopt', 'opts'])
        self.assertEqual(IPv6._lookup_payload(exported, exclude=names), (Raw, 'raw'))
        self.assertEqual(IPv6.from_data(exported).data, HOP_DST_DST)


if __name__ == '__main__':
    unittest.main()
