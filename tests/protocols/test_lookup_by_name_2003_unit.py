# -*- coding: utf-8 -*-
"""A dict rebuild dispatches as the info's, whatever the key order.

GitHub issue #2003: on PyPy, an :class:`~pcapkit.corekit.infoclass.Info`
lays its keys out as an earlier instance of the same class did, so its key
order is not CPython's. Lookups of a rebuild from ``to_dict()`` read
structure off that order: the payload was taken to be the *last* nested key,
and the IPv6 extension header chain was walked in key order. A cut frame
rebuilt short, and so did a Hop-by-Hop, Destination, Destination chain once
``hopopt`` had moved past the upper layer.

The order of an :class:`~pcapkit.corekit.infoclass.Info` is not part of its
contract, so nothing is read off it: ``to_dict()`` carries the
``__next_type__`` and ``__next_name__`` metadata the payload is dispatched on,
and ``__exthdr__``, the extension header chain as a tuple of parser and info
pairs in wire order. A dict without the metadata is not guessed at. These tests reorder an
instance's :attr:`~object.__dict__` as PyPy does, so CPython checks the same
thing.

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

    def test_extension_headers_follow_exthdr_whatever_the_key_order(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        ip6 = IPv6(HOP_DST_DST)
        self.assertEqual(len(ip6.data), len(HOP_DST_DST))

        # As PyPy laid it out: ``hopopt`` after every other key; and the
        # chain first.
        for key, before in (('hopopt', None), ('__exthdr__', 'version')):
            with self.subTest(moved=key):
                exported = moved(ip6.info, key, before=before).to_dict()
                chain = exported['__exthdr__']
                self.assertIsInstance(chain, tuple)
                self.assertEqual([parser for parser, _ in chain], [HOPOPT, IPv6_Opts, IPv6_Opts])
                self.assertEqual([info for _, info in chain],
                                 [ext.info for _, ext in ip6.extension_headers.items(multi=True)])
                self.assertEqual(IPv6.from_data(exported).data, HOP_DST_DST)

    def test_payload_follows_the_metadata_whatever_the_key_order(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.transport.udp import UDP as UDP_

        ip6 = IPv6(ATOMIC)
        self.assertIn('fragment', ip6.info)
        self.assertEqual(len(ip6.data), len(ATOMIC))

        # ``fragment`` is a mapping too, and not the payload; laid out after
        # the payload, it is the last of them, and the metadata first.
        info = moved(moved(ip6.info, 'udp', before='fragment'), '__next_name__', before='version')
        exported = info.to_dict()
        self.assertEqual(exported['__next_name__'], 'udp')
        self.assertIs(exported['__next_type__'], UDP_)
        rebuilt = IPv6.from_data(exported)
        self.assertIsInstance(rebuilt.payload, UDP_)
        self.assertEqual(rebuilt.data, ATOMIC)

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
        self.assertEqual(len(exported['__exthdr__']), 2)
        rebuilt = IPv6.from_data(exported)
        self.assertIsInstance(rebuilt.payload, Raw)
        self.assertEqual(rebuilt.data, HOP_DST_DST)

    def test_dict_without_the_dispatch_keys_is_not_guessed_at(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.null import NoPayload

        ip6 = IPv6(HOP_DST_DST)
        exported = ip6.info.to_dict()
        for key in ('__next_type__', '__next_name__'):
            exported.poplist(key)
        self.assertIn('udp', exported)

        # The extension headers are rebuilt from ``__exthdr__``, and the
        # upper layer, named by nothing, is not.
        rebuilt = IPv6.from_data(exported)
        self.assertIsInstance(rebuilt.payload, NoPayload)
        self.assertEqual(rebuilt.data, HOP_DST_DST[:40 + 3 * 8])

    def test_dict_without_exthdr_rebuilds_no_extension_header(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        ip6 = IPv6(HOP_DST_DST)
        exported = ip6.info.to_dict()
        exported.poplist('__exthdr__')
        self.assertIn('hopopt', exported)
        self.assertEqual(len(exported.getlist('opts')), 2)

        # The headers are still there under their keys, but nothing names
        # the chain, so only the upper layer follows the IPv6 header.
        self.assertEqual(IPv6.from_data(exported).data, HOP_DST_DST[:40] + DATAGRAM)

if __name__ == '__main__':
    unittest.main()
