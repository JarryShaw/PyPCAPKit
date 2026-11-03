# -*- coding: utf-8 -*-
"""A generic class pickles under protocol 0 and 1 on GraalPy (#2714).

Below protocol 2, :meth:`object.__reduce_ex__` hands an instance to
``copyreg._reduce_ex``, which walks the class's MRO for the first base that is not a
heap type and calls that base on the instance unless it is :class:`object`.
:class:`typing.Generic` is a heap type on CPython, so the walk passes it there.
GraalPy builds ``Generic`` as a built-in, so its walk stops at it and raises
``TypeError: typing.Generic() takes no arguments`` for every ``Info``, ``Schema``,
reassembly engine and ``Deferred``. :class:`~pcapkit.utilities.pickle.ReduceAsProtocol2`,
which each of them derives from, reduces as protocol 2 does under every protocol,
so the walk is never reached. The other reductions :mod:`pcapkit.utilities.pickle`
shares never reach it either, and each class using one is pinned here too.

GraalPy is not installed here, so :func:`_graalpy_reduce_ex` stands in for
``copyreg._reduce_ex`` with GraalPy's walk, treating ``Generic`` as a built-in.
:mod:`tests.foundation.reassembly.test_datagram_pickle_graalpy_2714_unit` uses it
for the reassembled datagrams.

"""

from __future__ import annotations

import copyreg
import decimal
import ipaddress
import pickle
import struct
import unittest
from typing import TYPE_CHECKING, Generic, TypeVar
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): pickling, whose protocols differ by interpreter.
__tier__ = 'ALL'

_T = TypeVar('_T')

#: The real hook, which the stand-in defers to wherever GraalPy's walk agrees.
_REDUCE_EX = copyreg._reduce_ex  # pylint: disable=protected-access

#: Every pickle protocol, ``0`` and ``1`` included.
PROTOCOLS = tuple(range(pickle.HIGHEST_PROTOCOL + 1))

#: A standalone HOPOPT header carrying one MPL option whose seed is the IPv6
#: source address, which a lone header has none of, so its schema holds
#: ``NO_VALUE`` (#1842).
MPL_HEADER = bytes.fromhex('3b006d0220070000')
#: An IPv4 header with no options and no payload.
IPV4_HEADER = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20, 1, 0, 64, 59, 0,
                          bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2]))


class _Plain(Generic[_T]):
    """A generic class with no reduction of its own, which GraalPy cannot pickle below 2.

    Module-level, so :mod:`pickle` can find it by name.

    """


def _graalpy_reduce_ex(obj: 'Any', proto: int) -> 'Any':
    """``copyreg._reduce_ex``, walking the MRO as GraalPy does.

    The walk stops at the first base that is not a heap type, or whose ``__new__`` is
    its own built-in, as ``copyreg._reduce_ex`` does, and also at
    :class:`typing.Generic`, which GraalPy builds as a built-in. Stopping there raises
    GraalPy's error, from calling ``Generic(obj)``; anywhere else defers to the real
    walk, which stops at the same base.

    PyPy's own walk leaves the ``__new__`` check out, and its ``__new__`` is a plain
    function with no ``__self__``, so the check reads ``__self__`` with
    :func:`getattr` and never stops the walk there, as on PyPy (#2714).

    """
    def stops(base: type) -> bool:
        new = base.__new__
        return (base is Generic
                or hasattr(base, '__flags__') and not base.__flags__ & 1 << 9  # Py_TPFLAGS_HEAPTYPE
                or isinstance(new, type(int.__new__)) and getattr(new, '__self__', None) is base)

    # NOTE: the walk stops at object if nowhere earlier, as copyreg's does.
    if next((base for base in type(obj).__mro__ if stops(base)), object) is Generic:
        raise TypeError('typing.Generic() takes no arguments')
    return _REDUCE_EX(obj, proto)


def _graalpy_walk() -> 'Any':
    """Patch :func:`_graalpy_reduce_ex` in for ``copyreg._reduce_ex``."""
    return mock.patch.object(copyreg, '_reduce_ex', _graalpy_reduce_ex)


def _round_trip(obj: 'Any', protocol: int) -> 'Any':
    """``obj`` through :mod:`pickle` at ``protocol``, under GraalPy's walk."""
    with _graalpy_walk():
        return pickle.loads(pickle.dumps(obj, protocol=protocol))


class StandInTests(unittest.TestCase):
    """The stand-in refuses what GraalPy refuses, so the passes below are not vacuous."""

    def test_the_stand_in_refuses_a_generic_class_as_graalpy_does(self) -> None:
        refused = r'^typing\.Generic\(\) takes no arguments$'
        for protocol in (0, 1):
            with self.subTest(protocol=protocol), self.assertRaisesRegex(TypeError, refused):
                _round_trip(_Plain(), protocol)
        self.assertIsInstance(_round_trip(_Plain(), 2), _Plain)
        self.assertIs(copyreg._reduce_ex, _REDUCE_EX)  # pylint: disable=protected-access


class GenericPickleTests(unittest.TestCase):
    """Each class deriving from ``ReduceAsProtocol2`` pickles under every protocol."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_an_info_reduces_as_protocol_2_does(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.protocols.internet.ipv4 import IPv4

        info = IPv4(IPV4_HEADER).info
        self.assertIsInstance(info, Info)
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                self.assertEqual(info.__reduce_ex__(protocol), info.__reduce_ex__(max(protocol, 2)))
                copy = _round_trip(info, protocol)
                self.assertIs(type(copy), type(info))
                self.assertEqual(copy, info)

    def test_an_ordered_multi_info_keeps_its_own_reduction(self) -> None:
        from pcapkit.corekit.infoclass import OrderedMultiInfo
        from pcapkit.corekit.multidict import OrderedMultiDict

        options = OrderedMultiInfo(OrderedMultiDict([('a', 1), ('b', 2), ('a', 3)]))
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                self.assertEqual(options.__reduce_ex__(protocol),
                                 (OrderedMultiInfo, ([('a', 1), ('b', 2), ('a', 3)],)))
                copy = _round_trip(options, protocol)
                self.assertIs(type(copy), OrderedMultiInfo)
                self.assertEqual(list(copy.items(multi=True)), [('a', 1), ('b', 2), ('a', 3)])

    def test_a_schema_pickles_and_keeps_its_sentinel(self) -> None:
        from pcapkit.corekit.sentinels import NO_VALUE
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.schema import Schema

        mpl = HOPOPT(MPL_HEADER, len(MPL_HEADER), extension=True).schema
        ipv4 = IPv4(IPV4_HEADER).schema
        self.assertIs(mpl.options[0].seed, NO_VALUE)
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                copy = _round_trip(mpl, protocol)
                self.assertIsInstance(copy, Schema)
                self.assertIs(copy.options[0].seed, NO_VALUE)
                self.assertEqual(bytes(copy), MPL_HEADER)
                copy = _round_trip(ipv4, protocol)
                self.assertIs(type(copy), type(ipv4))
                self.assertEqual(bytes(copy), IPV4_HEADER)

    def test_a_reassembly_engine_pickles_mid_datagram(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        bufid = (ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2'), 42,
                 TransType.UDP)

        def fragment(num: int, fo: int, mf: bool, payload: bytes) -> 'Any':
            return Packet(bufid, num, fo, 20, mf, 20 + len(payload), b'ip-header',
                          bytearray(payload), 1000.0)

        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                engine = IPv4()
                engine(fragment(1, 0, True, b'01234567'))
                copy = _round_trip(engine, protocol)
                self.assertIs(type(copy), IPv4)
                copy(fragment(2, 8, False, b'89abcdef'))
                datagram, = copy.datagram
                self.assertTrue(datagram.completed)
                self.assertEqual(datagram.payload, b'0123456789abcdef')


class SharedReductionTests(unittest.TestCase):
    """Each class on a shared reduction pickles under every protocol, through GraalPy's walk."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_deferred_pickles_still_deferred(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.data import Deferred
        from pcapkit.protocols.internet.ipv4 import IPv4

        payload = struct.pack('!HHHH', 1234, 9, 8, 0)
        deferred = Deferred(IPv4.analyze, TransType.UDP, payload)
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                copy = _round_trip(deferred, protocol)
                self.assertIs(type(copy), Deferred)
                self.assertEqual((copy.analyze, copy.proto, copy.payload),
                                 (IPv4.analyze, TransType.UDP, payload))
                self.assertEqual(copy().info, deferred().info)

    def test_a_frame_record_pickles_with_its_attributes(self) -> None:
        from pcapkit.foundation.traceflow.data.data import FrameRecord
        from pcapkit.protocols.data.misc.pcap.frame import FrameInfo

        record = FrameRecord({'packet': b'rebuilt', 'Ethernet': {'type': 2048}}, packet=b'captured',
                             frame_info=FrameInfo(ts_sec=1, ts_usec=2, incl_len=8, orig_len=9),
                             time_epoch=decimal.Decimal('1.000002'))
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                copy = _round_trip(record, protocol)
                self.assertIs(type(copy), FrameRecord)
                self.assertEqual(copy, record)
                self.assertEqual((copy.packet, copy.frame_info, copy.time_epoch),
                                 (record.packet, record.frame_info, record.time_epoch))

    def test_a_multi_valued_mapping_reduces_to_its_pairs(self) -> None:
        from pcapkit.corekit.infoclass import MultiInfo
        from pcapkit.corekit.multidict import OrderedMultiDict

        pairs = [('a', 1), ('b', 2), ('a', 3)]
        for kind in (OrderedMultiDict, MultiInfo):
            mapping = kind(pairs)
            for protocol in PROTOCOLS:
                with self.subTest(kind=kind.__name__, protocol=protocol):
                    self.assertEqual(mapping.__reduce_ex__(protocol),
                                     (kind, (list(mapping.items(multi=True)),)))
                    copy = _round_trip(mapping, protocol)
                    self.assertIs(type(copy), kind)
                    self.assertEqual(list(copy.items(multi=True)), list(mapping.items(multi=True)))

    def test_a_singleton_pickles_as_itself(self) -> None:
        from pcapkit.corekit import multidict, sentinels

        for name in ('NULL', 'NO_VALUE', 'NO_DEFAULT', 'ABSENT', 'MISSING'):
            for protocol in PROTOCOLS:
                with self.subTest(sentinel=name, protocol=protocol):
                    sentinel = getattr(sentinels, name)
                    self.assertIs(_round_trip(sentinel, protocol), sentinel)
        for protocol in PROTOCOLS:
            with self.subTest(sentinel='_missing', protocol=protocol):
                missing = multidict._missing  # pylint: disable=protected-access
                self.assertIs(_round_trip(missing, protocol), missing)

    def test_an_unregistered_member_pickles_unregistered(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.corekit.fields.numbers import PortEnumField

        tcp = AppType.__registries__[TransportProtocol.tcp]
        field = PortEnumField(length=2, namespace=AppType, proto=TransportProtocol.tcp)
        before = len(tcp.__members__)
        members = (('registry', tcp.get(50000)), ('field', field.unpack(b'\xd0\x9e', {})))
        for source, member in members:
            for protocol in PROTOCOLS:
                with self.subTest(source=source, protocol=protocol):
                    copy = _round_trip(member, protocol)
                    self.assertIs(type(copy), type(member))
                    self.assertEqual((copy, copy.port, copy.svc), (member, member.port, member.svc))
                    self.assertIn('__reduce_ex__', copy.__dict__)
        self.assertEqual(len(tcp.__members__), before)


if __name__ == '__main__':
    unittest.main()
