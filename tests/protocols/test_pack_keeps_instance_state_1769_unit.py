# -*- coding: utf-8 -*-
"""Calling ``pack()`` leaves the instance it is called on as it was. C.f. #1769.

:meth:`ProtocolBase.pack <pcapkit.protocols.protocol.ProtocolBase.pack>` builds
a fresh header from its keywords alone. This guards against it assigning that
header to the instance as well, where a bare
``UDP(srcport=1234, dstport=53).pack()`` left ``schema.srcport`` at ``0`` while
``info.srcport`` was still ``1234``, and
:meth:`TCP.make <pcapkit.protocols.transport.tcp.TCP.make>` overwrote
:attr:`~pcapkit.protocols.transport.tcp.TCP.connection` on the way. The
``pack`` overrides of ``Frame`` and ``PCAPNG`` did the same, and HTTP/2's
dropped the header altogether.

Every value is built here, so the module is in the unit tier.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.protocols.protocol import ProtocolBase

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class _KeepsState(unittest.TestCase):
    """Shared assertions."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def assertPackKeepsState(self, proto: 'ProtocolBase', **kwargs: 'Any') -> 'bytes':  # noqa: N802
        """Call ``proto.pack(**kwargs)`` and check nothing on ``proto`` moved.

        ``schema`` is a cached property, so it is read only *after* the call:
        read before, it would hide a replaced header behind its cache.

        Returns:
            What ``pack`` returned.

        """
        header, info, data = proto.__header__, proto.info, proto.data
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            packed = proto.pack(**kwargs)
        self.assertIs(proto.__header__, header)
        self.assertIs(proto.schema, header)
        self.assertIs(proto.info, info)
        self.assertEqual(proto.data, data)
        return packed


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestLayers(_KeepsState):
    """A link, an internet and two transport protocols, constructed and parsed."""

    CASES = (
        ('pcapkit.protocols.link.ethernet', 'Ethernet',
         {'src': 'aa:bb:cc:dd:ee:ff', 'dst': '11:22:33:44:55:66'}),
        ('pcapkit.protocols.internet.ipv4', 'IPv4', {'src': '1.2.3.4', 'dst': '5.6.7.8', 'ttl': 7}),
        ('pcapkit.protocols.transport.udp', 'UDP', {'srcport': 1234, 'dstport': 53}),
        ('pcapkit.protocols.transport.tcp', 'TCP', {'srcport': 80, 'dstport': 443, 'syn': True, 'ack': True}),
    )

    def test_bare_pack_returns_a_default_header(self) -> 'None':
        for module, name, kwargs in self.CASES:
            with self.subTest(protocol=name):
                cls = getattr(importlib.import_module(module), name)
                proto = cls(**kwargs)
                self.assertEqual(self.assertPackKeepsState(proto), cls().data)
                # NOTE: the schema still describes the octets the instance holds.
                self.assertEqual(bytes(proto.schema), proto.data)

    def test_pack_with_keywords_keeps_state(self) -> 'None':
        for module, name, kwargs in self.CASES:
            with self.subTest(protocol=name):
                cls = getattr(importlib.import_module(module), name)
                proto = cls()
                self.assertEqual(self.assertPackKeepsState(proto, **kwargs), cls(**kwargs).data)
                self.assertEqual(bytes(proto.schema), cls().data)

    def test_parsed_instance_keeps_state(self) -> 'None':
        for module, name, kwargs in self.CASES:
            with self.subTest(protocol=name):
                cls = getattr(importlib.import_module(module), name)
                octets = cls(**kwargs).data
                proto = cls(octets, len(octets))
                self.assertEqual(self.assertPackKeepsState(proto), cls().data)
                self.assertEqual(bytes(proto.schema), octets)

    def test_issue_example(self) -> 'None':
        from pcapkit.protocols.transport.udp import UDP

        udp = UDP(srcport=1234, dstport=53)
        self.assertEqual(udp.data, bytes.fromhex('04d2003500080000'))
        self.assertEqual(self.assertPackKeepsState(udp), bytes.fromhex('0000000000080000'))
        self.assertEqual(udp.schema.srcport, 1234)
        self.assertEqual(udp.info.srcport, 1234)

    def test_tcp_connection_flags(self) -> 'None':
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(srcport=80, dstport=443, syn=True, ack=True)
        self.assertEqual(tcp.connection, Flags.SYN | Flags.ACK)
        self.assertPackKeepsState(tcp)
        self.assertEqual(tcp.connection, Flags.SYN | Flags.ACK)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestOverrides(_KeepsState):
    """The ``pack`` overrides that built their own header."""

    def test_frame(self) -> 'None':
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        header = Header().info
        frame = Frame(num=1, header=header, ts_sec=1, ts_usec=2, packet=b'abcd')
        packed = self.assertPackKeepsState(frame, num=1, header=header, ts_sec=3, ts_usec=4, packet=b'xy')
        self.assertEqual(packed, Frame(num=1, header=header, ts_sec=3, ts_usec=4, packet=b'xy').data)
        self.assertEqual(frame.schema.ts_sec, 1)

    def test_pcapng(self) -> 'None':
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={'byteorder': 'big'})
        self.assertEqual(section.byteorder, 'big')
        self.assertPackKeepsState(section, num=0, sct=1, ctx=None,
                                  type=BlockType.Section_Header_Block, block={'byteorder': 'little'})
        self.assertEqual(section.byteorder, 'big')

        context = Context(section.info)
        kwargs = {'num': 1, 'sct': 1, 'ctx': context, 'type': BlockType.Interface_Description_Block,
                  'block': {'linktype': LinkType.ETHERNET, 'snaplen': 0x40000,
                            'options': [(OptionType.if_name, {'name': 'eth0'})]}}
        interface = PCAPNG(**kwargs)
        counts = dict(interface._opt)  # pylint: disable=protected-access
        self.assertEqual(self.assertPackKeepsState(interface, **kwargs), interface.data)
        self.assertEqual(dict(interface._opt), counts)  # pylint: disable=protected-access
        # NOTE: the bare make defaults to another block type.
        packed = self.assertPackKeepsState(interface, num=1, sct=1, ctx=context)
        self.assertNotEqual(packed, interface.data)
        self.assertEqual(interface.block, BlockType.Interface_Description_Block)

    def test_httpv2(self) -> 'None':
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        kwargs = {'type': 0x00, 'sid': 1, 'frame': {'data': b'abc'}}
        frame = HTTPv2(**kwargs)
        self.assertIsNotNone(frame.__header__)
        self.assertEqual(self.assertPackKeepsState(frame, **kwargs), frame.data)


if __name__ == '__main__':
    unittest.main()
