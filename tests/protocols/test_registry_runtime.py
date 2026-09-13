from __future__ import annotations

import importlib.util
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolRegistryRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_link_register_rejects_non_protocol_types(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.link import Link
        from pcapkit.utilities.exceptions import RegistryError

        with self.assertRaises(RegistryError):
            Link.register(EtherType.Internet_Protocol_version_4, dict)

    def test_link_register_warns_on_overwrite(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link import Ethernet
        from pcapkit.protocols.link.link import Link

        original = Link.__dict__['__proto__'][EtherType.Internet_Protocol_version_4]
        try:
            with mock.patch('pcapkit.protocols.link.link.warn') as warn:
                Link.register(EtherType.Internet_Protocol_version_4, Ethernet)
            warn.assert_called_once()
            self.assertIs(Link.__dict__['__proto__'][EtherType.Internet_Protocol_version_4], Ethernet)
        finally:
            Link.__dict__['__proto__'][EtherType.Internet_Protocol_version_4] = original

    def test_internet_register_rejects_non_protocol_types(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.utilities.exceptions import RegistryError

        with self.assertRaises(RegistryError):
            Internet.register(TransType.TCP, list)

    def test_internet_register_warns_on_overwrite(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet import IPv6
        from pcapkit.protocols.internet.internet import Internet

        original = Internet.__dict__['__proto__'][TransType.TCP]
        try:
            with mock.patch('pcapkit.protocols.internet.internet.warn') as warn:
                Internet.register(TransType.TCP, IPv6)
            warn.assert_called_once()
            self.assertIs(Internet.__dict__['__proto__'][TransType.TCP], IPv6)
        finally:
            Internet.__dict__['__proto__'][TransType.TCP] = original

    def test_transport_register_rejects_abstract_base_usage(self) -> None:
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.transport import Transport
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall):
            Transport.register(80, Raw)

    def test_transport_register_rejects_non_protocol_types(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        with self.assertRaises(TypeError):
            TCP.register(65535, dict)

    def test_transport_register_warns_on_overwrite(self) -> None:
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP

        original = TCP.__dict__['__proto__'].get(80)
        try:
            with mock.patch('pcapkit.protocols.transport.transport.warn') as warn:
                TCP.register(80, Raw)
            warn.assert_called_once()
            self.assertIs(TCP.__dict__['__proto__'][80], Raw)
        finally:
            if original is None:
                TCP.__dict__['__proto__'].pop(80, None)
            else:
                TCP.__dict__['__proto__'][80] = original

    def test_pcap_frame_register_rejects_non_protocol_types(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.utilities.exceptions import RegistryError

        with self.assertRaises(RegistryError):
            Frame.register(LinkType.ETHERNET, dict)

    def test_pcap_frame_register_warns_on_overwrite(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.raw import Raw

        original = Frame.__dict__['__proto__'][LinkType.ETHERNET]
        try:
            with mock.patch('pcapkit.protocols.misc.pcap.frame.warn') as warn:
                Frame.register(LinkType.ETHERNET, Raw)
            warn.assert_called_once()
            self.assertIs(Frame.__dict__['__proto__'][LinkType.ETHERNET], Raw)
        finally:
            Frame.__dict__['__proto__'][LinkType.ETHERNET] = original


if __name__ == '__main__':
    unittest.main()
