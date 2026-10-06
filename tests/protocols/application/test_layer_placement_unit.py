# -*- coding: utf-8 -*-
"""``OSPF`` and ``RARP`` are application-layer, by designed function.

Settled on GitHub issue #719: layer is decided by what a protocol is *for*, not by
what encapsulates it, with the IETF as the single source of truth.
:rfc:`1812#section-7` is titled "APPLICATION LAYER - ROUTING PROTOCOLS" with OSPF at
§7.2.2 and confines the internet layer to IP, ICMP and IGMP at §4.1;
:rfc:`1122#section-1.1.3` lists RARP in the application layer while ARP sits in the
Link Layer chapter at §2.3.2. The rule and its citations are written down at
:doc:`/contributing/conventions/protocol-layer-placement`.

Three separate things are pinned here, because each broke independently while the
move was being made:

#. the ``__layer__`` values and the base classes, including the **order** of RARP's
   two bases -- ``ARP``'s chain reaches ``Link``, which owns ``__layer__``, so
   ``class RARP(ARP, Application)`` would still report ``'Link'``;
#. that the dispatch keys did **not** move with the modules, only the
   ``ModuleDescriptor`` paths they point at;
#. that parsing still works, with **no per-class override**. ``Application`` accepts
   the ``-1`` sentinel (the undissected remainder), so ``OSPF`` and ``RARP`` inherit
   ``__post_init__``, ``_decode_next_layer`` and ``_import_next_layer`` unchanged.

Every case builds its own octets in memory and reads no capture under
``examples/captures/``, which are generated rather than committed.

"""
from __future__ import annotations

import importlib
import importlib.util
import os
import struct
import tempfile
import unittest

from tests._support import purge_modules, reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def ospf_hello() -> bytes:
    """An OSPFv2 header (24 octets) plus four octets of undissected body."""
    return bytes.fromhex('0201' '001c' '0a000001' '0a000000' '0000' '0000'
                         '0000000000000000' 'ffffff00')


def rarp_request() -> bytes:
    """A RARP request, 28 octets, operation 3."""
    return bytes.fromhex('0001' '0800' '06' '04' '0003' '001122334455' '00000000'
                         '66778899aabb' '0a000001')


def ipv4(proto: 'int', payload: bytes) -> bytes:
    """A minimal IPv4 header carrying ``payload`` under protocol ``proto``."""
    total = 20 + len(payload)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, 0, 64, proto, 0,
                       bytes((10, 0, 0, 1)), bytes((224, 0, 0, 5))) + payload


def make_pcap(linktype: 'int', *frames: bytes) -> str:
    """Write ``frames`` to a little-endian PCAP file with the given link type."""
    path = os.path.join(tempfile.mkdtemp(prefix='pcapkit-placement-'), 'placement.pcap')
    with open(path, 'wb') as file:
        file.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for index, frame in enumerate(frames):
            file.write(struct.pack('<IIII', 1600000000 + index, 0, len(frame), len(frame)))
            file.write(frame)
    return path


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolLayerPlacementTests(unittest.TestCase):
    """``OSPF``/``RARP`` report ``'Application'`` and still parse and dispatch."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def tearDown(self) -> None:
        purge_modules(['pcapkit'])

    ##########################################################################
    # Layer values and base classes.
    ##########################################################################

    def test_ospf_and_rarp_report_the_application_layer(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.application.rarp import DRARP, RARP

        for cls in (OSPF, RARP, DRARP):
            with self.subTest(cls=cls.__name__):
                self.assertEqual(cls.__layer__, 'Application')

        # read off a parsed packet, not just off the class
        self.assertEqual(OSPF(ospf_hello()).layer, 'Application')
        self.assertEqual(RARP(rarp_request()).layer, 'Application')

    def test_arp_and_inarp_stay_on_the_link_layer(self) -> None:
        """:rfc:`1122#section-2.3.2` keeps ARP where it is; only RARP moved."""
        from pcapkit.protocols.link.arp import ARP, InARP

        self.assertEqual(ARP.__layer__, 'Link')
        self.assertEqual(InARP.__layer__, 'Link')

    def test_ospf_names_application_as_its_only_base(self) -> None:
        from pcapkit.protocols.application.application import Application
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.link.link import Link

        self.assertEqual(OSPF.__bases__, (Application,))
        self.assertFalse(issubclass(OSPF, Link))

    def test_rarp_subclasses_both_application_and_arp_in_that_order(self) -> None:
        """The order is load-bearing: ``Link`` owns ``__layer__``, ``Raw`` does not."""
        from pcapkit.protocols.application.application import Application
        from pcapkit.protocols.application.rarp import DRARP, RARP
        from pcapkit.protocols.link.arp import ARP
        from pcapkit.protocols.link.link import Link

        self.assertTrue(issubclass(RARP, Application))
        self.assertTrue(issubclass(RARP, ARP))
        self.assertEqual(RARP.__bases__, (Application, ARP))

        mro = RARP.__mro__
        self.assertLess(mro.index(Application), mro.index(ARP),
                        'Application must precede ARP, or Link wins __layer__')
        self.assertLess(mro.index(ARP), mro.index(Link))

        # DRARP inherits the pair unchanged
        self.assertEqual(DRARP.__bases__, (RARP,))

    def test_link_owns_layer_but_raw_does_not(self) -> None:
        """The mechanism the ordering convention rests on, asserted directly."""
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.misc.raw import Raw

        self.assertIn('__layer__', vars(Link))
        self.assertNotIn('__layer__', vars(Raw))

    ##########################################################################
    # Re-exports.
    ##########################################################################

    def test_the_public_re_exports_are_unaffected_by_the_move(self) -> None:
        import pcapkit
        import pcapkit.protocols
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.application.rarp import DRARP, RARP

        for name, cls in (('OSPF', OSPF), ('RARP', RARP), ('DRARP', DRARP)):
            with self.subTest(name=name):
                self.assertIs(getattr(pcapkit, name), cls)
                self.assertIs(getattr(pcapkit.protocols, name), cls)
                self.assertIn(name, pcapkit.__all__)
                self.assertIn(name, pcapkit.protocols.__all__)

    def test_the_names_left_the_link_subpackage(self) -> None:
        """A pure move: no deprecated re-export at the old path, by ruling."""
        import pcapkit.protocols.application
        import pcapkit.protocols.link

        for name in ('OSPF', 'RARP', 'DRARP'):
            with self.subTest(name=name):
                self.assertNotIn(name, pcapkit.protocols.link.__all__)
                self.assertIn(name, pcapkit.protocols.application.__all__)

        for path in ('pcapkit.protocols.link.ospf', 'pcapkit.protocols.link.rarp',
                     'pcapkit.protocols.data.link.ospf',
                     'pcapkit.protocols.schema.link.ospf'):
            with self.subTest(path=path):
                self.assertIsNone(importlib.util.find_spec(path))

    ##########################################################################
    # Dispatch.
    ##########################################################################

    def test_dispatch_keys_did_not_move_with_the_modules(self) -> None:
        """The dispatch tier is decoupled from the subpackage, deliberately."""
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.application.rarp import RARP
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.link.link import Link

        cases = (
            ('OSPF', Internet.__proto__[TransType.OSPFIGP],
             'pcapkit.protocols.application.ospf', OSPF),
            ('RARP', Link.__proto__[EtherType.Reverse_Address_Resolution_Protocol],
             'pcapkit.protocols.application.rarp', RARP),
        )
        for name, entry, module, cls in cases:
            with self.subTest(name=name):
                self.assertIsInstance(entry, ModuleDescriptor)
                self.assertEqual(entry.module, module)
                self.assertEqual(entry.name, name)
                # the descriptor must actually resolve, not merely read right
                self.assertIs(getattr(importlib.import_module(entry.module), entry.name), cls)

    def test_ospf_leaves_links_registry_behind_and_rarp_keeps_it(self) -> None:
        """``Link`` sets seven names beyond ``ProtocolBase``; OSPF loses three of them.

        ``__proto__``, ``register`` and ``_read_protos`` are ``Link``'s EtherType
        machinery. The loss is inert because a ``-1`` lookup misses in either
        registry and falls back to :class:`~pcapkit.protocols.misc.raw.Raw`.
        """
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.application.rarp import RARP
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import ProtocolBase

        self.assertEqual(
            sorted(name for name in vars(Link)
                   if name in ('__data__', '__layer__', '__proto__', '__schema__',
                               '_read_protos', 'layer', 'register')),
            ['__data__', '__layer__', '__proto__', '__schema__', '_read_protos', 'layer', 'register'])

        self.assertIsNot(OSPF.__proto__, Link.__proto__)
        self.assertIs(OSPF.__proto__, ProtocolBase.__proto__)
        self.assertIs(OSPF._read_protos, ProtocolBase._read_protos)
        self.assertIs(RARP._read_protos, Link._read_protos)
        self.assertIsNot(OSPF.register.__func__, Link.register.__func__)

        self.assertIs(RARP.__proto__, Link.__proto__)
        self.assertIs(RARP.register.__func__, Link.register.__func__)

        for registry in (Link.__proto__, ProtocolBase.__proto__):
            with self.subTest(registry=registry is Link.__proto__):
                self.assertNotIn(-1, registry)
                self.assertIs(ProtocolBase._lookup_next_layer(registry, -1), Raw)
                self.assertNotIn(-1, registry, 'a miss must not grow the registry')

    ##########################################################################
    # Parsing -- no override of the next-layer hooks.
    ##########################################################################

    def test_ospf_and_rarp_override_none_of_the_next_layer_hooks(self) -> None:
        """Both inherit the hooks from ``Application`` rather than re-pointing them."""
        from pcapkit.protocols.application.application import Application
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.application.rarp import DRARP, RARP

        hooks = ('__post_init__', '_decode_next_layer', '_import_next_layer')
        for cls in (OSPF, RARP, DRARP):
            for hook in hooks:
                with self.subTest(cls=cls.__name__, hook=hook):
                    self.assertNotIn(hook, vars(cls))
                    self.assertIs(getattr(cls, hook), getattr(Application, hook))

    def test_ospf_still_attaches_its_undissected_body(self) -> None:
        """OSPF dispatches its body on ``-1``, which ``Application`` accepts."""
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.misc.raw import Raw

        packet = OSPF(ospf_hello())
        self.assertEqual(str(packet.protochain), 'OSPFv2:Raw')
        self.assertIsInstance(packet.payload, Raw)

    def test_rarp_still_attaches_a_padded_frames_trailer(self) -> None:
        """Ethernet pads a short RARP frame; ``ARP.read`` dispatches the padding."""
        from pcapkit.protocols.application.rarp import RARP
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.misc.raw import Raw

        unpadded = RARP(rarp_request())
        self.assertEqual(str(unpadded.protochain), 'RARP')
        self.assertIsInstance(unpadded.payload, NoPayload)

        padded = RARP(rarp_request() + bytes(18))
        self.assertEqual(str(padded.protochain), 'RARP:Raw')
        self.assertIsInstance(padded.payload, Raw)

    ##########################################################################
    # Layer-limited extraction.
    ##########################################################################

    def extract_ipv4_ospf(self, **kwargs):
        """Extract a LinkType ``IPV4`` capture carrying IPv4/OSPF, no Ethernet."""
        import pcapkit
        from pcapkit.const.reg.linktype import LinkType

        extraction = pcapkit.extract(fin=make_pcap(LinkType.IPV4, ipv4(89, ospf_hello())),
                                     nofile=True, store=True, engine='pcapkit', **kwargs)
        self.addCleanup(extraction.__del__)
        return extraction.frame[0]

    def test_layer_link_extraction_of_a_headerless_ipv4_capture(self) -> None:
        """Inert for the protochain, though the termination flag moves. Measured.

        ``_sigterm`` on the OSPF instance was ``True`` under ``layer='link'`` while
        OSPF reported ``'Link'``, and is ``False`` now. The extracted result does
        not change, because OSPF dispatches its body on the ``-1`` sentinel and
        both the ``_sigterm`` branch of ``_import_next_layer`` and
        ``ProtocolBase.__proto__``'s default resolve to
        :class:`~pcapkit.protocols.misc.raw.Raw`. A ``link`` extraction of a
        capture with no Ethernet header never reaches a link protocol at all.
        """
        from pcapkit.protocols.application.ospf import OSPF

        frame = self.extract_ipv4_ospf(layer='link')
        self.assertEqual(str(frame.protochain), 'IPv4:OSPFv2:Raw')

        ospf = frame.payload.payload
        self.assertIsInstance(ospf, OSPF)
        self.assertEqual(ospf.layer, 'Application')
        self.assertFalse(ospf._sigterm, "'link' must no longer terminate at OSPF")

    def test_layer_application_extraction_now_terminates_at_ospf(self) -> None:
        """The flip side: ``layer='application'`` now matches where it did not."""
        frame = self.extract_ipv4_ospf(layer='application')
        self.assertEqual(str(frame.protochain), 'IPv4:OSPFv2:Raw')

        ospf = frame.payload.payload
        self.assertTrue(ospf._sigterm, "'application' must terminate at OSPF")

    def test_layer_internet_extraction_stops_at_ipv4_as_before(self) -> None:
        """OSPF is not reached under ``internet`` either way: IPv4 terminates first."""
        frame = self.extract_ipv4_ospf(layer='internet')
        self.assertEqual(str(frame.protochain), 'IPv4:OSPFIGP')

    def test_rarp_over_ethernet_is_unchanged_under_every_layer_limit(self) -> None:
        """Ethernet-framed RARP: the chain is the same for each ``layer=`` value."""
        import pcapkit
        from pcapkit.const.reg.linktype import LinkType

        frame_bytes = bytes.fromhex('ffffffffffff' '001122334455' '8035') + rarp_request() + bytes(18)
        expected = {
            None: 'Ethernet:RARP:Raw',
            'link': 'Ethernet:Reverse_Address_Resolution_Protocol',
            'internet': 'Ethernet:RARP:Raw',
            'application': 'Ethernet:RARP:Raw',
        }
        for layer, chain in expected.items():
            with self.subTest(layer=layer):
                kwargs = {} if layer is None else {'layer': layer}
                extraction = pcapkit.extract(
                    fin=make_pcap(LinkType.ETHERNET, frame_bytes),
                    nofile=True, store=True, engine='pcapkit', **kwargs)
                self.addCleanup(extraction.__del__)
                self.assertEqual(str(extraction.frame[0].protochain), chain)

    def test_unlimited_extraction_is_unchanged(self) -> None:
        frame = self.extract_ipv4_ospf()
        self.assertEqual(str(frame.protochain), 'IPv4:OSPFv2:Raw')
        self.assertFalse(frame.payload.payload._sigterm)


if __name__ == '__main__':
    unittest.main()
