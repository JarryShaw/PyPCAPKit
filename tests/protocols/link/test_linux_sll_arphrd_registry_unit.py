# -*- coding: utf-8 -*-
"""GitHub issue #2510: LinuxSLL dispatches its non-EtherType ``arphrd_type`` values
through a registry of its own.

Covers :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`
as shipped, dispatch through it and through the EtherType path from both versions,
the ``__index__`` of the classes it reaches, and the registrars of it and of
:class:`~pcapkit.protocols.link.frad.FRAD`'s and
:class:`~pcapkit.protocols.link.netlink.Netlink`'s registries.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))

#: The payload each ``arphrd_type`` case carries, and the chain it parses to
#: after the LinuxSLL layer.
CASES = {
    'FRAD': (bytes.fromhex('0c21') + b'\x03\xcc' + IPV4, 'FRAD:IPv4:UDP'),
    'IPGRE': (bytes.fromhex('00000800') + IPV4, 'GRE:IPv4:UDP'),
    'IP6GRE': (bytes.fromhex('00000800') + IPV4, 'GRE:IPv4:UDP'),
    'IEEE80211_RADIOTAP': (bytes.fromhex('00' '00' '0800' '00000000') + b'\xaa' * 10, 'Radiotap:Raw'),
    'NETLINK': (struct.pack('<IHHII', 20, 3, 0, 1, 0) + b'\xaa\xbb\xcc\xdd', 'Netlink:Raw'),
}


def _sll1(protocol_type: int, arphrd_type: int) -> bytes:
    """A ``LINUX_SLL`` header carrying ``protocol_type`` on ``arphrd_type``."""
    return struct.pack('>HHH8sH', 0, arphrd_type, 0, b'', protocol_type)


def _sll2(protocol_type: int, arphrd_type: int) -> bytes:
    """A ``LINUX_SLL2`` header carrying ``protocol_type`` on ``arphrd_type``."""
    return struct.pack('>HHIHBB8s', protocol_type, 0, 0, arphrd_type, 0, 0, b'')


class LinuxSLLRegistryTests(unittest.TestCase):
    """Pin ``LinuxSLL.__proto__`` and the dispatch it drives."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _versions(self):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        return ((LinuxSLL1, _sll1, 'LINUX_SLL1'), (LinuxSLL2, _sll2, 'LINUX_SLL2'))

    def _snapshot(self):  # type: ignore[no-untyped-def]
        """Every registry the registrars here write, to put back after a test."""
        from pcapkit.foundation.registry import protocols as registrars
        from pcapkit.protocols import __proto__ as names
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.netlink import Netlink

        tables = (LinuxSLL.__proto__, FRAD.__proto__, Netlink.__proto__, names,
                  registrars._CODE_LEASES, registrars._NAME_LEASES)
        copies = [dict(table) for table in tables]

        def restore() -> None:
            for table, copy in zip(tables, copies):
                table.clear()
                table.update(copy)

        self.addCleanup(restore)

    def test_the_registry_as_shipped(self) -> None:
        """Keyed by ``arphrd_type``, owned by the base, shared by both versions."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.linux_sll import LinuxSLL

        self.assertEqual(dict(LinuxSLL.__proto__), {
            ARPHRD.FRAD: ModuleDescriptor('pcapkit.protocols.link.frad', 'FRAD'),
            ARPHRD.IPGRE: ModuleDescriptor('pcapkit.protocols.link.gre', 'GRE'),
            ARPHRD.IEEE80211_RADIOTAP: ModuleDescriptor('pcapkit.protocols.link.radiotap', 'Radiotap'),
            ARPHRD.IP6GRE: ModuleDescriptor('pcapkit.protocols.link.gre', 'GRE'),
            ARPHRD.NETLINK: ModuleDescriptor('pcapkit.protocols.link.netlink', 'Netlink'),
        })
        self.assertIn('__proto__', vars(LinuxSLL))
        self.assertIsNot(LinuxSLL.__proto__, Link.__proto__)
        self.assertEqual(vars(LinuxSLL)['__proto_key__'], (ARPHRD, False))
        for version, _, _ in self._versions():
            with self.subTest(version=version.__name__):
                self.assertNotIn('__proto__', vars(version))
                self.assertIs(version.__proto__, LinuxSLL.__proto__)

    def test_each_registered_arphrd_type_dispatches_through_the_registry(self) -> None:
        """``protocol_type`` is never read as an EtherType on these, even when it is one."""
        from pcapkit.const.linux.arphrd import ARPHRD

        for version, header, alias in self._versions():
            for name, (payload, chain) in CASES.items():
                with self.subTest(version=version.__name__, arphrd=name):
                    raw = header(0x0800, getattr(ARPHRD, name)) + payload
                    parsed = version(raw, len(raw))
                    self.assertEqual(parsed.protochain.chain, f'{alias}:{chain}')
                    self.assertEqual(parsed.data, raw)
                    self.assertEqual(version.from_data(parsed.info).data, raw)

    def test_every_other_arphrd_type_dispatches_by_ethertype(self) -> None:
        """Ethernet and an ``arphrd_type`` ARPHRD names no member for, alike."""
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.misc.raw import Raw

        for version, header, alias in self._versions():
            for arphrd in (1, 0xFFFE):
                with self.subTest(version=version.__name__, arphrd=arphrd):
                    raw = header(0x0800, arphrd) + IPV4
                    parsed = version(raw, len(raw))
                    self.assertEqual(parsed.protochain.chain, f'{alias}:IPv4:UDP')

                    raw = header(0x88CC, arphrd) + IPV4
                    parsed = version(raw, len(raw))
                    self.assertIsInstance(parsed.payload, Raw)
                    self.assertIs(parsed.payload.info.protocol,
                                  EtherType.IEEE_Std_802_1AB_Link_Layer_Discovery_Protocol)

    def test_an_empty_payload_is_no_payload_on_either_path(self) -> None:
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.misc.null import NoPayload

        for version, header, _ in self._versions():
            for arphrd in (ARPHRD.FRAD, 1):
                with self.subTest(version=version.__name__, arphrd=arphrd):
                    raw = header(0x0800, arphrd)
                    self.assertIsInstance(version(raw, len(raw)).payload, NoPayload)

    def test_a_stop_at_this_layer_still_parses_a_registered_arphrd_type(self) -> None:
        """The order the NOTE in ``LinuxSLL._import_next_layer`` records.

        Stopping at the link layer or at the version keeps an EtherType payload
        :class:`~pcapkit.protocols.misc.raw.Raw`, while a registered
        ``arphrd_type`` is still dispatched.
        """
        from pcapkit.const.linux.arphrd import ARPHRD

        for version, header, alias in self._versions():
            for stop in ({'layer': 'Link'}, {'protocol': version.__name__}):
                with self.subTest(version=version.__name__, stop=stop):
                    raw = header(0x0800, 1) + IPV4
                    self.assertEqual(version(raw, len(raw), **stop).protochain.chain,
                                     f'{alias}:Internet_Protocol_version_4')

                    raw = header(0x0800, ARPHRD.NETLINK) + CASES['NETLINK'][0]
                    self.assertEqual(version(raw, len(raw), **stop).protochain.chain,
                                     f'{alias}:Netlink:Raw')

    def test_index_is_the_arphrd_type_that_dispatches_here(self) -> None:
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.netlink import Netlink
        from pcapkit.protocols.link.radiotap import Radiotap

        for klass, member in ((FRAD, ARPHRD.FRAD), (GRE, ARPHRD.IPGRE),
                              (Radiotap, ARPHRD.IEEE80211_RADIOTAP), (Netlink, ARPHRD.NETLINK)):
            with self.subTest(protocol=klass.__name__):
                self.assertIs(klass.__index__(), member)
                self.assertIs(LinuxSLL._lookup_next_layer(LinuxSLL.__proto__, klass.__index__()),
                              klass)
        self.assertIs(LinuxSLL._lookup_next_layer(LinuxSLL.__proto__, ARPHRD.IP6GRE), GRE)

    ##########################################################################
    # The registrars.
    ##########################################################################

    def test_register_arphrd_reaches_dispatch(self) -> None:
        """A registered ``arphrd_type`` stops its ``protocol_type`` being an EtherType."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.foundation.registry import register_arphrd
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.netlink import Netlink

        self._snapshot()
        loopback = ARPHRD(772)
        self.assertNotIn(loopback, LinuxSLL.__proto__)
        register_arphrd(loopback, Netlink)
        self.assertIs(LinuxSLL.__proto__[loopback], Netlink)

        for version, header, alias in self._versions():
            with self.subTest(version=version.__name__):
                raw = header(0x0800, 772) + CASES['NETLINK'][0]
                parsed = version(raw, len(raw))
                self.assertEqual(parsed.protochain.chain, f'{alias}:Netlink:Raw')
                self.assertEqual(version.from_data(parsed.info).data, raw)

    def test_register_arphrd_by_name_and_over_a_shipped_entry(self) -> None:
        """The ``(module, class_)`` form, a warning naming the key, and a silent restore."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.registry import register_arphrd
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.warnings import RegistryWarning

        self._snapshot()
        shipped = LinuxSLL.__proto__[ARPHRD.FRAD]
        with self.assertWarnsRegex(RegistryWarning, r'^ARP hardware type '):
            register_arphrd(ARPHRD.FRAD, 'pcapkit.protocols.misc.raw', 'Raw')
        self.assertIs(LinuxSLL.__proto__[ARPHRD.FRAD], Raw)

        for version, header, alias in self._versions():
            with self.subTest(version=version.__name__):
                raw = header(0x0800, ARPHRD.FRAD) + CASES['FRAD'][0]
                self.assertEqual(version(raw, len(raw)).protochain.chain, f'{alias}:Raw')

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            register_arphrd(ARPHRD.FRAD, ModuleDescriptor('pcapkit.protocols.link.frad', 'FRAD'))
        self.assertIs(LinuxSLL.__proto__[ARPHRD.FRAD], shipped)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            register_arphrd(ARPHRD.FRAD, ModuleDescriptor('pcapkit.protocols.link.frad', 'FRAD'))

    def test_register_frad_reaches_dispatch(self) -> None:
        """A registered NLPID dispatches, from FRAD alone and from a LinuxSLL frame."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.foundation.registry import register_frad
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.utilities.warnings import RegistryWarning

        self._snapshot()
        frad = bytes.fromhex('0c21') + b'\x03\x81' + IPV4  # 0x81, ISO CLNP: not registered
        self.assertEqual(FRAD(frad, len(frad)).protochain.chain, 'FRAD:Raw')

        register_frad(0x81, IPv4)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            register_frad(0x81, IPv4)  # the entry already stored: silent
        self.assertIs(FRAD.__proto__[0x81], IPv4)
        self.assertEqual(FRAD(frad, len(frad)).protochain.chain, 'FRAD:IPv4:UDP')
        for version, header, alias in self._versions():
            with self.subTest(version=version.__name__):
                raw = header(0x0800, ARPHRD.FRAD) + frad
                self.assertEqual(version(raw, len(raw)).protochain.chain,
                                 f'{alias}:FRAD:IPv4:UDP')

        with self.assertWarnsRegex(RegistryWarning, r'^NLPID 129 already registered'):
            register_frad(0x81, 'pcapkit.protocols.internet.ipv6', 'IPv6')

    def test_register_netlink_reaches_dispatch(self) -> None:
        """Netlink ships an empty registry; a registered message type dispatches."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.foundation.registry import register_netlink
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.netlink import Netlink
        from pcapkit.utilities.warnings import RegistryWarning

        self._snapshot()
        nlmsg = struct.pack('<IHHII', 16 + len(IPV4), 3, 0, 1, 0) + IPV4
        self.assertEqual(Netlink(nlmsg, len(nlmsg)).protochain.chain, 'Netlink:Raw')

        register_netlink(3, IPv4)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            register_netlink(3, IPv4)  # the entry already stored: silent
        self.assertIs(Netlink.__proto__[3], IPv4)
        self.assertEqual(Netlink(nlmsg, len(nlmsg)).protochain.chain, 'Netlink:IPv4:UDP')
        for version, header, alias in self._versions():
            with self.subTest(version=version.__name__):
                raw = header(0x0800, ARPHRD.NETLINK) + nlmsg
                self.assertEqual(version(raw, len(raw)).protochain.chain,
                                 f'{alias}:Netlink:IPv4:UDP')

        with self.assertWarnsRegex(RegistryWarning, r'^message type 3 already registered'):
            register_netlink(3, 'pcapkit.protocols.internet.ipv6', 'IPv6')

    def test_the_registrars_reject_a_code_of_the_wrong_kind(self) -> None:
        """Each refuses before writing anything, naming the registry that refused."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.foundation.registry import register_arphrd, register_frad, register_netlink
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.netlink import Netlink
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import RegistryError

        cases = (
            (register_arphrd, EtherType(770), r'^LinuxSLL: code must be a member of ARPHRD, '
                                              r'not a member of EtherType: '),
            (register_arphrd, 770, r'^LinuxSLL: code must be a member of ARPHRD, not 770$'),
            (register_frad, ARPHRD.FRAD, r'^FRAD: code must be an int, not a member of ARPHRD: '),
            (register_frad, True, r'^FRAD: code must be an int, not True$'),
            (register_netlink, '3', r"^Netlink: code must be an int, not '3'$"),
        )
        tables = (LinuxSLL.__proto__, FRAD.__proto__, Netlink.__proto__)
        for register, code, message in cases:
            with self.subTest(registrar=register.__name__, code=code):
                before = [dict(table) for table in tables]
                with self.assertRaisesRegex(RegistryError, message):
                    register(code, Raw)
                self.assertEqual([dict(table) for table in tables], before)

    def test_register_protocol_code_reads_the_owner_pairing(self) -> None:
        """A version resolves to ``LinuxSLL``'s pairing; FRAD and Netlink declare none."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.foundation.registry import register_protocol_code
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.netlink import Netlink
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import RegistryError

        self._snapshot()
        for version, _, _ in self._versions():
            with self.subTest(version=version.__name__):
                with self.assertRaisesRegex(RegistryError, r'^LinuxSLL: code must be a member of ARPHRD'):
                    register_protocol_code(Raw, {version: EtherType.Internet_Protocol_version_4})
        register_protocol_code(Raw, {version: ARPHRD(772)})
        self.assertIs(LinuxSLL.__proto__[ARPHRD(772)], Raw)

        for owner in (FRAD, Netlink):
            with self.subTest(owner=owner.__name__):
                self.assertNotIn('__proto_key__', vars(owner))
                register_protocol_code(Raw, {owner: 0x7F})
                self.assertIs(owner.__proto__[0x7F], Raw)


if __name__ == '__main__':
    unittest.main()
