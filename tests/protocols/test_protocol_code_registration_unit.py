# -*- coding: utf-8 -*-
"""``code=`` opt-in next-layer dispatch registration.

GitHub issue #514 part (b): :class:`~pcapkit.protocols.protocol.Protocol`/
:class:`~pcapkit.protocols.protocol.ProtocolBase` gain a ``code`` class
keyword that registers a subclass into the next-layer dispatch registry (or
registries) it names -- e.g. :attr:`Link.__proto__
<pcapkit.protocols.link.link.Link.__proto__>`. Registration is opt-in,
exactly like the ``engine=``/``protocol=``/``fmt=`` keywords part (a) (#547)
gave :class:`~pcapkit.foundation.engines.engine.Engine`,
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`,
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` and
:class:`~pcapkit.dumpkit.common.Dumper` (``Engine``'s is ``engine=`` rather
than ``name=``, #557): omitting ``code`` leaves the
subclass unregistered, which is exactly what every built-in protocol class
does, since the built-in dispatch tables are populated by literal
assignment in each layer module rather than by ``__init_subclass__``.

Most tests here mock the destination classes' ``register`` classmethod (or
:func:`~pcapkit.foundation.registry.protocols.register_protocol_code`
itself) rather than mutating the real, process-wide ``__proto__`` registries
-- those are shared, module-level singletons, and a leaked entry would
corrupt :file:`test_dispatch_registry_unit.py`'s exact-count assertions for
the rest of the test session. The handful of tests that do exercise a real
table use :func:`unittest.mock.patch.dict` so the entry is guaranteed gone
again once the ``with`` block exits, even on failure.

"""
from __future__ import annotations

import importlib.util
import sys
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): branches on the running interpreter's version or implementation.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolCodeOptInTests(unittest.TestCase):
    """The opt-in gate itself: ``register_protocol_code`` runs iff ``code`` is given."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_code_omitted_leaves_next_layer_dispatch_unregistered(self) -> None:
        """No ``code=`` -> :func:`register_protocol_code` is never called."""
        from pcapkit.protocols.internet.internet import Internet

        with mock.patch('pcapkit.foundation.registry.protocols.register_protocol_code') as register:
            class NoCode(Internet):
                __layer__ = 'Internet'

        register.assert_not_called()
        # ``schema``/``data`` resolution still ran -- opting out of dispatch
        # registration does not opt out of anything else.
        self.assertTrue(hasattr(NoCode, '__schema__'))
        self.assertTrue(hasattr(NoCode, '__data__'))

    def test_code_given_calls_register_protocol_code(self) -> None:
        """A bare enum member is forwarded to :func:`register_protocol_code` unchanged."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet

        with mock.patch('pcapkit.foundation.registry.protocols.register_protocol_code') as register:
            class WithCode(Internet, code=TransType.GRE):
                __layer__ = 'Internet'

        register.assert_called_once_with(WithCode, TransType.GRE)

    def test_public_protocol_class_forwards_code_the_same_way(self) -> None:
        """Subclassing the public :class:`Protocol` reaches the same hook.

        ``Protocol.__init_subclass__`` also runs ``register_protocol`` (the
        name-keyed identity registry), which is unconditional and unrelated
        to ``code``; this only asserts the dispatch side.
        """
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.protocol import Protocol

        with mock.patch('pcapkit.foundation.registry.protocols.register_protocol_code') as register:
            class WithCode(Protocol, code=EtherType.XEROX_NS_IDP):
                __layer__ = None

                @property
                def name(self) -> str:
                    return 'WithCode'

                @classmethod
                def __index__(cls):
                    return 0

        register.assert_called_once_with(WithCode, EtherType.XEROX_NS_IDP)

    def test_unrecognised_class_keyword_raises_unsupportedcall(self) -> None:
        """A misspelled keyword raises rather than being silently swallowed.

        Without this hook, extra keywords fall into ``**kwargs`` and are
        dropped by a bare ``super().__init_subclass__()`` -- no exception, no
        warning. ``codes=`` (plural) is the natural typo for
        ``code=``, and does not collide with :meth:`abc.ABCMeta.__new__`.
        """
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.utilities.exceptions import UnsupportedCall

        with mock.patch('pcapkit.foundation.registry.protocols.register_protocol_code') as register:
            with self.assertRaises(UnsupportedCall) as caught:
                class Typo(Internet, codes=['wrong-keyword']):
                    __layer__ = 'Internet'

        register.assert_not_called()
        self.assertIn('codes', str(caught.exception))

    def test_name_keyword_collision_is_pinned_per_python_version(self) -> None:
        """``name=`` collides with :meth:`abc.ABCMeta.__new__` on 3.10, not 3.11+.

        Mirrors ``test_reassembly_subclass_rejects_unrecognised_keyword`` in
        ``tests/foundation/reassembly/test_reassembly_base.py``: ``mcls``,
        ``name``, ``bases`` and ``namespace`` are positional-or-keyword on
        3.10 and positional-only from 3.11, so the same misspelled keyword
        surfaces a different exception depending on interpreter version.
        ``Protocol``/``ProtocolBase`` never gave ``name`` a meaning, so this
        is purely about which exception reaches the caller, not a real
        keyword clash in the API.
        """
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.utilities.exceptions import UnsupportedCall

        expected = UnsupportedCall if sys.version_info >= (3, 11) else TypeError
        with mock.patch('pcapkit.foundation.registry.protocols.register_protocol_code') as register:
            with self.assertRaises(expected):
                class Collides(Internet, name='collides-with-ABCMeta-on-3.10'):
                    __layer__ = 'Internet'

        register.assert_not_called()


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegisterProtocolCodeInferenceTests(unittest.TestCase):
    """Unit tests for ``register_protocol_code``/the ``__proto_dest__`` it reads.

    Every destination class's ``register`` classmethod is mocked, so none of
    these touch a real, process-wide ``__proto__`` table.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_bare_ethertype_member_infers_link(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.link.link import Link

        class FakeProtocol:
            pass

        with mock.patch.object(Link, 'register') as register:
            register_protocol_code(FakeProtocol, EtherType.XEROX_NS_IDP)
        register.assert_called_once_with(EtherType.XEROX_NS_IDP, FakeProtocol)

    def test_bare_transtype_member_infers_internet(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.internet.internet import Internet

        class FakeProtocol:
            pass

        with mock.patch.object(Internet, 'register') as register:
            register_protocol_code(FakeProtocol, TransType.GRE)
        register.assert_called_once_with(TransType.GRE, FakeProtocol)

    def test_bare_payload_protocol_identifier_infers_sctp(self) -> None:
        from pcapkit.const.sctp.payload_protocol_identifier import \
            PayloadProtocolIdentifier
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.transport.sctp import SCTP

        class FakeProtocol:
            pass

        with mock.patch.object(SCTP, 'register') as register:
            register_protocol_code(FakeProtocol, PayloadProtocolIdentifier.IUA)
        register.assert_called_once_with(PayloadProtocolIdentifier.IUA, FakeProtocol)

    def test_bare_linktype_member_infers_both_frame_and_pcapng(self) -> None:
        """``LinkType`` names two destinations deterministically, not ambiguously.

        Mirrors what :func:`~pcapkit.foundation.registry.protocols.register_linktype`
        already does by hand (calls both ``Frame.register`` and
        ``PCAPNG.register`` on the same code).
        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG

        class FakeProtocol:
            pass

        with mock.patch.object(Frame, 'register') as reg_frame, \
                mock.patch.object(PCAPNG, 'register') as reg_pcapng:
            register_protocol_code(FakeProtocol, LinkType.RAW)
        reg_frame.assert_called_once_with(LinkType.RAW, FakeProtocol)
        reg_pcapng.assert_called_once_with(LinkType.RAW, FakeProtocol)

    def test_bare_arphrd_member_infers_linux_sll(self) -> None:
        """``ARPHRD`` names ``LinuxSLL``, the family base owning the registry (#2533)."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.link.linux_sll import LinuxSLL

        class FakeProtocol:
            pass

        with mock.patch.object(LinuxSLL, 'register') as register:
            register_protocol_code(FakeProtocol, ARPHRD.NETROM)
        register.assert_called_once_with(ARPHRD.NETROM, FakeProtocol)

    def test_raw_int_without_explicit_destination_refuses(self) -> None:
        """A bare ``int`` cannot say whether it means TCP or UDP -- it must refuse.

        This is the genuine residue the enum-type rule cannot cover: no
        ``EtherType``/``TransType``/``LinkType``/``PayloadProtocolIdentifier``
        member exists for ``0x8137`` (IPX) or for a TCP/UDP port, so there is
        nothing to infer from.
        """
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.utilities.exceptions import RegistryError

        class FakeProtocol:
            pass

        with self.assertRaises(RegistryError) as caught:
            register_protocol_code(FakeProtocol, 54321)
        self.assertIn('destination', str(caught.exception))

    def test_explicit_dict_registers_named_destination(self) -> None:
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.transport.tcp import TCP

        class FakeProtocol:
            pass

        with mock.patch.object(TCP, 'register') as register:
            register_protocol_code(FakeProtocol, {TCP: 54322})
        register.assert_called_once_with(54322, FakeProtocol)

    def test_explicit_dict_spanning_two_destinations(self) -> None:
        """One declaration, e.g. an application port meaningful on both transports."""
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        class FakeProtocol:
            pass

        with mock.patch.object(TCP, 'register') as reg_tcp, \
                mock.patch.object(UDP, 'register') as reg_udp:
            register_protocol_code(FakeProtocol, {TCP: 54323, UDP: 54323})
        reg_tcp.assert_called_once_with(54323, FakeProtocol)
        reg_udp.assert_called_once_with(54323, FakeProtocol)

    def test_iterable_mixes_inferred_and_explicit_targets(self) -> None:
        """The L2TPv3 shape: one class, an inferred entry and an explicit one.

        An ``L2TPv3`` class -- which this package does not implement yet -- would
        be a ``Link``-layer class reachable both by an IP protocol number
        (inferred: ``TransType`` -> ``Internet``, :rfc:`3931` §4.1.1) and by a
        UDP port (explicit, since a bare port cannot say TCP or UDP,
        :rfc:`3931` §4.1.2) -- see #514's design thread.

        Deliberately *not* ``L2TPv2`` (#548): v2 answers on port 1701 only, and
        registering it at ``TransType.L2TP`` points the :rfc:`2661` parser at a
        v3-over-IP header. The mechanism under test is the same either way -- the
        class here is a stand-in and nothing is really registered -- but the example
        should not recommend a binding the library refuses.
        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.transport.udp import UDP

        class FakeL2TPLike:
            pass

        with mock.patch.object(Internet, 'register') as reg_internet, \
                mock.patch.object(UDP, 'register') as reg_udp:
            register_protocol_code(FakeL2TPLike, [TransType.L2TP, {UDP: 1701}])
        reg_internet.assert_called_once_with(TransType.L2TP, FakeL2TPLike)
        reg_udp.assert_called_once_with(1701, FakeL2TPLike)

    def test_explicit_form_accepted_for_an_inferable_key(self) -> None:
        """Q12: ``{Internet: TransType.X}`` is legal, not an error, though inferable.

        Refusing it would punish someone for being clearer than required --
        the design thread's own reasoning for accepting the redundancy.
        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.internet.internet import Internet

        class FakeProtocol:
            pass

        with mock.patch.object(Internet, 'register') as register:
            register_protocol_code(FakeProtocol, {Internet: TransType.IGMP})
        register.assert_called_once_with(TransType.IGMP, FakeProtocol)

    def test_unknown_enum_type_refuses_rather_than_guessing(self) -> None:
        """An enum type declaring no ``__proto_dest__`` raises, not a silent no-op.

        ``AppType`` is deliberately not a live ``__proto__`` key type --
        ``register_apptype`` converts it to a port ``int`` before storing --
        so it must not be treated as inferable.
        """
        from pcapkit.const.reg.apptype import TCP as AppType_TCP
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.utilities.exceptions import RegistryError

        class FakeProtocol:
            pass

        with self.assertRaises(RegistryError) as caught:
            register_protocol_code(FakeProtocol, AppType_TCP.tcpmux)
        self.assertIn('no destination registry is known', str(caught.exception))

    def test_string_code_refuses_instead_of_iterating_characters(self) -> None:
        """A ``str`` is technically ``Iterable``, but iterating it is never intended."""
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.utilities.exceptions import RegistryError

        class FakeProtocol:
            pass

        with self.assertRaises(RegistryError):
            register_protocol_code(FakeProtocol, 'not-a-real-code')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolCodeEndToEndTests(unittest.TestCase):
    """A handful of tests through the real ``class`` statement and real tables.

    ``mock.patch.dict`` snapshots each registry before mutating it and
    restores it verbatim afterwards, so these cannot leak a stray entry into
    ``test_dispatch_registry_unit.py``'s exact-count assertions even if an
    assertion here fails first.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_end_to_end_class_statement_registers_the_real_table(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet

        with mock.patch.dict(Internet.__proto__, {}, clear=False):
            class MyGre(Internet, code=TransType.GRE):
                __layer__ = 'Internet'

            self.assertIs(Internet.__proto__[TransType.GRE], MyGre)
        self.assertNotIn(TransType.GRE, Internet.__proto__)

    def test_class_keyword_with_an_arphrd_member_reaches_linux_sll_dispatch(self) -> None:
        """``code=ARPHRD.X`` registers where a cooked frame dispatches (#2533)."""
        import struct

        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
        from pcapkit.protocols.misc.raw import Raw

        self.assertNotIn(ARPHRD.NETROM, LinuxSLL.__proto__)
        frame = struct.pack('>HHIHBB8s', 0x0800, 0, 0, ARPHRD.NETROM, 0, 0, b'') + b'\xaa\xbb'

        with mock.patch.dict(LinuxSLL.__proto__, {}, clear=False):
            class NetROM(Raw, code=ARPHRD.NETROM):
                pass

            self.assertIs(LinuxSLL.__proto__[ARPHRD.NETROM], NetROM)
            self.assertEqual(LinuxSLL2(frame, len(frame)).protochain.chain, 'LINUX_SLL2:NetROM')
        self.assertNotIn(ARPHRD.NETROM, LinuxSLL.__proto__)

    def test_subclass_without_code_does_not_inherit_parent_registration(self) -> None:
        """Opting in is per-subclass, not inherited from a registered parent.

        Mirrors part (a)'s ``Parent``/``Derived``/``DerivedOptIn`` measurement
        on the issue thread: a subclass of a registered class that itself
        passes no ``code=`` must not re-register under its own name -- there
        is no name-derived fallback to do that with, but the property is
        worth pinning directly for ``Protocol`` too.
        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet

        with mock.patch.dict(Internet.__proto__, {}, clear=False):
            class Parent(Internet, code=TransType.GRE):
                __layer__ = 'Internet'

            self.assertIs(Internet.__proto__[TransType.GRE], Parent)

            class Child(Parent):
                __layer__ = 'Internet'

            # ``Child`` passed no ``code=``, so the entry must still be ``Parent``.
            self.assertIs(Internet.__proto__[TransType.GRE], Parent)
            self.assertNotIn(Child, Internet.__proto__.values())
        self.assertNotIn(TransType.GRE, Internet.__proto__)

    def test_backward_compatible_dispatch_tables_are_unaffected(self) -> None:
        """No built-in protocol class passes ``code=``, so nothing shipped moves.

        The built-in dispatch tables (``Link.__proto__``, etc.) are populated
        by literal assignment in each layer module; re-importing the package
        must not have moved a single entry as a side effect of this hook
        existing.
        """
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.link.link import Link

        # Built-in entries are ``ModuleDescriptor``s, resolved lazily on first
        # dispatch (see ``ProtocolBase._lookup_registry``) -- this asserts the
        # table still *names* ``IPv4``, without triggering that resolution.
        link_entry = Link.__proto__[EtherType.Internet_Protocol_version_4]
        internet_entry = Internet.__proto__[TransType.IPv4]
        self.assertIsInstance(link_entry, ModuleDescriptor)
        self.assertEqual((link_entry.module, link_entry.name),
                         ('pcapkit.protocols.internet.ipv4', 'IPv4'))
        self.assertIsInstance(internet_entry, ModuleDescriptor)
        self.assertEqual((internet_entry.module, internet_entry.name),
                         ('pcapkit.protocols.internet.ipv4', 'IPv4'))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegisterProtocolCodeKeyCheckTests(unittest.TestCase):
    """Each ``code=`` key is checked against its destination's key type, all before any registers (#2268).

    The typed registrars reject a member of another enum (#2224), and
    ``register_protocol_code`` checks every ``{destination: key}`` pair against
    its destination's key type before it registers anything. The registry enums
    compare equal to their values, so a pair handed straight to
    ``destination.register`` -- ``{Frame: TransType.ICMP}`` -- would replace the
    shipped entry at ``LinkType.ETHERNET`` with only a warning; checking every
    pair up front also leaves no earlier target registered when a later one is
    bad.

    Each case snapshots every dispatch registry and the name registry, expects
    :exc:`~pcapkit.utilities.exceptions.RegistryError`, compares each registry
    with its snapshot, and restores the snapshot whatever happened.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rejected_unchanged(self, call: 'Any') -> None:
        from pcapkit.protocols import __proto__ as protocol_registry
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP
        from pcapkit.utilities.exceptions import RegistryError

        tables = {klass.__name__: klass.__proto__
                  for klass in (Link, Internet, IPX, Frame, PCAPNG, TCP, UDP, SCTP)}
        tables['pcapkit.protocols'] = protocol_registry
        before = {name: dict(table) for name, table in tables.items()}
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with self.assertRaises(RegistryError):
                    call()
            for name, table in tables.items():
                if name != 'pcapkit.protocols':
                    self.assertEqual(dict(table), before[name], f'{name}.__proto__ changed')
        finally:
            for name, table in tables.items():
                table.clear()
                table.update(before[name])

    def test_mapping_rejects_a_member_of_another_enum(self) -> None:
        """The issue's example: ``TransType.ICMP`` equals ``LinkType.ETHERNET``."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.raw import Raw

        self.assertEqual(TransType.ICMP, LinkType.ETHERNET)
        self._assert_rejected_unchanged(lambda: register_protocol_code(Raw, {Frame: TransType.ICMP}))

    def test_class_keyword_rejects_a_member_of_another_enum(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.raw import Raw

        def define() -> None:
            class Evil(Raw, code={Frame: TransType.ICMP}):
                pass

        self._assert_rejected_unchanged(define)

    def test_subclass_sharing_a_registry_is_checked_as_its_owner(self) -> None:
        """``Ethernet`` inherits ``Link.__proto__``, so its keys are ``EtherType``s."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw

        self._assert_rejected_unchanged(lambda: register_protocol_code(Raw, {Ethernet: TransType.ICMP}))

    def test_number_destination_rejects_a_member_of_another_enum(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.udp import UDP

        self._assert_rejected_unchanged(lambda: register_protocol_code(Raw, {UDP: LinkType(53)}))

    def test_a_bad_later_target_leaves_the_earlier_ones_unregistered(self) -> None:
        """The issue's list example, and one whose bad target fails the key check instead."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.misc.raw import Raw

        for code in ([TransType.L2TP, 5], [TransType.L2TP, {Internet: 115}]):
            with self.subTest(code=code):
                self._assert_rejected_unchanged(lambda: register_protocol_code(Raw, code))

    def test_number_and_own_registry_destinations_still_accept_an_int(self) -> None:
        """A port is a valid ``TCP`` key; ``Loopback`` keeps an unchecked registry of its own."""
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.protocols.transport.tcp import TCP

        class FakeProtocol:
            pass

        with mock.patch.object(TCP, 'register') as reg_tcp, \
                mock.patch.object(Loopback, 'register') as reg_loopback:
            register_protocol_code(FakeProtocol, [{TCP: 54324}, {Loopback: 2}])
        reg_tcp.assert_called_once_with(54324, FakeProtocol)
        reg_loopback.assert_called_once_with(2, FakeProtocol)

    def test_every_destination_kind_row_is_enforced(self) -> None:
        """Every ``__proto_key__`` declaration is exercised, both cells of it.

        The declarations are what the check is made of, so one dropped from a
        class, or a ``kind``/``number`` cell changed in it, silently stops
        checking a destination -- the registrars they stand in for are not
        called here, so nothing else would notice. Each is pinned by behaviour
        rather than by comparing the declaration with a copy of itself:

        * ``kind`` -- a member of *another* registry's enum must be rejected,
          and must leave every registry as it was. That is the #2224 confusion
          the check exists for, so a class that stops being checked, or one
          checked against the wrong enum, fails here.
        * ``number`` -- a bare :class:`int` is accepted where the registrar
          accepts one (a port, a payload protocol identifier, an IPX Packet
          Type) and rejected
          where it does not, which is the only observable difference the flag
          makes. The :class:`int` given to a rejecting class is the *value* of a
          member its registry already ships an entry at, so the check is pinned
          as being on the type and the entry at risk is a real one.

        The declared pairing is asserted as well, since one retyped to an enum
        unrelated to every key used here would reject both keys for the wrong
        reason. It is read out of the class's own :func:`vars`, which is where
        :func:`~pcapkit.foundation.registry.protocols.register_protocol_code`
        reads it: an inherited one would not be its own declaration.
        """
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.dccp import DCCP
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        # destination -> (kind, number, a member of another enum, a bare int)
        expected = {
            # 0x0800 is EtherType.Internet_Protocol_version_4, where Link ships IPv4.
            Link: (EtherType, False, TransType.ICMP, 0x0800),
            # 770 is ARPHRD.FRAD, where LinuxSLL ships FRAD; the EtherType is the
            # key of Link's registry, which LinuxSLL's own refuses (#2510).
            LinuxSLL: (ARPHRD, False, EtherType.Internet_Protocol_version_4, 770),
            # 6 is TransType.TCP, where Internet ships TCP.
            Internet: (TransType, False, EtherType.XEROX_NS_IDP, 6),
            # TransType.UDP is 17, Packet.NCP: IPX's registry of its own exists so
            # that the one cannot key the other (#2169).
            IPX: (Packet, True, TransType.UDP, 4),
            # The issue's own example: TransType.ICMP == LinkType.ETHERNET, where
            # both Frame and PCAPNG ship Ethernet.
            Frame: (LinkType, False, TransType.ICMP, 1),
            PCAPNG: (LinkType, False, TransType.ICMP, 1),
            TCP: (AppType, True, LinkType(53), 54324),
            UDP: (AppType, True, LinkType(53), 54324),
            DCCP: (AppType, True, LinkType(53), 54324),
            SCTP: (PayloadProtocolIdentifier, True, TransType.ICMP, 54324),
        }

        for destination, (kind, number, member, raw) in expected.items():
            with self.subTest(destination=destination.__name__):
                self.assertNotIsInstance(member, kind)  # the test data, not the declaration

                self._assert_rejected_unchanged(
                    lambda dest=destination, key=member: register_protocol_code(Raw, {dest: key}))

                if number:
                    with mock.patch.object(destination, 'register') as register:
                        register_protocol_code(Raw, {destination: raw})
                    register.assert_called_once_with(raw, Raw)
                else:
                    self._assert_rejected_unchanged(
                        lambda dest=destination, key=raw: register_protocol_code(Raw, {dest: key}))

                self.assertEqual(vars(destination).get('__proto_key__'), (kind, number),
                                 f'{destination.__name__} does not declare '
                                 f'({kind.__name__}, {number})')

        self.assertEqual(self._declaring_classes(), set(expected),
                         '__proto_key__ is no longer declared by the classes cased here')

    @staticmethod
    def _declaring_classes() -> 'set[type]':
        """Every ``ProtocolBase`` descendant declaring a ``__proto_key__`` of its own."""
        import pcapkit  # noqa: F401  # pylint: disable=unused-import
        from pcapkit.protocols.protocol import ProtocolBase

        found = set()
        pending = [ProtocolBase]
        while pending:
            klass = pending.pop()
            if '__proto_key__' in vars(klass):
                found.add(klass)
            pending.extend(klass.__subclasses__())
        return found

    def test_a_registry_of_its_own_does_not_inherit_its_parent_pairing(self) -> None:
        """``Loopback.__proto__`` is keyed by address family, ``IPX.__proto__`` by packet type.

        The pairing is read from the owning class's own :func:`vars`, not with
        :func:`getattr`, which walks the MRO: :class:`~pcapkit.protocols.link.\
loopback.Loopback` subclasses :class:`~pcapkit.protocols.link.link.Link`, so it
        *inherits* the attribute while owning a registry keyed by something
        else entirely, and no enum names its keys for it to declare one of its
        own. A key is therefore registered here rather than only the absent
        declaration asserted: checking address family ``2`` against
        :class:`~pcapkit.const.reg.ethertype.EtherType` rejects every key this
        registry does accept, and an assertion on :func:`vars` alone passes
        either way.

        :class:`~pcapkit.protocols.internet.ipx.IPX` declares a pairing of its
        own instead (#2511), so a bare packet type and a member of its own enum
        both reach it, where :class:`~pcapkit.protocols.internet.internet.Internet`'s
        would refuse the first and misread the second as an IP protocol number.
        """
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.loopback import Loopback

        cases = (
            (Loopback, Link, 2),             # an address family, not an EtherType
            (IPX, Internet, 4),              # a bare packet type, not an IP protocol number
            (IPX, Internet, Packet.PEP),     # the same, as a member of its own enum
        )
        for destination, parent, key in cases:
            with self.subTest(destination=destination.__name__, key=key):
                self.assertIn('__proto__', vars(destination))  # it owns a registry
                if destination is IPX:
                    self.assertNotEqual(vars(destination)['__proto_key__'], parent.__proto_key__)
                else:
                    self.assertNotIn('__proto_key__', vars(destination))  # declares no pairing
                    # inherited, not declared -- which is what makes the ``vars()`` read load-bearing
                    self.assertEqual(destination.__proto_key__, parent.__proto_key__)

                class FakeProtocol:
                    pass

                with mock.patch.object(destination, 'register') as register:
                    register_protocol_code(FakeProtocol, {destination: key})
                register.assert_called_once_with(key, FakeProtocol)

    def test_a_rejection_names_the_destination_registry(self) -> None:
        """The message says *whose* registry rejected the key, not only what it wanted."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.udp import UDP
        from pcapkit.utilities.exceptions import RegistryError

        for destination, key in ((Frame, TransType.ICMP), (UDP, LinkType(53))):
            with self.subTest(destination=destination.__name__):
                with self.assertRaisesRegex(RegistryError,
                                            rf'^{destination.__name__}: code must be '):
                    register_protocol_code(Raw, {destination: key})


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtoDestDeclarationTests(unittest.TestCase):
    """``__proto_dest__``, the declaration inference reads (#2392).

    The enumeration registry classes name their destination class(es)
    themselves, as a ``__proto_dest__`` dunder, so inference reads the pairing
    off the key's own type -- the mirror of ``__proto_key__``, which each
    destination declares to name the enum its own registry is keyed by. These
    pin the declarations themselves; the ``register_protocol_code`` behaviour
    they drive, which is the point of them, is pinned by
    :class:`RegisterProtocolCodeInferenceTests` above.
    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    #: ``enum registry -> the destination class(es) it names``, as dotted paths
    #: so the expectation does not import what it is checking.
    EXPECTED = (
        ('pcapkit.const.reg.ethertype', 'EtherType',
         (('pcapkit.protocols.link.link', 'Link'),)),
        ('pcapkit.const.reg.transtype', 'TransType',
         (('pcapkit.protocols.internet.internet', 'Internet'),)),
        ('pcapkit.const.sctp.payload_protocol_identifier', 'PayloadProtocolIdentifier',
         (('pcapkit.protocols.transport.sctp', 'SCTP'),)),
        ('pcapkit.const.reg.linktype', 'LinkType',
         (('pcapkit.protocols.misc.pcap.frame', 'Frame'),
          ('pcapkit.protocols.misc.pcapng', 'PCAPNG'))),
        ('pcapkit.const.linux.arphrd', 'ARPHRD',
         (('pcapkit.protocols.link.linux_sll', 'LinuxSLL'),)),
    )

    def test_each_registry_declares_the_destinations_it_keys(self) -> None:
        """Resolved, and in order -- ``LinkType`` fans out to both formats.

        A declaration is read off the class's own :func:`vars`, since an
        enumeration that inherited one would be declaring nothing.
        """
        import importlib

        for module, name, expected in self.EXPECTED:
            with self.subTest(registry=name):
                klass = getattr(importlib.import_module(module), name)
                declared = vars(klass).get('__proto_dest__')
                self.assertIsNotNone(declared, f'{name} declares no __proto_dest__')
                self.assertEqual(
                    [(entry.klass.__module__, entry.klass.__name__) for entry in declared],
                    [tuple(pair) for pair in expected])

    def test_the_declarations_name_classes_lazily_rather_than_importing_them(self) -> None:
        """:mod:`pcapkit.const` must not import :mod:`pcapkit.protocols`.

        That is why #2392 declares a
        :class:`~pcapkit.corekit.module.ModuleDescriptor` rather than the class:
        ``const`` sits strictly below ``protocols``, so holding a real class
        reference would make the import circular. Pinned on the generated source
        as well as on the value, since a regeneration is what would reintroduce
        it.
        """
        import importlib
        import pathlib

        from pcapkit.corekit.module import ModuleDescriptor

        for module, name, _ in self.EXPECTED:
            with self.subTest(registry=name):
                imported = importlib.import_module(module)
                klass = getattr(imported, name)
                for entry in vars(klass)['__proto_dest__']:
                    self.assertIsInstance(entry, ModuleDescriptor)
                    self.assertNotIsInstance(entry, type)

                source = pathlib.Path(
                    imported.__file__  # type: ignore[arg-type]
                ).read_text(encoding='utf-8')
                self.assertNotIn('from pcapkit.protocols', source)
                self.assertNotIn('import pcapkit.protocols', source)

    def test_only_these_registries_declare_a_destination(self) -> None:
        """No other generated enumeration declares a destination.

        The template renders nothing for a crawler that declares no
        ``PROTO_DEST``, so a declaration appearing anywhere else means either a
        crawler gained one by accident or a generated file was hand-edited --
        and ``code=`` would then infer a destination for an enumeration that
        keys no ``__proto__``.
        """
        import importlib
        import pkgutil

        import pcapkit.const as constpkg
        from pcapkit.corekit.enum import EnumRegistry

        declaring = set()
        for info in pkgutil.walk_packages(constpkg.__path__, prefix='pcapkit.const.'):
            module = importlib.import_module(info.name)
            for attr in vars(module).values():
                if (isinstance(attr, type) and issubclass(attr, EnumRegistry)
                        and '__proto_dest__' in vars(attr)):
                    declaring.add(f'{attr.__module__}.{attr.__name__}')

        self.assertEqual(declaring,
                         {f'{module}.{name}' for module, name, _ in self.EXPECTED})

    def test_an_enum_declaring_none_refuses_with_the_same_error(self) -> None:
        """Both shapes of "no declaration": absent, and present but empty.

        The real case is the absent one -- ``AppType``, covered by
        :meth:`RegisterProtocolCodeInferenceTests.\
test_unknown_enum_type_refuses_rather_than_guessing`. The empty one is the
        template's own default, which a crawler could reach by declaring an
        empty ``PROTO_DEST``, so it must refuse rather than register nothing and
        report success.
        """
        from aenum import IntEnum

        from pcapkit.corekit.enum import EnumRegistry
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.utilities.exceptions import RegistryError

        class Undeclared(EnumRegistry, IntEnum):
            """[Undeclared] An enumeration naming no destination."""

            SPAM = 1

        class DeclaredEmpty(EnumRegistry, IntEnum):
            """[DeclaredEmpty] An enumeration naming an empty set of destinations."""

            __proto_dest__ = ()

            SPAM = 1

        class FakeProtocol:
            pass

        for klass in (Undeclared, DeclaredEmpty):
            with self.subTest(registry=klass.__name__):
                with self.assertRaises(RegistryError) as caught:
                    register_protocol_code(FakeProtocol, klass.SPAM)
                self.assertIn('no destination registry is known', str(caught.exception))
                self.assertIn(klass.__name__, str(caught.exception))

    def test_an_unresolvable_declaration_fails_loudly(self) -> None:
        """A bad path raises rather than registering nothing and reporting success.

        The real declarations are hand-written, so this is defensive -- but
        the failure it guards against is the quiet kind: a typo'd class name that
        merely skipped its registration would leave the protocol unreachable with
        nothing said, which is #548's shape exactly.
        """
        from aenum import IntEnum

        from pcapkit.corekit.enum import EnumRegistry
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.registry.protocols import register_protocol_code
        from pcapkit.utilities.exceptions import ProtocolError

        class Mistyped(EnumRegistry, IntEnum):
            """[Mistyped] An enumeration naming a class that does not exist."""

            __proto_dest__ = (ModuleDescriptor('pcapkit.protocols.link.link', 'Linkk'),)

            SPAM = 1

        class Unimportable(EnumRegistry, IntEnum):
            """[Unimportable] An enumeration naming a module that does not exist."""

            __proto_dest__ = (ModuleDescriptor('pcapkit.protocols.link.no_such_module', 'Link'),)

            SPAM = 1

        class FakeProtocol:
            pass

        with self.assertRaises(ProtocolError):
            register_protocol_code(FakeProtocol, Mistyped.SPAM)
        with self.assertRaises(ModuleNotFoundError):
            register_protocol_code(FakeProtocol, Unimportable.SPAM)


if __name__ == '__main__':
    unittest.main()
