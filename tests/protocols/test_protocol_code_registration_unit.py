# -*- coding: utf-8 -*-
"""``code=`` opt-in next-layer dispatch registration.

GitHub issue #514 part (b): :class:`~pcapkit.protocols.protocol.Protocol`/
:class:`~pcapkit.protocols.protocol.ProtocolBase` gain a ``code`` class
keyword that registers a subclass into the next-layer dispatch registry (or
registries) it names -- e.g. :attr:`Link.__proto__
<pcapkit.protocols.link.link.Link.__proto__>`. Registration is opt-in,
exactly like the ``name=``/``protocol=``/``fmt=`` keywords part (a) (#547)
gave :class:`~pcapkit.foundation.engines.engine.Engine`,
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`,
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` and
:class:`~pcapkit.dumpkit.common.Dumper`: omitting ``code`` leaves the
subclass unregistered, which is exactly what every built-in protocol class
does today, since the built-in dispatch tables are populated by literal
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
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolCodeOptInTests(unittest.TestCase):
    """The opt-in gate itself: ``register_protocol_code`` runs iff ``code`` is given."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

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

        Before this hook existed, extra keywords fell into ``**kwargs`` and
        were dropped by the bare ``super().__init_subclass__()`` -- no
        exception, no warning. ``codes=`` (plural) is the natural typo for
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
    """Unit tests for ``register_protocol_code``/its enum-type inference table.

    Every destination class's ``register`` classmethod is mocked, so none of
    these touch a real, process-wide ``__proto__`` table.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

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

        Deliberately *not* ``L2TPv2``, which this docstring named until #548 was
        settled: v2 answers on port 1701 only, and registering it at
        ``TransType.L2TP`` points the :rfc:`2661` parser at a v3-over-IP header.
        The mechanism under test is unchanged either way -- the class here is a
        stand-in and nothing is really registered -- but the example should not
        recommend a binding the library refuses.
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
        """An enum type absent from the inference table raises, not a silent no-op.

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
        purge_modules(['pcapkit'])

    def test_end_to_end_class_statement_registers_the_real_table(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet

        with mock.patch.dict(Internet.__proto__, {}, clear=False):
            class MyGre(Internet, code=TransType.GRE):
                __layer__ = 'Internet'

            self.assertIs(Internet.__proto__[TransType.GRE], MyGre)
        self.assertNotIn(TransType.GRE, Internet.__proto__)

    def test_subclass_without_code_does_not_inherit_parent_registration(self) -> None:
        """Opting in is per-subclass, not inherited from a registered parent.

        Mirrors part (a)'s ``Parent``/``Derived``/``DerivedOptIn`` measurement
        on the issue thread: a subclass of a registered class that itself
        passes no ``code=`` must not re-register under its own name -- there
        is no name-derived fallback left to do that with, but the property is
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


if __name__ == '__main__':
    unittest.main()
