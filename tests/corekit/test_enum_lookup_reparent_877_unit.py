# -*- coding: utf-8 -*-
"""Phase 2 of GitHub issue #877, the unblocked half: re-parenting the
helper enumerations onto :class:`~pcapkit.corekit.enum.EnumLookup`.

The owner's last word on #877 was to re-parent every non-registry enumeration
onto an in-house base class so that they all share the same contracts; it
overrode the recommendation the thread had reached before it. Phase 1 (#906)
split :class:`~pcapkit.corekit.enum.EnumLookup` out of
:class:`~pcapkit.corekit.enum.EnumRegistry` for exactly this; this module
pins that the half of the tree that is not blocked by #913 or #904 derives
from the base -- :class:`TransportProtocol
<pcapkit.const.reg.apptype.apptype.TransportProtocol>`,
:class:`FinalisedState <pcapkit.corekit.infoclass.FinalisedState>`,
:class:`Completion <pcapkit.foundation.reassembly.data.data.Completion>`,
:class:`ftp.Type <pcapkit.protocols.application.ftp.Type>`,
:class:`httpv1.Type <pcapkit.protocols.application.httpv1.Type>`,
:class:`Criticality <pcapkit.protocols.application.ngap.Criticality>`,
:class:`PDUKind <pcapkit.protocols.application.ngap.PDUKind>`,
:class:`PacketDirection <pcapkit.protocols.misc.pcapng.PacketDirection>`,
:class:`PacketReception <pcapkit.protocols.misc.pcapng.PacketReception>`,
:class:`WireGuardKeyLabel <pcapkit.protocols.misc.pcapng.WireGuardKeyLabel>`,
and :class:`FrameType.Flags
<pcapkit.protocols.schema.application.httpv2.FrameType.Flags>` plus its
concrete per-frame subclasses.

:class:`TransportProtocol` defines its own ``get``, as a :class:`classmethod`
that delegates: :meth:`~pcapkit.corekit.enum.EnumLookup.get` is a
:class:`classmethod`, so a :class:`staticmethod` override is the exact trap
GitHub issue #908 hit and #915 fixed for
:meth:`~pcapkit.const.http.method.Method.get`. It keeps only its
``key.lower()`` call, because case folding has no equivalent on the base;
:class:`TransportProtocolGetTests` pins that behaviour, not merely that the
delegation compiles. :class:`Criticality` has no ``get`` of its own: one would
only convert the base's name-miss :exc:`KeyError` into a :exc:`ValueError`, a
conversion GitHub issue #923's ruling retired, so :class:`CriticalityGetTests`
exercises the inherited base.

The rest are pure re-parenting -- no ``get`` or ``_missing_`` of their own to
reconcile -- so :class:`PureReparentGetTests` pins that ``get``/``get_all``
exist on them and resolve.

Without the re-parenting, every test below that calls ``.get()`` on one of
these fails with ``AttributeError: type object '<Name>' has no attribute
'get'`` -- the base is what carries those methods to them -- and every
base-tuple assertion in :class:`ReparentedBasesTests` and
:class:`HttpV2FlagsHierarchyTests` fails since ``EnumLookup`` is in none of
these classes' ``__bases__`` or MRO.

"""
from __future__ import annotations

import inspect
import unittest

# EnumLookup is imported in each test, not here (#2115): an earlier module in
# the same process may re-import pcapkit, and the base has to come from the same
# import as the class it is checked against.

#: Test tier (#1958): exercises metaclass, ABC or enum machinery, which differs by
#: interpreter.
__tier__ = 'ALL'

__all__ = [
    'ReparentedBasesTests', 'HttpV2FlagsHierarchyTests', 'PureReparentGetTests',
    'TransportProtocolGetTests', 'CriticalityGetTests', 'NoMintingTests',
]


class ReparentedBasesTests(unittest.TestCase):
    """Every unblocked class has :class:`EnumLookup` as a base, mixed in
    *ahead of* its enum base so ``_member_type_`` resolves to :class:`int` or
    :class:`str`."""

    def test_transport_protocol(self) -> None:
        from aenum import IntEnum

        from pcapkit.const.reg.apptype.apptype import TransportProtocol
        from pcapkit.corekit.enum import EnumLookup

        self.assertEqual(TransportProtocol.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, TransportProtocol.__mro__)

    def test_finalised_state(self) -> None:
        import enum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.corekit.infoclass import FinalisedState

        self.assertEqual(FinalisedState.__bases__, (EnumLookup, enum.IntEnum))
        self.assertIn(EnumLookup, FinalisedState.__mro__)

    def test_completion(self) -> None:
        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(Completion.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, Completion.__mro__)

    def test_ftp_type(self) -> None:
        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.application.ftp import Type as FTPType
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(FTPType.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, FTPType.__mro__)

    def test_httpv1_type(self) -> None:
        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.application.httpv1 import Type as HTTPv1Type
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(HTTPv1Type.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, HTTPv1Type.__mro__)

    def test_criticality(self) -> None:
        from aenum import IntEnum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.application.ngap import Criticality

        self.assertEqual(Criticality.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, Criticality.__mro__)

    def test_pdu_kind(self) -> None:
        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.application.ngap import PDUKind
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(PDUKind.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, PDUKind.__mro__)

    def test_packet_direction(self) -> None:
        import enum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.misc.pcapng import PacketDirection

        self.assertEqual(PacketDirection.__bases__, (EnumLookup, enum.IntEnum))
        self.assertIn(EnumLookup, PacketDirection.__mro__)

    def test_packet_reception(self) -> None:
        import enum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.misc.pcapng import PacketReception

        self.assertEqual(PacketReception.__bases__, (EnumLookup, enum.IntEnum))
        self.assertIn(EnumLookup, PacketReception.__mro__)

    def test_wireguard_key_label(self) -> None:
        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.misc.pcapng import WireGuardKeyLabel
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(WireGuardKeyLabel.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, WireGuardKeyLabel.__mro__)


class HttpV2FlagsHierarchyTests(unittest.TestCase):
    """``FrameType.Flags`` plus its concrete per-frame subclasses -- one
    hierarchy, re-parented at the root only.

    Each concrete subclass declares ``class Flags(FrameType.Flags):`` with no
    base list of its own (see :mod:`pcapkit.protocols.schema.application.
    httpv2`), so the root's base carries to every subclass without each being
    re-parented individually. Verified here at runtime rather than assumed
    from Python's MRO rules.
    """

    def test_frame_type_flags_itself(self) -> None:
        import enum

        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.schema.application.httpv2 import FrameType

        self.assertEqual(FrameType.Flags.__bases__, (EnumLookup, enum.IntFlag))
        self.assertIn(EnumLookup, FrameType.Flags.__mro__)

    def test_every_concrete_subclass_carries_it_transitively(self) -> None:
        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.schema.application.httpv2 import (ContinuationFrame, DataFrame,
                                                                   FrameType, HeadersFrame,
                                                                   PingFrame, PushPromiseFrame,
                                                                   SettingsFrame)

        subclasses = {
            'DataFrame.Flags': DataFrame.Flags,
            'HeadersFrame.Flags': HeadersFrame.Flags,
            'SettingsFrame.Flags': SettingsFrame.Flags,
            'PushPromiseFrame.Flags': PushPromiseFrame.Flags,
            'PingFrame.Flags': PingFrame.Flags,
            'ContinuationFrame.Flags': ContinuationFrame.Flags,
        }
        for name, cls in subclasses.items():
            with self.subTest(cls=name):
                # No base list of its own -- inherits solely from
                # ``FrameType.Flags``, which is where ``EnumLookup`` sits.
                self.assertEqual(cls.__bases__, (FrameType.Flags,))
                self.assertIn(EnumLookup, cls.__mro__)
                # And the contract actually works, not merely appears in the MRO.
                member = next(iter(cls))
                self.assertIs(cls.get(member.name), member)


class PureReparentGetTests(unittest.TestCase):
    """The classes with no ``get``/``_missing_`` of their own: ``.get()``
    reaches them only through the base."""

    def test_finalised_state_get(self) -> None:
        from pcapkit.corekit.infoclass import FinalisedState

        self.assertIs(FinalisedState.get('FINAL'), FinalisedState.FINAL)
        self.assertIs(FinalisedState.get(FinalisedState.NONE.value), FinalisedState.NONE)
        self.assertEqual(len(FinalisedState.get_all('BASE')), 1)

    def test_completion_get(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        self.assertIs(Completion.get('complete'), Completion.COMPLETE)
        self.assertIs(Completion.get('timeout'), Completion.TIMEOUT)

    def test_ftp_type_get(self) -> None:
        from pcapkit.protocols.application.ftp import Type as FTPType

        self.assertIs(FTPType.get('request'), FTPType.REQUEST)
        self.assertIs(FTPType.get('response'), FTPType.RESPONSE)

    def test_httpv1_type_get(self) -> None:
        from pcapkit.protocols.application.httpv1 import Type as HTTPv1Type

        self.assertIs(HTTPv1Type.get('request'), HTTPv1Type.REQUEST)
        self.assertIs(HTTPv1Type.get('response'), HTTPv1Type.RESPONSE)

    def test_pdu_kind_get(self) -> None:
        from pcapkit.protocols.application.ngap import PDUKind

        self.assertIs(PDUKind.get('initiatingMessage'), PDUKind.INITIATING_MESSAGE)

    def test_packet_direction_get(self) -> None:
        from pcapkit.protocols.misc.pcapng import PacketDirection

        self.assertIs(PacketDirection.get('INBOUND'), PacketDirection.INBOUND)
        self.assertIs(PacketDirection.get(0b10), PacketDirection.OUTBOUND)

    def test_packet_reception_get(self) -> None:
        from pcapkit.protocols.misc.pcapng import PacketReception

        self.assertIs(PacketReception.get('PROMISCUOUS'), PacketReception.PROMISCUOUS)

    def test_wireguard_key_label_get(self) -> None:
        from pcapkit.protocols.misc.pcapng import WireGuardKeyLabel

        self.assertIs(WireGuardKeyLabel.get('PRESHARED_KEY'), WireGuardKeyLabel.PRESHARED_KEY)

    def test_a_pure_reparent_still_refuses_an_unknown_name(self) -> None:
        """The base's own contract -- raise, never mint -- reaches these for
        free, exactly as it does the registries."""
        from pcapkit.corekit.infoclass import FinalisedState

        with self.assertRaises(KeyError):
            FinalisedState.get('NOT_A_REAL_STATE')
        # No member was minted answering the failed lookup.
        self.assertNotIn('NOT_A_REAL_STATE', FinalisedState.__members__)


class TransportProtocolGetTests(unittest.TestCase):
    """:class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol` keeps its
    own ``get``, delegating. Every behaviour the override carries is pinned
    here, not merely that the delegated call runs."""

    def test_get_is_a_classmethod(self) -> None:
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIsInstance(inspect.getattr_static(TransportProtocol, 'get'), classmethod)

    def test_case_folding_is_preserved(self) -> None:
        """The base's own ``str`` branch is case-sensitive; this override
        lower-cases before delegating, so an upper-cased spelling
        must resolve -- unlike a class that relies on the base alone
        (see :class:`~tests.corekit.test_enum_lookup_reparent_877_unit.
        PureReparentGetTests`, all of whose members are matched exactly)."""
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIs(TransportProtocol.get('TCP'), TransportProtocol.tcp)
        self.assertIs(TransportProtocol.get('tcp'), TransportProtocol.tcp)
        self.assertIs(TransportProtocol.get('Udp'), TransportProtocol.udp)

    def test_int_path_unchanged(self) -> None:
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIs(TransportProtocol.get(1), TransportProtocol.tcp)

    def test_unrecognised_name_still_raises_naming_the_key(self) -> None:
        """Maintainer ruling on PR #836: refuse, never mint. Nothing is minted,
        and the refusal reaches the caller as the base's own
        :exc:`~pcapkit.utilities.exceptions.EnumKeyError`: GitHub issue #923
        retired the ``KeyError`` -> ``ValueError`` conversion, ruling that a name
        miss follows stdlib ``E['nosuch']`` and stays :exc:`KeyError`-derived.
        ``assertNotIsInstance(..., KeyError)`` would describe the minority shape
        -- #923's census found most concrete subclasses answering a name miss
        with a :exc:`KeyError`."""
        from pcapkit.utilities.exceptions import EnumKeyError

        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        before = len(TransportProtocol.__members__)
        with self.assertRaises(EnumKeyError) as caught:
            TransportProtocol.get('quic')
        self.assertIsInstance(caught.exception, KeyError)
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertIn('quic', str(caught.exception))
        self.assertIn('is not a valid', str(caught.exception))
        self.assertEqual(len(TransportProtocol.__members__), before)

    def test_default_falls_back_to_a_registered_member(self) -> None:
        """``default`` exists on this override purely because dropping an
        optional parameter the base declares is a genuine ``mypy``
        ``[override]`` violation. Forwarded
        verbatim, so it behaves exactly as
        :meth:`~pcapkit.corekit.enum.EnumLookup.get`'s own ``default``: a
        fallback to an *already-registered* value, never a new mint."""
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIs(TransportProtocol.get('bogus', default=TransportProtocol.udp),
                      TransportProtocol.udp)
        # Omitted, as every call site in this tree omits it: raises a KeyError
        # (GitHub issue #923), not a ValueError.
        with self.assertRaises(KeyError):
            TransportProtocol.get('bogus')


class CriticalityGetTests(unittest.TestCase):
    """:class:`~pcapkit.protocols.application.ngap.Criticality` has no ``get``
    of its own (GitHub issue #923): an override would only convert the base's
    name-miss :exc:`KeyError` into a :exc:`ValueError`, a conversion #923's
    ruling retired. Every behaviour below is therefore the *inherited*
    base's -- case-**sensitive**, unlike
    ``TransportProtocol``, which keeps its override for the case folding the
    base has no equivalent of."""

    def test_get_is_inherited_rather_than_overridden(self) -> None:
        """There is no override (GitHub issue #923). ``get`` is a
        :class:`classmethod` reached through the class --
        :meth:`~pcapkit.corekit.enum.EnumLookup.get` itself, which is what
        the rest of this class exercises."""
        from pcapkit.corekit.enum import EnumLookup
        from pcapkit.protocols.application.ngap import Criticality

        self.assertNotIn('get', Criticality.__dict__)
        self.assertIsInstance(inspect.getattr_static(Criticality, 'get'), classmethod)
        self.assertIs(inspect.getattr_static(Criticality, 'get'),
                      inspect.getattr_static(EnumLookup, 'get'))

    def test_name_lookup(self) -> None:
        from pcapkit.protocols.application.ngap import Criticality

        self.assertIs(Criticality.get('reject'), Criticality.reject)
        self.assertIs(Criticality.get('ignore'), Criticality.ignore)
        self.assertIs(Criticality.get('notify'), Criticality.notify)

    def test_value_lookup(self) -> None:
        from pcapkit.protocols.application.ngap import Criticality

        self.assertIs(Criticality.get(2), Criticality.notify)

    def test_a_criticality_instance_resolves_to_itself(self) -> None:
        """An ``isinstance(key, Criticality): return key`` branch is not
        needed: the base's own ``cls(key)`` call covers it -- a ``Criticality``
        is also an :class:`int` (it is an :class:`~aenum.IntEnum`), so the
        non-``str`` path hands back the identical canonical member."""
        from pcapkit.protocols.application.ngap import Criticality

        self.assertIs(Criticality.get(Criticality.reject), Criticality.reject)

    def test_case_sensitivity_is_unlike_transport_protocol(self) -> None:
        """Deliberately the opposite of ``TransportProtocol.get`` -- nothing
        here lower-cases, so an upper-cased spelling must be refused rather
        than folded. :exc:`KeyError`-shaped, per GitHub issue #923."""
        from pcapkit.protocols.application.ngap import Criticality

        with self.assertRaises(KeyError) as caught:
            Criticality.get('REJECT')
        self.assertIn('REJECT', str(caught.exception))

    def test_unresolved_name_raises_key_error_not_value_error(self) -> None:
        """A name miss is a :exc:`KeyError`, not a :exc:`ValueError` (GitHub issue #923).

        Converting the base's name-miss :exc:`KeyError` into a
        :exc:`ValueError` would make an unknown name and an unknown value
        report identically. #923's ruling is that they must *not*: a stdlib
        ``E['nosuch']`` raises :exc:`KeyError` and ``E(999)`` raises
        :exc:`ValueError`, so the two ways of getting this wrong are
        deliberately distinguishable, and each is raised from
        :mod:`pcapkit.utilities.exceptions`."""
        from pcapkit.utilities.exceptions import EnumKeyError

        from pcapkit.protocols.application.ngap import Criticality

        with self.assertRaises(EnumKeyError) as caught:
            Criticality.get('NoSuchMember')
        self.assertIsInstance(caught.exception, KeyError)
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertIn('NoSuchMember', str(caught.exception))

    def test_unresolved_value_still_raises_via_missing(self) -> None:
        """A :exc:`ValueError`, specifically
        :exc:`~pcapkit.utilities.exceptions.EnumValueError`: ``_missing_``
        raises a bare :exc:`ValueError` and the base converts it, per GitHub
        issue #923's "no builtin exceptions" half."""
        from pcapkit.utilities.exceptions import EnumValueError

        from pcapkit.protocols.application.ngap import Criticality

        with self.assertRaises(EnumValueError) as caught:
            Criticality.get(3)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertIn('3', str(caught.exception))

    def test_default_is_honoured_by_the_inherited_base(self) -> None:
        """The one thing that could make relying on the inherited base, with
        no override (GitHub issue #923), unsafe. An override would forward
        ``default`` verbatim, so the base has to answer identically: a
        member-valued default
        resolves, and one naming no registered value is not honoured."""
        from pcapkit.protocols.application.ngap import Criticality

        self.assertIs(Criticality.get('NoSuchMember', default=Criticality.ignore),
                      Criticality.ignore)
        with self.assertRaises(KeyError):
            Criticality.get('NoSuchMember', default=99)
        with self.assertRaises(KeyError):
            Criticality.get('NoSuchMember')


class NoMintingTests(unittest.TestCase):
    """None of the re-parented classes mint on a lookup -- each is a
    closed set on the bare lookup tier, not the mutating
    :class:`~pcapkit.corekit.enum.EnumRegistry` one. Measured per class in a
    throwaway subprocess, so a lookup made by an *earlier* assertion in this
    same test run can never be mistaken for growth caused by the class under
    test -- the house rule for probing a minting-capable enum, applied here
    even though these are the closed side of that line.
    """

    @staticmethod
    def _sizes_before_and_after(import_stmt: str, cls_expr: str, lookup_expr: str) -> 'tuple[int, int, int, int]':
        import subprocess
        import sys

        code = (
            f'{import_stmt}\n'
            f'cls = {cls_expr}\n'
            f'before_names = len(cls._member_map_)\n'
            f'before_values = len(cls._value2member_map_)\n'
            f'{lookup_expr}\n'
            f'after_names = len(cls._member_map_)\n'
            f'after_values = len(cls._value2member_map_)\n'
            f'print(before_names, before_values, after_names, after_values)\n'
        )
        result = subprocess.run(
            [sys.executable, '-c', code],
            capture_output=True, text=True, check=True,
        )
        before_names, before_values, after_names, after_values = map(int, result.stdout.split())
        return before_names, before_values, after_names, after_values

    def test_transport_protocol_does_not_grow(self) -> None:
        before_names, before_values, after_names, after_values = self._sizes_before_and_after(
            'from pcapkit.const.reg.apptype.apptype import TransportProtocol',
            'TransportProtocol',
            "cls.get('TCP')",
        )
        self.assertEqual(before_names, after_names)
        self.assertEqual(before_values, after_values)

    def test_criticality_does_not_grow(self) -> None:
        before_names, before_values, after_names, after_values = self._sizes_before_and_after(
            'from pcapkit.protocols.application.ngap import Criticality',
            'Criticality',
            "cls.get('reject')",
        )
        self.assertEqual(before_names, after_names)
        self.assertEqual(before_values, after_values)

    def test_finalised_state_does_not_grow(self) -> None:
        before_names, before_values, after_names, after_values = self._sizes_before_and_after(
            'from pcapkit.corekit.infoclass import FinalisedState',
            'FinalisedState',
            "cls.get('FINAL')",
        )
        self.assertEqual(before_names, after_names)
        self.assertEqual(before_values, after_values)


if __name__ == '__main__':
    unittest.main()
