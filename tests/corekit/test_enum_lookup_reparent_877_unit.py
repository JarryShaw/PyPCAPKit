# -*- coding: utf-8 -*-
"""Phase 2 of GitHub issue #877, the unblocked half: re-parenting 11 helper
enumerations across 8 files onto :class:`~pcapkit.corekit.enum.EnumLookup`.

The owner's ruling, verbatim: *"I still prefer to reparent all enums until a
in house base class so that they can share common contracts."* Phase 1
(#906) split :class:`~pcapkit.corekit.enum.EnumLookup` out of
:class:`~pcapkit.corekit.enum.EnumRegistry` for exactly this; this module
pins that the split half of the tree that is not blocked by #913 or #904
actually took the base -- :class:`TransportProtocol
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
<pcapkit.protocols.schema.application.httpv2.FrameType.Flags>` plus its six
concrete per-frame subclasses.

Two of those eleven, :class:`TransportProtocol` and :class:`Criticality`,
already defined their own ``get`` -- both as a :class:`staticmethod`, while
:meth:`~pcapkit.corekit.enum.EnumLookup.get` is a :class:`classmethod`, the
exact trap GitHub issue #908 hit and #915 fixed for
:meth:`~pcapkit.const.http.method.Method.get`. Both became classmethods that
delegate, each keeping only the behaviour the base does not reproduce on its
own -- :class:`TransportProtocolGetTests` and :class:`CriticalityGetTests` pin
that each of those kept behaviours is unchanged, not merely that the
delegation compiles.

GitHub issue #923 then reduced that pair to one. Both overrides converted the
base's name-miss :exc:`KeyError` into a :exc:`ValueError`, and #923's ruling
retired the conversion -- so ``Criticality.get``, whose *only* remaining job
that was, is gone entirely and :class:`CriticalityGetTests` now exercises the
inherited base; ``TransportProtocol.get`` survives, reduced to its
``key.lower()`` call, because case folding has no equivalent on the base.

The other nine are pure re-parenting -- no ``get`` or ``_missing_`` of their
own to reconcile -- so :class:`PureReparentGetTests` pins the one thing that
actually changes for them: ``get``/``get_all`` now exist and resolve, where
before this change the attribute did not exist at all.

On the tree before this change every test below that calls ``.get()`` on one
of these nine fails with ``AttributeError: type object '<Name>' has no
attribute 'get'`` -- the base did not carry those methods to them yet -- and
every base-tuple assertion in :class:`ReparentedBasesTests` and
:class:`HttpV2FlagsHierarchyTests` fails since ``EnumLookup`` is not yet in
any of these seventeen classes' ``__bases__`` or MRO.

"""
from __future__ import annotations

import inspect
import unittest

from pcapkit.corekit.enum import EnumLookup

__all__ = [
    'ReparentedBasesTests', 'HttpV2FlagsHierarchyTests', 'PureReparentGetTests',
    'TransportProtocolGetTests', 'CriticalityGetTests', 'NoMintingTests',
]


class ReparentedBasesTests(unittest.TestCase):
    """Every one of the 11 unblocked classes gained :class:`EnumLookup` as a
    base, mixed in *ahead of* its enum base so ``_member_type_`` still
    resolves to :class:`int` or :class:`str`."""

    def test_transport_protocol(self) -> None:
        from aenum import IntEnum

        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertEqual(TransportProtocol.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, TransportProtocol.__mro__)

    def test_finalised_state(self) -> None:
        import enum

        from pcapkit.corekit.infoclass import FinalisedState

        self.assertEqual(FinalisedState.__bases__, (EnumLookup, enum.IntEnum))
        self.assertIn(EnumLookup, FinalisedState.__mro__)

    def test_completion(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(Completion.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, Completion.__mro__)

    def test_ftp_type(self) -> None:
        from pcapkit.protocols.application.ftp import Type as FTPType
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(FTPType.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, FTPType.__mro__)

    def test_httpv1_type(self) -> None:
        from pcapkit.protocols.application.httpv1 import Type as HTTPv1Type
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(HTTPv1Type.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, HTTPv1Type.__mro__)

    def test_criticality(self) -> None:
        from aenum import IntEnum

        from pcapkit.protocols.application.ngap import Criticality

        self.assertEqual(Criticality.__bases__, (EnumLookup, IntEnum))
        self.assertIn(EnumLookup, Criticality.__mro__)

    def test_pdu_kind(self) -> None:
        from pcapkit.protocols.application.ngap import PDUKind
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(PDUKind.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, PDUKind.__mro__)

    def test_packet_direction(self) -> None:
        import enum

        from pcapkit.protocols.misc.pcapng import PacketDirection

        self.assertEqual(PacketDirection.__bases__, (EnumLookup, enum.IntEnum))
        self.assertIn(EnumLookup, PacketDirection.__mro__)

    def test_packet_reception(self) -> None:
        import enum

        from pcapkit.protocols.misc.pcapng import PacketReception

        self.assertEqual(PacketReception.__bases__, (EnumLookup, enum.IntEnum))
        self.assertIn(EnumLookup, PacketReception.__mro__)

    def test_wireguard_key_label(self) -> None:
        from pcapkit.protocols.misc.pcapng import WireGuardKeyLabel
        from pcapkit.utilities.compat import StrEnum

        self.assertEqual(WireGuardKeyLabel.__bases__, (EnumLookup, StrEnum))
        self.assertIn(EnumLookup, WireGuardKeyLabel.__mro__)


class HttpV2FlagsHierarchyTests(unittest.TestCase):
    """``FrameType.Flags`` plus its six concrete per-frame subclasses -- one
    hierarchy, re-parented at the root only.

    Each concrete subclass declares ``class Flags(FrameType.Flags):`` with no
    base list of its own (see :mod:`pcapkit.protocols.schema.application.
    httpv2`), so re-parenting the root should carry all six rather than
    needing each done individually. Verified here at runtime rather than
    assumed from Python's MRO rules, per the task's own instruction to check
    rather than assume.
    """

    def test_frame_type_flags_itself(self) -> None:
        import enum

        from pcapkit.protocols.schema.application.httpv2 import FrameType

        self.assertEqual(FrameType.Flags.__bases__, (EnumLookup, enum.IntFlag))
        self.assertIn(EnumLookup, FrameType.Flags.__mro__)

    def test_all_six_concrete_subclasses_carry_it_transitively(self) -> None:
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
                # ``FrameType.Flags``, which is where ``EnumLookup`` was added.
                self.assertEqual(cls.__bases__, (FrameType.Flags,))
                self.assertIn(EnumLookup, cls.__mro__)
                # And the contract actually works, not merely appears in the MRO.
                member = next(iter(cls))
                self.assertIs(cls.get(member.name), member)


class PureReparentGetTests(unittest.TestCase):
    """The nine classes with no ``get``/``_missing_`` of their own: before
    this change, ``.get()`` did not exist on any of them at all."""

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
        """The base's own contract -- raise, never mint -- reaches these nine
        for free, exactly as it does the 124 registries."""
        from pcapkit.corekit.infoclass import FinalisedState

        with self.assertRaises(KeyError):
            FinalisedState.get('NOT_A_REAL_STATE')
        # No member was minted answering the failed lookup.
        self.assertNotIn('NOT_A_REAL_STATE', FinalisedState.__members__)


class TransportProtocolGetTests(unittest.TestCase):
    """:class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol` kept its
    own ``get``, now delegating. Every behaviour the hand-rolled version had
    is pinned here, not merely that the delegated version runs."""

    def test_get_is_now_a_classmethod(self) -> None:
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIsInstance(inspect.getattr_static(TransportProtocol, 'get'), classmethod)

    def test_case_folding_is_preserved(self) -> None:
        """The base's own ``str`` branch is case-sensitive; this override
        still lower-cases before delegating, so an upper-cased spelling
        must still resolve -- unlike a class that relies on the base alone
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
        """Maintainer ruling on PR #836: refuse, never mint. Still refused, and
        still nothing minted -- but GitHub issue #923 retired the
        ``KeyError`` -> ``ValueError`` conversion this override used to do, so
        the refusal now reaches the caller as the base's own
        :exc:`~pcapkit.utilities.exceptions.EnumKeyError`. Updated from the
        pre-#923 tree, which asserted ``assertNotIsInstance(..., KeyError)``:
        that assertion described the minority shape -- #923's census found 119
        of the 127 concrete subclasses answering a name miss with a
        :exc:`KeyError` -- and #923's ruling is that a name miss follows stdlib
        ``E['nosuch']`` and stays :exc:`KeyError`-derived. The message is
        unchanged, so the two ``assertIn``\\ s below are the same ones that
        passed before."""
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

    def test_default_is_a_new_capability_not_exercised_before(self) -> None:
        """``default`` did not exist on this override before this change --
        added purely because dropping an optional parameter the base
        declares is a genuine ``mypy`` ``[override]`` violation. Forwarded
        verbatim, so it behaves exactly as
        :meth:`~pcapkit.corekit.enum.EnumLookup.get`'s own ``default``: a
        fallback to an *already-registered* value, never a new mint."""
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIs(TransportProtocol.get('bogus', default=TransportProtocol.udp),
                      TransportProtocol.udp)
        # Omitted, as every call site in this tree omits it: still raises, as
        # a KeyError since GitHub issue #923 rather than a ValueError.
        with self.assertRaises(KeyError):
            TransportProtocol.get('bogus')


class CriticalityGetTests(unittest.TestCase):
    """:class:`~pcapkit.protocols.application.ngap.Criticality` kept its own
    ``get`` for this issue, then lost it to GitHub issue #923: the only thing
    the override still did that the base does not was convert the base's
    name-miss :exc:`KeyError` into a :exc:`ValueError`, and #923's ruling
    retired that conversion, leaving a pure pass-through. Every behaviour
    below is therefore now the *inherited* base's, which is exactly what
    makes the deletion worth pinning -- case-**sensitive**, unlike
    ``TransportProtocol``, which keeps its override for the case folding the
    base has no equivalent of."""

    def test_get_is_inherited_rather_than_overridden(self) -> None:
        """GitHub issue #923 deleted the override. ``get`` is still a
        :class:`classmethod` reached through the class -- it is now
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
        """The removed ``isinstance(key, Criticality): return key`` branch is
        absorbed by the base's own ``cls(key)`` call -- a ``Criticality`` is
        also an :class:`int` (it is an :class:`~aenum.IntEnum`), so the
        non-``str`` path already hands back the identical canonical member."""
        from pcapkit.protocols.application.ngap import Criticality

        self.assertIs(Criticality.get(Criticality.reject), Criticality.reject)

    def test_case_sensitivity_is_unlike_transport_protocol(self) -> None:
        """Deliberately the opposite of ``TransportProtocol.get`` -- nothing
        here lower-cases, so an upper-cased spelling must be refused rather
        than folded. Now :exc:`KeyError`-shaped, per GitHub issue #923."""
        from pcapkit.protocols.application.ngap import Criticality

        with self.assertRaises(KeyError) as caught:
            Criticality.get('REJECT')
        self.assertIn('REJECT', str(caught.exception))

    def test_unresolved_name_raises_key_error_not_value_error(self) -> None:
        """The inverse of what this test asserted before GitHub issue #923.

        The deleted override converted the base's name-miss :exc:`KeyError`
        into a :exc:`ValueError` so that an unknown name and an unknown value
        reported identically. #923's ruling is that they must *not*: a stdlib
        ``E['nosuch']`` raises :exc:`KeyError` and ``E(999)`` raises
        :exc:`ValueError`, so the two ways of getting this wrong are
        deliberately distinguishable, and only the provenance of each moved
        into :mod:`pcapkit.utilities.exceptions`."""
        from pcapkit.utilities.exceptions import EnumKeyError

        from pcapkit.protocols.application.ngap import Criticality

        with self.assertRaises(EnumKeyError) as caught:
            Criticality.get('NoSuchMember')
        self.assertIsInstance(caught.exception, KeyError)
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertIn('NoSuchMember', str(caught.exception))

    def test_unresolved_value_still_raises_via_missing(self) -> None:
        """Still a :exc:`ValueError`, and now this class's own
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
        """The one thing that could have made GitHub issue #923's deletion of
        this override unsafe. The override forwarded ``default`` verbatim, so
        the inherited base has to answer identically: a member-valued default
        resolves, and one naming no registered value is not honoured."""
        from pcapkit.protocols.application.ngap import Criticality

        self.assertIs(Criticality.get('NoSuchMember', default=Criticality.ignore),
                      Criticality.ignore)
        with self.assertRaises(KeyError):
            Criticality.get('NoSuchMember', default=99)
        with self.assertRaises(KeyError):
            Criticality.get('NoSuchMember')


class NoMintingTests(unittest.TestCase):
    """None of the eleven re-parented classes mint on a lookup -- each is a
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
