# -*- coding: utf-8 -*-
"""An unregistered :class:`AppType` member survives :mod:`pickle` and :mod:`copy`.

GitHub issue :issue:`2417`. ``AppType.get`` answers a port it holds no
assignment for with a member built by
:meth:`AppType._unregistered_member
<pcapkit.const.reg.apptype.apptype.AppType._unregistered_member>`, deliberately
absent from every one of the registry's lookup tables so that a lookup does not
grow it (:issue:`860`). ``Enum.__reduce_ex__`` reduces a member to
``(cls, (value,))`` -- a *value*-keyed lookup, i.e. the one table such a member
is missing from -- so these pickled fine and then raised on read-back::

    ValueError: 'unknown [54321 - tcp]' is not a valid TCP

That became reachable from reassembly once
:meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>` began
dispatching on ``AppType`` members rather than bare port numbers: the
:class:`~pcapkit.foundation.reassembly.data.tcp.Datagram` it produces holds the
pair in an unresolved
:class:`~pcapkit.foundation.reassembly.data.data.Deferred`, so pickling an
unresolved datagram pickled the members. Measured before the fix, **59,413 of
the 65,536** possible TCP ports failed to round-trip -- not merely the truly
unregistered ``unknown`` ones but every IANA-span label too (``unassigned``,
``reserved``, ``x11``, ``swx`` and the rest), which is 90.7% of the port space.

:meth:`EnumRegistry._make_reducible
<pcapkit.corekit.enum.EnumRegistry._make_reducible>` fixes it the way
:meth:`EnumField._unregistered_member
<pcapkit.corekit.fields.numbers.EnumField._unregistered_member>` already fixed
the same class of problem for the *parse* path (:issue:`575`, :issue:`1774`): a
per-instance ``__reduce_ex__`` that rebuilds through
``_unregistered_member`` instead of through a value lookup. Rebuilding
therefore cannot register anything either, which these also pin -- a fix that
made the member picklable by minting it would have been a worse bug than the
one it cured.

"""
from __future__ import annotations

import copy
import pickle
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises pickling and copying, whose protocols differ by
#: interpreter.
__tier__ = 'ALL'

#: One port per label ``AppType.get`` answers a miss with, measured over the
#: whole port space on every transport. Every one of these failed to round-trip
#: before the fix.
MISS_PORTS = (
    (0, 'a reserved span, and the bottom of the range'),
    (51, 'no row and no span: get\'s own "unknown" fallback'),
    (225, 'a reserved span naming no transport'),
    (272, 'an unassigned span naming no transport'),
    (3322, 'the "active-net" span'),
    (3367, 'the "satvid-datalnk" span'),
    (4200, 'the "vrml-multi-use" span'),
    (6000, 'the "x11" span'),
    (6665, 'the "ircu" span, which is TCP-only'),
    (7300, 'the "swx" span'),
    (27000, 'the "flex-lm" span'),
    (54321, 'an ephemeral port, the common case in a real capture'),
    (65535, 'the top of the range'),
)

#: Ports IANA assigns, which resolve to a real registered member instead. These
#: never went through ``_unregistered_member`` and so were never broken; they
#: are here because the fix must not have changed them.
HIT_PORTS = (80, 443, 22)


def _protos() -> 'tuple[Any, ...]':
    from pcapkit.const.reg.apptype import TransportProtocol

    return (TransportProtocol.tcp, TransportProtocol.udp,
            TransportProtocol.sctp, TransportProtocol.dccp)


def _tables(owner: 'Any') -> 'tuple[Any, ...]':
    """Every table a member could leak into, as a comparable snapshot."""
    return (dict(owner.__members__),
            dict(owner._value2member_map_),  # pylint: disable=protected-access
            [(port, list(owner.__registry__.getlist(port))) for port in owner.__registry__])


class UnregisteredAppTypePickleTests(unittest.TestCase):
    """The round trip, and that it registers nothing."""

    def test_every_port_in_the_space_round_trips(self) -> None:
        """All 65,536 ports, the measurement the fix is stated against.

        A sample would have passed before the fix too -- 6,123 of these ports
        already round-tripped, being IANA assignments -- so the sweep is the
        whole range rather than a selection from it.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        owner = AppType.__registries__[TransportProtocol.tcp]
        failures = []
        for port in range(65536):
            member = AppType.get(port, proto=TransportProtocol.tcp)
            try:
                restored = pickle.loads(pickle.dumps(member))
            except Exception as exc:  # pylint: disable=broad-except
                failures.append((port, member.name, type(exc).__name__))
                continue
            if not (isinstance(restored, owner)
                    and (restored.port, restored.svc, restored.proto, restored.name)
                    == (member.port, member.svc, member.proto, member.name)):
                failures.append((port, member.name, 'mismatch'))
        self.assertEqual(failures, [], f'{len(failures)} of 65536 ports did not round-trip')

    def test_every_miss_label_round_trips_on_every_protocol(self) -> None:
        """Each shape of miss, on every transport and every pickle protocol."""
        from pcapkit.const.reg.apptype import AppType

        for proto in _protos():
            owner = AppType.__registries__[proto]
            for port, why in MISS_PORTS:
                member = AppType.get(port, proto=proto)
                for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                    with self.subTest(proto=proto.name, port=port, why=why,
                                      protocol=protocol):
                        restored = pickle.loads(pickle.dumps(member, protocol))

                        self.assertIsInstance(restored, owner)
                        self.assertEqual(restored, member)
                        self.assertEqual(
                            (restored.port, restored.svc, restored.proto, restored.name),
                            (member.port, member.svc, member.proto, member.name))

    def test_round_tripping_grows_no_table(self) -> None:
        """The registry must not grow -- not on the way out, nor on read-back.

        A reducer that rebuilt through ``cls(value)`` or ``cls.register`` would
        make the member picklable by *minting* it, trading a read-back failure
        for a process-wide registry that grows once per ephemeral port seen.

        """
        from pcapkit.const.reg.apptype import AppType

        for proto in _protos():
            owner = AppType.__registries__[proto]
            with self.subTest(proto=proto.name):
                before = _tables(owner)

                for port, _ in MISS_PORTS:
                    member = AppType.get(port, proto=proto)
                    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                        pickle.loads(pickle.dumps(member, protocol))
                    copy.deepcopy(member)

                self.assertEqual(_tables(owner), before)

    def test_a_restored_member_stays_absent_from_the_lookup_tables(self) -> None:
        """The rebuilt member is unregistered exactly as the original was."""
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        owner = AppType.__registries__[TransportProtocol.tcp]
        member = AppType.get(54321, proto=TransportProtocol.tcp)
        restored = pickle.loads(pickle.dumps(member))

        for label, obj in (('original', member), ('restored', restored)):
            with self.subTest(member=label):
                self.assertNotIn(
                    obj._value_, owner._value2member_map_)  # pylint: disable=protected-access
                self.assertNotIn(obj.name, owner.__members__)

    def test_a_restored_member_is_itself_reducible(self) -> None:
        """Rebuilding re-enters ``_unregistered_member``, so the reducer is
        installed again and a restored member pickles as the original did.

        Without that, a member would survive one round trip and fail the
        second, which is worse than failing the first: a datagram read back
        from a dump could not be written out again.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        member = AppType.get(54321, proto=TransportProtocol.tcp)
        once = pickle.loads(pickle.dumps(member))
        twice = pickle.loads(pickle.dumps(once))

        self.assertEqual(twice, member)
        self.assertEqual((twice.port, twice.svc, twice.proto, twice.name),
                         (member.port, member.svc, member.proto, member.name))

    def test_copy_and_deepcopy_preserve_the_member(self) -> None:
        """:mod:`copy` reduces through the same hook, so it is pinned too.

        On 3.11+ ``Enum.__copy__`` short-circuits ahead of any reduction and
        both return the member itself; where it does not exist they return an
        equal rebuilt one. Either is the right answer for an immutable value,
        so this asserts equality rather than identity.

        """
        from pcapkit.const.reg.apptype import AppType

        for proto in _protos():
            member = AppType.get(54321, proto=proto)
            for fn in (copy.copy, copy.deepcopy):
                with self.subTest(proto=proto.name, fn=fn.__name__):
                    clone = fn(member)

                    self.assertEqual(clone, member)
                    self.assertEqual((clone.port, clone.svc, clone.proto, clone.name),
                                     (member.port, member.svc, member.proto, member.name))

    def test_a_registered_member_still_reduces_to_the_registry_singleton(self) -> None:
        """The fix touches the unregistered path only.

        A real assignment never goes through ``_unregistered_member``, so it
        keeps ``Enum``'s own reduction and unpickles to the *identical* shared
        member. Pinning identity here is what would catch the reducer being
        installed on every member rather than on the unregistered ones.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        for port in HIT_PORTS:
            member = AppType.get(port, proto=TransportProtocol.tcp)
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                with self.subTest(port=port, protocol=protocol):
                    self.assertIs(pickle.loads(pickle.dumps(member, protocol)), member)


if __name__ == '__main__':
    unittest.main()
