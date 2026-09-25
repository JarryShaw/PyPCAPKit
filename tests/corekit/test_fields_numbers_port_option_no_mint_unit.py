# -*- coding: utf-8 -*-
"""A registry-backed ``EnumField`` subclass minted a member per unassigned value.

GitHub issue #575. :meth:`PortEnumField.post_process
<pcapkit.protocols.schema.transport.tcp.PortEnumField.post_process>` (TCP, UDP,
SCTP) and :meth:`OptionEnumField.post_process
<pcapkit.protocols.schema.misc.pcapng.OptionEnumField.post_process>` (PCAP-NG)
each resolved a wire value by calling their registry's ``.get()`` directly::

    return self._namespace.get(value, proto=...)

which mints a fresh member -- via :func:`aenum.extend_enum` -- for any value
neither an existing row nor one of the registry's own documented spans
accounts for. On ``examples/captures/http.pcap`` that is 111 calls, all from
ephemeral TCP ports with no IANA assignment, and measured at 13-17% of
extraction self time.

Every one of those four subclasses now falls through to
:meth:`EnumField._unregistered_member <pcapkit.corekit.fields.numbers.EnumField._unregistered_member>`
instead of minting: an actual instance of the registry the field names --
``isinstance`` holds, and it renders and dispatches exactly like a declared
member -- built by calling the registry's own storage base's ``__new__``
directly and skipping the registry's own ``__new__`` (and the
``cls.__registry__.add(...)`` / ``cls.__members_ns__[...]`` line inside it)
entirely, so nothing is ever added to any of its lookup tables. That is the
owner's ruling on this issue's return type: *"we should even apply to all
other Enum's legit but unbounded values -- so that we dont create registered
enums out of unrecognised/unregistered values, unless user/caller explicitly
created them"* -- tracked more broadly as #775, and applied here only to
these four call sites.

This mirrors :mod:`tests.corekit.test_fields_numbers_unassigned_enum`'s shape:
the field is tested directly, in isolation from extraction, and the "still
raises" and "still resolves to the real, named member" paths are pinned
alongside the fallback so the fix cannot be mistaken for a blanket
``except ValueError: pass``.

"""

from __future__ import annotations

import copy
import enum
import pickle
import unittest
from typing import TYPE_CHECKING

import aenum

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any


class IntCode(aenum.IntEnum):
    """An :class:`int`-backed registry stand-in.

    Module level rather than local to a test method because :mod:`pickle` has
    to be able to find it by name, which a class defined inside a method cannot
    be.

    """

    first = 1
    second = 2


class StdlibIntCode(enum.IntEnum):
    """The same shape, from the standard library's :mod:`enum`.

    ``_unregistered_member`` is annotated for both libraries, so both are
    exercised rather than assuming they behave alike here.

    """

    first = 1
    second = 2


class OpaqueCode(aenum.Enum):
    """A registry deriving from neither :class:`str` nor :class:`int`."""

    alpha = 'a'
    beta = 'b'


class PortEnumFieldBoundedFallbackTests(unittest.TestCase):
    """TCP, UDP and SCTP's port fields."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _fields(self) -> 'list[tuple[str, Any, Any]]':
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.protocols.schema.transport import sctp as sctp_schema
        from pcapkit.protocols.schema.transport import tcp as tcp_schema
        from pcapkit.protocols.schema.transport import udp as udp_schema

        return [
            ('tcp', tcp_schema.PortEnumField(length=2, namespace=AppType), TransportProtocol.tcp),
            ('udp', udp_schema.PortEnumField(length=2, namespace=AppType), TransportProtocol.udp),
            ('sctp', sctp_schema.PortEnumField(length=2, namespace=AppType), TransportProtocol.sctp),
        ]

    def test_an_ephemeral_port_resolves_without_growing_the_registry(self) -> None:
        """The issue's own finding: 111 ephemeral ports, 111 ``extend_enum`` calls.

        54321 carries no IANA assignment on any of the three transports and
        sits in none of ``AppType._missing_``'s documented spans, so this is
        exactly the value that used to mint ``PORT_54321_<transport>``. The
        resolved member still carries ``.port``, ``.svc`` and ``.proto`` --
        read unconditionally by e.g. ``Transport._decode_next_layer``'s
        ``srcport.port`` -- because losing them would trade one crash for
        another. Per the owner's ruling, it is now a real member of the
        registry -- ``isinstance`` holds against both the per-transport
        registry and ``AppType`` itself -- rather than some foreign stand-in,
        and two such members for the same value are distinct objects, which
        is what proves neither was cached into any lookup table.

        """
        from pcapkit.const.reg.apptype import AppType

        for label, field, proto in self._fields():
            with self.subTest(transport=label):
                owner = AppType.__registries__[proto]
                before = len(owner.__members__)

                resolved = field.unpack(b'\xd4\x31', {})  # 54321
                resolved_again = field.unpack(b'\xd4\x31', {})

                self.assertEqual(len(owner.__members__), before)
                self.assertIsInstance(resolved, owner)
                self.assertIsInstance(resolved, AppType)
                self.assertEqual(resolved.port, 54321)
                self.assertEqual(resolved.svc, 'unknown')
                self.assertEqual(resolved.proto, proto)
                self.assertEqual(resolved.name, '<unassigned>')
                # NOTE: a real member of a registered value would be the same
                # object every time (aenum caches by value); two distinct
                # objects here is what proves this one was never registered.
                self.assertIsNot(resolved, resolved_again)

    def test_two_unregistered_members_for_the_same_port_compare_equal(self) -> None:
        """A caveat of returning a real member: equality is by ``.port``, not
        identity, and that holds even across two never-registered instances.

        ``AppType`` defines ``__eq__``/``__hash__`` off ``.port`` for every
        member, declared or not, so this is not new to the unregistered case
        -- but it is worth pinning explicitly, since nothing else in this
        module would notice if it silently changed. No reader in this
        package compares a resolved port with ``is`` or keys a mapping on it
        expecting identity (checked by inspection, not asserted here).

        """
        from pcapkit.const.reg.apptype import AppType

        for label, field, proto in self._fields():
            with self.subTest(transport=label):
                first = field.unpack(b'\xd4\x31', {})   # 54321
                second = field.unpack(b'\xd4\x31', {})  # same port again

                self.assertIsNot(first, second)
                self.assertEqual(first, second)
                self.assertEqual(hash(first), hash(second))
                self.assertIsInstance(first, AppType)
                self.assertIsInstance(second, AppType)

    def test_a_value_lookup_on_the_resolved_port_still_raises(self) -> None:
        """The member is absent from ``_value2member_map_``, so looking the
        same port back up *by value*, on the same per-transport class the
        field resolved it against -- rather than reading the attributes off
        the object already in hand -- still raises, exactly as it did before
        this member existed. Nothing on the parse or reconstruction path
        does this to a value it just resolved; this pins that the registry
        itself has not changed underneath that assumption.

        A direct call to ``.get()`` is different on purpose and stays that
        way: the owner's ruling and the docstring above are both explicit
        that ``get()`` is the public API and minting for a caller who asked
        for this exact value directly is defensible, which is also what
        ``tests/const/test_const_apptype_split_unit.py`` pins for
        ``PORT_59001_tcp``/``PORT_51_tcp``. So this only asserts the
        value-lookup side, never the ``.get()`` side.

        """
        from pcapkit.const.reg.apptype import AppType

        for label, field, proto in self._fields():
            with self.subTest(transport=label):
                owner = AppType.__registries__[proto]
                resolved = field.unpack(b'\xd4\x31', {})  # 54321
                del resolved  # the object itself is not what is re-looked-up

                with self.assertRaises(ValueError):
                    owner(54321)

    def test_an_assigned_port_still_resolves_to_its_declared_member(self) -> None:
        """Port 80 is still ``http``, on every transport that carries it."""
        from pcapkit.const.reg.apptype import AppType

        for label, field, proto in self._fields():
            with self.subTest(transport=label):
                owner = AppType.__registries__[proto]
                before = len(owner.__members__)

                resolved = field.unpack(b'\x00\x50', {})  # 80

                self.assertEqual(len(owner.__members__), before)
                self.assertIsInstance(resolved, AppType)
                self.assertEqual(resolved.svc, 'http')
                self.assertIs(resolved, AppType.get(80, proto=proto))

    def test_a_documented_span_still_mints_its_own_bounded_member(self) -> None:
        """``_missing_``'s own declared-range mechanism is untouched.

        230 falls in the ``225-241`` "Reserved" span every registry's
        ``_missing_`` answers regardless of transport, so it has always
        resolved to a real, named member -- the mechanism the issue
        explicitly leaves alone, as distinct from ``get()``'s unbounded
        fall-through this fix removes.

        """
        from pcapkit.const.reg.apptype import AppType

        for label, field, proto in self._fields():
            with self.subTest(transport=label):
                resolved = field.unpack(b'\x00\xe6', {})  # 230

                self.assertIsInstance(resolved, AppType)
                self.assertEqual(resolved.svc, 'reserved')
                self.assertEqual(resolved.port, 230)

    def test_an_out_of_width_port_still_raises_764s_rejection(self) -> None:
        """The bounded fallback must not revert GitHub issue #764.

        ``post_process`` is reachable directly -- not only through ``unpack``,
        which cannot even construct an out-of-range value from a 2-octet
        field -- and a catch keyed on exception type alone cannot tell
        #764's deliberate out-of-range rejection apart from :mod:`aenum`'s own
        "no member has this value" for an in-range but unassigned port: both
        are a bare :exc:`ValueError`. So ``-1`` and ``70000`` (neither
        representable by a 2-octet port) must still raise, exactly as
        ``AppType.get()`` itself does, while ``54321`` (in-range, merely
        unassigned) still resolves to the unregistered member.

        """
        from pcapkit.const.reg.apptype import AppType

        for label, field, proto in self._fields():
            with self.subTest(transport=label):
                for out_of_width in (-1, 70000):
                    with self.subTest(transport=label, value=out_of_width):
                        with self.assertRaises(ValueError):
                            field.post_process(out_of_width, {})

                resolved = field.post_process(54321, {})
                self.assertIsInstance(resolved, AppType)
                self.assertEqual(resolved.port, 54321)

    def test_an_in_library_rejection_is_not_absorbed(self) -> None:
        """A registry's own deliberate decision still propagates.

        Patches the TCP registry's ``_missing_`` to reject with one of
        :mod:`pcapkit.utilities.exceptions`, which a blanket
        ``except ValueError: pass`` would have swallowed. Nothing under
        :mod:`pcapkit.const` actually raises one here today -- this is the
        stand-in the fallback still has to respect regardless.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.protocols.schema.transport import tcp as tcp_schema
        from pcapkit.utilities.exceptions import FieldValueError

        owner = AppType.__registries__[TransportProtocol.tcp]
        had_own = '_missing_' in owner.__dict__
        original = owner.__dict__.get('_missing_')

        def _reject(cls: object, value: int) -> None:
            raise FieldValueError('%r is deliberately rejected' % value)

        owner._missing_ = classmethod(_reject)
        try:
            field = tcp_schema.PortEnumField(length=2, namespace=AppType)
            with self.assertRaises(FieldValueError):
                field.unpack(b'\xd4\x31', {})
        finally:
            if had_own:
                owner._missing_ = original
            else:
                del owner._missing_

    def test_the_resolved_pseudo_member_repacks_to_the_octets_it_came_from(self) -> None:
        """The fallback is round-trip safe, same as #701's."""
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.protocols.schema.transport import tcp as tcp_schema

        field = tcp_schema.PortEnumField(length=2, namespace=AppType)
        resolved = field.unpack(b'\xd4\x31', {})

        self.assertEqual(field.pack(resolved, {}), b'\xd4\x31')


class OptionEnumFieldBoundedFallbackTests(unittest.TestCase):
    """PCAP-NG's option-type field."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_an_undeclared_option_code_resolves_without_growing_the_registry(self) -> None:
        """An interface-block option code no ``if`` or ``opt`` row covers.

        ``OptionType._missing_`` never declines -- unlike ``AppType``'s, it
        mints unconditionally on any miss -- so this fallback cannot consult
        it the way the port fields consult ``AppType``'s, and instead
        replicates the read-only membership test ``OptionType.get`` itself
        runs first. ``.opt_name`` and ``.opt_value`` are read unconditionally
        by pcapng's own ``_option_key``.

        """
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.schema.misc import pcapng as pcapng_schema

        field = pcapng_schema.OptionEnumField(length=2, namespace='if')
        before = len(OptionType.__members__)

        resolved = field.unpack(b'\x27\x0f', {})  # 9999
        resolved_again = field.unpack(b'\x27\x0f', {})

        self.assertEqual(len(OptionType.__members__), before)
        self.assertIsInstance(resolved, OptionType)
        self.assertEqual(resolved.opt_name, 'if_unknown')
        self.assertEqual(resolved.opt_value, 9999)
        # NOTE: as for AppType -- a real, registered member would be the same
        # cached object every time; two distinct ones proves it never was.
        self.assertIsNot(resolved, resolved_again)

    def test_a_declared_option_code_still_resolves_to_its_member(self) -> None:
        """``if_tsresol`` (9) is still ``if_tsresol``."""
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.schema.misc import pcapng as pcapng_schema

        field = pcapng_schema.OptionEnumField(length=2, namespace='if')
        before = len(OptionType.__members__)

        resolved = field.unpack(b'\x00\x09', {})  # if_tsresol == 9

        self.assertEqual(len(OptionType.__members__), before)
        self.assertIsInstance(resolved, OptionType)
        self.assertEqual(resolved.opt_name, 'if_tsresol')

    def test_the_resolved_pseudo_member_repacks_to_the_octets_it_came_from(self) -> None:
        """The fallback is round-trip safe here too."""
        from pcapkit.protocols.schema.misc import pcapng as pcapng_schema

        field = pcapng_schema.OptionEnumField(length=2, namespace='if')
        resolved = field.unpack(b'\x27\x0f', {})

        self.assertEqual(field.pack(resolved, {}), b'\x27\x0f')


class UnregisteredMemberStorageBaseTests(unittest.TestCase):
    """``_unregistered_member``'s ``int`` branch and its ``TypeError`` guard.

    Neither is reachable from the four call sites this issue touches:
    :class:`~pcapkit.const.reg.apptype.AppType` and
    :class:`~pcapkit.const.pcapng.option_type.OptionType` are both
    ``StrEnum``, so all four take the :class:`str` branch. The method is
    written for registries in general, though, and an untested branch in a
    fallback is the kind that turns out to be wrong the first time something
    needs it -- so both are driven directly here, against registries standing
    in for the ones a future caller would hand it.

    """

    def test_an_int_backed_namespace_gets_an_int_backed_member(self) -> None:
        """``int.__new__`` is used where the registry derives from :class:`int`.

        The resulting member has to be usable *as* an :class:`int` -- that is
        the whole reason the branch picks the storage base rather than always
        using :class:`str` -- and, exactly as on the :class:`str` path, must
        leave the registry's own tables untouched. Both ``__members__`` and
        ``_value2member_map_`` are compared as mappings rather than by length,
        so a substitution of equal size would still be caught.

        """
        from pcapkit.corekit.fields.numbers import EnumField

        for namespace in (IntCode, StdlibIntCode):
            with self.subTest(namespace=namespace.__name__):
                members = dict(namespace.__members__)
                by_value = dict(namespace._value2member_map_)  # pylint: disable=protected-access

                member = EnumField._unregistered_member(  # pylint: disable=protected-access
                    namespace, 4242, 'unassigned', label='none')

                self.assertIsInstance(member, namespace)
                self.assertIsInstance(member, int)
                self.assertEqual(int(member), 4242)
                self.assertEqual(member.value, 4242)
                self.assertEqual(member.name, 'unassigned')
                self.assertEqual(member.label, 'none')

                self.assertEqual(dict(namespace.__members__), members)
                self.assertEqual(
                    dict(namespace._value2member_map_), by_value)  # pylint: disable=protected-access
                # NOTE: the same value-keyed lookup the str path is pinned on
                # above -- absent from _value2member_map_, so it still raises.
                with self.assertRaises(ValueError):
                    namespace(4242)

    def test_a_namespace_deriving_from_neither_str_nor_int_is_refused(self) -> None:
        """The guard says so plainly instead of guessing a storage base.

        Building such a member with :class:`str` or :class:`int` regardless
        would ship one silently missing whatever its real base provides, which
        is a worse failure than refusing: it would surface somewhere else
        entirely, as a missing method rather than as an unsupported registry.

        """
        from pcapkit.corekit.fields.numbers import EnumField

        before = dict(OpaqueCode.__members__)

        with self.assertRaises(TypeError) as caught:
            EnumField._unregistered_member(  # pylint: disable=protected-access
                OpaqueCode, 'gamma', 'unassigned')

        self.assertIn('derives from neither str nor int', str(caught.exception))
        self.assertEqual(dict(OpaqueCode.__members__), before)


class UnregisteredMemberRoundTripTests(unittest.TestCase):
    """:mod:`pickle` and :mod:`copy` of a resolved unassigned port.

    ``Enum.__reduce_ex__`` reduces a member to ``(cls, (value,))``, i.e. to the
    one lookup an unregistered member is deliberately absent from. Before this
    issue's fix the port fields minted, so the member *was* registered and a
    round-trip worked; without the ``__reduce_ex__``
    :meth:`~pcapkit.corekit.fields.numbers.EnumField._unregistered_member`
    installs, removing the mint would have taken that away -- and taken it away
    on read-back, since ``pickle.dumps`` succeeds either way. These pin the
    mitigation, and that it does not put the mint back.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _resolved(self) -> 'Any':
        """An unassigned TCP port, resolved through the real field."""
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.protocols.schema.transport import tcp as tcp_schema

        field = tcp_schema.PortEnumField(length=2, namespace=AppType)
        return field.unpack(b'\xd0\x9e', {})  # 53406

    def test_a_pickle_round_trip_rebuilds_an_equivalent_unregistered_member(self) -> None:
        """Every protocol, since the reduction has to name a callable each can
        reference -- a module-level function, not one nested in a class, which
        protocols below 4 cannot address.

        """
        from pcapkit.const.reg.apptype import AppType

        member = self._resolved()
        owner = type(member)
        before = len(owner.__members__)

        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                restored = pickle.loads(pickle.dumps(member, protocol))

                self.assertIsInstance(restored, owner)
                self.assertIsInstance(restored, AppType)
                self.assertEqual(restored, member)
                self.assertEqual(restored.port, 53406)
                self.assertEqual(restored.svc, 'unknown')
                self.assertEqual(restored.proto, member.proto)
                self.assertEqual(restored.name, '<unassigned>')
                # NOTE: rebuilding goes back through _unregistered_member and
                # never through owner.__new__, so it cannot register anything.
                self.assertNotIn(restored.name, owner.__members__)
                self.assertEqual(len(owner.__members__), before)

    def test_copy_and_deepcopy_survive_without_the_3_11_enum_shim(self) -> None:
        """CPython's :mod:`enum` grew ``Enum.__copy__``/``__deepcopy__``, both
        returning ``self`` without any lookup, in 3.11; on 3.10 -- still a
        supported version here -- neither exists and both fall through to
        ``__reduce_ex__``. :class:`aenum.Enum` subclasses stdlib
        :class:`enum.Enum` and defines only ``__reduce_ex__`` of its own, so
        deleting those two off :class:`enum.Enum` is what 3.10 looks like from
        here; there is no 3.10 interpreter on this host to run instead.

        """
        member = self._resolved()
        owner = type(member)
        before = len(owner.__members__)

        shim = [name for name in ('__copy__', '__deepcopy__')
                if name in enum.Enum.__dict__]
        if shim:
            # 3.11+: both short-circuit ahead of any reduction at all.
            self.assertIs(copy.copy(member), member)
            self.assertIs(copy.deepcopy(member), member)

        originals = [(name, enum.Enum.__dict__[name]) for name in shim]
        for name, _ in originals:
            delattr(enum.Enum, name)
        try:
            for label, copier in (('copy', copy.copy), ('deepcopy', copy.deepcopy)):
                with self.subTest(copier=label):
                    restored = copier(member)

                    self.assertIsInstance(restored, owner)
                    self.assertEqual(restored, member)
                    self.assertEqual(restored.port, 53406)
                    self.assertEqual(restored.svc, 'unknown')
                    self.assertEqual(restored.name, '<unassigned>')
                    self.assertEqual(len(owner.__members__), before)
        finally:
            for name, original in originals:
                setattr(enum.Enum, name, original)

    def test_the_reducer_is_not_rendered_as_one_of_the_members_attributes(self) -> None:
        """``__reduce_ex__`` lives in the member's own ``__dict__``, which is
        what :meth:`pcapkit.dumpkit.common.make_dumper`'s ``object_hook`` reads
        a member's addon keys out of. It is filtered there by its leading
        underscore -- pinned here so the mitigation cannot start leaking a
        :class:`functools.partial` into every dumped capture.

        """
        member = self._resolved()

        self.assertIn('__reduce_ex__', member.__dict__)
        self.assertEqual([key for key in member.__dict__ if not key.startswith('_')],
                         ['svc', 'port', 'proto'])


if __name__ == '__main__':
    unittest.main()
