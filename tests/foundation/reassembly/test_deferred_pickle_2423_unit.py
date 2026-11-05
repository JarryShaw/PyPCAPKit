# -*- coding: utf-8 -*-
""":class:`Deferred` pickles under every protocol, protocol 0 and 1 included.

GitHub issues #2423 and #2425.

:class:`~pcapkit.foundation.reassembly.data.data.Deferred` declares
``__slots__``, and :mod:`copyreg` refuses a slotted class with no
``__getstate__`` of its own under protocol 0 or 1, so :func:`pickle.dumps`
raised :exc:`TypeError` for any instance (#2423). The review of that fix found
defects in the state itself (#2425), all covered here:

* it has to be the ``(dict_or_None, slots)`` pair Python's default reduction
  builds, which every released build pickled under protocol 2 and above;
  :meth:`__setstate__` also accepts the flat ``{slot: value}`` dict of an
  unreleased first fix;
* it has to carry every base class's slots, named as :func:`copyreg._slotnames`
  names them: a bare-string ``__slots__ = 'extra'`` is one slot, and a mangled
  ``__slots__ = ('__secret',)`` is ``_<ClassName>__secret``.

The analyser is a module-level function, since a :keyword:`lambda` pickles under
no protocol. :class:`_BareStringSlotSub` and :class:`_MangledSlotSub` are
module-level, and ``Deferred`` is imported at module scope unlike the rest of
this directory, so that :mod:`pickle` can locate them by qualified name for real
round trips; no assertion mixes them with the per-class re-imported ``Deferred``.

"""

import copyreg
import pickle
import unittest

from pcapkit.foundation.reassembly.data.data import Deferred as _Deferred
from tests._support import reimport_once_per_class

#: Test tier (#1958): pickling and copying behaviour belongs on ``ALL``, per
#: ``tests/_tiers.py``, since it can differ between interpreters.
__tier__ = 'ALL'


def _analyze(proto: 'object', payload: 'bytes') -> 'tuple[object, bytes]':
    """Module-level stand-in analyser; picklable under every protocol."""
    return (proto, payload)


def _state(obj: 'object') -> 'object':
    """The state :mod:`pickle` carries for ``obj``, under every protocol.

    ``Deferred`` defines no ``__getstate__`` of its own (#2714), so this is
    Python's default state for a slotted class: ``object.__getstate__()`` on
    3.11 and later, and the same pair from the protocol-2 reduction below it,
    which is why it is read through ``__reduce_ex__(2)[2]``.

    """
    return obj.__reduce_ex__(2)[2]


class _BareStringSlotSub(_Deferred):
    """A subclass declaring its own slot as a bare string, not a tuple.

    ``__slots__ = 'extra'`` is one slot named by the whole string, which a
    ``for name in cls.__slots__`` walk splits into characters (#2425).

    """

    __slots__ = 'extra'

    def __init__(self, analyze: 'object', proto: 'object', payload: 'bytes',
                 extra: 'object') -> 'None':
        super().__init__(analyze, proto, payload)
        self.extra = extra


class _MangledSlotSub(_Deferred):
    """A subclass declaring a private, name-mangled slot.

    ``__slots__ = ('__secret',)`` is stored under ``_MangledSlotSub__secret``, so
    ``hasattr(self, '__secret')`` never finds it (#2425).

    """

    __slots__ = ('__secret',)

    def __init__(self, analyze: 'object', proto: 'object', payload: 'bytes',
                 secret: 'object') -> 'None':
        super().__init__(analyze, proto, payload)
        self.__secret = secret  # pylint: disable=unused-private-member

    def reveal_secret(self) -> 'object':
        """Read back the mangled slot; there is no other way to from outside."""
        return self.__secret  # pylint: disable=no-member


class DeferredPickleTests(unittest.TestCase):
    """:class:`Deferred` must survive a pickle round trip under every protocol."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_pickles_under_every_protocol(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                restored = pickle.loads(pickle.dumps(deferred, protocol=protocol))
                self.assertIsInstance(restored, Deferred)
                self.assertEqual(restored.proto, 42)
                self.assertEqual(restored.payload, b'payload')
                self.assertIs(restored.analyze, _analyze)
                self.assertEqual(restored(), (42, b'payload'))

    def test_protocol_0_round_trips(self) -> None:
        """Protocol 0 specifically: the regression's own repro."""
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')
        restored = pickle.loads(pickle.dumps(deferred, protocol=0))
        self.assertEqual(restored.proto, 42)
        self.assertEqual(restored.payload, b'payload')

    def test_protocol_1_round_trips(self) -> None:
        """Protocol 1 specifically: the regression's other failing protocol."""
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')
        restored = pickle.loads(pickle.dumps(deferred, protocol=1))
        self.assertEqual(restored.proto, 42)
        self.assertEqual(restored.payload, b'payload')

    def test_getstate_shape_is_dict_state_and_slots_state(self) -> None:
        """The state is the native ``(dict_or_None, slots)`` pair, not a flat dict (#2425)."""
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')
        state = _state(deferred)
        self.assertIsInstance(state, tuple)
        self.assertEqual(len(state), 2)

        dict_state, slots_state = state
        # ``Deferred`` declares no bare ``__dict__`` of its own.
        self.assertIsNone(dict_state)
        self.assertEqual(slots_state, {'analyze': _analyze, 'proto': 42, 'payload': b'payload'})
        self.assertEqual(set(slots_state), set(Deferred.__slots__))


class DeferredPickleBackwardCompatibilityTests(unittest.TestCase):
    """#2425 finding 1: the state shape must match every released build's.

    A released ``Deferred`` pickled under protocol 2 and above through Python's
    default slotted-class reduction: a pair of the instance ``__dict__`` state
    (:data:`None`, as ``Deferred`` has none) and a slots-state :obj:`dict`. That
    pickle has to unpickle against the current class, and the reverse.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _native_default_state(analyze: 'object', proto: 'object',
                               payload: 'bytes') -> 'tuple[object, dict[str, object]]':
        """The exact state a released ``Deferred`` pickle carried.

        Built from an unrelated class sharing ``Deferred``'s slots with no
        ``__getstate__`` of its own, so Python's default reduction produces it.

        Read through ``__reduce_ex__(2)[2]``, which every supported interpreter has and
        which equals ``__getstate__()``; ``object.__getstate__`` arrived in Python 3.11.

        """
        class _PreFixShape:
            __slots__ = ('analyze', 'proto', 'payload')

        stand_in = _PreFixShape()
        stand_in.analyze = analyze
        stand_in.proto = proto
        stand_in.payload = payload
        return stand_in.__reduce_ex__(2)[2]

    def test_native_default_state_shape(self) -> None:
        """Pins the shape the rest of this class relies on."""
        state = self._native_default_state(_analyze, 42, b'payload')
        self.assertEqual(state, (None, {'analyze': _analyze, 'proto': 42, 'payload': b'payload'}))

    def test_setstate_accepts_the_native_default_shape(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Deferred

        state = self._native_default_state(_analyze, 99, b'old-data')
        restored = Deferred.__new__(Deferred)
        restored.__setstate__(state)
        self.assertEqual(restored.proto, 99)
        self.assertEqual(restored.payload, b'old-data')
        self.assertIs(restored.analyze, _analyze)

    def test_setstate_still_accepts_the_first_revisions_flat_shape(self) -> None:
        """The flat ``{slot: value}`` shape of the unreleased first #2423 fix.

        Accepting it costs nothing and protects anyone who pickled against it.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        flat_state = {'analyze': _analyze, 'proto': 7, 'payload': b'flat'}
        restored = Deferred.__new__(Deferred)
        restored.__setstate__(flat_state)
        self.assertEqual(restored.proto, 7)
        self.assertEqual(restored.payload, b'flat')
        self.assertIs(restored.analyze, _analyze)

    def test_a_pickle_made_before_the_2423_fix_still_unpickles(self) -> None:
        """End-to-end: real pickle bytes, built the way a released version would.

        ``Deferred`` defines no ``__getstate__`` (#2714), so a protocol-2 dump goes
        through Python's default slotted-class reduction, as a release's did; only the
        restore goes through ``__setstate__``.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        self.assertNotIn('__getstate__', vars(Deferred))
        pre_fix = Deferred(_analyze, 7, b'released')
        self.assertEqual(pre_fix.__reduce_ex__(2), object.__reduce_ex__(pre_fix, 2))
        pickled = pickle.dumps(pre_fix, protocol=2)

        restored = pickle.loads(pickled)
        self.assertEqual(restored.proto, 7)
        self.assertEqual(restored.payload, b'released')
        self.assertIs(restored.analyze, _analyze)


class DeferredPickleSubclassTests(unittest.TestCase):
    """#2425 finding 2: the state must not read ``self.__slots__``.

    ``self.__slots__`` resolves through the MRO, so a subclass's own ``__slots__``
    shadows ``Deferred``'s, and reading it silently drops every slot ``Deferred``
    declares until something reads one back.

    The subclass is local to the test, so :mod:`pickle` cannot locate it; these read
    the state and call ``__setstate__`` directly, which is the mechanism at fault.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _subclass_with_extra_slot():
        from pcapkit.foundation.reassembly.data.data import Deferred

        class _WithExtraSlot(Deferred):
            __slots__ = ('extra',)

            def __init__(self, analyze: 'object', proto: 'object', payload: 'bytes',
                         extra: 'object') -> 'None':
                super().__init__(analyze, proto, payload)
                self.extra = extra

        return _WithExtraSlot

    def test_getstate_carries_the_base_classs_slots_as_well_as_the_subclasss(self) -> None:
        subclass = self._subclass_with_extra_slot()
        sub = subclass(_analyze, 7, b'x', 'extra-value')

        dict_state, slots_state = _state(sub)
        self.assertIsNone(dict_state)
        self.assertEqual(slots_state, {
            'analyze': _analyze, 'proto': 7, 'payload': b'x', 'extra': 'extra-value',
        })

    def test_setstate_restores_both_the_subclasss_and_the_base_classs_slots(self) -> None:
        subclass = self._subclass_with_extra_slot()
        sub = subclass(_analyze, 7, b'x', 'extra-value')

        state = _state(sub)
        restored = subclass.__new__(subclass)
        restored.__setstate__(state)
        self.assertEqual(restored.proto, 7)
        self.assertEqual(restored.payload, b'x')
        self.assertEqual(restored.extra, 'extra-value')
        self.assertIs(restored.analyze, _analyze)


class DeferredGetstateEdgeCaseTests(unittest.TestCase):
    """The edge cases of the state, which ``Deferred`` takes from Python's own default.

    Each mirrors a branch of the default state construction: an unset slot, the
    ``__weakref__`` bookkeeping slot, and a subclass with no ``__slots__`` of its
    own, which gets a ``__dict__``.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_getstate_skips_an_unset_slot(self) -> None:
        """A slot never assigned is omitted, as Python's own default does."""
        from pcapkit.foundation.reassembly.data.data import Deferred

        partial = Deferred.__new__(Deferred)
        partial.proto = 1
        partial.payload = b'p'
        # ``analyze`` is deliberately left unset.

        dict_state, slots_state = _state(partial)
        self.assertIsNone(dict_state)
        self.assertEqual(slots_state, {'proto': 1, 'payload': b'p'})

    def test_getstate_excludes_a_weakref_slot(self) -> None:
        """``__weakref__``, like ``__dict__``, is bookkeeping, not state."""
        from pcapkit.foundation.reassembly.data.data import Deferred

        class _WithWeakrefSlot(Deferred):
            __slots__ = ('__weakref__',)

        sub = _WithWeakrefSlot(_analyze, 7, b'x')
        dict_state, slots_state = _state(sub)
        self.assertIsNone(dict_state)
        self.assertNotIn('__weakref__', slots_state)
        self.assertEqual(slots_state, {'analyze': _analyze, 'proto': 7, 'payload': b'x'})

    def test_getstate_and_setstate_carry_a_subclasss_bare_dict_too(self) -> None:
        """A subclass with no ``__slots__`` of its own gets a real ``__dict__``."""
        from pcapkit.foundation.reassembly.data.data import Deferred

        class _WithBareDict(Deferred):
            pass  # no __slots__ declared here, so instances gain a __dict__

        sub = _WithBareDict(_analyze, 7, b'x')
        sub.extra = 'extra-value'  # lands in __dict__, not in a slot

        dict_state, slots_state = _state(sub)
        self.assertEqual(dict_state, {'extra': 'extra-value'})
        self.assertEqual(slots_state, {'analyze': _analyze, 'proto': 7, 'payload': b'x'})

        restored = _WithBareDict.__new__(_WithBareDict)
        restored.__setstate__((dict_state, slots_state))
        self.assertEqual(restored.proto, 7)
        self.assertEqual(restored.payload, b'x')
        self.assertEqual(restored.extra, 'extra-value')


class DeferredPickleSlotSpellingTests(unittest.TestCase):
    """#2425: the two slot *spellings* a hand-rolled MRO walk gets wrong.

    Real :func:`pickle.dumps`/:func:`pickle.loads` round trips, since the defect is
    in how slot *names* are collected, which a direct ``__setstate__`` call would
    not reach; hence the module-level subclasses.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_bare_string_slot_round_trips_under_every_protocol(self) -> None:
        sub = _BareStringSlotSub(_analyze, 7, b'x', 'extra-value')
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                restored = pickle.loads(pickle.dumps(sub, protocol=protocol))
                self.assertEqual(restored.proto, 7)
                self.assertEqual(restored.payload, b'x')
                self.assertEqual(restored.extra, 'extra-value')

    def test_mangled_slot_round_trips_under_every_protocol(self) -> None:
        sub = _MangledSlotSub(_analyze, 7, b'x', 'secret-value')
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                restored = pickle.loads(pickle.dumps(sub, protocol=protocol))
                self.assertEqual(restored.proto, 7)
                self.assertEqual(restored.payload, b'x')
                self.assertEqual(restored.reveal_secret(), 'secret-value')

    def test_slotnames_resolves_both_spellings_correctly(self) -> None:
        """Pins what :func:`copyreg._slotnames` returns for each.

        A bare string resolves to the name itself, not its characters; a
        mangled name resolves to its real, ``_<ClassName>``-prefixed
        attribute name.

        """
        self.assertIn('extra', copyreg._slotnames(_BareStringSlotSub))
        self.assertNotIn('e', copyreg._slotnames(_BareStringSlotSub))
        self.assertIn('_MangledSlotSub__secret', copyreg._slotnames(_MangledSlotSub))
        self.assertNotIn('__secret', copyreg._slotnames(_MangledSlotSub))


if __name__ == '__main__':
    unittest.main()
