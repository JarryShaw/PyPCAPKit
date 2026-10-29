# -*- coding: utf-8 -*-
""":class:`Deferred` could not be pickled under protocol 0 or 1.

GitHub issues :issue:`2423` and :issue:`2425`.

:class:`~pcapkit.foundation.reassembly.data.data.Deferred` declares
``__slots__`` and defined neither ``__getstate__`` nor ``__setstate__``. A
slotted class has no ``__dict__`` for the default pickle reduction to read,
and :mod:`copyreg` refuses outright under protocol 0 or 1 whenever
``type(self).__getstate__`` is still the inherited default, so
:func:`pickle.dumps` raised :exc:`TypeError` -- *"a class that defines
__slots__ without defining __getstate__ cannot be pickled"* -- for *any*
``Deferred`` instance under either protocol, independent of what ``analyze``
and ``proto`` held (:issue:`2423`).

The cross-review on that fix raised further defects before it merged, all
covered here as well, every one of them at the ``__getstate__``/
``__setstate__`` pair (:issue:`2425`):

* the first revision's ``__getstate__`` returned a flat ``{slot: value}``
  dict -- a *different* shape from the ``(dict_or_None, slots)`` pair every
  released, pre-:issue:`2423` build already produced for protocol 2 and
  above (neither defined a custom ``__getstate__``, so Python's own default
  slotted-class reduction built it). Restoring either shape with the other's
  :meth:`__setstate__` raised :exc:`AttributeError`. The fix mirrors that
  native shape instead of inventing one, so a ``Deferred`` pickled by any
  released version still unpickles, and :meth:`__setstate__` additionally
  still accepts the first revision's own flat shape.
* the second revision's ``__getstate__`` walked ``type(self).__mro__`` and
  read each class's ``__slots__`` directly, fixing the dropped-base-class-slots
  case above but still getting two slot *spellings* wrong: a bare-string
  ``__slots__ = 'extra'`` (valid Python for one slot named by the whole
  string) was iterated character by character, and a private, name-mangled
  ``__slots__ = ('__secret',)`` was read back under its unmangled name, which
  :func:`hasattr` never finds (the instance attribute is really
  ``_<ClassName>__secret``). The fix replaces the hand-rolled walk with
  :func:`copyreg._slotnames`, the standard library's own helper for this,
  which already gets both right.

The analyser passed to ``Deferred`` has to be a module-level function here --
a :keyword:`lambda` is not picklable by :mod:`pickle` under *any* protocol
(its qualified name resolves to nothing importable), which is a separate,
unrelated limitation that would mask what this test is pinning. A *bound
method* is not the same problem -- its instance and its class are each
looked up by name and pickle just fine -- a module-level function is simply
the plainest picklable callable available here.

:class:`_BareStringSlotSub` and :class:`_MangledSlotSub` below are module-level
for the same reason ``Deferred`` itself is imported at module scope in this
file alone, breaking with the rest of this directory's per-test
``from pcapkit... import`` convention (see
:func:`~tests._support.reimport_once_per_class`): a class :mod:`pickle` can
locate by its qualified name has to be defined somewhere importable, not
nested inside a test method, for the round trips below to go through *real*
:func:`pickle.dumps`/:func:`pickle.loads` rather than a direct call to
``__getstate__``/``__setstate__``. The module-level import does not leak into
the rest of this file's tests: each ``Deferred`` instance built with a
freshly re-imported class, as every other test here does, is still ``isinstance``-
distinct from these two subclasses' own class object, but none of this file's
assertions mix the two.

"""

import copyreg
import pickle
import unittest

from pcapkit.foundation.reassembly.data.data import Deferred as _Deferred
from tests._support import reimport_once_per_class

#: Test tier (#1958): pickling and copying behaviour belongs on ``ALL``, per
#: ``tests/_tiers.py``'s own list of what qualifies -- it is exactly the kind
#: of thing that can (and, within this file's own history, did) differ
#: between interpreters, most sharply the :issue:`2425` round that needed
#: ``__reduce_ex__`` rather than ``object.__getstate__`` (3.11+ only) to build
#: a version-independent comparison shape.
__tier__ = 'ALL'


def _analyze(proto: 'object', payload: 'bytes') -> 'tuple[object, bytes]':
    """Module-level stand-in analyser; picklable under every protocol."""
    return (proto, payload)


class _BareStringSlotSub(_Deferred):
    """A subclass declaring its own slot as a bare string, not a tuple.

    ``__slots__ = 'extra'`` is valid Python -- one slot named by the whole
    string -- and is exactly what a ``for name in cls.__slots__`` walk gets
    wrong: it iterates the string's *characters* instead of treating it as a
    single name (:issue:`2425`).

    """

    __slots__ = 'extra'

    def __init__(self, analyze: 'object', proto: 'object', payload: 'bytes',
                 extra: 'object') -> 'None':
        super().__init__(analyze, proto, payload)
        self.extra = extra


class _MangledSlotSub(_Deferred):
    """A subclass declaring a private, name-mangled slot.

    ``__slots__ = ('__secret',)`` inside a class body is stored, at the
    instance level, under the mangled name ``_MangledSlotSub__secret`` -- the
    same mangling ``self.__secret`` gets for an ordinary attribute. Reading
    the unmangled spelling back, as ``hasattr(self, '__secret')`` does, never
    finds it (:issue:`2425`).

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
        """``__getstate__`` returns the native ``(dict_or_None, slots)`` pair.

        Not a flat :obj:`dict` -- that was the first revision's shape, and
        :issue:`2425` finding 1 is exactly that it disagreed with the shape
        every released pickle already used.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        deferred = Deferred(_analyze, 42, b'payload')
        state = deferred.__getstate__()
        self.assertIsInstance(state, tuple)
        self.assertEqual(len(state), 2)

        dict_state, slots_state = state
        # ``Deferred`` declares no bare ``__dict__`` of its own.
        self.assertIsNone(dict_state)
        self.assertEqual(slots_state, {'analyze': _analyze, 'proto': 42, 'payload': b'payload'})
        self.assertEqual(set(slots_state), set(Deferred.__slots__))


class DeferredPickleBackwardCompatibilityTests(unittest.TestCase):
    """:issue:`2425` finding 1: the state shape must match every released build's.

    A ``Deferred`` pickled under protocol 2 or above by any version before
    :issue:`2423`'s fix -- every one of them, since none defined a custom
    ``__getstate__`` -- used Python's own default slotted-class reduction: a
    2-tuple of an instance-``__dict__`` state (:data:`None` here, since
    ``Deferred`` has no bare ``__dict__``) and a slots-state :obj:`dict`.
    That pickle has to keep unpickling against the current, fixed class, and
    the reverse.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _native_default_state(analyze: 'object', proto: 'object',
                               payload: 'bytes') -> 'tuple[object, dict[str, object]]':
        """The exact state a pre-:issue:`2423` ``Deferred`` pickle carried.

        Built from an unrelated class sharing ``Deferred``'s three slots and
        defining no ``__getstate__`` of its own, so Python's own default
        slotted-class reduction produces this -- not a hand-written stand-in
        for it.

        Read through ``__reduce_ex__(2)[2]`` rather than a direct call to
        ``stand_in.__getstate__()``: the latter is ``object.__getstate__``,
        added only in Python 3.11, so it raises :exc:`AttributeError` on
        3.8-3.10. ``__reduce_ex__`` is the protocol-2 reduction every
        interpreter this project supports has always had, and its third
        element is the identical state -- confirmed equal to
        ``__getstate__()``'s own result on an interpreter that has one.

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
        """The flat ``{slot: value}`` shape the very first fix returned.

        Never released, but already pushed to this pull request's earlier
        commit -- accepting it costs nothing and protects anyone who
        pickled against that commit.

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

        ``Deferred.__getstate__``/``__setstate__`` are removed for just long
        enough to dump a real ``Deferred`` instance through Python's default
        slotted-class reduction, standing in for a pickle made by any
        pre-:issue:`2423` release. The dump itself never touches this
        class's own (fixed) ``__getstate__``; only the restore does.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        getstate = Deferred.__dict__['__getstate__']
        setstate = Deferred.__dict__['__setstate__']
        del Deferred.__getstate__
        del Deferred.__setstate__
        try:
            pre_fix = Deferred(_analyze, 7, b'released')
            pickled = pickle.dumps(pre_fix, protocol=2)
        finally:
            Deferred.__getstate__ = getstate
            Deferred.__setstate__ = setstate

        restored = pickle.loads(pickled)
        self.assertEqual(restored.proto, 7)
        self.assertEqual(restored.payload, b'released')
        self.assertIs(restored.analyze, _analyze)


class DeferredPickleSubclassTests(unittest.TestCase):
    """:issue:`2425` finding 2: ``__getstate__`` must not read ``self.__slots__``.

    ``self.__slots__`` resolves through the MRO like any other attribute, so
    a subclass declaring its own ``__slots__`` shadows ``Deferred``'s. The
    first revision read ``self.__slots__`` directly and so silently dropped
    every slot ``Deferred`` itself declares for such a subclass, rather than
    raising -- the loss is silent on ``__getstate__`` and only surfaces as a
    missing attribute later, on whatever first reads it back.

    Exercised directly through ``__getstate__``/``__setstate__`` rather than a
    full :func:`pickle.dumps`/:func:`pickle.loads` round trip: the subclass
    has to be defined inside the test for the same reason the module
    docstring gives for not using a lambda as the analyser -- a class local to
    a function is not importable by its qualified name, so :mod:`pickle`
    cannot locate it to build a real pickle. The two methods are exactly the
    mechanism :issue:`2425` finding 2 is about, so calling them directly still
    exercises the regression.

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

        dict_state, slots_state = sub.__getstate__()
        self.assertIsNone(dict_state)
        self.assertEqual(slots_state, {
            'analyze': _analyze, 'proto': 7, 'payload': b'x', 'extra': 'extra-value',
        })

    def test_setstate_restores_both_the_subclasss_and_the_base_classs_slots(self) -> None:
        subclass = self._subclass_with_extra_slot()
        sub = subclass(_analyze, 7, b'x', 'extra-value')

        state = sub.__getstate__()
        restored = subclass.__new__(subclass)
        restored.__setstate__(state)
        self.assertEqual(restored.proto, 7)
        self.assertEqual(restored.payload, b'x')
        self.assertEqual(restored.extra, 'extra-value')
        self.assertIs(restored.analyze, _analyze)


class DeferredGetstateEdgeCaseTests(unittest.TestCase):
    """The edge cases ``__getstate__``'s MRO walk has to match Python's own.

    Each of these mirrors a branch of the native default state construction
    (see the module docstring's worked example in
    :class:`DeferredPickleBackwardCompatibilityTests`): an unset slot, the
    ``__weakref__`` bookkeeping slot, and a subclass that picks up a bare
    ``__dict__`` by declaring no ``__slots__`` of its own.

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

        dict_state, slots_state = partial.__getstate__()
        self.assertIsNone(dict_state)
        self.assertEqual(slots_state, {'proto': 1, 'payload': b'p'})

    def test_getstate_excludes_a_weakref_slot(self) -> None:
        """``__weakref__``, like ``__dict__``, is bookkeeping, not state."""
        from pcapkit.foundation.reassembly.data.data import Deferred

        class _WithWeakrefSlot(Deferred):
            __slots__ = ('__weakref__',)

        sub = _WithWeakrefSlot(_analyze, 7, b'x')
        dict_state, slots_state = sub.__getstate__()
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

        dict_state, slots_state = sub.__getstate__()
        self.assertEqual(dict_state, {'extra': 'extra-value'})
        self.assertEqual(slots_state, {'analyze': _analyze, 'proto': 7, 'payload': b'x'})

        restored = _WithBareDict.__new__(_WithBareDict)
        restored.__setstate__((dict_state, slots_state))
        self.assertEqual(restored.proto, 7)
        self.assertEqual(restored.payload, b'x')
        self.assertEqual(restored.extra, 'extra-value')


class DeferredPickleSlotSpellingTests(unittest.TestCase):
    """:issue:`2425` round 2: two slot *spellings* the MRO-walk fix still missed.

    Unlike the other subclass tests in this file, these go through *real*
    :func:`pickle.dumps`/:func:`pickle.loads`, because the defect was in how
    slot *names* are collected -- :func:`copyreg._slotnames` versus a
    hand-rolled walk -- and a direct call to ``__getstate__``/``__setstate__``
    would not have caught the hand-rolled walk reading the wrong name in the
    first place. ``_BareStringSlotSub`` and ``_MangledSlotSub`` are therefore
    module-level (see the module docstring for why that is safe here).

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
        """Pins what :func:`copyreg._slotnames` actually returns for each.

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
