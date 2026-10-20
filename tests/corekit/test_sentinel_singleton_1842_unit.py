# -*- coding: utf-8 -*-
"""GitHub issue #1842: every sentinel is a true singleton.

The owner chose to make the sentinels singletons rather than amend the
convention page to excuse them, with the shared behaviour on one abstract
base. So for ``NULL``, ``NO_VALUE``, ``NO_DEFAULT`` and ``ABSENT`` alike,
calling the type again, :func:`copy.copy`, :func:`copy.deepcopy` and every
:mod:`pickle` protocol hand back the one object.

Before the change only ``NULL`` passed all of that. ``NO_DEFAULT`` failed
pickle protocols 0 and 1, and ``NO_VALUE`` and ``ABSENT`` failed everything.

In review of that change the owner asked for the base to be public, named
``Sentinel`` after the library's other abstract bases, for every sentinel
and sentinel type to be immutable, and for their repr and related behaviour
to agree with Python's own singletons. :class:`BuiltinParityTests` runs the
same probes against :obj:`None`, :obj:`Ellipsis` and :obj:`NotImplemented`
and against each sentinel, and the classes after it pin each behaviour on
its own.

:data:`OLD_PICKLES` are pickles written by the module as it stood at
``75a9f237b``, the commit this change is based on, so they pin that a pickle
made before the change still loads. They were produced by executing
``git show 75a9f237b:pcapkit/corekit/sentinels.py`` as a module named
``pcapkit.corekit.sentinels``, registering it in :data:`sys.modules`, and
calling :func:`pickle.dumps` on each sentinel at each protocol.

"""
from __future__ import annotations

import abc
import copy
import importlib
import inspect
import pickle
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): exercises pickling and copying, whose protocols differ by
#: interpreter.
__tier__ = 'ALL'

#: Where every sentinel is defined.
CANONICAL_MODULE = 'pcapkit.corekit.sentinels'

#: ``(object name, repr, truth value)`` for every sentinel. The repr is the
#: object's own name, as ``repr(None)`` is ``'None'``; the truth value is each
#: sentinel's own, which the shared base leaves alone.
SENTINELS = (
    ('NULL', 'NULL', False),
    ('NO_VALUE', 'NO_VALUE', False),
    ('NO_DEFAULT', 'NO_DEFAULT', True),
    ('ABSENT', 'ABSENT', False),
)

#: Python's own singletons, which a sentinel is to behave like.
BUILTINS = (None, Ellipsis, NotImplemented)

#: Pickles written at ``75a9f237b``, keyed by ``(object name, protocol)``. ``NULL``
#: reduced to the module-level ``_get_null``; the others took the default reduce,
#: which is ``copyreg._reconstructor`` below protocol 2 and ``NEWOBJ`` from 2 on.
OLD_PICKLES = {
    ('NULL', 0): b'cpcapkit.corekit.sentinels\n_get_null\np0\n(tRp1\n.',
    ('NULL', 1): b'cpcapkit.corekit.sentinels\n_get_null\nq\x00)Rq\x01.',
    ('NULL', 2): b'\x80\x02cpcapkit.corekit.sentinels\n_get_null\nq\x00)Rq\x01.',
    ('NULL', 3): b'\x80\x03cpcapkit.corekit.sentinels\n_get_null\nq\x00)Rq\x01.',
    ('NULL', 4): (b'\x80\x04\x95.\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                  b'\x94\x8c\t_get_null\x94\x93\x94)R\x94.'),
    ('NULL', 5): (b'\x80\x05\x95.\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                  b'\x94\x8c\t_get_null\x94\x93\x94)R\x94.'),
    ('NO_VALUE', 0): (b'ccopy_reg\n_reconstructor\np0\n(cpcapkit.corekit.sentinels\nNoValueType\n'
                      b'p1\nc__builtin__\nobject\np2\nNtp3\nRp4\n.'),
    ('NO_VALUE', 1): (b'ccopy_reg\n_reconstructor\nq\x00(cpcapkit.corekit.sentinels\nNoValueType\n'
                      b'q\x01c__builtin__\nobject\nq\x02Ntq\x03Rq\x04.'),
    ('NO_VALUE', 2): b'\x80\x02cpcapkit.corekit.sentinels\nNoValueType\nq\x00)\x81q\x01.',
    ('NO_VALUE', 3): b'\x80\x03cpcapkit.corekit.sentinels\nNoValueType\nq\x00)\x81q\x01.',
    ('NO_VALUE', 4): (b'\x80\x04\x950\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                      b'\x94\x8c\x0bNoValueType\x94\x93\x94)\x81\x94.'),
    ('NO_VALUE', 5): (b'\x80\x05\x950\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                      b'\x94\x8c\x0bNoValueType\x94\x93\x94)\x81\x94.'),
    ('NO_DEFAULT', 0): (b'ccopy_reg\n_reconstructor\np0\n(cpcapkit.corekit.sentinels\nNoDefaultType\n'
                        b'p1\nc__builtin__\nobject\np2\nNtp3\nRp4\n.'),
    ('NO_DEFAULT', 1): (b'ccopy_reg\n_reconstructor\nq\x00(cpcapkit.corekit.sentinels\nNoDefaultType\n'
                        b'q\x01c__builtin__\nobject\nq\x02Ntq\x03Rq\x04.'),
    ('NO_DEFAULT', 2): b'\x80\x02cpcapkit.corekit.sentinels\nNoDefaultType\nq\x00)\x81q\x01.',
    ('NO_DEFAULT', 3): b'\x80\x03cpcapkit.corekit.sentinels\nNoDefaultType\nq\x00)\x81q\x01.',
    ('NO_DEFAULT', 4): (b'\x80\x04\x952\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                        b'\x94\x8c\rNoDefaultType\x94\x93\x94)\x81\x94.'),
    ('NO_DEFAULT', 5): (b'\x80\x05\x952\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                        b'\x94\x8c\rNoDefaultType\x94\x93\x94)\x81\x94.'),
    ('ABSENT', 0): (b'ccopy_reg\n_reconstructor\np0\n(cpcapkit.corekit.sentinels\nAbsentType\n'
                    b'p1\nc__builtin__\nobject\np2\nNtp3\nRp4\n.'),
    ('ABSENT', 1): (b'ccopy_reg\n_reconstructor\nq\x00(cpcapkit.corekit.sentinels\nAbsentType\n'
                    b'q\x01c__builtin__\nobject\nq\x02Ntq\x03Rq\x04.'),
    ('ABSENT', 2): b'\x80\x02cpcapkit.corekit.sentinels\nAbsentType\nq\x00)\x81q\x01.',
    ('ABSENT', 3): b'\x80\x03cpcapkit.corekit.sentinels\nAbsentType\nq\x00)\x81q\x01.',
    ('ABSENT', 4): (b'\x80\x04\x95/\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                    b'\x94\x8c\nAbsentType\x94\x93\x94)\x81\x94.'),
    ('ABSENT', 5): (b'\x80\x05\x95/\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                    b'\x94\x8c\nAbsentType\x94\x93\x94)\x81\x94.'),
}

#: A standalone HOPOPT header carrying one MPL option whose seed is the IPv6
#: source address. Parsed with no IPv6 header around it, ``post_process`` has no
#: address to take, so the parsed schema's ``seed`` holds ``NO_VALUE``.
MPL_HEADER = bytes.fromhex('3b006d0220070000')


def _module() -> 'Any':
    """The sentinels module that is live now (GitHub issue #1332)."""
    return importlib.import_module(CANONICAL_MODULE)


def _star_import() -> 'dict[str, object]':
    """The namespace ``from pcapkit.corekit.sentinels import *`` binds."""
    namespace = {}  # type: dict[str, object]
    exec(f'from {CANONICAL_MODULE} import *', namespace)  # pylint: disable=exec-used
    return namespace


def _raised(probe: 'Callable[[], object]') -> 'type[BaseException] | None':
    """The type of the exception ``probe`` raises, or :obj:`None` if it returns."""
    try:
        probe()
    except Exception as error:  # pylint: disable=broad-except
        return type(error)
    return None


def _subclass(base: 'type') -> 'type':
    """Derive a class from ``base`` with a ``class`` statement."""
    class Derived(base):
        """A subclass of ``base``."""
    return Derived


#: ``(description, probe)``: what each probe does to a singleton ``obj``. Each is
#: run against :data:`BUILTINS` and against every sentinel, and must fail with the
#: same exception type, or succeed, alike.
PROBES = (
    ('set a new attribute', lambda obj: setattr(obj, 'x', 1)),
    ('set an existing attribute', lambda obj: setattr(obj, '__doc__', 'x')),
    ('delete a new attribute', lambda obj: delattr(obj, 'x')),
    ('delete an existing attribute', lambda obj: delattr(obj, '__doc__')),
    ('set through object.__setattr__', lambda obj: object.__setattr__(obj, 'x', 1)),
    ('read vars()', vars),
    ('set a new type attribute', lambda obj: setattr(type(obj), 'x', 1)),
    ('set an existing type attribute', lambda obj: setattr(type(obj), '__doc__', 'x')),
    ('delete a new type attribute', lambda obj: delattr(type(obj), 'x')),
    ('delete an existing type attribute', lambda obj: delattr(type(obj), '__doc__')),
    ('subclass the type', lambda obj: _subclass(type(obj))),
    ('call the type', lambda obj: type(obj)()),
)


class _ReimportCase(unittest.TestCase):
    """Base: give each test class one fresh ``pcapkit`` import."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)


class SingletonTests(_ReimportCase):
    """Each way of getting a second object hands back the first.

    Failures are collected and asserted once, so a regression confined to one
    sentinel or one protocol fails the test method itself under any runner.

    """

    def test_calling_the_type_again_returns_the_sentinel(self) -> 'None':
        module = _module()
        bad = [name for name, _, _ in SENTINELS
               if type(getattr(module, name))() is not getattr(module, name)]
        self.assertEqual(bad, [])

    def test_copy_and_deepcopy_return_the_sentinel(self) -> 'None':
        module = _module()
        bad = []
        for name, _, _ in SENTINELS:
            sentinel = getattr(module, name)
            for copier in (copy.copy, copy.deepcopy):
                if copier(sentinel) is not sentinel:
                    bad.append((name, copier.__name__))
        self.assertEqual(bad, [])

    def test_every_pickle_protocol_round_trips_to_the_sentinel(self) -> 'None':
        module = _module()
        bad = []
        for name, _, _ in SENTINELS:
            sentinel = getattr(module, name)
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                if pickle.loads(pickle.dumps(sentinel, protocol=protocol)) is not sentinel:
                    bad.append((name, protocol))
        self.assertEqual(bad, [])

    def test_repr_is_the_name_and_truth_value_is_unchanged(self) -> 'None':
        """The shared base supplies ``__repr__``; ``__bool__`` stays per sentinel.

        :func:`str` and an empty :func:`format` give the repr, as they do for
        :obj:`None`.

        """
        module = _module()
        for name, text, truth in SENTINELS:
            with self.subTest(sentinel=name):
                sentinel = getattr(module, name)
                self.assertEqual(repr(sentinel), text)
                self.assertEqual(str(sentinel), text)
                self.assertEqual(f'{sentinel}', text)
                self.assertIs(bool(sentinel), truth)

    def test_the_shared_base_is_public_and_abstract(self) -> 'None':
        """Every sentinel type derives from ``Sentinel``, which is exported and not instantiable.

        Its metaclass derives from :class:`abc.ABCMeta`, as the library's other
        abstract bases' do, and the private name it had before review is gone,
        with no alias left behind.

        """
        module = _module()
        base = module.Sentinel

        self.assertTrue(inspect.isabstract(base))
        self.assertTrue(issubclass(type(base), abc.ABCMeta))
        with self.assertRaises(TypeError):
            base()
        self.assertIn('Sentinel', module.__all__)
        self.assertIs(_star_import()['Sentinel'], base)
        self.assertFalse(hasattr(module, '_Sentinel'))
        for name, _, _ in SENTINELS:
            with self.subTest(sentinel=name):
                self.assertTrue(issubclass(type(getattr(module, name)), base))


class BuiltinParityTests(_ReimportCase):
    """A sentinel and its type behave as :obj:`None` and ``type(None)`` do.

    Run against :obj:`Ellipsis` and :obj:`NotImplemented` as well, so a probe
    whose outcome is particular to :obj:`None` cannot set the bar.

    """

    def test_every_probe_fails_or_succeeds_as_for_the_builtins(self) -> 'None':
        module = _module()
        bad = []
        for description, probe in PROBES:
            expected = {_raised(lambda: probe(obj)) for obj in BUILTINS}  # pylint: disable=cell-var-from-loop
            self.assertEqual(len(expected), 1, (description, expected))
            for name, _, _ in SENTINELS:
                got = _raised(lambda: probe(getattr(module, name)))  # pylint: disable=cell-var-from-loop
                if got not in expected:
                    bad.append((description, name, got, expected))
        self.assertEqual(bad, [])

    def test_reduce_names_the_object_as_for_ellipsis(self) -> 'None':
        """``Ellipsis.__reduce__()`` is ``'Ellipsis'``; :obj:`None` has no reduce of its own."""
        module = _module()
        self.assertEqual(Ellipsis.__reduce__(), 'Ellipsis')
        for name, _, _ in SENTINELS:
            with self.subTest(sentinel=name):
                self.assertEqual(getattr(module, name).__reduce__(), name)


class InstanceImmutabilityTests(_ReimportCase):
    """No attribute of a sentinel can be set or deleted, as for :obj:`None`."""

    def test_setting_or_deleting_any_attribute_raises_attribute_error(self) -> 'None':
        module = _module()
        for name, _, _ in SENTINELS:
            sentinel = getattr(module, name)
            for attr in ('x', '_name', '_instance', '__class__'):
                with self.subTest(sentinel=name, attr=attr):
                    with self.assertRaisesRegex(AttributeError, repr(type(sentinel).__name__)):
                        setattr(sentinel, attr, 1)
                    with self.assertRaisesRegex(AttributeError, repr(attr)):
                        delattr(sentinel, attr)
            with self.subTest(sentinel=name):
                self.assertEqual(sentinel._name, name)  # pylint: disable=protected-access
                self.assertFalse(hasattr(sentinel, 'x'))
                self.assertIs(type(sentinel)(), sentinel)

    def test_there_is_no_instance_dict_to_reach_round_the_hooks(self) -> 'None':
        """``__slots__`` is empty, so :meth:`object.__setattr__` has nowhere to write."""
        module = _module()
        for name, _, _ in SENTINELS:
            sentinel = getattr(module, name)
            with self.subTest(sentinel=name):
                self.assertFalse(hasattr(sentinel, '__dict__'))
                with self.assertRaises(AttributeError):
                    object.__setattr__(sentinel, 'x', 1)


class TypeImmutabilityTests(_ReimportCase):
    """No attribute of a sentinel type can be set or deleted, as for ``type(None)``."""

    def test_setting_or_deleting_any_type_attribute_raises_type_error(self) -> 'None':
        module = _module()
        types = [type(getattr(module, name)) for name, _, _ in SENTINELS] + [module.Sentinel]
        for type_ in types:
            for attr in ('x', '_name', '_instance', '__repr__', '__new__'):
                with self.subTest(type=type_.__name__, attr=attr):
                    message = f'{attr!r} attribute of immutable type {type_.__name__!r}'
                    with self.assertRaisesRegex(TypeError, message):
                        setattr(type_, attr, None)
                    with self.assertRaisesRegex(TypeError, message):
                        delattr(type_, attr)

    def test_a_refused_write_leaves_the_type_as_it_was(self) -> 'None':
        module = _module()
        for name, _, _ in SENTINELS:
            sentinel = getattr(module, name)
            type_ = type(sentinel)
            with self.subTest(sentinel=name):
                for attr, value in (('_name', 'x'), ('_instance', None)):
                    with self.assertRaises(TypeError):
                        setattr(type_, attr, value)
                self.assertEqual(type_._name, name)  # pylint: disable=protected-access
                self.assertIs(type_._instance, sentinel)  # pylint: disable=protected-access
                self.assertIs(type_(), sentinel)
                self.assertEqual(repr(sentinel), name)


class SubclassTests(_ReimportCase):
    """A concrete sentinel type cannot be subclassed; the abstract base can."""

    def test_a_concrete_sentinel_type_cannot_be_subclassed(self) -> 'None':
        """As ``class X(type(None))`` raises :exc:`TypeError`, so does this.

        :meth:`~abc.ABCMeta.register` is refused too: a virtual subclass would
        pass an :func:`isinstance` check against the type just as a real one
        would.

        """
        module = _module()
        for name, _, _ in SENTINELS:
            type_ = type(getattr(module, name))
            message = f'type {type_.__name__!r} is not an acceptable base type'
            with self.subTest(sentinel=name):
                with self.assertRaisesRegex(TypeError, message):
                    _subclass(type_)
                with self.assertRaisesRegex(TypeError, message):
                    type_.register(int)
                self.assertNotIsInstance(1, type_)
                self.assertIs(type_.__dict__.get('__final__'), True)

    def test_the_abstract_base_can_still_be_subclassed(self) -> 'None':
        """An abstract subclass, and a concrete one below it, are built as the library's are."""
        module = _module()

        class Abstract(module.Sentinel):
            """An abstract sentinel base."""

            __slots__ = ()

        class Concrete(Abstract):
            """A concrete sentinel."""

            __slots__ = ()

            _name = 'CONCRETE'

        class Virtual:
            """A class to register as a virtual subclass of :class:`Abstract`."""

        self.assertTrue(inspect.isabstract(Abstract))
        self.assertIs(Abstract.register(Virtual), Virtual)
        self.assertIsInstance(Virtual(), Abstract)

        instance = Concrete()
        self.assertIs(Concrete(), instance)
        self.assertIs(copy.deepcopy(instance), instance)
        self.assertEqual(repr(instance), 'CONCRETE')
        with self.assertRaises(TypeError):
            _subclass(Concrete)
        with self.assertRaises(TypeError):
            Concrete._name = 'x'  # pylint: disable=protected-access
        with self.assertRaises(AttributeError):
            instance.x = 1  # pylint: disable=attribute-defined-outside-init


class OldPickleTests(_ReimportCase):
    """A pickle written before the change still loads, as the sentinel where it can."""

    def test_every_old_pickle_still_loads(self) -> 'None':
        module = _module()
        for (name, protocol), blob in OLD_PICKLES.items():
            if protocol > pickle.HIGHEST_PROTOCOL:  # pragma: no cover
                continue
            with self.subTest(sentinel=name, protocol=protocol):
                self.assertIsInstance(pickle.loads(blob), type(getattr(module, name)))

    def test_an_old_pickle_loads_as_the_sentinel(self) -> 'None':
        """``NULL`` at every protocol, the others from protocol 2 on.

        ``NULL``'s old pickles call ``_get_null``, which the module keeps for them.
        The others' old pickles from protocol 2 on rebuild through
        ``cls.__new__(cls)``, which the shared base guards.

        """
        module = _module()
        bad = []
        for (name, protocol), blob in OLD_PICKLES.items():
            if protocol > pickle.HIGHEST_PROTOCOL:  # pragma: no cover
                continue
            if name != 'NULL' and protocol < 2:
                continue
            if pickle.loads(blob) is not getattr(module, name):
                bad.append((name, protocol))
        self.assertEqual(bad, [])

    def test_an_old_default_reduce_below_protocol_2_cannot(self) -> 'None':
        """Pinned so the documented limit stays true.

        Below protocol 2 the default reduce rebuilds through
        :func:`copyreg._reconstructor`, which calls :meth:`object.__new__`
        directly. No hook on the class runs, so these load as a second instance.
        Pickles written after the change reduce to the object's own name instead.

        """
        module = _module()
        for name in ('NO_VALUE', 'NO_DEFAULT', 'ABSENT'):
            for protocol in (0, 1):
                with self.subTest(sentinel=name, protocol=protocol):
                    self.assertIsNot(pickle.loads(OLD_PICKLES[name, protocol]),
                                     getattr(module, name))


class RealObjectTests(_ReimportCase):
    """The objects #1842 measured, which hold ``NO_VALUE`` in practice."""

    def test_a_parsed_mpl_seed_keeps_its_identity(self) -> 'None':
        from pcapkit.protocols.internet.hopopt import HOPOPT

        no_value = _module().NO_VALUE
        schema = HOPOPT(MPL_HEADER, len(MPL_HEADER), extension=True).schema
        self.assertIs(schema.options[0].seed, no_value)

        bad = []
        if copy.deepcopy(schema).options[0].seed is not no_value:
            bad.append('deepcopy')
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            if pickle.loads(pickle.dumps(schema, protocol=protocol)).options[0].seed is not no_value:
                bad.append(protocol)
        self.assertEqual(bad, [])

    def test_a_deep_copied_field_keeps_its_default(self) -> 'None':
        from pcapkit.corekit.fields.strings import BytesField

        no_value = _module().NO_VALUE
        self.assertIs(copy.deepcopy(BytesField(length=4)).default, no_value)


if __name__ == '__main__':
    unittest.main()
