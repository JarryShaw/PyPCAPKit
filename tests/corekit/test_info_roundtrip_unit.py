# -*- coding: utf-8 -*-
"""Every :class:`~pcapkit.corekit.infoclass.Info` survives ``to_dict``/``from_dict``. C.f. #1202.

The documented inverse of :meth:`Info.to_dict
<pcapkit.corekit.infoclass.Info.to_dict>` is :meth:`Info.from_dict
<pcapkit.corekit.infoclass.Info.from_dict>`: nested values annotated with an
:class:`Info` subclass are rebuilt into it, and a key held more than once keeps
every value (#1466). For every :class:`Info` subclass the library defines -- the
``Data_*`` models of :mod:`pcapkit.protocols.data`, the reassembly and
traceflow models, and the rest -- an instance is synthesised from its
annotations and must come back:

* equal, with the same ``to_dict()``, the same ``items(multi=True)``, and every
  nested value of the same :class:`Info` class (``plain``);
* with a key repeated through an
  :class:`~pcapkit.corekit.multidict.OrderedMultiDict` still repeated (``multi``);
* with the bookkeeping keys the parsers attach carried through: every
  :class:`~pcapkit.protocols.data.data.Data` with ``__short_read__`` (#1465), every
  PCAP-NG block with ``__truncated_raw__`` (#1475).

``to_dict()`` must also be an :class:`~pcapkit.corekit.multidict.InfoDict` at
every level. :class:`InfoMechanicsTests` covers the shapes a synthesised
instance does not: a key renamed because it shadows a method, ``Optional``
nesting, and repeated nested values.

A failing case is a defect and goes in ``KNOWN_FAILURES`` (see
:mod:`tests.corekit._roundtrip`). Nothing imports :mod:`pcapkit` at module
level. The module has no ``from __future__ import annotations``, so the models
:class:`InfoMechanicsTests` declares carry real annotations that
:meth:`~pcapkit.corekit.infoclass.Info.from_dict` can resolve.

"""

import importlib
import inspect
import pkgutil
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.corekit._roundtrip import (OK, KnownFailureTable, Outcome, describe, run,
                                      skip_without_runtime)

if TYPE_CHECKING:
    from typing import Any

#: Packages whose modules define :class:`Info` subclasses but are not imported by
#: ``import pcapkit`` alone.
PACKAGES = ('pcapkit.protocols.data', 'pcapkit.foundation.reassembly.data',
            'pcapkit.foundation.traceflow.data')

#: Values a model's ``__post_init__`` needs in a shape no marker has, by label;
#: each is a callable, so it is built against the current import.
VALUES = {
    'protocols.data.misc.pcapng:NameResolutionBlock': {
        'records': lambda: importlib.import_module('pcapkit.corekit.multidict').OrderedMultiDict(),
    },
}

#: Nesting depth past which a nested value is a marker rather than an instance;
#: some models are recursive.
MAX_DEPTH = 3


def info_classes() -> 'dict[str, type]':
    """Every :class:`Info` subclass defined under :mod:`pcapkit`, by label."""
    from pcapkit.corekit.infoclass import Info

    for package in PACKAGES:
        module = importlib.import_module(package)
        for info in pkgutil.walk_packages(module.__path__, f'{package}.'):
            importlib.import_module(info.name)

    found = {}  # type: dict[str, type]
    stack = [Info]
    while stack:
        current = stack.pop()
        for sub in current.__subclasses__():
            if sub.__module__.startswith('pcapkit.'):
                found[f'{sub.__module__.replace("pcapkit.", "", 1)}:{sub.__qualname__}'] = sub
            stack.append(sub)
    return found


def annotated_keys(cls: 'type') -> 'list[str]':
    """The keys :func:`~pcapkit.corekit.infoclass.info_final` builds ``__init__`` from."""
    from pcapkit.corekit.infoclass import Info

    keys = []  # type: list[str]
    for base in reversed(cls.__mro__):
        if base is Info or not issubclass(base, Info):
            continue
        # The same lookup info_final makes; on Python 3.14 a class's own
        # annotations are no longer stored in its ``__dict__``.
        for key in base.__dict__.get('__annotations__', getattr(base, '__annotations__', {})):
            if key not in keys and not key.startswith('__'):
                keys.append(key)
    return keys


def synthesise(cls: 'type', depth: 'int' = 0) -> 'Any':
    """An instance of ``cls``: a marker per key, a nested instance per nested key."""
    from pcapkit.corekit.infoclass import _nested_info_types

    nested = _nested_info_types(cls)
    preset = VALUES.get(f'{cls.__module__.replace("pcapkit.", "", 1)}:{cls.__qualname__}', {})
    values = {}  # type: dict[str, Any]
    for key in annotated_keys(cls):
        if key in preset:
            values[key] = preset[key]()
        elif key in nested and depth < MAX_DEPTH:
            values[key] = synthesise(nested[key], depth + 1)
        else:
            values[key] = f'{cls.__qualname__}.{key}'
    # The generated ``__init__`` takes the annotated keys as parameters, but a
    # model may annotate a key no parameter can be named -- IPv4's
    # ``OptionType`` injects ``class`` -- and is then built through
    # ``from_dict`` as the parsers build it.
    params = inspect.signature(cls.__init__).parameters
    if cls.__dict__.get('__final__') and all(key in params for key in values):
        return cls(**values)
    return cls.from_dict(values)


def _structure(info: 'Any') -> 'Any':
    """The class of ``info`` and of every nested :class:`Info`, recursively."""
    from pcapkit.corekit.infoclass import Info

    return (type(info).__qualname__,
            tuple((key, _structure(value) if isinstance(value, Info) else type(value).__qualname__)
                  for key, value in info.items(multi=True)))


def _plain_dicts(value: 'Any', path: 'str' = '') -> 'list[str]':
    """Paths in a ``to_dict()`` result of every mapping that should be an InfoDict.

    A nested :class:`Info` exports as an InfoDict. A
    :class:`~pcapkit.corekit.multidict.MultiDict` held as a field value -- a
    PCAP-NG block's ``records``, say -- is a value, not an export, and is kept.

    """
    from pcapkit.corekit.multidict import InfoDict, MultiDict

    if not isinstance(value, InfoDict):
        return [f'{path or "<top>"}: {type(value).__module__}.{type(value).__qualname__}']
    found = []  # type: list[str]
    for key, item in value.items(multi=True):
        if isinstance(item, InfoDict) or (isinstance(item, dict) and not isinstance(item, MultiDict)):
            found.extend(_plain_dicts(item, f'{path}.{key}'))
    return found


def check(info: 'Any') -> 'Outcome':
    """``from_dict(to_dict())`` reproduces ``info`` in every respect listed above."""
    try:
        exported = info.to_dict()
    except Exception as exc:  # pylint: disable=broad-except
        return Outcome('TO_DICT', describe(exc))
    plain = _plain_dicts(exported)
    if plain:
        return Outcome('TO_DICT', f'not an InfoDict: {plain}')
    try:
        rebuilt = type(info).from_dict(exported)
    except Exception as exc:  # pylint: disable=broad-except
        return Outcome('FROM_DICT', describe(exc))
    if rebuilt != info:
        return Outcome('EQUAL', f'{rebuilt!r} != {info!r}')
    if list(rebuilt.items(multi=True)) != list(info.items(multi=True)):
        return Outcome('MULTI', f'{list(rebuilt.items(multi=True))!r} != {list(info.items(multi=True))!r}')
    if _structure(rebuilt) != _structure(info):
        return Outcome('TYPE', f'{_structure(rebuilt)!r} != {_structure(info)!r}')
    if rebuilt.to_dict() != exported or list(rebuilt.to_dict().items(multi=True)) != list(exported.items(multi=True)):
        return Outcome('TO_DICT', 'to_dict() of the rebuilt instance differs')
    return OK


def _with(info: 'Any', key: 'str', value: 'Any', repeat: 'bool' = False) -> 'Any':
    """``info`` rebuilt with ``key`` set to ``value``, or added again if ``repeat``."""
    from pcapkit.corekit.multidict import OrderedMultiDict

    items = OrderedMultiDict()  # type: OrderedMultiDict[str, Any]
    for name, item in info.to_dict().items(multi=True):
        items.add(name, item)
    items.add(key, value)
    if not repeat:
        return type(info).from_dict(list(items.items(multi=True)))
    return type(info).from_dict(items)


def run_case(cls: 'type', variant: 'str') -> 'Outcome':
    """Synthesise ``cls`` and check ``variant`` of it."""
    from pcapkit.corekit.infoclass import _nested_info_types

    try:
        info = synthesise(cls)
    except Exception as exc:  # pylint: disable=broad-except
        return Outcome('BUILD', describe(exc))
    try:
        if variant == 'multi':
            keys = annotated_keys(cls)
            nested = _nested_info_types(cls)
            key = next((key for key in keys if key in nested), keys[0])
            again = synthesise(nested[key], 1) if key in nested else f'{cls.__qualname__}.{key}.again'
            info = _with(info, key, again, repeat=True)
            if len(info.to_dict().getlist(key)) != 2:
                return Outcome('MULTI', f'{key!r} holds {info.to_dict().getlist(key)!r}')
        elif variant == 'short-read':
            info = _with(info, '__short_read__', (annotated_keys(cls)[0], 1))
            if info.to_dict().get('__short_read__') != (annotated_keys(cls)[0], 1):
                return Outcome('TO_DICT', '__short_read__ is not carried by to_dict()')
        elif variant == 'truncated-raw':
            info = _with(info, '__truncated_raw__', b'\x0a\x0d\x0d')
            if info.to_dict().get('__truncated_raw__') != b'\x0a\x0d\x0d':
                return Outcome('TO_DICT', '__truncated_raw__ is not carried by to_dict()')
    except Exception as exc:  # pylint: disable=broad-except
        return Outcome('BUILD', describe(exc))
    return check(info)


class InfoRoundTripTests(KnownFailureTable, unittest.TestCase):
    """``Info.from_dict(info.to_dict())`` for every :class:`Info` subclass."""

    STATUSES = ('OK', 'BUILD', 'TO_DICT', 'FROM_DICT', 'EQUAL', 'MULTI', 'TYPE', 'TIMEOUT')

    KNOWN_FAILURES = ()

    def setUp(self) -> None:
        skip_without_runtime(self)
        reimport_once_per_class(self)

    def _cases(self) -> 'dict[str, tuple[type, str]]':
        from pcapkit.protocols.data.data import Data
        from pcapkit.protocols.data.misc.pcapng import PCAPNG

        cases = {}  # type: dict[str, tuple[type, str]]
        for label, cls in info_classes().items():
            if not annotated_keys(cls):
                continue
            variants = ['plain', 'multi']
            if issubclass(cls, Data):
                variants.append('short-read')
            if issubclass(cls, PCAPNG):
                variants.append('truncated-raw')
            for variant in variants:
                cases[f'{label}/{variant}'] = (cls, variant)
        return cases

    def test_tables_name_real_cases(self) -> None:
        self.check_table(self._cases())

    def test_the_census_covers_the_data_models(self) -> None:
        """The census reaches the protocol models, and every keyed class is a case."""
        classes = info_classes()
        keyed = {label for label, cls in classes.items() if annotated_keys(cls)}
        covered = {label.rsplit('/', 1)[0] for label in self._cases()}
        self.assertEqual(keyed, covered)
        self.assertGreater(sum(label.startswith('protocols.data.') for label in keyed), 400)

    def test_from_dict_of_to_dict_reproduces_the_instance(self) -> None:
        cases = self._cases()
        gaps = self.gap_table(cases)
        for label, (cls, variant) in sorted(cases.items()):
            with self.subTest(case=label):
                self.check_outcome(label, run(run_case, cls, variant), gaps)


class InfoMechanicsTests(unittest.TestCase):
    """The :class:`Info` shapes the synthesised census cannot produce."""

    def setUp(self) -> None:
        skip_without_runtime(self)
        reimport_once_per_class(self)

    def _classes(self) -> 'tuple[type, type]':
        from typing import Optional

        from pcapkit.corekit.infoclass import Info, info_final

        @info_final
        class Leaf(Info):
            """A nested model."""

            x: int

        @info_final
        class Node(Info):
            """Nested, optional, renamed and plain keys together."""

            leaf: Leaf
            maybe: Optional[Leaf]
            items: int
            keys: str
            plain: bytes

        return Leaf, Node

    def test_renamed_optional_and_nested_keys(self) -> None:
        Leaf, Node = self._classes()
        for maybe in (Leaf(x=2), None):
            with self.subTest(maybe=maybe):
                info = Node(leaf=Leaf(x=1), maybe=maybe, items=3, keys='k', plain=b'\x00\xff')
                self.assertEqual(check(info), OK)
                rebuilt = Node.from_dict(info.to_dict())
                self.assertEqual(rebuilt['items'], 3)
                self.assertEqual(list(rebuilt), ['leaf', 'maybe', 'items', 'keys', 'plain'])

    def test_repeated_nested_values_stay_nested_and_ordered(self) -> None:
        """#1466: every value of a repeated key, in order, rebuilt into its class."""
        from pcapkit.corekit.multidict import OrderedMultiDict

        Leaf, Node = self._classes()
        source = OrderedMultiDict()  # type: OrderedMultiDict[str, Any]
        for key, value in (('leaf', {'x': 1}), ('maybe', None), ('items', 3), ('leaf', {'x': 2}),
                           ('keys', 'k'), ('leaf', {'x': 3}), ('plain', b'')):
            source.add(key, value)
        info = Node.from_dict(source)
        leaves = [value for key, value in info.items(multi=True) if key == 'leaf']
        self.assertEqual([type(leaf) for leaf in leaves], [Leaf] * 3)
        self.assertEqual([leaf.x for leaf in leaves], [1, 2, 3])
        self.assertEqual([leaf['x'] for leaf in info.to_dict().getlist('leaf')], [1, 2, 3])
        self.assertEqual(check(info), OK)

    def test_an_intermediate_model_after_its_parent(self) -> None:
        """#1490: a non-final model built after its non-final parent is finalised too."""
        from pcapkit.corekit.infoclass import Info

        class Parent(Info):
            """A non-final model."""

            a: int

        class Child(Parent):
            """A non-final model under it."""

            b: int

        Parent.from_dict({'a': 1})
        child = Child.from_dict({'a': 1, 'b': 2})
        self.assertEqual(list(Parent.from_dict({'a': 1}).to_dict()), ['a'])
        self.assertEqual(list(child.to_dict()), ['a', 'b'])
        self.assertEqual((len(child), list(child)), (2, ['a', 'b']))

    def test_bookkeeping_keys_survive_a_second_round(self) -> None:
        """#1465 and #1475: the dunder keys survive ``to_dict`` -> ``from_dict`` twice."""
        _, Node = self._classes()
        info = Node.from_dict({'leaf': {'x': 1}, 'maybe': None, 'items': 0, 'keys': '', 'plain': b'',
                               '__short_read__': ('plain', 0), '__truncated_raw__': b'\x01'})
        twice = Node.from_dict(Node.from_dict(info.to_dict()).to_dict())
        self.assertEqual(twice.to_dict()['__short_read__'], ('plain', 0))
        self.assertEqual(twice.to_dict()['__truncated_raw__'], b'\x01')
        self.assertEqual(check(info), OK)


if __name__ == '__main__':
    unittest.main()
