# -*- coding: utf-8 -*-
"""A :func:`~collections.namedtuple` subclass never shares its base's name.

GitHub issue #1843: :class:`~pcapkit.corekit.version.VersionInfo`,
:class:`~pcapkit.corekit.module.ModuleDescriptor`,
:class:`~pcapkit.protocols.internet.mh.NTPTimestamp` and
:class:`~pcapkit.protocols.internet.mh.PMIPv6Timestamp` each subclassed a
generated namedtuple carrying the class's own name and module. Sphinx renders a
base as ``module.qualname``, so each page's ``Bases:`` line linked the class to
itself. The generated bases now carry names of their own.

Renaming the base changes nothing a caller sees: :func:`repr` and :mod:`pickle`
name the subclass, not the base. :class:`TestNamedTupleBehaviourKept` guards
that; it passes with or without the fix.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, for the reason given in
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit`.

"""

import copy
import importlib
import pickle
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Tuple

#: Each class under test, as ``(module, name, sample field values)``.
CASES = {
    'VersionInfo': ('pcapkit.corekit.version', 'VersionInfo', (2, 4)),
    'ModuleDescriptor': ('pcapkit.corekit.module', 'ModuleDescriptor',
                         ('pcapkit.protocols.misc.raw', 'Raw')),
    'NTPTimestamp': ('pcapkit.protocols.internet.mh', 'NTPTimestamp',
                     (3913056000, 2147483648)),
    'PMIPv6Timestamp': ('pcapkit.protocols.internet.mh', 'PMIPv6Timestamp',
                        (1700000000, 32768)),
}


def _load(label: 'str') -> 'Tuple[type, Tuple[Any, ...]]':
    module, name, values = CASES[label]
    return getattr(importlib.import_module(module), name), values


class TestNamedTupleBaseName(unittest.TestCase):
    """The direct namedtuple base is not named as the class itself."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assert_base_named_apart(self, label: 'str') -> None:
        cls, _ = _load(label)
        base = cls.__bases__[0]
        # The generated namedtuple itself, not some other tuple ancestor.
        self.assertTrue(issubclass(base, tuple), base)
        self.assertIn('_fields', vars(base), base)

        self.assertNotEqual(base.__name__, cls.__name__)
        self.assertNotEqual(f'{base.__module__}.{base.__qualname__}',
                            f'{cls.__module__}.{cls.__qualname__}',
                            'Bases: would link the class to itself')

    def test_version_info(self) -> None:
        self.assert_base_named_apart('VersionInfo')

    def test_module_descriptor(self) -> None:
        self.assert_base_named_apart('ModuleDescriptor')

    def test_ntp_timestamp(self) -> None:
        self.assert_base_named_apart('NTPTimestamp')

    def test_pmipv6_timestamp(self) -> None:
        self.assert_base_named_apart('PMIPv6Timestamp')


class TestNamedTupleBehaviourKept(unittest.TestCase):
    """What a caller sees names the subclass, whatever the base is called."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_repr_names_the_subclass(self) -> None:
        reprs = {}
        expected = {}
        for label in CASES:
            cls, values = _load(label)
            obj = cls(*values)
            fields = ', '.join(f'{field}={value!r}' for field, value in zip(obj._fields, values))
            reprs[label] = repr(obj)
            expected[label] = f'{cls.__name__}({fields})'
        self.assertEqual(reprs, expected)

    def test_copy_and_pickle_round_trip_to_the_subclass(self) -> None:
        failures = []
        for label in CASES:
            cls, values = _load(label)
            obj = cls(*values)
            clones = {'copy.deepcopy': copy.deepcopy(obj), '_make': cls._make(values)}
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                clones[f'pickle protocol {protocol}'] = pickle.loads(pickle.dumps(obj, protocol=protocol))
            for path, clone in clones.items():
                if type(clone) is not cls or clone != obj:
                    failures.append(f'{label} via {path}: {clone!r}')
        # Asserted once, outside any subTest, so a single bad path fails the test itself.
        self.assertEqual(failures, [])


if __name__ == '__main__':
    unittest.main()
