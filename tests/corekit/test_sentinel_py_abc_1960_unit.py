# -*- coding: utf-8 -*-
"""GitHub issue #1960: a sentinel type answers :func:`isinstance` under ``_py_abc``.

Where the C ``_abc`` module is missing, as on GraalPy, :mod:`abc` falls back to
``_py_abc``, whose ``__subclasscheck__`` rebinds ``_abc_negative_cache`` and
``_abc_negative_cache_version`` on the class once any ABC has registered a
virtual subclass since the class was built. Without the fix,
:class:`~pcapkit.corekit.sentinels.SentinelMeta` refuses every write to a built
sentinel type, so ``isinstance(1, NullType)`` raises :exc:`TypeError` there.
:class:`~pcapkit.corekit.sentinels.SentinelMeta` lets those two names through,
and no other.

:class:`PyABCFallbackTests` runs the checks in a child interpreter that really
takes the fallback. It starts with ``-S``, so that no module but :mod:`io` has
imported :mod:`abc` yet, drops both from :data:`sys.modules`, blocks ``_abc``
(except on GraalPy, which takes the fallback unaided, #1963), and imports
them again. The child reports whether :class:`abc.ABCMeta` is
``_py_abc``'s and whether ``_collections_abc`` was already loaded, rather than
trusting the block. :class:`CModuleTests` pins that, under the C module, the
names let through for ``_py_abc`` are still refused.

Neither runs on PyPy (#1958). Its built-in ``_abc`` keeps ``_py_abc``'s caches
on the class, so a sentinel type there holds both names, and it imports
``_collections_abc`` at startup even under ``-S``, so a child that blocks
``_abc`` builds :mod:`abc` anew under ABCs already made with the old one, and
``import pcapkit`` fails with a metaclass conflict.

"""

from __future__ import annotations

import _py_abc
import abc
import importlib
import json
import os
import subprocess  # nosec B404
import sys
import textwrap
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises metaclass, ABC or enum machinery, which differs by
#: interpreter.
__tier__ = 'ALL'

#: PyPy's ``_abc`` is no C module and keeps the caches on the class (#1958).
ON_PYPY = sys.implementation.name == 'pypy'
#: Why both classes skip there.
PYPY_REASON = "PyPy's built-in _abc keeps _py_abc's caches on the class, and the fallback cannot be forced"

#: Repository root, put first on the child interpreter's path so that it
#: imports this tree rather than whatever :mod:`pcapkit` is installed.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: Every sentinel type, the abstract base first, and the module-level name of
#: each concrete one's instance.
TYPES = (
    ('Sentinel', None),
    ('NullType', 'NULL'),
    ('NoValueType', 'NO_VALUE'),
    ('NoDefaultType', 'NO_DEFAULT'),
    ('AbsentType', 'ABSENT'),
    ('MissingType', 'MISSING'),
)

#: Run in the child. It prints one JSON object: whether the fallback was taken,
#: and for each sentinel type the outcome of every probe, as the ``repr`` of
#: what it returned or the name of the exception it raised.
CHILD = textwrap.dedent('''
    import sys

    preloaded = sorted(name for name in ('abc', 'io', '_collections_abc') if name in sys.modules)
    for name in ('abc', 'io'):
        sys.modules.pop(name, None)
    # GraalPy's ``_abc`` holds only the two helpers its own ``_py_abc`` imports,
    # so :mod:`abc` takes the fallback there unaided, and blocking ``_abc``
    # would break ``_py_abc`` too (#1963).
    if sys.implementation.name != 'graalpy':
        sys.modules['_abc'] = None

    import abc
    import io  # noqa: F401  # rebuilt on the fallback before anything uses it
    import json
    import _py_abc

    import pcapkit
    from pcapkit.corekit import sentinels

    class Probe(abc.ABC):
        """An ABC whose registrations invalidate every ``_py_abc`` negative cache."""

    def bump():
        """Register a fresh virtual subclass, so the next check rebinds the cache."""
        Probe.register(type('Virtual', (), {}))

    def outcome(probe):
        try:
            return repr(probe())
        except Exception as error:
            return type(error).__name__

    report = {
        'preloaded': preloaded,
        'fallback': abc.ABCMeta is _py_abc.ABCMeta,
        'metaclass_base': sentinels.SentinelMeta.__mro__[1] is _py_abc.ABCMeta,
        'file': pcapkit.__file__,
        'types': {},
    }
    for name, instance_name in json.loads(sys.argv[1]):
        type_ = getattr(sentinels, name)
        instance = None if instance_name is None else getattr(sentinels, instance_name)
        probes = report['types'][name] = {}
        bump()
        probes['isinstance(1)'] = outcome(lambda: isinstance(1, type_))
        bump()
        probes['issubclass(int)'] = outcome(lambda: issubclass(int, type_))
        bump()
        probes['isinstance(instance)'] = outcome(lambda: isinstance(instance, type_))
        probes['isinstance(instance, Sentinel)'] = outcome(
            lambda: isinstance(instance, sentinels.Sentinel))
        probes['register(int)'] = outcome(lambda: type_.register(int))
        for attr in ('x', '_name', '_instance', '_abc_cache', '_abc_registry'):
            probes['set ' + attr] = outcome(lambda: setattr(type_, attr, None))
        for attr in ('x', '_abc_negative_cache', '_abc_negative_cache_version'):
            probes['delete ' + attr] = outcome(lambda: delattr(type_, attr))
        if instance is not None:
            probes['_name'] = outcome(lambda: type_.__dict__['_name'])
    print(json.dumps(report))
''')


def _expected(instance_name: 'str | None') -> 'dict[str, str]':
    """The outcome of every probe :data:`CHILD` runs against a sentinel type.

    Args:
        instance_name: Module-level name of the type's one instance, or
            :obj:`None` for the abstract base.

    """
    concrete = instance_name is not None
    probes = {
        'isinstance(1)': 'False',
        'issubclass(int)': 'False',
        'isinstance(instance)': repr(concrete),
        'isinstance(instance, Sentinel)': repr(concrete),
        # Only a concrete type refuses; the abstract base registers ``int``,
        # after every check against it has run.
        'register(int)': 'TypeError' if concrete else repr(int),
    }
    if concrete:
        probes['_name'] = repr(instance_name)
    for attr in ('x', '_name', '_instance', '_abc_cache', '_abc_registry'):
        probes['set ' + attr] = 'TypeError'
    for attr in ('x', '_abc_negative_cache', '_abc_negative_cache_version'):
        probes['delete ' + attr] = 'TypeError'
    return probes


@unittest.skipIf(ON_PYPY, PYPY_REASON)
class PyABCFallbackTests(unittest.TestCase):
    """Every sentinel type behaves under ``_py_abc`` as it does under ``_abc``."""

    report = {}  # type: dict

    @classmethod
    def setUpClass(cls) -> 'None':
        path = [REPO_ROOT] + [entry for entry in sys.path if entry]
        env = dict(os.environ, PCAPKIT_DEVMODE='0', PYTHONSAFEPATH='1',
                   PYTHONPATH=os.pathsep.join(path))
        proc = subprocess.run([sys.executable, '-S', '-c', CHILD, json.dumps(TYPES)],  # nosec B603
                              cwd=REPO_ROOT, env=env, capture_output=True, text=True,
                              timeout=120, check=False)
        if proc.returncode != 0:
            raise AssertionError(f'child interpreter failed:\n{proc.stderr}')
        cls.report = json.loads(proc.stdout.strip().splitlines()[-1])

    def test_the_child_really_takes_the_fallback(self) -> 'None':
        """:mod:`abc` is ``_py_abc``'s, and nothing else had imported it at startup."""
        self.assertTrue(self.report['fallback'], 'abc.ABCMeta is not _py_abc.ABCMeta')
        self.assertTrue(self.report['metaclass_base'], 'SentinelMeta is not built on _py_abc')
        self.assertNotIn('_collections_abc', self.report['preloaded'])
        self.assertTrue(self.report['file'].startswith(REPO_ROOT), self.report['file'])

    def test_every_probe_behaves_as_under_the_c_module(self) -> 'None':
        """Each check answers as it should, and every other write is still refused."""
        for name, instance_name in TYPES:
            expected = _expected(instance_name)
            actual = self.report['types'][name]
            with self.subTest(type=name):
                self.assertEqual(sorted(actual), sorted(expected))
            for probe, outcome in expected.items():
                with self.subTest(type=name, probe=probe):
                    self.assertEqual(actual[probe], outcome)


@unittest.skipIf(ON_PYPY, PYPY_REASON)
class CModuleTests(unittest.TestCase):
    """Under the C ``_abc`` module, the names let through for ``_py_abc`` stay refused."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def test_the_py_abc_cache_names_are_refused_where_the_type_lacks_them(self) -> 'None':
        """Neither ``_abc_negative_cache`` nor its version can be set on a type that lacks it."""
        sentinels = importlib.import_module('pcapkit.corekit.sentinels')
        if abc.ABCMeta is _py_abc.ABCMeta:
            self.skipTest('abc is the _py_abc fallback here; PyABCFallbackTests covers it')
        for name, _ in TYPES:
            type_ = getattr(sentinels, name)
            for attr in ('_abc_negative_cache', '_abc_negative_cache_version'):
                with self.subTest(type=name, attr=attr):
                    self.assertNotIn(attr, type_.__dict__)
                    message = f'{attr!r} attribute of immutable type {name!r}'
                    with self.assertRaisesRegex(TypeError, message):
                        setattr(type_, attr, None)
                    self.assertNotIn(attr, type_.__dict__)


if __name__ == '__main__':
    unittest.main()
