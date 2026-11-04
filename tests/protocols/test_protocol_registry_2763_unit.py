# -*- coding: utf-8 -*-
"""``ProtocolBase.__registry__``, the by-name protocol registry (GitHub issue #2763).

The module-level dict ``pcapkit.protocols.__proto__`` is gone, with no alias. The
registry is a class-level map on :class:`~pcapkit.protocols.protocol.ProtocolBase`,
from an upper-cased class name to the class, read with ``get_protocol`` and written
with ``register_protocol``:

* :class:`ShippedEntriesTests` is the guard: every shipped protocol class has its
  entry, a :class:`~pcapkit.corekit.module.ModuleDescriptor` naming its own module
  and class, and no entry names anything else.
* :class:`AutoRegistrationTests` pins what defining a subclass does: a concrete
  :class:`~pcapkit.protocols.protocol.Protocol` subclass names itself, an abstract
  one does not, nor does a class deriving ``ProtocolBase`` alone, as every built-in
  does; a clash keeps the entry and warns, a class meeting its own descriptor is
  silent, and only ``register_protocol`` replaces an entry, putting a built-in's
  descriptor back as shipped.
* :class:`GetterTests` pins the lookup and the removal of the module dict.
* :class:`RegistryViewTests` pins ``AnyProtocol.registry``, the read-only view of the
  entries as stored.
* :class:`ColdProcessTests` runs in a fresh interpreter, since this one imported
  everything long ago: the view and the map import nothing, the getter imports a
  class only when it resolves its entry, a reloaded built-in is followed silently,
  and threads racing on a first resolution all get the one class.

"""

import importlib
import inspect
import json
import os
import pathlib
import pkgutil
import subprocess
import sys
import textwrap
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises ABC machinery, threads and the import system, which
#: differ by interpreter.
__tier__ = 'ALL'

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _import_protocols() -> 'None':
    """Import every shipped protocol module, so every class is a subclass by now."""
    import pcapkit.protocols as package

    for info in pkgutil.walk_packages(package.__path__, 'pcapkit.protocols.'):
        if 'NotImplemented' not in info.name:
            importlib.import_module(info.name)


def _shipped_classes() -> 'set[type]':
    """Every protocol class :mod:`pcapkit.protocols` exports, and every concrete one it defines."""
    import pcapkit.protocols
    from pcapkit.protocols.protocol import ProtocolBase

    _import_protocols()
    found = {value for value in (getattr(pcapkit.protocols, name) for name in pcapkit.protocols.__all__)
             if isinstance(value, type) and issubclass(value, ProtocolBase)}
    pending, seen = [ProtocolBase], set()  # type: list[type], set[type]
    while pending:
        klass = pending.pop()
        if klass in seen:
            continue
        seen.add(klass)
        pending.extend(klass.__subclasses__())
        if klass.__module__.startswith('pcapkit.protocols.') and not inspect.isabstract(klass):
            found.add(klass)
    return found


def _registry_warnings(caught: 'list[warnings.WarningMessage]') -> 'list[str]':
    from pcapkit.utilities.warnings import RegistryWarning

    return [str(item.message) for item in caught if issubclass(item.category, RegistryWarning)]


def _concrete(name: 'str', base: 'Any' = None, module: 'str' = __name__, **keywords: 'Any') -> 'Any':
    """A concrete protocol class named ``name`` in ``module``, defined with the class ``keywords``."""
    if base is None:
        from pcapkit.protocols.protocol import Protocol as base

    def read(self, length=None, **kwargs):  # type: ignore[no-untyped-def]
        return None

    def make(self, **kwargs):  # type: ignore[no-untyped-def]
        return None

    def index(cls):  # type: ignore[no-untyped-def]
        return None

    body = {'__module__': module, 'name': name, 'length': 0, 'read': read, 'make': make,
            '__index__': classmethod(index)}
    return type(name, (base,), body, **keywords)


class _RegistryTestCase(unittest.TestCase):
    """Imports :mod:`pcapkit` once per class, and puts the registry back after each test."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)
        from pcapkit.protocols.protocol import ProtocolBase

        registry = ProtocolBase.__registry__
        saved = dict(registry)

        def restore() -> 'None':
            registry.clear()
            registry.update(saved)

        self.addCleanup(restore)
        self.ProtocolBase = ProtocolBase
        self.registry = registry


class ShippedEntriesTests(_RegistryTestCase):
    """The guard: each shipped protocol class has an entry naming it, and nothing else does."""

    def test_every_shipped_protocol_class_has_its_entry(self) -> 'None':
        shipped = _shipped_classes()
        self.assertIn(self.ProtocolBase.get_protocol('IPv4'), shipped)  # the walk still finds them
        for klass in sorted(shipped, key=lambda klass: klass.__name__):
            with self.subTest(protocol=f'{klass.__module__}.{klass.__qualname__}'):
                entry = self.ProtocolBase._shipped_registry.get(klass.__name__.upper())
                self.assertIsNotNone(entry, 'a shipped protocol class has no __registry__ entry')
                self.assertEqual(entry, (klass.__module__, klass.__name__),
                                 'the entry names another module or class')

    def test_no_entry_names_anything_but_a_shipped_class(self) -> 'None':
        from pcapkit.corekit.module import ModuleDescriptor

        names = {klass.__name__.upper() for klass in _shipped_classes()}
        self.assertEqual(sorted(set(self.ProtocolBase._shipped_registry) - names), [])
        for key, entry in self.ProtocolBase._shipped_registry.items():
            with self.subTest(key=key):
                self.assertIsInstance(entry, ModuleDescriptor)
                klass = entry.klass
                self.assertEqual((klass.__module__, klass.__name__.upper()), (entry.module, key))
                self.assertTrue(issubclass(klass, self.ProtocolBase))

    def test_the_map_starts_as_shipped(self) -> 'None':
        """Each built-in entry is the very descriptor shipped, and stays one once its class is imported."""
        _import_protocols()
        shipped = self.ProtocolBase._shipped_registry
        self.assertTrue(shipped)
        for key, entry in shipped.items():
            with self.subTest(key=key):
                self.assertIs(self.registry[key], entry)


class AutoRegistrationTests(_RegistryTestCase):
    """What defining a subclass does to the registry."""

    def test_a_concrete_protocol_subclass_names_itself(self) -> 'None':
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            klass = _concrete('W2763Fresh')
        self.assertIs(self.registry['W2763FRESH'], klass)
        self.assertIs(self.ProtocolBase.get_protocol('w2763fresh'), klass)
        self.assertEqual(_registry_warnings(caught), [])

    def test_a_class_deriving_the_internal_base_alone_is_not_named(self) -> 'None':
        """Only the public base registers: a built-in's subclass is named by nothing, clashing or not."""
        from pcapkit.protocols.application.application import Application
        from pcapkit.protocols.misc.raw.protocol import Raw

        before = dict(self.registry)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            classes = [type('W2763Raw', (Raw,), {'__module__': __name__}),
                       _concrete('W2763App', base=Application),
                       type('IPv4', (Raw,), {'__module__': __name__})]
        for klass in classes:
            with self.subTest(base=klass.__mro__[1].__name__, name=klass.__name__):
                self.assertFalse(inspect.isabstract(klass))
        self.assertEqual(self.registry, before)
        self.assertEqual(_registry_warnings(caught), [])

    def test_an_abstract_subclass_is_skipped(self) -> 'None':
        from pcapkit.protocols.protocol import Protocol

        bare = type('W2763Bare', (Protocol,), {'__module__': __name__})
        self.assertTrue(inspect.isabstract(bare))
        self.assertNotIn('W2763BARE', self.registry)

        # A concrete subclass of an abstract one is still named.
        member = _concrete('W2763Member', base=bare)
        self.assertFalse(inspect.isabstract(member))
        self.assertIs(self.registry['W2763MEMBER'], member)

    def test_a_clash_keeps_the_entry_and_warns(self) -> 'None':
        shipped = self.registry['IPV4']
        builtin = self.ProtocolBase.get_protocol('IPV4')
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            custom = _concrete('IPv4')
        self.assertIs(self.registry['IPV4'], shipped)
        self.assertIs(self.ProtocolBase.get_protocol('IPV4'), builtin)
        messages = _registry_warnings(caught)
        self.assertEqual(len(messages), 1, messages)
        self.assertIn('keeping', messages[0])
        self.assertLess(messages[0].index(repr(shipped)), messages[0].index(repr(custom)))

    def test_a_clash_between_same_named_classes_tells_them_apart(self) -> 'None':
        """#710: the reprs coincide, so the message carries each id, the kept one first."""
        first = _concrete('W2763Twice')
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            second = _concrete('W2763Twice')
        self.assertEqual(repr(first), repr(second))
        self.assertIs(self.registry['W2763TWICE'], first)
        messages = _registry_warnings(caught)
        self.assertEqual(len(messages), 1, messages)
        self.assertLess(messages[0].index(f'id={id(first):#x}'), messages[0].index(f'id={id(second):#x}'))

    def test_a_class_meeting_its_own_descriptor_is_silent(self) -> 'None':
        """A class defined under a built-in's module and name is no clash, and leaves the descriptor."""
        from pcapkit.protocols.application.ngap.protocol import NGAP

        shipped = self.registry['NGAP']
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            redefined = _concrete('NGAP', module=NGAP.__module__)
        self.assertFalse(inspect.isabstract(redefined))
        self.assertEqual(_registry_warnings(caught), [])
        self.assertIs(self.registry['NGAP'], shipped)
        self.assertIs(self.ProtocolBase.get_protocol('NGAP'), NGAP)

    def test_a_refused_code_names_nothing(self) -> 'None':
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.utilities.exceptions import RegistryError

        before = dict(self.registry)
        with self.assertRaises(RegistryError):
            _concrete('W2763Refused', code={Frame: TransType.ICMP})
        self.assertEqual(self.registry, before)

    def test_register_protocol_replaces_and_puts_the_shipped_entry_back(self) -> 'None':
        from pcapkit.foundation.registry import register_protocol

        shipped = self.registry['IPV4']
        builtin = self.ProtocolBase.get_protocol('IPV4')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            custom = _concrete('IPv4')

        for replacement, displaced, entry in ((custom, builtin, custom), (builtin, custom, shipped)):
            with self.subTest(replacement=replacement.__module__):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    register_protocol(replacement)
                self.assertIs(self.registry['IPV4'], entry)
                self.assertIs(self.ProtocolBase.get_protocol('IPV4'), replacement)
                messages = _registry_warnings(caught)
                self.assertEqual(len(messages), 1, messages)
                self.assertIn(f'overwriting {displaced!r} with {replacement!r}', messages[0])

        # Handing back what the name already shows is silent, and keeps the descriptor.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.ProtocolBase.register_protocol(builtin)
        self.assertEqual(_registry_warnings(caught), [])
        self.assertIs(self.registry['IPV4'], shipped)

    def test_register_protocol_refuses_a_non_protocol(self) -> 'None':
        from pcapkit.utilities.exceptions import RegistryError

        before = dict(self.registry)
        for value in (object(), 'IPv4', object, self.registry['IPV4']):
            with self.subTest(value=repr(value)), self.assertRaises(RegistryError):
                self.ProtocolBase.register_protocol(value)  # type: ignore[arg-type]
        self.assertEqual(self.registry, before)


class GetterTests(_RegistryTestCase):
    """``get_protocol`` and the removal of the module dict."""

    def test_the_getter_resolves_a_name_in_any_case(self) -> 'None':
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for name in ('TCP', 'tcp', 'Tcp'):
            with self.subTest(name=name):
                self.assertIs(self.ProtocolBase.get_protocol(name), TCP)
        self.assertIsInstance(self.registry['TCP'], ModuleDescriptor)  # resolved, not written back
        self.assertIsNone(self.ProtocolBase.get_protocol('W2763-NoSuch'))
        self.assertIs(self.ProtocolBase.get_protocol('W2763-NoSuch', Raw), Raw)

    def test_a_descriptor_naming_no_class_raises(self) -> 'None':
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError

        self.registry['W2763LOST'] = ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'W2763Lost')
        with CaughtByCaller(ProtocolError), self.assertRaises(ProtocolError):
            self.ProtocolBase.get_protocol('W2763Lost')

    def test_the_module_dict_is_gone(self) -> 'None':
        import pcapkit.protocols

        with self.assertRaises(AttributeError):
            pcapkit.protocols.__proto__  # pylint: disable=pointless-statement
        with self.assertRaises(ImportError):
            exec('from pcapkit.protocols import __proto__', {})  # nosec: B102
        self.assertNotIn('__proto__', dir(pcapkit.protocols))
        self.assertNotIn('__proto__', vars(pcapkit.protocols))


class RegistryViewTests(_RegistryTestCase):
    """``AnyProtocol.registry``, the read-only view :class:`~pcapkit.protocols.protocol.ProtocolMeta` defines."""

    def _classes(self) -> 'list[type]':
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.protocol import Protocol

        return [self.ProtocolBase, Protocol, IPv4, Raw, _concrete('W2763Viewer')]

    def test_the_view_is_read_only(self) -> 'None':
        import types

        view = self.ProtocolBase.registry
        self.assertIsInstance(view, types.MappingProxyType)
        with self.assertRaises(TypeError):
            view['W2763RO'] = self.ProtocolBase  # type: ignore[index]
        with self.assertRaises(TypeError):
            del view['IPV4']  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            self.ProtocolBase.registry = {}  # type: ignore[misc]
        self.assertNotIn('W2763RO', self.registry)
        self.assertIn('IPV4', self.registry)

    def test_the_view_holds_the_entries_as_stored(self) -> 'None':
        from pcapkit.corekit.module import ModuleDescriptor

        view = self.ProtocolBase.registry
        self.assertEqual(sorted(view), sorted(self.registry))
        for key, entry in self.registry.items():
            with self.subTest(key=key):
                self.assertIs(view[key], entry)
        self.assertIsInstance(view['IPV4'], ModuleDescriptor)

    def test_every_protocol_class_reaches_the_same_live_view(self) -> 'None':
        views = [(klass.__name__, klass.registry) for klass in self._classes()]
        added = _concrete('W2763Later')
        for name, view in views:
            with self.subTest(through=name):
                self.assertEqual(dict(view), dict(self.registry))
                self.assertIs(view['W2763LATER'], added)


#: What every child runs first: a cold ``import pcapkit`` from this tree.
PRELUDE = f'''
import importlib, json, sys, warnings

def loaded(*names):
    return [name for name in names if name in sys.modules]

def emit(**kwargs):
    print(json.dumps(kwargs))

import pcapkit
assert pcapkit.__file__.startswith({str(ROOT)!r}), pcapkit.__file__
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.protocol import ProtocolBase
'''


def run_child(code: 'str') -> 'dict[str, Any]':
    """Run :data:`PRELUDE` then ``code`` in a fresh interpreter; return its last ``emit`` line."""
    environ = dict(os.environ)
    environ.pop('PYTHONSAFEPATH', None)
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH') else [str(ROOT)])
    result = subprocess.run([sys.executable, '-c', PRELUDE + textwrap.dedent(code)],  # nosec: B603
                            cwd=str(ROOT), env=environ, capture_output=True, text=True,
                            timeout=300, check=False)
    if result.returncode != 0:
        raise AssertionError(f'child exited {result.returncode}:\n{result.stderr}')
    return json.loads(result.stdout.splitlines()[-1])


class ColdProcessTests(unittest.TestCase):
    """What the registry imports, and when, from a cold ``import pcapkit``."""

    def test_reading_the_view_imports_no_protocol(self) -> 'None':
        out = run_child('''
            from pcapkit.protocols.protocol import Protocol
            before = sorted(name for name in sys.modules if name.startswith('pcapkit.protocols.'))
            views = [ProtocolBase.registry, Protocol.registry]
            entries = [sorted((key, list(entry)) for key, entry in view.items()) for view in views]
            after = sorted(name for name in sys.modules if name.startswith('pcapkit.protocols.'))
            emit(new=sorted(set(after) - set(before)), same=entries[0] == entries[1],
                 descriptors=all(isinstance(entry, ModuleDescriptor) for entry in views[0].values()),
                 count=len(entries[0]))
        ''')
        self.assertEqual(out['new'], [])
        self.assertTrue(out['same'])
        self.assertTrue(out['descriptors'])
        self.assertGreater(out['count'], 0)

    def test_the_getter_imports_a_class_only_when_resolving(self) -> 'None':
        out = run_child('''
            module = 'pcapkit.protocols.application.ngap.protocol'
            before = loaded(module)
            entry = ProtocolBase.__registry__['NGAP']
            listed = ['NGAP' in ProtocolBase.__registry__, loaded(module)]
            klass = ProtocolBase.get_protocol('ngap')
            emit(before=before, listed=listed, entry=list(entry), after=loaded(module),
                 same=klass is sys.modules[module].NGAP, kept=ProtocolBase.__registry__['NGAP'] is entry)
        ''')
        module = 'pcapkit.protocols.application.ngap.protocol'
        self.assertEqual(out['before'], [])
        self.assertEqual(out['listed'], [True, []])
        self.assertEqual(out['entry'], [module, 'NGAP'])
        self.assertEqual(out['after'], [module])
        self.assertTrue(out['same'])
        self.assertTrue(out['kept'])

    def test_a_reloaded_built_in_is_silent_and_followed(self) -> 'None':
        out = run_child('''
            from pcapkit.utilities.warnings import RegistryWarning
            module = importlib.import_module('pcapkit.protocols.application.ngap.protocol')
            old = ProtocolBase.get_protocol('NGAP')
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                importlib.reload(module)
            new = ProtocolBase.get_protocol('NGAP')
            emit(messages=[str(w.message) for w in caught if issubclass(w.category, RegistryWarning)],
                 followed=[new is not old, new is module.NGAP],
                 descriptor=isinstance(ProtocolBase.__registry__['NGAP'], ModuleDescriptor))
        ''')
        self.assertEqual(out['messages'], [])
        self.assertEqual(out['followed'], [True, True])
        self.assertTrue(out['descriptor'])

    def test_threads_racing_on_a_first_resolution_get_one_class(self) -> 'None':
        """Every thread resolving a not-yet-imported protocol at once gets the class its module binds."""
        out = run_child('''
            import random, threading
            sys.setswitchinterval(1e-6)
            names = sorted(name for name, entry in ProtocolBase.__registry__.items()
                           if entry.module not in sys.modules)
            barrier = threading.Barrier(16)
            results, errors = {}, []

            def worker(seed):
                order = names[:]
                random.Random(seed).shuffle(order)
                barrier.wait()
                try:
                    results[seed] = {name: ProtocolBase.get_protocol(name) for name in order}
                except BaseException as exc:  # noqa: BLE001
                    errors.append(f'{type(exc).__name__}: {exc}')

            threads = [threading.Thread(target=worker, args=(seed,)) for seed in range(16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            wrong = sorted(name for name in names for got in results.values()
                           if got[name] is not getattr(sys.modules[ProtocolBase.__registry__[name].module],
                                                       ProtocolBase.__registry__[name].name))
            emit(names=names, errors=errors, threads=len(results), wrong=wrong)
        ''')
        self.assertGreater(len(out['names']), 1, 'no protocol was left unimported to race on')
        self.assertEqual(out['errors'], [])
        self.assertEqual(out['threads'], 16)
        self.assertEqual(out['wrong'], [])


if __name__ == '__main__':
    unittest.main()
