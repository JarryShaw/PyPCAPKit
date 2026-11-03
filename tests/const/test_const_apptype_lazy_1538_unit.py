# -*- coding: utf-8 -*-
"""The app-type registries, and every const enumeration, load on first use.

GitHub issue #1538. :mod:`pcapkit.const.reg.apptype.tcp` and
:mod:`~pcapkit.const.reg.apptype.udp` are generated from IANA's registry and
hold about 49,700 lines of members between them; ``python -X importtime -c
'import pcapkit'`` put them at 104 ms and 102 ms of a 700 ms import. Nothing on
any import path needs them, so :mod:`pcapkit.const.reg.apptype` imports them
from a :pep:`562` ``__getattr__`` and from
:attr:`AppType.__registries__ <pcapkit.const.reg.apptype.apptype.AppType.__registries__>`
the first time either is read. GitHub issue #2729 extended that to SCTP and
DCCP, and to every package under :mod:`pcapkit.const`, through
:func:`pcapkit.utilities.importlib.lazy_exports`; #2726 made the registries an
:class:`~pcapkit.corekit.infoclass.Info` rather than a :obj:`dict` subclass.

The subprocess checks run in a fresh interpreter, since the question is what a
cold import leaves in :data:`sys.modules` and this process has long since
imported everything. :data:`PRELUDE` imports :mod:`pcapkit`, whose protocol
modules import the const modules they name at module level --
:mod:`pcapkit.protocols.application.ngap` imports SCTP's registry, for one, which
#2730 is to move -- so a check of the const packages themselves runs on :data:`BARE`, which
binds :mod:`pcapkit` as a bare package and so runs none of
:file:`pcapkit/__init__.py`. Each check fails on an eager tree at its first
``loaded()`` or ``enumerations()``; what follows it pins that nothing a caller
can observe changed apart from *when* the import happens.
:class:`RegistriesMappingTests` and :class:`PackageGetattrTests` run in-process,
on a private import, so that coverage sees every line.
:class:`PinnedSnapshotTests` covers the suite's own side: :file:`tests/conftest.py`
has to pin every const module, or its restore leaves a second generation of each
behind.

"""

import copy
import importlib.util
import inspect
import json
import os
import pathlib
import pickle
import subprocess
import sys
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from types import ModuleType
    from typing import Any

#: Test tier (#1958): exercises the import system and pickling, which differ between interpreters.
__tier__ = 'ALL'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The per-transport registries, in :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol` order.
TRANSPORTS = ('tcp', 'udp', 'sctp', 'dccp')

#: The names ``dir(pcapkit.const.reg.apptype)`` listed on the eager package
#: besides those the import system sets. Those are not pinned, since they vary
#: by interpreter -- Python 3.15 no longer sets ``__cached__`` (:gh:`97879`,
#: GitHub issue #1648) -- so :func:`eager_dir` reads them off the running one.
PACKAGE_NAMES = ['AppType', 'DCCP', 'SCTP', 'TCP', 'TransportProtocol', 'UDP', '__all__',
                 'apptype', 'dccp', 'sctp', 'tcp', 'udp']

#: The const modules a package of :mod:`pcapkit.const` imports with itself, and why:
#: the app-type package binds ``__registries__`` on the memberless base, so it
#: needs :class:`~pcapkit.const.reg.apptype.apptype.AppType` and
#: :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol` at once.
EAGER = {'pcapkit.const.reg.apptype.apptype': 'pcapkit.const.reg.apptype'}


def import_system_names(module: 'ModuleType') -> 'list[str]':
    """``dir(module)`` as importing it would leave it, were its body empty.

    An import is :func:`importlib.util.module_from_spec`, which sets the
    attributes the spec implies, then the loader's ``exec_module``, which runs
    the body with :func:`exec` in the module's namespace and so adds
    ``__builtins__``. Both run here on ``module``'s own spec, so the names are
    the ones this interpreter, and the loader that imported ``module``, set.
    :data:`HELPERS` carries this function's source into each child.

    """
    fresh = importlib.util.module_from_spec(module.__spec__)  # type: ignore[arg-type]
    exec('', vars(fresh))  # pylint: disable=exec-used
    return dir(fresh)


def eager_dir(interpreter: 'list[str]') -> 'list[str]':
    """``dir()`` of the eager package, given :func:`import_system_names` of it."""
    if not set(interpreter).isdisjoint(PACKAGE_NAMES):
        raise AssertionError(f'the import system set a name the package defines: {interpreter}')
    return sorted({*PACKAGE_NAMES, *interpreter})


HELPERS = f'''
import importlib.util, json, pathlib, sys

def loaded(*names):
    return [name for name in (names or {TRANSPORTS!r})
            if f'pcapkit.const.reg.apptype.{{name}}' in sys.modules]

def enumerations():
    return sorted(name for name, module in list(sys.modules.items())
                  if name.startswith('pcapkit.const.') and not hasattr(module, '__path__'))

def emit(**kwargs):
    print(json.dumps(kwargs))

''' + inspect.getsource(import_system_names)

#: A child that imports :mod:`pcapkit`, protocols and all.
PRELUDE = HELPERS + f'''
import pcapkit
assert pcapkit.__file__.startswith({str(ROOT)!r}), pcapkit.__file__
'''

#: A child that binds :mod:`pcapkit` as a bare package, so importing a
#: subpackage runs none of :file:`pcapkit/__init__.py` -- nor the protocol
#: modules it imports, which name const modules of their own.
BARE = HELPERS + f'''
_root = pathlib.Path({str(ROOT)!r}) / 'pcapkit'
_spec = importlib.util.spec_from_file_location('pcapkit', _root / '__init__.py',
                                               submodule_search_locations=[str(_root)])
sys.modules['pcapkit'] = importlib.util.module_from_spec(_spec)
import pcapkit.const
assert pcapkit.const.__file__.startswith({str(ROOT)!r}), pcapkit.const.__file__
assert 'pcapkit.protocols' not in sys.modules
'''

#: ``repr(AppType.__registries__)`` once populated, eager or lazy.
REGISTRIES_REPR = ("{<TransportProtocol.tcp: 1>: <aenum 'TCP'>, <TransportProtocol.udp: 2>: "
                   "<aenum 'UDP'>, <TransportProtocol.sctp: 3>: <aenum 'SCTP'>, "
                   "<TransportProtocol.dccp: 4>: <aenum 'DCCP'>}")


def run_child(code: 'str', prelude: 'str' = PRELUDE) -> 'dict':
    """Run ``prelude`` then ``code`` in a fresh interpreter; return its last
    :func:`emit` line."""
    environ = dict(os.environ)
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH') else [str(ROOT)])
    result = subprocess.run([sys.executable, '-c', prelude + textwrap.dedent(code)],
                            cwd=str(ROOT), env=environ, capture_output=True, text=True,
                            timeout=300, check=False)
    if result.returncode != 0:
        raise AssertionError(f'child exited {result.returncode}:\n{result.stderr}')
    return json.loads(result.stdout.splitlines()[-1])


class LazyAppTypeImportTests(unittest.TestCase):
    """What a cold import loads, and what loads each registry afterwards."""

    def test_import_pcapkit_leaves_the_registries_unimported(self) -> 'None':
        # NOTE: SCTP's is left out: pcapkit.protocols.application.ngap imports it
        # at module level, which LazyConstImportTests accounts for (#2730).
        out = run_child('''
            emit(loaded=loaded('tcp', 'udp', 'dccp'),
                 eager='pcapkit.const.reg.apptype.apptype' in sys.modules)
        ''')
        self.assertEqual(out['loaded'], [])
        self.assertTrue(out['eager'])

    def test_the_package_imports_no_registry(self) -> 'None':
        out = run_child('''
            import pcapkit.const.reg.apptype as pkg
            from pcapkit.const.reg.apptype import AppType
            steps = [loaded()]
            sctp = pkg.SCTP
            steps.append(loaded())
            dccp = type(AppType.get(9, proto='dccp'))
            steps.append(loaded())
            tcp = pkg.tcp.TCP
            steps.append(loaded())
            from pcapkit.const.reg.apptype import UDP
            steps.append(loaded())
            emit(steps=steps,
                 same=[sctp is sys.modules['pcapkit.const.reg.apptype.sctp'].SCTP, dccp is pkg.DCCP,
                       tcp is pkg.TCP, UDP is pkg.udp.UDP, 'SCTP' in vars(pkg)],
                 members=[isinstance(sctp.discard, AppType), str(AppType.get(9, proto='sctp')),
                          str(AppType.get(9, proto=pkg.TransportProtocol.dccp))])
        ''', prelude=BARE)
        self.assertEqual(out['steps'], [[], ['sctp'], ['sctp', 'dccp'], ['tcp', 'sctp', 'dccp'],
                                        ['tcp', 'udp', 'sctp', 'dccp']])
        self.assertEqual(out['same'], [True] * 5)
        self.assertEqual(out['members'], [True, 'discard [9 - sctp]', 'discard [9 - dccp]'])

    def test_attribute_access_loads_only_the_registry_it_names(self) -> 'None':
        out = run_child('''
            import pcapkit.const.reg.apptype as pkg
            steps = [loaded('tcp', 'udp')]
            tcp = pkg.TCP
            steps.append(loaded('tcp', 'udp'))
            udp = pkg.udp.UDP
            steps.append(loaded('tcp', 'udp'))
            emit(steps=steps,
                 same=[tcp is sys.modules['pcapkit.const.reg.apptype.tcp'].TCP,
                       udp is pkg.UDP, pkg.TCP is pkg.tcp.TCP, 'TCP' in vars(pkg)])
        ''')
        self.assertEqual(out['steps'], [[], ['tcp'], ['tcp', 'udp']])
        self.assertEqual(out['same'], [True, True, True, True])

    def test_port_lookup_loads_only_the_transport_it_asks_for(self) -> 'None':
        out = run_child('''
            from pcapkit.const.reg.apptype import AppType, TransportProtocol
            steps = [loaded('tcp', 'udp')]
            http = AppType.get(80, proto='tcp')
            steps.append(loaded('tcp', 'udp'))
            dns = AppType.get(53, proto=TransportProtocol.udp)
            steps.append(loaded('tcp', 'udp'))
            emit(steps=steps, members=[str(http), type(http).__qualname__,
                                       str(dns), type(dns).__qualname__])
        ''')
        self.assertEqual(out['steps'], [[], ['tcp'], ['tcp', 'udp']])
        self.assertEqual(out['members'], ['http [80 - tcp] (aliases: www, www-http)', 'TCP',
                                          'domain [53 - udp]', 'UDP'])


class LazyAppTypeContractTests(unittest.TestCase):
    """Nothing but the moment of import changed."""

    def test_dir_and_star_import_are_unchanged(self) -> 'None':
        out = run_child('''
            import pcapkit.const.reg.apptype as pkg
            listed, before = dir(pkg), loaded()
            namespace = {}
            exec('from pcapkit.const.reg.apptype import *', namespace)
            emit(dir=listed, before=before, after=loaded(), all=pkg.__all__,
                 interpreter=import_system_names(pkg),
                 star=sorted(name for name in namespace if name != '__builtins__'),
                 resolved=[namespace[name] is getattr(pkg, name) for name in pkg.__all__])
        ''', prelude=BARE)
        self.assertEqual(out['dir'], eager_dir(out['interpreter']))
        self.assertEqual(out['before'], [])
        self.assertEqual(out['star'], sorted(out['all']))
        self.assertEqual(out['resolved'], [True] * 6)
        self.assertEqual(out['after'], list(TRANSPORTS))

    def test_registries_never_expose_a_pending_registry(self) -> 'None':
        # NOTE: one interpreter for every view, so each starts from the pending
        # state again rather than from whatever the previous view loaded.
        out = run_child('''
            import copy, pickle
            from pcapkit.const.reg.apptype import AppType, TransportProtocol
            from pcapkit.corekit.infoclass import Info
            from pcapkit.corekit.module import ModuleDescriptor
            registries = AppType.__registries__
            shape = [len(registries), [int(key) for key in registries],
                     1 in registries, TransportProtocol.udp in registries, loaded(),
                     isinstance(registries, Info), isinstance(registries, dict)]
            populated = dict(registries)
            views = {
                'getitem': lambda: repr(registries[TransportProtocol.tcp]),
                'get': lambda: repr(registries.get(1)),
                'dict': lambda: repr(dict(registries)),
                'unpack': lambda: repr({**registries}),
                'values': lambda: repr(list(registries.values())),
                'items': lambda: repr(dict(registries.items())),
                'items_multi': lambda: repr(dict(registries.items(multi=True))),
                'to_dict': lambda: repr(dict(registries.to_dict())),
                'copy.copy': lambda: repr(dict(copy.copy(registries))),
                'copy.deepcopy': lambda: repr(dict(copy.deepcopy(registries))),
                'pickle': lambda: repr(dict(pickle.loads(pickle.dumps(registries)))),
                'repr': lambda: repr(registries),
                'str': lambda: str(registries),
                'eq': lambda: repr(registries == populated),
                'ne': lambda: repr(registries != populated),
            }
            reprs = {}
            for name, view in views.items():
                for proto in list(TransportProtocol)[1:]:
                    vars(registries)[registries.__map__[proto]] = ModuleDescriptor(
                        f'pcapkit.const.reg.apptype.{proto.name}', proto.name.upper())
                reprs[name] = view()
            emit(shape=shape, reprs=reprs, default=registries.get(0, 'fallback'))
        ''', prelude=BARE)
        self.assertEqual(out['shape'], [4, [1, 2, 3, 4], True, True, [], True, False])
        self.assertEqual(len(out['reprs']), 15)
        for name, text in out['reprs'].items():
            with self.subTest(view=name):
                self.assertNotIn('ModuleDescriptor', text)
                self.assertEqual(text, {'getitem': "<aenum 'TCP'>", 'get': "<aenum 'TCP'>",
                                        'values': "[<aenum 'TCP'>, <aenum 'UDP'>, "
                                                  "<aenum 'SCTP'>, <aenum 'DCCP'>]",
                                        'eq': 'True', 'ne': 'False'}
                                 .get(name, REGISTRIES_REPR))
        self.assertEqual(out['default'], 'fallback')

    def test_member_pickled_eagerly_unpickles_after_a_lazy_import(self) -> 'None':
        payload = run_child('''
            import pickle
            from pcapkit.const.reg.apptype.dccp import DCCP
            from pcapkit.const.reg.apptype.sctp import SCTP
            from pcapkit.const.reg.apptype.tcp import TCP
            from pcapkit.const.reg.apptype.udp import UDP
            emit(payload=pickle.dumps([TCP.http, UDP.domain, SCTP.discard, DCCP.discard]).hex())
        ''')['payload']
        out = run_child(f'''
            import copy, pickle
            before = loaded()
            members = pickle.loads(bytes.fromhex({payload!r}))
            import pcapkit.const.reg.apptype as pkg
            emit(before=before, after=loaded(),
                 same=[member is getattr(pkg, name).__members__[member.name]
                       for name, member in zip(('TCP', 'UDP', 'SCTP', 'DCCP'), members)],
                 copies=[copy.copy(member) is member and copy.deepcopy(member) is member
                         for member in members])
        ''', prelude=BARE)
        self.assertEqual(out['before'], [])
        self.assertEqual(out['after'], list(TRANSPORTS))
        self.assertEqual(out['same'], [True] * 4)
        self.assertEqual(out['copies'], [True] * 4)

    def test_port_registered_before_first_use_dispatches_the_same(self) -> 'None':
        code = '''
            from pcapkit.foundation.registry import register_tcp
            from pcapkit.protocols.transport.tcp import TCP
            if {lookup_first}:
                import pcapkit.const.reg.apptype
                pcapkit.const.reg.apptype.TCP
            at_register = loaded('tcp', 'udp')
            register_tcp(54321, 'pcapkit.protocols.application.ftp', 'FTP')
            raw = TCP(srcport=40000, dstport=54321, payload=b'USER anonymous\\r\\n').data
            parsed = TCP(raw, len(raw))
            emit(at_register=at_register, raw=raw.hex(), chain=str(parsed.protochain),
                 ports=[repr(parsed.info.srcport), repr(parsed.info.dstport)],
                 rebuilt=[TCP.from_data(parsed.info).data == raw,
                          TCP.from_data(parsed.info.to_dict()).data == raw])
        '''
        before = run_child(code.format(lookup_first=False))
        after = run_child(code.format(lookup_first=True))
        self.assertEqual(before.pop('at_register'), [])
        self.assertEqual(after.pop('at_register'), ['tcp'])
        self.assertEqual(before, after)
        self.assertEqual(before['chain'], 'TCP:FTP')
        self.assertEqual(before['rebuilt'], [True, True])


class LazyConstImportTests(unittest.TestCase):
    """:mod:`pcapkit.const` imports no enumeration until one is used (GitHub issue #2729)."""

    def test_import_pcapkit_const_loads_no_enumeration(self) -> 'None':
        out = run_child('''
            packages = sorted(name for name in sys.modules if name.startswith('pcapkit.const'))
            steps = [enumerations()]
            option = pcapkit.const.TCP_Option
            steps.append(enumerations())
            from pcapkit.const.ipv4 import IPv4_OptionNumber
            steps.append(enumerations())
            import pcapkit.const.vlan.priority_level
            steps.append(enumerations())
            apptype = pcapkit.const.APPTYPE
            steps.append(enumerations())
            namespace = {}
            exec('from pcapkit.const import *', namespace)
            emit(packages=packages, steps=steps, loaded=loaded(),
                 same=[option is pcapkit.const.tcp.option.Option,
                       IPv4_OptionNumber is pcapkit.const.ipv4.option_number.OptionNumber,
                       pcapkit.const.vlan.priority_level.PriorityLevel is pcapkit.const.VLAN_PriorityLevel,
                       apptype is pcapkit.const.reg.apptype.apptype.AppType],
                 star=all(namespace[name] is getattr(pcapkit.const, name) for name in pcapkit.const.__all__),
                 every=enumerations())
        ''', prelude=BARE)
        tree = ROOT / 'pcapkit' / 'const'
        packages = sorted('.'.join(path.relative_to(ROOT).parent.parts) for path in tree.rglob('__init__.py'))
        modules = sorted('.'.join(path.relative_to(ROOT).with_suffix('').parts)
                         for path in tree.rglob('*.py') if path.name != '__init__.py')
        self.assertEqual(out['packages'], [name for name in packages if name != 'pcapkit.const.reg.apptype'])
        self.assertEqual(out['steps'], [
            [],
            ['pcapkit.const.tcp.option'],
            ['pcapkit.const.ipv4.option_number', 'pcapkit.const.tcp.option'],
            ['pcapkit.const.ipv4.option_number', 'pcapkit.const.tcp.option',
             'pcapkit.const.vlan.priority_level'],
            ['pcapkit.const.ipv4.option_number', 'pcapkit.const.reg.apptype.apptype',
             'pcapkit.const.tcp.option', 'pcapkit.const.vlan.priority_level'],
        ])
        # NOTE: pcapkit.const exports APPTYPE, the memberless base, and none of
        # the per-transport registries, so its star import loads every other
        # enumeration and none of those.
        self.assertEqual(out['loaded'], [])
        self.assertEqual(out['same'], [True] * 4)
        self.assertTrue(out['star'])
        self.assertEqual(out['every'], [name for name in modules if name not in
                                        {f'pcapkit.const.reg.apptype.{name}' for name in TRANSPORTS}])

    def test_import_pcapkit_loads_only_what_other_modules_import(self) -> 'None':
        """Every const module ``import pcapkit`` loads is one a module outside the
        const packages imports at module level, or one :data:`EAGER` names.

        Those are the protocol, schema and data modules naming the const module
        they read; moving them is GitHub issue #2730.

        """
        out = run_child('''
            import ast

            def imported(body, found):
                for node in body:
                    if isinstance(node, ast.Import):
                        found.update(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                        found.update(f'{node.module}.{alias.name}' for alias in node.names)
                        found.add(node.module)
                    elif isinstance(node, ast.If):
                        if not (isinstance(node.test, ast.Name) and node.test.id == 'TYPE_CHECKING'):
                            imported(node.body, found)
                        imported(node.orelse, found)
                    elif isinstance(node, ast.Try):
                        for block in (node.body, *(handler.body for handler in node.handlers),
                                      node.orelse, node.finalbody):
                            imported(block, found)
                return found

            loaded = set(enumerations())
            importers = {}
            for name, module in list(sys.modules.items()):
                path = getattr(module, '__file__', None)
                if not name.startswith('pcapkit') or path is None or (
                        name.startswith('pcapkit.const') and hasattr(module, '__path__')):
                    continue
                with open(path, encoding='utf-8') as file:
                    found = imported(ast.parse(file.read()).body, set())
                for target in found & loaded:
                    importers.setdefault(target, []).append(name)
            emit(loaded=sorted(loaded), explained=sorted(importers),
                 packages=sorted(name for name in sys.modules
                                 if name.startswith('pcapkit.const') and hasattr(sys.modules[name], '__path__')))
        ''')
        unexplained = sorted(set(out['loaded']) - set(out['explained']) - set(EAGER))
        self.assertEqual(unexplained, [], 'a const package imported these with itself')
        for module, package in EAGER.items():
            self.assertIn(package, out['packages'], f'{module} names a package import pcapkit does not load')
        self.assertNotIn('pcapkit.const.reg.apptype.tcp', out['loaded'])


class RegistriesMappingTests(unittest.TestCase):
    """Every method of the lazy mapping, on a private instance in this process."""

    def setUp(self) -> 'None':
        # NOTE: a private import, so that the package starts cold -- the shared
        # one has every registry loaded, since tests/conftest.py pins them --
        # and nothing bound here outlives the class.
        reimport_once_per_class(self, restore=True)
        self.make()

    def make(self) -> 'None':
        from pcapkit.const.reg.apptype import _Registries  # type: ignore[attr-defined]
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, TransportProtocol
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.utilities.exceptions import UnsupportedCall

        self.proto = TransportProtocol
        self.classes = [TCP, UDP, SCTP, DCCP]
        self.descriptor = ModuleDescriptor
        self.info, self.unsupported, self.factory = Info, UnsupportedCall, _Registries
        self.registries = _Registries({
            TransportProtocol.tcp: ModuleDescriptor('pcapkit.const.reg.apptype.tcp', 'TCP'),
            TransportProtocol.udp: ModuleDescriptor('pcapkit.const.reg.apptype.udp', 'UDP'),
            TransportProtocol.sctp: SCTP,
            TransportProtocol.dccp: DCCP,
        })

    def assert_pending(self, *protos: 'object', registries: 'Any' = None) -> 'None':
        registries = self.registries if registries is None else registries
        held = vars(registries)
        self.assertEqual([proto for name, proto in registries.__map_reverse__.items()
                          if isinstance(held[name], self.descriptor)], list(protos))

    def test_reads_resolve_in_place(self) -> 'None':
        registries, proto = self.registries, self.proto
        self.assertEqual((len(registries), list(registries), 1 in registries), (4, list(proto)[1:], True))
        self.assert_pending(proto.tcp, proto.udp)
        self.assertIs(registries.get(2), self.classes[1])
        self.assert_pending(proto.tcp)
        self.assertIs(registries[proto.tcp], self.classes[0])
        self.assert_pending()
        self.assertEqual(list(registries), list(proto)[1:])
        self.assertIsNone(registries.get(proto.undefined))

    def test_a_descriptor_default_is_returned_untouched(self) -> 'None':
        default = self.descriptor('pcapkit.const.reg.apptype.tcp', 'TCP')
        self.assertIs(self.registries.get(0, default), default)
        self.assertNotIn(0, self.registries)

    def test_only_a_transport_is_a_key(self) -> 'None':
        registries = self.registries
        for key in ('tcp', '__map__', '__dict__', registries.__map__[self.proto.tcp], self.proto.undefined, 5):
            with self.subTest(key=key):
                self.assertNotIn(key, registries)
                with self.assertRaises(KeyError) as context:
                    registries[key]  # pylint: disable=pointless-statement
                self.assertEqual(context.exception.args, (key,))
        with self.assertRaises(TypeError):
            [] in registries  # pylint: disable=pointless-statement
        self.assert_pending(self.proto.tcp, self.proto.udp)

    def test_keys_by_member_value_or_name(self) -> 'None':
        proto, (tcp, udp, sctp, _) = self.proto, self.classes
        for registries in (self.factory({1: tcp, 'UDP': udp}, sctp=sctp),
                           self.factory([(proto.tcp, tcp), (2, udp)], sctp=sctp),
                           self.factory.from_dict({proto.tcp: tcp, 'udp': udp}, SCTP=sctp)):
            with self.subTest(registries=registries):
                self.assertEqual(list(registries), [proto.tcp, proto.udp, proto.sctp])
                self.assertEqual([registries[key] for key in registries], [tcp, udp, sctp])

    def test_whole_mapping_reads_resolve_everything(self) -> 'None':
        proto, classes = self.proto, self.classes
        expected = dict(zip(list(proto)[1:], classes))
        views = {
            'values': lambda registries: list(registries.values()) == classes,
            'items': lambda registries: dict(registries.items()) == expected,
            'items_multi': lambda registries: list(registries.items(multi=True)) == list(expected.items()),
            'to_dict': lambda registries: list(registries.to_dict().items(multi=True)) == list(expected.items()),
            'dict': lambda registries: dict(registries) == expected,
            'eq': lambda registries: registries == expected,
            'ne': lambda registries: (registries != expected) is False,
            'repr': lambda registries: repr(registries) == repr(expected),
            'str': lambda registries: str(registries) == repr(expected),
            'deepcopy': lambda registries: dict(copy.deepcopy(registries)) == expected,
        }
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            views[f'pickle-{protocol}'] = lambda registries, protocol=protocol: self.round_trips(registries, protocol)
        for name, view in views.items():
            with self.subTest(view=name):
                self.make()
                self.assertTrue(view(self.registries))
                self.assert_pending()

    def round_trips(self, registries: 'Any', protocol: 'int') -> 'bool':
        """Whether ``registries`` comes back from :mod:`pickle` as an equal registry holding no descriptor."""
        copied = pickle.loads(pickle.dumps(registries, protocol))
        self.assertIs(type(copied), self.factory)
        self.assertEqual(list(copied), list(registries))
        self.assert_pending(registries=copied)
        return copied == registries

    def test_a_copy_resolves_on_its_own(self) -> 'None':
        proto, registries = self.proto, self.registries
        copied = copy.copy(registries)
        self.assertIsNot(copied.__map__, registries.__map__)
        self.assert_pending(proto.tcp, proto.udp, registries=copied)
        self.assertIs(copied[proto.tcp], self.classes[0])
        self.assert_pending(proto.udp, registries=copied)
        self.assert_pending(proto.tcp, proto.udp)
        self.assertEqual(copied, registries)

    def test_it_is_an_immutable_info(self) -> 'None':
        # NOTE: GitHub issue #2726. As a dict subclass it had every dict method,
        # and the | operator from Python 3.9 (#1694); as an Info it has the
        # read-only mapping interface, and nothing it does imports a registry.
        registries, proto = self.registries, self.proto
        self.assertIsInstance(registries, self.info)
        self.assertNotIsInstance(registries, dict)
        with self.assertRaises(TypeError):
            registries | {}  # pylint: disable=pointless-statement
        with self.assertRaises(TypeError):
            {} | registries  # pylint: disable=pointless-statement
        with self.assertRaises(TypeError):
            registries[proto.tcp] = self.classes[0]  # type: ignore[index]
        with self.assertRaises(TypeError):
            del registries[proto.tcp]  # type: ignore[attr-defined]
        local = registries
        with self.assertRaises(TypeError):
            local |= {}  # type: ignore[operator]
        with self.assertRaises(self.unsupported):
            registries.tcp = self.classes[0]
        for name in ('pop', 'popitem', 'setdefault', 'update', 'clear', 'copy', 'fromkeys'):
            with self.subTest(method=name):
                self.assertFalse(hasattr(registries, name))
        self.assert_pending(proto.tcp, proto.udp)


class PackageGetattrTests(unittest.TestCase):
    """The :pep:`562` hooks, called in this process so that coverage sees them."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self, restore=True)  # see RegistriesMappingTests.setUp

    def test_hooks(self) -> 'None':
        import pcapkit.const.reg.apptype as pkg

        # NOTE: TCP, UDP and DCCP, since pcapkit.protocols.application.ngap
        # imports SCTP's submodule at module level (#2730).
        for name in ('TCP', 'UDP', 'DCCP'):
            self.assertNotIn(name, vars(pkg))
            self.assertNotIn(f'pcapkit.const.reg.apptype.{name.lower()}', sys.modules)
        getattr_ = vars(pkg)['__getattr__']
        tcp_module = getattr_('tcp')
        self.assertIs(tcp_module, sys.modules['pcapkit.const.reg.apptype.tcp'])
        self.assertIs(getattr_('TCP'), tcp_module.TCP)
        self.assertIs(vars(pkg)['TCP'], tcp_module.TCP)
        self.assertIs(getattr_('DCCP'), sys.modules['pcapkit.const.reg.apptype.dccp'].DCCP)
        for name in ('Tcp', 'tCP', 'sctp_', 'nope'):
            with self.subTest(name=name), self.assertRaises(AttributeError) as context:
                getattr_(name)
            self.assertEqual(str(context.exception), f"module 'pcapkit.const.reg.apptype' has no attribute {name!r}")
        self.assertEqual(vars(pkg)['__dir__'](), eager_dir(import_system_names(pkg)))


class SharedImportProbe(unittest.TestCase):
    """Two tests on the shared import, with the conftest restore between them.

    The first binds every registry through the package; the second imports
    their submodules directly. Unless :data:`tests.conftest.WARM_MODULES` puts
    them in the pinned snapshot, the restore drops them in between and the
    second test builds another generation of each. :mod:`unittest` runs the
    two in name order, and :class:`PinnedSnapshotTests` runs them in one
    :program:`pytest` process, so they meet that restore whatever runs this file.

    """

    def test_1_bind_through_the_package(self) -> 'None':
        import pcapkit.const.reg.apptype as pkg
        from pcapkit.const.reg.apptype import AppType

        for name, port in (('TCP', 80), ('UDP', 53), ('SCTP', 9), ('DCCP', 9)):
            with self.subTest(registry=name):
                self.assertIs(type(AppType.get(port, proto=name.lower())), getattr(pkg, name))

    def test_2_import_the_submodules_directly(self) -> 'None':
        import pcapkit.const.reg.apptype as pkg
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        for name in TRANSPORTS:
            with self.subTest(registry=name):
                registry = getattr(importlib.import_module(f'pcapkit.const.reg.apptype.{name}'), name.upper())
                self.assertIs(registry, getattr(pkg, name.upper()))
                self.assertIs(AppType.__registries__[TransportProtocol[name]], registry)


class PinnedSnapshotTests(unittest.TestCase):
    """:data:`tests.conftest.WARM_MODULES` keeps one generation of each registry."""

    def test_the_probe_passes_in_one_pytest_process(self) -> 'None':
        environ = dict(os.environ)
        environ['PYTHONPATH'] = os.pathsep.join(
            [str(ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH') else [str(ROOT)])
        for name in ('PYTEST_ADDOPTS', 'PYTEST_CURRENT_TEST', 'PYTEST_XDIST_WORKER',
                     'PYTEST_XDIST_WORKER_COUNT', 'PYTEST_XDIST_TESTRUNUID'):
            environ.pop(name, None)
        probe = f'{pathlib.Path(__file__).resolve().relative_to(ROOT)}::SharedImportProbe'
        result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', probe],
                                cwd=str(ROOT), env=environ, capture_output=True, text=True,
                                timeout=300, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('2 passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
