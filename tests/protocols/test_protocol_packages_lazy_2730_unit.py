# -*- coding: utf-8 -*-
"""The packages above a protocol's package import it on first use (GitHub issue #2730).

:mod:`pcapkit.protocols`, its layer packages, :mod:`pcapkit.protocols.misc.pcap` and
:mod:`pcapkit.protocols.misc.checksum` name each protocol class only under
:data:`~typing.TYPE_CHECKING` and import it through
:func:`pcapkit.utilities.importlib.lazy_exports`. :mod:`pcapkit` re-exports
:mod:`pcapkit.protocols` the same way, and :data:`pcapkit.protocols.__proto__` is
built by :mod:`pcapkit.protocols.registry` the first time it is reached. A protocol's
own package keeps its literal imports, which the #2534 layout tests pin.

* :class:`LazyPackageSweepTests` holds each such package, read off the tree, to what
  its eager import did: every export resolves to what its import names, ``import *``
  binds them all, :func:`dir` lists them and the layer's base class but none of the
  helpers, and every protocol class pickles as itself.
* :class:`ColdImportTests` runs in a fresh interpreter, since this one has long since
  imported everything. Each check fails on an eager tree at its first look at
  :data:`sys.modules`, bar the Shim6 one, which guards a registration made as a
  module is imported: :mod:`pcapkit.protocols.internet.ipv6_ext.protocol` writes
  ``Internet.__proto__[TransType.Shim6]`` as it is imported, so that entry exists only
  because ``import pcapkit`` imports that module, through HIP and MH, which
  :mod:`pcapkit.foundation.registry.protocols.internet` imports.

"""

import ast
import importlib
import importlib.util
import json
import os
import pathlib
import pickle
import subprocess
import sys
import textwrap
import types
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises the import system and pickling, which differ between interpreters.
__tier__ = 'ALL'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every package under :mod:`pcapkit.protocols` that is not a protocol's own, read off the tree.
PACKAGES = sorted('.'.join(path.relative_to(ROOT).parent.parts)
                  for path in (ROOT / 'pcapkit' / 'protocols').rglob('__init__.py')
                  if path.parent == ROOT / 'pcapkit' / 'protocols' or not (path.parent / 'protocol.py').exists())

#: The exports a package imports with itself, and why: the framework modules every
#: protocol module imports anyway, and the protocol-number enumerations, which are
#: :mod:`pcapkit.const` modules rather than protocols.
EAGER = {
    'pcapkit.protocols': {'Data', 'data', 'Schema', 'schema'},
    'pcapkit.protocols.application': {'APPTYPE'},
    'pcapkit.protocols.internet': {'ETHERTYPE'},
    'pcapkit.protocols.link': {'LINKTYPE'},
    'pcapkit.protocols.transport': {'TRANSTYPE'},
}

#: The base class each package binds outside its ``__all__``, which ``dir()`` listed eagerly.
BASES = {
    'pcapkit.protocols': {'Protocol'},
    'pcapkit.protocols.application': {'Application'},
    'pcapkit.protocols.internet': {'Internet'},
    'pcapkit.protocols.link': {'Link'},
    'pcapkit.protocols.transport': {'Transport'},
}


def init_path(package: 'str') -> 'pathlib.Path':
    """The ``__init__.py`` of ``package``."""
    return ROOT.joinpath(*package.split('.'), '__init__.py')


def declared(package: 'str') -> 'dict[str, tuple[str, str, bool]]':
    """What the ``__init__.py`` of ``package`` imports at module level, ``TYPE_CHECKING`` included.

    Each bound name maps to the module it is imported from, its name there, and
    whether the import is under ``TYPE_CHECKING``; a star import maps each name
    its module's ``__all__`` lists to that module and the same name.

    """
    names = {}  # type: dict[str, tuple[str, str, bool]]

    def visit(body: 'list[ast.stmt]', typing_only: 'bool') -> 'None':
        for node in body:
            if isinstance(node, ast.If):
                guarded = isinstance(node.test, ast.Name) and node.test.id == 'TYPE_CHECKING'
                visit(node.body, typing_only or guarded)
                visit(node.orelse, typing_only)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for alias in node.names:
                    if alias.name == '*':
                        source = importlib.import_module(node.module)
                        names.update((name, (node.module, name, typing_only)) for name in source.__all__)
                    else:
                        names[alias.asname or alias.name] = (node.module, alias.name, typing_only)

    visit(ast.parse(init_path(package).read_text(encoding='utf-8')).body, False)
    return names


def import_system_names(module: 'types.ModuleType') -> 'set[str]':
    """The names importing ``module`` would leave in it, were its body empty."""
    fresh = importlib.util.module_from_spec(module.__spec__)  # type: ignore[arg-type]
    exec('', vars(fresh))  # pylint: disable=exec-used
    return set(dir(fresh))


class LazyPackageSweepTests(unittest.TestCase):
    """Each package above a protocol's, as an eager import of it would leave it."""

    def test_the_sweep_found_the_packages(self) -> 'None':
        """An empty walk would let every loop below pass without checking a package."""
        for package in ('pcapkit.protocols', 'pcapkit.protocols.link', 'pcapkit.protocols.misc.pcap',
                        'pcapkit.protocols.misc.checksum'):
            self.assertIn(package, PACKAGES)
        self.assertNotIn('pcapkit.protocols.link.vlan', PACKAGES)

    def test_every_name_in_all_resolves_to_what_its_import_names(self) -> 'None':
        for package in PACKAGES:
            module = importlib.import_module(package)
            imports = declared(package)
            names = [*module.__all__, *BASES.get(package, ())]
            with self.subTest(package=package):
                self.assertTrue(module.__all__)
                self.assertEqual([name for name in names if name not in imports], [],
                                 'name each export in an import under TYPE_CHECKING')
                eager = sorted(name for name in module.__all__ if not imports[name][2])
                self.assertEqual(eager, sorted(EAGER.get(package, ())),
                                 'import each protocol under TYPE_CHECKING alone, so that it loads on first use')
                for name in names:
                    source, attribute, _ = imports[name]
                    self.assertIs(getattr(module, name), getattr(importlib.import_module(source), attribute),
                                  f'{package}.{name}')

    def test_star_import_binds_every_name(self) -> 'None':
        for package in [*PACKAGES, 'pcapkit']:
            module = importlib.import_module(package)
            namespace = {}  # type: dict[str, Any]
            exec(f'from {package} import *', namespace)  # pylint: disable=exec-used
            namespace.pop('__builtins__')
            with self.subTest(package=package):
                self.assertEqual(sorted(namespace), sorted(module.__all__))
                for name, value in namespace.items():
                    self.assertIs(value, getattr(module, name))

    def test_pcapkit_re_exports_the_protocols(self) -> 'None':
        import pcapkit
        import pcapkit.protocols

        for name in pcapkit.protocols.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(pcapkit, name), getattr(pcapkit.protocols, name))

    def test_dir_lists_what_an_eager_import_bound(self) -> 'None':
        # NOTE: the eager import bound every submodule its imports name, and any
        # other one already imported; the first are listed whether imported or
        # not, as they are not on a cold import. ``registry`` is where
        # ``__proto__`` comes from, which ``dir()`` lists as the eager import did.
        for package in PACKAGES:
            module = importlib.import_module(package)
            named = {source[len(package) + 1:].split('.')[0] for (source, _, _) in declared(package).values()
                     if source.startswith(f'{package}.')}
            submodules = named | {name for (name, value) in vars(module).items()
                                  if isinstance(value, types.ModuleType) and value.__name__ == f'{package}.{name}'}
            extra = {'__proto__', 'registry'} if package == 'pcapkit.protocols' else set()
            with self.subTest(package=package):
                self.assertTrue(named)
                self.assertEqual(dir(module), sorted({*import_system_names(module), '__all__', *module.__all__,
                                                      *BASES.get(package, ()), *submodules, *extra}))
                for helper in ('TYPE_CHECKING', 'lazy_exports', '__getattr__', '__dir__'):
                    self.assertIn(helper, vars(module))
                    self.assertNotIn(helper, dir(module))

    def test_every_protocol_class_pickles_as_itself(self) -> 'None':
        import pcapkit.protocols
        from pcapkit.protocols.protocol import ProtocolBase

        classes = [getattr(pcapkit.protocols, name) for name in pcapkit.protocols.__all__]
        classes = [value for value in classes if isinstance(value, type) and issubclass(value, ProtocolBase)]
        self.assertIn(pcapkit.protocols.IPv4, classes)
        for value in classes:
            with self.subTest(protocol=value.__name__):
                for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                    self.assertIs(pickle.loads(pickle.dumps(value, protocol)), value)


#: What every child runs first: the helpers, then a cold ``import pcapkit`` from this tree.
PRELUDE = f'''
import io, json, pickle, struct, sys, warnings

def loaded(*names):
    return [name for name in names if name in sys.modules]

def emit(**kwargs):
    print(json.dumps(kwargs))

def ipv4(proto, payload):
    return struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                       bytes([127, 0, 0, 1]), bytes([127, 0, 0, 1])) + payload

#: An IGMPv2 general query, eight octets: type 0x11, max response time 10s.
IGMP = bytes([0x11, 0x64, 0, 0]) + bytes(4)

import pcapkit
assert pcapkit.__file__.startswith({str(ROOT)!r}), pcapkit.__file__
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


class ColdImportTests(unittest.TestCase):
    """What a cold ``import pcapkit`` leaves unimported, and what reaches it later."""

    def test_import_pcapkit_binds_no_protocol_class(self) -> 'None':
        """No package holds a protocol class, nor the registry, until it is reached."""
        out = run_child(f'''
            import importlib
            import pcapkit.protocols
            bound = {{}}
            for package in {PACKAGES!r}:
                module = importlib.import_module(package)
                bound[package] = sorted(name for name in module.__all__ if name in vars(module))
            emit(bound=bound, top=sorted(name for name in pcapkit.protocols.__all__ if name in vars(pcapkit)),
                 registry=['__proto__' in vars(pcapkit.protocols), 'pcapkit.protocols.registry' in sys.modules],
                 loaded=loaded('pcapkit.protocols.link.ethernet', 'pcapkit.protocols.link.s_tag',
                               'pcapkit.protocols.internet.igmp', 'pcapkit.protocols.application.ngap'))
        ''')
        self.assertEqual(out['bound'], {package: sorted(EAGER.get(package, ())) for package in PACKAGES})
        self.assertEqual(out['top'], [])
        self.assertEqual(out['registry'], [False, False])
        self.assertEqual(out['loaded'], [])

    def test_reaching_a_name_imports_its_package(self) -> 'None':
        out = run_child('''
            import pcapkit.protocols.link as link
            steps = [loaded('pcapkit.protocols.link.ethernet')]
            ethernet = link.Ethernet
            steps.append(loaded('pcapkit.protocols.link.ethernet'))
            from pcapkit.protocols.link.ethernet.protocol import Ethernet
            emit(steps=steps, same=[ethernet is Ethernet, vars(link)['Ethernet'] is Ethernet,
                                    pcapkit.protocols.Ethernet is Ethernet, pcapkit.Ethernet is Ethernet,
                                    link.ethernet is sys.modules['pcapkit.protocols.link.ethernet']])
        ''')
        self.assertEqual(out['steps'], [[], ['pcapkit.protocols.link.ethernet']])
        self.assertEqual(out['same'], [True] * 5)

    def test_dispatch_imports_a_next_layer_not_yet_imported(self) -> 'None':
        """IPv4 dispatches protocol number 2 to IGMP, which picks IGMPv2, neither imported yet."""
        out = run_child('''
            from pcapkit.protocols.internet.ipv4.protocol import IPv4
            before = loaded('pcapkit.protocols.internet.igmp', 'pcapkit.protocols.internet.igmpv2')
            packet = IPv4(io.BytesIO(ipv4(2, IGMP)), 20 + len(IGMP))
            emit(before=before, chain=str(packet.protochain), layer=type(packet.payload).__module__,
                 registry='pcapkit.protocols.registry' in sys.modules)
        ''')
        self.assertEqual(out['before'], [])
        self.assertEqual(out['chain'], 'IPv4:IGMPv2')
        self.assertEqual(out['layer'], 'pcapkit.protocols.internet.igmpv2.protocol')
        self.assertFalse(out['registry'], 'dispatching a next layer read the name registry')

    def test_a_registration_made_on_import_is_found_by_a_dissector(self) -> 'None':
        """Shim6's entry exists after a bare ``import pcapkit``, so IPv6 parses it as ``IPv6_Ext``."""
        out = run_child('''
            from pcapkit.const.reg.transtype import TransType
            from pcapkit.protocols.internet.internet import Internet
            entry = Internet.__proto__.get(TransType.Shim6)
            entry = None if entry is None else f'{entry.__module__}.{entry.__qualname__}'
            from pcapkit.protocols.internet.ipv6.protocol import IPv6
            udp = struct.pack('>HHHH', 12345, 53, 8 + 8, 0) + b'shim6-ok'
            body = bytes([int(TransType.UDP), 1]) + bytes(14) + udp
            raw = struct.pack('>IHBB', 6 << 28, len(body), int(TransType.Shim6), 64)
            raw += (bytes(15) + bytes([1])) * 2 + body
            packet = IPv6(io.BytesIO(raw), len(raw))
            emit(entry=entry, chain=str(packet.protochain),
                 headers=[type(header).__name__ for _, header in packet.extension_headers.items(multi=True)])
        ''')
        self.assertEqual(out['entry'], 'pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext')
        self.assertEqual(out['headers'], ['IPv6_Ext'])
        self.assertEqual(out['chain'], 'IPv6:IPv6-Ext:UDP:Raw')

    def test_a_selector_reaches_a_class_not_yet_imported(self) -> 'None':
        """``'S_Tag' in`` a C-Tag frame expands through the registry, which imports S_Tag."""
        out = run_child('''
            Ethernet = pcapkit.protocols.link.Ethernet
            tag = bytes([0x81, 0x00, 0x00, 0x01, 0x08, 0x00])
            udp = struct.pack('>HHHH', 1, 2, 8, 0)
            raw = bytes([0xff] * 6) + bytes(range(6)) + tag + ipv4(17, udp)
            frame = Ethernet(io.BytesIO(raw), len(raw))
            before = loaded('pcapkit.protocols.link.s_tag', 'pcapkit.protocols.registry')
            emit(before=before, chain=str(frame.protochain), selected=['S_Tag' in frame, 'C_Tag' in frame],
                 after=loaded('pcapkit.protocols.link.s_tag', 'pcapkit.protocols.registry'))
        ''')
        self.assertEqual(out['before'], [])
        self.assertEqual(out['chain'], 'Ethernet:802.1Q:IPv4:UDP')
        self.assertEqual(out['selected'], [True, True])
        self.assertEqual(out['after'], ['pcapkit.protocols.link.s_tag', 'pcapkit.protocols.registry'])

    def test_the_registry_is_whole_when_first_read(self) -> 'None':
        out = run_child('''
            import pcapkit.protocols as protocols
            from pcapkit.protocols.protocol import ProtocolBase
            before = ['__proto__' in vars(protocols), loaded('pcapkit.protocols.registry')]
            from pcapkit.protocols import __proto__ as registry
            names = [name for name in protocols.__all__ if isinstance(getattr(protocols, name), type)
                     and issubclass(getattr(protocols, name), ProtocolBase)]
            emit(before=before, keys=sorted(registry), names=sorted(name.upper() for name in names),
                 values=all(registry[name.upper()] is getattr(protocols, name) for name in names),
                 same=[registry is protocols.__proto__, registry is vars(protocols)['__proto__'],
                       registry is sys.modules['pcapkit.protocols.registry'].__proto__])
        ''')
        self.assertEqual(out['before'], [False, []])
        self.assertIn('IPV4', out['keys'])
        self.assertEqual(out['keys'], out['names'])
        self.assertTrue(out['values'])
        self.assertEqual(out['same'], [True] * 3)

    def test_a_user_protocol_meets_the_shipped_name_before_any_read(self) -> 'None':
        """Defining a :class:`~pcapkit.protocols.protocol.Protocol` subclass first still warns on a shipped name."""
        out = run_child('''
            from pcapkit.protocols.protocol import Protocol
            from pcapkit.utilities.warnings import RegistryWarning
            before = loaded('pcapkit.protocols.link.ethernet', 'pcapkit.protocols.registry')
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')

                class Ethernet(Protocol):
                    """A user protocol named like the shipped one."""

            emit(before=before, messages=[str(w.message) for w in caught if issubclass(w.category, RegistryWarning)],
                 registered=pcapkit.protocols.__proto__['ETHERNET'] is Ethernet)
        ''')
        self.assertEqual(out['before'], [])
        self.assertEqual(len(out['messages']), 1, out['messages'])
        self.assertIn('pcapkit.protocols.link.ethernet.protocol.Ethernet', out['messages'][0])
        self.assertTrue(out['registered'])

    def test_a_pickle_loads_where_its_class_is_not_yet_imported(self) -> 'None':
        dumped = run_child('''
            from pcapkit.protocols.internet.ipv4.protocol import IPv4
            layer = IPv4(io.BytesIO(ipv4(2, IGMP)), 20 + len(IGMP)).payload
            emit(payload=pickle.dumps(layer).hex(), info=repr(layer.info))
        ''')
        out = run_child(f'''
            before = loaded('pcapkit.protocols.internet.igmpv2')
            layer = pickle.loads(bytes.fromhex({dumped['payload']!r}))
            emit(before=before, layer=f'{{type(layer).__module__}}.{{type(layer).__qualname__}}', info=repr(layer.info))
        ''')
        self.assertEqual(out['before'], [])
        self.assertEqual(out['layer'], 'pcapkit.protocols.internet.igmpv2.protocol.IGMPv2')
        self.assertEqual(out['info'], dumped['info'])


if __name__ == '__main__':
    unittest.main()
