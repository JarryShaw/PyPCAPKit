# -*- coding: utf-8 -*-
"""The TCP and UDP app-type registries load on first use, not with ``pcapkit``.

GitHub issue #1538. :mod:`pcapkit.const.reg.apptype.tcp` and
:mod:`~pcapkit.const.reg.apptype.udp` are generated from IANA's registry and
hold about 49,700 lines of members between them; ``python -X importtime -c
'import pcapkit'`` put them at 104 ms and 102 ms of a 700 ms import. Nothing on
any import path needs them, so :mod:`pcapkit.const.reg.apptype` imports them
from a :pep:`562` ``__getattr__`` and from
:attr:`AppType.__registries__ <pcapkit.const.reg.apptype.apptype.AppType.__registries__>`
the first time either is read.

The subprocess checks run in a fresh interpreter, since the question is what a
cold ``import pcapkit`` leaves in :data:`sys.modules` and this process has long
since imported both. Each fails on an eager tree at its first ``loaded()``
check; what follows it pins that nothing a caller can observe changed apart
from *when* the import happens. :class:`RegistriesMappingTests` and
:class:`PackageGetattrTests` run in-process, on a private import, so that
coverage sees every line. :class:`PinnedSnapshotTests` covers the suite's own
side: :file:`tests/conftest.py` has to pin both registries, or its restore
leaves a second generation of each behind.

"""

import importlib.util
import inspect
import json
import os
import pathlib
import subprocess
import sys
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from types import ModuleType
    from typing import Any

#: Test tier (#1958): branches on the running interpreter's version or implementation.
__tier__ = 'ALL'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The names ``dir(pcapkit.const.reg.apptype)`` listed on the eager package
#: besides those the import system sets. Those are not pinned, since they vary
#: by interpreter -- Python 3.15 no longer sets ``__cached__`` (:gh:`97879`,
#: GitHub issue #1648) -- so :func:`eager_dir` reads them off the running one.
PACKAGE_NAMES = ['AppType', 'DCCP', 'SCTP', 'TCP', 'TransportProtocol', 'UDP', '__all__',
                 'apptype', 'dccp', 'sctp', 'tcp', 'udp']

#: Whether :obj:`dict` has union, :pep:`584`. Before Python 3.9, a registry has
#: none either (GitHub issue #1694), so the union views run from 3.9 only.
UNION = sys.version_info >= (3, 9)


def merge(left: 'Any', right: 'Any') -> 'Any':
    """``left |= right``, as an expression."""
    left |= right
    return left


#: Each dict union operator, as a function of its two operands.
UNIONS = {'|': lambda left, right: left | right, '|=': merge}


def union_error(op: 'str', left: 'object', right: 'object') -> 'str':
    """The :exc:`TypeError` message for ``left <op> right`` where neither supports it."""
    return (f'unsupported operand type(s) for {op}: '
            f'{type(left).__name__!r} and {type(right).__name__!r}')


def import_system_names(module: 'ModuleType') -> 'list[str]':
    """``dir(module)`` as importing it would leave it, were its body empty.

    An import is :func:`importlib.util.module_from_spec`, which sets the
    attributes the spec implies, then the loader's ``exec_module``, which runs
    the body with :func:`exec` in the module's namespace and so adds
    ``__builtins__``. Both run here on ``module``'s own spec, so the names are
    the ones this interpreter, and the loader that imported ``module``, set.
    :data:`PRELUDE` carries this function's source into each child.

    """
    fresh = importlib.util.module_from_spec(module.__spec__)  # type: ignore[arg-type]
    exec('', vars(fresh))  # pylint: disable=exec-used
    return dir(fresh)


def eager_dir(interpreter: 'list[str]') -> 'list[str]':
    """``dir()`` of the eager package, given :func:`import_system_names` of it."""
    if not set(interpreter).isdisjoint(PACKAGE_NAMES):
        raise AssertionError(f'the import system set a name the package defines: {interpreter}')
    return sorted({*PACKAGE_NAMES, *interpreter})


PRELUDE = f'''
import importlib.util, json, sys
import pcapkit
assert pcapkit.__file__.startswith({str(ROOT)!r}), pcapkit.__file__

def loaded():
    return [name for name in ('tcp', 'udp')
            if f'pcapkit.const.reg.apptype.{{name}}' in sys.modules]

def emit(**kwargs):
    print(json.dumps(kwargs))

''' + inspect.getsource(import_system_names)

#: ``repr(AppType.__registries__)`` once populated, eager or lazy.
REGISTRIES_REPR = ("{<TransportProtocol.tcp: 1>: <aenum 'TCP'>, <TransportProtocol.udp: 2>: "
                   "<aenum 'UDP'>, <TransportProtocol.sctp: 3>: <aenum 'SCTP'>, "
                   "<TransportProtocol.dccp: 4>: <aenum 'DCCP'>}")


def run_child(code: 'str') -> 'dict':
    """Run :data:`PRELUDE` then ``code`` in a fresh interpreter; return its last
    :func:`emit` line."""
    environ = dict(os.environ)
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH') else [str(ROOT)])
    result = subprocess.run([sys.executable, '-c', PRELUDE + textwrap.dedent(code)],
                            cwd=str(ROOT), env=environ, capture_output=True, text=True,
                            timeout=300, check=False)
    if result.returncode != 0:
        raise AssertionError(f'child exited {result.returncode}:\n{result.stderr}')
    return json.loads(result.stdout.splitlines()[-1])


class LazyAppTypeImportTests(unittest.TestCase):
    """What a cold import loads, and what loads each registry afterwards."""

    def test_import_pcapkit_leaves_tcp_and_udp_unimported(self) -> 'None':
        out = run_child('''
            emit(loaded=loaded(),
                 eager=[f'pcapkit.const.reg.apptype.{name}' in sys.modules
                        for name in ('apptype', 'sctp', 'dccp')])
        ''')
        self.assertEqual(out['loaded'], [])
        self.assertEqual(out['eager'], [True, True, True])

    def test_attribute_access_loads_only_the_registry_it_names(self) -> 'None':
        out = run_child('''
            import pcapkit.const.reg.apptype as pkg
            steps = [loaded()]
            tcp = pkg.TCP
            steps.append(loaded())
            udp = pkg.udp.UDP
            steps.append(loaded())
            emit(steps=steps,
                 same=[tcp is sys.modules['pcapkit.const.reg.apptype.tcp'].TCP,
                       udp is pkg.UDP, pkg.TCP is pkg.tcp.TCP, 'TCP' in vars(pkg)])
        ''')
        self.assertEqual(out['steps'], [[], ['tcp'], ['tcp', 'udp']])
        self.assertEqual(out['same'], [True, True, True, True])

    def test_port_lookup_loads_only_the_transport_it_asks_for(self) -> 'None':
        out = run_child('''
            from pcapkit.const.reg.apptype import AppType, TransportProtocol
            steps = [loaded()]
            http = AppType.get(80, proto='tcp')
            steps.append(loaded())
            dns = AppType.get(53, proto=TransportProtocol.udp)
            steps.append(loaded())
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
        ''')
        self.assertEqual(out['dir'], eager_dir(out['interpreter']))
        self.assertEqual(out['before'], [])
        self.assertEqual(out['star'], sorted(out['all']))
        self.assertEqual(out['resolved'], [True] * 6)
        self.assertEqual(out['after'], ['tcp', 'udp'])

    def test_registries_never_expose_a_pending_registry(self) -> 'None':
        # NOTE: one interpreter for every view, so each starts from the pending
        # state again rather than from whatever the previous view loaded.
        out = run_child('''
            import copy
            from pcapkit.const.reg.apptype import AppType, TransportProtocol
            from pcapkit.corekit.module import ModuleDescriptor
            registries = AppType.__registries__
            shape = [len(registries), [int(key) for key in registries],
                     1 in registries, TransportProtocol.udp in registries, loaded()]
            populated = dict(registries)
            views = {
                'getitem': lambda: registries[TransportProtocol.tcp],
                'get': lambda: registries.get(1),
                'dict': lambda: dict(registries),
                'unpack': lambda: {**registries},
                'values': lambda: list(registries.values()),
                'items': lambda: dict(registries.items()),
                'copy': registries.copy,
                'copy.copy': lambda: dict(copy.copy(registries)),
                'repr': lambda: registries,
                'eq': lambda: registries == populated,
                'ne': lambda: registries != populated,
            }
            if sys.version_info >= (3, 9):  # dict union, PEP 584
                views.update({'or': lambda: registries | {}, 'ror': lambda: {} | registries})
            reprs = {}
            for name, view in views.items():
                for proto in (TransportProtocol.tcp, TransportProtocol.udp):
                    dict.__setitem__(registries, proto, ModuleDescriptor(
                        f'pcapkit.const.reg.apptype.{proto.name}', proto.name.upper()))
                reprs[name] = repr(view())
            emit(shape=shape, reprs=reprs, default=registries.get(0, 'fallback'))
        ''')
        self.assertEqual(out['shape'], [4, [1, 2, 3, 4], True, True, []])
        self.assertEqual(len(out['reprs']), 13 if UNION else 11)
        self.assertEqual({'or', 'ror'} <= set(out['reprs']), UNION)
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
            from pcapkit.const.reg.apptype.tcp import TCP
            emit(payload=pickle.dumps(TCP.http).hex())
        ''')['payload']
        out = run_child(f'''
            import copy, pickle
            before = loaded()
            member = pickle.loads(bytes.fromhex({payload!r}))
            from pcapkit.const.reg.apptype import TCP
            emit(before=before, after=loaded(),
                 same=[member is TCP.http, copy.copy(member) is member,
                       copy.deepcopy(member) is member])
        ''')
        self.assertEqual(out['before'], [])
        self.assertEqual(out['after'], ['tcp'])
        self.assertEqual(out['same'], [True, True, True])

    def test_port_registered_before_first_use_dispatches_the_same(self) -> 'None':
        code = '''
            from pcapkit.foundation.registry import register_tcp
            from pcapkit.protocols.transport.tcp import TCP
            if {lookup_first}:
                import pcapkit.const.reg.apptype
                pcapkit.const.reg.apptype.TCP
            at_register = loaded()
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


class RegistriesMappingTests(unittest.TestCase):
    """Every method of the lazy mapping, on a private instance in this process."""

    def setUp(self) -> 'None':
        # NOTE: a private import, so that the package starts cold -- the shared
        # one has both registries loaded, since tests/conftest.py pins them --
        # and nothing bound here outlives the class.
        reimport_once_per_class(self, restore=True)
        self.make()

    def make(self) -> 'None':
        from pcapkit.const.reg.apptype import _Registries  # type: ignore[attr-defined]
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, TransportProtocol
        from pcapkit.corekit.module import ModuleDescriptor

        self.proto = TransportProtocol
        self.classes = [TCP, UDP, SCTP, DCCP]
        self.descriptor = ModuleDescriptor
        self.registries = _Registries({
            TransportProtocol.tcp: ModuleDescriptor('pcapkit.const.reg.apptype.tcp', 'TCP'),
            TransportProtocol.udp: ModuleDescriptor('pcapkit.const.reg.apptype.udp', 'UDP'),
            TransportProtocol.sctp: SCTP,
            TransportProtocol.dccp: DCCP,
        })

    def assert_pending(self, *protos: 'object') -> 'None':
        raw = dict.items(self.registries)
        self.assertEqual([key for key, value in raw if isinstance(value, self.descriptor)],
                         list(protos))

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

    def test_whole_mapping_reads_resolve_everything(self) -> 'None':
        proto, classes = self.proto, self.classes
        expected = dict(zip(list(proto)[1:], classes))
        views = {
            'values': lambda registries: list(registries.values()) == classes,
            'items': lambda registries: dict(registries.items()) == expected,
            'copy': lambda registries: registries.copy() == expected,
            'dict': lambda registries: dict.__eq__(dict(registries), expected),
            'eq': lambda registries: registries == expected,
            'ne': lambda registries: (registries != expected) is False,
            'repr': lambda registries: 'ModuleDescriptor' not in repr(registries),
            'pop': lambda registries: registries.pop(proto.tcp) is classes[0],
            'popitem': lambda registries: registries.popitem() == (proto.dccp, classes[3]),
            'setdefault': lambda registries: registries.setdefault(proto.udp) is classes[1],
        }
        if UNION:
            views.update({
                'or': lambda registries: dict.__eq__(registries | {}, expected),
                'ror': lambda registries: dict.__eq__({} | registries, expected),
            })
        for name, view in views.items():
            with self.subTest(view=name):
                self.make()
                self.assertTrue(view(self.registries))
                self.assert_pending()

    def test_union_is_dict_s_on_every_python(self) -> 'None':
        # NOTE: GitHub issue #1694. Where dict has no union (Python < 3.9), a
        # registry raises dict's TypeError, naming its own type, and imports
        # nothing; where it does, ``registries |= other`` is dict's in-place
        # update, which reads no value and so leaves the registry pending.
        proto, expected = self.proto, dict(zip(list(self.proto)[1:], self.classes))
        for op, side in (('|', 'left'), ('|', 'right'), ('|=', 'left'), ('|=', 'right')):
            with self.subTest(op=op, side=side):
                self.make()
                operands = (self.registries, {}) if side == 'left' else ({}, self.registries)
                if not UNION:
                    with self.assertRaises(TypeError) as plain:
                        UNIONS[op]({}, {})
                    with self.assertRaises(TypeError) as registry:
                        UNIONS[op](*operands)
                    self.assertEqual(str(plain.exception), union_error(op, {}, {}))
                    self.assertEqual(str(registry.exception), union_error(op, *operands))
                    self.assert_pending(proto.tcp, proto.udp)
                elif (op, side) == ('|=', 'left'):
                    self.assertIs(UNIONS[op](*operands), self.registries)
                    self.assert_pending(proto.tcp, proto.udp)
                    self.assertEqual(self.registries, expected)
                else:
                    result = UNIONS[op](*operands)
                    self.assertIs(type(result), dict)
                    self.assertTrue(dict.__eq__(result, expected))
                    self.assert_pending()
        for name in ('__or__', '__ror__'):
            self.assertIs(name in vars(type(self.registries)), UNION)
        self.assertNotIn('__ior__', vars(type(self.registries)))


class PackageGetattrTests(unittest.TestCase):
    """The :pep:`562` hooks, called in this process so that coverage sees them."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self, restore=True)  # see RegistriesMappingTests.setUp

    def test_hooks(self) -> 'None':
        import pcapkit.const.reg.apptype as pkg

        self.assertNotIn('TCP', vars(pkg))
        self.assertNotIn('pcapkit.const.reg.apptype.tcp', sys.modules)
        getattr_ = vars(pkg)['__getattr__']
        tcp_module = getattr_('tcp')
        self.assertIs(tcp_module, sys.modules['pcapkit.const.reg.apptype.tcp'])
        self.assertIs(getattr_('TCP'), tcp_module.TCP)
        self.assertIs(vars(pkg)['TCP'], tcp_module.TCP)
        for name in ('Tcp', 'tCP', 'sctp_', 'nope'):
            with self.subTest(name=name), self.assertRaises(AttributeError):
                getattr_(name)
        self.assertEqual(vars(pkg)['__dir__'](), eager_dir(import_system_names(pkg)))


class SharedImportProbe(unittest.TestCase):
    """Two tests on the shared import, with the conftest restore between them.

    The first binds both registries through the package; the second imports
    their submodules directly. Unless :data:`tests.conftest.WARM_MODULES` puts
    them in the pinned snapshot, the restore drops them in between and the
    second test builds another ``TCP`` and ``UDP``. :mod:`unittest` runs the
    two in name order, and :class:`PinnedSnapshotTests` runs them in one
    :program:`pytest` process, so they meet that restore whatever runs this file.

    """

    def test_1_bind_through_the_package(self) -> 'None':
        import pcapkit.const.reg.apptype as pkg
        from pcapkit.const.reg.apptype import AppType

        self.assertIs(type(AppType.get(80, proto='tcp')), pkg.TCP)
        self.assertIs(type(AppType.get(53, proto='udp')), pkg.UDP)

    def test_2_import_the_submodules_directly(self) -> 'None':
        import pcapkit.const.reg.apptype as pkg
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.const.reg.apptype.tcp import TCP
        from pcapkit.const.reg.apptype.udp import UDP

        self.assertIs(TCP, pkg.TCP)
        self.assertIs(UDP, pkg.UDP)
        self.assertIs(AppType.__registries__[TransportProtocol.tcp], TCP)
        self.assertIs(AppType.__registries__[TransportProtocol.udp], UDP)


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
