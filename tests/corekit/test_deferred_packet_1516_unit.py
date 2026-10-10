# -*- coding: utf-8 -*-
"""GitHub issue #1516: one :class:`~pcapkit.corekit.packet.DeferredPacket` for
reassembly and flow tracing.

There used to be two copies of the mixin, in
``pcapkit/foundation/reassembly/data/data.py`` and
``pcapkit/foundation/traceflow/data/data.py``. Their method bodies were
AST-identical, and the one thing that differed was which module-level
``Deferred`` the ``isinstance`` test named. The merged class takes that
difference as the ``__deferred__`` hook each subclass sets, so a model resolves
its own placeholder class and nothing else.

:class:`DeferredPacketTests` pins the shared class against a placeholder of its
own, so it holds whatever either subsystem later does with the mixin.
:class:`WiringTests` pins the three real models.

Each test imports what it needs itself, rather than the module importing it at
the top. On a tree without :mod:`pcapkit.corekit.packet`, every test then fails
on its own instead of the module failing to collect.

"""

import ast
import importlib
import pathlib
import types
import unittest

#: The module under test, read as source by the import-layering check.
MODULE = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit' / 'corekit' / 'packet.py'

#: The three models, as ``(module, class, module holding its placeholder)``.
MODELS = (
    ('pcapkit.foundation.reassembly.data.ip', 'Datagram', 'pcapkit.foundation.reassembly.data.data'),
    ('pcapkit.foundation.reassembly.data.tcp', 'Datagram', 'pcapkit.foundation.reassembly.data.data'),
    ('pcapkit.foundation.traceflow.data.tcp', 'Index', 'pcapkit.foundation.traceflow.data.data'),
)


class Placeholder:
    """Counts its own calls, and answers with a fixed result."""

    def __init__(self, result: 'object') -> 'None':
        self.result = result
        self.calls = 0

    def __call__(self) -> 'object':
        self.calls += 1
        return self.result


class Unrelated:
    """Callable as well, but not the class a holder names."""

    def __init__(self) -> 'None':
        self.calls = 0

    def __call__(self) -> 'object':
        self.calls += 1
        return 'must not be called'


def holder_class() -> 'type':
    """A fresh model that keeps the contract, holding :class:`Placeholder`."""
    from pcapkit.corekit.infoclass import Info, info_final
    from pcapkit.corekit.packet import DeferredPacket

    @info_final
    class Holder(DeferredPacket, Info):
        __additional__ = ['packet']
        __deferred__ = Placeholder

        name: 'str'
        packet: 'object'

    return Holder


class DeferredPacketTests(unittest.TestCase):
    """The shared class, against a placeholder of the test's own."""

    def setUp(self) -> 'None':
        self.result = {'parsed': True}
        self.placeholder = Placeholder(self.result)
        self.holder = holder_class()(name='x', packet=self.placeholder)

    def test_construction_does_not_resolve(self) -> 'None':
        self.assertEqual(self.placeholder.calls, 0)
        self.assertNotIn('packet', self.holder.__dict__)
        self.assertIs(self.holder.__dict__[self.holder.__map__['packet']], self.placeholder)

    def test_reading_packet_resolves_exactly_once(self) -> 'None':
        first = self.holder.packet
        self.assertIs(first, self.result)
        self.assertEqual(self.placeholder.calls, 1)

        # every later read, by whatever route, returns the same object without
        # calling the placeholder again
        self.assertIs(self.holder.packet, first)
        self.assertIs(self.holder['packet'], first)
        self.assertIs(self.holder.to_dict()['packet'], first)
        self.assertIs(dict(self.holder)['packet'], first)
        str(self.holder)
        repr(self.holder)
        self.assertEqual(self.placeholder.calls, 1)

    def test_views_report_the_field_by_name_without_resolving(self) -> 'None':
        self.assertIn('packet', self.holder)
        self.assertEqual(list(self.holder), ['name', 'packet'])
        self.assertEqual(list(self.holder.keys()), ['name', 'packet'])
        self.assertEqual(len(self.holder), 2)
        self.assertEqual(self.placeholder.calls, 0)

    def test_every_reader_resolves_once_and_reports_packet_by_name(self) -> 'None':
        readers = {
            'to_dict': lambda holder: holder.to_dict()['packet'],
            'dict': lambda holder: dict(holder)['packet'],
            'getitem': lambda holder: holder['packet'],
            'get': lambda holder: holder.get('packet'),
            'items': lambda holder: dict(holder.items())['packet'],
        }
        for (reader, read) in readers.items():
            with self.subTest(reader=reader):
                placeholder = Placeholder(self.result)
                holder = holder_class()(name='x', packet=placeholder)
                self.assertIs(read(holder), self.result)
                self.assertEqual(placeholder.calls, 1)

        for render in (str, repr):
            with self.subTest(reader=render.__name__):
                placeholder = Placeholder(self.result)
                holder = holder_class()(name='x', packet=placeholder)
                text = render(holder)
                self.assertIn("packet={'parsed': True}", text)
                self.assertNotIn('Placeholder', text)
                self.assertEqual(placeholder.calls, 1)

    def test_only_the_named_placeholder_class_is_resolved(self) -> 'None':
        """``__deferred__`` is a hook on the class, not a test for "callable"."""
        unrelated = Unrelated()
        function = types.SimpleNamespace(calls=0)

        def callback() -> 'None':
            function.calls += 1

        for value in (unrelated, callback, None, ('a', 'b')):
            with self.subTest(value=type(value).__name__):
                holder = holder_class()(name='x', packet=value)
                self.assertIs(holder.packet, value)
                self.assertIs(holder.to_dict()['packet'], value)
        self.assertEqual(unrelated.calls, 0)
        self.assertEqual(function.calls, 0)

    def test_an_unknown_attribute_still_raises_without_resolving(self) -> 'None':
        self.assertFalse(hasattr(self.holder, 'nope'))
        with self.assertRaises(AttributeError):
            self.holder.nope  # pylint: disable=pointless-statement
        self.assertEqual(self.placeholder.calls, 0)

    def test_a_subclass_must_list_packet_in_additional(self) -> 'None':
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.packet import DeferredPacket
        from pcapkit.utilities.exceptions import InfoError

        with self.assertRaisesRegex(InfoError, r"Unlisted: 'packet' is not listed in __additional__"):
            class Unlisted(DeferredPacket, Info):  # pylint: disable=unused-variable
                __deferred__ = Placeholder
                packet: 'object'

    def test_a_subclass_must_name_its_placeholder_class(self) -> 'None':
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.packet import DeferredPacket
        from pcapkit.utilities.exceptions import InfoError

        with self.assertRaisesRegex(InfoError, r'Unnamed: __deferred__ does not name the placeholder class'):
            class Unnamed(DeferredPacket, Info):  # pylint: disable=unused-variable
                __additional__ = ['packet']
                packet: 'object'

        with self.assertRaisesRegex(InfoError, r'Instance: __deferred__ does not name the placeholder class'):
            class Instance(DeferredPacket, Info):  # pylint: disable=unused-variable
                __additional__ = ['packet']
                __deferred__ = Placeholder(None)
                packet: 'object'

    def test_the_module_imports_nothing_from_foundation_or_protocols(self) -> 'None':
        """``corekit`` sits below both, so the mixin may not reach up to either."""
        tree = ast.parse(MODULE.read_text(encoding='utf-8'))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, f'relative import at line {node.lineno}')
                imported.append(node.module or '')
        self.assertTrue(imported)
        for name in imported:
            with self.subTest(module=name):
                self.assertFalse(name.startswith(('pcapkit.foundation', 'pcapkit.protocols')), name)


class WiringTests(unittest.TestCase):
    """The three real models share the one class, each with its own placeholder."""

    def test_every_model_shares_the_one_class_mixin_first(self) -> 'None':
        from pcapkit.corekit.packet import DeferredPacket

        for (module, name, deferred_module) in MODELS:
            with self.subTest(model=f'{module}.{name}'):
                cls = getattr(importlib.import_module(module), name)
                self.assertIs(cls.__mro__[1], DeferredPacket)
                self.assertIn('packet', cls.__additional__)
                self.assertIs(cls.__deferred__, importlib.import_module(deferred_module).Deferred)

    def test_the_old_import_paths_resolve_to_the_one_class(self) -> 'None':
        """The name was public at all three before the move, and still is.

        Each path is the class object itself rather than a copy of it, so the
        two old definitions really are gone and nothing can diverge again.

        """
        from pcapkit.corekit.packet import DeferredPacket

        self.assertEqual(DeferredPacket.__module__, 'pcapkit.corekit.packet')
        for module in ('pcapkit.foundation.reassembly.data',
                       'pcapkit.foundation.reassembly.data.data',
                       'pcapkit.foundation.traceflow.data.data'):
            with self.subTest(module=module):
                imported = importlib.import_module(module)
                self.assertIs(imported.DeferredPacket, DeferredPacket)
                self.assertIn('DeferredPacket', imported.__all__)

    def test_each_model_resolves_its_own_placeholder_and_not_the_other(self) -> 'None':
        from pcapkit.corekit.packet import DeferredPacket
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.data.data import Deferred as ReassemblyDeferred
        from pcapkit.foundation.reassembly.data.ip import Datagram as IP_Datagram
        from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
        from pcapkit.foundation.traceflow.data.data import Deferred as TraceFlowDeferred
        from pcapkit.foundation.traceflow.data.tcp import Index

        def reassembly() -> 'ReassemblyDeferred':
            return ReassemblyDeferred(lambda proto, payload: ('parsed', proto, payload), 'proto', b'payload')

        def traceflow() -> 'TraceFlowDeferred':
            return TraceFlowDeferred(types.SimpleNamespace(datagram=('reassembled',)))  # type: ignore[arg-type]

        def datagram(cls: 'type', packet: 'object') -> 'DeferredPacket':
            return cls(completed=Completion.COMPLETE, id=None, index=(1,), header=b'',
                       payload=b'payload', packet=packet, conflict=())

        def index(packet: 'object') -> 'DeferredPacket':
            return Index(fpout=None, index=(1,), label='label', forward=(1,), reverse=(), packet=packet)

        cases = (
            ('ip', lambda packet: datagram(IP_Datagram, packet), reassembly, traceflow,
             ('parsed', 'proto', b'payload')),
            ('tcp', lambda packet: datagram(TCP_Datagram, packet), reassembly, traceflow,
             ('parsed', 'proto', b'payload')),
            ('trace', index, traceflow, reassembly, ('reassembled',)),
        )
        for (label, build, own, other, expected) in cases:
            with self.subTest(model=label):
                self.assertEqual(build(own()).packet, expected)
                foreign = other()
                self.assertIs(build(foreign).packet, foreign)


if __name__ == '__main__':
    unittest.main()
