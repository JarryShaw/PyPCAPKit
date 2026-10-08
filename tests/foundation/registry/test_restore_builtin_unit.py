# -*- coding: utf-8 -*-
"""A foundation registrar restores the built-in a name shipped with.

GitHub issue #1363: the public engine, reassembly and flow tracing registrars
refuse pcapkit's own classes (#513, #1016), so once ``register_extractor_engine
('dpkt', MyEngine)`` overrode a built-in, handing ``DPKT`` back raised
:exc:`~pcapkit.utilities.exceptions.RegistryError` and the override could not be
undone. The owner ruled that a registrar accepts the shipped original for a name
it shipped with, and still refuses every other built-in.

The restore must leave each registry exactly as shipped: the same objects,
which are :class:`~pcapkit.corekit.module.ModuleDescriptor` entries, not the
classes they name. That also covers the dumper half of GitHub issue #1364, where
handing a dumper registrar its own shipped entry warned and replaced the
descriptor with the class.

Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, so they
belong to the import the registries live in.

"""

import contextlib
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class


class TestRestoreBuiltin(unittest.TestCase):
    """Override, then restore, every shipped foundation registry entry."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @contextlib.contextmanager
    def _registries(self):  # type: ignore[no-untyped-def]
        """Snapshot the four registries, and put them back afterwards."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        tables = (Extractor.__engine__, Extractor.__reassembly__, Extractor.__traceflow__,
                  Extractor.__output__, TraceFlow.__output__)
        saved = [dict(table) for table in tables]
        try:
            yield saved
        finally:
            for table, copy in zip(tables, saved):
                table.clear()
                table.update(copy)

    def _assert_as_shipped(self, table: 'dict', snapshot: 'dict') -> None:
        self.assertEqual(table.keys(), snapshot.keys())
        for key, entry in snapshot.items():
            with self.subTest(key=key):
                self.assertIs(table[key], entry)

    def _override_then_restore(self, register, key, custom, original, table) -> None:  # type: ignore[no-untyped-def]
        """Override ``key`` with ``custom``, restore ``original``, compare the table."""
        from pcapkit.utilities.warnings import RegistryWarning

        snapshot = dict(table)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            register(key, custom)
        self.assertIs(table[key], custom)
        with self.assertWarns(RegistryWarning):  # the override is what gets overwritten
            register(key, original)
        self._assert_as_shipped(table, snapshot)

    def test_engine_restores_shipped_entry(self) -> None:
        from pcapkit.foundation.engines.dpkt import DPKT
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry import register_extractor_engine

        class MyEngine(Engine):
            pass

        with self._registries():
            self._override_then_restore(register_extractor_engine, 'dpkt', MyEngine, DPKT,
                                        Extractor.__engine__)

    def test_reassembly_restores_shipped_entries(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.reassembly.ipv6 import IPv6
        from pcapkit.foundation.reassembly.reassembly import Reassembly
        from pcapkit.foundation.reassembly.tcp import TCP
        from pcapkit.foundation.registry import register_extractor_reassembly

        class MyReassembly(Reassembly):
            pass

        for key, original in (('ipv4', IPv4), ('ipv6', IPv6), ('tcp', TCP)):
            with self.subTest(protocol=key), self._registries():
                self._override_then_restore(register_extractor_reassembly, key, MyReassembly,
                                            original, Extractor.__reassembly__)

    def test_traceflow_restores_shipped_entry(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry import register_extractor_traceflow
        from pcapkit.foundation.traceflow.tcp import TCP
        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        class MyTraceFlow(TraceFlow):
            pass

        with self._registries():
            self._override_then_restore(register_extractor_traceflow, 'tcp', MyTraceFlow, TCP,
                                        Extractor.__traceflow__)

    def test_dumpers_restore_shipped_entry(self) -> None:
        from dictdumper import JSON, Dumper

        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry import register_dumper
        from pcapkit.foundation.traceflow.traceflow import TraceFlow
        from pcapkit.utilities.warnings import RegistryWarning

        class MyDumper(JSON):
            pass

        self.assertTrue(issubclass(MyDumper, Dumper))
        with self._registries() as saved:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                register_dumper('json', MyDumper, ext='.json')
            with self.assertWarns(RegistryWarning):
                register_dumper('json', JSON, ext='.json')
            self._assert_as_shipped(Extractor.__output__, saved[3])
            self._assert_as_shipped(TraceFlow.__output__, saved[4])

    def test_restore_takes_the_shipped_descriptor(self) -> None:
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry import register_extractor_engine
        from pcapkit.utilities.warnings import RegistryWarning

        class MyEngine(Engine):
            pass

        with self._registries() as saved:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                register_extractor_engine('scapy', MyEngine)
            # an equal descriptor, not the shipped object, still restores the shipped object
            with self.assertWarns(RegistryWarning):
                register_extractor_engine('scapy', 'pcapkit.foundation.engines.scapy', 'Scapy')
            self._assert_as_shipped(Extractor.__engine__, saved[0])

    def test_shipped_descriptor_is_matched_without_import(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry import register_extractor_engine

        with self._registries() as saved, \
                mock.patch.object(ModuleDescriptor, 'klass', new_callable=mock.PropertyMock,
                                  side_effect=AssertionError('descriptor resolved')):
            Extractor.__engine__['pyshark'] = 'overridden'  # type: ignore[assignment]
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                register_extractor_engine('pyshark', saved[0]['pyshark'])
            self._assert_as_shipped(Extractor.__engine__, saved[0])

    def test_reregistering_shipped_original_is_silent_noop(self) -> None:
        from dictdumper import JSON

        from pcapkit.foundation.engines.dpkt import DPKT
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.registry import (register_dumper, register_extractor_engine,
                                                 register_extractor_reassembly,
                                                 register_extractor_traceflow)
        from pcapkit.foundation.traceflow.tcp import TCP
        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        with self._registries() as saved:
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                register_extractor_engine('dpkt', DPKT)
                register_extractor_reassembly('ipv4', IPv4)
                register_extractor_traceflow('tcp', TCP)
                register_dumper('json', JSON, ext='.json')
                Extractor.register_dumper('json', *Extractor.__output__['json'])  # type: ignore[arg-type]
                TraceFlow.register_dumper('json', *TraceFlow.__output__['json'])  # type: ignore[arg-type]
            for table, snapshot in zip((Extractor.__engine__, Extractor.__reassembly__,
                                        Extractor.__traceflow__, Extractor.__output__,
                                        TraceFlow.__output__), saved):
                self._assert_as_shipped(table, snapshot)

    def test_other_builtins_still_refused(self) -> None:
        from pcapkit.foundation.engines.dpkt import DPKT
        from pcapkit.foundation.engines.scapy import Scapy
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.registry import (register_extractor_engine,
                                                 register_extractor_reassembly,
                                                 register_extractor_traceflow)
        from pcapkit.foundation.traceflow.tcp import TCP
        from pcapkit.utilities.exceptions import RegistryError

        cases = (
            (register_extractor_engine, 'zzz', DPKT),       # a built-in under a name it never shipped with
            (register_extractor_engine, 'dpkt', Scapy),     # another name's built-in
            (register_extractor_reassembly, 'ipv6', IPv4),
            (register_extractor_reassembly, 'zzz', IPv4),
            (register_extractor_traceflow, 'zzz', TCP),
        )
        with self._registries() as saved:
            for register, key, klass in cases:
                with self.subTest(key=key, klass=klass.__name__), self.assertRaises(RegistryError):
                    register(key, klass)
            self._assert_as_shipped(Extractor.__engine__, saved[0])
            self._assert_as_shipped(Extractor.__reassembly__, saved[1])
            self._assert_as_shipped(Extractor.__traceflow__, saved[2])


if __name__ == '__main__':
    unittest.main()
