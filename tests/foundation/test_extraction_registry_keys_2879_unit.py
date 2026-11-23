# -*- coding: utf-8 -*-
"""The extractor's name-keyed registries store a name as every lookup reads it. C.f. #2879.

``Extractor.register_engine``, ``register_reassembly`` and ``register_traceflow``
stored their key as given, while ``Extractor(engine=...)``, ``make_reassembly``,
the options classes and the callback registrars look a name up lower-cased. So a
name registered with a capital letter could never be reached. Each registrar
lower-cases its key, refuses one that is not a :obj:`str`, and so restores a
shipped entry however its name is cased.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import importlib.util
import io
import struct
import typing
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: An Ethernet frame of an unfragmented IPv4 datagram carrying UDP to the discard port.
FRAME = (b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00'
         b'\x45\x00\x00\x20\x00\x01\x40\x00\x40\x11\x00\x00\xc0\x00\x02\x01\xc0\x00\x02\x02'
         b'\x04\xd2\x00\x09\x00\x0c\x00\x00data')


def capture(count: int = 2) -> bytes:
    """A microsecond little-endian PCAP savefile of ``count`` copies of :data:`FRAME`."""
    octets = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for second in range(count):
        octets += struct.pack('<IIII', 1000 + second, 0, len(FRAME), len(FRAME)) + FRAME
    return octets


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegistryKeyTests(unittest.TestCase):
    """Registration and lookup share one key rule, in each of the three registries."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.foundation.extraction import Extractor

        for registry in (Extractor.__engine__, Extractor.__reassembly__, Extractor.__traceflow__,
                         PCAP.__reassembly__):
            patcher = mock.patch.dict(registry)
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def engine() -> 'type':
        """A public engine, importable through :mod:`io`, that reads no frame."""
        from pcapkit.foundation.engines.engine import Engine

        class Idle(Engine[str]):
            __engine_name__ = 'Idle'
            __engine_module__ = 'io'

            def run(self) -> None:
                pass

            def read_frame(self) -> str:
                raise EOFError

        return Idle

    @staticmethod
    def reassembly() -> 'type':
        """A public reassembler recording what it is fed."""
        from pcapkit.foundation.reassembly.reassembly import Reassembly

        class Recorder(Reassembly[object, object, typing.Tuple[str], object]):
            __protocol_name__ = 'Recorder'

            def reassembly(self, info: 'Any') -> None:
                self._dtgram.append(info)

            def submit(self, buf: 'Any', **kwargs: 'Any') -> 'list[Any]':
                return []

        return Recorder

    @staticmethod
    def traceflow() -> 'type':
        """A public flow tracer that traces nothing."""
        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        class Silent(TraceFlow[str, object, object, object]):
            def dump(self, packet: 'Any') -> None:
                pass

            def trace(self, packet: 'Any', *, output: bool = False) -> 'Any':
                return object() if output else 'trace'

            def submit(self) -> 'tuple[Any, ...]':
                return ()

        return Silent

    def test_issue_reproduction(self) -> None:
        """#2879: the issue's ``MyProto``, registered mixed-case, is made however it is spelt."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.reassembly import Reassembly
        from pcapkit.foundation.reassembly.tcp import TCP

        class MyProto(TCP, Reassembly):
            pass

        Extractor.register_reassembly('MyProto', MyProto)
        self.assertIs(Extractor.__reassembly__['myproto'], MyProto)
        self.assertNotIn('MyProto', Extractor.__reassembly__)
        for name in ('MyProto', 'myproto', 'MYPROTO'):
            with self.subTest(name=name):
                self.assertIsInstance(Extractor.make_reassembly(name), MyProto)

    def test_mixed_case_reassembly_is_enabled_and_fed(self) -> None:
        """An extractor enables a mixed-case reassembler by name, and its callback reaches it."""
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry.foundation import register_reassembly_callback

        Recorder = self.reassembly()
        Extractor.register_reassembly('ReCorder', Recorder)
        PCAP.register_reassembly('RECORDER', lambda frame: frame.info.number)
        callback = mock.Mock()
        register_reassembly_callback('Recorder', callback)
        self.assertEqual(Recorder.__callback_fn__, [callback])

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = Extractor(io.BytesIO(capture()), reassembly=['Recorder'])
        self.assertEqual(list(extractor._reasm), ['recorder'])
        self.assertEqual(extractor._reasm['recorder']._dtgram, [1, 2])

    def test_mixed_case_traceflow_is_enabled_and_reached(self) -> None:
        """A mixed-case flow tracer passes the extractor's name check and its callback reaches it."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry.foundation import register_traceflow_callback
        from pcapkit.utilities.warnings import AttributeWarning

        Silent = self.traceflow()
        Extractor.register_traceflow('SiLent', Silent)
        self.assertIs(Extractor.__traceflow__['silent'], Silent)
        callback = mock.Mock()
        register_traceflow_callback('SILENT', callback)
        self.assertEqual(Silent.__callback_fn__, [callback])

        # NOTE: no engine feeds a tracer but TCP's, so the name passes and is then dropped.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            Extractor(io.BytesIO(capture()), traceflow=['Silent'])
        self.assertTrue(any(issubclass(warning.category, AttributeWarning)
                            and "'silent' will be ignored" in str(warning.message) for warning in caught))

    def test_mixed_case_engine_runs(self) -> None:
        """``engine=`` reaches an engine registered mixed-case, as the engine registrar does."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry.foundation import register_engine_reassembly

        Idle = self.engine()
        Extractor.register_engine('IdLe', Idle)
        self.assertIs(Extractor.__engine__['idle'], Idle)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = Extractor(io.BytesIO(capture()), engine='Idle')
        self.assertIs(type(extractor.engine), Idle)

        adapter = mock.Mock()
        register_engine_reassembly('IDLE', 'recorder', adapter)
        self.assertIs(Idle.__reassembly__['recorder'], adapter)

    def test_internal_registrars_share_the_rule(self) -> None:
        """The internal doors, which every class hook reaches, lower-case as the public ones do."""
        from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.traceflow.tcp import TCP

        cases = (
            (Extractor._register_internal_engine, Extractor.__engine__, PCAP_Engine),
            (Extractor._register_internal_reassembly, Extractor.__reassembly__, IPv4),
            (Extractor._register_internal_traceflow, Extractor.__traceflow__, TCP),
        )
        for register, registry, klass in cases:
            with self.subTest(registry=register.__name__):
                register('Unit-2879', klass)
                self.assertIs(registry['unit-2879'], klass)
                self.assertNotIn('Unit-2879', registry)

    def test_shipped_name_in_any_case_restores_the_shipped_entry(self) -> None:
        """A built-in handed back under its name in capitals restores, rather than being refused."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.traceflow.tcp import TCP
        from pcapkit.utilities.warnings import RegistryWarning

        cases = (
            (Extractor.register_engine, Extractor.__engine__, 'DPKT',
             Extractor._shipped_engine['dpkt']),
            (Extractor.register_reassembly, Extractor.__reassembly__, 'IPv4', IPv4),
            (Extractor.register_traceflow, Extractor.__traceflow__, 'TCP', TCP),
        )
        for register, registry, name, builtin in cases:
            with self.subTest(name=name):
                before = sorted(registry)
                with warnings.catch_warnings():
                    warnings.simplefilter('error', RegistryWarning)
                    register(name, builtin)
                self.assertEqual(sorted(registry), before)

    def test_mixed_case_name_overwrites_its_entry(self) -> None:
        """Two spellings of one name are one entry, so the second displaces the first with a warning."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.warnings import RegistryWarning

        first, second = self.reassembly(), self.reassembly()
        Extractor.register_reassembly('unit-2879', first)
        with self.assertWarnsRegex(RegistryWarning, 'reassembly unit-2879 already registered'):
            Extractor.register_reassembly('UNIT-2879', second)
        self.assertIs(Extractor.__reassembly__['unit-2879'], second)
        self.assertEqual([name for name in Extractor.__reassembly__ if name.lower() == 'unit-2879'],
                         ['unit-2879'])

    def test_a_name_must_be_a_str(self) -> None:
        """A name that is not a :obj:`str` is refused, writing nothing, rather than stored unreachable."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.traceflow.tcp import TCP
        from pcapkit.utilities.exceptions import RegistryError

        cases = (
            ('engine', Extractor.register_engine, Extractor.__engine__, self.engine()),
            ('engine', Extractor._register_internal_engine, Extractor.__engine__, self.engine()),
            ('reassembly', Extractor.register_reassembly, Extractor.__reassembly__, self.reassembly()),
            ('reassembly', Extractor._register_internal_reassembly, Extractor.__reassembly__, IPv4),
            ('traceflow', Extractor.register_traceflow, Extractor.__traceflow__, self.traceflow()),
            ('traceflow', Extractor._register_internal_traceflow, Extractor.__traceflow__, TCP),
        )
        for kind, register, registry, klass in cases:
            with self.subTest(registrar=register.__name__):
                with self.assertRaisesRegex(RegistryError, f'{kind} name must be a str, not 2879'):
                    register(2879, klass)  # type: ignore[arg-type]
                self.assertNotIn(2879, registry)
        with self.assertRaisesRegex(RegistryError, 'reassembly name must be a str, not 2879'):
            Extractor.make_reassembly(2879)  # type: ignore[arg-type]


if __name__ == '__main__':
    unittest.main()
