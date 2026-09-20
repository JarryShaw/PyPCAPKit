from __future__ import annotations

import importlib.util
import sys
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ReassemblyBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_base_cache_datagram_index_run_and_callbacks(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase

        @info_final
        class DummyPacket(Info):
            value: int

        @info_final
        class DummyDatagram(Info):
            index: tuple[int, ...]
            total: int

        @info_final
        class DummyBuffer(Info):
            entries: list[int]

        class DummyProtocol:
            pass

        class DummyReassembly(ReassemblyBase[DummyPacket, DummyDatagram, tuple[str], DummyBuffer]):
            __protocol_name__ = 'Dummy'
            __protocol_type__ = DummyProtocol

            def reassembly(self, info: DummyPacket) -> None:
                super().reassembly(info)
                self._buffer.setdefault(('dummy',), DummyBuffer([])).entries.append(info.value)

            def submit(self, buf: DummyBuffer, **kwargs: object) -> list[DummyDatagram]:
                ret = [DummyDatagram(tuple(buf.entries), sum(buf.entries))]
                for callback in self.__callback_fn__:
                    callback(ret)
                return ret

        callback_calls: list[list[DummyDatagram]] = []
        leading_calls: list[list[DummyDatagram]] = []
        DummyReassembly.register(callback_calls.append)
        DummyReassembly.register(leading_calls.append, index=0)

        reasm = DummyReassembly()
        self.assertEqual(DummyReassembly.name, 'Dummy')
        self.assertIs(DummyReassembly.protocol, DummyProtocol)
        self.assertEqual(reasm.name, 'Dummy')
        self.assertIs(reasm.protocol, DummyProtocol)

        reasm.run([DummyPacket(1), DummyPacket(2)])
        reasm._dtgram.append(DummyDatagram((99,), 99))

        fetched = reasm.fetch()
        self.assertEqual([item.total for item in fetched], [3, 99])
        self.assertIs(reasm.fetch(), fetched)
        self.assertEqual(reasm.count, 2)
        self.assertEqual(reasm.count, 2)
        reasm._flag_n = True
        self.assertEqual(reasm.count, 2)
        reasm._flag_n = True
        self.assertEqual([item.total for item in reasm.fetch()], [3, 99])
        self.assertEqual(reasm.index(1), 0)
        self.assertEqual(reasm.index(99), 1)
        self.assertIsNone(reasm.index(404))
        self.assertEqual(len(callback_calls), 3)
        self.assertEqual(len(leading_calls), 3)

        reasm(DummyPacket(4))
        self.assertEqual(reasm.fetch()[0].total, 7)

    def test_store_false_blocks_datagram_and_instance_metadata_overrides(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
        from pcapkit.utilities.exceptions import UnsupportedCall

        @info_final
        class DummyPacket(Info):
            value: int

        @info_final
        class DummyDatagram(Info):
            index: tuple[int, ...]

        @info_final
        class DummyBuffer(Info):
            entries: list[int]

        class BaseFallback(ReassemblyBase[DummyPacket, DummyDatagram, tuple[str], DummyBuffer]):
            def reassembly(self, info: DummyPacket) -> None:
                super().reassembly(info)

            def submit(self, buf: DummyBuffer, **kwargs: object) -> list[DummyDatagram]:
                return []

        class InstanceProtocol:
            pass

        reasm = BaseFallback(store=False)
        self.assertEqual(BaseFallback.name, 'BaseFallback')
        self.assertEqual(reasm.name, 'BaseFallback')
        self.assertEqual(BaseFallback.protocol.__name__, 'Raw')
        self.assertEqual(reasm.protocol.__name__, 'Raw')

        reasm.__protocol_name__ = 'instance'
        reasm.__protocol_type__ = InstanceProtocol
        self.assertEqual(reasm.name, 'instance')
        self.assertIs(reasm.protocol, InstanceProtocol)

        with self.assertRaises(UnsupportedCall):
            _ = reasm.datagram

    def test_reassembly_subclass_registration_is_opt_in(self) -> None:
        """Registration happens if and only if ``protocol`` is given.

        This is the #514 opt-in contract; see the sibling test in
        ``tests/foundation/engines/test_engine_base.py`` for the full rationale.

        """
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.foundation.reassembly.reassembly import Reassembly

        @info_final
        class DummyPacket(Info):
            value: int

        @info_final
        class DummyDatagram(Info):
            index: tuple[int, ...]

        @info_final
        class DummyBuffer(Info):
            entries: list[int]

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_reassembly') as register:
            class Explicit(Reassembly[DummyPacket, DummyDatagram, tuple[str], DummyBuffer],
                           protocol='ExampleProto'):
                def reassembly(self, info: DummyPacket) -> None:
                    super().reassembly(info)

                def submit(self, buf: DummyBuffer, **kwargs: object) -> list[DummyDatagram]:
                    return []

        register.assert_called_once_with('exampleproto', Explicit)
        self.assertEqual(Explicit.__callback_fn__, [])

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_reassembly') as register:
            class Default(Reassembly[DummyPacket, DummyDatagram, tuple[str], DummyBuffer]):
                __protocol_name__ = 'DefaultProto'

                def reassembly(self, info: DummyPacket) -> None:
                    super().reassembly(info)

                def submit(self, buf: DummyBuffer, **kwargs: object) -> list[DummyDatagram]:
                    return []

        # #514: registration is opt-in. Before it, the absent keyword fell back to
        # ``cls.name`` -- i.e. ``__protocol_name__`` here -- and this registered
        # under ``'defaultproto'``. A class attribute is not a registry key.
        register.assert_not_called()
        self.assertEqual(Default.name, 'DefaultProto')
        self.assertEqual(Default.__callback_fn__, [])

    def test_reassembly_subclass_rejects_unrecognised_keyword(self) -> None:
        """A misspelled class keyword raises instead of being swallowed.

        It used to land in ``**kwargs``, get dropped by the bare
        ``super().__init_subclass__()``, and leave the class registered under its
        own class name -- no exception, no warning.

        The keyword used here is deliberately *not* ``name``. Four class keyword
        names -- ``mcls``, ``name``, ``bases`` and ``namespace`` -- collide with
        :meth:`abc.ABCMeta.__new__`'s own parameters, which are
        positional-or-keyword on Python 3.10 and positional-only from 3.11. On
        3.10 the collision therefore raises :exc:`TypeError` from the metaclass
        *before* ``__init_subclass__`` is reached, so testing the guard with
        ``name=`` would only exercise it on 3.11+. Measured on 3.10.21, 3.11.15
        and 3.14.7. The colliding case is pinned separately below.

        """
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.foundation.reassembly.reassembly import Reassembly
        from pcapkit.utilities.exceptions import UnsupportedCall

        @info_final
        class DummyPacket(Info):
            value: int

        @info_final
        class DummyDatagram(Info):
            index: tuple[int, ...]

        @info_final
        class DummyBuffer(Info):
            entries: list[int]

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_reassembly') as register:
            with self.assertRaises(UnsupportedCall) as caught:
                class Typo(Reassembly[DummyPacket, DummyDatagram, tuple[str], DummyBuffer],
                           reassembly='wrong-keyword-for-reassembly'):
                    def reassembly(self, info: DummyPacket) -> None:
                        super().reassembly(info)

                    def submit(self, buf: DummyBuffer, **kwargs: object) -> list[DummyDatagram]:
                        return []

        register.assert_not_called()
        self.assertIn('reassembly', str(caught.exception))

        # ``name=`` is the mistake a user actually makes, by analogy with
        # ``Engine``, and it is one of the four colliding names -- so which
        # exception surfaces is version-dependent. Pinned rather than skipped, so
        # the 3.10 behaviour is recorded rather than merely untested.
        expected = UnsupportedCall if sys.version_info >= (3, 11) else TypeError
        with mock.patch('pcapkit.foundation.extraction.Extractor.register_reassembly') as register:
            with self.assertRaises(expected):
                class Collides(Reassembly[DummyPacket, DummyDatagram, tuple[str], DummyBuffer],
                               name='collides-with-ABCMeta-on-3.10'):
                    def reassembly(self, info: DummyPacket) -> None:
                        super().reassembly(info)

                    def submit(self, buf: DummyBuffer, **kwargs: object) -> list[DummyDatagram]:
                        return []

        register.assert_not_called()

    def test_reassembly_registry_property_reads_the_extractor_table(self) -> None:
        """``Reassembly.registry`` is a class-level accessor, as on ``EnumSchema``."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.reassembly import Reassembly

        self.assertIs(Reassembly.registry, Extractor.__reassembly__)


if __name__ == '__main__':
    unittest.main()
