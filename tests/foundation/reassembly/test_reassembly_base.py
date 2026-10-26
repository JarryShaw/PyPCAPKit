from __future__ import annotations

import importlib.util
import sys
import unittest
from typing import Tuple
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): branches on the running interpreter's version or implementation.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ReassemblyBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

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

        class DummyReassembly(ReassemblyBase[DummyPacket, DummyDatagram, Tuple[str], DummyBuffer]):
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

        class BaseFallback(ReassemblyBase[DummyPacket, DummyDatagram, Tuple[str], DummyBuffer]):
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
            class Explicit(Reassembly[DummyPacket, DummyDatagram, Tuple[str], DummyBuffer],
                           protocol='ExampleProto'):
                def reassembly(self, info: DummyPacket) -> None:
                    super().reassembly(info)

                def submit(self, buf: DummyBuffer, **kwargs: object) -> list[DummyDatagram]:
                    return []

        register.assert_called_once_with('exampleproto', Explicit)
        self.assertEqual(Explicit.__callback_fn__, [])

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_reassembly') as register:
            class Default(Reassembly[DummyPacket, DummyDatagram, Tuple[str], DummyBuffer]):
                __protocol_name__ = 'DefaultProto'

                def reassembly(self, info: DummyPacket) -> None:
                    super().reassembly(info)

                def submit(self, buf: DummyBuffer, **kwargs: object) -> list[DummyDatagram]:
                    return []

        # #514: registration is opt-in. A fallback for the absent keyword to
        # ``cls.name`` -- i.e. ``__protocol_name__`` here -- would register this
        # under ``'defaultproto'``. A class attribute is not a registry key.
        register.assert_not_called()
        self.assertEqual(Default.name, 'DefaultProto')
        self.assertEqual(Default.__callback_fn__, [])

    def test_reassembly_subclass_rejects_unrecognised_keyword(self) -> None:
        """A misspelled class keyword raises instead of being swallowed.

        Guards against it landing in ``**kwargs``, being dropped by a bare
        ``super().__init_subclass__()``, and leaving the class registered under
        its own class name -- no exception, no warning.

        The keyword used here is deliberately *not* ``name``. Four class keyword
        names -- ``mcls``, ``name``, ``bases`` and ``namespace`` -- collide with
        :meth:`abc.ABCMeta.__new__`'s own parameters, which are
        positional-or-keyword before Python 3.11 and positional-only from 3.11.
        Below 3.11 the collision therefore raises :exc:`TypeError` from the metaclass
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
                class Typo(Reassembly[DummyPacket, DummyDatagram, Tuple[str], DummyBuffer],
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
        # the behaviour below 3.11 is recorded rather than merely untested.
        expected = UnsupportedCall if sys.version_info >= (3, 11) else TypeError
        with mock.patch('pcapkit.foundation.extraction.Extractor.register_reassembly') as register:
            with self.assertRaises(expected):
                class Collides(Reassembly[DummyPacket, DummyDatagram, Tuple[str], DummyBuffer],
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
