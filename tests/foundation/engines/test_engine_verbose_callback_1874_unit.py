# -*- coding: utf-8 -*-
"""A callback given as ``verbose`` reaches every frame on every engine (#1874).

:class:`~pcapkit.foundation.extraction.Extractor` keeps a callable ``verbose``
as its ``_vfunc``, but each third-party engine installed its own printer
whenever verbose output was on, so the caller's callback was replaced and never
called. An engine installs its printer only for ``verbose=True``.

Each case runs a real extraction of :file:`in.pcap`, which git tracks, so the
module is unit tier. It proves first that the requested engine ran: the
extractor falls back to the default engine, with an
:class:`~pcapkit.utilities.warnings.EngineWarning`, when it cannot run the one
requested, and that would pass the callback case vacuously. An engine that
cannot run here is skipped, with the reason the extractor itself would give.

"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class, sample_path

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from pcapkit.foundation.engines.engine import EngineBase
    from pcapkit.foundation.extraction import Extractor

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The capture every case reads, a little-endian PCAP.
CAPTURE = 'in.pcap'


def _record_count(fin: 'str') -> 'int':
    """Count the records of a little-endian PCAP by walking its record headers."""
    with open(fin, 'rb') as file:
        rest = file.read()[24:]
    count = 0
    while rest:
        incl_len, = struct.unpack('<I', rest[8:12])
        rest = rest[16 + incl_len:]
        count += 1
    return count


class _VerboseCases:
    """The cases, run on one engine by each :class:`unittest.TestCase` below."""

    #: The engine under test, as ``Extractor(engine=...)`` names it.
    ENGINE: 'str'

    def setUp(self: 'Any') -> None:
        reimport_once_per_class(self)
        reason = self.unavailable()
        if reason is not None:
            self.skipTest(f'the {self.ENGINE} engine cannot run here: {reason}')

    def engine_class(self) -> 'Type[EngineBase]':
        """The class that runs :attr:`ENGINE`."""
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor

        entry = Extractor.__engine__[self.ENGINE]
        return entry.klass if isinstance(entry, ModuleDescriptor) else entry

    def unavailable(self) -> 'Optional[str]':
        """Why the extractor would not run :attr:`ENGINE` here, if it would not.

        These are the checks ``Extractor._select_engine`` makes, in its order.

        """
        from pcapkit.foundation.extraction import Extractor

        engine = self.engine_class()
        reason = engine.unsupported_reason()
        if reason is not None:
            return reason
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            if Extractor.import_test(engine.module, name=engine.name) is None:  # type: ignore[arg-type]
                return f'{engine.module} is not installed'
        return None

    def chain(self, extractor: 'Extractor', frame: 'Any') -> 'str':
        """The protocol chain the engine's own printer reports for ``frame``."""
        raise NotImplementedError

    def extract(self: 'Any', verbose: 'Any') -> 'tuple[Extractor, str]':
        """Extract :data:`CAPTURE` on :attr:`ENGINE`; return it and its stdout."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.warnings import EngineWarning

        out = io.StringIO()
        with warnings.catch_warnings(record=True) as caught, contextlib.redirect_stdout(out):
            warnings.simplefilter('always')
            extractor = Extractor(fin=sample_path(CAPTURE), engine=self.ENGINE,  # type: ignore[arg-type]
                                  nofile=True, store=True, verbose=verbose)
        self.addCleanup(close_extractor, extractor)

        # the requested engine ran, not the default one it would fall back to
        self.assertEqual([str(item.message) for item in caught
                          if issubclass(item.category, EngineWarning)], [])
        self.assertEqual(extractor._exnam, self.ENGINE)
        self.assertIs(type(extractor._exeng), self.engine_class())
        self.assertEqual(len(extractor.frame), _record_count(sample_path(CAPTURE)))
        return extractor, out.getvalue()

    def test_a_verbose_callback_is_called_with_every_frame(self: 'Any') -> None:
        calls = []  # type: list[tuple[Extractor, Any]]
        extractor, out = self.extract(lambda ext, frame: calls.append((ext, frame)))

        frames = extractor.frame
        self.assertEqual(len(calls), len(frames))
        for (ext, frame), stored in zip(calls, frames):
            self.assertIs(ext, extractor)
            self.assertIs(frame, stored)
        # and the engine's own printer did not run in its place
        self.assertEqual(out, '')

    def test_verbose_true_prints_the_engines_own_chain(self: 'Any') -> None:
        extractor, out = self.extract(True)

        self.assertEqual(out.splitlines(), [
            f'Frame {number:>3d}: {self.chain(extractor, frame)}'
            for number, frame in enumerate(extractor.frame, 1)
        ])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DefaultEngineVerboseTests(_VerboseCases, unittest.TestCase):
    """The built-in PCAP engine, which always kept the callback."""

    ENGINE = 'default'

    def engine_class(self) -> 'Type[EngineBase]':
        from pcapkit.foundation.engines.pcap import PCAP

        return PCAP

    def unavailable(self) -> 'Optional[str]':
        return None

    def chain(self, extractor: 'Extractor', frame: 'Any') -> 'str':
        return str(frame.protochain)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ScapyVerboseTests(_VerboseCases, unittest.TestCase):
    ENGINE = 'scapy'

    def chain(self, extractor: 'Extractor', frame: 'Any') -> 'str':
        from pcapkit.toolkit.scapy import packet2chain

        return packet2chain(frame)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DPKTVerboseTests(_VerboseCases, unittest.TestCase):
    ENGINE = 'dpkt'

    def chain(self, extractor: 'Extractor', frame: 'Any') -> 'str':
        from pcapkit.toolkit.dpkt import packet2chain

        return packet2chain(frame)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PySharkVerboseTests(_VerboseCases, unittest.TestCase):
    ENGINE = 'pyshark'

    def chain(self, extractor: 'Extractor', frame: 'Any') -> 'str':
        from pcapkit.foundation.engines.pyshark import _frame_layer

        return _frame_layer(frame).protocols  # type: ignore[union-attr]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPVerboseTests(_VerboseCases, unittest.TestCase):
    ENGINE = 'pypcap'

    def chain(self, extractor: 'Extractor', frame: 'Any') -> 'str':
        from pcapkit.toolkit.pypcap import packet2chain

        return packet2chain(frame[1], data_link=extractor._exeng._dlink)  # type: ignore[attr-defined]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAP_CTVerboseTests(_VerboseCases, unittest.TestCase):
    ENGINE = 'pcap_ct'

    def chain(self, extractor: 'Extractor', frame: 'Any') -> 'str':
        from pcapkit.toolkit.pcap_ct import packet2chain

        return packet2chain(frame[1], data_link=extractor._exeng._dlink)  # type: ignore[attr-defined]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileVerboseTests(_VerboseCases, unittest.TestCase):
    ENGINE = 'pypcapfile'

    def chain(self, extractor: 'Extractor', frame: 'Any') -> 'str':
        from pcapkit.toolkit.pypcapfile import packet2chain

        return packet2chain(frame, data_link=extractor._exeng._dlink)  # type: ignore[attr-defined]


if __name__ == '__main__':
    unittest.main()
