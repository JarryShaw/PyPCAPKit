# -*- coding: utf-8 -*-
""":obj:`None` is an extraction's only no stop, as for the protocols (GitHub issue #2840).

``Extractor`` keeps accepting ``layer='none'`` and :data:`pcapkit.RAW`, and maps them to
:obj:`None` before any engine reads them, since a protocol no longer reads ``'none'``
or ``'null'`` as no stop:

* :class:`StopTests` -- ``_exlyr`` and ``_exptl`` are :obj:`None` unless a stop is
  given, and the default engine hands its frames and its reassemblers the stops and
  the ``context`` by their parse names;
* :class:`ThirdPartyEngineTests` -- an engine that ignores the stops warns of it only
  when one is set, checked on the installed engines; the other engines' modules pin it
  on fixtures.

The captures are built in memory; no sample capture is read.

"""
from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any

#: An Ethernet frame of IPv4 and TCP, whose payload no port dispatches.
FRAME = wire.ethernet(wire.ipv4(wire.tcp(b'payload', seq=1), proto=6), 0x0800)

#: A PCAP of :data:`FRAME`, twice.
CAPTURE = wire.pcap([(1500000000, 0, FRAME), (1500000001, 0, FRAME)])


class StopTests(unittest.TestCase):
    """The default engine's stops are :obj:`None` unless given."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def extract(self, **kwargs: 'Any') -> 'Any':
        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(CAPTURE), store=True, **kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_an_omitted_or_raw_stop_is_none(self) -> None:
        from pcapkit import RAW

        for kwargs in ({}, {'layer': RAW}, {'layer': 'NONE'}, {'layer': None, 'protocol': None}):
            with self.subTest(kwargs=kwargs):
                extractor = self.extract(**kwargs)
                self.assertIsNone(extractor._exlyr)  # pylint: disable=protected-access
                self.assertIsNone(extractor._exptl)  # pylint: disable=protected-access
                self.assertEqual([str(frame.protochain) for frame in extractor.frame],
                                 ['Ethernet:IPv4:TCP:Raw'] * 2)

    def test_a_given_stop_is_kept(self) -> None:
        extractor = self.extract(layer='Internet', protocol='TCP')
        self.assertEqual((extractor._exlyr, extractor._exptl), ('internet', 'TCP'))  # pylint: disable=protected-access
        self.assertEqual(type(extractor.frame[0]['IPv4'].payload).__name__, 'Raw')

    def test_the_engine_hands_the_stops_and_the_context_by_their_parse_names(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp.protocol import ESPContext

        keywords = self.extract()._exeng._frame_keywords()  # pylint: disable=protected-access
        self.assertEqual(keywords, {})

        extractor = self.extract(layer='Transport', protocol='TCP', context=ESPContext())
        keywords = extractor._exeng._frame_keywords()  # pylint: disable=protected-access
        self.assertEqual(set(keywords), {'layer', 'protocol', 'context'})
        self.assertEqual((keywords['layer'], keywords['protocol']), ('transport', 'TCP'))
        self.assertIsInstance(keywords['context'], ContextRegistry)


@unittest.skipUnless(importlib.util.find_spec('dpkt') or importlib.util.find_spec('scapy'),
                     'neither DPKT nor Scapy installed')
class ThirdPartyEngineTests(unittest.TestCase):
    """An engine that ignores the stops warns only when one is set."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        directory = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(directory.cleanup)
        self.path = os.path.join(directory.name, 'frames.pcap')
        with open(self.path, 'wb') as file:
            file.write(CAPTURE)

    def warned(self, engine: str, **kwargs: 'Any') -> 'list[str]':
        """The threshold warnings ``engine`` gives while extracting :data:`CAPTURE`."""
        from pcapkit import extract

        # NOTE: Observed on ``warn``, as outside development mode the category is not the
        # one ``warnings`` sees (cf. the engine modules' own threshold tests).
        with mock.patch(f'pcapkit.foundation.engines.{engine}.warn') as warn, warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=self.path, engine=engine, store=True, **kwargs)
        self.addCleanup(close_extractor, extractor)
        return [call.args[0] for call in warn.call_args_list if 'threshold' in call.args[0]]

    def test_the_warning_fires_only_with_a_stop(self) -> None:
        from pcapkit import RAW

        for engine in ('dpkt', 'scapy'):
            if importlib.util.find_spec(engine) is None:
                continue
            with self.subTest(engine=engine):
                self.assertEqual(self.warned(engine), [])
                self.assertEqual(self.warned(engine, layer=RAW), [])
                self.assertEqual(self.warned(engine, layer='Internet'),
                                 [f"'Extractor(engine={engine})' does not support protocol and layer "
                                  "threshold; 'layer=internet' and 'protocol=None' ignored"])


if __name__ == '__main__':
    unittest.main()
