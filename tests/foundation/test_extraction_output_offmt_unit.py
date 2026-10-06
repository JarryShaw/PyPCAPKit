# -*- coding: utf-8 -*-
"""Regression tests for three :class:`~pcapkit.foundation.extraction.Extractor` defects -- #1095.

* :attr:`Extractor.output` on a ``nofile=True`` extractor named the wrong
  attribute, ``format``, in its :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`.
* :meth:`Extractor.make_name` subscripted the ``__output__`` defaultdict, so an
  unknown format was inserted into the registry before
  :exc:`~pcapkit.utilities.exceptions.FormatError` was raised.
* The `Scapy`_ engine never set ``Extractor._offmt``, so :attr:`Extractor.format`
  raised :exc:`AttributeError` after a file-producing extraction.

.. _Scapy: https://scapy.net

"""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import warnings

from pcapkit.foundation.extraction import Extractor
from pcapkit.interface import extract
from pcapkit.utilities.exceptions import FormatError, UnsupportedCall
from tests._support import sample_path

HAS_SCAPY = importlib.util.find_spec('scapy') is not None


class OutputMessageTests(unittest.TestCase):
    """:attr:`Extractor.output` names itself when output is disabled."""

    def test_nofile_output_names_output(self) -> None:
        """The :exc:`UnsupportedCall` message names ``output``, not ``format``."""
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=sample_path('in.pcap'), nofile=True)
        with self.assertRaises(UnsupportedCall) as ctx:
            extractor.output  # pylint: disable=pointless-statement
        self.assertEqual(str(ctx.exception),
                         "'Extractor(nofile=True)' object has no attribute 'output'")


class MakeNameRegistryTests(unittest.TestCase):
    """An unknown format leaves ``Extractor.__output__`` untouched."""

    def test_unknown_format_is_not_inserted(self) -> None:
        """The registry keys are unchanged after :exc:`FormatError`."""
        before = set(Extractor.__output__)
        self.assertNotIn('bogus-1095', before)
        with self.assertRaises(FormatError):
            Extractor.make_name(sample_path('in.pcap'), None, 'bogus-1095', nofile=False)
        self.assertEqual(set(Extractor.__output__), before)


@unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
class ScapyFormatTests(unittest.TestCase):
    """The `Scapy`_ engine records the output format like every other engine."""

    def test_scapy_engine_sets_format(self) -> None:
        """:attr:`Extractor.format` reads back the requested format."""
        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=sample_path('in.pcap'), fout=os.path.join(tmp, 'out'),
                                engine='scapy', format='json', nofile=False)
            self.assertEqual(extractor.format, 'json')


if __name__ == '__main__':
    unittest.main()
