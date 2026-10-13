# -*- coding: utf-8 -*-
"""A copied, deep-copied or pickled DPKT timestamp keeps all three of its attributes. C.f. #1647.

:func:`copy.copy` and :func:`copy.deepcopy` look up ``__copy__`` and
``__deepcopy__`` before ``__reduce_ex__``, and :class:`decimal.Decimal` defines
both, so :class:`~pcapkit.toolkit.dpkt.DecimalTimestamp`'s own
:meth:`~object.__reduce__` was never asked. The C :mod:`_decimal` returns
``self``. The pure-Python :mod:`_pydecimal` returns ``self.__class__(str(self))``,
which resets ``resolution`` and ``orig_len`` to the constructor's defaults. CPython
3.15 no longer falls back to its bundled libmpdec, so a build on a host without
the library has no :mod:`_decimal` -- the ``actions/setup-python`` 3.15.0 build
reports it missing -- and CI's 3.15 leg alone lost them.

The in-process tests run under whichever implementation this interpreter has;
:class:`PurePythonDecimalTests` reruns them under :mod:`_pydecimal` in a fresh
interpreter, so the defect is reproduced on every leg. Every value is built
here, so the module is in the unit tier.

"""
from __future__ import annotations

import copy
import decimal
import json
import os
import pickle
import subprocess  # nosec: B404
import sys
import unittest
from typing import TYPE_CHECKING

from tests.corekit._roundtrip import skip_without_runtime

if TYPE_CHECKING:
    from typing import Any, Iterator

    from pcapkit.toolkit.dpkt import RecordTimestamp

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: Rerun :func:`clones` over :func:`stamps` with :mod:`_decimal` unimportable, as
#: :mod:`decimal` finds it on a CPython built without it, and report the results.
SCRIPT = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
sys.modules['_decimal'] = None

import _pydecimal, decimal, pcapkit
from pcapkit.toolkit.dpkt import DecimalTimestamp
from tests.toolkit.test_dpkt_timestamp_copy_1647_unit import clones, describe, stamps

print(json.dumps({
    'file': pcapkit.__file__,
    'pure': decimal.Decimal is _pydecimal.Decimal and issubclass(DecimalTimestamp, _pydecimal.Decimal),
    'results': [[describe(stamp), way, describe(clone)] for stamp in stamps() for way, clone in clones(stamp)],
}))
'''


def stamps() -> 'list[RecordTimestamp]':
    """One timestamp of each type.

    Neither resolution is its constructor's default, and the :obj:`float`'s exact
    value is not the float itself, so a clone rebuilt from the value alone is
    caught on every attribute.

    """
    from pcapkit.toolkit.dpkt import DecimalTimestamp, Timestamp

    return [Timestamp(1500000000.000774, decimal.Decimal('1500000000.000774'), 1_000_000_000, 78),
            DecimalTimestamp(decimal.Decimal('1500000000.000774789'), 1_000_000, 78)]


def clones(stamp: 'RecordTimestamp') -> 'Iterator[tuple[str, Any]]':
    """``stamp`` through :func:`copy.copy`, :func:`copy.deepcopy` and every pickle protocol."""
    yield 'copy', copy.copy(stamp)
    yield 'deepcopy', copy.deepcopy(stamp)
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        yield f'pickle-{protocol}', pickle.loads(pickle.dumps(stamp, protocol=protocol))  # nosec: B301


def describe(stamp: 'Any') -> 'list[Any]':
    """``stamp``'s type, value and attributes, as JSON can carry them."""
    return [type(stamp).__name__, str(stamp), str(stamp.exact), stamp.resolution, stamp.orig_len]


class RecordTimestampCopyTests(unittest.TestCase):
    """Under this interpreter's :mod:`decimal`."""

    def setUp(self) -> None:
        skip_without_runtime(self)

    def test_every_protocol_keeps_every_attribute(self) -> None:
        for stamp in stamps():
            for way, clone in clones(stamp):
                with self.subTest(type=type(stamp).__name__, way=way):
                    self.assertIs(type(clone), type(stamp))
                    self.assertEqual(clone, stamp)
                    self.assertEqual(describe(clone), describe(stamp))

    def test_a_deep_copy_keeps_aliasing(self) -> None:
        for stamp in stamps():
            with self.subTest(type=type(stamp).__name__):
                first, second = copy.deepcopy([stamp, stamp])
                self.assertIs(first, second)
                self.assertEqual(describe(first), describe(stamp))

    def test_the_base_class_does_not_guess(self) -> None:
        # a subclass says how it is rebuilt; the base has nothing to rebuild from
        from pcapkit.toolkit.dpkt import RecordTimestamp

        for way in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(way=way.__name__), self.assertRaises(NotImplementedError):
                way(RecordTimestamp())


class PurePythonDecimalTests(unittest.TestCase):
    """Under :mod:`_pydecimal`, in a fresh interpreter started from the repository root."""

    def setUp(self) -> None:
        skip_without_runtime(self)

    def test_every_protocol_keeps_every_attribute(self) -> None:
        proc = subprocess.run([sys.executable, '-c', SCRIPT, ROOT],  # nosec: B603
                              cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
        if proc.returncode:
            raise AssertionError(proc.stderr)
        result = json.loads(proc.stdout.splitlines()[-1])
        self.assertEqual(os.path.dirname(os.path.dirname(result['file'])), ROOT)
        self.assertTrue(result['pure'], 'the child did not run on _pydecimal')
        self.assertEqual(len(result['results']), 2 * (pickle.HIGHEST_PROTOCOL + 3))
        for want, way, got in result['results']:
            with self.subTest(type=want[0], way=way):
                self.assertEqual(got, want)


if __name__ == '__main__':
    unittest.main()
