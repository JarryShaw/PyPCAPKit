# -*- coding: utf-8 -*-
"""Scaffolding shared by the end-to-end integration modules.

The modules next to this one drive :mod:`pcapkit` the way a user does -- a
capture in, a report file or a reassembled datagram out -- so they all need the
same three things: the dependency gates that decide whether the runtime is
usable at all, a private scratch directory to write reports into, and a couple
of readers for the report formats. Those live here rather than in
:mod:`tests._support`, which is shared with the unit tiers and is deliberately
free of anything this specific.

Nothing in this file is collected by :program:`pytest`: ``python_files`` in
:file:`pyproject.toml` is ``test_*.py``.

"""
from __future__ import annotations

import collections
import importlib.util
import json
import pathlib
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from tests._support import close_extractor, purge_modules

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.foundation.extraction import Extractor

__all__ = [
    'HAS_RUNTIME', 'HAS_DPKT', 'HAS_SCAPY', 'HAS_EMOJI',
    'EndToEndTestCase',
    'read_json', 'plist_keys', 'section_counts', 'report_stems',
]

#: Packages :mod:`pcapkit` needs before it can parse anything at all.
RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
#: Whether the runtime dependencies are importable.
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
#: Whether the :mod:`dpkt` extraction engine can be selected.
HAS_DPKT = importlib.util.find_spec('dpkt') is not None
#: Whether the :mod:`scapy` extraction engine can be selected.
HAS_SCAPY = importlib.util.find_spec('scapy') is not None
#: Whether the command line tool's ``cli`` extra is installed.
HAS_EMOJI = importlib.util.find_spec('emoji') is not None


class EndToEndTestCase(unittest.TestCase):
    """Base class for the end-to-end modules.

    Gives every test a private temporary directory in :attr:`tmp_path` and an
    :meth:`extract` wrapper that closes the input stream on teardown. Captures
    under :file:`examples/captures/` are fixtures -- some of them committed --
    so nothing here ever writes outside :attr:`tmp_path`.

    """

    @classmethod
    def setUpClass(cls) -> None:
        """Drop the imported library so the class starts from a clean state.

        The surrounding tiers purge in :meth:`setUp`, i.e. once per test. A
        fresh :mod:`pcapkit` import measures at roughly 0.7s on this machine,
        which across this tier would cost more than the extractions themselves,
        so the purge happens once per class instead. That is equivalent here:
        every test below imports :mod:`pcapkit` inside the test method, so none
        of them depends on what an earlier test left in :data:`sys.modules`.

        The re-import on the last line is what keeps it once per class, and it
        has to happen here rather than being left to the first test.
        :func:`tests.conftest.restore_module_table` snapshots the module table
        immediately after this method and restores to that snapshot after every
        test, so purging without re-importing makes the snapshot an *empty*
        table -- and then all 92 of this tier's test methods pay the 0.7s each,
        rather than one per class across its 28 classes. Measured with a
        throwaway subclass of this class whose second and third test methods
        report whether ``pcapkit`` is still in :data:`sys.modules`: ``True`` on
        ``mainline`` and ``True`` with this line, ``False`` without it. The other
        ``setUpClass`` methods in the suite are unaffected because each already
        loads something immediately after its own purge, which populates the
        table before the snapshot is taken.

        The re-import is guarded because it is an optimisation and nothing more,
        so it must not be able to turn a test failure into a class error. Most
        subclasses carry ``@skipUnless(HAS_RUNTIME, ...)`` and never reach this
        method without the runtime dependencies installed, but
        ``PlistRoundTripTests`` and ``PcapngUnescapedKeyTests`` do not, so on a
        checkout without them an unguarded ``import`` here would raise
        :exc:`ModuleNotFoundError` out of ``setUpClass`` and error the whole
        class, where before it was the individual tests that failed. Swallowed,
        the table simply stays cold and those tests fail exactly as they did.
        :exc:`BaseException` is deliberately not caught, for the same reason as
        in :func:`tests._support._close_quietly`.

        """
        purge_modules(['pcapkit'])
        try:
            importlib.import_module('pcapkit')
        except Exception:  # pragma: no cover  # pylint: disable=broad-except
            pass

    def setUp(self) -> None:
        """Hand the test a private scratch directory."""
        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-e2e-')
        self.addCleanup(tmpdir.cleanup)
        self.tmp_path = pathlib.Path(tmpdir.name)

    def out(self, name: str) -> 'str':
        """Absolute path to ``name`` inside this test's scratch directory."""
        return str(self.tmp_path / name)

    def extract(self, **kwargs: 'Any') -> 'Extractor':
        """Run :func:`pcapkit.interface.extract`, closing the input on teardown."""
        from pcapkit.interface import extract

        extractor = extract(**kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor


def read_json(path: 'str') -> 'dict[str, Any]':
    """Parse a report written with ``format='json'``."""
    with open(path, encoding='utf-8') as stream:
        return json.load(stream)


def plist_keys(path: 'str') -> 'list[str]':
    """Top-level keys of a report written with ``format='plist'``.

    Read with :mod:`xml.etree.ElementTree` rather than :mod:`plistlib`, because
    the dumper emits ``<date>`` values that :mod:`plistlib` rejects; see
    ``PlistRoundTripTests`` in :mod:`tests.integration.test_output_formats`.

    """
    root = ET.parse(path).getroot()
    if root.tag != 'plist':
        raise AssertionError(f'not a plist document: {root.tag}')
    return [key.text or '' for key in root[0].findall('key')]


def section_counts(report: 'dict[str, Any]') -> 'collections.Counter[str]':
    """Count the report's top-level sections by kind.

    ``'Frame 1'``, ``'Frame 2'`` and so on collapse to ``'Frame'``, and the
    PCAP-NG block sections likewise, so a report can be described by what it
    contains rather than by listing every key.

    """
    return collections.Counter(re.sub(r' \d+$', '', key) for key in report)


def report_stems(directory: 'str') -> 'list[str]':
    """Sorted section names of the reports ``files=True`` wrote into ``directory``.

    Split at the *first* dot, which keeps the callers' assertions about *which*
    sections a report holds independent of what the extension happens to be.

    This used to be neutrality about the number of dots as well: per-frame
    reports were named ``f'{name}.{ext._fext}'`` while ``_fext`` still carried
    its own leading dot, so they landed on disk as ``Frame 1..json`` (#358).
    That is fixed -- the extension is bare now, and
    :mod:`tests.integration.test_files_output_naming` asserts the real names --
    so nothing here is working around it any more.

    """
    return sorted(entry.name.split('.', 1)[0] for entry in pathlib.Path(directory).iterdir())
