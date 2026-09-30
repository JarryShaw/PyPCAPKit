# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.vendor.ngap`'s pycrate-sourced crawlers.

GitHub issue #880's owner ruling for the ``ngap.py`` half of the defect: unlike
the four closed :mod:`pcapkit.protocols.internet.mh` helper enums #877 ruled
on, :class:`~pcapkit.const.ngap.procedure_code.ProcedureCode` and
:class:`~pcapkit.const.ngap.protocol_ie.ProtocolIE` are genuinely open per
3GPP TS 38.413, and the fix is to source their real assignment from |pycrate|_
through a vendor crawler rather than hand-maintaining the list or minting a
value at lookup time. This module tests the crawler half of that: that
:meth:`~pcapkit.vendor.ngap.procedure_code.ProcedureCode._request` reads
|pycrate|_'s own compiled specification correctly, that its output matches the
generated :mod:`pcapkit.const.ngap` modules exactly, that two independent
calls agree (the property that makes ``pcapkit-vendor``'s regeneration
reproducible), and that the two registries partition |pycrate|_'s
``NGAP_Constants`` disjointly.

This never fetches anything over the network -- see the module docstring on
:mod:`pcapkit.vendor.ngap.procedure_code` for why: |pycrate|_ is an
already-installed optional dependency, not a network registry, so
:meth:`_request` only ever imports it.

.. |pycrate| replace:: ``pycrate``
.. _pycrate: https://github.com/pycrate-org/pycrate

"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from unittest import mock

HAS_PYCRATE = importlib.util.find_spec('pycrate_asn1dir') is not None


@unittest.skipUnless(HAS_PYCRATE, "the optional 'pycrate' dependency is not installed")
class NGAPVendorCrawlerTests(unittest.TestCase):
    """:meth:`_request` against the real, installed |pycrate|_ package."""

    def test_procedure_code_request_matches_the_generated_const_module(self) -> None:
        from pcapkit.const.ngap.procedure_code import ProcedureCode as Generated
        from pcapkit.vendor.ngap.procedure_code import ProcedureCode as Crawler

        # ``object.__new__`` bypasses ``Vendor.__init__`` -- and so its file
        # write -- entirely; ``_request`` needs no instance state.
        entries = object.__new__(Crawler)._request()  # type: ignore[misc]

        self.assertEqual(len(entries), 81)

        names = [name for name, _ in entries]
        self.assertEqual(len(names), len(set(names)), 'pycrate named a duplicate identifier')
        values = [value for _, value in entries]
        self.assertEqual(len(values), len(set(values)), 'pycrate assigned a duplicate value')

        self.assertEqual(len(Generated.__members__), len(entries))
        for name, value in entries:
            with self.subTest(name=name):
                self.assertIn(name, Generated.__members__)
                self.assertEqual(int(Generated[name]), value)  # type: ignore[misc]

    def test_protocol_ie_request_matches_the_generated_const_module(self) -> None:
        from pcapkit.const.ngap.protocol_ie import ProtocolIE as Generated
        from pcapkit.vendor.ngap.protocol_ie import ProtocolIE as Crawler

        entries = object.__new__(Crawler)._request()  # type: ignore[misc]

        self.assertEqual(len(entries), 438)

        names = [name for name, _ in entries]
        self.assertEqual(len(names), len(set(names)), 'pycrate named a duplicate identifier')
        values = [value for _, value in entries]
        self.assertEqual(len(values), len(set(values)), 'pycrate assigned a duplicate value')

        self.assertEqual(len(Generated.__members__), len(entries))
        for name, value in entries:
            with self.subTest(name=name):
                self.assertIn(name, Generated.__members__)
                self.assertEqual(int(Generated[name]), value)  # type: ignore[misc]

    def test_request_is_reproducible_across_two_independent_calls(self) -> None:
        """Byte-reproducibility starts here: if two calls disagreed, the
        generated const file could not be either -- ``pcapkit-vendor`` run
        twice would produce two different files from the same installed
        |pycrate|_.
        """
        from pcapkit.vendor.ngap.procedure_code import ProcedureCode as ProcCrawler
        from pcapkit.vendor.ngap.protocol_ie import ProtocolIE as IECrawler

        for crawler_cls in (ProcCrawler, IECrawler):
            with self.subTest(crawler=crawler_cls.__qualname__):
                first = object.__new__(crawler_cls)._request()  # type: ignore[misc]
                second = object.__new__(crawler_cls)._request()  # type: ignore[misc]
                self.assertEqual(first, second)
                self.assertIsNot(first, second)

    def test_procedure_code_and_protocol_ie_partition_ngap_constants_disjointly(self) -> None:
        """Each crawler claims its own ``NGAP-CommonDataTypes`` open type; no
        identifier should ever be read by both."""
        from pcapkit.vendor.ngap.procedure_code import ProcedureCode as ProcCrawler
        from pcapkit.vendor.ngap.protocol_ie import ProtocolIE as IECrawler

        proc_names = {name for name, _ in object.__new__(ProcCrawler)._request()}  # type: ignore[misc]
        ie_names = {name for name, _ in object.__new__(IECrawler)._request()}  # type: ignore[misc]

        self.assertEqual(proc_names & ie_names, set())
        self.assertEqual(len(proc_names), 81)
        self.assertEqual(len(ie_names), 438)

    def test_count_needs_no_duplicate_bookkeeping(self) -> None:
        """Neither crawler's :meth:`~pcapkit.vendor.default.Vendor.rename`
        path is ever reached (pycrate names each assignment once), so
        :meth:`count` is overridden to a trivial, always-empty
        :class:`collections.Counter` rather than the CSV-oriented base
        implementation, which would fail outright on this crawler's
        ``(name, value)`` tuples."""
        import collections

        from pcapkit.vendor.ngap.procedure_code import ProcedureCode as ProcCrawler
        from pcapkit.vendor.ngap.protocol_ie import ProtocolIE as IECrawler

        for crawler_cls in (ProcCrawler, IECrawler):
            with self.subTest(crawler=crawler_cls.__qualname__):
                crawler = object.__new__(crawler_cls)  # type: ignore[misc]
                data = crawler._request()
                self.assertEqual(crawler.count(data), collections.Counter())

    def test_context_renders_the_current_generated_file_byte_for_byte(self) -> None:
        """:meth:`context` is what :meth:`~pcapkit.vendor.default.Vendor.
        __init__` writes to disk; comparing its output against the committed
        generated file directly (rather than re-running ``pcapkit-vendor`` and
        diffing files) proves the same reproducibility without ever touching
        the filesystem."""
        import pathlib

        from pcapkit.vendor.ngap.procedure_code import ProcedureCode as ProcCrawler
        from pcapkit.vendor.ngap.protocol_ie import ProtocolIE as IECrawler

        repo_root = pathlib.Path(__file__).resolve().parents[2]
        for crawler_cls, relpath in (
            (ProcCrawler, 'pcapkit/const/ngap/procedure_code.py'),
            (IECrawler, 'pcapkit/const/ngap/protocol_ie.py'),
        ):
            with self.subTest(crawler=crawler_cls.__qualname__):
                crawler = object.__new__(crawler_cls)  # type: ignore[misc]
                crawler.NAME = crawler_cls.__name__
                crawler.DOCS = crawler_cls.__doc__
                data = crawler._request()
                rendered = crawler.context(data).strip()

                on_disk = (repo_root / relpath).read_text().strip()
                self.assertEqual(rendered, on_disk)


class NGAPVendorCrawlerMissingDependencyTests(unittest.TestCase):
    """:meth:`_request` without |pycrate|_ installed -- simulated via
    ``sys.modules``, run unconditionally regardless of whether this
    environment actually has it, since the failure path itself needs no
    |pycrate|_ to exercise."""

    def test_procedure_code_request_reports_the_missing_optional_dependency(self) -> None:
        from pcapkit.vendor.ngap.procedure_code import ProcedureCode as Crawler

        crawler = object.__new__(Crawler)  # type: ignore[misc]
        with mock.patch.dict(sys.modules, {'pycrate_asn1dir.NGAP': None}):
            with self.assertRaises(ImportError) as caught:
                crawler._request()
        self.assertIn('pypcapkit[NGAP]', str(caught.exception))
        self.assertIn('#880', str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, ImportError)

    def test_protocol_ie_request_reports_the_missing_optional_dependency(self) -> None:
        from pcapkit.vendor.ngap.protocol_ie import ProtocolIE as Crawler

        crawler = object.__new__(Crawler)  # type: ignore[misc]
        with mock.patch.dict(sys.modules, {'pycrate_asn1dir.NGAP': None}):
            with self.assertRaises(ImportError) as caught:
                crawler._request()
        self.assertIn('pypcapkit[NGAP]', str(caught.exception))
        self.assertIn('#880', str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, ImportError)


if __name__ == '__main__':
    unittest.main()
