# -*- coding: utf-8 -*-
"""The layout of the const census in :mod:`tests.const.census`. C.f. #2615.

The census keeps one module per package of :mod:`pcapkit.const` so that a
registry added to one package and a registry added to another land in
different files. That only holds while each module covers its own package
alone, and while each keeps its entries sorted, one per line, so that two
additions to one package land on different lines too. This module pins both,
and that every entry reads ``module:QualName`` with a known kind.

Whether the census matches the tree is the sweeps' question, not this
module's: each const sweep compares what it discovers against the census.

This module is unit-tier and reads no capture.

"""
import pathlib
import unittest

from tests.const import census

#: Test tier (#1958): checks the census files, a question about the tree.
__tier__ = 'LATEST'

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]


class CensusLayoutTests(unittest.TestCase):
    """Each census module covers one package, sorted, one registry per line."""

    def test_each_module_is_named_after_a_const_package(self) -> None:
        for package in census.MANIFESTS:
            with self.subTest(package=package):
                self.assertTrue((ROOT / 'pcapkit' / 'const' / package / '__init__.py').is_file(),
                                f'tests/const/census/{package}.py names no package of pcapkit.const')

    def test_each_module_covers_its_own_package_alone(self) -> None:
        for package, manifest in census.MANIFESTS.items():
            for name in manifest.REGISTRIES:
                with self.subTest(package=package, registry=name):
                    module, colon, qualname = name.partition(':')
                    self.assertEqual(colon, ':', f'{name} is not module:QualName')
                    self.assertTrue(module.startswith(f'pcapkit.const.{package}.'),
                                    f'{name} belongs in the census module of its own package')
                    self.assertRegex(qualname, r'^[A-Za-z_]\w*$')

    def test_each_module_is_sorted(self) -> None:
        for package, manifest in census.MANIFESTS.items():
            with self.subTest(package=package):
                entries = list(manifest.REGISTRIES)
                self.assertEqual(entries, sorted(entries),
                                 f'tests/const/census/{package}.py is not sorted')

    def test_each_entry_is_on_a_line_of_its_own(self) -> None:
        for package, manifest in census.MANIFESTS.items():
            lines = pathlib.Path(manifest.__file__).read_text(encoding='utf-8').splitlines()
            for name in manifest.REGISTRIES:
                with self.subTest(package=package, registry=name):
                    self.assertEqual(sum(1 for line in lines if f"'{name}'" in line), 1)
                    line, = (line for line in lines if f"'{name}'" in line)
                    self.assertEqual(line.strip(), f"'{name}': '{manifest.REGISTRIES[name]}',")

    def test_every_kind_is_known(self) -> None:
        for name, kind in census.REGISTRIES.items():
            with self.subTest(registry=name):
                self.assertIn(kind, census.KINDS)

    def test_compare_names_what_differs(self) -> None:
        self.assertEqual(census.compare(['a', 'b'], ['b', 'a']), census.AGREES)
        self.assertEqual(census.compare(['a', 'a', 'c'], ['a', 'b']),
                         {'found twice': ['a'], 'not in the census': ['c'], 'not found': ['b']})


if __name__ == '__main__':
    unittest.main()
