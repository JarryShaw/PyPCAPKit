# -*- coding: utf-8 -*-
"""Unit tests for the :mod:`pcapkit.const.linux` package surface (#2661).

Every other package of :mod:`pcapkit.const` re-exports its registries under a
package prefix, and :mod:`pcapkit.const` star-imports each package so the names
reach its own ``__all__``. The Linux package did neither, and
:mod:`pcapkit.vendor.linux` already exports its crawler as ``Linux_ARPHRD``.

"""
from __future__ import annotations

import unittest

#: Test tier (#1958): pure-Python attribute lookups, which behave the same on
#: every interpreter.
__tier__ = 'LATEST'


class LinuxConstSurfaceTests(unittest.TestCase):
    """:mod:`pcapkit.const.linux` and its place in :mod:`pcapkit.const`."""

    def test_package_exports_the_registry_under_a_package_prefix(self) -> None:
        import pcapkit.const.linux
        from pcapkit.const.linux.arphrd import ARPHRD

        self.assertEqual(pcapkit.const.linux.__all__, ['Linux_ARPHRD'])
        self.assertIs(pcapkit.const.linux.Linux_ARPHRD, ARPHRD)

    def test_const_package_re_exports_the_registry(self) -> None:
        import pcapkit.const
        from pcapkit.const.linux.arphrd import ARPHRD

        self.assertIn('Linux_ARPHRD', pcapkit.const.__all__)
        self.assertIs(pcapkit.const.Linux_ARPHRD, ARPHRD)

    def test_star_import_of_const_binds_the_registry(self) -> None:
        from pcapkit.const.linux.arphrd import ARPHRD

        namespace = {}  # type: dict[str, object]
        exec('from pcapkit.const import *', namespace)  # pylint: disable=exec-used
        self.assertIs(namespace['Linux_ARPHRD'], ARPHRD)

    def test_names_pair_with_the_vendor_crawler(self) -> None:
        import pcapkit.const.linux
        import pcapkit.vendor.linux

        self.assertEqual(pcapkit.const.linux.__all__, pcapkit.vendor.linux.__all__)


if __name__ == '__main__':
    unittest.main()
