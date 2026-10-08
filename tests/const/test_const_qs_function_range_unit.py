# -*- coding: utf-8 -*-
"""The Quick-Start ``QSFunction`` enums accept the whole four-bit field.

GitHub issue #1350: RFC 4782 section 3.1 gives the Quick-Start option "a
four-bit Function field", so every value in ``0..15`` is a valid wire value,
and those without an assignment (``1..7`` and ``9..15``) resolve to an
``Unassigned`` member. Values outside the field are still rejected.

The bound comes from ``FLAG`` in the vendor templates
:mod:`pcapkit.vendor.ipv4.qs_function` and :mod:`pcapkit.vendor.ipv6.qs_function`,
so the generated const files are also checked against the template's output.
Both templates take their registry from a local ``DATA`` dict, so rendering
them reaches no network.

Modules are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import importlib
import os
import tempfile
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

NAMESPACES = ('ipv4', 'ipv6')


class TestQSFunctionRange(unittest.TestCase):
    """Pin the accepted range of both ``QSFunction`` enums."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unassigned_values_resolve(self) -> None:
        for ns in NAMESPACES:
            enum = importlib.import_module(f'pcapkit.const.{ns}.qs_function').QSFunction
            for value in range(16):
                with self.subTest(ns=ns, value=value):
                    member = enum.get(value)
                    self.assertEqual(int(member), value)
                    if value not in (0, 8):
                        self.assertEqual(enum(value), member)
                        self.assertTrue(member.name.startswith('Unassigned'), member.name)

    def test_values_outside_the_field_are_rejected(self) -> None:
        for ns in NAMESPACES:
            enum = importlib.import_module(f'pcapkit.const.{ns}.qs_function').QSFunction
            for value in (-1, 16, 255):
                with self.subTest(ns=ns, value=value):
                    with self.assertRaises(ValueError):
                        enum(value)

    def test_const_file_matches_template_output(self) -> None:
        for ns in NAMESPACES:
            with self.subTest(ns=ns):
                vendor = importlib.import_module(f'pcapkit.vendor.{ns}.qs_function').QSFunction
                self.assertIsNone(vendor.LINK)
                const_file = vendor._dest_path()
                with tempfile.TemporaryDirectory() as tempdir:
                    dest = os.path.join(tempdir, 'qs_function.py')
                    with mock.patch.object(vendor, '_dest_path', return_value=dest):
                        vendor()
                    with open(dest, 'rb') as file:
                        rendered = file.read()
                with open(const_file, 'rb') as file:
                    self.assertEqual(file.read(), rendered)


if __name__ == '__main__':
    unittest.main()
