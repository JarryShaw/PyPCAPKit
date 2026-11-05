# -*- coding: utf-8 -*-
"""The test helpers that write a capture remove its directory once their test is done (#2664).

Each helper below made a temporary directory with :func:`tempfile.mkdtemp`, handed
back the path of the capture in it, and never removed it, so every test that called
one left a directory in the temporary directory. A helper takes the
:class:`unittest.TestCase` it serves and registers the removal on it.

The helpers live in modules of their own and take different arguments, so each is
named here with a minimal call.

"""
from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from unittest import mock

#: Test tier (#1958): writes a few octets to disk and imports nothing of :mod:`pcapkit`.
__tier__ = 'LATEST'

#: ``(module, helper, arguments after the test case)``.
HELPERS = (
    ('tests.protocols.internet.test_esp_unit', 'make_pcap', (bytes(60),)),
    ('tests.protocols.link.test_l2tp_version_unit', 'make_pcap', (bytes(60),)),
    ('tests.protocols.test_dispatch_bindings_unit', 'make_pcap', (bytes(60),)),
    ('tests.protocols.application.test_layer_placement_unit', 'make_pcap', (1, bytes(60))),
    ('tests.protocols.application.test_dtls_connection_id_2515_unit', '_ethernet_pcap',
     (((True, b'\x16\xfe\xfd'),),)),
)  # type: tuple[tuple[str, str, tuple], ...]


class PcapHelperTempdirTests(unittest.TestCase):
    """What each helper leaves in the temporary directory."""

    def test_a_helper_leaves_nothing_once_its_case_is_done(self) -> None:
        """The capture is there while the test runs, and its directory is gone after.

        Fails without the fix, where the directory outlives the case.

        """
        with tempfile.TemporaryDirectory(prefix='pcapkit-2664-') as scratch, \
                mock.patch.object(tempfile, 'tempdir', scratch):
            for module, name, arguments in HELPERS:
                with self.subTest(helper=f'{module}.{name}'):
                    helper = getattr(importlib.import_module(module), name)
                    case = unittest.TestCase()

                    path = helper(case, *arguments)
                    self.assertTrue(path.startswith(scratch + os.sep), f'{path} is not under {scratch}')
                    self.assertTrue(os.path.isfile(path))

                    case.doCleanups()
                    self.assertEqual(os.listdir(scratch), [])


if __name__ == '__main__':
    unittest.main()
