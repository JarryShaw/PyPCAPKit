# -*- coding: utf-8 -*-
"""Pins the docs build's rendering of third-party classes that share a bare name.

GitHub issue #1918: ``typehints_fully_qualified`` is off, so the frame types of
:class:`~pcapkit.foundation.extraction.Extractor` read
``Packet | Packet | Packet``, for the ``scapy``, ``dpkt`` and ``pyshark`` classes
:mod:`pcapkit.foundation.extraction` imports under ``TYPE_CHECKING``.
``format_class`` in :file:`docs/source/conf.py`, the build's
``typehints_formatter``, qualifies a third-party class when the pcapkit modules
bind another class of its name, which ``record_class_names`` notes as the build
starts.

GitHub issue #1920: a package without ``py:`` objects in its inventory cannot be
cross-referenced (#934), so such a class is named by a literal, not a role.

The tests call the hooks directly. They need Sphinx and the pinned
``sphinx-autodoc-typehints``, and skip without them, but run no build.

"""

from __future__ import annotations

import importlib.util
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests.project.test_docs_ambiguous_xrefs_1775_unit import HAS_SPHINX, SPHINX_SKIP_REASON, load_conf

if TYPE_CHECKING:
    from typing import Any

HAS_SCAPY = importlib.util.find_spec('scapy') is not None
HAS_DPKT = importlib.util.find_spec('dpkt') is not None
HAS_PYSHARK = importlib.util.find_spec('pyshark') is not None


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class ClassFormatterTests(unittest.TestCase):
    """``format_class`` qualifies a third-party class whose bare name is ambiguous."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def setUp(self) -> 'None':
        patcher = mock.patch.dict(self.conf.CLASS_NAMES, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def record(self, *classes: 'type') -> 'None':
        """Record a module binding ``classes``."""
        module = types.ModuleType('pcapkit_test_module')
        for at, cls in enumerate(classes):
            setattr(module, f'Alias{at}', cls)
        self.conf.record_class_names(module)

    @unittest.skipUnless(HAS_SCAPY, 'scapy is not installed')
    @unittest.skipUnless(HAS_DPKT, 'dpkt is not installed')
    @unittest.skipUnless(HAS_PYSHARK, 'pyshark is not installed')
    def test_extraction_packets_render_apart(self) -> 'None':
        """From the names the module's ``TYPE_CHECKING`` block binds, as the build records them."""
        # pylint: disable=import-outside-toplevel
        from dpkt.dpkt import Packet as DPKTPacket
        from pyshark.packet.packet import Packet as PySharkPacket
        from scapy.packet import Packet as ScapyPacket

        from pcapkit.foundation import extraction

        self.conf.resolve_type_guarded_imports([], extraction)
        self.conf.record_class_names(extraction)
        answers = [self.conf.format_class(cls, None) for cls in (ScapyPacket, DPKTPacket, PySharkPacket)]
        self.assertEqual(answers, [':py:class:`scapy.packet.Packet`', ':py:class:`dpkt.dpkt.Packet`',
                                   '``pyshark.packet.packet.Packet``'])

    def test_unlinked_package_gets_a_literal(self) -> 'None':
        """``aenum`` has no ``py:`` objects to link to; its exported name is shown."""
        import aenum  # pylint: disable=import-outside-toplevel
        self.assertEqual(self.conf.format_class(aenum.IntFlag, None), '``aenum.IntFlag``')
        self.assertNotIn(':py:', self.conf.format_class(aenum.IntFlag, None))

    def test_unambiguous_class_is_left_alone(self) -> 'None':
        """A third-party class no other recorded class shares a name with."""
        import dictdumper  # pylint: disable=import-outside-toplevel
        self.record(dictdumper.JSON)
        self.assertIsNone(self.conf.format_class(dictdumper.JSON, None))

    def test_pcapkit_and_stdlib_classes_are_left_alone(self) -> 'None':
        """Even when they share a name with a third-party class."""
        import enum  # pylint: disable=import-outside-toplevel

        import aenum  # pylint: disable=import-outside-toplevel

        from pcapkit.protocols.data.protocol import Packet  # pylint: disable=import-outside-toplevel

        class Imposter:  # pylint: disable=too-few-public-methods
            """A third-party class named ``Packet``."""

        Imposter.__name__ = Imposter.__qualname__ = 'Packet'
        Imposter.__module__ = 'thirdparty.packet'
        self.record(Packet, Imposter, enum.IntEnum, aenum.IntEnum)
        self.assertIsNone(self.conf.format_class(Packet, None))
        self.assertIsNone(self.conf.format_class(enum.IntEnum, None))
        self.assertEqual(self.conf.format_class(Imposter, None), '``thirdparty.packet.Packet``')

    def test_walk_records_every_module(self) -> 'None':
        """``bind_type_checking_names`` records each module it walks."""
        from pcapkit.foundation import extraction  # pylint: disable=import-outside-toplevel
        app = types.SimpleNamespace(config=types.SimpleNamespace(autodoc_mock_imports=[]))
        with mock.patch.object(self.conf.pkgutil, 'walk_packages',
                               return_value=[types.SimpleNamespace(name=extraction.__name__)]), \
                mock.patch.object(self.conf, 'bind_guarded_names'), \
                mock.patch.object(self.conf, 'record_class_names') as record:
            self.conf.bind_type_checking_names(app, None, [])
        record.assert_called_once_with(extraction)


if __name__ == '__main__':
    unittest.main()
