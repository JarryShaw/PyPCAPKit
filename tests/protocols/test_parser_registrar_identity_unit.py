# -*- coding: utf-8 -*-
"""GitHub issues #1362 and #1363: the parser registrars warn only on a real displacement.

The registrars that store a parser -- a method name or a ``(parser,
constructor)`` pair -- tested only whether ``code`` was present, so handing back
the entry already stored warned that it was being overwritten. They now compare
the incumbent with the replacement, as the class-storing registrars do since
#718 and #739: an equal entry is a silent no-op. Under the #1363 ruling, the
entry a code shipped with is accepted back after an override, which undoes it.

Every registry is process-wide, so each case runs under
:func:`unittest.mock.patch.dict`. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: ``(module, class, registrar, registry)`` for every parser registrar but
#: PCAP-NG's, which another change owns.
SITES = (
    ('pcapkit.protocols.internet.ipv4', 'IPv4', 'register_option', '__option__'),
    ('pcapkit.protocols.internet.hopopt', 'HOPOPT', 'register_option', '__option__'),
    ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts', 'register_option', '__option__'),
    ('pcapkit.protocols.internet.ipv6_route', 'IPv6_Route', 'register_routing', '__routing__'),
    ('pcapkit.protocols.internet.hip', 'HIP', 'register_parameter', '__parameter__'),
    ('pcapkit.protocols.internet.mh', 'MH', 'register_message', '__message__'),
    ('pcapkit.protocols.internet.mh', 'MH', 'register_option', '__option__'),
    ('pcapkit.protocols.internet.mh', 'MH', 'register_extension', '__extension__'),
    ('pcapkit.protocols.transport.tcp', 'TCP', 'register_option', '__option__'),
    ('pcapkit.protocols.transport.tcp', 'TCP', 'register_mp_option', '__mp_option__'),
    ('pcapkit.protocols.transport.sctp', 'SCTP', 'register_chunk', '__chunk__'),
    ('pcapkit.protocols.transport.sctp', 'SCTP', 'register_parameter', '__parameter__'),
    ('pcapkit.protocols.transport.sctp', 'SCTP', 'register_cause', '__cause__'),
    ('pcapkit.protocols.application.httpv2', 'HTTP', 'register_frame', '__frame__'),
)


def _parse(*args: object, **kwargs: object) -> None:
    """Stand-in parser."""


def _make(*args: object, **kwargs: object) -> None:
    """Stand-in constructor."""


class TestParserRegistrarIdentity(unittest.TestCase):
    """Pin when a parser registrar warns."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _each_site(self, check):  # type: ignore[no-untyped-def]
        """Run ``check(register, registry)`` for every site, each in its own ``subTest``."""
        for module, name, meth, attr in SITES:
            cls = getattr(importlib.import_module(module), name)
            registry = getattr(cls, attr)
            with self.subTest(site=f'{name}.{meth}'), mock.patch.dict(registry):
                check(getattr(cls, meth), registry)

    def _count(self, call, *args) -> int:  # type: ignore[no-untyped-def]
        """Run ``call(*args)`` and return how many registry warnings it raised."""
        from pcapkit.utilities.warnings import RegistryWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            call(*args)
        return sum(issubclass(item.category, RegistryWarning) for item in caught)

    def test_reregistering_the_stored_entry_is_silent(self) -> None:
        def check(register, registry):  # type: ignore[no-untyped-def]
            for code, value in list(registry.items()):
                self.assertEqual(self._count(register, code, value), 0, code)
                self.assertIs(registry[code], value)
                # An equal method name built at run time is the same entry, and
                # the stored object is kept.
                if isinstance(value, str):
                    self.assertEqual(self._count(register, code, ''.join(list(value))), 0, code)
                    self.assertIs(registry[code], value)
        self._each_site(check)

    def test_reregistering_a_parser_pair_is_silent(self) -> None:
        def check(register, registry):  # type: ignore[no-untyped-def]
            code = next(iter(registry))
            pair = (_parse, _make)
            self.assertEqual(self._count(register, code, pair), 1)
            self.assertIs(registry[code], pair)
            self.assertEqual(self._count(register, code, pair), 0)
            self.assertEqual(self._count(register, code, (_parse, _make)), 0)
            self.assertIs(registry[code], pair)
        self._each_site(check)

    def test_restoring_the_shipped_entry_undoes_an_override(self) -> None:
        def check(register, registry):  # type: ignore[no-untyped-def]
            code, shipped = next(iter(registry.items()))
            self.assertEqual(self._count(register, code, 'w1362_override'), 1)
            self.assertEqual(registry[code], 'w1362_override')
            # Putting the shipped entry back displaces the override, so it warns.
            self.assertEqual(self._count(register, code, shipped), 1)
            self.assertIs(registry[code], shipped)
            self.assertEqual(self._count(register, code, shipped), 0)
        self._each_site(check)

    def test_a_foreign_entry_still_warns(self) -> None:
        def check(register, registry):  # type: ignore[no-untyped-def]
            code, shipped = next(iter(registry.items()))
            self.assertEqual(self._count(register, code, (_parse, _make)), 1)
            self.assertEqual(self._count(register, code, f'{shipped}_w1362'), 1)
            self.assertEqual(registry[code], f'{shipped}_w1362')
        self._each_site(check)

    def test_an_unregistered_code_is_silent(self) -> None:
        def check(register, registry):  # type: ignore[no-untyped-def]
            code = next(iter(registry))
            registry.pop(code)
            self.assertEqual(self._count(register, code, 'w1362_new'), 0)
            self.assertEqual(registry[code], 'w1362_new')
        self._each_site(check)


if __name__ == '__main__':
    unittest.main()
