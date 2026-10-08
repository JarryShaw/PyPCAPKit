# -*- coding: utf-8 -*-
"""GitHub issue #1401: the PCAP-NG parser registrars warn only on a real displacement.

``register_block``, ``register_option``, ``register_record`` and
``register_secrets`` tested only whether ``code`` was present, so handing back
the entry already stored warned that it was being overwritten. They now apply
the #1400 guard: an equal entry is a silent no-op, and the entry a code shipped
with is accepted back after an override, which undoes it.

Every registry is process-wide, so each case runs under
:func:`unittest.mock.patch.dict`. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: ``(registrar, registry)`` for each PCAP-NG parser registrar.
SITES = (
    ('register_block', '__block__'),
    ('register_option', '__option__'),
    ('register_record', '__record__'),
    ('register_secrets', '__secrets__'),
)


def _parse(*args: object, **kwargs: object) -> None:
    """Stand-in parser."""


def _make(*args: object, **kwargs: object) -> None:
    """Stand-in constructor."""


class TestPCAPNGRegistrarIdentity(unittest.TestCase):
    """Pin when a PCAP-NG parser registrar warns."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _each_site(self, check):  # type: ignore[no-untyped-def]
        """Run ``check(register, registry, code_of)`` for every site, each in its own ``subTest``.

        ``code_of`` maps a registry key back to the code the registrar takes:
        the option registry is keyed by :func:`_option_key`, not by the code.

        """
        module = importlib.import_module('pcapkit.protocols.misc.pcapng')
        option_type = importlib.import_module('pcapkit.const.pcapng.option_type').OptionType
        option_codes = {module._option_key(member): member for member in option_type}
        for meth, attr in SITES:
            registry = module.PCAPNG.__dict__[attr]
            code_of = option_codes.__getitem__ if attr == '__option__' else (lambda key: key)
            with self.subTest(site=meth), mock.patch.dict(registry):
                check(getattr(module.PCAPNG, meth), registry, code_of)

    def _count(self, call, *args) -> int:  # type: ignore[no-untyped-def]
        """Run ``call(*args)`` and return how many registry warnings it raised."""
        from pcapkit.utilities.warnings import RegistryWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            call(*args)
        return sum(issubclass(item.category, RegistryWarning) for item in caught)

    def test_reregistering_the_stored_entry_is_silent(self) -> None:
        def check(register, registry, code_of):  # type: ignore[no-untyped-def]
            for key, value in list(registry.items()):
                self.assertEqual(self._count(register, code_of(key), value), 0, key)
                self.assertIs(registry[key], value)
                # An equal method name built at run time is the same entry, and
                # the stored object is kept.
                self.assertEqual(self._count(register, code_of(key), ''.join(list(value))), 0, key)
                self.assertIs(registry[key], value)
        self._each_site(check)

    def test_reregistering_a_parser_pair_is_silent(self) -> None:
        def check(register, registry, code_of):  # type: ignore[no-untyped-def]
            key = next(iter(registry))
            pair = (_parse, _make)
            self.assertEqual(self._count(register, code_of(key), pair), 1)
            self.assertIs(registry[key], pair)
            self.assertEqual(self._count(register, code_of(key), pair), 0)
            self.assertEqual(self._count(register, code_of(key), (_parse, _make)), 0)
            self.assertIs(registry[key], pair)
        self._each_site(check)

    def test_restoring_the_shipped_entry_undoes_an_override(self) -> None:
        def check(register, registry, code_of):  # type: ignore[no-untyped-def]
            key, shipped = next(iter(registry.items()))
            self.assertEqual(self._count(register, code_of(key), 'w1401_override'), 1)
            self.assertEqual(registry[key], 'w1401_override')
            # Putting the shipped entry back displaces the override, so it warns.
            self.assertEqual(self._count(register, code_of(key), shipped), 1)
            self.assertIs(registry[key], shipped)
            self.assertEqual(self._count(register, code_of(key), shipped), 0)
        self._each_site(check)

    def test_an_unregistered_code_is_silent_and_not_defaulted(self) -> None:
        def check(register, registry, code_of):  # type: ignore[no-untyped-def]
            key = next(iter(registry))
            registry.pop(key)
            # The lookup must not trip the ``defaultdict`` factory.
            self.assertEqual(self._count(register, code_of(key), 'w1401_new'), 0)
            self.assertEqual(registry[key], 'w1401_new')
        self._each_site(check)


if __name__ == '__main__':
    unittest.main()
