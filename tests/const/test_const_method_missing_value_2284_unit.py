# -*- coding: utf-8 -*-
"""``Method._missing_`` must find the hyphenated methods by value.

GitHub issue #2284. The constructor resolves case-insensitively (#896): it
upper-cases the value and looks it up. It checked member *names* only, so the
two RFC 3253 methods whose name differs from their value (``BASELINE_CONTROL``
/ ``'BASELINE-CONTROL'``, ``VERSION_CONTROL`` / ``'VERSION-CONTROL'``) missed,
and ``Method('baseline-control')`` minted an unregistered member with
``idempotent=False`` instead of returning the registered one. #908 fixed the
same gap in ``Method.get``; that override stays case-sensitive and is repinned
here. Strings that are no method still mint an unregistered member (#860).

"""
from __future__ import annotations

import inspect
import unittest

#: Test tier (#1958): pure-Python lookups over a generated registry, which behave
#: the same on every interpreter.
__tier__ = 'LATEST'

#: Spellings of the two hyphenated methods, keyed by member name.
SPELLINGS = {
    'BASELINE_CONTROL': ('baseline-control', 'Baseline-Control', 'BASELINE-CONTROL'),
    'VERSION_CONTROL': ('version-control', 'Version-Control', 'VERSION-CONTROL'),
}


class HyphenatedLookupTests(unittest.TestCase):
    """The constructor returns the registered member in any casing."""

    def test_hyphenated_methods_resolve_in_any_case(self) -> None:
        """Without the fix, the lower- and mixed-case spellings mint a
        member named e.g. ``BASELINE-CONTROL`` with ``idempotent=False``."""
        from pcapkit.const.http.method import Method

        for name, spellings in SPELLINGS.items():
            member = Method[name]
            for value in spellings:
                with self.subTest(value=value):
                    probed = Method(value)
                    self.assertIs(probed, member)
                    self.assertTrue(probed.idempotent)
                    self.assertFalse(probed.safe)

    def test_name_lookup_still_folds_case(self) -> None:
        """#896: the constructor's name lookup stays case-insensitive."""
        from pcapkit.const.http.method import Method

        self.assertIs(Method('get'), Method.GET)
        self.assertIs(Method('Get'), Method.GET)

    def test_get_stays_case_sensitive(self) -> None:
        """#908/#896: ``get`` does not fold case, so a lower-case hyphenated
        spelling is still a distinct, unregistered method there."""
        from pcapkit.const.http.method import Method

        probed = Method.get('baseline-control')
        self.assertIsNot(probed, Method.BASELINE_CONTROL)
        self.assertEqual(probed.value, 'baseline-control')


class UnregisteredMemberTests(unittest.TestCase):
    """A string matching no name or value still mints (#860)."""

    def test_non_method_strings_mint_an_unregistered_member(self) -> None:
        """The minted member keeps the caller's casing as its value, carries
        the upper-cased name, and is not added to either lookup table."""
        from pcapkit.const.http.method import Method

        before = (len(Method._member_map_), len(Method._value2member_map_))
        for value in ('frob', 'Frob-Control', 'baseline control'):
            with self.subTest(value=value):
                probed = Method(value)
                self.assertNotIn(probed, list(Method))
                self.assertEqual(probed.value, value)
                self.assertEqual(probed.name, value.upper())
                self.assertFalse(probed.safe)
                self.assertFalse(probed.idempotent)
        self.assertEqual(
            (len(Method._member_map_), len(Method._value2member_map_)), before)


class VendorTemplateParityTests(unittest.TestCase):
    """The fix lives in the crawler template, so a regeneration keeps it."""

    def test_the_crawler_template_carries_the_same_missing(self) -> None:
        """The generated ``_missing_`` appears verbatim in the rendered
        template, and both consult ``_value2member_map_``."""
        from pcapkit.const.http.method import Method
        from pcapkit.vendor.http.method import LINE

        rendered = LINE('Method', 'HTTP Method', '<ENUM>', 'pcapkit.vendor.http.method')
        source = inspect.getsource(Method._missing_.__func__)  # type: ignore[attr-defined]

        self.assertIn('cls._value2member_map_[name]', source)
        self.assertIn(source.rstrip('\n'), rendered)


if __name__ == '__main__':
    unittest.main()
