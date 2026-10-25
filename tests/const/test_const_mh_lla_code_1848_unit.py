# -*- coding: utf-8 -*-
"""``LLACode`` names codes ``0`` and ``2`` as :rfc:`5568#section-6.4.3` does.

GitHub issue #1848. Code ``0`` is ``Wildcard``, which the module misspelt
``Wilcard``, and code ``2``, the *Link-Layer Address of the MN*, is ``MN``,
which it named ``MH``. Neither misspelling is an alias, as #1090 and #1715
keep no alias for a renamed member either.

"""
import unittest


class LLACodeRenameTests(unittest.TestCase):
    """The RFC's names resolve both ways, and the misspellings resolve neither."""

    def test_code_0_is_wildcard(self) -> 'None':
        from pcapkit.const.mh.lla_code import LLACode

        self.assertEqual(LLACode.Wildcard, 0)
        self.assertEqual(LLACode(0).name, 'Wildcard')
        self.assertIs(LLACode['Wildcard'], LLACode(0))

    def test_code_2_is_mn(self) -> 'None':
        from pcapkit.const.mh.lla_code import LLACode

        self.assertEqual(LLACode.MN, 2)
        self.assertEqual(LLACode(2).name, 'MN')
        self.assertIs(LLACode['MN'], LLACode(2))

    def test_the_shipped_names_are_not_aliases(self) -> 'None':
        from pcapkit.const.mh.lla_code import LLACode

        for name in ('Wilcard', 'MH'):
            with self.subTest(name=name):
                self.assertFalse(hasattr(LLACode, name))
                self.assertNotIn(name, LLACode.__members__)

    def test_the_class_docstring_carries_no_version_directive(self) -> 'None':
        # The module is generated, so the rename is noted on the docs page.
        from pcapkit.const.mh.lla_code import LLACode

        doc = LLACode.__doc__ or ''
        for directive in ('.. versionadded::', '.. versionchanged::', '.. versionremoved::'):
            with self.subTest(directive=directive):
                self.assertNotIn(directive, doc)


if __name__ == '__main__':
    unittest.main()
