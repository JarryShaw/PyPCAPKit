# -*- coding: utf-8 -*-
"""``OptionType.register_alias`` adds a name for an existing option code.

GitHub issue #1330: :meth:`OptionType.register_alias
<pcapkit.const.pcapng.option_type.OptionType.register_alias>` fell through to
the base, which tests the :class:`int` code against
:attr:`~aenum.Enum._value2member_map_`. That table is keyed by the formatted
``'{name} [{value}]'`` strings, so every call raised ``ValueError: … is not a
registered OptionType``.

The alias resolves ``value`` in the alias name's namespace overlaid on ``opt``,
as :meth:`~pcapkit.const.pcapng.option_type.OptionType.get` does.

The registry is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, and the class's private import
is restored afterwards, so the aliases added here do not leak. The import is
shared by the tests of the class, so each test uses its own alias names.

"""

import unittest

from tests._support import reimport_once_per_class


class TestOptionTypeRegisterAlias(unittest.TestCase):
    """GitHub issue #1330."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_alias_in_opt_resolves_to_the_member(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        count = len(list(OptionType))
        member = OptionType.register_alias(1, 'opt_note_1330')
        self.assertIs(member, OptionType.opt_comment)
        self.assertIs(getattr(OptionType, 'opt_note_1330'), OptionType.opt_comment)
        self.assertIs(OptionType.__members__['opt_note_1330'], OptionType.opt_comment)
        self.assertIs(OptionType.get('opt_note_1330'), OptionType.opt_comment)
        # An alias adds a name, not a member, and the member keeps its own name.
        self.assertEqual(len(list(OptionType)), count)
        self.assertEqual(member.name, 'opt_comment')
        self.assertEqual(member.opt_name, 'opt_comment')

    def test_alias_leaves_the_namespace_table_on_the_member(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        OptionType.register_alias(2, 'if_label_1330')
        self.assertIs(OptionType.__members_ns__['if'][2], OptionType.if_name)
        self.assertIs(OptionType.get(2, namespace='if'), OptionType.if_name)
        self.assertIs(getattr(OptionType, 'if_label_1330'), OptionType.if_name)

    def test_alias_namespace_falls_back_to_opt(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        member = OptionType.register_alias(1, 'if_note_1330')
        self.assertIs(member, OptionType.opt_comment)
        self.assertNotIn(1, OptionType.__members_ns__['if'])
        self.assertIs(OptionType.__members_ns__['opt'][1], OptionType.opt_comment)

    def test_alias_namespace_takes_precedence_over_opt(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        # Code 2 is ``epb_flags`` in ``epb`` and ``if_name`` in ``if``.
        self.assertIs(OptionType.register_alias(2, 'epb_fl_1330'), OptionType.epb_flags)
        self.assertIs(OptionType.__members_ns__['epb'][2], OptionType.epb_flags)
        self.assertIs(OptionType.__members_ns__['if'][2], OptionType.if_name)

    def test_register_aliases_adds_each_name(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        members = OptionType.register_aliases(1, 'opt_a_1330', 'opt_b_1330')
        self.assertEqual(members, (OptionType.opt_comment, OptionType.opt_comment))
        self.assertIs(OptionType.__members__['opt_b_1330'], OptionType.opt_comment)

    def test_unassigned_code_is_refused(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        with self.assertRaisesRegex(ValueError, 'is not a registered OptionType'):
            OptionType.register_alias(0x7ABC, 'if_missing_1330')
        self.assertNotIn('if_missing_1330', OptionType.__members__)

    def test_taken_name_is_refused(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        with self.assertRaises(ValueError):
            OptionType.register_alias(2, 'opt_comment')
        self.assertIs(OptionType.__members_ns__['opt'][1], OptionType.opt_comment)
        self.assertIs(OptionType.__members_ns__['if'][2], OptionType.if_name)


if __name__ == '__main__':
    unittest.main()
