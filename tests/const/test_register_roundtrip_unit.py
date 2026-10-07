# -*- coding: utf-8 -*-
"""``register()`` mints a member that ``get()`` and ``cls()`` find again.

* GitHub issue #1298: :meth:`OptionType.register
  <pcapkit.const.pcapng.option_type.OptionType.register>` went through the base
  ``extend_enum(cls, name, value)``, so :meth:`OptionType.__new__` never saw the
  name and minted ``opt_unknown`` under ``opt``. The base duplicate guard tested
  the :class:`int` code against string keys, so an assigned code was accepted
  and took over ``opt``'s entry for it.
* GitHub issue #1299: :meth:`Command.register
  <pcapkit.const.ftp.command.Command.register>` kept the name's case, while
  :meth:`~pcapkit.const.ftp.command.Command.get` looks names up upper-cased.
* GitHub issue #1300: :meth:`OptionType.get
  <pcapkit.const.pcapng.option_type.OptionType.get>` with a member's own value
  returned a stand-in rather than the member that ``cls(value)`` returns.

Registries are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, and the class's private import
is restored afterwards, so the members minted here do not leak.

"""

import unittest

from tests._support import reimport_once_per_class


class TestOptionTypeRegister(unittest.TestCase):
    """GitHub issues #1298 and #1300."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_register_keeps_name_and_namespace(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        member = OptionType.register(0x7ABC, 'if_rtaudit')
        self.assertEqual(member.name, 'if_rtaudit')
        self.assertEqual(member.opt_name, 'if_rtaudit')
        self.assertEqual(member.opt_value, 0x7ABC)
        self.assertEqual(member.value, 'if_rtaudit [31420]')
        self.assertIs(OptionType.__members_ns__['if'][0x7ABC], member)
        self.assertNotIn(0x7ABC, OptionType.__members_ns__['opt'])

    def test_registered_member_round_trips(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        member = OptionType.register(0x7ABD, 'epb_rtaudit')
        self.assertIs(OptionType.get(0x7ABD, namespace='epb'), member)
        self.assertIs(OptionType.get('epb_rtaudit'), member)
        self.assertIs(OptionType.get(member.value), member)
        self.assertIs(OptionType(member.value), member)

    def test_register_refuses_an_assigned_code(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        # 1 is opt_comment, common to every block; 2 is if_name.
        for value, name in ((1, 'if_dup'), (1, 'opt_dup'), (2, 'if_dup')):
            with self.subTest(value=value, name=name):
                with self.assertRaises(ValueError):
                    OptionType.register(value, name)
        self.assertIs(OptionType.get(1), OptionType.opt_comment)
        self.assertIs(OptionType.get(1, namespace='if'), OptionType.opt_comment)
        self.assertIs(OptionType.get(2, namespace='if'), OptionType.if_name)
        self.assertNotIn('if_dup', OptionType.__members__)

    def test_register_refuses_a_taken_name(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        with self.assertRaises(ValueError):
            OptionType.register(0x7ABE, 'opt_comment')
        self.assertNotIn(0x7ABE, OptionType.__members_ns__['opt'])

    def test_get_by_member_value(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        for member in (OptionType.opt_comment, OptionType.if_name, OptionType.opt_custom_2988):
            with self.subTest(member=member.name):
                self.assertIs(OptionType.get(member.value), member)


class TestCommandRegister(unittest.TestCase):
    """GitHub issue #1299."""

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def test_register_upper_cases_the_name(self) -> None:
        from pcapkit.const.ftp.command import Command

        member = Command.register('xaud', 'xaud')
        self.assertEqual(member.name, 'XAUD')
        self.assertEqual(member.value, 'xaud')
        self.assertIs(Command.get('xaud'), member)
        self.assertIs(Command.get('XAUD'), member)
        self.assertIs(Command('xaud'), member)
        self.assertIs(Command('XAUD'), member)

    def test_register_alias_upper_cases_the_name(self) -> None:
        from pcapkit.const.ftp.command import Command

        member = Command.register_alias('USER', 'xusr')
        self.assertIs(member, Command.USER)
        self.assertIs(Command.get('xusr'), Command.USER)

    def test_register_refuses_a_taken_upper_case_name(self) -> None:
        from pcapkit.const.ftp.command import Command

        with self.assertRaises(ValueError):
            Command.register('user-2', 'user')


if __name__ == '__main__':
    unittest.main()
