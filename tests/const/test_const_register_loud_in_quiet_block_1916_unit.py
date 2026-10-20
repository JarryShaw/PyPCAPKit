# -*- coding: utf-8 -*-
"""The generated ``register`` overrides stay loud inside a quiet block.

GitHub issue #1916. :meth:`~pcapkit.corekit.enum.EnumRegistry.register` runs
:meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` inside a
:class:`~pcapkit.utilities.exceptions.CaughtByCaller` block declaring that
nothing is caught, so its rejection is logged even when an enclosing ``get``
has quieted :exc:`ValueError` (#1845). The overrides on
:class:`~pcapkit.const.reg.apptype.apptype.AppType` and
:class:`~pcapkit.const.pcapng.option_type.OptionType` called the hook bare, so
inside such a block their rejection raised and logged nothing.

Each test opens the quiet block the way ``get`` does and checks that the
rejection still leaves its record on the ``pcapkit`` logger. The record comes
from :mod:`pcapkit.utilities.exceptions`'s own logger, a child of that one.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import logging
import sys
import threading
import unittest
from typing import TYPE_CHECKING

from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Callable

#: Test tier (#1958): exercises threading, locking or warning and exception hooks, which
#: differ by interpreter.
__tier__ = 'ALL'


class RegisterLoudInQuietBlock1916Tests(unittest.TestCase):
    """``register`` on a generated registry logs its rejection inside a quiet block."""

    def setUp(self) -> 'None':
        # A loud error outside development mode replaces both hooks; put the
        # real ones back so this test does not leak pcapkit's into later ones.
        saved_sys, saved_threading = sys.excepthook, threading.excepthook

        def _restore() -> 'None':
            sys.excepthook = saved_sys
            threading.excepthook = saved_threading

        self.addCleanup(_restore)

    def assertLoudInsideQuietBlock(self, registry: 'type', call: 'Callable[[], object]',
                                   message: 'str') -> 'None':
        """Assert ``call`` raises ``message`` and logs it, inside a quiet block."""
        from pcapkit.utilities.exceptions import CaughtByCaller, EnumValueError

        members = dict(registry.__members__)  # type: ignore[attr-defined]
        with capture(logging.getLogger('pcapkit')) as package:
            with CaughtByCaller(ValueError):
                with self.assertRaises(EnumValueError) as caught:
                    call()
        self.assertEqual(str(caught.exception), message)
        self.assertEqual(package.messages, [('CRITICAL', f'EnumValueError: {message}')],
                         'the rejection was quieted by the enclosing block')
        self.assertEqual(dict(registry.__members__), members)  # type: ignore[attr-defined]

    def test_apptype_register(self) -> 'None':
        from pcapkit.const.reg.apptype import TCP

        self.assertLoudInsideQuietBlock(TCP, lambda: TCP.register(70000, 'x'),
                                        '70000 is not a valid TCP')

    def test_option_type_register(self) -> 'None':
        from pcapkit.const.pcapng.option_type import OptionType

        self.assertLoudInsideQuietBlock(OptionType, lambda: OptionType.register(-1, 'x'),
                                        '-1 is not a valid OptionType')


if __name__ == '__main__':
    unittest.main()
