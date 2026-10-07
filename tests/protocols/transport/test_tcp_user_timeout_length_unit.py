# -*- coding: utf-8 -*-
"""The TCP User Timeout option's length, as :rfc:`5482#section-3.3` defines it.

GitHub issue #1120. The option is ``Kind`` (1 octet), ``Length`` (1 octet) and
a 16-bit field holding the ``G`` granularity bit and the 15-bit timeout, so its
``Length`` is **4**. :meth:`TCP._read_mode_timeout
<pcapkit.protocols.transport.tcp.TCP._read_mode_timeout>` checks for exactly
that, and :class:`~pcapkit.protocols.schema.transport.tcp.UserTimeout` packs
four octets; :meth:`TCP._make_mode_timeout
<pcapkit.protocols.transport.tcp.TCP._make_mode_timeout>` wrote **3**, so every
option it made failed with ``TCP: [OptNo 28] invalid format``.

Every case builds its own octets in memory, so this belongs to the unit tier.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load: a
:class:`TCP` bound at load builds option schemas of whatever import was live
then, and once an earlier module has purged it, :meth:`ListField.pack
<pcapkit.corekit.fields.collections.ListField.pack>` checks them against the new
import's ``Schema`` and raises ``Field options has invalid value``.

"""
from __future__ import annotations

import datetime
import io
import unittest

from tests._support import reimport_once_per_class


class UserTimeoutLengthTests(unittest.TestCase):
    """The maker's ``Length`` octet against RFC 5482 and the reader."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def test_maker_writes_length_four(self) -> 'None':
        """Both granularities, and the ``opt`` path, declare four octets."""
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP

        proto = object.__new__(TCP)
        cases = {
            'seconds': {'timeout': 30},
            'minutes': {'timeout': 1 << 16},
            'timedelta': {'timeout': datetime.timedelta(minutes=5)},
        }
        for name, kwargs in cases.items():
            with self.subTest(name=name):
                schema = proto._make_mode_timeout(Option.User_Timeout_Option, **kwargs)
                self.assertEqual(schema.length, 4)
                self.assertEqual(len(schema.pack()), 4)

    def test_option_round_trips(self) -> 'None':
        """A segment made with the option parses back with the same timeout.

        ``1c04001e`` is kind 28, length 4, ``G`` clear and 30 seconds.

        """
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(options=[(Option.User_Timeout_Option, {'timeout': 30})])
        raw = tcp.data
        self.assertIn(bytes.fromhex('1c04001e'), raw)

        parsed = TCP(io.BytesIO(raw), len(raw))
        option = parsed.info.options[Option.User_Timeout_Option]
        self.assertEqual(option.length, 4)
        self.assertEqual(option.timeout, datetime.timedelta(seconds=30))


if __name__ == '__main__':
    unittest.main()
