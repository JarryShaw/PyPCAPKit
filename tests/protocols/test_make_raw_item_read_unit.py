# -*- coding: utf-8 -*-
"""A raw ``make()`` item rejected by ``read`` raises the wrapped error.

GitHub issue #1394: :meth:`~pcapkit.protocols.protocol.ProtocolBase.unpack`
wrapped only the schema re-parse of a made header holding raw items. A raw
item the schema accepts but ``read`` rejects -- an option whose length runs
past the option area, or one cut short of its own fields -- escaped as the
reader's bare :exc:`~pcapkit.utilities.exceptions.ProtocolError`. The read is
now covered too: the error says ``malformed raw item given to make()``,
carries the reader's message, and chains it as ``__cause__``.

Every case builds its own packet in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so they belong to the live
:mod:`pcapkit` import.

"""

import importlib
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


def _attr(path: 'str') -> 'Any':
    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


#: One raw item per protocol that the schema parses and ``read`` rejects:
#: (protocol class, construction keywords, the reader's own message).
READ_REJECTED = {
    # the lone ``0x02`` takes the next item's kind octet as its length, 148,
    # which runs past the 8-octet option area
    'IPv4 overrun': ('pcapkit.protocols.internet.ipv4.IPv4',
                     {'options': [b'\x02', b'\x94\x04\x00\x00'], 'protocol': 253},
                     r'IPv4: invalid format'),
    'IPv4 short': ('pcapkit.protocols.internet.ipv4.IPv4',
                   {'options': [b'\x0c'], 'protocol': 253},
                   r'IPv4: \[OptNo 12\] invalid format'),
    'TCP': ('pcapkit.protocols.transport.tcp.TCP',
            {'options': [b'\x03']},
            r'TCP: \[OptNo 3\] invalid format'),
    'HOPOPT': ('pcapkit.protocols.internet.hopopt.HOPOPT',
               {'extension': True, 'options': [b'\x23']},
               r'HOPOPT: \[OptNo 35\] invalid format'),
    'IPv6_Opts': ('pcapkit.protocols.internet.ipv6_opts.IPv6_Opts',
                  {'extension': True, 'options': [b'\x26']},
                  r'IPv6-Opts: \[OptNo 38\] invalid format'),
    'MH': ('pcapkit.protocols.internet.mh.MH',
           {'data': {'options': [b'\x2b']}},
           r'MH: \[Opt 43\] invalid format'),
    'SCTP': ('pcapkit.protocols.transport.sctp.SCTP',
             {'chunks': [b'\x01']},
             r'SCTP: \[Chunk 1\] invalid format'),
    # ESP_INFO needs a 12-octet body, and this one has 8
    'HIP': ('pcapkit.protocols.internet.hip.HIP',
            {'extension': True, 'parameters': [b'\x00\x41\x00\x08' + bytes(8)]},
            r'HIPv6: \[ParamNo 65\] invalid format'),
}


class TestRawItemRejectedByRead(unittest.TestCase):
    """A raw item ``read`` rejects raises the wrapped ``ProtocolError`` (#1394)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_read_rejection_is_wrapped(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        for case, (klass, kwargs, message) in READ_REJECTED.items():
            with self.subTest(case=case):
                cls = _attr(klass)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaisesRegex(exc, r'malformed raw item given to make\(\)') as caught:
                        cls(**kwargs)
                # the reader's own error is chained, and its message kept
                self.assertIsInstance(caught.exception.__cause__, exc)
                self.assertRegex(str(caught.exception.__cause__), message)
                self.assertRegex(str(caught.exception), message)

    def test_well_formed_raw_item_still_builds(self) -> None:
        # the wider ``try`` leaves a raw item that does parse alone
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.IPv4')
        proto = ipv4(options=[b'\x94\x04\x00\x00'], protocol=253)
        self.assertEqual(proto.data.hex(), '460000180000000000fd00007f0000010000000094040000')


if __name__ == '__main__':
    unittest.main()
