# -*- coding: utf-8 -*-
"""GitHub issue #2516: a trial parse that raises at full length and is kept as ``Raw`` warns nothing.

:func:`~pcapkit.corekit.decorators.beholder` replaces a layer that raises at any
length (#2308), so holding only a next layer captured shorter than its length
hint (#1580) lets a full-length layer's warnings through: a TCP segment to port
443 that starts mid-record warns ``packet length < 0`` twice, from TLS's record
header and from the SSLv2 fallback it tries, for a TLS layer the result keeps as
``Raw``. Under ``beholder``,
:meth:`~pcapkit.protocols.protocol.ProtocolBase._parse_next_layer` holds every
layer, and drops a replaced layer's warnings with it. A kept layer warns from the
caller's line, after the layers it carries. Outside ``beholder``, a full-length
layer cannot be replaced and holds nothing.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import inspect
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): exercises the warning machinery, which free-threaded
#: builds make context-aware.
__tier__ = 'ALL'

#: Ethernet destination and source addresses.
MACS = bytes(6) + bytes(range(1, 7))
#: A 20-octet TCP header, 40000 to 443, PSH|ACK.
TCP_TO_443 = struct.pack('!HHIIBBHHH', 40000, 443, 1, 1, 5 << 4, 0x18, 65535, 0, 0)
#: Octets from the middle of a TLS record, as the issue's segment carries.
MID_RECORD = b'.android' + bytes(range(256)) * 4
#: The ``error`` of the ``Raw`` that :data:`MID_RECORD`'s TLS is kept as.
TLS_ERROR = 'TLS: invalid format: unrecognised content type 46'
#: An SSLv2 CLIENT-HELLO, 2-octet header, cut 4 octets short of its record.
CUT_HELLO = (b'\x80\x1c' + b'\x01\x00\x02\x00\x03\x00\x00\x00\x10'
             + b'\x01\x00\x80' + bytes(12))
#: A 24-octet TCP header whose one option runs past its end.
TCP_CUT = struct.pack('!HHIIBBHHH', 12345, 80, 1, 0, 6 << 4, 0x02, 4095, 0, 0) + bytes.fromhex('b4060000')
#: The message IPv4's Security option below reports, for a layer that is kept.
OPTION_WARNING = 'IPv4: [OptNo 130] invalid format: remaining data'
#: The warnings of IPv6 carrying a Shim6 header cut to 1 octet, as #1580 pins them.
SHIM6_CUT_MESSAGES = ['packet length < 0: -1',
                      'IPv6: extension header declares a length of 8 octet(s) with 1 octet(s) '
                      'left in the chain; stopping the walk instead of skipping past it']


def _ipv4(proto: 'int', body: 'bytes', options: 'bytes' = b'') -> 'bytes':
    """An Ethernet frame carrying IPv4 with ``options``, then ``body`` as protocol ``proto``."""
    header = struct.pack('!BBHHHBBH4s4s', 0x45 + len(options) // 4, 0, 20 + len(options) + len(body),
                         0, 0, 64, proto, 0, bytes([127, 0, 0, 1]), bytes([127, 0, 0, 2]))
    return MACS + b'\x08\x00' + header + options + body


def _ipv6(next_header: 'int', body: 'bytes') -> 'bytes':
    """IPv6 carrying ``body`` as ``next_header``."""
    return (struct.pack('!IHBB', 0x60000000, len(body), next_header, 64)
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + body)


#: IPv4's Security option, its flags running on past the last octet, padded.
SECURITY = bytes.fromhex('8205ab0000') + bytes(3)


class TestTrialParseFullLength(unittest.TestCase):
    """Pin that a full-length layer replaced by ``beholder`` reports nothing."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _parse(klass: 'str', data: 'bytes', action: 'str' = 'always') -> 'tuple[object, list[warnings.WarningMessage]]':
        """Parse ``data`` as ``klass``, TCP or Ethernet, with the warnings it reports."""
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.transport.tcp import TCP

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter(action)
            parsed = {'TCP': TCP, 'Ethernet': Ethernet}[klass](data, len(data))
        return parsed, caught

    def test_mid_record_segment_is_raw_and_warns_nothing(self) -> None:
        """The issue's segment: TLS and its SSLv2 fallback both reject it, on both channels."""
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.logging import logger

        with capture(logger) as recorder:
            parsed, caught = self._parse('TCP', TCP_TO_443 + MID_RECORD)
        self.assertIs(type(parsed.payload), Raw)  # type: ignore[attr-defined]
        self.assertEqual(parsed.payload.info.error, TLS_ERROR)  # type: ignore[attr-defined]
        self.assertEqual([str(item.message) for item in caught], [])
        self.assertEqual([record.getMessage() for record in recorder.records
                          if record.getMessage().startswith('packet length')], [])

    def test_error_filter_reports_the_tls_rejection(self) -> None:
        """Under ``error``, the ``Raw`` names TLS's rejection, not a warning of the trial."""
        parsed, caught = self._parse('TCP', TCP_TO_443 + MID_RECORD, 'error')
        self.assertEqual(str(parsed.protochain), 'TCP:Raw')  # type: ignore[attr-defined]
        self.assertEqual(parsed.payload.info.error, TLS_ERROR)  # type: ignore[attr-defined]
        self.assertEqual(caught, [])

    def test_rejected_sslv2_fallback_warns_nothing(self) -> None:
        """A cut SSLv2 hello passes TLS's header read, then warns only in the fallback it fails."""
        parsed, caught = self._parse('TCP', TCP_TO_443 + CUT_HELLO)
        self.assertEqual(str(parsed.protochain), 'TCP:Raw')  # type: ignore[attr-defined]
        self.assertEqual(parsed.payload.info.error,  # type: ignore[attr-defined]
                         'TLS: invalid format: unrecognised content type 128')
        self.assertEqual([str(item.message) for item in caught], [])

    def test_full_length_layer_that_raises_warns_nothing(self) -> None:
        """TCP past its hint raises under IPv4's and IPv6's own ``beholder`` alike."""
        from pcapkit.protocols.misc.raw import Raw

        for name, frame in (('IPv4', _ipv4(6, TCP_CUT)),
                            ('IPv6', MACS + b'\x86\xdd' + _ipv6(6, TCP_CUT))):
            with self.subTest(carrier=name):
                parsed, caught = self._parse('Ethernet', frame)
                self.assertEqual(str(parsed.protochain), f'Ethernet:{name}:TCP')  # type: ignore[attr-defined]
                self.assertIs(type(parsed.payload.payload), Raw)  # type: ignore[attr-defined]
                self.assertEqual([str(item.message) for item in caught], [])

    def test_well_formed_tls_record_warns_nothing(self) -> None:
        """Control: a whole TLS record on 443 parses as TLS and reports nothing."""
        parsed, caught = self._parse('TCP', TCP_TO_443 + b'\x17\x03\x03\x00\x04abcd')
        self.assertEqual(str(parsed.protochain), 'TCP:TLS 1.2')  # type: ignore[attr-defined]
        self.assertEqual(caught, [])

    def test_kept_layer_still_warns_from_the_callers_line(self) -> None:
        """Control: a kept IPv4 is held, and reports its warning from the caller's line."""
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.utilities.warnings import ProtocolWarning

        frame = _ipv4(17, struct.pack('!HHHH', 40000, 40001, 12, 0) + b'abcd', SECURITY)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            line = inspect.currentframe().f_lineno + 1  # type: ignore[union-attr]
            parsed = Ethernet(frame, len(frame))
        self.assertEqual(str(parsed.protochain), 'Ethernet:IPv4:UDP:Raw')
        self.assertEqual([(item.category, str(item.message), item.filename, item.lineno) for item in caught],
                         [(ProtocolWarning, OPTION_WARNING, __file__, line)])

    def test_kept_layer_reports_after_the_layers_it_carries(self) -> None:
        """Each held layer reports as its own parse ends, so IPv4's warning follows IPv6's."""
        shim6_cut = _ipv6(140, b'\x00')
        _, caught = self._parse('Ethernet', _ipv4(41, shim6_cut, SECURITY))
        self.assertEqual([str(item.message) for item in caught], SHIM6_CUT_MESSAGES + [OPTION_WARNING])

    def test_full_length_layer_outside_beholder_holds_nothing(self) -> None:
        """Outside ``beholder``, a full-length IPv4 reports its warning before the layers it carries.

        Nothing can replace it, so it holds nothing, even inside a block that
        discards: its warning is reported as raised. Only the layers its own
        ``beholder`` parses are held, and report as their parse ends.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.utilities.warnings import hold_warnings

        packet = _ipv4(41, _ipv6(140, b'\x00'), SECURITY)[len(MACS) + 2:]  # past the Ethernet header
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with hold_warnings() as outer:
                outer.discard = True
                parsed = ProtocolBase._parse_next_layer(IPv4, packet, len(packet))  # pylint: disable=protected-access
        self.assertEqual(str(parsed.protochain), 'IPv4:IPv6:IPv6-Ext')
        self.assertEqual([str(item.message) for item in caught], [OPTION_WARNING] + SHIM6_CUT_MESSAGES)


if __name__ == '__main__':
    unittest.main()
