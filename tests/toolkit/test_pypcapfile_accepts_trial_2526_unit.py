# -*- coding: utf-8 -*-
"""GitHub issue #2526: pypcapfile's header check warns nothing for a header it rejects.

:func:`~pcapkit.toolkit.pypcapfile._default_accepts` asks pcapkit's IPv4 or TCP
parser about a header, and answers :data:`False` when that raises. The #2308
rule applies: the trial's warnings describe a header nothing keeps, so they go
with it. Held by nothing, a TCP header whose Timestamps option runs past its end
warns ``packet length < 0`` twice before the answer. A header the parser accepts
warns from the caller's line.

The parser reads its own header rather than a next layer, so setting
``beholding`` around it holds nothing, and the trial holds its own warnings.

The answers are cached by octets, so each test clears the cache before it asks.
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


def _ipv4(options: 'bytes') -> 'bytes':
    """A bare IPv4 header carrying ``options``."""
    return struct.pack('!BBHHHBBH4s4s', 0x45 + len(options) // 4, 0, 20 + len(options),
                       0, 0, 64, 6, 0, bytes([127, 0, 0, 1]), bytes([127, 0, 0, 2])) + options


#: A 24-octet TCP header whose Timestamps option claims 10 octets of the 4 left.
TCP_TIMESTAMPS_CUT = (struct.pack('!HHIIBBHHH', 12345, 80, 1, 0, 6 << 4, 0x02, 4095, 0, 0)
                      + bytes.fromhex('080a0000'))
#: A 24-octet IPv4 header whose Record Route option claims 40 octets of the 4 left.
IPV4_RECORD_ROUTE_CUT = _ipv4(bytes.fromhex('07280400'))
#: A 28-octet IPv4 header whose Security option runs on past its last octet.
IPV4_SECURITY = _ipv4(bytes.fromhex('8205ab0000') + bytes(3))
#: The warning :data:`IPV4_SECURITY`'s option reports.
SECURITY_WARNING = 'IPv4: [OptNo 130] invalid format: remaining data'


class TestAcceptsTrial(unittest.TestCase):
    """Pin that a rejected header reports nothing, and an accepted one does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _ask(self, name: 'str', header: 'bytes',
             action: 'str' = 'always') -> 'tuple[bool, list[warnings.WarningMessage]]':
        """Ask the uncached check about ``header``, with the warnings it reports."""
        from pcapkit.toolkit.pypcapfile import _default_accepts

        _default_accepts.cache_clear()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter(action)
            answer = _default_accepts(name, header)
        return answer, caught

    def test_rejected_header_warns_nothing(self) -> None:
        """A TCP or IPv4 header whose option runs past its end is rejected, reporting nothing on either channel."""
        from pcapkit.utilities.logging import logger

        for name, header in (('TCP', TCP_TIMESTAMPS_CUT), ('IPv4', IPV4_RECORD_ROUTE_CUT)):
            with self.subTest(name=name):
                with capture(logger) as recorder:
                    answer, caught = self._ask(name, header)
                self.assertFalse(answer)
                self.assertEqual([str(item.message) for item in caught], [])
                self.assertEqual([record.getMessage() for record in recorder.records
                                  if record.getMessage().startswith('packet length')], [])

    def test_error_filter_rejects_a_warning_header(self) -> None:
        """Control: under ``error``, a header that warns is rejected, and nothing escapes."""
        for name, header in (('TCP', TCP_TIMESTAMPS_CUT), ('IPv4', IPV4_SECURITY)):
            with self.subTest(name=name):
                answer, caught = self._ask(name, header, 'error')
                self.assertFalse(answer)
                self.assertEqual(caught, [])

    def test_accepted_header_warns_from_the_callers_line(self) -> None:
        """Control: an IPv4 header the parser accepts reports its option's warning."""
        from pcapkit.toolkit.pypcapfile import _default_accepts
        from pcapkit.utilities.warnings import ProtocolWarning

        _default_accepts.cache_clear()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            line = inspect.currentframe().f_lineno + 1  # type: ignore[union-attr]
            answer = _default_accepts('IPv4', IPV4_SECURITY)
        self.assertTrue(answer)
        self.assertEqual([(item.category, str(item.message), item.filename, item.lineno) for item in caught],
                         [(ProtocolWarning, SECURITY_WARNING, __file__, line)])


if __name__ == '__main__':
    unittest.main()
