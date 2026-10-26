# -*- coding: utf-8 -*-
"""GitHub issue #2308: a trial parse that raises and is kept as ``Raw`` warns nothing.

:meth:`~pcapkit.protocols.protocol.ProtocolBase._parse_next_layer` holds the
warnings of a next layer captured shorter than its length hint (#1580). When
that parse raises, :func:`~pcapkit.corekit.decorators.beholder` replaces the
layer, and without the fix the held warnings were reported anyway: an Ethernet
frame cut inside its IPv4 header warned ``packet length < 0`` three times for an
IPv4 layer the result keeps as ``Raw``. They are dropped with the layer, whose
``error`` names the cut. A held layer that is kept still warns, and so does one
that raises where no :func:`~pcapkit.corekit.decorators.beholder` replaces it.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import re
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): exercises the warning machinery, which free-threaded
#: builds make context-aware.
__tier__ = 'ALL'

#: The first 10 of the 20 octets of an IPv4 header.
IPV4_CUT = bytes.fromhex('4500008c000100004011')
#: An Ethernet frame carrying :data:`IPV4_CUT`.
FRAME = bytes(6) + bytes(range(1, 7)) + b'\x08\x00' + IPV4_CUT
#: The ``error`` of the ``Raw`` that :data:`FRAME`'s IPv4 is kept as.
ERROR = 'IPv4: header length 20 runs past the end of the data (10 octets)'


def _ipv6(next_header: 'int') -> 'bytes':
    """An Ethernet frame carrying IPv6 whose ``next_header`` is cut to 1 octet."""
    return (bytes(6) + bytes(range(1, 7)) + b'\x86\xdd'
            + bytes.fromhex('600000000001') + bytes([next_header, 64])
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + b'\x00')


#: The warnings of the kept, cut ``IPv6_Ext`` that each :func:`_ipv6` frame ends in.
IPV6_EXT_CUT = ['packet length < 0: -1',
                'IPv6: extension header declares a length of 8 octet(s) with 1 octet(s) '
                'left in the chain; stopping the walk instead of skipping past it']


class TestTrialParseRaises(unittest.TestCase):
    """Pin that a raising trial parse replaced by ``beholder`` reports nothing."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, frame: 'bytes', action: 'str' = 'always') -> 'tuple[object, list[str]]':
        """Parse ``frame`` as Ethernet, with the :class:`SchemaWarning` messages it reports."""
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.utilities.warnings import SchemaWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter(action)
            parsed = Ethernet(frame, len(frame))
        return parsed, [str(item.message) for item in caught if issubclass(item.category, SchemaWarning)]

    def test_cut_ipv4_header_is_raw_and_warns_nothing(self) -> None:
        """IPv4 cut to 10 octets raises, is kept as ``Raw`` naming the cut, and reports nothing."""
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.logging import logger

        with capture(logger) as recorder:
            parsed, messages = self._parse(FRAME)
        ipv4 = parsed.payload  # type: ignore[attr-defined]
        self.assertIsInstance(ipv4, Raw)
        self.assertEqual(ipv4.info.error, ERROR)
        self.assertEqual(messages, [])
        self.assertEqual([record.getMessage() for record in recorder.records
                          if record.getMessage().startswith('packet length')], [])

    def test_error_filter_keeps_the_cut_as_the_error(self) -> None:
        """Under ``error``, the ``Raw`` names the cut header, not a warning it dropped."""
        from pcapkit.protocols.misc.raw import Raw

        parsed, messages = self._parse(FRAME, 'error')
        self.assertIsInstance(parsed.payload, Raw)  # type: ignore[attr-defined]
        self.assertEqual(parsed.payload.info.error, ERROR)  # type: ignore[attr-defined]
        self.assertEqual(messages, [])

    def test_replaced_by_ipv6_ext_reports_only_the_replacement(self) -> None:
        """A cut Hop-by-Hop header raises and is parsed as ``IPv6_Ext``, which alone warns."""
        parsed, messages = self._parse(_ipv6(0))
        self.assertEqual(str(parsed.protochain), 'Ethernet:IPv6:IPv6-Ext')  # type: ignore[attr-defined]
        self.assertEqual(messages, IPV6_EXT_CUT)

    def test_kept_trial_still_warns(self) -> None:
        """A cut Shim6 header is held, kept, and reports its warnings as before."""
        parsed, messages = self._parse(_ipv6(140))
        self.assertEqual(str(parsed.protochain), 'Ethernet:IPv6:IPv6-Ext')  # type: ignore[attr-defined]
        self.assertEqual(messages, IPV6_EXT_CUT)

    def test_raise_outside_beholder_reports(self) -> None:
        """With no ``beholder`` to replace it, the layer's error and its warnings both reach the caller."""
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.warnings import SchemaWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with self.assertRaisesRegex(ProtocolError, re.escape(ERROR)):
                ProtocolBase._parse_next_layer(IPv4, IPV4_CUT, len(IPV4_CUT))  # pylint: disable=protected-access
        self.assertEqual([str(item.message) for item in caught if issubclass(item.category, SchemaWarning)],
                         ['packet length < 0: -2', 'packet length < 0: -6', 'packet length < 0: -10',
                          'packet length < 0: -10'])


if __name__ == '__main__':
    unittest.main()
