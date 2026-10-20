# -*- coding: utf-8 -*-
"""The generator's Jumbo Payload frame is a jumbogram RFC 2675 accepts. C.f. #1687.

:file:`examples/generators/options.py` puts HOPOPT's Jumbo Payload case in an
IPv6 envelope in :file:`examples/captures/options-ipv6.pcap`. It used to carry
the option's default Jumbo Payload Length of 0 behind a non-zero Payload Length,
two of the errors :rfc:`2675#section-3` lists, and since #1687 the default
engine rejects such a packet: the frame stopped at IPv6 and its option was never
walked. The case now carries a legal length, and ``_frame`` builds a genuine
jumbogram around it, filled out by ``_jumbogram_datagram``.

:data:`JUMBO_LEN` and the datagram's fields are spelled out here rather than
read from the generator, so a wrong generator constant fails as ``0 != 65536``.

This module is unit tier: it builds its frames in memory from the generator's
own cases and reads no capture. The checks on ``_frame`` need scapy, which
builds the envelope, and skip without it. ``_jumbogram_datagram`` needs none,
and one check builds it with scapy unimportable, as on a unit-tier leg.

"""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import time_limit
from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): tests examples/generators/options.py, which make_samples.py runs
#: on every integration leg.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: The Jumbo Payload Length the case has to carry: the least a jumbogram may,
#: one above what the 16-bit Payload Length holds (:rfc:`2675#section-2`).
JUMBO_LEN = 65536
#: The envelope's IPv6 addresses, ``2001:db8::1`` and ``2001:db8::2``, as octets.
SRC6 = bytes.fromhex('20010db8000000000000000000000001')
DST6 = bytes.fromhex('20010db8000000000000000000000002')
#: Source and destination port of the datagram: an ephemeral port, and Discard.
PORTS = (50000, 9)


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/options.py` by path, under a name of its own.

    Returns:
        The generator module.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'options.py'
    spec = importlib.util.spec_from_file_location('pcapkit_samples_options_jumbogram', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the option generator from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _ones_sum(data: 'bytes') -> 'int':
    """The 16-bit one's complement sum of ``data`` [:rfc:`1071`], uncomplemented."""
    if len(data) % 2:
        data += b'\x00'
    total = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class JumbogramCaseTests(unittest.TestCase):
    """The ``hopopt-option/Jumbo_Payload`` case, and the datagram that fills it."""

    options = None  # type: Any
    outcome = None  # type: Any
    octets = b''

    @classmethod
    def setUpClass(cls) -> None:
        cls.options = _load_generator()
        case, = [case for case in cls.options.cases((cls.options.FAMILY_MAP['hopopt-option'],))
                 if case.name == 'Jumbo_Payload']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            cls.outcome = cls.options.roundtrip(case)
        cls.octets = cls.outcome.octets or b''

    def test_the_case_carries_a_legal_jumbo_payload_length(self) -> None:
        """It round-trips, names UDP next, and its option says 65,536."""
        from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length

        self.assertEqual(self.outcome.status, 'OK', self.outcome.detail)
        self.assertEqual(self.octets[0], 17)
        self.assertEqual(jumbo_payload_length(0, self.octets), JUMBO_LEN)

    def test_the_datagram_makes_up_the_jumbo_payload_length(self) -> None:
        """Header plus datagram is the Jumbo Payload Length, with a valid UDP checksum."""
        datagram = self.options._jumbogram_datagram(self.octets, JUMBO_LEN)  # pylint: disable=protected-access

        self.assertEqual(len(self.octets) + len(datagram), JUMBO_LEN)
        self.assertEqual((int.from_bytes(datagram[0:2], 'big'), int.from_bytes(datagram[2:4], 'big')), PORTS)
        self.assertEqual(int.from_bytes(datagram[4:6], 'big'), len(datagram))
        self.assertEqual(datagram[8:], bytes(len(datagram) - 8))
        self.assertNotEqual(datagram[6:8], b'\x00\x00')
        # A receiver's check: the sum over the pseudo-header and the datagram,
        # checksum included, is all ones (RFC 8200 section 8.1, RFC 1071).
        pseudo = SRC6 + DST6 + len(datagram).to_bytes(4, 'big') + b'\x00\x00\x00\x11'
        self.assertEqual(_ones_sum(pseudo + datagram), 0xFFFF)

    def test_the_datagram_needs_no_scapy(self) -> None:
        """It is built with scapy unimportable, as a unit-tier leg installs none."""
        blocked = {name: None for name in list(sys.modules) if name.startswith('scapy.')}
        blocked['scapy'] = None
        with mock.patch.dict(sys.modules, blocked):
            datagram = self.options._jumbogram_datagram(self.octets, JUMBO_LEN)  # pylint: disable=protected-access
        self.assertEqual(len(self.octets) + len(datagram), JUMBO_LEN)

    def test_a_jumbogram_it_cannot_fill_is_refused(self) -> None:
        """No UDP next header, or no room for a datagram that fits its Length field."""
        build = self.options._jumbogram_datagram  # pylint: disable=protected-access
        size = len(self.octets)
        for label, octets, jumbo in (
            ('next header TCP', b'\x06' + self.octets[1:], JUMBO_LEN),
            ('no room for a UDP header', self.octets, size + 7),
            ('more than a UDP Length holds', self.octets, size + 0x10000),
        ):
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    build(octets, jumbo)

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_the_frame_is_a_jumbogram_read_whole(self) -> None:
        """Payload Length 0, octets to the Jumbo Payload Length, decoded to the end."""
        from pcapkit.protocols.link.ethernet import Ethernet

        frame = bytes(self.options._frame(self.options.FAMILY_MAP['hopopt-option'],  # pylint: disable=protected-access
                                          self.octets, 12))
        self.assertEqual(frame[14 + 4:14 + 6], b'\x00\x00')
        self.assertEqual(len(frame), 14 + 40 + JUMBO_LEN)
        self.assertEqual(frame[14 + 40:14 + 40 + len(self.octets)], self.octets)

        with time_limit():
            proto = Ethernet(frame, len(frame))
        self.assertEqual(str(proto.protochain), 'Ethernet:IPv6:HOPOPT:UDP:Raw')
        ipv6 = proto.payload.info  # type: Any
        self.assertEqual((ipv6.payload, ipv6.hdr_len + ipv6.raw_len), (0, 40 + JUMBO_LEN))


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies or scapy not installed')
class OtherIPv6EnvelopeTests(unittest.TestCase):
    """Every other frame in an IPv6 envelope keeps the Payload Length of its octets."""

    def test_only_the_jumbo_payload_frame_is_a_jumbogram(self) -> None:
        options = _load_generator()
        families = tuple(family for family in options.FAMILIES if family.envelope == 'ipv6')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            outcomes = [outcome for outcome in options.outcomes(families)
                        if outcome.status in options.CAPTURABLE]
        self.assertTrue(outcomes)

        jumbograms = []
        for outcome in outcomes:
            family = options.FAMILY_MAP[outcome.case.family]
            frame = bytes(options._frame(family, outcome.octets, 0))  # pylint: disable=protected-access
            length = int.from_bytes(frame[14 + 4:14 + 6], 'big')
            if length == 0:
                jumbograms.append(outcome.case.label)
                continue
            with self.subTest(case=outcome.case.label):
                self.assertEqual(length, len(outcome.octets))
                self.assertEqual(frame[14 + 40:], outcome.octets)
        self.assertEqual(jumbograms, ['hopopt-option/Jumbo_Payload'])


if __name__ == '__main__':
    unittest.main()
