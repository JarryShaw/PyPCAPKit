# -*- coding: utf-8 -*-
"""The generator's ICMP and ICMPv6 messages carry their RFC layouts. C.f. #2560.

The ``icmpv4-type`` and ``icmpv6-type`` families of
:file:`examples/generators/options.py` build one message per code of
``ICMPv4.__type__`` and ``ICMPv6.__type__``. A round trip cannot see an entry
retargeted at a method of the same layout: with Time Exceeded mapped to
``destination_unreachable`` the cycle still closes. So :data:`ICMPV4` and
:data:`ICMPV6` spell each type's data model and body out against :rfc:`792` and
:rfc:`4443` rather than reading them from the generator.

This module is unit tier: it builds its messages in memory from the generator's
own cases and reads no capture, so it runs on a fresh checkout.

"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import types
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): tests examples/generators/options.py, which make_samples.py runs
#: on every integration leg.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: An Echo body: identifier 0x1234, sequence number 0x5678, then the data.
ECHO = bytes.fromhex('1234' '5678') + b'ping'
#: An IPv4 header (protocol UDP) and its first eight payload octets, a UDP header.
QUOTED4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
           + bytes.fromhex('3039003500080000'))
#: An IPv6 header (next header UDP) and a UDP header.
QUOTED6 = (bytes.fromhex('6000000000081140') + bytes(15) + b'\x01' + bytes(15) + b'\x02'
           + bytes.fromhex('3039003500080000'))

#: ICMP type -> the data model it parses into, and its body after the 4-octet
#: header (:rfc:`792`).
ICMPV4 = {
    0: ('Echo', ECHO),                                    # Echo Reply
    3: ('DestinationUnreachable', bytes(4) + QUOTED4),    # 4 unused octets
    8: ('Echo', ECHO),                                    # Echo
    11: ('TimeExceeded', bytes(4) + QUOTED4),             # 4 unused octets
    12: ('ParameterProblem', b'\x08' + bytes(3) + QUOTED4),  # Pointer, 3 unused
}

#: ICMPv6 type -> the data model it parses into, and its body after the 4-octet
#: header (:rfc:`4443#section-3`, :rfc:`4443#section-4`).
ICMPV6 = {
    1: ('DestinationUnreachable', bytes(4) + QUOTED6),        # 4 unused octets
    2: ('PacketTooBig', (1280).to_bytes(4, 'big') + QUOTED6),  # 32-bit MTU
    3: ('TimeExceeded', bytes(4) + QUOTED6),                  # 4 unused octets
    4: ('ParameterProblem', (6).to_bytes(4, 'big') + QUOTED6),  # 32-bit Pointer
    128: ('Echo', ECHO),                                      # Echo Request
    129: ('Echo', ECHO),                                      # Echo Reply
}

#: Family label -> (protocol module and class, data module, expected table).
FAMILIES = {
    'icmpv4-type': (('pcapkit.protocols.internet.icmpv4', 'ICMPv4'),
                    'pcapkit.protocols.data.internet.icmpv4', ICMPV4),
    'icmpv6-type': (('pcapkit.protocols.internet.icmpv6', 'ICMPv6'),
                    'pcapkit.protocols.data.internet.icmpv6', ICMPV6),
}


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/options.py` by path, under a name of its own.

    Returns:
        The generator module.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'options.py'
    spec = importlib.util.spec_from_file_location('pcapkit_samples_options_icmp', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the option generator from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _ones_complement_sum(octets: bytes) -> int:
    """The :rfc:`1071` sum of ``octets``, an odd last octet padded with a zero."""
    padded = octets + bytes(len(octets) % 2)
    total = sum(int.from_bytes(padded[i:i + 2], 'big') for i in range(0, len(padded), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ICMPGeneratedMessageTests(unittest.TestCase):
    """Each ``icmpv4-type`` and ``icmpv6-type`` case, as the generator builds it."""

    @classmethod
    def setUpClass(cls) -> None:
        options = _load_generator()
        cls.messages = {}  # type: dict[str, dict[int, Any]]
        for label in FAMILIES:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                cls.messages[label] = {
                    int(outcome.case.code): outcome
                    for outcome in options.outcomes((options.FAMILY_MAP[label],))}

    def test_every_type_is_generated(self) -> None:
        """Each family yields exactly the registered types, and each round-trips."""
        for label, (_, _, expected) in FAMILIES.items():
            with self.subTest(family=label):
                self.assertEqual(sorted(self.messages[label]), sorted(expected))
                for code, outcome in self.messages[label].items():
                    with self.subTest(type=code):
                        self.assertEqual(outcome.status, 'OK', outcome.detail)

    def test_each_message_is_laid_out_as_its_rfc_says(self) -> None:
        """Type, a zero code, the checksum, then the type's own body."""
        for label, (_, _, expected) in FAMILIES.items():
            for code, outcome in self.messages[label].items():
                with self.subTest(family=label, type=code):
                    octets = outcome.octets
                    self.assertEqual(octets[:2], bytes([code, 0]))
                    self.assertEqual(octets[4:].hex(), expected[code][1].hex())

    def test_each_icmpv4_checksum_is_the_rfc_1071_sum(self) -> None:
        """The whole message, checksum included, sums to all ones (:rfc:`792`)."""
        for code, outcome in self.messages['icmpv4-type'].items():
            with self.subTest(type=code):
                self.assertEqual(_ones_complement_sum(outcome.octets), 0xFFFF)

    def test_each_message_parses_into_its_types_data_model(self) -> None:
        """The data model is the one :data:`ICMPV4` and :data:`ICMPV6` name.

        This is what a retarget between two types of the same layout changes:
        Time Exceeded parsed by Destination Unreachable's method yields a
        ``DestinationUnreachable``, octets unchanged.

        """
        for label, ((module, name), data_module, expected) in FAMILIES.items():
            protocol = getattr(importlib.import_module(module), name)
            data = importlib.import_module(data_module)
            for code, outcome in self.messages[label].items():
                with self.subTest(family=label, type=code):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        parsed = protocol(outcome.octets, len(outcome.octets))
                    self.assertIs(type(parsed.info), getattr(data, expected[code][0]))


if __name__ == '__main__':
    unittest.main()
