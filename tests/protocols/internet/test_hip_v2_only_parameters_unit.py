# -*- coding: utf-8 -*-
"""HIP rejects the HIPv2-only list parameters inside a HIPv1 packet.

GitHub issue #1133. :rfc:`7401` introduces ``DH_GROUP_LIST`` (511),
``HIP_CIPHER`` (579), ``HIT_SUITE_LIST`` (715) and ``TRANSPORT_FORMAT_LIST``
(2049); :rfc:`5201` has none of them. All four built and parsed back at
version 1. They now raise :class:`~pcapkit.utilities.exceptions.ProtocolError`
on both sides, as ``R1_Counter`` does for the opposite mismatch.
"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Header fields shared by every HIP packet built here.
HIP_BASE = {
    'next': 6, 'packet': 1, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPv2OnlyParameterTests(unittest.TestCase):
    """The four :rfc:`7401` list parameters, at HIP versions 1 and 2."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _cases(self) -> 'dict[object, dict[str, object]]':
        """Map each HIPv2-only parameter code to the keywords that build it."""
        from pcapkit.const.hip.parameter import Parameter

        return {
            Parameter.DH_GROUP_LIST: {'groups': [1]},
            Parameter.HIP_CIPHER: {'ciphers': [1]},
            Parameter.HIT_SUITE_LIST: {'suites': [1]},
            Parameter.TRANSPORT_FORMAT_LIST: {'formats': [Parameter.ESP_INFO]},
        }

    def _build(self, code: 'object', kwargs: 'dict[str, object]', version: 'int') -> 'bytes':
        from pcapkit.protocols.internet.hip import HIP

        return HIP(parameters=[(code, kwargs)], extension=True,
                   version=version, **HIP_BASE).data

    def test_building_at_version_1_raises(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for code, kwargs in self._cases().items():
            with self.subTest(code=code):
                with self.assertRaisesRegex(ProtocolError, rf'HIPv1: \[ParamNo {code}\] invalid parameter'):
                    self._build(code, kwargs, 1)

    def test_parsing_at_version_1_raises(self) -> None:
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        for code, kwargs in self._cases().items():
            with self.subTest(code=code):
                # Build at version 2, then rewrite the 4-bit Version field
                # (the high nibble of octet 3) to 1.
                octets = bytearray(self._build(code, kwargs, 2))
                octets[3] = (octets[3] & 0x0F) | 0x10
                with self.assertRaisesRegex(ProtocolError, rf'HIPv1: \[ParamNo {code}\] invalid parameter'):
                    HIP(bytes(octets), len(octets), extension=True)

    def test_version_2_still_round_trips(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for code, kwargs in self._cases().items():
            with self.subTest(code=code):
                octets = self._build(code, kwargs, 2)
                parsed = HIP(octets, len(octets), extension=True)
                self.assertEqual(parsed.info.version, 2)
                codes = [int(key) for key in parsed.info.parameters]
                self.assertEqual(codes, [int(code)])  # type: ignore[call-overload]


if __name__ == '__main__':
    unittest.main()
