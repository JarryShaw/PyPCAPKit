# -*- coding: utf-8 -*-
"""The HIP ``HOST_ID`` DI-Type/DI-Length word is two octets, not four.

GitHub issue #1118. :rfc:`7401#section-5.2.9` packs ``DI-Type`` (4 bits) and
``DI Length`` (12 bits) into one 16-bit word between ``HI Length`` and
``Algorithm``. The schema declared that word as a four-octet
:class:`~pcapkit.corekit.fields.strings.BitField` while its namespace covered
only sixteen bits, so a made ``HOST_ID`` carried two surplus zero octets, and a
conformant one was read two octets late -- ``Algorithm`` came out as the ECDSA
curve that follows it.

The DI word is non-zero in every case here (``FQDN``, two octets), because an
all-zero word reads the same at either width and cannot discriminate the defect.
"""
from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Header fields shared by every HIP packet built here, as in
#: :data:`examples.generators.options.HIP_BASE`.
HIP_BASE = {
    'next': 6, 'packet': 1, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

PUB_KEY = b'\xaa\xbb\xcc\xdd'
DI = b'ab'


def rfc_host_id() -> 'bytes':
    """A ``HOST_ID`` record laid out by hand from :rfc:`7401#section-5.2.9`.

    ECDSA (7) over NIST P-256 (1) with a four-octet public key, so ``HI Length``
    is six; ``DI-Type = 1`` (FQDN) and ``DI Length = 2`` share one word,
    ``0x1002``. ``Length`` is ``2 + 2 + 2 + 6 + 2 = 14``, and the record is
    padded to Section 5.2.1's ``11 + 14 - (14 + 3) % 8 = 24`` octets.

    Returns:
        The whole record, type-and-length header and padding included.

    """
    body = struct.pack('!HHH', 6, (1 << 12) | len(DI), 7)
    body += struct.pack('!H', 1) + PUB_KEY + DI
    record = struct.pack('!HH', 705, len(body)) + body
    return record + b'\x00' * ((-len(record)) % 8)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPHostIDDIWidthTests(unittest.TestCase):
    """``HOST_ID``'s DI word width, against :rfc:`7401#section-5.2.9`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_made_host_id_packs_the_rfc_layout(self) -> None:
        """A made ``HOST_ID`` is octet-for-octet the hand-built RFC record."""
        from pcapkit.const.hip.di import DITypes
        from pcapkit.const.hip.ecdsa_curve import ECDSACurve
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        schema = object.__new__(HIP)._make_param_host_id(  # type: ignore[arg-type]
            Parameter.HOST_ID, version=2, hi_curve=ECDSACurve.NIST_P_256,
            hi_pub_key=PUB_KEY, di=DI, di_type=DITypes.FQDN)

        self.assertEqual(schema.len, 14)
        # 26 octets before #1118: two zero octets after the DI word.
        self.assertEqual(schema.pack().hex(), rfc_host_id().hex())

    def test_rfc_host_id_parses_algorithm_and_di(self) -> None:
        """A conformant record reads ``Algorithm = 7`` and the DI it carries."""
        from pcapkit.const.hip.di import DITypes
        from pcapkit.const.hip.hi_algorithm import HIAlgorithm
        from pcapkit.protocols.schema.internet.hip import HostIDParameter

        raw = rfc_host_id()
        schema = HostIDParameter.unpack(raw, len(raw))  # type: ignore[arg-type]

        # Read as 1 -- the curve -- before #1118.
        self.assertEqual(schema.algorithm, HIAlgorithm.ECDSA)
        self.assertEqual(int(schema.algorithm), 7)
        self.assertEqual(schema.di_data['type'], DITypes.FQDN)
        self.assertEqual(schema.di_data['len'], len(DI))
        self.assertEqual(schema.hi.pub_key, PUB_KEY)  # type: ignore[union-attr]
        self.assertEqual(schema.di, DI)
        self.assertEqual(schema.pack(), raw)

    def test_a_lone_host_id_survives_a_hip_packet(self) -> None:
        """One ``HOST_ID`` in a real packet builds, parses and builds back.

        ``HIP.make`` derives the header's ``len`` from the parameter octets, so a
        record that is not a multiple of eight raised ``HIPv2: invalid format``
        on the way back in.
        """
        from pcapkit.const.hip.di import DITypes
        from pcapkit.const.hip.ecdsa_curve import ECDSACurve
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        options = {'hi_curve': ECDSACurve.NIST_P_256, 'hi_pub_key': PUB_KEY,
                   'di': DI, 'di_type': DITypes.FQDN}
        built = HIP(parameters=[(Parameter.HOST_ID, options)],
                    extension=True, version=2, **HIP_BASE).data
        self.assertEqual(built[40:], rfc_host_id())

        parsed = HIP(built, len(built), extension=True)
        param = parsed.info.parameters[Parameter.HOST_ID]
        self.assertEqual(int(param.algorithm), 7)
        self.assertEqual(param.di_type, DITypes.FQDN)
        self.assertEqual(param.di_len, len(DI))
        self.assertEqual(param.di, DI)

        again = HIP(parameters=parsed.info.parameters, extension=True,
                    version=2, **HIP_BASE).data
        self.assertEqual(again, built)


if __name__ == '__main__':
    unittest.main()
