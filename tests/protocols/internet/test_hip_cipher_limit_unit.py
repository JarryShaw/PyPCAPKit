# -*- coding: utf-8 -*-
"""HIP ``HIP_CIPHER`` accepts six Cipher IDs and keeps only the first six.

GitHub issue #1092. :rfc:`7401#section-5.2.8` says the sender "MUST make sure
that there are no more than six (6) Cipher IDs", and that a recipient handles
more "by accepting the first six Cipher IDs and dropping the rest". The reader
warned at six and kept every ID at seven or more.
"""
from __future__ import annotations

import importlib.util
import unittest
import warnings

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Header fields shared by every HIP packet built here.
HIP_BASE = {
    'next': 6, 'packet': 1, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPCipherLimitTests(unittest.TestCase):
    """``HIP_CIPHER``'s six-ID limit, against :rfc:`7401#section-5.2.8`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, count: 'int') -> 'tuple[object, list[warnings.WarningMessage], int]':
        """Build a packet carrying ``count`` distinct Cipher IDs and parse it back.

        Args:
            count: Number of Cipher IDs to put in the parameter.

        Returns:
            The parsed ``HIP_CIPHER`` data, the warnings raised while parsing,
            and the length of the packed frame.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        # Distinct values, so a test can tell *which* IDs were kept.
        built = HIP(parameters=[(Parameter.HIP_CIPHER, {'ciphers': list(range(1, count + 1))})],
                    extension=True, version=2, **HIP_BASE)
        octets = built.data
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = HIP(octets, len(octets), extension=True)
        params = parsed.info.parameters
        self.assertEqual(len(list(params)), 1)
        return params[Parameter.HIP_CIPHER], caught, len(octets)

    def _protocol_warnings(self, caught: 'list[warnings.WarningMessage]') -> 'list[warnings.WarningMessage]':
        """Keep only the :class:`ProtocolWarning` records from ``caught``."""
        from pcapkit.utilities.warnings import ProtocolWarning
        return [w for w in caught if issubclass(w.category, ProtocolWarning)]

    def test_five_and_six_ids_parse_without_warning(self) -> None:
        """Up to six IDs is legal, so nothing warns and every ID is kept."""
        for count in (5, 6):
            with self.subTest(count=count):
                param, caught, _ = self._parse(count)
                self.assertEqual(self._protocol_warnings(caught), [])
                self.assertEqual([int(c) for c in param.cipher_id],  # type: ignore[attr-defined]
                                 list(range(1, count + 1)))

    def test_seven_ids_warn_and_keep_the_first_six(self) -> None:
        """Seven IDs warn once, keep IDs 1-6, and still report the whole record.

        ``length`` stays the wire record's total (``Length = 14`` pads to 24),
        because the reader consumed all of it; only the data model drops the
        seventh ID.
        """
        param, caught, frame = self._parse(7)
        self.assertEqual(len(self._protocol_warnings(caught)), 1)
        self.assertEqual([int(c) for c in param.cipher_id], [1, 2, 3, 4, 5, 6])  # type: ignore[attr-defined]
        self.assertEqual(param.length, 24)  # type: ignore[attr-defined]
        # 40-octet fixed header plus the one 24-octet record.
        self.assertEqual(frame, 40 + 24)


if __name__ == '__main__':
    unittest.main()
