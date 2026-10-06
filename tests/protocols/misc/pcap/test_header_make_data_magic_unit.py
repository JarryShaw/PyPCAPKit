from __future__ import annotations

import importlib.util
import io
import unittest
import warnings

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

MAGIC = {
    ('little', False): b'\xd4\xc3\xb2\xa1',
    ('little', True): b'\x4d\x3c\xb2\xa1',
    ('big', False): b'\xa1\xb2\xc3\xd4',
    ('big', True): b'\xa1\xb2\x3c\x4d',
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPHeaderMakeDataMagicUnitTests(unittest.TestCase):
    """``Header._make_data`` keeps the byte order and resolution (GH-1125)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_make_data_keys_are_make_keywords(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.protocols.protocol import _declared_keywords

        accepted = _declared_keywords(Header)
        self.assertIsNotNone(accepted)
        made = Header._make_data(Header(byteorder='big', nanosecond=True).info)
        self.assertEqual(set(made) - set(accepted), set())

    def test_from_data_round_trips_every_magic(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcap.header import Header

        for (byteorder, nanosecond), magic in MAGIC.items():
            with self.subTest(byteorder=byteorder, nanosecond=nanosecond):
                built = Header(byteorder=byteorder, nanosecond=nanosecond,
                               thiszone=-3600, snaplen=1500, network=LinkType.ETHERNET)
                self.assertEqual(built.data[:4], magic)

                with warnings.catch_warnings():
                    warnings.simplefilter('error')
                    rebuilt = Header.from_data(built.info)
                self.assertEqual(rebuilt.data, built.data)

                parsed = Header(io.BytesIO(built.data))
                self.assertEqual(Header.from_data(parsed.info).data, built.data)


if __name__ == '__main__':
    unittest.main()
