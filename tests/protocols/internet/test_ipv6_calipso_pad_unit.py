# -*- coding: utf-8 -*-
"""A CALIPSO option keeps the octets ``Opt Data Len`` covers past its bitmap.

GitHub issue #1403: those octets were a zero-packing padding field missing from
the data model, so :meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data`
dropped them, shrank ``Opt Data Len`` and padded the header with a ``PadN``
instead. They are now the ``pad`` data field, written back on rebuild.

Every case builds its own octets in memory and reads no capture. The classes
are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so that they belong to the
:mod:`pcapkit` import that is live when the test runs.

"""

import importlib
import io
import unittest

from tests._support import reimport_once_per_class

#: The protocol classes sharing the option code, by module and class name.
PROTOCOLS = (
    ('pcapkit.protocols.internet.hopopt', 'HOPOPT'),
    ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts'),
)

#: Parsed headers which have to rebuild unchanged, with the pad each carries.
HEADERS = {
    'cmpt_len 0, zero pad': ('3b01' '070c' '00000001' '0005' '0000' '00000000', b'\x00' * 4),
    'cmpt_len 0, non-zero pad': ('3b01' '070c' '00000001' '0005' '0000' 'aabbccdd',
                                 b'\xaa\xbb\xcc\xdd'),
    'cmpt_len 2, zero pad': ('3b02' '0714' '00000001' '0205' '0000' '1122334455667788' '00000000',
                             b'\x00' * 4),
    'cmpt_len 2, non-zero pad': ('3b02' '0714' '00000001' '0205' '0000' '1122334455667788' 'aabbccdd',
                                 b'\xaa\xbb\xcc\xdd'),
    'cmpt_len 0, no pad': ('3b01' '0708' '00000001' '0005' '0000' '01020000', b''),
}


class TestCALIPSOPad(unittest.TestCase):
    """Pin the CALIPSO pad through read, make and rebuild."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _protocols(self) -> 'list[type]':
        return [getattr(importlib.import_module(mod), name) for mod, name in PROTOCOLS]

    def _parse(self, cls: 'type', octets: 'bytes') -> 'object':
        return cls(io.BytesIO(octets), len(octets), extension=True)

    def test_parsed_headers_rebuild_byte_for_byte(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for cls in self._protocols():
            for label, (hexstr, pad) in HEADERS.items():
                octets = bytes.fromhex(hexstr)
                with self.subTest(protocol=cls.__name__, header=label):
                    parsed = self._parse(cls, octets)
                    self.assertEqual(parsed.info.options[Option.CALIPSO].pad, pad)  # type: ignore[attr-defined]
                    self.assertEqual(cls.from_data(parsed.info).data, octets)

    def test_make_writes_the_pad_and_counts_it_in_the_length(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for cls in self._protocols():
            with self.subTest(protocol=cls.__name__, cmpt_len=0):
                made = cls(next=59, options=[(Option.CALIPSO, {
                    'domain': 1, 'level': 5, 'pad': b'\xaa\xbb\xcc\xdd',
                })])
                self.assertEqual(made.data, bytes.fromhex(HEADERS['cmpt_len 0, non-zero pad'][0]))
            with self.subTest(protocol=cls.__name__, cmpt_len=2):
                made = cls(next=59, options=[(Option.CALIPSO, {
                    'domain': 1, 'level': 5, 'bitmap': bytes.fromhex('1122334455667788'),
                    'pad': b'\x00' * 4,
                })])
                self.assertEqual(made.data, bytes.fromhex(HEADERS['cmpt_len 2, zero pad'][0]))
            with self.subTest(protocol=cls.__name__, pad=None):
                # without a pad the option is the fixed header alone, as before
                made = cls(next=59, options=[(Option.CALIPSO, {'domain': 1, 'level': 5})])
                self.assertEqual(made.data, bytes.fromhex(HEADERS['cmpt_len 0, no pad'][0]))


if __name__ == '__main__':
    unittest.main()
