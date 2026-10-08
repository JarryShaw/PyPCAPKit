# -*- coding: utf-8 -*-
"""MH ``PadN`` contents rebuild as captured.

GitHub issue #1329, its ``PadN`` remainder: the contents of a ``PadN``
mobility option, and of a Flow Identification ``PadN`` sub-option, were held by
a :class:`~pcapkit.corekit.fields.strings.PaddingField` that packed zeros, so
``0106aabbccddeeff`` came back as ``0106000000000000``. The contents are now
kept on the data model (``data``) and written back; a fresh build still writes
zeros. The root cause is #1223.

Every case builds its own octets in memory and reads no capture. :class:`MH` is
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class


class TestMHPadNContents(unittest.TestCase):
    """Pin the wire form of MH ``PadN`` contents across rebuilds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_padn_option_contents_rebuild_from_data(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        # BRR, then a PadN of Option Length 6 with non-zero contents
        raw = bytes.fromhex('3b01000000000000' '0106aabbccddeeff')
        parsed = MH(io.BytesIO(raw), len(raw), extension=True)
        option = next(iter(parsed.info.options.values()))
        self.assertEqual(option.data, bytes.fromhex('aabbccddeeff'))
        self.assertEqual(bytes(MH.from_data(parsed.info).data).hex(), raw.hex())

    def test_padn_option_make_writes_zeros_unless_given(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        proto = object.__new__(MH)
        self.assertEqual(bytes(proto._make_opt_pad(Option.PadN, length=2)).hex(), '01020000')
        self.assertEqual(bytes(proto._make_opt_pad(Option.PadN, length=2, data=b'\xaa\xbb')).hex(),
                         '0102aabb')

    def test_padn_suboption_contents_round_trip(self) -> None:
        from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH

        def build(pad: 'dict[str, object]') -> 'bytes':
            args = {'fid': 7, 'fid_pri': 2, 'status': 0,
                    'suboptions': [(FlowIDSuboption.PadN, pad)]}
            return bytes(MH(next=TransType.UDP, chksum=b'\x12\x34',
                            type=Packet.Binding_Refresh_Request,
                            data={'options': [(Option.Flow_Identification_Mobility_Option, args)]}))

        zeros = build({'length': 2})
        raw = build({'length': 2, 'data': b'\xaa\xbb'})
        self.assertEqual(raw.replace(b'\x01\x02\xaa\xbb', b'\x01\x02\x00\x00'), zeros)
        self.assertNotEqual(raw, zeros)

        parsed = MH(io.BytesIO(raw), len(raw), extension=True).info
        rebuilt = bytes(MH(next=parsed.next, type=parsed.type, chksum=parsed.chksum, data=parsed))
        self.assertEqual(rebuilt.hex(), raw.hex())


if __name__ == '__main__':
    unittest.main()
