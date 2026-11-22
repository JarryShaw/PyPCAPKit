# -*- coding: utf-8 -*-
"""SCTP dissects the chunks and parameters of its extensions (GitHub issue #2811).

``SCTP.__chunk__`` and ``SCTP.__parameter__`` held only what :rfc:`9260` defines,
so these parsed as unknown ones, their fields undecoded:

* the I-DATA and I-FORWARD-TSN chunks of :rfc:`8260`;
* the FORWARD TSN chunk and Forward-TSN-Supported parameter of :rfc:`3758`;
* the PAD chunk and padding parameter of :rfc:`4820`;
* the supported extensions parameter of :rfc:`5061`.

The tests read octets written out from those RFCs' figures and assert the fields
the figures imply, build the same octets with the makers, check what each refuses,
and check that the first I-DATA chunk picks the next layer on its PPID as the
first DATA chunk does. Where :mod:`scapy` is installed, its encoding of each is
read and matched as an independent check. Byte-exact round trips of these chunks
are in :file:`tests/protocols/transport/test_sctp_roundtrip_unit.py`.

Every case builds its own octets, so this belongs to the unit tier.

"""
from __future__ import annotations

import importlib.util
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): a per-protocol field-by-field table.
__tier__ = 'LATEST'

HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: SCTP common header with a zero checksum.
HEADER = '138813891122334400000000'

#: An I-DATA chunk of a first fragment: I, B and E set, TSN 0x0a0b0c0d, stream 1,
#: message 7, PPID 60, user data ``010203``.
I_DATA_FIRST = '400b0017' + '0a0b0c0d' + '00010000' + '00000007' + '0000003c' + '01020300'

#: An I-DATA chunk of a later fragment: E alone set, fragment sequence number 5.
I_DATA_LATER = '40010017' + '0a0b0c0d' + '00010000' + '00000007' + '00000005' + '01020300'


class SCTPExtensionChunkTests(unittest.TestCase):
    """The #2811 chunks and parameters parse, build and dispatch as their RFCs say."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def parse(hexdata: str) -> 'Any':
        """``hexdata``, after :data:`HEADER`, parsed as a whole SCTP packet."""
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        raw = bytes.fromhex(HEADER + hexdata)
        return SCTP(raw, len(raw))

    @staticmethod
    def build(chunks: 'list') -> str:
        """The chunk area, in hex, of a packet ``SCTP.make`` builds from ``chunks``."""
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        proto = SCTP.__new__(SCTP)
        return SCTP.make(proto, srcport=5000, dstport=5001, vtag=0x11223344,
                         chksum=b'\x00' * 4, chunks=chunks).pack()[12:].hex()

    @staticmethod
    def first(proto: 'Any') -> 'Any':
        """The first chunk of ``proto``."""
        return next(iter(proto.info.chunks.values()))

    def assertRefused(self, hexdata: str, message: str) -> None:
        """Parsing ``hexdata`` raises ``ProtocolError`` saying ``message``, and logs no
        ``FieldValueError``."""
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertLogs('pcapkit', level='DEBUG') as logs:
            with self.assertRaises(ProtocolError) as context:
                self.parse(hexdata)
        self.assertEqual(str(context.exception), message)
        self.assertEqual([line for line in logs.output if 'FieldValueError' in line], [])

    ##########################################################################
    # I-DATA.
    ##########################################################################

    def test_i_data_first_fragment_wire_conformance(self) -> None:
        """RFC 8260 s2.1: with B set, the field after the MID is the PPID, and the FSN is 0."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier

        proto = self.parse(I_DATA_FIRST)
        chunk = self.first(proto)
        self.assertIs(chunk.type, Chunk.Payload_Data_supporting_Interleaving)
        self.assertEqual(chunk.length, 23)
        self.assertEqual((chunk.flags.reserved, chunk.flags.I, chunk.flags.U, chunk.flags.B,
                          chunk.flags.E), (0, True, False, True, True))
        self.assertEqual((chunk.tsn, chunk.stream_id, chunk.reserved, chunk.mid),
                         (0x0a0b0c0d, 1, 0, 7))
        self.assertIs(chunk.ppid,
                      PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NG_Application_Protocol)
        self.assertEqual(chunk.fsn, 0)
        self.assertEqual(chunk.data, b'\x01\x02\x03')

    def test_i_data_later_fragment_wire_conformance(self) -> None:
        """RFC 8260 s2.1: with B clear, the field after the MID is the FSN, and no PPID is carried."""
        chunk = self.first(self.parse(I_DATA_LATER))
        self.assertFalse(chunk.flags.B)
        self.assertTrue(chunk.flags.E)
        self.assertIsNone(chunk.ppid)
        self.assertEqual(chunk.fsn, 5)
        self.assertEqual(chunk.data, b'\x01\x02\x03')

    def test_i_data_without_user_data_is_refused(self) -> None:
        """RFC 8260 s2.2.2 keeps DATA's rule of at least one octet of user data."""
        self.assertRefused('40030014' + '0a0b0c0d' + '00010000' + '00000007' + '0000003c',
                           'SCTP: [Chunk 64] invalid format')

    def test_i_data_maker_writes_the_figure(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk

        code = Chunk.Payload_Data_supporting_Interleaving
        common = dict(tsn=0x0a0b0c0d, stream_id=1, mid=7, data=b'\x01\x02\x03')
        self.assertEqual(self.build([(code, dict(common, I=True, ppid=60))]), I_DATA_FIRST)
        self.assertEqual(self.build([(code, dict(common, B=False, fsn=5))]), I_DATA_LATER)
        # No PPID given for a first fragment writes 0, as DATA's default does.
        self.assertEqual(self.build([(code, {'data': b'\x01'})])[32:40], '00000000')

    def test_i_data_maker_refuses_what_the_field_cannot_hold(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp.protocol import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        code = Chunk.Payload_Data_supporting_Interleaving
        sctp = SCTP.__new__(SCTP)
        cases = {
            'fsn on a first fragment': (dict(fsn=1, data=b'\x01'),
                                        f'SCTP: [Chunk {code}] invalid fsn: must be 0 on a first '
                                        'fragment, not 1'),
            'ppid on a later fragment': (dict(B=False, ppid=60, data=b'\x01'),
                                         f'SCTP: [Chunk {code}] invalid ppid: must be None on a '
                                         'later fragment, not 60'),
            'no user data': (dict(data=b''),
                             f"SCTP: [Chunk {code}] invalid data: must be at least one octet, "
                             "not b''"),
        }
        for name, (kwargs, message) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ProtocolError) as context:
                    sctp._make_chunk_i_data(code, **kwargs)  # pylint: disable=protected-access
                self.assertEqual(str(context.exception), message)

    def test_first_i_data_chunk_selects_the_next_layer(self) -> None:
        """The first DATA or I-DATA chunk picks the next layer on its PPID, a PAD before it aside."""
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        bundle = '84000004' + I_DATA_FIRST + I_DATA_LATER
        with mock.patch.object(SCTP, '_decode_next_layer', autospec=True,
                               side_effect=SCTP._decode_next_layer) as decode:  # pylint: disable=protected-access
            proto = self.parse(bundle)
        self.assertEqual(decode.call_args.args[2], 60)
        self.assertEqual(proto.ppid, 60)
        self.assertEqual(proto._get_payload(), b'\x01\x02\x03')  # pylint: disable=protected-access
        self.assertEqual(str(proto.protochain),
                         'SCTP:PayloadProtocolIdentifier_3GPP_NG_Application_Protocol')

    def test_later_i_data_fragment_has_no_ppid_to_dispatch_on(self) -> None:
        """A later fragment's user data is the payload, kept raw for want of a PPID."""
        from pcapkit.protocols.misc.raw.protocol import Raw

        proto = self.parse(I_DATA_LATER)
        self.assertIsNone(proto.ppid)
        self.assertIsInstance(proto.payload, Raw)
        self.assertEqual(bytes(proto.payload), b'\x01\x02\x03')

    ##########################################################################
    # PAD, FORWARD TSN and I-FORWARD-TSN.
    ##########################################################################

    def test_pad_chunk_wire_conformance(self) -> None:
        """RFC 4820 s3: the length is the padding data plus 4, the flags kept as sent."""
        from pcapkit.const.sctp.chunk import Chunk

        chunk = self.first(self.parse('845a0007' + '01020300'))
        self.assertIs(chunk.type, Chunk.Padding_Chunk)
        self.assertEqual((chunk.length, chunk.flags, chunk.data), (7, b'\x5a', b'\x01\x02\x03'))
        self.assertEqual(self.build([(Chunk.Padding_Chunk, {'data': b'\x01\x02\x03'})]),
                         '84000007' + '01020300')

    def test_forward_tsn_wire_conformance(self) -> None:
        """RFC 3758 s3.2: the new cumulative TSN, then stream and stream sequence pairs."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp.data import ForwardTSNStream

        hexdata = 'c0000010' + '00000005' + '00010002' + '00030004'
        chunk = self.first(self.parse(hexdata))
        self.assertIs(chunk.type, Chunk.Forward_TSN)
        self.assertEqual((chunk.length, chunk.new_cum_tsn), (16, 5))
        self.assertEqual([(entry.stream_id, entry.stream_seq) for entry in chunk.streams],
                         [(1, 2), (3, 4)])
        self.assertEqual(self.build([(Chunk.Forward_TSN, {
            'new_cum_tsn': 5, 'streams': [(1, 2), ForwardTSNStream(stream_id=3, stream_seq=4)],
        })]), hexdata)

    def test_i_forward_tsn_wire_conformance(self) -> None:
        """RFC 8260 s2.3.1: each entry is a stream, 15 reserved bits and the U bit, then a MID."""
        from pcapkit.const.sctp.chunk import Chunk

        hexdata = 'c2000018' + '00000005' + '00010001' + '00000002' + '0003fffe' + '00000004'
        chunk = self.first(self.parse(hexdata))
        self.assertIs(chunk.type, Chunk.I_FORWARD_TSN)
        self.assertEqual((chunk.length, chunk.new_cum_tsn), (24, 5))
        self.assertEqual([(entry.stream_id, entry.reserved, entry.U, entry.mid)
                          for entry in chunk.streams],
                         [(1, 0, True, 2), (3, 0x7fff, False, 4)])
        self.assertEqual(self.build([(Chunk.I_FORWARD_TSN, {
            'new_cum_tsn': 5, 'streams': [(1, True, 2), chunk.streams[1]],
        })]), hexdata)

    def test_a_length_leaving_part_of_an_entry_is_refused(self) -> None:
        """A length past the fixed fields that is no whole number of entries is a ProtocolError."""
        cases = {
            'FORWARD TSN': ('c000000a' + '00000005' + '0001' + '0000',
                            'SCTP: [Chunk 192] invalid length: 10, not a whole number of 4-octet entries'),
            'I-FORWARD-TSN': ('c200000c' + '00000005' + '00010001',
                              'SCTP: [Chunk 194] invalid length: 12, not a whole number of 8-octet entries'),
        }
        for name, (hexdata, message) in cases.items():
            with self.subTest(chunk=name):
                self.assertRefused(hexdata, message)

    def test_stream_makers_take_entry_schemas_as_given(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp.schema import ForwardTSNStream, IForwardTSNStream

        self.assertEqual(self.build([(Chunk.Forward_TSN, {
            'streams': [ForwardTSNStream(stream_id=1, stream_seq=2)],
        })]), 'c000000c' + '00000000' + '00010002')
        self.assertEqual(self.build([(Chunk.I_FORWARD_TSN, {
            'streams': [IForwardTSNStream(stream_id=1, flags={'reserved': 0, 'U': 1}, mid=2)],
        })]), 'c2000010' + '00000000' + '00010001' + '00000002')

    def test_readers_refuse_a_length_short_of_the_header(self) -> None:
        """A length below the four-octet header is refused, though no list hands one on."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.transport.sctp.protocol import SCTP
        from pcapkit.protocols.transport.sctp.schema import (PaddingChunk, PaddingParameter,
                                                             SupportedExtensionsParameter)
        from pcapkit.utilities.exceptions import ProtocolError

        sctp = SCTP.__new__(SCTP)
        cases = {
            '_read_chunk_pad': (PaddingChunk(type=Chunk.Padding_Chunk, flags=b'\x00', length=2, data=b''),
                                {'chunks': OrderedMultiDict()}),
            '_read_param_pad': (PaddingParameter(type=Parameter.Padding, length=2, data=b''),
                                {'parameters': OrderedMultiDict()}),
            '_read_param_extensions': (SupportedExtensionsParameter(
                type=Parameter.Supported_Extensions, length=2, types=[]), {'parameters': OrderedMultiDict()}),
        }
        for reader, (schema, kwargs) in cases.items():
            with self.subTest(reader=reader):
                with self.assertRaises(ProtocolError):
                    getattr(sctp, reader)(schema, **kwargs)

    def test_a_length_short_of_the_fixed_fields_is_refused(self) -> None:
        """Both TSN chunks need the eight octets of their header and new cumulative TSN."""
        for name, hexdata in {'FORWARD TSN': 'c0000004', 'I-FORWARD-TSN': 'c2000004'}.items():
            with self.subTest(chunk=name):
                self.assertRefused(hexdata + '0b000004', f'SCTP: [Chunk {int(hexdata[:2], 16)}] invalid format')

    ##########################################################################
    # Parameters.
    ##########################################################################

    def test_parameters_wire_conformance(self) -> None:
        """RFC 4820 s4, RFC 5061 s4.2.7 and RFC 3758 s3.1, carried in an INIT chunk."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter

        params = '80050007' + '01020300' + '80080007' + 'c082c200' + 'c0000004'
        hexdata = '01000028' + '00000000' + '00000000' + '00010001' + '00000000' + params
        parameters = self.first(self.parse(hexdata)).parameters
        self.assertEqual(list(parameters.keys()),
                         [Parameter.Padding, Parameter.Supported_Extensions,
                          Parameter.Forward_TSN_supported])
        self.assertEqual(parameters[Parameter.Padding].data, b'\x01\x02\x03')
        self.assertEqual(parameters[Parameter.Supported_Extensions].types,
                         (Chunk.Forward_TSN, Chunk.Re_configuration_Chunk, Chunk.I_FORWARD_TSN))
        self.assertEqual(parameters[Parameter.Forward_TSN_supported].length, 4)
        self.assertEqual(self.build([(Chunk.Initiation, {'a_rwnd': 0, 'parameters': [
            (Parameter.Padding, {'data': b'\x01\x02\x03'}),
            (Parameter.Supported_Extensions, {'types': [Chunk.Forward_TSN, 130, Chunk.I_FORWARD_TSN]}),
            (Parameter.Forward_TSN_supported, {}),
        ]})]), hexdata)

    def test_forward_tsn_supported_of_another_length_is_refused(self) -> None:
        """RFC 3758 s3.1 fixes the Forward-TSN-Supported parameter's length at 4."""
        self.assertRefused('0100001c' + '00000000' + '00000000' + '00010001' + '00000000'
                           + 'c0000008' + 'c0000004', 'SCTP: [Param 49152] invalid format')

    ##########################################################################
    # Scapy cross-check.
    ##########################################################################

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_cross_check(self) -> None:
        """Scapy's octets for each read back with the values scapy was given, and rebuild.

        Scapy's PAD chunk is left out: it declares a length four octets past its
        padding data, which :rfc:`4820#section-3` does not.
        """
        from scapy.layers.sctp import (SCTPChunkForwardTSN, SCTPChunkIData, SCTPChunkIForwardTSN,
                                       SCTPChunkInit, SCTPChunkParamFwdTSN,
                                       SCTPChunkParamSupportedExtensions, SCTPForwardSkip,
                                       SCTPIForwardSkip)

        from pcapkit.protocols.transport.sctp.protocol import SCTP

        cases = {
            'I-DATA first': (SCTPChunkIData(beginning=1, ending=1, tsn=1, stream_id=2, message_id=3,
                                            ppid_fsn=60, data=b'abc'),
                             lambda c: (c.tsn, c.stream_id, c.mid, c.ppid, c.fsn), (1, 2, 3, 60, 0)),
            'I-DATA later': (SCTPChunkIData(beginning=0, ending=1, tsn=1, stream_id=2, message_id=3,
                                            ppid_fsn=4, data=b'abc'),
                             lambda c: (c.tsn, c.stream_id, c.mid, c.ppid, c.fsn), (1, 2, 3, None, 4)),
            'FORWARD TSN': (SCTPChunkForwardTSN(new_tsn=5, skips=[SCTPForwardSkip(stream_id=1, stream_seq=2)]),
                            lambda c: (c.new_cum_tsn, [(s.stream_id, s.stream_seq) for s in c.streams]),
                            (5, [(1, 2)])),
            'I-FORWARD-TSN': (SCTPChunkIForwardTSN(new_tsn=5, skips=[
                SCTPIForwardSkip(stream_id=1, unordered=1, message_id=2)]),
                lambda c: (c.new_cum_tsn, [(s.stream_id, s.U, s.mid) for s in c.streams]),
                (5, [(1, True, 2)])),
            'INIT parameters': (SCTPChunkInit(params=[
                SCTPChunkParamSupportedExtensions(supported_extensions=[192, 194]), SCTPChunkParamFwdTSN()]),
                lambda c: [(int(k), tuple(map(int, getattr(v, 'types', ())))) for k, v in c.parameters.items()],
                [(0x8008, (192, 194)), (0xc000, ())]),
        }
        for name, (chunk, fields, expected) in cases.items():
            with self.subTest(chunk=name):
                proto = self.parse(bytes(chunk).hex())
                self.assertEqual(fields(self.first(proto)), expected)
                self.assertEqual(SCTP.from_data(proto.info).data, proto.data)


if __name__ == '__main__':
    unittest.main()
