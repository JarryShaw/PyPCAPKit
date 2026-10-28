# -*- coding: utf-8 -*-
"""GitHub issue #2296: makers name the argument they rejected.

The ``_make_*`` builders pinned below refuse a caller-supplied argument in the
house form established by #2232 and #2257,
``<prefix>: <lowercase description>: must be X, not {value!r}``, which names
the keyword at fault and the value passed. A reader instead says
``<alias>: [Chunk|Param|Cause|OptNo N] invalid format``, which describes wire
data -- something a maker has not parsed -- and identifies neither.

Readers are deliberately exempt: ``invalid format`` is the right thing for a
reader to say, which is why the ``SCTP: [Chunk 0] invalid format`` pin in
:mod:`tests.protocols.transport.test_transport_edge_roundtrip_unit` -- a parse
case -- expects exactly that. :class:`ReadersKeepInvalidFormat` below pins that
division for the one maker/reader pair where the two guards check the same
thing.

Every message is pinned whole, and every maker's valid input is exercised in the
same class, so a guard that starts refusing good input regresses here too.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import datetime
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


class MakerMessageTestCase(unittest.TestCase):
    """Re-import :mod:`pcapkit` once per class, as the suite's convention asks."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def protocol(self, cls: 'Any') -> 'Any':
        """An uninitialised protocol instance, for calling a maker directly.

        The makers under test read nothing off ``self`` but ``alias``, so there
        is no packet to construct first -- and constructing one would route the
        bad argument through a schema that raises its own error instead.

        """
        return object.__new__(cls)


class SCTPChunkFlagsMessage(MakerMessageTestCase):
    """``_make_chunk_*`` names ``flags`` and shows the octets it was handed."""

    #: Chunk type per maker, as :rfc:`9260` assigns them. ``_make_chunk_donone``
    #: serves the unsupported types, so it gets one that has no maker of its own.
    MAKERS = {
        '_make_chunk_donone': 'Padding_Chunk',
        '_make_chunk_init': 'Initiation',
        '_make_chunk_init_ack': 'Initiation_Acknowledgement',
        '_make_chunk_sack': 'Selective_Acknowledgement',
        '_make_chunk_heartbeat': 'Heartbeat_Request',
        '_make_chunk_heartbeat_ack': 'Heartbeat_Acknowledgement',
        '_make_chunk_shutdown': 'Shutdown',
        '_make_chunk_shutdown_ack': 'Shutdown_Acknowledgement',
        '_make_chunk_error': 'Operation_Error',
        '_make_chunk_cookie_echo': 'State_Cookie',
        '_make_chunk_cookie_ack': 'Cookie_Acknowledgement',
    }

    def test_wrong_width_flags_name_the_argument(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        sctp = self.protocol(SCTP)
        for maker, name in self.MAKERS.items():
            code = Chunk[name]
            for flags in (b'', b'\x00\x00', b'\x00\x00\x00\x00'):
                with self.subTest(maker=maker, flags=flags):
                    with self.assertRaises(ProtocolError) as context:
                        getattr(sctp, maker)(code, flags=flags)
                    self.assertEqual(
                        str(context.exception),
                        f'SCTP: [Chunk {code}] invalid flags: '
                        f'must be one octet, not {flags!r}')

    def test_one_octet_flags_still_build(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        sctp = self.protocol(SCTP)
        for maker, name in self.MAKERS.items():
            with self.subTest(maker=maker):
                schema = getattr(sctp, maker)(Chunk[name], flags=b'\x01')
                self.assertEqual(schema.flags, b'\x01')


class SCTPDataChunkMessage(MakerMessageTestCase):
    """``_make_chunk_data`` names ``data`` rather than the chunk's format."""

    def test_empty_data_names_the_argument(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        sctp = self.protocol(SCTP)
        code = Chunk.Payload_Data
        with self.assertRaises(ProtocolError) as context:
            sctp._make_chunk_data(code, data=b'')
        self.assertEqual(str(context.exception),
                         f"SCTP: [Chunk {code}] invalid data: "
                         f"must be at least one octet, not b''")

    def test_one_octet_of_user_data_still_builds(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        sctp = self.protocol(SCTP)
        schema = sctp._make_chunk_data(Chunk.Payload_Data, data=b'!')
        self.assertEqual(schema.data, b'!')
        self.assertEqual(schema.length, 17)


class SCTPHostNameMessage(MakerMessageTestCase):
    """``_make_param_hostname`` names ``name`` and the terminator it wants."""

    def test_unterminated_name_names_the_argument(self) -> None:
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        sctp = self.protocol(SCTP)
        code = Parameter.Host_Name_Address
        for name in (b'example', b'example.com', b''):
            with self.subTest(name=name):
                with self.assertRaises(ProtocolError) as context:
                    sctp._make_param_hostname(code, name=name)
                self.assertEqual(
                    str(context.exception),
                    f'SCTP: [Param {code}] invalid name: '
                    f'must be NUL-terminated, not {name!r}')

    def test_terminated_name_still_builds(self) -> None:
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport.sctp import SCTP

        sctp = self.protocol(SCTP)
        schema = sctp._make_param_hostname(Parameter.Host_Name_Address, name=b'example\x00')
        self.assertEqual(schema.name, b'example\x00')


class SCTPInvalidStreamMessage(MakerMessageTestCase):
    """``_make_cause_invalid_stream`` names ``reserved`` and its width."""

    def test_wrong_width_reserved_names_the_argument(self) -> None:
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        sctp = self.protocol(SCTP)
        code = CauseCode.Invalid_Stream_Identifier
        for reserved in (b'', b'\x00', b'\x00\x00\x00'):
            with self.subTest(reserved=reserved):
                with self.assertRaises(ProtocolError) as context:
                    sctp._make_cause_invalid_stream(code, reserved=reserved)
                self.assertEqual(
                    str(context.exception),
                    f'SCTP: [Cause {code}] invalid reserved: '
                    f'must be two octets, not {reserved!r}')

    def test_two_octet_reserved_still_builds(self) -> None:
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.protocols.transport.sctp import SCTP

        sctp = self.protocol(SCTP)
        schema = sctp._make_cause_invalid_stream(CauseCode.Invalid_Stream_Identifier,
                                                 stream_id=7, reserved=b'\x00\x00')
        self.assertEqual(schema.stream_id, 7)
        self.assertEqual(schema.reserved, b'\x00\x00')


class MHMakeDataMessage(MakerMessageTestCase):
    """:meth:`MH.make` names ``data`` and the forms it reads."""

    def test_unreadable_data_names_the_argument(self) -> None:
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        mh = self.protocol(MH)
        code = Packet.Binding_Refresh_Request
        for data in (5, None, 1.5, 'data'):
            with self.subTest(data=data):
                with self.assertRaises(ProtocolError) as context:
                    mh.make(type=code, data=data)
                self.assertEqual(
                    str(context.exception),
                    f'MH: [Type {code}] invalid data: must be bytes, a dict, '
                    f'an MH data model or a Packet schema, not {data!r}')

    def test_bytes_data_still_builds(self) -> None:
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH

        mh = self.protocol(MH)
        schema = mh.make(type=Packet.Binding_Refresh_Request, data=b'\x00\x00')
        self.assertEqual(schema.data, b'\x00\x00')


class MHOptionDataMessages(MakerMessageTestCase):
    """The MH option makers name ``data`` and the width each one needs."""

    def test_authorization_data_multiple_of_eight(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        mh = self.protocol(MH)
        code = Option.Authorization_Data
        for data in (b'a', b'abc', b'a' * 9):
            with self.subTest(data=data):
                with self.assertRaises(ProtocolError) as context:
                    mh._make_opt_bad(code, data=data)
                self.assertEqual(
                    str(context.exception),
                    f'MH: [OptNo {code}] invalid data: '
                    f'must be a multiple of eight octets, not {data!r}')

        self.assertEqual(mh._make_opt_bad(code, data=b'a' * 8).data, b'a' * 8)

    def test_badf_authenticator_not_empty(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        mh = self.protocol(MH)
        code = Option.Binding_Authorization_Data_for_FMIPv6
        with self.assertRaises(ProtocolError) as context:
            mh._make_opt_badf(code, data=b'')
        self.assertEqual(str(context.exception),
                         f"MH: [OptNo {code}] invalid data: "
                         f"must be at least one octet, not b''")

        self.assertEqual(mh._make_opt_badf(code, data=b'\x01').data, b'\x01')

    def test_auth_data_keeps_the_option_aligned(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        mh = self.protocol(MH)
        code = Option.AUTH_OPTION_TYPE
        for data in (b'', b'a', b'abc', b'abcd'):
            with self.subTest(data=data):
                with self.assertRaises(ProtocolError) as context:
                    mh._make_opt_auth(code, data=data)
                self.assertEqual(
                    str(context.exception),
                    f'MH: [OptNo {code}] invalid data: '
                    f'must be two octets more than a multiple of four, not {data!r}')

        for data in (b'ab', b'abcdef'):
            with self.subTest(data=data):
                self.assertEqual(mh._make_opt_auth(code, data=data).data, data)


class MHPadOptionWarning(MakerMessageTestCase):
    """``_make_opt_pad`` warns about ``length``, not about a format."""

    def test_pad1_with_a_length_warns_by_name(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.warnings import ProtocolWarning

        mh = self.protocol(MH)
        code = Option.Pad1
        for length in (1, 3):
            with self.subTest(length=length):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    schema = mh._make_opt_pad(code, length=length)
                messages = [str(w.message) for w in caught
                            if issubclass(w.category, ProtocolWarning)]
                self.assertEqual(len(messages), 1, messages)
                self.assertEqual(
                    messages[0],
                    f'MH: [OptNo {code}] invalid length: must be 0 for a Pad1 option, '
                    f'not {length!r}; making a PadN')
                self.assertEqual(schema.type, Option.PadN)

    def test_pad1_with_no_length_does_not_warn(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.warnings import ProtocolWarning

        mh = self.protocol(MH)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            schema = mh._make_opt_pad(Option.Pad1, length=0)
        self.assertEqual([str(w.message) for w in caught
                          if issubclass(w.category, ProtocolWarning)], [])
        self.assertEqual(schema.type, Option.Pad1)


class TCPMPTCPCapableMessage(MakerMessageTestCase):
    """``_make_mptcp_capable`` names the field given and the gap before it."""

    #: One case per field that can be given without its predecessor: the
    #: keywords to pass, then the field named and the absent one it follows.
    CASES = (
        ({'skey': None, 'rkey': 1}, 'rkey', 'skey', 1),
        ({'skey': None, 'rkey': None, 'dl_len': 7}, 'dl_len', 'skey', 7),
        ({'rkey': None, 'dl_len': 7}, 'dl_len', 'rkey', 7),
        ({'dl_len': None, 'checksum': b'ab'}, 'checksum', 'dl_len', b'ab'),
    )

    def test_a_field_without_its_predecessor_names_both(self) -> None:
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        tcp = self.protocol(TCP)
        for kwargs, named, absent, value in self.CASES:
            with self.subTest(**kwargs):
                with self.assertRaises(ProtocolError) as context:
                    tcp._make_mptcp_capable(MPTCPOption.MP_CAPABLE, **kwargs)
                self.assertEqual(
                    str(context.exception),
                    f'TCP: [OptNo {Option.Multipath_TCP}] invalid {named}: '
                    f'must be None when {absent} is None, not {value!r}')

    def test_every_rfc_8684_length_still_builds(self) -> None:
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.protocols.transport.tcp import TCP

        tcp = self.protocol(TCP)
        #: :rfc:`8684` section 3.1's five MP_CAPABLE lengths, by how many of
        #: ``skey``, ``rkey``, ``dl_len`` and ``checksum`` are present.
        cases = (
            ({'skey': None, 'rkey': None, 'dl_len': None, 'checksum': None}, 4),
            ({'skey': 1, 'rkey': None, 'dl_len': None, 'checksum': None}, 12),
            ({'skey': 1, 'rkey': 2, 'dl_len': None, 'checksum': None}, 20),
            ({'skey': 1, 'rkey': 2, 'dl_len': 3, 'checksum': None}, 22),
            ({'skey': 1, 'rkey': 2, 'dl_len': 3, 'checksum': b'ab'}, 24),
        )
        for kwargs, length in cases:
            with self.subTest(length=length):
                schema = tcp._make_mptcp_capable(MPTCPOption.MP_CAPABLE, **kwargs)
                self.assertEqual(schema.length, length)


class HIPLocatorMessage(MakerMessageTestCase):
    """``_make_locator`` names the locator it could not read."""

    def locator(self, value: 'Any') -> 'Any':
        from pcapkit.protocols.data.internet.hip import Locator

        return Locator(traffic=0, type=0, length=16, preferred=False, reserved=0,
                       lifetime=datetime.timedelta(seconds=0), locator=value)

    def parameter(self, value: 'Any') -> 'Any':
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.data.internet.hip import LocatorSetParameter

        return LocatorSetParameter(type=Parameter.LOCATOR_SET, critical=False, length=24,
                                   locator_set=(self.locator(value),))

    def test_unreadable_locator_names_the_argument(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        hip = self.protocol(HIP)
        code = Parameter.LOCATOR_SET
        for value in ('::1', 5, None, b'\x00' * 16):
            with self.subTest(value=value):
                with self.assertRaises(ProtocolError) as context:
                    hip._make_param_locator_set(code, self.parameter(value), version=2)
                self.assertEqual(
                    str(context.exception),
                    f'HIPv2: [ParamNo {code}] invalid locator: must be an '
                    f'ipaddress.IPv6Address or a LocatorData, not {value!r}')

    def test_an_ipv6_address_locator_still_builds(self) -> None:
        import ipaddress

        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        hip = self.protocol(HIP)
        address = ipaddress.IPv6Address('::1')
        schema = hip._make_param_locator_set(Parameter.LOCATOR_SET,
                                             self.parameter(address), version=2)
        self.assertEqual(schema.locators[0]['value'], address.packed)


class PCAPNGDSBSecretsMessage(MakerMessageTestCase):
    """``_make_block_dsb`` names ``secrets_data`` and the forms it reads."""

    def test_unreadable_secrets_data_names_the_argument(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        pcapng = self.protocol(PCAPNG)
        for secrets_data in (5, None, 1.5, 'secrets'):
            with self.subTest(secrets_data=secrets_data):
                with self.assertRaises(ProtocolError) as context:
                    pcapng._make_block_dsb(secrets_data=secrets_data)
                self.assertEqual(
                    str(context.exception),
                    f'PCAP-NG: [DSB] invalid secrets_data: must be bytes, a dict, '
                    f'a DSBSecrets data model or a Schema, not {secrets_data!r}')

    def test_raw_secrets_data_still_builds(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        pcapng = self.protocol(PCAPNG)
        schema = pcapng._make_block_dsb(secrets_data=b'CLIENT_RANDOM 00 11\n')
        self.assertEqual(schema.secrets_length, 20)


class ReadersKeepInvalidFormat(MakerMessageTestCase):
    """The parse side says ``invalid format``, as #2296 asks.

    ``_read_chunk_data`` and ``_make_chunk_data`` guard the same thing -- a DATA
    chunk with no user data -- so the pair is where a sweep over the makers is
    most likely to catch a reader by accident.

    """

    #: ``sctp/data-no-user-data`` from
    #: :mod:`tests.protocols.transport.test_transport_edge_roundtrip_unit`: the
    #: SCTP common header, then a DATA chunk declaring its own 16 octets and
    #: carrying no user data -- TSN, stream id, stream sequence and PPID only.
    NO_USER_DATA = (struct.pack('!HHII', 5000, 5001, 0xdeadbeef, 0)
                    + struct.pack('!BBH', 0, 0xff, 16)
                    + b'\x00\x00\x00\x01' + b'\x00\x01\x00\x02' + bytes(4))

    def test_the_reader_still_reports_an_invalid_format(self) -> None:
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as context:
            SCTP(self.NO_USER_DATA, len(self.NO_USER_DATA))
        self.assertEqual(str(context.exception), 'SCTP: [Chunk 0] invalid format')


if __name__ == '__main__':
    unittest.main()
