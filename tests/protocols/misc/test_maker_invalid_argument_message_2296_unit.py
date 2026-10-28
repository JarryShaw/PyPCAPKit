"""#2296 -- makers name the rejected argument in their error messages.

Guards against :exc:`~pcapkit.utilities.exceptions.ProtocolError` (and
:class:`~pcapkit.protocols.protocol.ProtocolWarning`) messages in which a
``_make_*`` builder rejects a caller-supplied argument with the parse-error
text ``invalid format``. That text says the wire data is malformed, but here
nothing was parsed: the caller passed a bad value, and the message gave no
hint of which keyword was wrong or what value was received.

The house form these tests pin is ``invalid <argument>: <requirement>, not
<value>`` -- the maker names the argument, states the requirement, and shows
the offending value -- already used elsewhere in the codebase, e.g. the
mobile network prefix check in ``MH._make_opt_mnp``. The reader side keeps
its ``invalid format`` text, so the ``SCTP: [Chunk 0] invalid format`` pin in
``test_transport_edge_roundtrip_unit`` (a parse case) is untouched.

Every message here is asserted **in full** rather than by substring, so that
a regression back to the generic text cannot slip through a partial match.

"""
from __future__ import annotations

import unittest
import warnings
from datetime import timedelta
from types import SimpleNamespace

from tests._support import reimport_once_per_class


class MakerInvalidArgumentMessageUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_sctp_flags_guards(self) -> None:
        """The ``flags`` guards name the argument and show the value.

        ``_make_chunk_init`` stands in for the eleven identical guards; the
        guard rejects a two-octet ``flags`` with the requirement spelled out.

        """
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = SCTP.__new__(SCTP)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_chunk_init(0, flags=b'\x00\x00')

        self.assertEqual(
            str(caught.exception),
            "SCTP: [Chunk 0] invalid flags: must be one octet, not b'\\x00\\x00'",
        )

    def test_sctp_data_guard(self) -> None:
        """The ``DATA`` chunk's empty-``data`` guard names the argument."""
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = SCTP.__new__(SCTP)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_chunk_data(0)

        self.assertEqual(str(caught.exception), 'SCTP: [Chunk 0] invalid data: must not be empty')

    def test_sctp_hostname_guard(self) -> None:
        """The host name parameter guard quotes the rejected name."""
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = SCTP.__new__(SCTP)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_param_hostname(11, name=b'example')

        self.assertEqual(
            str(caught.exception),
            "SCTP: [Param 11] invalid name: must be NUL-terminated, not b'example'",
        )

    def test_sctp_cause_reserved_guard(self) -> None:
        """The invalid stream identifier cause quotes the ``reserved`` value."""
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = SCTP.__new__(SCTP)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_cause_invalid_stream(3, reserved=b'\x00')

        self.assertEqual(
            str(caught.exception),
            "SCTP: [Cause 3] invalid reserved: must be two octets, not b'\\x00'",
        )

    def test_mh_make_data_guard(self) -> None:
        """``MH.make`` names the ``data`` argument and its runtime type.

        The value is deliberately described by type rather than ``repr``:
        this branch is reached with an arbitrary object, whose repr may be
        unbounded, while the type name is what tells the caller how to fix
        the call.

        """
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        proto = MH.__new__(MH)
        with self.assertRaises(ProtocolError) as caught:
            proto.make(type=1, data=object())

        self.assertEqual(
            str(caught.exception),
            'MH: [Type 1] invalid data: unsupported type object',
        )

    def test_mh_pad1_length_warning(self) -> None:
        """The ``Pad1`` fallback warning states the length and the fallback."""
        from pcapkit.const.mh.option import Option as Enum_Option
        from pcapkit.protocols.internet.mh import MH

        proto = MH.__new__(MH)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            proto._make_opt_pad(Enum_Option.Pad1, length=3)

        self.assertEqual(len(caught), 1)
        self.assertEqual(
            str(caught[0].message),
            'MH: [OptNo 0] invalid length for Pad1: 3; falling back to PadN',
        )

    def test_mh_auth_data_length_guard(self) -> None:
        """The binding authorization data guard quotes the data length."""
        from pcapkit.const.mh.option import Option as Enum_Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        proto = MH.__new__(MH)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_opt_bad(Enum_Option.Authorization_Data, data=b'123')

        self.assertEqual(
            str(caught.exception),
            f'MH: [OptNo {Enum_Option.Authorization_Data}] '
            'invalid data: length must be a multiple of 8, not 3',
        )

    def test_mh_auth_option_length_guard(self) -> None:
        """The auth option guard quotes the data length it cannot align."""
        from pcapkit.const.mh.option import Option as Enum_Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        proto = MH.__new__(MH)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_opt_auth(Enum_Option.Authorization_Data, data=b'123')

        self.assertEqual(
            str(caught.exception),
            f'MH: [OptNo {Enum_Option.Authorization_Data}] '
            'invalid data: length must make the option a multiple of 4, not 3',
        )

    def test_mh_badf_empty_data_guard(self) -> None:
        """The FMIPv6 binding authorization guard shows the empty value."""
        from pcapkit.const.mh.option import Option as Enum_Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        proto = MH.__new__(MH)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_opt_badf(Enum_Option.Binding_Authorization_Data_for_FMIPv6)

        self.assertEqual(
            str(caught.exception),
            f'MH: [OptNo {Enum_Option.Binding_Authorization_Data_for_FMIPv6}] '
            "invalid data: must not be empty, not b''",
        )

    def test_tcp_mptcp_field_order_guard(self) -> None:
        """The MP_CAPABLE guard names the field and its missing predecessor.

        The check is a prefix rule -- each field requires every field before
        it -- so the message pins both ends of the violated pair.

        """
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = TCP.__new__(TCP)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_mptcp_capable(Enum_Option.Multipath_TCP, skey=None, rkey=2)

        self.assertEqual(
            str(caught.exception),
            f"TCP: [OptNo {Enum_Option.Multipath_TCP}] "
            "invalid fields: 'rkey' given without 'skey'",
        )

    def test_hip_locator_value_guard(self) -> None:
        """The locator guard quotes the value that is neither address nor data."""
        from pcapkit.protocols.data.internet.hip import Locator as Data_Locator
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = HIP.__new__(HIP)
        bad = Data_Locator(locator='not-an-ip', traffic=0, type=0, length=16,
                           preferred=False, reserved=0, lifetime=timedelta(0))
        param = SimpleNamespace(locator_set=[bad])
        with self.assertRaises(ProtocolError) as caught:
            proto._make_param_locator_set(193, version=2, param=param)  # type: ignore[arg-type]

        self.assertEqual(
            str(caught.exception),
            "HIPv2: [ParamNo 193] invalid locator: "
            "must be an IPv6Address or LocatorData, not 'not-an-ip'",
        )

    def test_pcapng_dsb_secrets_data_guard(self) -> None:
        """The DSB guard names the ``secrets_data`` argument and its type.

        As with ``MH.make``, the unsupported branch receives an arbitrary
        object, so the message reports the type name rather than a repr.

        """
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        proto = PCAPNG.__new__(PCAPNG)
        with self.assertRaises(ProtocolError) as caught:
            proto._make_block_dsb(secrets_data=object())

        self.assertEqual(
            str(caught.exception),
            'PCAP-NG: [DSB] invalid secrets_data: unsupported type object',
        )
