# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""TCP - Transmission Control Protocol
=========================================

.. module:: pcapkit.protocols.transport.tcp

:mod:`pcapkit.protocols.transport.tcp` contains
:class:`~pcapkit.protocols.transport.tcp.TCP` only,
which implements extractor for Transmission Control
Protocol (TCP) [*]_, whose structure is described as
below:

======= ========= ========================= =======================================
Octets      Bits        Name                    Description
======= ========= ========================= =======================================
  0           0   ``tcp.srcport``           Source Port
  2          16   ``tcp.dstport``           Destination Port
  4          32   ``tcp.seq``               Sequence Number
  8          64   ``tcp.ack``               Acknowledgement Number (if ACK set)
  12         96   ``tcp.hdr_len``           Data Offset
  12        100                             Reserved (must be ``\\x00``)
  12        103   ``tcp.flags.ns``          ECN Concealment Protection (NS)
  13        104   ``tcp.flags.cwr``         Congestion Window Reduced (CWR)
  13        105   ``tcp.flags.ece``         ECN-Echo (ECE)
  13        106   ``tcp.flags.urg``         Urgent (URG)
  13        107   ``tcp.flags.ack``         Acknowledgement (ACK)
  13        108   ``tcp.flags.psh``         Push Function (PSH)
  13        109   ``tcp.flags.rst``         Reset Connection (RST)
  13        110   ``tcp.flags.syn``         Synchronize Sequence Numbers (SYN)
  13        111   ``tcp.flags.fin``         Last Packet from Sender (FIN)
  14        112   ``tcp.window_size``       Size of Receive Window
  16        128   ``tcp.checksum``          Checksum
  18        144   ``tcp.urgent_pointer``    Urgent Pointer (if URG set)
  20        160   ``tcp.opt``               TCP Options (if data offset > 5)
======= ========= ========================= =======================================

.. [*] https://en.wikipedia.org/wiki/Transmission_Control_Protocol

"""
import collections
import datetime
import ipaddress
import math
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.transtype import TransType
from pcapkit.const.tcp.checksum import Checksum as Enum_Checksum
from pcapkit.const.tcp.flags import Flags as Enum_Flags
from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
from pcapkit.const.tcp.option import Option as Enum_Option
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.transport.tcp import CC as Data_CC
from pcapkit.protocols.data.transport.tcp import MPTCPDSS as Data_MPTCPDSS
from pcapkit.protocols.data.transport.tcp import SACK as Data_SACK
from pcapkit.protocols.data.transport.tcp import TCP as Data_TCP
from pcapkit.protocols.data.transport.tcp import AlternateChecksumData as Data_AlternateChecksumData
from pcapkit.protocols.data.transport.tcp import \
    AlternateChecksumRequest as Data_AlternateChecksumRequest
from pcapkit.protocols.data.transport.tcp import Authentication as Data_Authentication
from pcapkit.protocols.data.transport.tcp import CCEcho as Data_CCEcho
from pcapkit.protocols.data.transport.tcp import CCNew as Data_CCNew
from pcapkit.protocols.data.transport.tcp import Echo as Data_Echo
from pcapkit.protocols.data.transport.tcp import EchoReply as Data_EchoReply
from pcapkit.protocols.data.transport.tcp import EndOfOptionList as Data_EndOfOptionList
from pcapkit.protocols.data.transport.tcp import FastOpenCookie as Data_FastOpenCookie
from pcapkit.protocols.data.transport.tcp import Flags as Data_Flags
from pcapkit.protocols.data.transport.tcp import MaximumSegmentSize as Data_MaximumSegmentSize
from pcapkit.protocols.data.transport.tcp import MD5Signature as Data_MD5Signature
from pcapkit.protocols.data.transport.tcp import MPTCPAddAddress as Data_MPTCPAddAddress
from pcapkit.protocols.data.transport.tcp import MPTCPCapable as Data_MPTCPCapable
from pcapkit.protocols.data.transport.tcp import MPTCPCapableFlag as Data_MPTCPCapableFlag
from pcapkit.protocols.data.transport.tcp import MPTCPFallback as Data_MPTCPFallback
from pcapkit.protocols.data.transport.tcp import MPTCPFastclose as Data_MPTCPFastclose
from pcapkit.protocols.data.transport.tcp import MPTCPJoinACK as Data_MPTCPJoinACK
from pcapkit.protocols.data.transport.tcp import MPTCPJoinSYN as Data_MPTCPJoinSYN
from pcapkit.protocols.data.transport.tcp import MPTCPJoinSYNACK as Data_MPTCPJoinSYNACK
from pcapkit.protocols.data.transport.tcp import MPTCPPriority as Data_MPTCPPriority
from pcapkit.protocols.data.transport.tcp import MPTCPRemoveAddress as Data_MPTCPRemoveAddress
from pcapkit.protocols.data.transport.tcp import MPTCPUnknown as Data_MPTCPUnknown
from pcapkit.protocols.data.transport.tcp import NoOperation as Data_NoOperation
from pcapkit.protocols.data.transport.tcp import \
    PartialOrderConnectionPermitted as Data_PartialOrderConnectionPermitted
from pcapkit.protocols.data.transport.tcp import \
    PartialOrderServiceProfile as Data_PartialOrderServiceProfile
from pcapkit.protocols.data.transport.tcp import QuickStartResponse as Data_QuickStartResponse
from pcapkit.protocols.data.transport.tcp import SACKBlock as Data_SACKBlock
from pcapkit.protocols.data.transport.tcp import SACKPermitted as Data_SACKPermitted
from pcapkit.protocols.data.transport.tcp import Timestamps as Data_Timestamps
from pcapkit.protocols.data.transport.tcp import UnassignedOption as Data_UnassignedOption
from pcapkit.protocols.data.transport.tcp import UserTimeout as Data_UserTimeout
from pcapkit.protocols.data.transport.tcp import WindowScale as Data_WindowScale
from pcapkit.protocols.schema.transport.tcp import CC as Schema_CC
from pcapkit.protocols.schema.transport.tcp import MPTCPDSS as Schema_MPTCPDSS
from pcapkit.protocols.schema.transport.tcp import SACK as Schema_SACK
from pcapkit.protocols.schema.transport.tcp import TCP as Schema_TCP
from pcapkit.protocols.schema.transport.tcp import \
    AlternateChecksumData as Schema_AlternateChecksumData
from pcapkit.protocols.schema.transport.tcp import \
    AlternateChecksumRequest as Schema_AlternateChecksumRequest
from pcapkit.protocols.schema.transport.tcp import Authentication as Schema_Authentication
from pcapkit.protocols.schema.transport.tcp import CCEcho as Schema_CCEcho
from pcapkit.protocols.schema.transport.tcp import CCNew as Schema_CCNew
from pcapkit.protocols.schema.transport.tcp import Echo as Schema_Echo
from pcapkit.protocols.schema.transport.tcp import EchoReply as Schema_EchoReply
from pcapkit.protocols.schema.transport.tcp import EndOfOptionList as Schema_EndOfOptionList
from pcapkit.protocols.schema.transport.tcp import FastOpenCookie as Schema_FastOpenCookie
from pcapkit.protocols.schema.transport.tcp import MaximumSegmentSize as Schema_MaximumSegmentSize
from pcapkit.protocols.schema.transport.tcp import MD5Signature as Schema_MD5Signature
from pcapkit.protocols.schema.transport.tcp import MPTCPAddAddress as Schema_MPTCPAddAddress
from pcapkit.protocols.schema.transport.tcp import MPTCPCapable as Schema_MPTCPCapable
from pcapkit.protocols.schema.transport.tcp import MPTCPFallback as Schema_MPTCPFallback
from pcapkit.protocols.schema.transport.tcp import MPTCPFastclose as Schema_MPTCPFastclose
from pcapkit.protocols.schema.transport.tcp import MPTCPJoinACK as Schema_MPTCPJoinACK
from pcapkit.protocols.schema.transport.tcp import MPTCPJoinSYN as Schema_MPTCPJoinSYN
from pcapkit.protocols.schema.transport.tcp import MPTCPJoinSYNACK as Schema_MPTCPJoinSYNACK
from pcapkit.protocols.schema.transport.tcp import MPTCPPriority as Schema_MPTCPPriority
from pcapkit.protocols.schema.transport.tcp import MPTCPRemoveAddress as Schema_MPTCPRemoveAddress
from pcapkit.protocols.schema.transport.tcp import MPTCPUnknown as Schema_MPTCPUnknown
from pcapkit.protocols.schema.transport.tcp import NoOperation as Schema_NoOperation
from pcapkit.protocols.schema.transport.tcp import \
    PartialOrderConnectionPermitted as Schema_PartialOrderConnectionPermitted
from pcapkit.protocols.schema.transport.tcp import \
    PartialOrderServiceProfile as Schema_PartialOrderServiceProfile
from pcapkit.protocols.schema.transport.tcp import QuickStartResponse as Schema_QuickStartResponse
from pcapkit.protocols.schema.transport.tcp import SACKBlock as Schema_SACKBlock
from pcapkit.protocols.schema.transport.tcp import SACKPermitted as Schema_SACKPermitted
from pcapkit.protocols.schema.transport.tcp import Timestamps as Schema_Timestamps
from pcapkit.protocols.schema.transport.tcp import UnassignedOption as Schema_UnassignedOption
from pcapkit.protocols.schema.transport.tcp import UserTimeout as Schema_UserTimeout
from pcapkit.protocols.schema.transport.tcp import WindowScale as Schema_WindowScale
from pcapkit.protocols.transport.transport import Transport
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import timedelta
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Callable, DefaultDict, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.const.reg.apptype import AppType as Enum_AppType
    from pcapkit.protocols.data.transport.tcp import MPTCP as Data_MPTCP
    from pcapkit.protocols.data.transport.tcp import MPTCPJoin as Data_MPTCPJoin
    from pcapkit.protocols.data.transport.tcp import Option as Data_Option
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema
    from pcapkit.protocols.schema.transport.tcp import MPTCP as Schema_MPTCP
    from pcapkit.protocols.schema.transport.tcp import Flags as Schema_Flags
    from pcapkit.protocols.schema.transport.tcp import MPTCPJoin as Schema_MPTCPJoin
    from pcapkit.protocols.schema.transport.tcp import Option as Schema_Option

    Option = OrderedMultiDict[Enum_Option, Data_Option]
    OptionParser = Callable[[Schema_Option, NamedArg(Option, 'options')], Data_Option]
    MPOptionParser = Callable[[Schema_MPTCP, NamedArg(Option, 'options')], Data_MPTCP]
    OptionConstructor = Callable[[Enum_Option, DefaultArg(Optional[Data_Option]),
                                  KwArg(Any)], Schema_Option]
    MPOptionConstructor = Callable[[Enum_MPTCPOption, DefaultArg(Optional[Data_MPTCP]),
                                    KwArg(Any)], Schema_MPTCP]

__all__ = ['TCP']


class TCP(Transport[Data_TCP, Schema_TCP],
          schema=Schema_TCP, data=Data_TCP):
    """This class implements Transmission Control Protocol.

    This class currently supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Port Number
         - Protocol
       * - 21
         - :class:`pcapkit.protocols.application.ftp.FTP`
       * - 80
         - :class:`pcapkit.protocols.application.http.HTTP`

    This class currently supports parsing of the following TCP options,
    which are directly mapped to the :class:`pcapkit.const.tcp.option.Option`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
         - Option Constructor
       * - :attr:`~pcapkit.const.tcp.option.Option.End_of_Option_List`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_eool`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_eool`
       * - :attr:`~pcapkit.const.tcp.option.Option.No_Operation`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_nop`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_nop`
       * - :attr:`~pcapkit.const.tcp.option.Option.Maximum_Segment_Size`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_mss`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_mss`
       * - :attr:`~pcapkit.const.tcp.option.Option.Window_Scale`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_ws`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_ws`
       * - :attr:`~pcapkit.const.tcp.option.Option.SACK_Permitted`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_sackpmt`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_sackpmt`
       * - :attr:`~pcapkit.const.tcp.option.Option.SACK`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_sack`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_sack`
       * - :attr:`~pcapkit.const.tcp.option.Option.Echo`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_echo`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_echo`
       * - :attr:`~pcapkit.const.tcp.option.Option.Echo_Reply`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_echore`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_echore`
       * - :attr:`~pcapkit.const.tcp.option.Option.Timestamps`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_ts`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_ts`
       * - :attr:`~pcapkit.const.tcp.option.Option.Partial_Order_Connection_Permitted`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_poc`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_poc`
       * - :attr:`~pcapkit.const.tcp.option.Option.Partial_Order_Service_Profile`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_pocsp`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_pocsp`
       * - :attr:`~pcapkit.const.tcp.option.Option.CC`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_cc`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_cc`
       * - :attr:`~pcapkit.const.tcp.option.Option.CC_NEW`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_ccnew`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_ccnew`
       * - :attr:`~pcapkit.const.tcp.option.Option.CC_ECHO`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_ccecho`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_ccecho`
       * - :attr:`~pcapkit.const.tcp.option.Option.TCP_Alternate_Checksum_Request`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_chkreq`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_chkreq`
       * - :attr:`~pcapkit.const.tcp.option.Option.TCP_Alternate_Checksum_Data`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_chksum`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_chksum`
       * - :attr:`~pcapkit.const.tcp.option.Option.MD5_Signature_Option`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_sig`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_sig`
       * - :attr:`~pcapkit.const.tcp.option.Option.Quick_Start_Response`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_qs`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_qs`
       * - :attr:`~pcapkit.const.tcp.option.Option.User_Timeout_Option`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_timeout`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_timeout`
       * - :attr:`~pcapkit.const.tcp.option.Option.TCP_Authentication_Option`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_ao`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_ao`
       * - :attr:`~pcapkit.const.tcp.option.Option.Multipath_TCP`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_mp`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_mp`
       * - :attr:`~pcapkit.const.tcp.option.Option.TCP_Fast_Open_Cookie`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mode_fastopen`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mode_fastopen`

    This class currently supports parsing of the following Multipath TCP options,
    which are directly mapped to the :class:`pcapkit.const.tcp.mp_tcp_option.MPTCPOption`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
         - Option Constructor
       * - :attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.MP_CAPABLE`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_capable`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mptcp_capable`
       * - :attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.MP_JOIN`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_join`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mptcp_join`
       * - :attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.DSS`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_dss`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mptcp_dss`
       * - :attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.ADD_ADDR`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_addaddr`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mptcp_addaddr`
       * - :attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.REMOVE_ADDR`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_remove`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mptcp_remove`
       * - :attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.MP_PRIO`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_prio`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mptcp_prio`
       * - :attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.MP_FAIL`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_fail`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mptcp_fail`
       * - :attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.MP_FASTCLOSE`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._read_mptcp_fastclose`
         - :meth:`~pcapkit.protocols.transport.tcp.TCP._make_mptcp_fastclose`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[int, ModuleDescriptor[Protocol] | Type[Protocol]]: Protocol
    #: index mapping for decoding next layer, c.f.
    #: :meth:`self._decode_next_layer <pcapkit.protocols.transport.transport.Transport._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            21: ModuleDescriptor('pcapkit.protocols.application.ftp', 'FTP'),      # FTP
            80: ModuleDescriptor('pcapkit.protocols.application.httpv1', 'HTTP'),  # HTTP/1.*
        },
    )

    #: DefaultDict[Enum_Option, str | tuple[OptionParser, OptionConstructor]]: Option
    #: code to method mapping, c.f. :meth:`_read_tcp_options` and
    #: :meth:`_make_tcp_options`. Method names are expected to be referred to
    #: the class by ``_read_mode_${name}`` and ``_make_mode_${name}``, and if
    #: such name not found, the value should then be a method that can parse
    #: the option by itself.
    __option__ = collections.defaultdict(
        lambda: 'donone',
        {
            Enum_Option.End_of_Option_List: 'eool',                 # [RFC 793] End of Option List
            Enum_Option.No_Operation: 'nop',                        # [RFC 793] No-Operation
            Enum_Option.Maximum_Segment_Size: 'mss',                # [RFC 793] Maximum Segment Size
            Enum_Option.Window_Scale: 'ws',                         # [RFC 7323] Window Scale
            Enum_Option.SACK_Permitted: 'sackpmt',                  # [RFC 2018] SACK Permitted
            Enum_Option.SACK: 'sack',                               # [RFC 2018] SACK
            Enum_Option.Echo: 'echo',                               # [RFC 1072] Echo
            Enum_Option.Echo_Reply: 'echore',                       # [RFC 1072] Echo Reply
            Enum_Option.Timestamps: 'ts',                           # [RFC 7323] Timestamps
            Enum_Option.Partial_Order_Connection_Permitted: 'poc',  # [RFC 1693] POC Permitted
            Enum_Option.Partial_Order_Service_Profile: 'pocsp',     # [RFC 1693] POC-Serv Profile
            Enum_Option.CC: 'cc',                                   # [RFC 1644] Connection Count
            Enum_Option.CC_NEW: 'ccnew',                            # [RFC 1644] CC.NEW
            Enum_Option.CC_ECHO: 'ccecho',                          # [RFC 1644] CC.ECHO
            Enum_Option.TCP_Alternate_Checksum_Request: 'chkreq',   # [RFC 1146] Alt-Chksum Request
            Enum_Option.TCP_Alternate_Checksum_Data: 'chksum',      # [RFC 1146] Alt-Chksum Data
            Enum_Option.MD5_Signature_Option: 'sig',                # [RFC 2385] MD5 Signature Option
            Enum_Option.Quick_Start_Response: 'qs',                 # [RFC 4782] Quick-Start Response
            Enum_Option.User_Timeout_Option: 'timeout',             # [RFC 5482] User Timeout Option
            Enum_Option.TCP_Authentication_Option: 'ao',            # [RFC 5925] TCP Authentication Option
            Enum_Option.Multipath_TCP: 'mp',                        # [RFC 6824] Multipath TCP
            Enum_Option.TCP_Fast_Open_Cookie: 'fastopen',           # [RFC 7413] Fast Open
        },
    )  # type: DefaultDict[int, str | tuple[OptionParser, OptionConstructor]]

    #: DefaultDict[Enum_MPTCPOption, str | tuple[MPOptionParser, MPOptionConstructor]]: Option
    #: code to method mapping, c.f. :meth:`_read_mode_mp` and :meth:`_make_mode_mp`.
    #: Method names are expected to be referred to the class by ``_read_mptcp_${name}``
    #: and ``_make_mptcp_${name}``, and if such name not found, the value should
    #: then be a method that can parse the option by itself.
    __mp_option__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_MPTCPOption.MP_CAPABLE: 'capable',
            Enum_MPTCPOption.MP_JOIN: 'join',
            Enum_MPTCPOption.DSS: 'dss',
            Enum_MPTCPOption.ADD_ADDR: 'addaddr',
            Enum_MPTCPOption.REMOVE_ADDR: 'removeaddr',
            Enum_MPTCPOption.MP_PRIO: 'prio',
            Enum_MPTCPOption.MP_FAIL: 'fail',
            Enum_MPTCPOption.MP_FASTCLOSE: 'fastclose',
        },
    )  # type: DefaultDict[int, str | tuple[MPOptionParser, MPOptionConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Transmission Control Protocol"]':
        """Name of current protocol."""
        return 'Transmission Control Protocol'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.hdr_len

    @property
    def src(self) -> 'Enum_AppType':
        """Source port."""
        return self._info.srcport

    @property
    def dst(self) -> 'Enum_AppType':
        """Destination port."""
        return self._info.dstport

    @property
    def connection(self) -> 'Enum_Flags':
        """Connection flags."""
        return self._flags

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TCP':  # pylint: disable=unused-argument
        """Read Transmission Control Protocol (TCP).

        Structure of TCP header [:rfc:`793`]::

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Source Port          |       Destination Port        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                        Sequence Number                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                   Acknowledgement Number                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Data |           |U|A|P|R|S|F|                               |
            | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
            |       |           |G|K|H|T|N|N|                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Checksum            |         Urgent Pointer        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                    Options                    |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                             data                              |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        tcp = Data_TCP(
            srcport=schema.srcport,
            dstport=schema.dstport,
            seq=schema.seq,
            ack=schema.ack,
            hdr_len=schema.offset['offset'] * 4,
            flags=Data_Flags(
                #ns=bool(schema.offset['ns']),
                cwr=bool(schema.flags['cwr']),
                ece=bool(schema.flags['ece']),
                urg=bool(schema.flags['urg']),
                ack=bool(schema.flags['ack']),
                psh=bool(schema.flags['psh']),
                rst=bool(schema.flags['rst']),
                syn=bool(schema.flags['syn']),
                fin=bool(schema.flags['fin']),
            ),
            window_size=schema.window,
            checksum=schema.checksum,
            urgent_pointer=schema.urgent,
        )

        # connection control flags
        _flag = cast('Enum_Flags', 0)
        for key, val in schema.flags.items():
            if val == 1:
                _flag |= Enum_Flags.get(key.upper())
        self._flags = _flag

        tcp.__update__({
            'connection': self._flags,
        })

        _optl = tcp.hdr_len - 20
        if _optl:
            tcp.__update__({
                'options': self._read_tcp_options(_optl),
            })

        return self._decode_next_layer(tcp, (tcp.srcport.port, tcp.dstport.port), length - tcp.hdr_len)

    def make(self,
             srcport: 'Enum_AppType | int' = 0,
             dstport: 'Enum_AppType | int' = 0,
             seq_no: 'int' = 0,
             ack_no: 'int' = 0,
             ns: 'bool' = False,
             cwr: 'bool' = False,
             ece: 'bool' = False,
             urg: 'bool' = False,
             ack: 'bool' = False,
             psh: 'bool' = False,
             rst: 'bool' = False,
             syn: 'bool' = False,
             fin: 'bool' = False,
             window: 'int' = 65535,  # reasonable default value
             checksum: 'bytes' = b'\x00\x00',
             urgent: 'int' = 0,
             options: 'Optional[list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes] | Option]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_TCP':
        """Make (construct) packet data.

        Args:
            srcport: Source port.
            dstport: Destination port.
            seq_no: Sequence number.
            ack_no: Acknowledgement number.
            ns: ECN-nonce concealment protection.
            cwr: Congestion window reduced.
            ece: ECN-Echo.
            urg: Urgent.
            ack: Acknowledgement.
            psh: Push function.
            rst: Reset connection.
            syn: Synchronize sequence numbers.
            fin: Last packet from sender.
            window: Window size.
            checksum: Checksum.
            urgent: Urgent pointer.
            options: TCP options.
            payload: Payload of the packet.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        if options is not None:
            options_value, total_length = self._make_tcp_options(options)
        else:
            options_value, total_length = [], 0

        offset = math.ceil((20 + total_length) / 4)
        flags = {
            'cwr': int(cwr),
            'ece': int(ece),
            'urg': int(urg),
            'ack': int(ack),
            'psh': int(psh),
            'rst': int(rst),
            'syn': int(syn),
            'fin': int(fin),
        }  # type: Schema_Flags

        _flag = cast('Enum_Flags', 0)
        for key, val in flags.items():
            if val == 1:
                _flag |= Enum_Flags.get(key.upper())
        self._flags = _flag

        return Schema_TCP(
            srcport=srcport,
            dstport=dstport,
            seq=seq_no,
            ack=ack_no,
            offset={
                'offset': offset,
                'ns': int(ns),
            },
            flags=flags,
            window=window,
            checksum=checksum,
            urgent=urgent,
            options=options_value,
            payload=payload,
        )

    @classmethod
    def register_option(cls, code: 'Enum_Option', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register an option parser.

        Args:
            code: TCP option code.
            meth: Method name or callable to parse and/or construct the option.

        """
        if code in cls.__option__:
            warn(f'option {code} already registered, overwriting', RegistryWarning)
        cls.__option__[code] = meth

    @classmethod
    def register_mp_option(cls, code: 'Enum_MPTCPOption', meth: 'str | tuple[MPOptionParser, MPOptionConstructor]') -> 'None':
        """Register an MPTCP option parser.

        Args:
            code: MPTCP option code.
            meth: Method name or callable to parse and/or construct the option.

        """
        if code in cls.__mp_option__:
            warn(f'option {code} already registered, overwriting', RegistryWarning)
        cls.__mp_option__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[20]':
        """Return an estimated length for the object."""
        return 20

    @classmethod
    def __index__(cls) -> 'TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType.TCP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_TCP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'srcport': data.srcport,
            'dstport': data.dstport,
            'seq_no': data.seq,
            'ack_no': data.ack,
            #'ns': data.flags.ns,
            'cwr': data.flags.cwr,
            'ece': data.flags.ece,
            'urg': data.flags.urg,
            'ack': data.flags.ack,
            'psh': data.flags.psh,
            'rst': data.flags.rst,
            'syn': data.flags.syn,
            'fin': data.flags.fin,
            'window': data.window_size,
            'checksum': data.checksum,
            'urgent': data.urgent_pointer,
            'options': getattr(data, 'options', None),
            'payload': cls._make_payload(data),
        }

    def _read_tcp_options(self, size: 'int') -> 'Option':
        """Read TCP option list.

        Arguments:
            size: length of option list

        Returns:
            Extracted TCP options.

        Raises:
            ProtocolError: If the threshold is **NOT** matching.

        """
        counter = 0                   # length of read option list
        options = OrderedMultiDict()  # type: Option

        for schema in self.__header__.options:
            kind = schema.kind
            name = self.__option__[kind]

            if isinstance(name, str):
                meth_name = f'_read_mode_{name}'
                meth = cast('OptionParser',
                            getattr(self, meth_name, self._read_mode_donone))
            else:
                meth = name[0]
            data = meth(schema, options=options)

            # record option data
            options.add(kind, data)
            counter += len(schema)

            # break when End of Option List (EOOL) triggered
            if kind == Enum_Option.End_of_Option_List:
                break

        # check threshold
        if counter > size:
            raise ProtocolError('TCP: invalid format')
        return options

    def _read_mode_donone(self, schema: 'Schema_UnassignedOption', *, options: 'Option') -> 'Data_UnassignedOption':  # pylint: disable=unused-argument
        """Read options request no process.

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        """
        option = Data_UnassignedOption(
            kind=schema.kind,
            length=schema.length,
            data=schema.data,
        )
        return option

    def _read_mode_eool(self, schema: 'Schema_EndOfOptionList', *, options: 'Option') -> 'Data_EndOfOptionList':  # pylint: disable=unused-argument
        """Read TCP End of Option List option.

        Structure of TCP end of option list option [:rfc:`793`]:

        .. code-block:: text

           +--------+
           |00000000|
           +--------+
            Kind=0

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        """
        return Data_EndOfOptionList(
            kind=schema.kind,
            length=1,
        )

    def _read_mode_nop(self, schema: 'Schema_NoOperation', *, options: 'Option') -> 'Data_NoOperation':  # pylint: disable=unused-argument
        """Read TCP No Operation option.

        Structure of TCP maximum segment size option [:rfc:`793`]:

        .. code-block:: text

           +--------+
           |00000001|
           +--------+
            Kind=1

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        """
        return Data_NoOperation(
            kind=schema.kind,
            length=1,
        )

    def _read_mode_mss(self, schema: 'Schema_MaximumSegmentSize', *, options: 'Option') -> 'Data_MaximumSegmentSize':  # pylint: disable=unused-argument
        """Read TCP max segment size option.

        Structure of TCP maximum segment size option [:rfc:`793`]:

        .. code-block:: text

           +--------+--------+---------+--------+
           |00000010|00000100|   max seg size   |
           +--------+--------+---------+--------+
            Kind=2   Length=4

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MaximumSegmentSize(
            kind=schema.kind,
            length=schema.length,
            mss=schema.mss,
        )
        return data

    def _read_mode_ws(self, schema: 'Schema_WindowScale', *, options: 'Option') -> 'Data_WindowScale':  # pylint: disable=unused-argument
        """Read TCP windows scale option.

        Structure of TCP window scale option [:rfc:`7323`]:

        .. code-block:: text

           +---------+---------+---------+
           | Kind=3  |Length=3 |shift.cnt|
           +---------+---------+---------+
                1         1         1

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``3``.

        """
        if schema.length != 3:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_WindowScale(
            kind=schema.kind,
            length=schema.length,
            shift=schema.shift,
        )
        return data

    def _read_mode_sackpmt(self, schema: 'Schema_SACKPermitted', *, options: 'Option') -> 'Data_SACKPermitted':  # pylint: disable=unused-argument
        """Read TCP SACK permitted option.

        Structure of TCP SACK permitted option [:rfc:`2018`]:

        .. code-block:: text

           +---------+---------+
           | Kind=4  | Length=2|
           +---------+---------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``2``.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        return Data_SACKPermitted(
            kind=schema.kind,
            length=schema.length,
        )

    def _read_mode_sack(self, schema: 'Schema_SACK', *, options: 'Option') -> 'Data_SACK':  # pylint: disable=unused-argument
        """Read TCP SACK option.

        Structure of TCP SACK option [:rfc:`2018`]:

        .. code-block:: text

                             +--------+--------+
                             | Kind=5 | Length |
           +--------+--------+--------+--------+
           |      Left Edge of 1st Block       |
           +--------+--------+--------+--------+
           |      Right Edge of 1st Block      |
           +--------+--------+--------+--------+
           |                                   |
           /            . . .                  /
           |                                   |
           +--------+--------+--------+--------+
           |      Left Edge of nth Block       |
           +--------+--------+--------+--------+
           |      Right Edge of nth Block      |
           +--------+--------+--------+--------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** multiply of ``8`` plus ``2``.

        """
        data = Data_SACK(
            kind=schema.kind,
            length=schema.length,
            sack=tuple(
                Data_SACKBlock(
                    left=block.left,
                    right=block.right,
                ) for block in schema.sack
            ),
        )
        return data

    def _read_mode_echo(self, schema: 'Schema_Echo', *, options: 'Option') -> 'Data_Echo':  # pylint: disable=unused-argument
        """Read TCP echo option.

        Structure of TCP echo option [:rfc:`1072`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------+
           | Kind=6 | Length |   4 bytes of info to be echoed    |
           +--------+--------+--------+--------+--------+--------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``6``.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_Echo(
            kind=schema.kind,
            length=schema.length,
            data=schema.data,
        )
        return data

    def _read_mode_echore(self, schema: 'Schema_EchoReply', *, options: 'Option') -> 'Data_EchoReply':  # pylint: disable=unused-argument
        """Read TCP echo reply option.

        Structure of TCP echo reply option [:rfc:`1072`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------+
           | Kind=7 | Length |    4 bytes of echoed info         |
           +--------+--------+--------+--------+--------+--------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``6``.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_EchoReply(
            kind=schema.kind,
            length=schema.length,
            data=schema.data,
        )
        return data

    def _read_mode_ts(self, schema: 'Schema_Timestamps', *, options: 'Option') -> 'Data_Timestamps':  # pylint: disable=unused-argument
        """Read TCP timestamps option.

        Structure of TCP timestamp option [:rfc:`7323`]:

        .. code-block:: text

           +-------+-------+---------------------+---------------------+
           |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
           +-------+-------+---------------------+---------------------+
               1       1              4                     4

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``10``.

        """
        if schema.length != 10:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_Timestamps(
            kind=schema.kind,
            length=schema.length,
            timestamp=schema.value,
            echo=schema.reply,
        )
        return data

    def _read_mode_poc(self, schema: 'Schema_PartialOrderConnectionPermitted', *, options: 'Option') -> 'Data_PartialOrderConnectionPermitted':  # pylint: disable=unused-argument
        """Read TCP partial order connection service profile option.

        Structure of TCP ``POC-Permitted`` option [:rfc:`1693`][:rfc:`6247`]:

        .. code-block:: text

           +-----------+-------------+
           |  Kind=9   |  Length=2   |
           +-----------+-------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``2``.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        return Data_PartialOrderConnectionPermitted(
            kind=schema.kind,
            length=schema.length,
        )

    def _read_mode_pocsp(self, schema: 'Schema_PartialOrderServiceProfile', *, options: 'Option') -> 'Data_PartialOrderServiceProfile':  # pylint: disable=unused-argument
        """Read TCP partial order connection service profile option.

        Structure of TCP ``POC-SP`` option [:rfc:`1693`][:rfc:`6247`]:

        .. code-block:: text

                                     1 bit        1 bit    6 bits
           +----------+----------+------------+----------+--------+
           |  Kind=10 | Length=3 | Start_flag | End_flag | Filler |
           +----------+----------+------------+----------+--------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``3``.

        """
        if schema.length != 3:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_PartialOrderServiceProfile(
            kind=schema.kind,
            length=schema.length,
            start=bool(schema.profile['start']),
            end=bool(schema.profile['end']),
        )
        return data

    def _read_mode_cc(self, schema: 'Schema_CC', *, options: 'Option') -> 'Data_CC':  # pylint: disable=unused-argument
        """Read TCP connection count option.

        Structure of TCP ``CC`` option [:rfc:`1644`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------+
           |00001011|00000110|    Connection Count:  SEG.CC      |
           +--------+--------+--------+--------+--------+--------+
            Kind=11  Length=6

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``6``.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_CC(
            kind=schema.kind,
            length=schema.length,
            cc=schema.count,
        )
        return data

    def _read_mode_ccnew(self, schema: 'Schema_CCNew', *, options: 'Option') -> 'Data_CCNew':  # pylint: disable=unused-argument
        """Read TCP connection count (new) option.

        Structure of TCP ``CC.NEW`` option [:rfc:`1644`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------+
           |00001100|00000110|    Connection Count:  SEG.CC      |
           +--------+--------+--------+--------+--------+--------+
            Kind=12  Length=6

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``6``.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_CCNew(
            kind=schema.kind,
            length=schema.length,
            cc=schema.count,
        )
        return data

    def _read_mode_ccecho(self, schema: 'Schema_CCEcho', *, options: 'Option') -> 'Data_CCEcho':  # pylint: disable=unused-argument
        """Read TCP connection count (echo) option.

        Structure of TCP ``CC.ECHO`` option [:rfc:`1644`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------+
           |00001101|00000110|    Connection Count:  SEG.CC      |
           +--------+--------+--------+--------+--------+--------+
            Kind=13  Length=6

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``6``.

        """
        if schema.length != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_CCEcho(
            kind=schema.kind,
            length=schema.length,
            cc=schema.count,
        )
        return data

    def _read_mode_chkreq(self, schema: 'Schema_AlternateChecksumRequest', *, options: 'Option') -> 'Data_AlternateChecksumRequest':  # pylint: disable=unused-argument
        """Read TCP Alternate Checksum Request option.

        Structure of TCP ``CHKSUM-REQ`` [:rfc:`1146`][:rfc:`6247`]:

        .. code-block:: text

           +----------+----------+----------+
           |  Kind=14 | Length=3 |  chksum  |
           +----------+----------+----------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``3``.

        """
        if schema.length != 3:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_AlternateChecksumRequest(
            kind=schema.kind,
            length=schema.length,
            chksum=schema.algorithm,
        )
        return data

    def _read_mode_chksum(self, schema: 'Schema_AlternateChecksumData', *, options: 'Option') -> 'Data_AlternateChecksumData':  # pylint: disable=unused-argument
        """Read Alternate Checksum Data option.

        Structure of TCP ``CHKSUM`` [:rfc:`1146`][:rfc:`6247`]:

        .. code-block:: text

           +---------+---------+---------+     +---------+
           | Kind=15 |Length=N |  data   | ... |  data   |
           +---------+---------+---------+     +---------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        """
        data = Data_AlternateChecksumData(
            kind=schema.kind,
            length=schema.length,
            data=schema.data,
        )
        return data

    def _read_mode_sig(self, schema: 'Schema_MD5Signature', *, options: 'Option') -> 'Data_MD5Signature':  # pylint: disable=unused-argument
        """Read MD5 Signature option.

        Structure of TCP ``SIG`` option [:rfc:`2385`]:

        .. code-block:: text

           +---------+---------+-------------------+
           | Kind=19 |Length=18|   MD5 digest...   |
           +---------+---------+-------------------+
           |                                       |
           +---------------------------------------+
           |                                       |
           +---------------------------------------+
           |                                       |
           +-------------------+-------------------+
           |                   |
           +-------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``18``.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MD5Signature(
            kind=schema.kind,
            length=schema.length,
            digest=schema.digest,
        )
        return data

    def _read_mode_qs(self, schema: 'Schema_QuickStartResponse', *, options: 'Option') -> 'Data_QuickStartResponse':  # pylint: disable=unused-argument
        """Read Quick-Start Response option.

        Structure of TCP ``QSopt`` [:rfc:`4782`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Kind      |  Length=8     | Resv. | Rate  |   TTL Diff    |
           |               |               |       |Request|               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                   QS Nonce                                | R |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``8``.

        """
        size = self._read_unpack(1)
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        rate = schema.flags['rate']
        data = Data_QuickStartResponse(
            kind=schema.kind,
            length=schema.length,
            req_rate=40000 * (2 ** rate) / 1000 if rate > 0 else 0,
            ttl_diff=schema.diff,
            nonce=schema.nonce['nonce'],
        )
        return data

    def _read_mode_timeout(self, schema: 'Schema_UserTimeout', *, options: 'Option') -> 'Data_UserTimeout':  # pylint: disable=unused-argument
        """Read User Timeout option.

        Structure of TCP ``TIMEOUT`` [:rfc:`5482`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Kind = 28   |   Length = 4  |G|        User Timeout         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        if schema.info['granularity'] == 1:
            time = datetime.timedelta(minutes=schema.info['timeout'])
        else:
            time = datetime.timedelta(seconds=schema.info['timeout'])

        data = Data_UserTimeout(
            kind=schema.kind,
            length=schema.length,
            timeout=time,
        )
        return data

    def _read_mode_ao(self, schema: 'Schema_Authentication', *, options: 'Option') -> 'Data_Authentication':  # pylint: disable=unused-argument
        """Read Authentication option.

        Structure of TCP ``AOopt`` [:rfc:`5925`]:

        .. code-block:: text

           +------------+------------+------------+------------+
           |  Kind=29   |   Length   |   KeyID    | RNextKeyID |
           +------------+------------+------------+------------+
           |                     MAC           ...
           +-----------------------------------...

           ...-----------------+
           ...  MAC (con't)    |
           ...-----------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** larger than or equal to ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_Authentication(
            kind=schema.kind,
            length=schema.length,
            key_id=schema.key_id,
            next_key_id=schema.next_key_id,
            mac=schema.mac,
        )
        return data

    def _read_mode_mp(self, schema: 'Schema_MPTCP', *, options: 'Option') -> 'Data_MPTCP':  # pylint: disable=unused-argument
        """Read Multipath TCP option.

        Structure of ``MP-TCP`` [:rfc:`6824`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----------------------+
           |     Kind      |    Length     |Subtype|                       |
           +---------------+---------------+-------+                       |
           |                     Subtype-specific data                     |
           |                       (variable length)                       |
           +---------------------------------------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        """
        subtype = schema.subtype
        name = self.__mp_option__[subtype]

        if isinstance(name, str):
            meth_name = f'_read_mptcp_{name}'
            meth = cast('MPOptionParser',
                        getattr(self, meth_name, self._read_mptcp_unknown))
        else:
            meth = name[0]

        data = meth(schema, options=options)
        return data

    def _read_mptcp_unknown(self, schema: 'Schema_MPTCPUnknown', *, options: 'Option') -> 'Data_MPTCPUnknown':  # pylint: disable=unused-argument
        """Read unknown MPTCP subtype.

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        """
        data = Data_MPTCPUnknown(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            data=schema.test['data'].to_bytes(1, 'big', signed=False) + schema.data,
        )
        return data

    def _read_mptcp_capable(self, schema: 'Schema_MPTCPCapable', *, options: 'Option') -> 'Data_MPTCPCapable':  # pylint: disable=unused-argument
        """Read Multipath Capable option.

        Structure of ``MP_CAPABLE`` [:rfc:`6824`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-------+---------------+
           |     Kind      |    Length     |Subtype|Version|A|B|C|D|E|F|G|H|
           +---------------+---------------+-------+-------+---------------+
           |                   Option Sender's Key (64 bits)               |
           |                                                               |
           |                                                               |
           +---------------------------------------------------------------+
           |                  Option Receiver's Key (64 bits)              |
           |                     (if option Length == 20)                  |
           |                                                               |
           +---------------------------------------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``20`` or ``32``.

        """
        if schema.length not in (20, 32):
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MPTCPCapable(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            version=schema.test['version'],
            flags=Data_MPTCPCapableFlag(
                req=bool(schema.flags['req']),
                ext=bool(schema.flags['ext']),
                hsa=bool(schema.flags['hsa']),
            ),
            skey=schema.skey,
            rkey=schema.rkey if schema.length == 32 else None,
        )
        return data

    def _read_mptcp_join(self, schema: 'Schema_MPTCPJoin', *, options: 'Option') -> 'Data_MPTCPJoin':
        """Read Join Connection option.

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is not given on a valid SYN/ACK packet.

        """
        if Enum_Flags.SYN in self._flags and Enum_Flags.ACK not in self._flags:  # MP_JOIN-SYN
            return self._read_join_syn(schema, options=options)  # type: ignore[arg-type]
        if Enum_Flags.SYN in self._flags and Enum_Flags.ACK in self._flags:      # MP_JOIN-SYN/ACK
            return self._read_join_synack(schema, options=options)  # type: ignore[arg-type]
        if Enum_Flags.SYN not in self._flags and Enum_Flags.ACK in self._flags:  # MP_JOIN-ACK
            return self._read_join_ack(schema, options=options)  # type: ignore[arg-type]
        raise ProtocolError(f'{self.alias}: : [OptNo {schema.kind}] {schema.subtype}: invalid flags combination')

    def _read_join_syn(self, schema: 'Schema_MPTCPJoinSYN', *, options: 'Option') -> 'Data_MPTCPJoinSYN':  # pylint: disable=unused-argument
        """Read Join Connection option for Initial SYN.

        Structure of ``MP_JOIN-SYN`` [:rfc:`6824`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----+-+---------------+
           |     Kind      |  Length = 12  |Subtype|     |B|   Address ID  |
           +---------------+---------------+-------+-----+-+---------------+
           |                   Receiver's Token (32 bits)                  |
           +---------------------------------------------------------------+
           |                Sender's Random Number (32 bits)               |
           +---------------------------------------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``12``.

        """
        if schema.length != 12:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MPTCPJoinSYN(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            connection=Enum_Flags.SYN,  # type: ignore[arg-type]
            backup=bool(schema.test['backup']),
            addr_id=schema.addr_id,
            token=schema.token,
            nonce=schema.nonce,
        )
        return data

    def _read_join_synack(self, schema: 'Schema_MPTCPJoinSYNACK', options: 'Option') -> 'Data_MPTCPJoinSYNACK':  # pylint: disable=unused-argument
        """Read Join Connection option for Responding SYN/ACK.

        Structure of ``MP_JOIN-SYN/ACK`` [:rfc:`6824`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----+-+---------------+
           |     Kind      |  Length = 16  |Subtype|     |B|   Address ID  |
           +---------------+---------------+-------+-----+-+---------------+
           |                                                               |
           |                Sender's Truncated HMAC (64 bits)              |
           |                                                               |
           +---------------------------------------------------------------+
           |                Sender's Random Number (32 bits)               |
           +---------------------------------------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``20``.

        """
        if schema.length != 20:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MPTCPJoinSYNACK(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            connection=Enum_Flags.SYN | Enum_Flags.ACK,  # type: ignore[arg-type]
            backup=bool(schema.test['backup']),
            addr_id=schema.addr_id,
            hmac=schema.hmac,
            nonce=schema.nonce,
        )
        return data

    def _read_join_ack(self, schema: 'Schema_MPTCPJoinACK', *, options: 'Option') -> 'Data_MPTCPJoinACK':  # pylint: disable=unused-argument
        """Read Join Connection option for Third ACK.

        Structure of ``MP_JOIN-ACK`` [:rfc:`6824`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----------------------+
           |     Kind      |  Length = 24  |Subtype|      (reserved)       |
           +---------------+---------------+-------+-----------------------+
           |                                                               |
           |                                                               |
           |                   Sender's HMAC (160 bits)                    |
           |                                                               |
           |                                                               |
           +---------------------------------------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** ``24``.

        """
        if schema.length != 24:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MPTCPJoinACK(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            connection=Enum_Flags.ACK,  # type: ignore[arg-type]
            hmac=schema.hmac,
        )
        return data

    def _read_mptcp_dss(self, schema: 'Schema_MPTCPDSS', *, options: 'Option') -> 'Data_MPTCPDSS':  # pylint: disable=unused-argument
        """Read Data Sequence Signal (Data ACK and Data Sequence Mapping) option.

        Structure of ``DSS`` [:rfc:`6824`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+----------------------+
           |     Kind      |    Length     |Subtype| (reserved) |F|m|M|a|A|
           +---------------+---------------+-------+----------------------+
           |                                                              |
           |           Data ACK (4 or 8 octets, depending on flags)       |
           |                                                              |
           +--------------------------------------------------------------+
           |                                                              |
           |   Data sequence number (4 or 8 octets, depending on flags)   |
           |                                                              |
           +--------------------------------------------------------------+
           |              Subflow Sequence Number (4 octets)              |
           +-------------------------------+------------------------------+
           |  Data-Level Length (2 octets) |      Checksum (2 octets)     |
           +-------------------------------+------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        """
        data = Data_MPTCPDSS(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            data_fin=bool(schema.flags['F']),
            ack=schema.ack,
            dsn=schema.dsn,
            ssn=schema.ssn,
            dl_len=schema.dl_len,
            checksum=schema.checksum,
        )
        return data

    def _read_mptcp_addaddr(self, schema: 'Schema_MPTCPAddAddress', *, options: 'Option') -> 'Data_MPTCPAddAddress':  # pylint: disable=unused-argument
        """Read Add Address option.

        Structure of ``ADD_ADDR`` [:rfc:`6824`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-------+---------------+
           |     Kind      |     Length    |Subtype| IPVer |  Address ID   |
           +---------------+---------------+-------+-------+---------------+
           |          Address (TCP - 4 octets / IPv6 - 16 octets)         |
           +-------------------------------+-------------------------------+
           |   Port (2 octets, optional)   |
           +-------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: Invalid IP version and/or addresses.

        """
        if schema.test['version'] not in (4, 6):
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid IP version')

        data = Data_MPTCPAddAddress(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            version=schema.test['version'],
            addr_id=schema.addr_id,
            addr=schema.address,
            port=schema.port,
        )
        return data

    def _read_mptcp_remove(self, schema: 'Schema_MPTCPRemoveAddress', *, options: 'Option') -> 'Data_MPTCPRemoveAddress':  # pylint: disable=unused-argument
        """Read Remove Address option.

        Structure of ``REMOVE_ADDR`` [:rfc:`6824`]:

        .. code-block:: text

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-------+---------------+
            |     Kind      |  Length = 3+n |Subtype|(resvd)|   Address ID  | ...
            +---------------+---------------+-------+-------+---------------+
                                       (followed by n-1 Address IDs, if required)

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the length is smaller than **3**.

        """
        if schema.length < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MPTCPRemoveAddress(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            addr_id=tuple(schema.addr_id),
        )

        return data

    def _read_mptcp_prio(self, schema: 'Schema_MPTCPPriority', *, options: 'Option') -> 'Data_MPTCPPriority':  # pylint: disable=unused-argument
        """Read Change Subflow Priority option.

        Structure of ``MP_PRIO`` [RFC 6824]:

        .. code-block:: text

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----+-+--------------+
           |     Kind      |     Length    |Subtype|     |B| AddrID (opt) |
           +---------------+---------------+-------+-----+-+--------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the length is smaller than **3**.

        """
        if schema.length not in (3, 4):
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MPTCPPriority(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            backup=bool(schema.test['backup']),
            addr_id=schema.addr_id,
        )

        return data

    def _read_mptcp_fail(self, schema: 'Schema_MPTCPFallback', *, options: 'Option') -> 'Data_MPTCPFallback':  # pylint: disable=unused-argument
        """Read Fallback option.

        Structure of ``MP_FAIL`` [:rfc:`6824`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+----------------------+
           |     Kind      |   Length=12   |Subtype|      (reserved)      |
           +---------------+---------------+-------+----------------------+
           |                                                              |
           |                 Data Sequence Number (8 octets)              |
           |                                                              |
           +--------------------------------------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the length is **NOT** 12.

        """
        if schema.length != 12:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MPTCPFallback(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            dsn=schema.dsn,
        )
        return data

    def _read_mptcp_fastclose(self, schema: 'Schema_MPTCPFastclose', options: 'Option') -> 'Data_MPTCPFastclose':  # pylint: disable=unused-argument
        """Read Fast Close option.

        Structure of ``MP_FASTCLOSE`` [RFC 6824]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----------------------+
           |     Kind      |    Length     |Subtype|      (reserved)       |
           +---------------+---------------+-------+-----------------------+
           |                      Option Receiver's Key                    |
           |                            (64 bits)                          |
           |                                                               |
           +---------------------------------------------------------------+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the length is **NOT** 16.

        """
        if schema.length != 16:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_MPTCPFastclose(
            kind=Enum_Option.Multipath_TCP,  # type: ignore[arg-type]
            length=schema.length,
            subtype=schema.subtype,
            rkey=schema.key,
        )
        return data

    def _read_mode_fastopen(self, schema: 'Schema_FastOpenCookie', *, options: 'Option') -> 'Data_FastOpenCookie':  # pylint: disable=unused-argument
        """Read Fast Open option.

        Structure of TCP ``FASTOPEN`` [:rfc:`7413`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Kind     |    Length     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           ~                            Cookie                             ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed option schema
            options: extracted TCP options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If length is **NOT** valid.

        """
        if not (6 <= schema.length <= 18 or schema.length == 2) and schema.length % 2 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.kind}] invalid format')

        data = Data_FastOpenCookie(
            kind=schema.kind,
            length=schema.length,
            cookie=schema.cookie,
        )
        return data

    def _make_tcp_options(self, options: 'list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes] | Option') -> 'tuple[list[Schema_Option | bytes], int]':
        """Make options for TCP.

        Args:
            options: TCP options

        Returns:
            Tuple of options and total length of options.

        """
        total_length = 0
        if isinstance(options, list):
            options_list = []  # type: list[Schema_Option | bytes]
            for schema in options:
                if isinstance(schema, bytes):
                    code = Enum_Option.get(schema[0])
                    if code in (Enum_Option.No_Operation, Enum_Option.End_of_Option_List):  # ignore padding options by default
                        continue

                    data = schema  # type: Schema_Option | bytes
                    data_len = len(data)
                elif isinstance(schema, Schema):
                    code = schema.type
                    if code in (Enum_Option.No_Operation, Enum_Option.End_of_Option_List):  # ignore padding options by default
                        continue

                    data = schema
                    data_len = len(schema.pack())
                else:
                    code, args = cast('tuple[Enum_Option, dict[str, Any]]', schema)
                    if code in (Enum_Option.No_Operation, Enum_Option.End_of_Option_List):  # ignore padding options by default
                        continue

                    name = self.__option__[code]
                    if isinstance(name, str):
                        meth_name = f'_make_mode_{name}'
                        meth = cast('OptionConstructor',
                                    getattr(self, meth_name, self._make_mode_donone))
                    else:
                        meth = name[1]

                    data = meth(code, **args)
                    data_len = len(data.pack())

                options_list.append(data)
                total_length += data_len

                # force alignment to 32-bit boundary
                if data_len % 4:
                    pad_len = 4 - (data_len % 4)
                    pad_opt = self._make_mode_nop(Enum_Option.No_Operation)  # type: ignore[arg-type]
                    total_length += pad_len

                    for _ in range(pad_len - 1):
                        options_list.append(pad_opt)
                    options_list.append(self._make_mode_eool(Enum_Option.End_of_Option_List))  # type: ignore[arg-type]
            return options_list, total_length

        options_list = []
        for code, option in options.items(multi=True):
            # ignore padding options by default
            if code in (Enum_Option.No_Operation, Enum_Option.End_of_Option_List):
                continue

            name = self.__option__[code]
            if isinstance(name, str):
                meth_name = f'_make_mode_{name}'
                meth = cast('OptionConstructor',
                            getattr(self, meth_name, self._make_mode_donone))
            else:
                meth = name[1]

            data = meth(code, option)
            data_len = len(data.pack())

            options_list.append(data)
            total_length += data_len

            # force alignment to 32-bit boundary
            if data_len % 4:
                pad_len = 4 - (data_len % 4)
                pad_opt = self._make_mode_nop(Enum_Option.No_Operation)  # type: ignore[arg-type]
                total_length += pad_len

                for _ in range(pad_len - 1):
                    options_list.append(pad_opt)
                options_list.append(self._make_mode_eool(Enum_Option.End_of_Option_List))  # type: ignore[arg-type]
        return options_list, total_length

    def _make_mode_donone(self, code: 'Enum_Option', opt: 'Optional[Data_UnassignedOption]' = None, *,
                         data: 'bytes' = b'',
                         **kwargs: 'Any') -> 'Schema_UnassignedOption':
        """Make TCP unassigned option.

        Args:
            code: option code
            opt: option data
            data: option payload in :obj:`bytes`
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            data = opt.data

        return Schema_UnassignedOption(
            kind=code,
            length=len(data) + 2,
            data=data,
        )

    def _make_mode_eool(self, code: 'Enum_Option', opt: 'Optional[Data_EndOfOptionList]' = None, **kwargs: 'Any') -> 'Schema_EndOfOptionList':
        """Make TCP End of Option List option.

        Args:
            code: option code
            opt: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        return Schema_EndOfOptionList(
            kind=code,
            length=1,
        )

    def _make_mode_nop(self, code: 'Enum_Option', opt: 'Optional[Data_NoOperation]' = None, **kwargs: 'Any') -> 'Schema_NoOperation':
        """Make TCP NoOperation option.

        Args:
            code: option code
            opt: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        return Schema_NoOperation(
            kind=code,
            length=1,
        )

    def _make_mode_mss(self, code: 'Enum_Option', opt: 'Optional[Data_MaximumSegmentSize]' = None, *,
                       mss: 'int' = 65535,  # reasonable default value
                       **kwargs: 'Any') -> 'Schema_MaximumSegmentSize':
        """Make TCP maximum segment size option.

        Args:
            code: option code
            opt: option data
            mss: maximum segment size
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            mss = opt.mss

        return Schema_MaximumSegmentSize(
            kind=code,
            length=4,
            mss=mss,
        )

    def _make_mode_ws(self, code: 'Enum_Option', opt: 'Optional[Data_WindowScale]' = None, *,
                      shift: 'int' = 0,  # reasonable default value
                      **kwargs: 'Any') -> 'Schema_WindowScale':
        """Make TCP window scale option.

        Args:
            code: option code
            opt: option data
            shift: window scale shift count
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            shift = opt.shift

        return Schema_WindowScale(
            kind=code,
            length=3,
            scale=shift,
        )

    def _make_mode_sackpmt(self, code: 'Enum_Option', opt: 'Optional[Data_SACKPermitted]' = None,
                           **kwargs: 'Any') -> 'Schema_SACKPermitted':
        """Make TCP SACK permitted option.

        Args:
            code: option code
            opt: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        return Schema_SACKPermitted(
            kind=code,
            length=2,
        )

    def _make_mode_sack(self, code: 'Enum_Option', opt: 'Optional[Data_SACK]' = None, *,
                        sack: 'Optional[list[tuple[int, int]]]' = None,
                        **kwargs: 'Any') -> 'Schema_SACK':
        """Make TCP SACK option.

        Args:
            code: option code
            opt: option data
            sack: SACK blocks
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            sack_val = [Schema_SACKBlock(
                left=block.left,
                right=block.right,
            ) for block in opt.sack]
        else:
            sack_val = []

            if sack is not None:
                for left, right in sack:
                    sack_val.append(Schema_SACKBlock(
                        left=left,
                        right=right,
                    ))

        return Schema_SACK(
            kind=code,
            length=2 + (len(sack_val) * 8),
            sack=sack_val,
        )

    def _make_mode_echo(self, code: 'Enum_Option', opt: 'Optional[Data_Echo]' = None, *,
                        data: 'bytes' = b'\x00\x00\x00\x00',
                        **kwargs: 'Any') -> 'Schema_Echo':
        """Make TCP echo option.

        Args:
            code: option code
            opt: option data
            data: 4 bytes of info to be echoed
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            data = opt.data

        return Schema_Echo(
            kind=code,
            length=6,
            data=data,
        )

    def _make_mode_echore(self, code: 'Enum_Option', opt: 'Optional[Data_EchoReply]' = None, *,
                          data: 'bytes' = b'\x00\x00\x00\x00',
                          **kwargs: 'Any') -> 'Schema_EchoReply':
        """Make TCP echo reply option.

        Args:
            code: option code
            opt: option data
            data: 4 bytes of echoed info
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            data = opt.data

        return Schema_EchoReply(
            kind=code,
            length=6,
            data=data,
        )

    def _make_mode_ts(self, code: 'Enum_Option', opt: 'Optional[Data_Timestamps]' = None, *,
                      tsval: 'int' = 0,
                      tsecr: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_Timestamps':
        """Make TCP timestamps option.

        Args:
            code: option code
            opt: option data
            tsval: timestamp value
            tsecr: timestamp echo reply
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            tsval = opt.timestamp
            tsecr = opt.echo

        return Schema_Timestamps(
            kind=code,
            length=10,
            value=tsval,
            reply=tsecr,
        )

    def _make_mode_poc(self, code: 'Enum_Option', opt: 'Optional[Data_PartialOrderConnectionPermitted]' = None,
                       **kwargs: 'Any') -> 'Schema_PartialOrderConnectionPermitted':
        """Make TCP partial order connection option.

        Args:
            code: option code
            opt: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        return Schema_PartialOrderConnectionPermitted(
            kind=code,
            length=2,
        )

    def _make_mode_pocsp(self, code: 'Enum_Option', opt: 'Optional[Data_PartialOrderServiceProfile]' = None, *,
                         start: 'bool' = False,
                         end: 'bool' = False,
                         **kwargs: 'Any') -> 'Schema_PartialOrderServiceProfile':
        """Make TCP partial order connection service profile option.

        Args:
            code: option code
            opt: option data
            start: start partial order connection
            end: end partial order connection
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            start = opt.start
            end = opt.end

        return Schema_PartialOrderServiceProfile(
            kind=code,
            length=3,
            profile={
                'start': start,
                'end': end,
            },
        )

    def _make_mode_cc(self, code: 'Enum_Option', opt: 'Optional[Data_CC]' = None, *,
                      count: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_CC':
        """Make TCP connection count option.

        Args:
            code: option code
            opt: option data
            count: connection count
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            count = opt.cc

        return Schema_CC(
            kind=code,
            length=6,
            count=count,
        )

    def _make_mode_ccnew(self, code: 'Enum_Option', opt: 'Optional[Data_CCNew]' = None, *,
                         count: 'int' = 0,
                         **kwargs: 'Any') -> 'Schema_CCNew':
        """Make TCP connection count new option.

        Args:
            code: option code
            opt: option data
            count: connection count
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            count = opt.cc

        return Schema_CCNew(
            kind=code,
            length=6,
            count=count,
        )

    def _make_mode_ccecho(self, code: 'Enum_Option', opt: 'Optional[Data_CCEcho]' = None, *,
                          count: 'int' = 0,
                          **kwargs: 'Any') -> 'Schema_CCEcho':
        """Make TCP connection count echo option.

        Args:
            code: option code
            opt: option data
            count: connection count
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            count = opt.cc

        return Schema_CCEcho(
            kind=code,
            length=6,
            count=count,
        )

    def _make_mode_chkreq(self, code: 'Enum_Option', opt: 'Optional[Data_AlternateChecksumRequest]' = None, *,
                          algorithm: 'Enum_Checksum | StdlibEnum | AenumEnum | int | str' = Enum_Checksum.TCP_checksum,
                          algorithm_default: 'Optional[int]' = None,
                          algorithm_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                          algorithm_reversed: 'bool' = False,
                          **kwargs: 'Any') -> 'Schema_AlternateChecksumRequest':
        """Make TCP alternate checksum request option.

        Args:
            code: option code
            opt: option data
            algorithm: checksum algorithm
            algorithm_default: default value for checksum algorithm
            algorithm_namespace: namespace for checksum algorithm
            algorithm_reversed: reversed flag for checksum algorithm
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            algorithm_val = opt.chksum
        else:
            algorithm_val = self._make_index(algorithm, algorithm_default, namespace=algorithm_namespace,  # type: ignore[assignment]
                                             reversed=algorithm_reversed, pack=False)

        return Schema_AlternateChecksumRequest(
            kind=code,
            length=3,
            algorithm=algorithm_val,
        )

    def _make_mode_chksum(self, code: 'Enum_Option', opt: 'Optional[Data_AlternateChecksumData]' = None, *,
                          data: 'bytes' = b'',
                          **kwargs: 'Any') -> 'Schema_AlternateChecksumData':
        """Make TCP alternate checksum data option.

        Args:
            code: option code
            opt: option data
            data: checksum data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            data = opt.data

        return Schema_AlternateChecksumData(
            kind=code,
            length=2 + len(data),
            data=data,
        )

    def _make_mode_sig(self, code: 'Enum_Option', opt: 'Optional[Data_MD5Signature]' = None, *,
                       digest: 'bytes' = bytes(16),
                       **kwargs: 'Any') -> 'Schema_MD5Signature':
        """Make TCP MD5 signature option.

        Args:
            code: option code
            opt: option data
            digest: digest
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            digest = opt.digest

        return Schema_MD5Signature(
            kind=code,
            length=18,
            digest=digest,
        )

    def _make_mode_qs(self, code: 'Enum_Option', opt: 'Optional[Data_QuickStartResponse]' = None, *,
                      rate: 'int' = 0,
                      diff: 'timedelta | int' = 0,
                      nonce: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_QuickStartResponse':
        """Make TCP quick start response option.

        Args:
            code: option code
            opt: option data
            rate: rate (in kbps)
            diff: time to live (in seconds) difference
            nonce: nonce value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            rate = opt.req_rate
            diff = opt.ttl_diff
            nonce = opt.nonce

        rate_val = math.floor(math.log2(rate * 1000 / 40000)) if rate > 0 else 0
        diff_val = diff if isinstance(diff, int) else math.floor(diff.total_seconds())

        return Schema_QuickStartResponse(
            kind=code,
            length=8,
            flags={
                'rate': rate_val,
            },
            diff=diff_val,
            nonce={
                'nonce': nonce,
            },
        )

    def _make_mode_timeout(self, code: 'Enum_Option', opt: 'Optional[Data_UserTimeout]' = None, *,
                           timeout: 'timedelta | int' = 0,
                           **kwargs: 'Any') -> 'Schema_UserTimeout':
        """Make TCP user timeout option.

        Args:
            code: option code
            opt: option data
            timeout: timeout value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            timeout_val = math.floor(opt.timeout.total_seconds())
        else:
            timeout_val = timeout if isinstance(timeout, int) else math.floor(timeout.total_seconds())

        granularity = timeout_val.bit_length() > 15
        timeout_val = math.floor(timeout_val / 60) if granularity else timeout_val

        if timeout_val.bit_length() > 15:
            raise ProtocolError(f'TCP: [OptNo {code}] timeout value too large: {timeout}')

        return Schema_UserTimeout(
            kind=code,
            length=3,
            info={
                'granularity': granularity,
                'timeout': timeout_val,
            },
        )

    def _make_mode_ao(self, code: 'Enum_Option', opt: 'Optional[Data_Authentication]' = None, *,
                      key_id: 'int' = 0,
                      next_key_id: 'int' = 0,
                      mac: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_Authentication':
        """Make TCP authentication option.

        Args:
            code: option code
            opt: option data
            key_id: key ID
            next_key_id: next key ID
            mac: MAC value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            key_id = opt.key_id
            next_key_id = opt.next_key_id
            mac = opt.mac

        return Schema_Authentication(
            kind=code,
            length=4 + len(mac),
            key_id=key_id,
            next_key_id=next_key_id,
            mac=mac,
        )

    def _make_mode_mp(self, code: 'Enum_Option', opt: 'Optional[Data_MPTCP]' = None, *,
                      subtype: 'Enum_MPTCPOption | StdlibEnum | AenumEnum | int | str' = Enum_MPTCPOption.MP_CAPABLE,
                      subtype_default: 'Optional[int]' = None,
                      subtype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      subtype_reversed: 'bool' = False,
                      **kwargs: 'Any') -> 'Schema_MPTCP':
        """Make multipath TCP option.

        Args:
            code: option code
            opt: option data
            subtype: MPTCP subtype
            subtype_default: default value for MPTCP subtype
            subtype_namespace: namespace for MPTCP subtype
            subtype_reversed: reversed flag for MPTCP subtype
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            subtype_val = opt.subtype
        else:
            subtype_val = self._make_index(subtype, subtype_default, namespace=subtype_namespace,  # type: ignore[assignment]
                                           reversed=subtype_reversed, pack=False)

        name = self.__mp_option__[subtype_val]
        if isinstance(name, str):
            meth_name = f'_make_mptcp_{name}'
            meth = cast('MPOptionConstructor',
                        getattr(self, meth_name, self._make_mptcp_unknown))
        else:
            meth = name[1]

        schema = meth(subtype_val, opt, **kwargs)
        return schema

    def _make_mptcp_unknown(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPUnknown]' = None, *,
                            data: 'bytes' = b'\x00',
                            **kwargs: 'Any') -> 'Schema_MPTCPUnknown':
        """Make unknown multipath TCP option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            data: option payload data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            data = opt.data

        return Schema_MPTCPUnknown(
            kind=Enum_Option.MPTCP,
            length=2 + len(data),
            test={
                'subtype': subtype.value,
                'data': data[0] & 0x0F if data else 0,
            },
            data=data[1:],
        )

    def _make_mptcp_capable(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPCapable]' = None, *,
                            version: 'int' = 0,
                            flag_req: 'bool' = False,
                            flag_ext: 'bool' = False,
                            flag_hsa: 'bool' = False,
                            skey: 'int' = 0,
                            rkey: 'Optional[int]' = 0,
                            **kwargs: 'Any') -> 'Schema_MPTCPCapable':
        """Make multipath TCP capable option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            version: MPTCP version
            flag_req: checksum required flag
            flag_ext: extensability flag
            flag_hsa: use of HMAC-SHA1 flag
            skey: option sender's key
            rkey: option receiver's key
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            version = opt.version
            flag_req = opt.flags.req
            flag_ext = opt.flags.ext
            flag_hsa = opt.flags.hsa
            skey = opt.skey
            rkey = opt.rkey

        return Schema_MPTCPCapable(
            kind=Enum_Option.MPTCP,
            length=20 if rkey is None else 32,
            test={
                'subtype': subtype.value,
                'version': version,
            },
            flags={
                'req': flag_req,
                'ext': flag_ext,
                'hsa': flag_hsa,
            },
            skey=skey,
            rkey=rkey,
        )

    def _make_mptcp_join(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPJoin]' = None, **kwargs: 'Any') -> 'Schema_MPTCPJoin':
        """Make multipath TCP join option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if Enum_Flags.SYN in self._flags and Enum_Flags.ACK not in self._flags:  # MP_JOIN-SYN
            return self._make_join_syn(subtype, opt, **kwargs)  # type: ignore[arg-type]
        if Enum_Flags.SYN in self._flags and Enum_Flags.ACK in self._flags:      # MP_JOIN-SYN/ACK
            return self._make_join_synack(subtype, opt, **kwargs)  # type: ignore[arg-type]
        if Enum_Flags.SYN not in self._flags and Enum_Flags.ACK in self._flags:  # MP_JOIN-ACK
            return self._make_join_ack(subtype, opt, **kwargs)  # type: ignore[arg-type]
        raise ProtocolError(f'{self.alias}: : [OptNo {Enum_Option.Multipath_TCP}] {subtype}: invalid flags combination')

    def _make_join_syn(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPJoinSYN]' = None, *,
                       backup: 'bool' = False,
                       addr_id: 'int' = 0,
                       token: 'int' = 0,
                       nonce: 'int' = 0,
                       **kwargs: 'Any') -> 'Schema_MPTCPJoinSYN':
        """Make multipath TCP join SYN option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            backup: backup flag
            addr_id: address ID
            token: receiver's token
            nonce: sender's random number
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            backup = opt.backup
            addr_id = opt.addr_id
            token = opt.token
            nonce = opt.nonce

        return Schema_MPTCPJoinSYN(
            kind=Enum_Option.MPTCP,
            length=12,
            test={
                'subtype': subtype.value,
                'backup': backup,
            },
            addr_id=addr_id,
            token=token,
            nonce=nonce,
        )

    def _make_join_synack(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPJoinSYNACK]' = None, *,
                          backup: 'bool' = False,
                          addr_id: 'int' = 0,
                          hmac: 'bytes' = bytes(8),
                          nonce: 'int' = 0,
                          **kwargs: 'Any') -> 'Schema_MPTCPJoinSYNACK':
        """Make multipath TCP join SYN/ACK option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            backup: backup flag
            addr_id: address ID
            hmac: sender's truncated HMAC
            nonce: sender's random number
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            backup = opt.backup
            addr_id = opt.addr_id
            nonce = opt.nonce
            nonce = opt.nonce

        return Schema_MPTCPJoinSYNACK(
            kind=Enum_Option.MPTCP,
            length=12,
            test={
                'subtype': subtype.value,
                'backup': backup,
            },
            addr_id=addr_id,
            hmac=hmac,
            nonce=nonce,
        )

    def _make_join_ack(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPJoinACK]' = None, *,
                       hmac: 'bytes' = bytes(20),
                       **kwargs: 'Any') -> 'Schema_MPTCPJoinACK':
        """Make multipath TCP join ACK option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            hmac: sender's HMAC
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            hmac = opt.hmac

        return Schema_MPTCPJoinACK(
            kind=Enum_Option.MPTCP,
            length=8,
            test={
                'subtype': subtype.value,
            },
            hmac=hmac,
        )

    def _make_mptcp_dss(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPDSS]' = None, *,
                        data_fin: 'bool' = False,
                        ack: 'Optional[int]' = None,
                        dsn: 'Optional[int]' = None,
                        ssn: 'Optional[int]' = None,
                        dl_len: 'Optional[int]' = None,
                        checksum: 'Optional[bytes]' = None,
                        **kwargs: 'Any') -> 'Schema_MPTCPDSS':
        """Make multipath TCP DSS option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            data_fin: ``DATA_FIN`` flag
            ack: Data ACK
            dsn: data sequence number
            ssn: subflow sequence number
            dl_len: data-level length
            checksum: checksum
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            data_fin = opt.data_fin
            ack = opt.ack
            dsn = opt.dsn
            ssn = opt.ssn
            dl_len = opt.dl_len
            checksum = opt.checksum

        flag_A = ack is not None
        flag_a = cast('int', ack).bit_length() > 32 if flag_A else False

        flag_M = dsn is not None
        flag_m = cast('int', dsn).bit_length() > 32 if flag_M else False

        if flag_M and (ssn is None or dl_len is None or checksum is None):
            raise ProtocolError(f'{self.alias}: : [OptNo {Enum_Option.Multipath_TCP}] {subtype}: missing required fields')
        if not flag_M and (ssn is not None or dl_len is not None or checksum is not None):
            raise ProtocolError(f'{self.alias}: : [OptNo {Enum_Option.Multipath_TCP}] {subtype}: missing required fields')

        return Schema_MPTCPDSS(
            kind=Enum_Option.MPTCP,
            length=4 + (4 if flag_A else 0) + (4 if flag_a else 0) + (12 if flag_M else 0) + (4 if flag_m else 0),
            test={
                'subtype': subtype.value,
            },
            flags={
                'F': data_fin,
                'A': flag_A,
                'm': flag_m,
                'M': flag_M,
                'a': flag_a,
                'A': flag_A,
            },
            ack=ack,
            dsn=dsn,
            ssn=ssn,
            dl_len=dl_len,
            checksum=checksum,
        )

    def _make_mptcp_addaddr(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPAddAddress]' = None, *,
                             addr_id: 'int' = 0,
                             addr: 'IPv4Address | IPv6Address | int | bytes | str' = '0.0.0.0',  # nosec: B104
                             port: 'Optional[int]' = None,
                             **kwargs: 'Any') -> 'Schema_MPTCPAddAddress':
        """Make multipath TCP add address option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            addr_id: address ID
            addr: address
            port: port number
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            addr_id = opt.addr_id
            addr_val = opt.addr
            port = opt.port
        else:
            addr_val = ipaddress.ip_address(addr)
        version = addr_val.version

        return Schema_MPTCPAddAddress(
            kind=Enum_Option.MPTCP,
            length=4 + (4 if version == 4 else 16) + (2 if port is not None else 0),
            test={
                'subtype': subtype.value,
                'version': version,
            },
            addr_id=addr_id,
            address=addr_val,
            port=port,
        )

    def _make_mptcp_remove(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPRemoveAddress]' = None, *,
                           addr_id: 'Optional[list[int]]' = None,
                           **kwargs: 'Any') -> 'Schema_MPTCPRemoveAddress':
        """Make multipath TCP remove address option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            addr_id: address ID list
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            addr_id_list = cast('list[int]', opt.addr_id)
        else:
            addr_id_list = addr_id if addr_id is not None else []

        return Schema_MPTCPRemoveAddress(
            kind=Enum_Option.MPTCP,
            length=4,
            test={
                'subtype': subtype.value,
            },
            addr_id=addr_id_list,
        )

    def _make_mptcp_prio(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPPriority]' = None, *,
                             backup: 'bool' = False,
                             addr_id: 'Optional[int]' = None,
                             **kwargs: 'Any') -> 'Schema_MPTCPPriority':
        """Make multipath TCP priority option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            backup: backup flag
            addr_id: address ID
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            addr_id = opt.addr_id

        return Schema_MPTCPPriority(
            kind=Enum_Option.MPTCP,
            length=4,
            test={
                'subtype': subtype.value,
                'backup': backup,
            },
            addr_id=addr_id,
        )

    def _make_mptcp_fail(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPFallback]' = None, *,
                         dsn: 'int' = 0,
                         **kwargs: 'Any') -> 'Schema_MPTCPFallback':
        """Make multipath TCP fail option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            dsn: data sequence number
            **kwargs: arbitrary keyword arguments

            Returns:
                Constructed option schema.

        """
        if opt is not None:
            dsn = opt.dsn

        return Schema_MPTCPFallback(
            kind=Enum_Option.MPTCP,
            length=12,
            test={
                'subtype': subtype.value,
            },
            dsn=dsn,
        )

    def _make_mptcp_fastclose(self, subtype: 'Enum_MPTCPOption', opt: 'Optional[Data_MPTCPFastclose]' = None, *,
                              key: 'int' = 0,
                              **kwargs: 'Any') -> 'Schema_MPTCPFastclose':
        """Make multipath TCP fastclose option.

        Args:
            subtype: MPTCP subtype
            opt: option data
            key: option receiver's key
            **kwargs: arbitrary keyword arguments

            Returns:
                Constructed option schema.

        """
        if opt is not None:
            key = opt.rkey

        return Schema_MPTCPFastclose(
            kind=Enum_Option.MPTCP,
            length=12,
            test={
                'subtype': subtype.value,
            },
            key=key,
        )

    def _make_mode_fastopen(self, code: 'Enum_Option', opt: 'Optional[Data_FastOpenCookie]' = None, *,
                            cookie: 'Optional[bytes]' = None,
                            **kwargs: 'Any') -> 'Schema_FastOpenCookie':
        """Make TCP Fast Open option.

        Args:
            code: option code
            opt: option data
            cookie: fast open cookie
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            cookie = opt.cookie

        return Schema_FastOpenCookie(
            kind=code,
            length=2 + (len(cookie) if cookie is not None else 0),
            cookie=cookie,
        )
