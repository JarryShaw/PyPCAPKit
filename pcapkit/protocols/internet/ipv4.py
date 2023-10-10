# -*- coding: utf-8 -*-
"""IPv4 - Internet Protocol version 4
========================================

.. module:: pcapkit.protocols.internet.ipv4

:mod:`pcapkit.protocols.internet.ipv4` contains
:class:`~pcapkit.protocols.internet.ipv4.IPv4` only,
which implements extractor for Internet Protocol
version 4 (IPv4) [*]_, whose structure is described
as below:

======= ========= ====================== =============================================
Octets      Bits        Name                    Description
======= ========= ====================== =============================================
  0           0   ``ip.version``              Version (``4``)
  0           4   ``ip.hdr_len``              Internal Header Length (IHL)
  1           8   ``ip.dsfield.dscp``         Differentiated Services Code Point (DSCP)
  1          14   ``ip.dsfield.ecn``          Explicit Congestion Notification (ECN)
  2          16   ``ip.len``                  Total Length
  4          32   ``ip.id``                   Identification
  6          48                               Reserved Bit (must be ``\\x00``)
  6          49   ``ip.flags.df``             Don't Fragment (DF)
  6          50   ``ip.flags.mf``             More Fragments (MF)
  6          51   ``ip.frag_offset``          Fragment Offset
  8          64   ``ip.ttl``                  Time To Live (TTL)
  9          72   ``ip.proto``                Protocol (Transport Layer)
  10         80   ``ip.checksum``             Header Checksum
  12         96   ``ip.src``                  Source IP Address
  16        128   ``ip.dst``                  Destination IP Address
  20        160   ``ip.options``              IP Options (if IHL > ``5``)
======= ========= ====================== =============================================

.. [*] https://en.wikipedia.org/wiki/IPv4

"""
import datetime
import ipaddress
import math
from typing import TYPE_CHECKING, cast

from pcapkit.const.ipv4.classification_level import ClassificationLevel as Enum_ClassificationLevel
from pcapkit.const.ipv4.option_class import OptionClass as Enum_OptionClass
from pcapkit.const.ipv4.option_number import OptionNumber as Enum_OptionNumber
from pcapkit.const.ipv4.protection_authority import ProtectionAuthority as Enum_ProtectionAuthority
from pcapkit.const.ipv4.qs_function import QSFunction as Enum_QSFunction
from pcapkit.const.ipv4.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.ipv4.tos_del import ToSDelay as Enum_ToSDelay
from pcapkit.const.ipv4.tos_ecn import ToSECN as Enum_ToSECN
from pcapkit.const.ipv4.tos_pre import ToSPrecedence as Enum_ToSPrecedence
from pcapkit.const.ipv4.tos_rel import ToSReliability as Enum_ToSReliability
from pcapkit.const.ipv4.tos_thr import ToSThroughput as Enum_ToSThroughput
from pcapkit.const.ipv4.ts_flag import TSFlag as Enum_TSFlag
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.internet.ipv4 import EOOLOption as Data_EOOLOption
from pcapkit.protocols.data.internet.ipv4 import ESECOption as Data_ESECOption
from pcapkit.protocols.data.internet.ipv4 import Flags as Data_Flags
from pcapkit.protocols.data.internet.ipv4 import IPv4 as Data_IPv4
from pcapkit.protocols.data.internet.ipv4 import LSROption as Data_LSROption
from pcapkit.protocols.data.internet.ipv4 import MTUPOption as Data_MTUPOption
from pcapkit.protocols.data.internet.ipv4 import MTUROption as Data_MTUROption
from pcapkit.protocols.data.internet.ipv4 import NOPOption as Data_NOPOption
from pcapkit.protocols.data.internet.ipv4 import OptionType as Data_OptionType
from pcapkit.protocols.data.internet.ipv4 import QSOption as Data_QSOption
from pcapkit.protocols.data.internet.ipv4 import \
    QuickStartReportOption as Data_QuickStartReportOption
from pcapkit.protocols.data.internet.ipv4 import \
    QuickStartRequestOption as Data_QuickStartRequestOption
from pcapkit.protocols.data.internet.ipv4 import RROption as Data_RROption
from pcapkit.protocols.data.internet.ipv4 import RTRALTOption as Data_RTRALTOption
from pcapkit.protocols.data.internet.ipv4 import SECOption as Data_SECOption
from pcapkit.protocols.data.internet.ipv4 import SIDOption as Data_SIDOption
from pcapkit.protocols.data.internet.ipv4 import SSROption as Data_SSROption
from pcapkit.protocols.data.internet.ipv4 import ToSField as Data_ToSField
from pcapkit.protocols.data.internet.ipv4 import TROption as Data_TROption
from pcapkit.protocols.data.internet.ipv4 import TSOption as Data_TSOption
from pcapkit.protocols.data.internet.ipv4 import UnassignedOption as Data_UnassignedOption
from pcapkit.protocols.internet.ip import IP
from pcapkit.protocols.schema.internet.ipv4 import EOOLOption as Schema_EOOLOption
from pcapkit.protocols.schema.internet.ipv4 import ESECOption as Schema_ESECOption
from pcapkit.protocols.schema.internet.ipv4 import IPv4 as Schema_IPv4
from pcapkit.protocols.schema.internet.ipv4 import LSROption as Schema_LSROption
from pcapkit.protocols.schema.internet.ipv4 import MTUPOption as Schema_MTUPOption
from pcapkit.protocols.schema.internet.ipv4 import MTUROption as Schema_MTUROption
from pcapkit.protocols.schema.internet.ipv4 import NOPOption as Schema_NOPOption
from pcapkit.protocols.schema.internet.ipv4 import QSOption as Schema_QSOption
from pcapkit.protocols.schema.internet.ipv4 import \
    QuickStartReportOption as Schema_QuickStartReportOption
from pcapkit.protocols.schema.internet.ipv4 import \
    QuickStartRequestOption as Schema_QuickStartRequestOption
from pcapkit.protocols.schema.internet.ipv4 import RROption as Schema_RROption
from pcapkit.protocols.schema.internet.ipv4 import RTRALTOption as Schema_RTRALTOption
from pcapkit.protocols.schema.internet.ipv4 import SECOption as Schema_SECOption
from pcapkit.protocols.schema.internet.ipv4 import SIDOption as Schema_SIDOption
from pcapkit.protocols.schema.internet.ipv4 import SSROption as Schema_SSROption
from pcapkit.protocols.schema.internet.ipv4 import TROption as Schema_TROption
from pcapkit.protocols.schema.internet.ipv4 import TSOption as Schema_TSOption
from pcapkit.protocols.schema.internet.ipv4 import UnassignedOption as Schema_UnassignedOption
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import timedelta
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address
    from typing import Any, Callable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.protocols.data.internet.ipv4 import Option as Data_Option
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.internet.ipv4 import Option as Schema_Option

    Option = OrderedMultiDict[Enum_OptionNumber, Data_Option]
    OptionParser = Callable[[Schema_Option, NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[[Enum_OptionNumber, DefaultArg(Optional[Data_Option]),
                                  KwArg(Any)], Schema_Option]

__all__ = ['IPv4']


class IPv4(IP[Data_IPv4, Schema_IPv4],
           schema=Schema_IPv4, data=Data_IPv4):
    """This class implements Internet Protocol version 4.

    This class currently supports parsing of the following IPv4 options,
    which are directly mapped to the :class:`pcapkit.const.ipv4.option_number.OptionNumber`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
         - Option Constructor
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.EOOL`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_eool`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_eool`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.NOP`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_nop`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_nop`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.SEC`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_sec`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_sec`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.LSR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_lsr`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_lsr`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.TS`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_ts`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_ts`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.E_SEC`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_e_sec`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_e_sec`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.RR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_rr`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_rr`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.SID`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_sid`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_sid`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.SSR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_ssr`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_ssr`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.MTUP`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_mtup`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_mtup`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.MTUR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_mtur`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_mtur`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.TR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_tr`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_tr`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.RTRALT`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_rtralt`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_rtralt`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.QS`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_qs`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_qs`

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Protocol version 4"]':
        """Name of corresponding protocol."""
        return 'Internet Protocol version 4'

    @property
    def length(self) -> 'int':
        """Header length of corresponding protocol."""
        return self._info.hdr_len

    @property
    def protocol(self) -> 'Enum_TransType':
        """Name of next layer protocol."""
        return self._info.protocol

    # source IP address
    @property
    def src(self) -> 'IPv4Address':
        """Source IP address."""
        return self._info.src

    # destination IP address
    @property
    def dst(self) -> 'IPv4Address':
        """Destination IP address."""
        return self._info.dst

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_IPv4':  # pylint: disable=unused-argument
        """Read Internet Protocol version 4 (IPv4).

        Structure of IPv4 header [:rfc:`791`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |Version|  IHL  |Type of Service|          Total Length         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Identification        |Flags|      Fragment Offset    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Time to Live |    Protocol   |         Header Checksum       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Source Address                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    Destination Address                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    Options                    |    Padding    |
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

        if schema.vihl['version'] != 4:
            raise ProtocolError(f"[IPv4] invalid version: {schema.vihl['version']}")

        ipv4 = Data_IPv4(
            version=schema.vihl['version'],  # type: ignore[arg-type]
            hdr_len=schema.vihl['ihl'] * 4,
            tos=Data_ToSField.from_dict({
                'pre': Enum_ToSPrecedence.get(schema.tos['pre']),
                'del': Enum_ToSDelay.get(schema.tos['del']),
                'thr': Enum_ToSThroughput.get(schema.tos['thr']),
                'rel': Enum_ToSReliability.get(schema.tos['rel']),
                'ecn': Enum_ToSECN.get(schema.tos['ecn']),
            }),
            len=schema.length,
            id=schema.id,
            flags=Data_Flags(
                df=bool(schema.flags['df']),
                mf=bool(schema.flags['mf']),
            ),
            offset=int(schema.flags['offset']) * 8,
            ttl=datetime.timedelta(seconds=schema.ttl),
            protocol=schema.proto,
            checksum=schema.chksum,
            src=schema.src,
            dst=schema.dst,
        )

        _optl = ipv4.hdr_len - 20
        if _optl:
            ipv4.__update__([
                ('options', self._read_ipv4_options(_optl)),
            ])

        return self._decode_next_layer(ipv4, ipv4.protocol, ipv4.len - ipv4.hdr_len)

    def make(self,
             tos_pre: 'Enum_ToSPrecedence | StdlibEnum | AenumEnum | int | str' = Enum_ToSPrecedence.Routine,
             tos_pre_default: 'Optional[int]' = None,
             tos_pre_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             tos_pre_reversed: 'bool' = False,
             tos_del: 'Enum_ToSDelay | StdlibEnum | AenumEnum | int | str' = Enum_ToSDelay.NORMAL,
             tos_del_default: 'Optional[int]' = None,
             tos_del_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             tos_del_reversed: 'bool' = False,
             tos_thr: 'Enum_ToSThroughput | StdlibEnum | AenumEnum | int | str' = Enum_ToSThroughput.NORMAL,
             tos_thr_default: 'Optional[int]' = None,
             tos_thr_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             tos_thr_reversed: 'bool' = False,
             tos_rel: 'Enum_ToSReliability | StdlibEnum | AenumEnum | int | str' = Enum_ToSReliability.NORMAL,
             tos_rel_default: 'Optional[int]' = None,
             tos_rel_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             tos_rel_reversed: 'bool' = False,
             tos_ecn: 'Enum_ToSECN | StdlibEnum | AenumEnum | int | str' = Enum_ToSECN.Not_ECT,
             tos_ecn_default: 'Optional[int]' = None,
             tos_ecn_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             tos_ecn_reversed: 'bool' = False,
             id: 'int' = 0,
             df: 'bool' = False,
             mf: 'bool' = False,
             offset: 'int' = 0,
             ttl: 'timedelta | int' = 0,
             protocol: 'Enum_TransType | StdlibEnum | AenumEnum | int | str' = Enum_TransType.UDP,
             protocol_default: 'Optional[int]' = None,
             protocol_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             protocol_reversed: 'bool' = False,
             checksum: 'bytes' = b'\x00\x00',
             src: 'IPv4Address | str | int | bytes' = '127.0.0.1',
             dst: 'IPv4Address | str | int | bytes' = '0.0.0.0',  # nosec: B104
             options: 'Optional[list[Schema_Option | tuple[Enum_OptionNumber, dict[str, Any]] | bytes] | Option]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_IPv4':
        """Make (construct) packet data.

        Args:
            tos_pre: Precedence of the packet.
            tos_pre_default: Default value of ``tos_pre``.
            tos_pre_namespace: Namespace of ``tos_pre``.
            tos_pre_reversed: If the namespace of ``tos_pre`` is reversed.
            tos_del: Delay of the packet.
            tos_del_default: Default value of ``tos_del``.
            tos_del_namespace: Namespace of ``tos_del``.
            tos_del_reversed: If the namespace of ``tos_del`` is reversed.
            tos_thr: Throughput of the packet.
            tos_thr_default: Default value of ``tos_thr``.
            tos_thr_namespace: Namespace of ``tos_thr``.
            tos_thr_reversed: If the namespace of ``tos_thr`` is reversed.
            tos_rel: Reliability of the packet.
            tos_rel_default: Default value of ``tos_rel``.
            tos_rel_namespace: Namespace of ``tos_rel``.
            tos_rel_reversed: If the namespace of ``tos_rel`` is reversed.
            tos_ecn: ECN of the packet.
            tos_ecn_default: Default value of ``tos_ecn``.
            tos_ecn_namespace: Namespace of ``tos_ecn``.
            tos_ecn_reversed: If the namespace of ``tos_ecn`` is reversed.
            id: Identification of the packet.
            df: Don't fragment flag.
            mf: More fragments flag.
            offset: Fragment offset.
            ttl: Time to live of the packet.
            protocol: Payload protocol of the packet.
            protocol_default: Default value of ``protocol``.
            protocol_namespace: Namespace of ``protocol``.
            protocol_reversed: If the namespace of ``protocol`` is reversed.
            checksum: Checksum of the packet.
            src: Source address of the packet.
            dst: Destination address of the packet.
            options: Options of the packet.
            payload: Payload of the packet.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        tos_pre_val = self._make_index(tos_pre, tos_pre_default, namespace=tos_pre_namespace,
                                       reversed=tos_pre_reversed, pack=False)
        tos_del_val = self._make_index(tos_del, tos_del_default, namespace=tos_del_namespace,
                                       reversed=tos_del_reversed, pack=False)
        tos_thr_val = self._make_index(tos_thr, tos_thr_default, namespace=tos_thr_namespace,
                                       reversed=tos_thr_reversed, pack=False)
        tos_rel_val = self._make_index(tos_rel, tos_rel_default, namespace=tos_rel_namespace,
                                       reversed=tos_rel_reversed, pack=False)
        tos_ecn_val = self._make_index(tos_ecn, tos_ecn_default, namespace=tos_ecn_namespace,
                                       reversed=tos_ecn_reversed, pack=False)

        proto = self._make_index(protocol, protocol_default, namespace=protocol_namespace,
                                 reversed=protocol_reversed, pack=False)
        ttl_val = ttl if isinstance(ttl, int) else math.ceil(ttl.total_seconds())

        if options is not None:
            options_value, total_length = self._make_ipv4_options(options)
        else:
            options_value, total_length = [], 0

        ihl = 5 + math.ceil(total_length / 4)
        len = ihl * 4 + len(payload)

        return Schema_IPv4(
            vihl={
                'version': 4,
                'ihl': ihl,
            },
            tos={
                'pre': tos_pre_val,
                'del': tos_del_val,
                'thr': tos_thr_val,
                'rel': tos_rel_val,
                'ecn': tos_ecn_val,
            },
            length=len,
            id=id,
            flags={
                'df': df,
                'mf': mf,
                'offset': offset,
            },
            ttl=ttl_val,
            proto=proto,  # type: ignore[arg-type]
            chksum=checksum,
            src=src,
            dst=dst,
            options=options_value,
            payload=payload,
        )

    @classmethod
    def id(cls) -> 'tuple[Literal["IPv4"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('IPv4',)

    @classmethod
    def register_option(cls, code: 'Enum_OptionNumber', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register an option parser.

        Args:
            code: IPv4 option code.
            meth: Method name or callable to parse and/or construct the option.

        """
        name = code.name.lower()
        if hasattr(cls, f'_read_opt_{name}'):
            warn(f'option {code} already registered, overwriting', RegistryWarning)

        if isinstance(meth, str):
            meth = (getattr(cls, f'_read_opt_{meth}', cls._read_opt_unassigned),  # type: ignore[arg-type]
                    getattr(cls, f'_make_opt_{meth}', cls._make_opt_unassigned))  # type: ignore[arg-type]

        setattr(cls, f'_read_opt_{name}', meth[0])
        setattr(cls, f'_make_opt_{name}', meth[1])

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[20]':
        """Return an estimated length for the object."""
        return 20

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IPv4  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPv4') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'tos_pre': data.tos.pre,
            'tos_del': data.tos['del'],
            'tos_thr': data.tos.thr,
            'tos_rel': data.tos.rel,
            'tos_ecn': data.tos.ecn,
            'id': data.id,
            'df': data.flags.df,
            'mf': data.flags.mf,
            'offset': data.offset,
            'ttl': data.ttl,
            'protocol': data.protocol,
            'checksum': data.checksum,
            'src': data.src,
            'dst': data.dst,
            'options': data.options,
            'payload': cls._make_payload(data),
        }

    def _read_ipv4_addr(self) -> 'IPv4Address':
        """Read IP address.

        Returns:
            Parsed IP address.

        """
        _byte = self._read_fileng(4)
        # _addr = '.'.join([str(_) for _ in _byte])
        # return _addr
        return ipaddress.ip_address(_byte)  # type: ignore[return-value]

    def _read_ipv4_opt_type(self, code: 'int') -> 'Data_OptionType':
        """Read option type field.

        Arguments:
            code: option kind value

        Returns:
            Extracted IPv4 option type, as an object of the option flag (copied
            flag), option class, and option number.

        """
        oflg = bool(code >> 7)
        ocls = Enum_OptionClass.get((code >> 5) & 0b11)
        onum = code & 0b11111

        return Data_OptionType.from_dict({
            'change': oflg,
            'class': ocls,
            'number': onum,
        })

    def _read_ipv4_options(self, length: 'int') -> 'Option':
        """Read IPv4 option list.

        Arguments:
            length: length of options

        Returns:
            Extracted IPv4 options.

        Raises:
            ProtocolError: If the threshold is **NOT** matching.

        """
        counter = 0                   # length of read option list
        options = OrderedMultiDict()  # type: Option

        for schema in self.__header__.options:
            kind = schema.type
            name = kind.name.lower()

            meth_name = f'_read_opt_{name}'
            meth = cast('OptionParser',
                        getattr(self, meth_name, self._read_opt_unassigned))
            data = meth(schema, options=options)

            # record option data
            counter += data.length
            options.add(kind, data)

            # break when End of Option List (EOOL) triggered
            if kind == Enum_OptionNumber.EOOL:
                break

        # check threshold
        if counter > length:
            raise ProtocolError(f'IPv4: invalid format')
        return options

    def _read_opt_unassigned(self, schema: 'Schema_UnassignedOption', *, options: 'Option') -> 'Data_UnassignedOption':  # pylint: disable=unused-argument
        """Read IPv4 unassigned options.

        Structure of IPv4 unassigned options [:rfc:`791`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     type      |    length     |         option data ...
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``length`` is **LESS THAN** ``3``.

        """
        if schema.length < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_UnassignedOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            data=schema.data,
        )
        return opt

    def _read_opt_eool(self, schema: 'Schema_EOOLOption', *, options: 'Option') -> 'Data_EOOLOption':  # pylint: disable=unused-argument
        """Read IPv4 End of Option List (``EOOL``) option.

        Structure of IPv4 End of Option List (``EOOL``) option [:rfc:`719`]:

        .. code-block:: text

           +--------+
           |00000000|
           +--------+
             Type=0

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        """
        opt = Data_EOOLOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=1,
        )
        return opt

    def _read_opt_nop(self, schema: 'Schema_NOPOption', *, options: 'Option') -> 'Data_NOPOption':  # pylint: disable=unused-argument
        """Read IPv4 No Operation (``NOP``) option.

        Structure of IPv4 No Operation (``NOP``) option [:rfc:`719`]:

        .. code-block:: text

           +--------+
           |00000001|
           +--------+
             Type=1

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        """
        opt = Data_NOPOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=1,
        )
        return opt

    def _read_opt_sec(self, schema: 'Schema_SECOption', *, options: 'Option') -> 'Data_SECOption':  # pylint: disable=unused-argument
        """Read IPv4 Security (``SEC``) option.

        Structure of IPv4 Security (``SEC``) option [:rfc:`1108`]:

        .. code-block:: text

           +------------+------------+------------+-------------//----------+
           |  10000010  |  XXXXXXXX  |  SSSSSSSS  |  AAAAAAA[1]    AAAAAAA0 |
           |            |            |            |         [0]             |
           +------------+------------+------------+-------------//----------+
             TYPE = 130     LENGTH   CLASSIFICATION         PROTECTION
                                          LEVEL              AUTHORITY
                                                               FLAGS

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``length`` is **LESS THAN** ``3``.

        """
        if schema.length < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        if schema.length > 3:
            flags = []  # type: list[Enum_ProtectionAuthority]
            for base, byte in enumerate(schema.data):
                for bit in range(7):
                    authority = Enum_ProtectionAuthority.get(base * 8 + bit)
                    if byte & (0x80 >> bit):
                        if 'Unassigned' in authority.name:
                            warn(f'{self.alias}: [OptNo {schema.type}] invalid format: unknown protection authority: {authority}', ProtocolWarning)
                        flags.append(authority)

                if byte & 0x01 == 1 and base < schema.length - 4:
                    #raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format: remaining data')
                    warn(f'{self.alias}: [OptNo {schema.type}] invalid format: remaining data', ProtocolWarning)

            if schema.data[-1] & 0x01 == 0:
                warn(f'{self.alias}: [OptNo {schema.type}] invalid format: field termination indicator not set', ProtocolWarning)
        else:
            flags = []

        opt = Data_SECOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            level=schema.level,
            flags=tuple(flags),
        )

        return opt

    def _read_opt_lsr(self, schema: 'Schema_LSROption', *, options: 'Option') -> 'Data_LSROption':  # pylint: disable=unused-argument
        """Read IPv4 Loose Source Route (``LSR``) option.

        Structure of IPv4 Loose Source Route (``LSR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |10000011| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If option is malformed.

        """
        if schema.length < 3 or (schema.length - 3) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')
        if schema.pointer < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format: pointer too small: {schema.pointer}')

        opt = Data_LSROption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            pointer=schema.pointer,
            route=tuple(schema.route),
        )
        return opt

    def _read_opt_ts(self, schema: 'Schema_TSOption', *, options: 'Option') -> 'Data_TSOption':  # pylint: disable=unused-argument
        """Read IPv4 Time Stamp (``TS``) option.

        Structure of IPv4 Time Stamp (``TS``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |01000100| length | pointer|oflw|flg|
           +--------+--------+--------+--------+
           |         internet address          |
           +--------+--------+--------+--------+
           |             timestamp             |
           +--------+--------+--------+--------+
           |                 .                 |
                             .
                             .

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        if schema.length > 40 or schema.length < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')
        if schema.pointer < 5:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format: pointer too small: {schema.pointer}')

        opt = Data_TSOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            pointer=schema.pointer,
            overflow=schema.flags['oflw'],
            flag=schema.ts_flag,
            timestamp=schema.timestamp,
        )
        return opt

    def _read_opt_e_sec(self, schema: 'Schema_ESECOption', *, options: 'Option') -> 'Data_ESECOption':  # pylint: disable=unused-argument
        """Read IPv4 Extended Security (``E-SEC``) option.

        Structure of IPv4 Extended Security (``E-SEC``) option [:rfc:`1108`]:

        .. code-block:: text

           +------------+------------+------------+-------//-------+
           |  10000101  |  000LLLLL  |  AAAAAAAA  |  add sec info  |
           +------------+------------+------------+-------//-------+
            TYPE = 133      LENGTH     ADDITIONAL      ADDITIONAL
                                      SECURITY INFO     SECURITY
                                       FORMAT CODE        INFO

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``length`` is **LESS THAN** ``3``.

        """
        if schema.length < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_ESECOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            format=schema.format,
            info=schema.info,
        )
        return opt

    def _read_opt_rr(self, schema: 'Schema_RROption', *, options: 'Option') -> 'Data_RROption':  # pylint: disable=unused-argument
        """Read IPv4 Record Route (``RR``) option.

        Structure of IPv4 Record Route (``RR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |00000111| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+
             Type=7

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If option is malformed.

        """
        if schema.length < 3 or (schema.length - 3) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')
        if schema.pointer < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format: pointer too small: {schema.pointer}')

        opt = Data_RROption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            pointer=schema.pointer,
            route=tuple(schema.route),
        )
        return opt

    def _read_opt_sid(self, schema: 'Schema_SIDOption', *, options: 'Option') -> 'Data_SIDOption':  # pylint: disable=unused-argument
        """Read IPv4 Stream ID (``SID``) option.

        Structure of IPv4 Stream ID (``SID``) option [:rfc:`791`][:rfc:`6814`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |10001000|00000010|    Stream ID    |
           +--------+--------+--------+--------+
            Type=136 Length=4

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_SIDOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            sid=schema.sid,
        )
        return opt

    def _read_opt_ssr(self, schema: 'Schema_SSROption', *, options: 'Option') -> 'Data_SSROption':  # pylint: disable=unused-argument
        """Read IPv4 Strict Source Route (``SSR``) option.

        Structure of IPv4 Strict Source Route (``SSR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |10001001| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+
            Type=137

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If option is malformed.

        """
        if schema.length < 3 or (schema.length - 3) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')
        if schema.pointer < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format: pointer too small: {schema.pointer}')

        opt = Data_SSROption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            pointer=schema.pointer,
            route=tuple(schema.route),
        )
        return opt

    def _read_opt_mtup(self, schema: 'Schema_MTUPOption', *, options: 'Option') -> 'Data_MTUPOption':  # pylint: disable=unused-argument
        """Read IPv4 MTU Probe (``MTUP``) option.

        Structure of IPv4 MTU Probe (``MTUP``) option [:rfc:`1063`][:rfc:`1191`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |00001011|00000100|   2 octet value |
           +--------+--------+--------+--------+

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_MTUPOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            mtu=schema.mtu,
        )
        return opt

    def _read_opt_mtur(self, schema: 'Schema_MTUROption', *, options: 'Option') -> 'Data_MTUROption':  # pylint: disable=unused-argument
        """Read IPv4 MTU Reply (``MTUR``) option.

        Structure of IPv4 MTU Reply (``MTUR``) option [:rfc:`1063`][:rfc:`1191`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |00001100|00000100|   2 octet value |
           +--------+--------+--------+--------+

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_MTUROption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            mtu=schema.mtu,
        )
        return opt

    def _read_opt_tr(self, schema: 'Schema_TROption', *, options: 'Option') -> 'Data_TROption':  # pylint: disable=unused-argument
        """Read IPv4 Traceroute (``TR``) option.

        Structure of IPv4 Traceroute (``TR``) option [:rfc:`1393`][:rfc:`6814`]:

        .. code-block:: text

            0               8              16              24
           +-+-+-+-+-+-+-+-+---------------+---------------+---------------+
           |F| C |  Number |    Length     |          ID Number            |
           +-+-+-+-+-+-+-+-+---------------+---------------+---------------+
           |      Outbound Hop Count       |       Return Hop Count        |
           +---------------+---------------+---------------+---------------+
           |                     Originator IP Address                     |
           +---------------+---------------+---------------+---------------+

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``12``.

        """
        if schema.length != 12:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_TROption.from_dict({
            'code': schema.type,
            'type': self._read_ipv4_opt_type(schema.type),
            'length': schema.length,
            'id': schema.id,
            'outbound': schema.out,
            'return': schema.ret,
            'originator': schema.origin,
        })
        return opt

    def _read_opt_rtralt(self, schema: 'Schema_RTRALTOption', *, options: 'Option') -> 'Data_RTRALTOption':  # pylint: disable=unused-argument
        """Read IPv4 Router Alert (``RTRALT``) option.

        Structure of IPv4 Router Alert (``RTRALT``) option [:rfc:`2113`]:

        .. code:: text

           +--------+--------+--------+--------+
           |10010100|00000100|  2 octet value  |
           +--------+--------+--------+--------+

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_RTRALTOption(
            code=schema.type,
            type=self._read_ipv4_opt_type(schema.type),
            length=schema.length,
            alert=schema.alert,
        )
        return opt

    def _read_opt_qs(self, schema: 'Schema_QSOption', *, options: 'Option') -> 'Data_QSOption':  # pylint: disable=unused-argument
        """Read IPv4 Quick Start (``QS``) option.

        Structure of IPv4 Quick Start (``QS``) option [:rfc:`4782`]:

        * A Quick-Start Request

          .. code-block:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |   Option      |  Length=8     | Func. | Rate  |   QS TTL      |
             |               |               | 0000  |Request|               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                        QS Nonce                           | R |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        * Report of Approved Rate

          .. code-block:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |   Option      |  Length=8     | Func. | Rate  |   Not Used    |
             |               |               | 1000  | Report|               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                        QS Nonce                           | R |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed option schema
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        func = schema.func
        if func == Enum_QSFunction.Quick_Start_Request:
            schema_req = cast('Schema_QuickStartRequestOption', schema)

            rate = schema_req.flags['rate']
            opt = Data_QuickStartRequestOption(
                code=schema.type,
                type=self._read_ipv4_opt_type(schema.type),
                length=schema_req.length,
                func=func,
                rate=40000 * (2 ** rate) / 1000 if rate > 0 else 0,
                ttl=datetime.timedelta(seconds=schema_req.ttl),
                nonce=schema_req.nonce['nonce'],
            )  # type: Data_QSOption
        elif func == Enum_QSFunction.Report_of_Approved_Rate:
            schema_rep = cast('Schema_QuickStartReportOption', schema)

            rate = schema_rep.flags['rate']
            opt = Data_QuickStartReportOption(
                code=schema.type,
                type=self._read_ipv4_opt_type(schema.type),
                length=schema_rep.length,
                func=func,
                rate=40000 * (2 ** rate) / 1000 if rate > 0 else 0,
                nonce=schema_rep.nonce['nonce'],
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] unknown QS function: {func}')
        return opt

    def _make_ipv4_options(self, options: 'list[Schema_Option | tuple[Enum_OptionNumber, dict[str, Any]] | bytes] | Option') -> 'tuple[list[Schema_Option | bytes], int]':
        """Make options for IPv4.

        Args:
            option: IPv4 options

        Returns:
            Tuple of options and total length of options.

        """
        total_length = 0
        if isinstance(options, list):
            options_list = []  # type: list[Schema_Option | bytes]
            for schema in options:
                if isinstance(schema, bytes):
                    code = Enum_OptionNumber.get(schema[0])
                    if code in (Enum_OptionNumber.NOP, Enum_OptionNumber.EOOL):  # ignore padding options by default
                        continue

                    data = schema  # type: Schema_Option | bytes
                    data_len = len(data)
                elif isinstance(schema, Schema):
                    code = schema.type
                    if code in (Enum_OptionNumber.NOP, Enum_OptionNumber.EOOL):  # ignore padding options by default
                        continue

                    data = schema
                    data_len = len(schema.pack())
                else:
                    code, args = cast('tuple[Enum_OptionNumber, dict[str, Any]]', schema)
                    if code in (Enum_OptionNumber.NOP, Enum_OptionNumber.EOOL):  # ignore padding options by default
                        continue

                    name = f'_make_opt_{code.name.lower()}'
                    meth = cast('OptionConstructor',
                                getattr(self, name, self._make_opt_unassigned))

                    data = meth(code, **args)
                    data_len = len(data.pack())

                options_list.append(data)
                total_length += data_len

                # force alignment to 32-bit boundary
                if data_len % 4:
                    pad_len = 4 - (data_len % 4)
                    pad_opt = self._make_opt_nop(Enum_OptionNumber.NOP)  # type: ignore[arg-type]
                    total_length += pad_len

                    for _ in range(pad_len - 1):
                        options_list.append(pad_opt)
                    options_list.append(Enum_OptionNumber.EOOL)  # type: ignore[arg-type]
            return options_list, total_length

        options_list = []
        for code, option in options.items(multi=True):
            # ignore padding options by default
            if code in (Enum_OptionNumber.NOP, Enum_OptionNumber.EOOL):
                continue

            name = f'_make_opt_{code.name.lower()}'
            meth = cast('OptionConstructor',
                        getattr(self, name, self._make_opt_unassigned))

            data = meth(code, option)
            data_len = len(data.pack())

            options_list.append(data)
            total_length += data_len

            # force alignment to 32-bit boundary
            if data_len % 4:
                pad_len = 4 - (data_len % 4)
                pad_opt = self._make_opt_nop(Enum_OptionNumber.NOP)  # type: ignore[arg-type]
                total_length += pad_len

                for _ in range(pad_len - 1):
                    options_list.append(pad_opt)
                options_list.append(Enum_OptionNumber.EOOL)  # type: ignore[arg-type]
        return options_list, total_length

    def _make_opt_unassigned(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_UnassignedOption]' = None, *,
                             data: 'bytes',
                             **kwargs: 'Any') -> 'Schema_Option':
        """Make IPv4 unassigned options.

        Args:
            kind: option type code
            option: option data
            data: option payload
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            data = option.data

        return Schema_UnassignedOption(
            type=kind,
            length=len(data),
            data=data,
        )

    def _make_opt_eool(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_EOOLOption]' = None,
                       **kwargs: 'Any') -> 'Schema_EOOLOption':
        """Make IPv4 End of Option List (``EOOL``) option.

        Args:
            kind: option type code
            option: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        return Schema_EOOLOption(
            type=kind,
            length=1,
        )

    def _make_opt_nop(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_NOPOption]' = None,
                      **kwargs: 'Any') -> 'Schema_NOPOption':
        """Make IPv4 No Operation (``NOP``) option.

        Args:
            kind: option type code
            option: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        return Schema_NOPOption(
            type=kind,
            length=1,
        )

    def _make_opt_sec(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_SECOption]' = None, *,
                      level: 'Enum_ClassificationLevel | StdlibEnum | AenumEnum | int | str' = Enum_ClassificationLevel.Unclassified,
                      level_default: 'Optional[int]' = None,
                      level_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                      level_reversed: 'bool' = False,
                      authorities: 'Optional[list[Enum_ProtectionAuthority]]' = None,
                      **kwargs: 'Any') -> 'Schema_SECOption':
        """Make IPv4 Security (``SEC``) option.

        Args:
            kind: option type code
            option: option data
            sec: security option
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            level_val = option.level
            authorities = cast('list[Enum_ProtectionAuthority]', option.flags)
        else:
            level_val = self._make_index(level, level_default, namespace=level_namespace,  # type: ignore[assignment]
                                         reversed=level_reversed, pack=False)
            authorities = [] if authorities is None else authorities

        if authorities:
            max_auth = max(authorities)
            int_len = math.ceil(max_auth / 8)

            data_list = [b'0' for _ in range(int_len * 8)]
            for auth in authorities:
                data_list[auth] = b'1'
            data = int(b''.join(data_list), base=2).to_bytes(int_len, 'big', signed=False)
        else:
            data = b''

        return Schema_SECOption(
            type=kind,
            length=3 + len(data),
            level=level_val,
            data=data,
        )

    def _make_opt_lsr(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_LSROption]' = None, *,
                      counts: 'int' = 10,  # reasonable default
                      route: 'Optional[list[IPv4Address | str | bytes | int]]' = None,
                      **kwargs: 'Any') -> 'Schema_LSROption':
        """Make IPv4 Loose Source and Record Route (``LSR``) option.

        Args:
            kind: option type code
            option: option data
            counts: maximum number of addresses to record
            route: list of IPv4 addresses as recorded routes
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            route = cast('list[IPv4Address | str | bytes | int]', option.route)
            pointer = option.pointer
            length = option.length
        else:
            route = [] if route is None else route
            length = 3 + counts * 4
            pointer = 4 + min(len(route), counts) * 4

        return Schema_LSROption(
            type=kind,
            length=length,
            pointer=pointer,
            route=route,
        )

    def _make_opt_ts(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_TSOption]' = None, *,
                     counts: 'int' = 5,
                     overflow: 'int' = 0,
                     timestamp: 'Optional[list[int | timedelta] | dict[IPv4Address, int | timedelta]]' = None,
                     **kwargs: 'Any') -> 'Schema_TSOption':
        """Make IPv4 Timestamp (``TS``) option.

        Args:
            kind: option type code
            option: option data
            counts: maximum number of timestamps to record
            timestamp: list of timestamps
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            ts_list = []  # type: list[int]
            if isinstance(option.timestamp, tuple):
                for ts in option.timestamp:
                    if not isinstance(ts, int):
                        ts = math.floor(ts.total_seconds() * 1000)

                    if ts.bit_length() > 31:
                        warn(f'{self.alias}: [OptNo {kind}] timestamp value is too large: {ts}', ProtocolWarning)
                        ts = ts | 0x80000000
                    ts_list.append(ts)
            else:
                for ip, ts in option.timestamp.items(True):
                    ts_list.append(int(ip))
                    if not isinstance(ts, int):
                        ts = math.floor(ts.total_seconds() * 1000)

                    if ts.bit_length() > 31:
                        warn(f'{self.alias}: [OptNo {kind}] timestamp value is too large: {ts}', ProtocolWarning)
                        ts = ts | 0x80000000
                    ts_list.append(ts)

            length = option.length
            pointer = option.pointer
            overflow = option.overflow
            flag = option.flag
        else:
            ts_list = []
            if isinstance(timestamp, list):
                flag = Enum_TSFlag.Timestamp_Only  # type: ignore[assignment]
                counts = min(9, counts)  # 9 is the maximum number of timestamps
                length = 4 + counts * 4

                for index, ts in enumerate(timestamp):
                    if index >= counts:
                        warn(f'{self.alias}: [OptNo {kind}] too many timestamps: {len(timestamp)}', ProtocolWarning)
                        break

                    if not isinstance(ts, int):
                        ts = math.floor(ts.total_seconds() * 1000)

                    if ts.bit_length() > 31:
                        warn(f'{self.alias}: [OptNo {kind}] timestamp value is too large: {ts}', ProtocolWarning)
                        ts = ts | 0x80000000
                    ts_list.append(ts)
            elif isinstance(timestamp, dict):
                flag = Enum_TSFlag.IP_with_Timestamp  # type: ignore[assignment]
                counts = min(4, counts)  # 4 is the maximum number of timestamps
                length = 4 + counts * 8

                for index, (ip, ts) in enumerate(timestamp.items()):
                    if index >= counts:
                        warn(f'{self.alias}: [OptNo {kind}] too many timestamps: {len(timestamp)}', ProtocolWarning)
                        break

                    ts_list.append(int(ip))
                    if not isinstance(ts, int):
                        ts = math.floor(ts.total_seconds() * 1000)
                    if ts == 0:
                        flag = Enum_TSFlag.Prespecified_IP_with_Timestamp  # type: ignore[assignment]

                    if ts.bit_length() > 31:
                        warn(f'{self.alias}: [OptNo {kind}] timestamp value is too large: {ts}', ProtocolWarning)
                        ts = ts | 0x80000000
                    ts_list.append(ts)
            else:
                raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid timestamp value: {timestamp}')
            pointer = 5 + len(ts_list) * 4

        return Schema_TSOption(
            type=kind,
            length=length,
            pointer=pointer,
            flags={
                'oflw': overflow,
                'flag': flag,
            },
            data=ts_list,
        )

    def _make_opt_e_sec(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_ESECOption]' = None, *,
                       format: 'int' = 0,
                       info: 'Optional[bytes]' = None,
                       **kwargs: 'Any') -> 'Schema_ESECOption':
        """Make IPv4 Extended Security (``E-SEC``) option.

        Args:
            kind: option type code
            option: option data
            format: additional security information format code
            info: additional security information
            **kwargs: arbitrary keyword arguments

            Returns:
                Constructured option schema.

        """
        if option is not None:
            length = option.length
            format = option.format
            info = option.info
        else:
            length = (3 + len(info)) if info is not None else 3

        return Schema_ESECOption(
            type=kind,
            length=length,
            format=format,
            info=info,
        )

    def _make_opt_rr(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_RROption]' = None, *,
                     counts: 'int' = 10,  # reasonable default
                     route: 'Optional[list[IPv4Address | str | bytes | int]]' = None,
                     **kwargs: 'Any') -> 'Schema_RROption':
        """Make IPv4 Record Route (``RR``) option.

        Args:
            kind: option type code
            option: option data
            counts: maximum number of addresses to record
            route: list of IPv4 addresses as recorded routes
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            route = cast('list[IPv4Address | str | bytes | int]', option.route)
            pointer = option.pointer
            length = option.length
        else:
            route = [] if route is None else route
            length = 3 + counts * 4
            pointer = 4 + min(len(route), counts) * 4

        return Schema_RROption(
            type=kind,
            length=length,
            pointer=pointer,
            route=route,
        )

    def _make_opt_sid(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_SIDOption]' = None, *,
                      sid: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_SIDOption':
        """Make IPv4 Stream ID (``SID``) option.

        Args:
            kind: option type code
            option: option data
            sid: stream ID
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            sid = option.sid

        return Schema_SIDOption(
            type=kind,
            length=4,
            sid=sid,
        )

    def _make_opt_ssr(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_SSROption]' = None, *,
                      counts: 'int' = 10,  # reasonable default
                      route: 'Optional[list[IPv4Address | str | bytes | int]]' = None,
                      **kwargs: 'Any') -> 'Schema_SSROption':
        """Make IPv4 Strict Source Route (``SSR``) option.

        Args:
            kind: option type code
            option: option data
            counts: maximum number of addresses to record
            route: list of IPv4 addresses as recorded routes
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            route = cast('list[IPv4Address | str | bytes | int]', option.route)
            pointer = option.pointer
            length = option.length
        else:
            route = [] if route is None else route
            length = 3 + counts * 4
            pointer = 4 + min(len(route), counts) * 4

        return Schema_SSROption(
            type=kind,
            length=length,
            pointer=pointer,
            route=route,
        )

    def _make_opt_mtup(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_MTUPOption]' = None, *,
                       mtu: 'int' = 0,
                       **kwargs: 'Any') -> 'Schema_MTUPOption':
        """Make IPv4 MTU Probe (``MTUP``) option.

        Args:
            kind: option type code
            option: option data
            mtu: MTU value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            mtu = option.mtu

        return Schema_MTUPOption(
            type=kind,
            length=4,
            mtu=mtu,
        )

    def _make_opt_mtur(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_MTUROption]' = None, *,
                       mtu: 'int' = 0,
                       **kwargs: 'Any') -> 'Schema_MTUROption':
        """Make IPv4 MTU Reply (``MTUR``) option.

        Args:
            kind: option type code
            option: option data
            mtu: MTU value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            mtu = option.mtu

        return Schema_MTUROption(
            type=kind,
            length=4,
            mtu=mtu,
        )

    def _make_opt_tr(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_TROption]' = None, *,
                     id: 'int' = 0,
                     out: 'int' = 0,
                     ret: 'int' = 0,
                     origin: 'IPv4Address | str | bytes | int' = '127.0.0.1',
                     **kwargs: 'Any') -> 'Schema_TROption':
        """Make IPv4 Traceroute (``TR``) option.

        Args:
            kind: option type code
            option: option data
            id: ID number
            out: outbound hop count
            ret: return hop count
            origin: originator IP address
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            id = option.id
            out = option.outbound
            ret = option['return']
            origin = option.originator

        return Schema_TROption(
            type=kind,
            length=12,
            id=id,
            out=out,
            ret=ret,
            origin=origin,
        )

    def _make_opt_rtralt(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_RTRALTOption]' = None, *,
                         alert: 'Enum_RouterAlert | StdlibEnum | AenumEnum | int | str' = Enum_RouterAlert.Aggregated_Reservation_Nesting_Level_0,
                         alert_default: 'Optional[int]' = None,
                         alert_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                         alert_reversed: 'bool' = False,
                         **kwargs: 'Any') -> 'Schema_RTRALTOption':
        """Make IPv4 Router Alert (``RTRALT``) option.

        Args:
            kind: option type code
            option: option data
            alert: router alert type
            alert_default: default value for router alert type
            alert_namespace: namespace for router alert type
            alert_reversed: whether router alert type is reversed
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            alert_val = option.alert
        else:
            alert_val = self._make_index(alert, alert_default, namespace=alert_namespace,  # type: ignore[assignment]
                                         reversed=alert_reversed, pack=False)

        return Schema_RTRALTOption(
            type=kind,
            length=4,
            alert=alert_val,
        )

    def _make_opt_qs(self, kind: 'Enum_OptionNumber', option: 'Optional[Data_QuickStartRequestOption | Data_QuickStartReportOption]' = None, *,
                     func: 'Enum_QSFunction | StdlibEnum | AenumEnum | str | int' = Enum_QSFunction.Quick_Start_Request,
                     func_default: 'Optional[int]' = None,
                     func_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,   # pylint: disable=line-too-long
                     func_reversed: 'bool' = False,
                     rate: 'int' = 0,
                     ttl: 'timedelta | int' = 0,
                     nonce: 'int' = 0,
                     **kwargs: 'Any') -> 'Schema_QSOption':
        """Make IPv4 Quick-Start (``QS``) option.

        Args:
            code: option type value
            opt: option data
            func: QS function type
            func_default: default value for QS function type
            func_namespace: namespace for QS function type
            func_reversed: reversed flag for QS function type
            rate: rate (in kbps)
            ttl: time to live (in seconds)
            nonce: nonce value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if option is not None:
            func_enum = option.func
            rate = option.rate
            ttl = getattr(option, 'ttl', 0)
            nonce = option.nonce
        else:
            func_enum = self._make_index(func, func_default, namespace=func_namespace,  # type: ignore[assignment]
                                         reversed=func_reversed, pack=False)
        rate_val = math.floor(math.log2(rate * 1000 / 40000)) if rate > 0 else 0

        if func_enum == Enum_QSFunction.Quick_Start_Request:
            ttl_value = ttl if isinstance(ttl, int) else math.floor(ttl.total_seconds())

            return Schema_QuickStartRequestOption(
                type=kind,
                length=8,
                flags={
                    'func': func_enum,
                    'rate': rate_val,
                },
                ttl=ttl_value,
                nonce={
                    'nonce': nonce,
                },
            )
        if func_enum == Enum_QSFunction.Report_of_Approved_Rate:
            return Schema_QuickStartReportOption(
                type=kind,
                length=8,
                flags={
                    'func': func_enum,
                    'rate': rate_val,
                },
                nonce={
                    'nonce': nonce,
                },
            )
        raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid QS function: {func_enum}')
