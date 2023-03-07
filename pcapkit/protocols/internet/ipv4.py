# -*- coding: utf-8 -*-
"""IPv4 - Internet Protocol version 4
========================================

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
from typing import TYPE_CHECKING, cast
import math
import struct

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
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.protocols.schema.internet.ipv4 import EOOLOption as Schema_EOOLOption
from pcapkit.protocols.schema.internet.ipv4 import ESECOption as Schema_ESECOption
from pcapkit.protocols.schema.internet.ipv4 import Flags as Schema_Flags
from pcapkit.protocols.schema.internet.ipv4 import IPv4 as Schema_IPv4
from pcapkit.protocols.schema.internet.ipv4 import LSROption as Schema_LSROption
from pcapkit.protocols.schema.internet.ipv4 import MTUPOption as Schema_MTUPOption
from pcapkit.protocols.schema.internet.ipv4 import MTUROption as Schema_MTUROption
from pcapkit.protocols.schema.internet.ipv4 import NOPOption as Schema_NOPOption
from pcapkit.protocols.schema.internet.ipv4 import OptionType as Schema_OptionType
from pcapkit.protocols.schema.internet.ipv4 import QSOption as Schema_QSOption
from pcapkit.protocols.schema.internet.ipv4 import RROption as Schema_RROption
from pcapkit.protocols.schema.internet.ipv4 import RTRALTOption as Schema_RTRALTOption
from pcapkit.protocols.schema.internet.ipv4 import SECOption as Schema_SECOption
from pcapkit.protocols.schema.internet.ipv4 import SIDOption as Schema_SIDOption
from pcapkit.protocols.schema.internet.ipv4 import SSROption as Schema_SSROption
from pcapkit.protocols.schema.internet.ipv4 import ToSField as Schema_ToSField
from pcapkit.protocols.schema.internet.ipv4 import TROption as Schema_TROption
from pcapkit.protocols.schema.internet.ipv4 import TSOption as Schema_TSOption
from pcapkit.protocols.schema.internet.ipv4 import UnassignedOption as Schema_UnassignedOption
from pcapkit.protocols.schema.schema import Schema

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from ipaddress import IPv4Address
    from typing import Any, Callable, Type, Optional

    from enum import IntEnum as StdlibEnum
    from aenum import IntEnum as AenumEnum

    from mypy_extensions import NamedArg, DefaultArg, KwArg
    from typing_extensions import Literal

    from pcapkit.protocols.data.internet.ipv4 import Option as Data_Option
    from datetime import timedelta
    from pcapkit.protocols.schema.internet.ipv4 import Option as Schema_Option
    from pcapkit.protocols.protocol import Protocol

    Option = OrderedMultiDict[Enum_OptionNumber, Data_Option]
    OptionParser = Callable[['IPv4', Enum_OptionNumber, NamedArg(bytes, 'data'), NamedArg(int, 'length'),
                             NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[['IPv4', Enum_OptionNumber, DefaultArg(Optional[Data_Option]),
                                  KwArg(Any)], Schema_Option]

__all__ = ['IPv4']


class IPv4(IP[Data_IPv4, Schema_IPv4]):
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
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.ESEC`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_esec`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_esec`
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
             src: 'IPv4Address | str | int | bytes' = '0.0.0.0',  # nosec: B104
             dst: 'IPv4Address | str | int | bytes' = '255.255.255.255',
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
        tos_pre_val = self._make_index(tos_pre, tos_pre_default, namespace=tos_pre_namespace,  # type: ignore[call-overload]
                                       reversed=tos_pre_reversed, pack=False)
        tos_del_val = self._make_index(tos_del, tos_del_default, namespace=tos_del_namespace,  # type: ignore[call-overload]
                                       reversed=tos_del_reversed, pack=False)
        tos_thr_val = self._make_index(tos_thr, tos_thr_default, namespace=tos_thr_namespace,  # type: ignore[call-overload]
                                       reversed=tos_thr_reversed, pack=False)
        tos_rel_val = self._make_index(tos_rel, tos_rel_default, namespace=tos_rel_namespace,  # type: ignore[call-overload]
                                       reversed=tos_rel_reversed, pack=False)
        tos_ecn_val = self._make_index(tos_ecn, tos_ecn_default, namespace=tos_ecn_namespace,  # type: ignore[call-overload]
                                       reversed=tos_ecn_reversed, pack=False)

        proto = self._make_index(protocol, protocol_default, namespace=protocol_namespace,  # type: ignore[call-overload]
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
            proto=proto,
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
        payload = cast('bytes', self.__header__.options)
        self.__header__.options = []

        counter = 0                   # length of read option list
        options = OrderedMultiDict()  # type: Option

        while counter < length:
            # break when eol triggerred
            cbuf = payload[counter:counter + 1]
            if not cbuf:
                break

            # get option type
            code = int(cbuf, base=2)
            kind = Enum_OptionNumber.get(code)

            # get option length
            if code in (Enum_OptionNumber.NOP, Enum_OptionNumber.EOOL):
                clen = 1
            else:
                cbuf = payload[counter + 1:counter + 2]
                clen = struct.unpack('!B', cbuf)[0]

            # extract option data
            meth_name = f'_read_opt_{kind.name.lower()}'
            meth = cast('OptionParser',
                        getattr(self, meth_name, self._read_opt_unassigned))
            data = meth(self, kind, data=payload[counter:counter + clen],
                        length=clen, options=options)

            # record option data
            counter += data.length
            options.add(kind, data)

            # break when End of Option List (EOOL) triggered
            if kind == Enum_OptionNumber.EOOL:
                break

        # get padding
        if counter < length:
            self._read_fileng(length - counter)

        return options

    def _read_opt_unassigned(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                             length: 'int', options: 'Option') -> 'Data_UnassignedOption':  # pylint: disable=unused-argument
        """Read IPv4 unassigned options.

        Structure of IPv4 unassigned options [:rfc:`791`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     type      |    length     |         option data ...
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **LESS THAN** ``3``.

        """
        if length < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        schema = Schema_UnassignedOption.unpack(data, length)  # type: Schema_UnassignedOption
        self.__header__.options.append(schema)

        opt = Data_UnassignedOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=schema.length,
            data=schema.data,
        )
        return opt

    def _read_opt_eool(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                       length: 'int', options: 'Option') -> 'Data_EOOLOption':  # pylint: disable=unused-argument
        """Read IPv4 End of Option List (``EOOL``) option.

        Structure of IPv4 End of Option List (``EOOL``) option [:rfc:`719`]:

        .. code-block:: text

           +--------+
           |00000000|
           +--------+
             Type=0

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        """
        schema = Schema_EOOLOption.unpack(data, length)  # type: Schema_EOOLOption
        self.__header__.options.append(schema)

        opt = Data_EOOLOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=1,
        )
        return opt

    def _read_opt_nop(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                      length: 'int', options: 'Option') -> 'Data_NOPOption':  # pylint: disable=unused-argument
        """Read IPv4 No Operation (``NOP``) option.

        Structure of IPv4 No Operation (``NOP``) option [:rfc:`719`]:

        .. code-block:: text

           +--------+
           |00000001|
           +--------+
             Type=1

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        """
        schema = Schema_NOPOption.unpack(data, length)  # type: Schema_NOPOption
        self.__header__.options.append(schema)

        opt = Data_NOPOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=1,
        )
        return opt

    def _read_opt_sec(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                      length: 'int', options: 'Option') -> 'Data_SECOption':  # pylint: disable=unused-argument
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
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **LESS THAN** ``3``.

        """
        size = self._read_unpack(1)
        if size < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _clvl = self._read_unpack(1)

        if size > 3:
            _data = OrderedMultiDict()  # type: OrderedMultiDict[Enum_ProtectionAuthority, bool]
            for counter in range(3, size):
                _flag = self._read_binary(1)
                if (counter < size - 1 and int(_flag[7], base=2) != 1) \
                        or (counter == size - 1 and int(_flag[7], base=2) != 0):
                    raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

                for (index, bit) in enumerate(_flag):
                    _auth = Enum_ProtectionAuthority.get(index)
                    _data.add(_auth, bool(int(bit, base=2)))
        else:
            _data = None  # type: ignore[assignment]

        opt = Data_SECOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            level=Enum_ClassificationLevel.get(_clvl),
            flags=_data,
        )

        return opt

    def _read_opt_lsr(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                      length: 'int', options: 'Option') -> 'Data_LSROption':  # pylint: disable=unused-argument
        """Read IPv4 Loose Source Route (``LSR``) option.

        Structure of IPv4 Loose Source Route (``LSR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |10000011| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If option is malformed.

        """
        size = self._read_unpack(1)
        if size < 3 or (size - 3) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _rptr = self._read_unpack(1)
        if _rptr < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        counter = 4
        address = []  # type: list[IPv4Address]
        endpoint = min(_rptr, size)
        while counter < endpoint:
            counter += 4
            address.append(self._read_ipv4_addr())

        opt = Data_LSROption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            pointer=_rptr,
            route=tuple(address) or None,
        )

        return opt

    def _read_opt_ts(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                     length: 'int', options: 'Option') -> 'Data_TSOption':  # pylint: disable=unused-argument
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
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        size = self._read_unpack(1)
        if size > 40 or size < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _tptr = self._read_unpack(1)
        _oflg = self._read_binary(1)
        _oflw = int(_oflg[:4], base=2)
        _tflg = int(_oflg[4:], base=2)

        if _tptr < 5:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _flag = Enum_TSFlag.get(_tflg)

        endpoint = min(_tptr, size)
        if _flag == Enum_TSFlag.Timestamp_Only:
            if (size - 4) % 4 != 0:
                raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')
            counter = 5

            _tsls = []  # type: list[dt_type]
            while counter < endpoint:
                counter += 4
                time = self._read_unpack(4, lilendian=True)
                _tsls.append(datetime.datetime.fromtimestamp(time))
            timestamp = tuple(_tsls) or None
        elif _flag in (Enum_TSFlag.IP_with_Timestamp, Enum_TSFlag.Prespecified_IP_with_Timestamp):
            if (size - 4) % 8 != 0:
                raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

            counter = 5
            _tsdt = OrderedMultiDict()  # type: OrderedMultiDict[IPv4Address, dt_type]
            while counter < endpoint:
                counter += 8
                ip = self._read_ipv4_addr()
                time = self._read_unpack(4, lilendian=True)
                _tsdt.add(ip, datetime.datetime.fromtimestamp(time))
            timestamp = _tsdt or None  # type: ignore[assignment]
        else:
            timestamp = self._read_fileng(size - 4) or None  # type: ignore[assignment]

        opt = Data_TSOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            pointer=_tptr,
            overflow=_oflw,
            flag=_flag,
            timestamp=timestamp,
        )

        return opt

    def _read_opt_esec(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                       length: 'int', options: 'Option') -> 'Data_ESECOption':  # pylint: disable=unused-argument
        """Read IPv4 Extended Security (``ESEC``) option.

        Structure of IPv4 Extended Security (``ESEC``) option [:rfc:`1108`]:

        .. code-block:: text

           +------------+------------+------------+-------//-------+
           |  10000101  |  000LLLLL  |  AAAAAAAA  |  add sec info  |
           +------------+------------+------------+-------//-------+
            TYPE = 133      LENGTH     ADDITIONAL      ADDITIONAL
                                      SECURITY INFO     SECURITY
                                       FORMAT CODE        INFO

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **LESS THAN** ``3``.

        """
        size = self._read_unpack(1)
        if size < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _clvl = self._read_unpack(1)

        if size > 3:
            _data = OrderedMultiDict()  # type: OrderedMultiDict[Enum_ProtectionAuthority, bool]
            for counter in range(3, size):
                _flag = self._read_binary(1)
                if (counter < size - 1 and int(_flag[7], base=2) != 1) \
                        or (counter == size - 1 and int(_flag[7], base=2) != 0):
                    raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

                for (index, bit) in enumerate(_flag):
                    _auth = Enum_ProtectionAuthority.get(index)
                    _data.add(_auth, bool(int(bit, base=2)))
        else:
            _data = None  # type: ignore[assignment]

        opt = Data_ESECOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            level=Enum_ClassificationLevel.get(_clvl),
            flags=_data,
        )

        return opt

    def _read_opt_rr(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                     length: 'int', options: 'Option') -> 'Data_RROption':  # pylint: disable=unused-argument
        """Read IPv4 Record Route (``RR``) option.

        Structure of IPv4 Record Route (``RR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |00000111| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+
             Type=7

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If option is malformed.

        """
        size = self._read_unpack(1)
        if size < 3 or (size - 3) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _rptr = self._read_unpack(1)
        if _rptr < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        counter = 4
        address = []  # type: list[IPv4Address]
        endpoint = min(_rptr, size)
        while counter < endpoint:
            counter += 4
            address.append(self._read_ipv4_addr())

        opt = Data_RROption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            pointer=_rptr,
            route=tuple(address) or None,
        )

        return opt

    def _read_opt_sid(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                      length: 'int', options: 'Option') -> 'Data_SIDOption':  # pylint: disable=unused-argument
        """Read IPv4 Stream ID (``SID``) option.

        Structure of IPv4 Stream ID (``SID``) option [:rfc:`791`][:rfc:`6814`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |10001000|00000010|    Stream ID    |
           +--------+--------+--------+--------+
            Type=136 Length=4

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **NOT** ``4``.

        """
        size = self._read_unpack(1)
        if size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        opt = Data_SIDOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            sid=self._read_unpack(size),
        )

        return opt

    def _read_opt_ssr(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                      length: 'int', options: 'Option') -> 'Data_SSROption':  # pylint: disable=unused-argument
        """Read IPv4 Strict Source Route (``SSR``) option.

        Structure of IPv4 Strict Source Route (``SSR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |10001001| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+
            Type=137

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If option is malformed.

        """
        size = self._read_unpack(1)
        if size < 3 or (size - 3) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _rptr = self._read_unpack(1)
        if _rptr < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        counter = 4
        address = []  # type: list[IPv4Address]
        endpoint = min(_rptr, size)
        while counter < endpoint:
            counter += 4
            address.append(self._read_ipv4_addr())

        opt = Data_SSROption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            pointer=_rptr,
            route=tuple(address) or None,
        )

        return opt

    def _read_opt_mtup(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                       length: 'int', options: 'Option') -> 'Data_MTUPOption':  # pylint: disable=unused-argument
        """Read IPv4 MTU Probe (``MTUP``) option.

        Structure of IPv4 MTU Probe (``MTUP``) option [:rfc:`1063`][:rfc:`1191`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |00001011|00000100|   2 octet value |
           +--------+--------+--------+--------+

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **NOT** ``4``.

        """
        size = self._read_unpack(1)
        if size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        opt = Data_MTUPOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            mtu=self._read_unpack(size),
        )

        return opt

    def _read_opt_mtur(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                       length: 'int', options: 'Option') -> 'Data_MTUROption':  # pylint: disable=unused-argument
        """Read IPv4 MTU Reply (``MTUR``) option.

        Structure of IPv4 MTU Reply (``MTUR``) option [:rfc:`1063`][:rfc:`1191`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |00001100|00000100|   2 octet value |
           +--------+--------+--------+--------+

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **NOT** ``4``.

        """
        size = self._read_unpack(1)
        if size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        opt = Data_MTUROption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            mtu=self._read_unpack(size),
        )

        return opt

    def _read_opt_tr(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                     length: 'int', options: 'Option') -> 'Data_TROption':  # pylint: disable=unused-argument
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
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **NOT** ``12``.

        """
        size = self._read_unpack(1)
        if size != 12:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _idnm = self._read_unpack(2)
        _ohcn = self._read_unpack(2)
        _rhcn = self._read_unpack(2)
        _ipad = self._read_ipv4_addr()

        opt = Data_TROption.from_dict({
            'code': kind,
            'type': self._read_ipv4_opt_type(kind),
            'length': size,
            'id': _idnm,
            'outbound': _ohcn,
            'return': _rhcn,
            'originator': _ipad,
        })

        return opt

    def _read_opt_rtralt(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                         length: 'int', options: 'Option') -> 'Data_RTRALTOption':  # pylint: disable=unused-argument
        """Read IPv4 Router Alert (``RTRALT``) option.

        Structure of IPv4 Router Alert (``RTRALT``) option [:rfc:`2113`]:

        .. code:: text

           +--------+--------+--------+--------+
           |10010100|00000100|  2 octet value  |
           +--------+--------+--------+--------+

        Arguments:
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **NOT** ``4``.

        """
        size = self._read_unpack(1)
        if size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _code = self._read_unpack(2)

        opt = Data_RTRALTOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            alert=Enum_RouterAlert.get(_code),
        )

        return opt

    def _read_opt_qs(self, kind: 'Enum_OptionNumber', *, data: 'bytes',
                     length: 'int', options: 'Option') -> 'Data_QSOption':  # pylint: disable=unused-argument
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
            kind: option type code
            data: option payload
            length: option payload length
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        size = self._read_unpack(1)
        if size != 8:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _fcrr = self._read_binary(1)
        _func = int(_fcrr[:4], base=2)
        _rate = int(_fcrr[4:], base=2)
        _ttlv = self._read_unpack(1)
        _nonr = self._read_binary(4)
        _qsnn = int(_nonr[:30], base=2)

        _qsfn = Enum_QSFunction.get(_func)
        if _qsfn not in (Enum_QSFunction.Quick_Start_Request, Enum_QSFunction.Report_of_Approved_Rate):
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        opt = Data_QSOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            func=_qsfn,
            rate=40000 * (2 ** _rate) / 1000,
            ttl=None if _func != Enum_QSFunction.Quick_Start_Request else datetime.timedelta(seconds=_ttlv),
            nonce=_qsnn,
        )

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

                    data = meth(self, code, **args)
                    data_len = len(data.pack())

                options_list.append(data)
                total_length += data_len

                # force alignment to 32-bit boundary
                if data_len % 4:
                    data_len = 4 - (data_len % 4)
                    pad_opt = self._make_opt_nop(code)

                    for _ in range(data_len):
                        options_list.append(pad_opt)
                    total_length += data_len
            return options_list, total_length

        options_list = []
        for code, option in options.items(multi=True):
            # ignore padding options by default
            if code in (Enum_OptionNumber.NOP, Enum_OptionNumber.EOOL):
                continue

            name = f'_make_opt_{code.name.lower()}'
            meth = cast('OptionConstructor',
                        getattr(self, name, self._make_opt_unassigned))

            data = meth(self, code, option)
            data_len = len(data.pack())

            options_list.append(data)
            total_length += data_len

            # force alignment to 32-bit boundary
            if data_len % 4:
                pad_len = 4 - (data_len % 4)
                pad_opt = self._make_opt_nop(code)

                for _ in range(pad_len):
                    options_list.append(pad_opt)
                total_length += pad_len
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
            IPv4 option schema.

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
            IPv4 option schema.

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
            IPv4 option schema.

        """
        return Schema_NOPOption(
            type=kind,
            length=1,
        )
