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
from typing import TYPE_CHECKING

from pcapkit.const.ipv4.classification_level import \
    ClassificationLevel as RegType_ClassificationLevel
from pcapkit.const.ipv4.option_class import OptionClass as RegType_OptionClass
from pcapkit.const.ipv4.option_number import OptionNumber as RegType_OptionNumber
from pcapkit.const.ipv4.protection_authority import \
    ProtectionAuthority as RegType_ProtectionAuthority
from pcapkit.const.ipv4.qs_function import QSFunction as RegType_QSFunction
from pcapkit.const.ipv4.router_alert import RouterAlert as RegType_RouterAlert
from pcapkit.const.ipv4.tos_del import ToSDelay as RegType_ToSDelay
from pcapkit.const.ipv4.tos_ecn import ToSECN as RegType_ToSECN
from pcapkit.const.ipv4.tos_pre import ToSPrecedence as RegType_ToSPrecedence
from pcapkit.const.ipv4.tos_rel import ToSReliability as RegType_ToSReliability
from pcapkit.const.ipv4.tos_thr import ToSThroughput as RegType_ToSThroughput
from pcapkit.const.ipv4.ts_flag import TSFlag as RegType_TSFlag
from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.internet.ipv4 import EOOLOption as DataType_EOOLOption
from pcapkit.protocols.data.internet.ipv4 import ESECOption as DataType_ESECOption
from pcapkit.protocols.data.internet.ipv4 import Flags as DataType_Flags
from pcapkit.protocols.data.internet.ipv4 import IPv4 as DataType_IPv4
from pcapkit.protocols.data.internet.ipv4 import LSROption as DataType_LSROption
from pcapkit.protocols.data.internet.ipv4 import MTUPOption as DataType_MTUPOption
from pcapkit.protocols.data.internet.ipv4 import MTUROption as DataType_MTUROption
from pcapkit.protocols.data.internet.ipv4 import NOPOption as DataType_NOPOption
from pcapkit.protocols.data.internet.ipv4 import OptionType as DataType_OptionType
from pcapkit.protocols.data.internet.ipv4 import QSOption as DataType_QSOption
from pcapkit.protocols.data.internet.ipv4 import RROption as DataType_RROption
from pcapkit.protocols.data.internet.ipv4 import RTRALTOption as DataType_RTRALTOption
from pcapkit.protocols.data.internet.ipv4 import SECOption as DataType_SECOption
from pcapkit.protocols.data.internet.ipv4 import SIDOption as DataType_SIDOption
from pcapkit.protocols.data.internet.ipv4 import SSROption as DataType_SSROption
from pcapkit.protocols.data.internet.ipv4 import ToSField as DataType_ToSField
from pcapkit.protocols.data.internet.ipv4 import TROption as DataType_TROption
from pcapkit.protocols.data.internet.ipv4 import TSOption as DataType_TSOption
from pcapkit.protocols.data.internet.ipv4 import UnassignedOption as DataType_UnassignedOption
from pcapkit.protocols.internet.ip import IP
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from ipaddress import IPv4Address
    from typing import Any, Callable, NoReturn, Optional

    from mypy_extensions import NamedArg
    from typing_extensions import Literal

    from pcapkit.protocols.data.internet.ipv4 import Option as DataType_Option

    Option = OrderedMultiDict[RegType_OptionNumber, DataType_Option]
    OptionParser = Callable[[RegType_OptionNumber, NamedArg(Option, 'options')], DataType_Option]

__all__ = ['IPv4']


class IPv4(IP[DataType_IPv4]):
    """This class implements Internet Protocol version 4.

    This class currently supports parsing of the following IPv4 options,
    which are directly mapped to the :class:`pcapkit.const.ipv4.option_number.OptionNumber`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.EOOL`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_eool`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.NOP`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_nop`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.SEC`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_sec`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.LSR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_lsr`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.TS`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_ts`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.ESEC`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_esec`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.RR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_rr`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.SID`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_sid`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.SSR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_ssr`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.MTUP`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_mtup`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.MTUR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_mtur`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.TR`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_tr`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.RTRALT`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_rtralt`
       * - :attr:`~pcapkit.const.ipv4.option_number.OptionNumber.QS`
         - :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_qs`

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
    def protocol(self) -> 'RegType_TransType':
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

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_IPv4':  # pylint: disable=unused-argument
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

        _vihl = self._read_fileng(1).hex()
        _dscp = self._read_binary(1)
        _tlen = self._read_unpack(2)
        _iden = self._read_unpack(2)
        _frag = self._read_binary(2)
        _ttol = self._read_unpack(1)
        _prot = self._read_protos(1)
        _csum = self._read_fileng(2)
        _srca = self._read_ipv4_addr()
        _dsta = self._read_ipv4_addr()

        _vers = int(_vihl[0], base=16)
        if _vers != 4:
            raise ProtocolError(f'[IPv4] invalid version: {_vers}')

        ipv4 = DataType_IPv4(
            version=_vers,  # type: ignore[arg-type]
            hdr_len=int(_vihl[1], base=16) * 4,
            tos=DataType_ToSField.from_dict({
                'pre': RegType_ToSPrecedence.get(int(_dscp[:3], base=2)),
                'del': RegType_ToSDelay.get(int(_dscp[3], base=2)),
                'thr': RegType_ToSThroughput.get(int(_dscp[4], base=2)),
                'rel': RegType_ToSReliability.get(int(_dscp[5], base=2)),
                'ecn': RegType_ToSECN.get(int(_dscp[6:], base=2)),
            }),
            len=_tlen,
            id=_iden,
            flags=DataType_Flags(
                df=bool(int(_frag[1])),
                mf=bool(int(_frag[2])),
            ),
            offset=int(_frag[3:], base=2) * 8,
            ttl=datetime.timedelta(seconds=_ttol),
            protocol=_prot,
            checksum=_csum,
            src=_srca,
            dst=_dsta,
        )

        _optl = ipv4.hdr_len - 20
        if _optl:
            ipv4.__update__([
                ('options', self._read_ipv4_options(_optl)),
            ])

        return self._decode_next_layer(ipv4, _prot, ipv4.len - ipv4.hdr_len)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

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
    def __index__(cls) -> 'RegType_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return RegType_TransType.IPv4  # type: ignore[return-value]

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

    def _read_ipv4_opt_type(self, code: 'int') -> 'DataType_OptionType':
        """Read option type field.

        Arguments:
            code: option kind value

        Returns:
            Extracted IPv4 option type, as an object of the option flag (copied
            flag), option class, and option number.

        """
        bin_ = bin(code)[2:].zfill(8)

        oflg = bool(int(bin_[0], base=2))
        ocls = RegType_OptionClass.get(int(bin_[1:3], base=2))
        onum = int(bin_[3:], base=2)

        return DataType_OptionType.from_dict({
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

        while counter < length:
            # break when eol triggerred
            code = self._read_unpack(1)
            if not code:
                break

            # get options type
            kind = RegType_OptionNumber.get(code)

            # extract option data
            meth_name = f'_read_opt_{kind.name.lower()}'
            meth = getattr(self, meth_name, self._read_opt_unassigned)  # type: OptionParser
            data = meth(self, kind, options=options)  # type: ignore[arg-type,misc]

            # record option data
            counter += data.length
            options.add(kind, data)

            # break when End of Option List (EOOL) triggered
            if kind == RegType_OptionNumber.EOOL:
                break

        # get padding
        if counter < length:
            self._read_fileng(length - counter)

        return options

    def _read_opt_unassigned(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_UnassignedOption':  # pylint: disable=unused-argument
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
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **LESS THAN** ``3``.

        """
        size = self._read_unpack(1)
        if size < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = DataType_UnassignedOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            data=self._read_fileng(size),
        )

        return data

    def _read_opt_eool(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_EOOLOption':  # pylint: disable=unused-argument
        """Read IPv4 End of Option List (``EOOL``) option.

        Structure of IPv4 End of Option List (``EOOL``) option [:rfc:`719`]:

        .. code-block:: text

           +--------+
           |00000000|
           +--------+
             Type=0

        Arguments:
            kind: option type code
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        """
        data = DataType_EOOLOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=1,
        )

        return data

    def _read_opt_nop(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_NOPOption':  # pylint: disable=unused-argument
        """Read IPv4 No Operation (``NOP``) option.

        Structure of IPv4 No Operation (``NOP``) option [:rfc:`719`]:

        .. code-block:: text

           +--------+
           |00000001|
           +--------+
             Type=1

        Arguments:
            kind: option type code
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        """
        data = DataType_NOPOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=1,
        )

        return data

    def _read_opt_sec(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_SECOption':  # pylint: disable=unused-argument
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
            _data = OrderedMultiDict()  # type: OrderedMultiDict[RegType_ProtectionAuthority, bool]
            for counter in range(3, size):
                _flag = self._read_binary(1)
                if (counter < size - 1 and int(_flag[7], base=2) != 1) \
                        or (counter == size - 1 and int(_flag[7], base=2) != 0):
                    raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

                for (index, bit) in enumerate(_flag):
                    _auth = RegType_ProtectionAuthority.get(index)
                    _data.add(_auth, bool(int(bit, base=2)))
        else:
            _data = None  # type: ignore[assignment]

        data = DataType_SECOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            level=RegType_ClassificationLevel.get(_clvl),
            flags=_data,
        )

        return data

    def _read_opt_lsr(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_LSROption':  # pylint: disable=unused-argument
        """Read IPv4 Loose Source Route (``LSR``) option.

        Structure of IPv4 Loose Source Route (``LSR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |10000011| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+

        Arguments:
            kind: option type code
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

        data = DataType_LSROption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            pointer=_rptr,
            route=tuple(address) or None,
        )

        return data

    def _read_opt_ts(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_TSOption':  # pylint: disable=unused-argument
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

        _flag = RegType_TSFlag.get(_tflg)

        endpoint = min(_tptr, size)
        if _flag == RegType_TSFlag.Timestamp_Only:
            if (size - 4) % 4 != 0:
                raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')
            counter = 5

            _tsls = []  # type: list[dt_type]
            while counter < endpoint:
                counter += 4
                time = self._read_unpack(4, lilendian=True)
                _tsls.append(datetime.datetime.fromtimestamp(time))
            timestamp = tuple(_tsls) or None
        elif _flag in (RegType_TSFlag.IP_with_Timestamp, RegType_TSFlag.Prespecified_IP_with_Timestamp):
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

        data = DataType_TSOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            pointer=_tptr,
            overflow=_oflw,
            flag=_flag,
            timestamp=timestamp,
        )

        return data

    def _read_opt_esec(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_ESECOption':  # pylint: disable=unused-argument
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
            _data = OrderedMultiDict()  # type: OrderedMultiDict[RegType_ProtectionAuthority, bool]
            for counter in range(3, size):
                _flag = self._read_binary(1)
                if (counter < size - 1 and int(_flag[7], base=2) != 1) \
                        or (counter == size - 1 and int(_flag[7], base=2) != 0):
                    raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

                for (index, bit) in enumerate(_flag):
                    _auth = RegType_ProtectionAuthority.get(index)
                    _data.add(_auth, bool(int(bit, base=2)))
        else:
            _data = None  # type: ignore[assignment]

        data = DataType_ESECOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            level=RegType_ClassificationLevel.get(_clvl),
            flags=_data,
        )

        return data

    def _read_opt_rr(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_RROption':  # pylint: disable=unused-argument
        """Read IPv4 Record Route (``RR``) option.

        Structure of IPv4 Record Route (``RR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |00000111| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+
             Type=7

        Arguments:
            kind: option type code
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

        data = DataType_RROption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            pointer=_rptr,
            route=tuple(address) or None,
        )

        return data

    def _read_opt_sid(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_SIDOption':  # pylint: disable=unused-argument
        """Read IPv4 Stream ID (``SID``) option.

        Structure of IPv4 Stream ID (``SID``) option [:rfc:`791`][:rfc:`6814`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |10001000|00000010|    Stream ID    |
           +--------+--------+--------+--------+
            Type=136 Length=4

        Arguments:
            kind: option type code
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **NOT** ``4``.

        """
        size = self._read_unpack(1)
        if size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = DataType_SIDOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            sid=self._read_unpack(size),
        )

        return data

    def _read_opt_ssr(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_SSROption':  # pylint: disable=unused-argument
        """Read IPv4 Strict Source Route (``SSR``) option.

        Structure of IPv4 Strict Source Route (``SSR``) option [:rfc:`791`]:

        .. code-block:: text

           +--------+--------+--------+---------//--------+
           |10001001| length | pointer|     route data    |
           +--------+--------+--------+---------//--------+
            Type=137

        Arguments:
            kind: option type code
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

        data = DataType_SSROption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            pointer=_rptr,
            route=tuple(address) or None,
        )

        return data

    def _read_opt_mtup(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_MTUPOption':  # pylint: disable=unused-argument
        """Read IPv4 MTU Probe (``MTUP``) option.

        Structure of IPv4 MTU Probe (``MTUP``) option [:rfc:`1063`][:rfc:`1191`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |00001011|00000100|   2 octet value |
           +--------+--------+--------+--------+

        Arguments:
            kind: option type code
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **NOT** ``4``.

        """
        size = self._read_unpack(1)
        if size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = DataType_MTUPOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            mtu=self._read_unpack(size),
        )

        return data

    def _read_opt_mtur(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_MTUROption':  # pylint: disable=unused-argument
        """Read IPv4 MTU Reply (``MTUR``) option.

        Structure of IPv4 MTU Reply (``MTUR``) option [:rfc:`1063`][:rfc:`1191`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |00001100|00000100|   2 octet value |
           +--------+--------+--------+--------+

        Arguments:
            kind: option type code
            options: extracted IPv4 options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``size`` is **NOT** ``4``.

        """
        size = self._read_unpack(1)
        if size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = DataType_MTUROption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            mtu=self._read_unpack(size),
        )

        return data

    def _read_opt_tr(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_TROption':  # pylint: disable=unused-argument
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

        data = DataType_TROption.from_dict({
            'code': kind,
            'type': self._read_ipv4_opt_type(kind),
            'length': size,
            'id': _idnm,
            'outbound': _ohcn,
            'return': _rhcn,
            'originator': _ipad,
        })

        return data

    def _read_opt_rtralt(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_RTRALTOption':  # pylint: disable=unused-argument
        """Read IPv4 Router Alert (``RTRALT``) option.

        Structure of IPv4 Router Alert (``RTRALT``) option [:rfc:`2113`]:

        .. code:: text

           +--------+--------+--------+--------+
           |10010100|00000100|  2 octet value  |
           +--------+--------+--------+--------+

        Arguments:
            kind: option type code
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

        data = DataType_RTRALTOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            alert=RegType_RouterAlert.get(_code),
        )

        return data

    def _read_opt_qs(self, kind: 'RegType_OptionNumber', *, options: 'Option') -> 'DataType_QSOption':  # pylint: disable=unused-argument
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

        _qsfn = RegType_QSFunction.get(_func)
        if _qsfn not in (RegType_QSFunction.Quick_Start_Request, RegType_QSFunction.Report_of_Approved_Rate):
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = DataType_QSOption(
            code=kind,
            type=self._read_ipv4_opt_type(kind),
            length=size,
            func=_qsfn,
            rate=40000 * (2 ** _rate) / 1000,
            ttl=None if _func != RegType_QSFunction.Quick_Start_Request else datetime.timedelta(seconds=_ttlv),
            nounce=_qsnn,
        )

        return data
