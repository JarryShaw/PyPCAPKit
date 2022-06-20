# -*- coding: utf-8 -*-
"""HOPOPT - IPv6 Hop-by-Hop Options
======================================

:mod:`pcapkit.protocols.internet.hopopt` contains
:class:`~pcapkit.protocols.internet.hopopt.HOPOPT`
only, which implements extractor for IPv6 Hop-by-Hop
Options header (HOPOPT) [*]_, whose structure is
described as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``hopopt.next``             Next Header
  1           8   ``hopopt.length``           Header Extensive Length
  2          16   ``hopopt.options``          Options
======= ========= =================== =================================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options

"""
import collections
import datetime
import ipaddress
from typing import TYPE_CHECKING, overload

from pcapkit.const.ipv6.option import Option as RegType_Option
from pcapkit.const.ipv6.qs_function import QSFunction as RegType_QSFunction
from pcapkit.const.ipv6.router_alert import RouterAlert as RegType_RouterAlert
from pcapkit.const.ipv6.seed_id import SeedID as RegType_SeedID
from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode as RegType_SMFDPDMode
from pcapkit.const.ipv6.tagger_id import TaggerID as RegType_TaggerID
from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.internet.hopopt import HOPOPT as DataType_HOPOPT
from pcapkit.protocols.data.internet.hopopt import CALIPSOOption as DataType_CALIPSOOption
from pcapkit.protocols.data.internet.hopopt import DFFFlags as DataType_DFFFlags
from pcapkit.protocols.data.internet.hopopt import HomeAddressOption as DataType_HomeAddressOption
from pcapkit.protocols.data.internet.hopopt import ILNPOption as DataType_ILNPOption
from pcapkit.protocols.data.internet.hopopt import IPDFFOption as DataType_IPDFFOption
from pcapkit.protocols.data.internet.hopopt import JumboPayloadOption as DataType_JumboPayloadOption
from pcapkit.protocols.data.internet.hopopt import \
    LineIdentificationOption as DataType_LineIdentificationOption
from pcapkit.protocols.data.internet.hopopt import MPLFlags as DataType_MPLFlags
from pcapkit.protocols.data.internet.hopopt import MPLOption as DataType_MPLOption
from pcapkit.protocols.data.internet.hopopt import PadOption as DataType_PadOption
from pcapkit.protocols.data.internet.hopopt import PDMOption as DataType_PDMOption
from pcapkit.protocols.data.internet.hopopt import QuickStartOption as DataType_QuickStartOption
from pcapkit.protocols.data.internet.hopopt import RouterAlertOption as DataType_RouterAlertOption
from pcapkit.protocols.data.internet.hopopt import RPLFlags as DataType_RPLFlags
from pcapkit.protocols.data.internet.hopopt import RPLOption as DataType_RPLOption
from pcapkit.protocols.data.internet.hopopt import \
    SMFHashBasedDPDOption as DataType_SMFHashBasedDPDOption
from pcapkit.protocols.data.internet.hopopt import \
    SMFIdentificationBasedDPDOption as DataType_SMFIdentificationBasedDPDOption
from pcapkit.protocols.data.internet.hopopt import \
    TunnelEncapsulationLimitOption as DataType_TunnelEncapsulationLimitOption
from pcapkit.protocols.data.internet.hopopt import UnassignedOption as DataType_UnassignedOption
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, BinaryIO, Callable, DefaultDict, NoReturn, Optional

    from mypy_extensions import NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.hopopt import Option as DataType_Option
    from pcapkit.protocols.protocol import Protocol

    Option = OrderedMultiDict[RegType_Option, DataType_Option]
    OptionParser = Callable[['HOPOPT', RegType_Option, int, bool, NamedArg(Option, 'options')], DataType_Option]

__all__ = ['HOPOPT']


class HOPOPT(Internet[DataType_HOPOPT]):
    """This class implements IPv6 Hop-by-Hop Options.

    This class currently supports parsing of the following IPv6 Hop-by-Hop
    options, which are registered in the :attr:`self.__option__ <pcapkit.protocols.internet.hopopt.HOPOPT.__option__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
       * - :attr:`~pcapkit.const.ipv6.option.Option.Pad1`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_pad`
       * - :attr:`~pcapkit.const.ipv6.option.Option.PadN`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_pad`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Tunnel_Encapsulation_Limit`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_tun`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Router_Alert`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_ra`
       * - :attr:`~pcapkit.const.ipv6.option.Option.CALIPSO`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_calipso`
       * - :attr:`~pcapkit.const.ipv6.option.Option.SMF_DPD`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_smf_dpd`
       * - :attr:`~pcapkit.const.ipv6.option.Option.PDM`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_pdm`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Quick_Start`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_qs`
       * - :attr:`~pcapkit.const.ipv6.option.Option.RPL_Option_0x63`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_rpl`
       * - :attr:`~pcapkit.const.ipv6.option.Option.MPL_Option`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_mpl`
       * - :attr:`~pcapkit.const.ipv6.option.Option.ILNP_Nonce`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_ilnp`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Line_Identification_Option`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_lio`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Jumbo_Payload`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_jumbo`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Home_Address`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_home`
       * - :attr:`~pcapkit.const.ipv6.option.Option.IP_DFF`
         - :meth:`~pcapkit.protocols.internet.hopopt.HOPOPT._read_opt_ip_dff`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[RegType_Option, str | OptionParser]: Option code to method
    #: mapping, c.f. :meth:`_read_hopopt_options`. Method names are expected
    #: to be referred to the class by ``_read_opt_${name}``, and if such name
    #: not found, the value should then be a method that can parse the option
    #: by itself.
    __option__ = collections.defaultdict(
        lambda: 'none',
        {
            RegType_Option.Pad1:                       'pad',      # [RFC 8200] 0
            RegType_Option.PadN:                       'pad',      # [RFC 8200]
            RegType_Option.Tunnel_Encapsulation_Limit: 'tun',      # [RFC 2473] 1
            RegType_Option.Router_Alert:               'ra',       # [RFC 2711] 2
            RegType_Option.CALIPSO:                    'calipso',  # [RFC 5570]
            RegType_Option.SMF_DPD:                    'smf_dpd',  # [RFC 6621]
            RegType_Option.PDM:                        'pdm',      # [RFC 8250] 10
            RegType_Option.Quick_Start:                'qs',       # [RFC 4782][RFC Errata 2034] 6
            RegType_Option.RPL_Option_0x63:            'rpl',      # [RFC 6553]
            RegType_Option.MPL_Option:                 'mpl',      # [RFC 7731]
            RegType_Option.ILNP_Nonce:                 'ilnp',     # [RFC 6744]
            RegType_Option.Line_Identification_Option: 'lio',      # [RFC 6788]
            RegType_Option.Jumbo_Payload:              'jumbo',    # [RFC 2675]
            RegType_Option.Home_Address:               'home',     # [RFC 6275]
            RegType_Option.IP_DFF:                     'ip_dff',   # [RFC 6971]
        },
    )  # type: DefaultDict[int, str | OptionParser]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["IPv6 Hop-by-Hop Options"]':
        """Name of current protocol."""
        return 'IPv6 Hop-by-Hop Options'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self) -> 'Protocol | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        :rtype: pcapkit.protocols.protocol.Protocol
        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return self._next

    @property
    def protocol(self) -> 'Optional[str] | NoReturn':
        """Name of next layer protocol (if any).

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")
        return super().protocol

    @property
    def protochain(self) -> 'ProtoChain | NoReturn':
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protochain'")
        return super().protochain

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, extension: 'bool' = False, **kwargs: 'Any') -> 'DataType_HOPOPT':  # pylint: disable=arguments-differ,unused-argument
        """Read IPv6 Hop-by-Hop Options.

        Structure of HOPOPT header [:rfc:`8200`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |  Hdr Ext Len  |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
           |                                                               |
           .                                                               .
           .                            Options                            .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            extension: If the packet is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        # _opts = self._read_fileng(_hlen*8+6)

        hopopt = DataType_HOPOPT(
            next=_next,
            length=(_hlen + 1) * 8,
            options=self._read_hopopt_options(_hlen * 8 + 6),
        )

        if extension:
            return hopopt
        return self._decode_next_layer(hopopt, _next, length - hopopt.length)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def register_option(cls, code: 'RegType_Option', meth: 'str | OptionParser') -> 'None':
        """Register an option parser.

        Args:
            code: HOPOPT option code.
            meth: Method name or callable to parse the option.

        """
        cls.__option__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'BinaryIO', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[BinaryIO]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[2]':
        """Return an estimated length for the object."""
        return 2

    @classmethod
    def __index__(cls) -> 'RegType_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return RegType_TransType.HOPOPT  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_opt_type(self, kind: 'int') -> 'tuple[int, bool]':
        """Read option type field.

        Arguments:
            kind (int): option kind value

        Returns:
            Extracted HOPOPT option type field information (unknown option
            action and change flag), c.f. [:rfc:`8200#section-4.2`].

        """
        bin_ = bin(kind)[2:].zfill(8)
        return int(bin_[:2], base=2), bool(int(bin_[2], base=2))

    def _read_hopopt_options(self, length: 'int') -> 'Option':
        """Read HOPOPT options.

        Positional arguments:
            length: length of options

        Returns:
            Extracted HOPOPT options

        Raises:
            ProtocolError: If the threshold is **NOT** matching.

        """
        counter = 0                   # length of read options
        options = OrderedMultiDict()  # type: Option

        while counter < length:
            # break when eol triggered
            code = self._read_unpack(1)
            if not code:
                break

            # get option type
            kind = RegType_Option.get(code)
            acts, cflg = self._read_opt_type(code)

            # extract option data
            name = self.__option__[kind]  # type: str | OptionParser
            if isinstance(name, str):
                meth_name = f'_read_opt_{kind.name.lower()}'
                meth = getattr(
                    self, meth_name,
                    self._read_opt_none
                )  # type: Callable[[RegType_Option, int, bool, NamedArg(Option, 'options')], DataType_Option]
                data = meth(kind, acts, cflg, options=options)
            else:
                data = name(self, kind, acts, cflg, options=options)

            # record option data
            counter += data.length
            options.add(kind, data)

        # check threshold
        if counter != length:
            raise ProtocolError(f'{self.alias}: invalid format')

        return options

    def _read_opt_none(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                       options: 'Option') -> 'DataType_UnassignedOption':  # pylint: disable=unused-argument
        """Read HOPOPT unassigned options.

        Structure of HOPOPT unassigned options [:rfc:`8200`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
           |  Option Type  |  Opt Data Len |  Option Data
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        _size = self._read_unpack(1)
        _data = self._read_fileng(_size)

        opt = DataType_UnassignedOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            data=_data,
        )

        return opt

    def _read_opt_pad(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                      options: 'Option') -> 'DataType_PadOption':  # pylint: disable=unused-argument
        """Read HOPOPT padding options.

        Structure of HOPOPT padding options [:rfc:`8200`]:

        * ``Pad1`` option:

          .. code-block:: text

             +-+-+-+-+-+-+-+-+
             |       0       |
             +-+-+-+-+-+-+-+-+

        * ``PadN`` option:

          .. code-block:: text

             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
             |       1       |  Opt Data Len |  Option Data
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``code`` is **NOT** ``0`` or ``1``.

        """
        if code == RegType_Option.Pad1:
            _size = 1
        elif code == RegType_Option.PadN:
            _size = self._read_unpack(1) + 2
            _padn = self._read_fileng(_size)
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        opt = DataType_PadOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size,
        )

        return opt

    def _read_opt_tun(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                      options: 'Option') -> 'DataType_TunnelEncapsulationLimitOption':  # pylint: disable=unused-argument
        """Read HOPOPT Tunnel Encapsulation Limit option.

        Structure of HOPOPT Tunnel Encapsulation Limit option [:rfc:`2473`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |Hdr Ext Len = 0| Opt Type = 4  |Opt Data Len=1 |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Tun Encap Lim |PadN Opt Type=1|Opt Data Len=1 |       0       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.tun.length`` is **NOT** ``1``.

        """
        _size = self._read_unpack(1)
        if _size != 1:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _limt = self._read_unpack(1)

        opt = DataType_TunnelEncapsulationLimitOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            limit=_limt,
        )

        return opt

    def _read_opt_ra(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                     options: 'Option') -> 'DataType_RouterAlertOption':  # pylint: disable=unused-argument
        """Read HOPOPT Router Alert option.

        Structure of HOPOPT Router Alert option [:rfc:`2711`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |0 0 0|0 0 1 0 1|0 0 0 0 0 0 1 0|        Value (2 octets)       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.tun.length`` is **NOT** ``2``.

        """
        _size = self._read_unpack(1)
        if _size != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _rval = self._read_unpack(2)

        _enum = RegType_RouterAlert.get(_rval)
        opt = DataType_RouterAlertOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            value=_enum,
        )

        return opt

    def _read_opt_calipso(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                          options: 'Option') -> 'DataType_CALIPSOOption':  # pylint: disable=unused-argument
        """Read HOPOPT Common Architecture Label IPv6 Security Option (CALIPSO) option.

        Structure of HOPOPT CALIPSO option [:rfc:`5570`]:

        .. code-block:: text

           ------------------------------------------------------------
           | Next Header | Hdr Ext Len   | Option Type | Option Length|
           +-------------+---------------+-------------+--------------+
           |             CALIPSO Domain of Interpretation             |
           +-------------+---------------+-------------+--------------+
           | Cmpt Length |  Sens Level   |     Checksum (CRC-16)      |
           +-------------+---------------+-------------+--------------+
           |      Compartment Bitmap (Optional; variable length)      |
           +-------------+---------------+-------------+--------------+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        _size = self._read_unpack(1)
        if _size < 8 and _size % 8 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _cmpt = self._read_unpack(4)
        _clen = self._read_unpack(1)
        if _clen % 2 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _sens = self._read_unpack(1)
        _csum = self._read_fileng(2)

        opt = DataType_CALIPSOOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            domain=_cmpt,
            cmpt_len=_clen * 4,
            level=_sens,
            checksum=_csum,
        )

        if _clen:
            _bmap = []  # type: list[int]
            for _ in range(_clen // 2):
                _bmap.append(self._read_unpack(8))

            opt.__update__([
                ('cmpt_bitmap', tuple(_bmap)),
            ])

        _plen = _size - _clen * 4 - 8
        if _plen:
            self._read_fileng(_plen)

        return opt

    def _read_opt_smf_dpd(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                          options: 'Option') -> 'DataType_SMFIdentificationBasedDPDOption | DataType_SMFHashBasedDPDOption':  # pylint: disable=unused-argument,line-too-long
        """Read HOPOPT Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) option.

        Structure of HOPOPT ``SMF_DPD`` option [:rfc:`6621`]:

        * IPv6 ``SMF_DPD`` option header in **I-DPD** (Identification-Based DPD) mode

          .. code-block:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            ...              |0|0|0|  01000  | Opt. Data Len |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |0|TidTy| TidLen|             TaggerID (optional) ...           |
             +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                               |            Identifier  ...
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        * IPv6 ``SMF_DPD`` option header in **H-DPD** (Hash-Based) mode

          .. code-block:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            ...              |0|0|0| OptType | Opt. Data Len |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |1|    Hash Assist Value (HAV) ...
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        _size = self._read_unpack(1)
        _tidd = self._read_binary(1)

        if _tidd[0] == '0':
            _mode = RegType_SMFDPDMode.I_DPD
            _tidt = RegType_TaggerID.get(_tidd[1:4])
            _tidl = int(_tidd[4:], base=2)

            if _tidt == RegType_TaggerID.NULL:
                if _tidl != 0:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _iden = self._read_unpack(_size-1)

                opt = DataType_SMFIdentificationBasedDPDOption(
                    type=code,
                    action=acts,
                    change=cflg,
                    length=_size + 2,
                    dpd_type=_mode,  # type: ignore[arg-type]
                    tid_type=_tidt,
                    tid_len=_tidl,
                    tid=None,
                    id=_iden,
                )
            elif _tidt == RegType_TaggerID.IPv4:
                if _tidl != 3:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _tidf = self._read_fileng(4)
                _iden = self._read_unpack(_size-4)

                opt = DataType_SMFIdentificationBasedDPDOption(
                    type=code,
                    action=acts,
                    change=cflg,
                    length=_size + 2,
                    dpd_type=_mode,  # type: ignore[arg-type]
                    tid_type=_tidt,
                    tid_len=_tidl,
                    tid=ipaddress.ip_address(_tidf),
                    id=_iden,
                )
            elif _tidt == RegType_TaggerID.IPv6:
                if _tidl != 15:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _tidf = self._read_fileng(15)
                _iden = self._read_unpack(_size-15)

                opt = DataType_SMFIdentificationBasedDPDOption(
                    type=code,
                    action=acts,
                    change=cflg,
                    length=_size + 2,
                    dpd_type=_mode,  # type: ignore[arg-type]
                    tid_type=_tidt,
                    tid_len=_tidl,
                    tid=ipaddress.ip_address(_tidf),
                    id=_iden,
                )
            else:
                _tidf = self._read_unpack(_tidl+1)  # type: ignore[assignment]
                _iden = self._read_unpack(_size-_tidl-2)

                opt = DataType_SMFIdentificationBasedDPDOption(
                    type=code,
                    action=acts,
                    change=cflg,
                    length=_size + 2,
                    dpd_type=_mode,  # type: ignore[arg-type]
                    tid_type=_tidt,
                    tid_len=_tidl,
                    tid=_tidf,  # type: ignore[arg-type]
                    id=_iden,
                )
        elif _tidd[0] == '1':
            _mode = RegType_SMFDPDMode.H_DPD
            _tidt = RegType_TaggerID.get(_tidd[1:4])
            _data = self._read_fileng(_size-1)

            opt = DataType_SMFHashBasedDPDOption(  # type: ignore[assignment]
                type=code,
                action=acts,
                change=cflg,
                length=_size + 2,
                dpd_type=_mode,  # type: ignore[arg-type]
                tid_type=_tidt,
                hav=int(_tidd[1:], base=2).to_bytes(length=1, byteorder='little') + _data,
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        return opt

    def _read_opt_pdm(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                      options: 'Option') -> 'DataType_PDMOption':  # pylint: disable=unused-argument
        """Read HOPOPT Performance and Diagnostic Metrics (PDM) option.

        Structure of HOPOPT PDM option [:rfc:`8250`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Option Type  | Option Length |    ScaleDTLR  |     ScaleDTLS |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   PSN This Packet             |  PSN Last Received            |
           |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Delta Time Last Received    |  Delta Time Last Sent         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.pdm.length`` is **NOT** ``10``.

        """
        _size = self._read_unpack(1)
        if _size != 10:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _stlr = self._read_unpack(1)
        _stls = self._read_unpack(1)
        _psnt = self._read_unpack(2)
        _psnl = self._read_unpack(2)
        _dtlr = self._read_unpack(2)
        _dtls = self._read_unpack(2)

        opt = DataType_PDMOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            scaledtlr=datetime.timedelta(seconds=_stlr),
            scaledtls=datetime.timedelta(seconds=_stls),
            psntp=_psnt,
            psnlr=_psnl,
            deltatlr=datetime.timedelta(seconds=_dtlr),
            deltatls=datetime.timedelta(seconds=_dtls),
        )

        return opt

    def _read_opt_qs(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                     options: 'Option') -> 'DataType_QuickStartOption':  # pylint: disable=unused-argument  # pylint: disable=unused-argument
        """Read HOPOPT Quick Start option.

        Structure of HOPOPT Quick-Start option [:rfc:`4782`]:

        * A Quick-Start Request:

          .. code-block:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |   Option      |  Length=6     | Func. | Rate  |   QS TTL      |
             |               |               | 0000  |Request|               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                        QS Nonce                           | R |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        * Report of Approved Rate:

          .. code-block:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |   Option      |  Length=6     | Func. | Rate  |   Not Used    |
             |               |               | 1000  | Report|               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                        QS Nonce                           | R |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        _size = self._read_unpack(1)
        if _size != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        _fcrr = self._read_binary(1)
        _func = int(_fcrr[:4], base=2)
        _rate = int(_fcrr[4:], base=2)
        _ttlv = self._read_unpack(1)
        _nonr = self._read_binary(4)
        _qsnn = int(_nonr[:30], base=2)

        _qsfn = RegType_QSFunction.get(_func)
        if _qsfn not in (RegType_QSFunction.Quick_Start_Request, RegType_QSFunction.Report_of_Approved_Rate):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        data = DataType_QuickStartOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            func=_qsfn,
            rate=40000 * (2 ** _rate) / 1000,
            ttl=None if _func != RegType_QSFunction.Quick_Start_Request else datetime.timedelta(seconds=_ttlv),
            nounce=_qsnn,
        )

        return data

    def _read_opt_rpl(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                      options: 'Option') -> 'DataType_RPLOption':  # pylint: disable=unused-argument
        """Read HOPOPT Routing Protocol for Low-Power and Lossy Networks (RPL) option.

        Structure of HOPOPT RPL option [:rfc:`6553`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  |  Opt Data Len |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |O|R|F|0|0|0|0|0| RPLInstanceID |          SenderRank           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         (sub-TLVs)                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.rpl.length`` is **NOT** ``4``.

        """
        _size = self._read_unpack(1)
        if _size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _flag = self._read_binary(1)
        _rpld = self._read_unpack(1)
        _rank = self._read_unpack(2)

        opt = DataType_RPLOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            flags=DataType_RPLFlags(
                down=bool(int(_flag[0], base=2)),
                rank_err=bool(int(_flag[1], base=2)),
                fwd_err=bool(int(_flag[2], base=2)),
            ),
            id=_rpld,
            rank=_rank,
        )

        return opt

    def _read_opt_mpl(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                      options: 'Option') -> 'DataType_MPLOption':  # pylint: disable=unused-argument
        """Read HOPOPT Multicast Protocol for Low-Power and Lossy Networks (MPL) option.

        Structure of HOPOPT MPL option [:rfc:`7731`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  |  Opt Data Len |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | S |M|V|  rsv  |   sequence    |      seed-id (optional)       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        _size = self._read_unpack(1)
        if _size < 2:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _smvr = self._read_binary(1)
        _seqn = self._read_unpack(1)

        _kind = RegType_SeedID.get(int(_smvr[:2], base=2))
        if _kind == _kind.IPV6_SOURCE_ADDRESS:
            if _size != 2:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            _seed = None
            _slen = 0
        elif _kind == _kind.SEEDID_16_BIT_UNSIGNED_INTEGER:
            if _size != 4:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            _seed = self._read_unpack(2)
            _slen = 2
        elif _kind == _kind.SEEDID_64_BIT_UNSIGNED_INTEGER:
            if _size != 10:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            _seed = self._read_unpack(8)
            _slen = 8
        elif _kind == _kind.SEEDID_128_BIT_UNSIGNED_INTEGER:
            if _size != 18:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            _seed = self._read_unpack(16)
            _slen = 16
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        opt = DataType_MPLOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            seed_type=_kind,
            flags=DataType_MPLFlags(
                max=bool(int(_smvr[2], base=2)),
                verification=bool(int(_smvr[3], base=2)),
            ),
            seq=_seqn,
            seed_id=_seed,
        )

        _plen = _size - _slen
        if _plen:
            self._read_fileng(_plen)

        return opt

    def _read_opt_ilnp(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                       options: 'Option') -> 'DataType_ILNPOption':  # pylint: disable=unused-argument
        """Read HOPOPT Identifier-Locator Network Protocol (ILNP) Nonce option.

        Structure of HOPOPT ILNP Nonce option [:rfc:`6744`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Next Header   | Hdr Ext Len   |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                         Nonce Value                           /
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        _size = self._read_unpack(1)
        _nval = self._read_fileng(_size)

        opt = DataType_ILNPOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            nounce=_nval,
        )

        return opt

    def _read_opt_lio(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                      options: 'Option') -> 'DataType_LineIdentificationOption':  # pylint: disable=unused-argument
        """Read HOPOPT Line-Identification option.

        Structure of HOPOPT Line-Identification option [:rfc:`6788`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | LineIDLen     |     Line ID...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        _size = self._read_unpack(1)
        _llen = self._read_unpack(1)
        _line = self._read_unpack(_llen)

        opt = DataType_LineIdentificationOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            line_id_len=_llen,
            line_id=_line,
        )

        _plen = _size - _llen
        if _plen:
            self._read_fileng(_plen)

        return opt

    def _read_opt_jumbo(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                        options: 'Option') -> 'DataType_JumboPayloadOption':  # pylint: disable=unused-argument
        """Read HOPOPT Jumbo Payload option.

        Structure of HOPOPT Jumbo Payload option [:rfc:`2675`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  |  Opt Data Len |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                     Jumbo Payload Length                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.jumbo.length`` is **NOT** ``4``.

        """
        _size = self._read_unpack(1)
        if _size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _jlen = self._read_unpack(4)

        opt = DataType_JumboPayloadOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            payload_len=_jlen,
        )

        return opt

    def _read_opt_home(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                       options: 'Option') -> 'DataType_HomeAddressOption':  # pylint: disable=unused-argument
        """Read HOPOPT Home Address option.

        Structure of HOPOPT Home Address option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                          Home Address                         +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.jumbo.length`` is **NOT** ``16``.

        """
        _size = self._read_unpack(1)
        if _size != 16:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _addr = self._read_fileng(16)

        opt = DataType_HomeAddressOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return opt

    def _read_opt_ip_dff(self, code: 'RegType_Option', acts: 'int', cflg: 'bool', *,
                         options: 'Option') -> 'DataType_IPDFFOption':  # pylint: disable=unused-argument
        """Read HOPOPT Depth-First Forwarding (``IP_DFF``) option.

        Structure of HOPOPT ``IP_DFF`` option [:rfc:`6971`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |  Hdr Ext Len  |  OptTypeDFF   | OptDataLenDFF |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |VER|D|R|0|0|0|0|        Sequence Number        |      Pad1     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.ip_dff.length`` is **NOT** ``2``.

        """
        _size = self._read_unpack(1)
        if _size != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _verf = self._read_binary(1)
        _seqn = self._read_unpack(2)

        opt = DataType_IPDFFOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            version=int(_verf[:2], base=2),
            flags=DataType_DFFFlags(
                dup=bool(int(_verf[2], base=2)),
                ret=bool(int(_verf[3], base=2)),
            ),
            seq=_seqn,
        )

        return opt
