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
import struct
from typing import TYPE_CHECKING, overload, cast

from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.ipv6.qs_function import QSFunction as Enum_QSFunction
from pcapkit.const.ipv6.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.ipv6.seed_id import SeedID as Enum_SeedID
from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode as Enum_SMFDPDMode
from pcapkit.const.ipv6.tagger_id import TaggerID as Enum_TaggerID
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.internet.hopopt import HOPOPT as Data_HOPOPT
from pcapkit.protocols.data.internet.hopopt import CALIPSOOption as Data_CALIPSOOption
from pcapkit.protocols.data.internet.hopopt import DFFFlags as Data_DFFFlags
from pcapkit.protocols.data.internet.hopopt import HomeAddressOption as Data_HomeAddressOption
from pcapkit.protocols.data.internet.hopopt import ILNPOption as Data_ILNPOption
from pcapkit.protocols.data.internet.hopopt import IPDFFOption as Data_IPDFFOption
from pcapkit.protocols.data.internet.hopopt import JumboPayloadOption as Data_JumboPayloadOption
from pcapkit.protocols.data.internet.hopopt import \
    LineIdentificationOption as Data_LineIdentificationOption
from pcapkit.protocols.data.internet.hopopt import MPLFlags as Data_MPLFlags
from pcapkit.protocols.data.internet.hopopt import MPLOption as Data_MPLOption
from pcapkit.protocols.data.internet.hopopt import PadOption as Data_PadOption
from pcapkit.protocols.data.internet.hopopt import PDMOption as Data_PDMOption
from pcapkit.protocols.data.internet.hopopt import QuickStartOption as Data_QuickStartOption
from pcapkit.protocols.data.internet.hopopt import RouterAlertOption as Data_RouterAlertOption
from pcapkit.protocols.data.internet.hopopt import RPLFlags as Data_RPLFlags
from pcapkit.protocols.data.internet.hopopt import RPLOption as Data_RPLOption
from pcapkit.protocols.data.internet.hopopt import \
    SMFHashBasedDPDOption as Data_SMFHashBasedDPDOption
from pcapkit.protocols.data.internet.hopopt import \
    SMFIdentificationBasedDPDOption as Data_SMFIdentificationBasedDPDOption
from pcapkit.protocols.data.internet.hopopt import \
    TunnelEncapsulationLimitOption as Data_TunnelEncapsulationLimitOption
from pcapkit.protocols.data.internet.hopopt import UnassignedOption as Data_UnassignedOption
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.protocols.schema.internet.hopopt import HOPOPT as Schema_HOPOPT
from pcapkit.protocols.schema.schema import Schema
from pcapkit.const.ipv6.option_action import OptionAction as Enum_OptionAction
from pcapkit.protocols.schema.internet.hopopt import HOPOPT as Schema_HOPOPT
from pcapkit.protocols.schema.internet.hopopt import CALIPSOOption as Schema_CALIPSOOption
from pcapkit.protocols.schema.internet.hopopt import DFFFlags as Schema_DFFFlags
from pcapkit.protocols.schema.internet.hopopt import HomeAddressOption as Schema_HomeAddressOption
from pcapkit.protocols.schema.internet.hopopt import ILNPOption as Schema_ILNPOption
from pcapkit.protocols.schema.internet.hopopt import IPDFFOption as Schema_IPDFFOption
from pcapkit.protocols.schema.internet.hopopt import JumboPayloadOption as Schema_JumboPayloadOption
from pcapkit.protocols.schema.internet.hopopt import \
    LineIdentificationOption as Schema_LineIdentificationOption
from pcapkit.protocols.schema.internet.hopopt import MPLFlags as Schema_MPLFlags
from pcapkit.protocols.schema.internet.hopopt import MPLOption as Schema_MPLOption
from pcapkit.protocols.schema.internet.hopopt import PadOption as Schema_PadOption
from pcapkit.protocols.schema.internet.hopopt import PDMOption as Schema_PDMOption
from pcapkit.protocols.schema.internet.hopopt import QuickStartOption as Schema_QuickStartOption
from pcapkit.protocols.schema.internet.hopopt import RouterAlertOption as Schema_RouterAlertOption
from pcapkit.protocols.schema.internet.hopopt import RPLFlags as Schema_RPLFlags
from pcapkit.protocols.schema.internet.hopopt import RPLOption as Schema_RPLOption
from pcapkit.protocols.schema.internet.hopopt import \
    SMFHashBasedDPDOption as Schema_SMFHashBasedDPDOption
from pcapkit.protocols.schema.internet.hopopt import \
    SMFIdentificationBasedDPDOption as Schema_SMFIdentificationBasedDPDOption
from pcapkit.protocols.schema.internet.hopopt import \
    TunnelEncapsulationLimitOption as Schema_TunnelEncapsulationLimitOption
from pcapkit.protocols.schema.internet.hopopt import UnassignedOption as Schema_UnassignedOption

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, Callable, DefaultDict, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import NamedArg, DefaultArg, KwArg
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.hopopt import Option as Data_Option
    from pcapkit.protocols.protocol import Protocol
    from pcapkit.protocols.schema.internet.hopopt import Option as Schema_Option

    Option = OrderedMultiDict[Enum_Option, Data_Option]
    OptionParser = Callable[['HOPOPT', Enum_Option, int, bool, int, NamedArg(bytes, 'data'),
                             NamedArg(int, 'length'), NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[['HOPOPT', Enum_Option,
                                  DefaultArg(Optional[Data_Option]), KwArg(Any)], Schema_Option]

__all__ = ['HOPOPT']


class HOPOPT(Internet[Data_HOPOPT, Schema_HOPOPT]):
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

    #: DefaultDict[Enum_Option, str | OptionParser]: Option code to method
    #: mapping, c.f. :meth:`_read_hopopt_options`. Method names are expected
    #: to be referred to the class by ``_read_opt_${name}``, and if such name
    #: not found, the value should then be a method that can parse the option
    #: by itself.
    __option__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_Option.Pad1:                       'pad',      # [RFC 8200] 0
            Enum_Option.PadN:                       'pad',      # [RFC 8200]
            Enum_Option.Tunnel_Encapsulation_Limit: 'tun',      # [RFC 2473] 1
            Enum_Option.Router_Alert:               'ra',       # [RFC 2711] 2
            Enum_Option.CALIPSO:                    'calipso',  # [RFC 5570]
            Enum_Option.SMF_DPD:                    'smf_dpd',  # [RFC 6621]
            Enum_Option.PDM:                        'pdm',      # [RFC 8250] 10
            Enum_Option.Quick_Start:                'qs',       # [RFC 4782][RFC Errata 2034] 6
            Enum_Option.RPL_Option_0x63:            'rpl',      # [RFC 6553]
            Enum_Option.MPL_Option:                 'mpl',      # [RFC 7731]
            Enum_Option.ILNP_Nonce:                 'ilnp',     # [RFC 6744]
            Enum_Option.Line_Identification_Option: 'lio',      # [RFC 6788]
            Enum_Option.Jumbo_Payload:              'jumbo',    # [RFC 2675]
            Enum_Option.Home_Address:               'home',     # [RFC 6275]
            Enum_Option.IP_DFF:                     'ip_dff',   # [RFC 6971]
        },
    )  # type: DefaultDict[Enum_Option | int, str | tuple[OptionParser, OptionConstructor]]

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

    def read(self, length: 'Optional[int]' = None, *, extension: 'bool' = False, **kwargs: 'Any') -> 'Data_HOPOPT':  # pylint: disable=arguments-differ,unused-argument
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
        schema = self.__schema__

        hopopt = Data_HOPOPT(
            next=schema.next,
            length=(schema.len + 1) * 8,
            options=self._read_hopopt_options(schema.len * 8 + 6),
        )

        if extension:
            return hopopt
        return self._decode_next_layer(hopopt, schema.next, length - hopopt.length)

    def make(self,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             options: 'Optional[list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes] | Option]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_HOPOPT':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            next_default: Default value of next header type.
            next_namespace: Namespace of next header type.
            next_reversed: If the namespace of next header type is reversed.
            option: Hop-by-Hop Options.
            payload: Payload of current protocol.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_value = self._make_index(next, next_default, namespace=next_namespace,  # type: ignore[call-overload]
                                      reversed=next_reversed, pack=False)

        if options is not None:
            options_value, total_length = self._make_hopopt_options(options)
            length = (total_length - 6) // 8
        else:
            options_value, length = [], 0

        return Schema_HOPOPT(
            next=next_value,
            len=length,
            options=options_value,
            payload=payload,
        )

    @classmethod
    def register_option(cls, code: 'Enum_Option', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
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
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
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
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.HOPOPT  # type: ignore[return-value]

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
        payload = cast('bytes', self.__header__.options)
        self.__header__.options = []

        counter = 0                   # length of read options
        options = OrderedMultiDict()  # type: Option

        while counter < length:
            cbuf = payload[counter:counter + 1]
            if not cbuf:  # break when eol triggered
                break

            # get option type
            code = int(cbuf, base=2)
            kind = Enum_Option.get(code)
            acts = Enum_OptionAction.get(code >> 6)
            cflg = bool(code & 0b00100000)

            # get option length
            if kind == Enum_Option.Pad1:
                clen, olen = 0, 1
            else:
                cbuf = payload[counter + 1:counter + 2]
                clen = struct.unpack('!B', cbuf)[0]  # length of option data
                olen = clen + 2                      # total length

            # extract option data
            name = self.__option__[kind]  # type: str | tuple[OptionParser, OptionConstructor]
            if isinstance(name, str):
                meth_name = f'_read_opt_{name}'
                meth = cast('OptionParser',
                            getattr(self, meth_name, self._read_opt_none))
            else:
                meth = name[0]
            data = meth(self, kind, acts, cflg, clen,
                        data=payload[counter:counter + olen],
                        length=olen, options=options)

            # record option data
            counter += data.length
            options.add(kind, data)

        # check threshold
        if counter != length:
            raise ProtocolError(f'{self.alias}: invalid format')

        return options

    def _read_opt_none(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                       data: 'bytes', length: 'int', option: 'Option') -> 'Data_UnassignedOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        schema = Schema_UnassignedOption.unpack(data, length)  # type: Schema_UnassignedOption
        self.__header__.options.append(schema)

        opt = Data_UnassignedOption(
            type=code,
            action=acts,
            change=cflg,
            length=schema.len + 2,
            data=schema.data,
        )
        return opt

    def _read_opt_pad(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                      data: 'bytes', length: 'int', option: 'Option') -> 'Data_PadOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``code`` is **NOT** ``0`` or ``1``.

        """
        if code not in (Enum_Option.Pad1, Enum_Option.PadN):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.Pad1 and clen != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.PadN and clen == 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        schema = Schema_PadOption.unpack(data)  # type: Schema_PadOption
        self.__header__.options.append(schema)

        if code == Enum_Option.Pad1:
            _size = 1
        else:
            _size = schema.len + 2

        opt = Data_PadOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size,
        )
        return opt

    def _read_opt_tun(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                      data: 'bytes', length: 'int', option: 'Option') -> 'Data_TunnelEncapsulationLimitOption':  # pylint: disable=unused-argument
        """Read HOPOPT Tunnel Encapsulation Limit option.

        Structure of HOPOPT Tunnel Encapsulation Limit option [:rfc:`2473`]:

        .. code-block:: text

              Option Type     Opt Data Len   Opt Data Len
            0 1 2 3 4 5 6 7
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |0 0 0 0 0 1 0 0|       1       | Tun Encap Lim |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: option type value
            acts: unknown option action value
            cflg: change flag value
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.tun.length`` is **NOT** ``1``.

        """
        if clen != 1:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        schema = Schema_TunnelEncapsulationLimitOption.unpack(data)  # type: Schema_TunnelEncapsulationLimitOption
        self.__header__.options.append(schema)

        opt = Data_TunnelEncapsulationLimitOption(
            type=code,
            action=acts,
            change=cflg,
            length=schema.len + 2,
            limit=schema.limit,
        )
        return opt

    def _read_opt_ra(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                     data: 'bytes', length: 'int', option: 'Option') -> 'Data_RouterAlertOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.tun.length`` is **NOT** ``2``.

        """
        _size = self._read_unpack(1)
        if _size != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        schema = Schema_RouterAlertOption.unpack(data, length)  # type: Schema_RouterAlertOption
        self.__header__.options.append(schema)

        opt = Data_RouterAlertOption(
            type=code,
            action=acts,
            change=cflg,
            length=schema.len + 2,
            value=schema.alert,
        )
        return opt

    def _read_opt_calipso(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                          data: 'bytes', length: 'int', option: 'Option') -> 'Data_CALIPSOOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        if clen < 8 and clen % 8 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        schema = Schema_CALIPSOOption.unpack(data, length)  # type: Schema_CALIPSOOption
        self.__header__.options.append(schema)

        if schema.cmpt_len % 2 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        opt = Data_CALIPSOOption(
            type=code,
            action=acts,
            change=cflg,
            length=schema.len + 2,
            domain=schema.domain,
            cmpt_len=schema.cmpt_len * 4,
            level=schema.level,
            checksum=schema.checksum,
        )

        if schema.cmpt_len > 0:
            opt.__update__([
                ('cmpt_bitmap', tuple(schema.bitmap)),
            ])
        return opt

    def _read_opt_smf_dpd(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                          data: 'bytes', length: 'int', option: 'Option') -> 'Data_SMFIdentificationBasedDPDOption | Data_SMFHashBasedDPDOption':  # pylint: disable=unused-argument,line-too-long
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        _size = self._read_unpack(1)
        _tidd = self._read_binary(1)

        if _tidd[0] == '0':
            _mode = Enum_SMFDPDMode.I_DPD
            _tidt = Enum_TaggerID.get(_tidd[1:4])
            _tidl = int(_tidd[4:], base=2)

            if _tidt == Enum_TaggerID.NULL:
                if _tidl != 0:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _iden = self._read_unpack(_size-1)

                opt = Data_SMFIdentificationBasedDPDOption(
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
            elif _tidt == Enum_TaggerID.IPv4:
                if _tidl != 3:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _tidf = self._read_fileng(4)
                _iden = self._read_unpack(_size-4)

                opt = Data_SMFIdentificationBasedDPDOption(
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
            elif _tidt == Enum_TaggerID.IPv6:
                if _tidl != 15:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _tidf = self._read_fileng(15)
                _iden = self._read_unpack(_size-15)

                opt = Data_SMFIdentificationBasedDPDOption(
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

                opt = Data_SMFIdentificationBasedDPDOption(
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
            _mode = Enum_SMFDPDMode.H_DPD
            _tidt = Enum_TaggerID.get(_tidd[1:4])
            _data = self._read_fileng(_size-1)

            opt = Data_SMFHashBasedDPDOption(  # type: ignore[assignment]
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

    def _read_opt_pdm(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                      data: 'bytes', length: 'int', option: 'Option') -> 'Data_PDMOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

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

        opt = Data_PDMOption(
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

    def _read_opt_qs(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                     data: 'bytes', length: 'int', option: 'Option') -> 'Data_QuickStartOption':  # pylint: disable=unused-argument  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

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

        _qsfn = Enum_QSFunction.get(_func)
        if _qsfn not in (Enum_QSFunction.Quick_Start_Request, Enum_QSFunction.Report_of_Approved_Rate):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        data = Data_QuickStartOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            func=_qsfn,
            rate=40000 * (2 ** _rate) / 1000,
            ttl=None if _func != Enum_QSFunction.Quick_Start_Request else datetime.timedelta(seconds=_ttlv),
            nounce=_qsnn,
        )

        return data

    def _read_opt_rpl(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                      data: 'bytes', length: 'int', option: 'Option') -> 'Data_RPLOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

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

        opt = Data_RPLOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            flags=Data_RPLFlags(
                down=bool(int(_flag[0], base=2)),
                rank_err=bool(int(_flag[1], base=2)),
                fwd_err=bool(int(_flag[2], base=2)),
            ),
            id=_rpld,
            rank=_rank,
        )

        return opt

    def _read_opt_mpl(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                      data: 'bytes', length: 'int', option: 'Option') -> 'Data_MPLOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

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

        _kind = Enum_SeedID.get(int(_smvr[:2], base=2))
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

        opt = Data_MPLOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            seed_type=_kind,
            flags=Data_MPLFlags(
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

    def _read_opt_ilnp(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                       data: 'bytes', length: 'int', option: 'Option') -> 'Data_ILNPOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        _size = self._read_unpack(1)
        _nval = self._read_fileng(_size)

        opt = Data_ILNPOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            nounce=_nval,
        )

        return opt

    def _read_opt_lio(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                      data: 'bytes', length: 'int', option: 'Option') -> 'Data_LineIdentificationOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        _size = self._read_unpack(1)
        _llen = self._read_unpack(1)
        _line = self._read_unpack(_llen)

        opt = Data_LineIdentificationOption(
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

    def _read_opt_jumbo(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                        data: 'bytes', length: 'int', option: 'Option') -> 'Data_JumboPayloadOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.jumbo.length`` is **NOT** ``4``.

        """
        _size = self._read_unpack(1)
        if _size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _jlen = self._read_unpack(4)

        opt = Data_JumboPayloadOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            payload_len=_jlen,
        )

        return opt

    def _read_opt_home(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                       data: 'bytes', length: 'int', option: 'Option') -> 'Data_HomeAddressOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``hopopt.jumbo.length`` is **NOT** ``16``.

        """
        _size = self._read_unpack(1)
        if _size != 16:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _addr = self._read_fileng(16)

        opt = Data_HomeAddressOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return opt

    def _read_opt_ip_dff(self, code: 'Enum_Option', acts: 'Enum_OptionAction', cflg: 'bool', clen: 'int', *,
                         data: 'bytes', length: 'int', option: 'Option') -> 'Data_IPDFFOption':  # pylint: disable=unused-argument
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
            clen: option data length
            data: option payload data (incl. type, length, content)
            length: option length (incl. type, length, content)
            option: extracted HOPOPT options

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

        opt = Data_IPDFFOption(
            type=code,
            action=acts,
            change=cflg,
            length=_size + 2,
            version=int(_verf[:2], base=2),
            flags=Data_DFFFlags(
                dup=bool(int(_verf[2], base=2)),
                ret=bool(int(_verf[3], base=2)),
            ),
            seq=_seqn,
        )

        return opt

    def _make_hopopt_options(self, options: 'list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes] | Option') -> 'tuple[list[Schema_Option | bytes], int]':
        """Make options for HOPOPT.

        Args:
            option: HOPOPT options

        Returns:
            Tuple of options and total length of options.

        """
        total_length = 0
        if isinstance(options, list):
            options_list = []  # type: list[Schema_Option | bytes]
            for schema in options:
                if isinstance(schema, bytes):
                    options_list.append(schema)
                    total_length += len(schema)
                elif isinstance(schema, Schema):
                    opt_packed = schema.pack()

                    options_list.append(opt_packed)
                    total_length += len(opt_packed)
                else:
                    code, args = cast('tuple[Enum_Option, dict[str, Any]]', schema)
                    name = self.__option__[code]  # type: str | tuple[OptionParser, OptionConstructor]
                    if isinstance(name, str):
                        meth_name = f'_make_opt_{name}'
                        meth = cast('OptionConstructor',
                                    getattr(self, meth_name, self._make_opt_none))
                    else:
                        meth = name[1]

                    data = meth(self, code, **args)
                    data_packed = data.pack()

                    options_list.append(data)
                    total_length += len(data_packed)
            return options_list, total_length

        options_list = []
        for code, opt in options.items(multi=True):
            name = self.__option__[code]
            if isinstance(name, str):
                meth_name = f'_make_opt_{name}'
                meth = cast('OptionConstructor',
                            getattr(self, meth_name, self._make_opt_none))
            else:
                meth = name[1]

            data = meth(self, code, opt)
            data_packed = data.pack()

            options_list.append(data)
            total_length += len(data_packed)
        return options_list, total_length

    def _make_opt_none(self, code: 'Enum_Option', opt: 'Optional[Data_UnassignedOption]' = None, *,
                       data: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_UnassignedOption':
        """Make HOPOPT unassigned option.

        Args:
            code: option type value
            opt: option data
            data: option payload in :obj:`bytes`
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            data = opt.data

        return Schema_UnassignedOption(
            type=code,
            len=len(data),
            data=data,
        )

    def _make_opt_pad(self, code: 'Enum_Option', opt: 'Optional[Data_PadOption]' = None, *,
                      length: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_PadOption':
        """Make HOPOPT pad option.

        Args:
            code: option type value
            opt: option data
            length: padding length
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if code == Enum_Option.Pad1 and length != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.PadN and length == 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        return Schema_PadOption(
            type=code,
            len=length,
        )

    def _make_opt_tun(self, code: 'Enum_Option', opt: 'Optional[Data_TunnelEncapsulationLimitOption]' = None, *,
                      limit: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_TunnelEncapsulationLimitOption':
        """Make HOPOPT tunnel encapsulation limit option.

        Args:
            code: option type value
            opt: option data
            limit: tunnel encapsulation limit
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            limit = opt.limit

        return Schema_TunnelEncapsulationLimitOption(
            type=code,
            len=1,
            limit=limit,
        )

    def _make_opt_ra(self, code: 'Enum_Option', opt: 'Optional[Data_RouterAlertOption]' = None, *,
                     alert: 'Enum_RouterAlert | StdlibEnum | AenumEnum | str | int' = Enum_RouterAlert.Datagram_contains_a_Multicast_Listener_Discovery_message,  # pylint: disable=line-too-long
                     alert_default: 'Optional[int]' = None,
                     alert_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                     alert_reversed: 'bool' = False,
                     **kwargs: 'Any') -> 'Schema_RouterAlertOption':
        """Make HOPOPT router alert option.

        Args:
            code: option type value
            opt: option data
            alert: router alert value
            alert_default: default value of router alert
            alert_namespace: namespace of router alert
            alert_reversed: reversed flag of router alert
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            value = opt.value
        else:
            value = self._make_index(alert, alert_default, namespace=alert_namespace,  # type: ignore[call-overload]
                                     reversed=alert_reversed, pack=False)

        return Schema_RouterAlertOption(
            type=code,
            len=2,
            alert=value,
        )

    def _make_opt_calipso(self, code: 'Enum_Option', opt: 'Optional[Data_CALIPSOOption]' = None, *,
                          domain: 'int' = 0,
                          level: 'int' = 0,
                          checksum: 'bytes' = b'\x00\x00',
                          bitmap: 'Optional[bytes]' = None,
                          **kwargs: 'Any') -> 'Schema_CALIPSOOption':
        """Make HOPOPT calipso option.

        Args:
            code: option type value
            opt: option data
            domain: CALIPSO domain of interpretation
            level: sensitivity level
            checksum: checksum of the option
            bitmap: compartment bitmap
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            domain = opt.domain
            cmpt_len = len(opt.cmpt_bitmap) if hasattr(opt, 'cmpt_bitmap') else 0
            level = opt.level
            checksum = opt.checksum
            bitmap = opt.cmpt_bitmap if hasattr(opt, 'cmpt_bitmap') else None

        return Schema_CALIPSOOption(
            type=code,
            len=8 + cmpt_len,
            domain=domain,
            cmpt_len=cmpt_len,
            level=level,
            checksum=checksum,
            bitmap=bitmap,
        )
