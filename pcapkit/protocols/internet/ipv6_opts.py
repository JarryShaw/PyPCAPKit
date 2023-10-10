# -*- coding: utf-8 -*-
"""IPv6-Opts - Destination Options for IPv6
==============================================

.. module:: pcapkit.protocols.internet.hopopt

:mod:`pcapkit.protocols.internet.ipv6_opts` contains
:class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`
only, which implements extractor for Destination Options
for IPv6 (IPv6-Opts) [*]_, whose structure is described
as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``opt.next``              Next Header
  1           8   ``opt.length``            Header Extensive Length
  2          16   ``opt.options``           Options
======= ========= =================== =================================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options

"""
import collections
import datetime
import ipaddress
import math
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.ipv6.option_action import OptionAction as Enum_OptionAction
from pcapkit.const.ipv6.qs_function import QSFunction as Enum_QSFunction
from pcapkit.const.ipv6.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.ipv6.seed_id import SeedID as Enum_SeedID
from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode as Enum_SMFDPDMode
from pcapkit.const.ipv6.tagger_id import TaggerID as Enum_TaggerID
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.field import NoValue
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.internet.ipv6_opts import CALIPSOOption as Data_CALIPSOOption
from pcapkit.protocols.data.internet.ipv6_opts import DFFFlags as Data_DFFFlags
from pcapkit.protocols.data.internet.ipv6_opts import HomeAddressOption as Data_HomeAddressOption
from pcapkit.protocols.data.internet.ipv6_opts import ILNPOption as Data_ILNPOption
from pcapkit.protocols.data.internet.ipv6_opts import IPDFFOption as Data_IPDFFOption
from pcapkit.protocols.data.internet.ipv6_opts import IPv6_Opts as Data_IPv6_Opts
from pcapkit.protocols.data.internet.ipv6_opts import JumboPayloadOption as Data_JumboPayloadOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    LineIdentificationOption as Data_LineIdentificationOption
from pcapkit.protocols.data.internet.ipv6_opts import MPLFlags as Data_MPLFlags
from pcapkit.protocols.data.internet.ipv6_opts import MPLOption as Data_MPLOption
from pcapkit.protocols.data.internet.ipv6_opts import PadOption as Data_PadOption
from pcapkit.protocols.data.internet.ipv6_opts import PDMOption as Data_PDMOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    QuickStartReportOption as Data_QuickStartReportOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    QuickStartRequestOption as Data_QuickStartRequestOption
from pcapkit.protocols.data.internet.ipv6_opts import RouterAlertOption as Data_RouterAlertOption
from pcapkit.protocols.data.internet.ipv6_opts import RPLFlags as Data_RPLFlags
from pcapkit.protocols.data.internet.ipv6_opts import RPLOption as Data_RPLOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    SMFHashBasedDPDOption as Data_SMFHashBasedDPDOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    SMFIdentificationBasedDPDOption as Data_SMFIdentificationBasedDPDOption
from pcapkit.protocols.data.internet.ipv6_opts import \
    TunnelEncapsulationLimitOption as Data_TunnelEncapsulationLimitOption
from pcapkit.protocols.data.internet.ipv6_opts import UnassignedOption as Data_UnassignedOption
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.ipv6_opts import CALIPSOOption as Schema_CALIPSOOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    HomeAddressOption as Schema_HomeAddressOption
from pcapkit.protocols.schema.internet.ipv6_opts import ILNPOption as Schema_ILNPOption
from pcapkit.protocols.schema.internet.ipv6_opts import IPDFFOption as Schema_IPDFFOption
from pcapkit.protocols.schema.internet.ipv6_opts import IPv6_Opts as Schema_IPv6_Opts
from pcapkit.protocols.schema.internet.ipv6_opts import \
    JumboPayloadOption as Schema_JumboPayloadOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    LineIdentificationOption as Schema_LineIdentificationOption
from pcapkit.protocols.schema.internet.ipv6_opts import MPLOption as Schema_MPLOption
from pcapkit.protocols.schema.internet.ipv6_opts import PadOption as Schema_PadOption
from pcapkit.protocols.schema.internet.ipv6_opts import PDMOption as Schema_PDMOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    QuickStartReportOption as Schema_QuickStartReportOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    QuickStartRequestOption as Schema_QuickStartRequestOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    RouterAlertOption as Schema_RouterAlertOption
from pcapkit.protocols.schema.internet.ipv6_opts import RPLOption as Schema_RPLOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    SMFHashBasedDPDOption as Schema_SMFHashBasedDPDOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    SMFIdentificationBasedDPDOption as Schema_SMFIdentificationBasedDPDOption
from pcapkit.protocols.schema.internet.ipv6_opts import \
    TunnelEncapsulationLimitOption as Schema_TunnelEncapsulationLimitOption
from pcapkit.protocols.schema.internet.ipv6_opts import UnassignedOption as Schema_UnassignedOption
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import timedelta
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, Callable, DefaultDict, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.ipv6_opts import Option as Data_Option
    from pcapkit.protocols.data.internet.ipv6_opts import QuickStartOption as Data_QuickStartOption
    from pcapkit.protocols.data.internet.ipv6_opts import SMFDPDOption as Data_SMFDPDOption
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.internet.ipv6_opts import Option as Schema_Option
    from pcapkit.protocols.schema.internet.ipv6_opts import \
        QuickStartOption as Schema_QuickStartOption
    from pcapkit.protocols.schema.internet.ipv6_opts import SMFDPDOption as Schema_SMFDPDOption

    Option = OrderedMultiDict[Enum_Option, Data_Option]
    OptionParser = Callable[[Schema_Option, NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[[Enum_Option,
                                  DefaultArg(Optional[Data_Option]), KwArg(Any)], Schema_Option]

__all__ = ['IPv6_Opts']


class IPv6_Opts(Internet[Data_IPv6_Opts, Schema_IPv6_Opts],
                schema=Schema_IPv6_Opts, data=Data_IPv6_Opts):
    """This class implements Destination Options for IPv6.

    This class currently supports parsing of the following IPv6 destination
    options, which are registered in the
    :attr:`self.__option__ <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
         - Option Constructor
       * - :attr:`~pcapkit.const.ipv6.option.Option.Pad1`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_pad`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_pad`
       * - :attr:`~pcapkit.const.ipv6.option.Option.PadN`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_pad`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_pad`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Tunnel_Encapsulation_Limit`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_tun`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_tun`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Router_Alert`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_ra`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_ra`
       * - :attr:`~pcapkit.const.ipv6.option.Option.CALIPSO`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_calipso`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_calipso`
       * - :attr:`~pcapkit.const.ipv6.option.Option.SMF_DPD`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_smf_dpd`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_smf_dpd`
       * - :attr:`~pcapkit.const.ipv6.option.Option.PDM`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_pdm`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_pdm`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Quick_Start`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_qs`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_qs`
       * - :attr:`~pcapkit.const.ipv6.option.Option.RPL_Option_0x63`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_rpl`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_rpl`
       * - :attr:`~pcapkit.const.ipv6.option.Option.MPL_Option`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_mpl`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_mpl`
       * - :attr:`~pcapkit.const.ipv6.option.Option.ILNP_Nonce`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_ilnp`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_ilnp`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Line_Identification_Option`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_lio`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_lio`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Jumbo_Payload`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_jumbo`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_jumbo`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Home_Address`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_home`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_home`
       * - :attr:`~pcapkit.const.ipv6.option.Option.IP_DFF`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._read_opt_ip_dff`
         - :meth:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_ip_dff`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_Option, str | tuple[OptionParser, OptionConstructor]]: Option
    #: code to method mapping, c.f. :meth:`_read_ipv6_opts` and/or
    #: :meth:`_make_ipv6_opts`. Method names are expected to be referred to the
    #: class by ``_read_opt_${name}`` and/or ``_make_opt_${name}``, and if such
    #: name not found, the value should then be a method that can parse the
    #: option by itself.
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
    def name(self) -> 'Literal["Destination Options for IPv6"]':
        """Name of current protocol."""
        return 'Destination Options for IPv6'

    @property
    def alias(self) -> 'Literal["IPv6-Opts"]':
        """Acronym of corresponding protocol."""
        return 'IPv6-Opts'

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

    def read(self, length: 'Optional[int]' = None, *, extension: 'bool' = False,  # pylint: disable=arguments-differ
             **kwargs: 'Any') -> 'Data_IPv6_Opts':  # pylint: disable=unused-argument
        """Read Destination Options for IPv6.

        Structure of IPv6-Opts header [:rfc:`8200`]:

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

        ipv6_opts = Data_IPv6_Opts(
            next=schema.next,
            length=(schema.len + 1) * 8,
            options=self._read_ipv6_opts(schema.len * 8 + 6),
        )

        if extension:
            return ipv6_opts
        return self._decode_next_layer(ipv6_opts, schema.next, length - ipv6_opts.length)

    def make(self,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             options: 'Optional[list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes] | Option]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_IPv6_Opts':
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
        next_value = self._make_index(next, next_default, namespace=next_namespace,
                                      reversed=next_reversed, pack=False)

        if options is not None:
            options_value, total_length = self._make_ipv6_opts(options)
            length = math.ceil((total_length - 6) / 8)
        else:
            options_value, length = [], 0

        return Schema_IPv6_Opts(
            next=next_value,  # type: ignore[arg-type]
            len=length,
            options=options_value,
            payload=payload,
        )

    @classmethod
    def register_option(cls, code: 'Enum_Option', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register an option parser.

        Args:
            code: IPv6-Opts option code.
            meth: Method name or callable to parse and/or construct the option.

        """
        if code in cls.__option__:
            warn(f'option {code} already registered, overwriting', RegistryWarning)
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
            For construction argument, please refer to :meth:`self.make <IPv6_Opts.make>`.

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
        return Enum_TransType.IPv6_Opts  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPv6_Opts') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'next': data.next,
            'options': data.options,
            'payload': cls._make_payload(data),
        }

    def _read_opt_type(self, kind: 'int') -> 'tuple[int, bool]':
        """Read option type field.

        Arguments:
            kind (int): option kind value

        Returns:
            Extracted IPv6-Opts option type field information (unknown option
            action and change flag), c.f. [:rfc:`8200#section-4.2`].

        """
        bin_ = bin(kind)[2:].zfill(8)
        return int(bin_[:2], base=2), bool(int(bin_[2], base=2))

    def _read_ipv6_opts(self, length: 'int') -> 'Option':
        """Read IPv6-Opts options.

        Positional arguments:
            length: length of options

        Returns:
            Extracted IPv6-Opts options

        Raises:
            ProtocolError: If the threshold is **NOT** matching.

        """
        counter = 0                   # length of read options
        options = OrderedMultiDict()  # type: Option

        for schema in self.__header__.options:
            dscp = schema.type
            name = self.__option__[dscp]

            if isinstance(name, str):
                meth_name = f'_read_opt_{name}'
                meth = cast('OptionParser',
                            getattr(self, meth_name, self._read_opt_none))
            else:
                meth = name[0]
            data = meth(schema, options=options)

            # record option data
            options.add(dscp, data)
            counter += len(schema)

        # check threshold
        if counter != length:
            raise ProtocolError('IPv6-Opts: invalid format')
        return options

    def _read_opt_none(self, schema: 'Schema_UnassignedOption', option: 'Option') -> 'Data_UnassignedOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts unassigned options.

        Structure of IPv6-Opts unassigned options [:rfc:`8200`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
           |  Option Type  |  Opt Data Len |  Option Data
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

        Args:
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        """
        opt = Data_UnassignedOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            data=schema.data,
        )
        return opt

    def _read_opt_pad(self, schema: 'Schema_PadOption', option: 'Option') -> 'Data_PadOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts padding options.

        Structure of IPv6-Opts padding options [:rfc:`8200`]:

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
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``code`` is **NOT** ``0`` or ``1``.

        """
        code, clen = schema.type, schema.len

        if code not in (Enum_Option.Pad1, Enum_Option.PadN):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.Pad1 and clen != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.PadN and clen == 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        if code == Enum_Option.Pad1:
            _size = 1
        else:
            _size = schema.len + 2

        opt = Data_PadOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=_size,
        )
        return opt

    def _read_opt_tun(self, schema: 'Schema_TunnelEncapsulationLimitOption', option: 'Option') -> 'Data_TunnelEncapsulationLimitOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Tunnel Encapsulation Limit option.

        Structure of IPv6-Opts Tunnel Encapsulation Limit option [:rfc:`2473`]:

        .. code-block:: text

              Option Type     Opt Data Len   Opt Data Len
            0 1 2 3 4 5 6 7
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |0 0 0 0 0 1 0 0|       1       | Tun Encap Lim |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``ipv6_opts.tun.length`` is **NOT** ``1``.

        """
        if schema.len != 1:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_TunnelEncapsulationLimitOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            limit=schema.limit,
        )
        return opt

    def _read_opt_ra(self, schema: 'Schema_RouterAlertOption', option: 'Option') -> 'Data_RouterAlertOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Router Alert option.

        Structure of IPv6-Opts Router Alert option [:rfc:`2711`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |0 0 0|0 0 1 0 1|0 0 0 0 0 0 1 0|        Value (2 octets)       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``ipv6_opts.tun.length`` is **NOT** ``2``.

        """
        if schema.len != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_RouterAlertOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            value=schema.alert,
        )
        return opt

    def _read_opt_calipso(self, schema: 'Schema_CALIPSOOption', option: 'Option') -> 'Data_CALIPSOOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Common Architecture Label IPv6 Security Option (CALIPSO) option.

        Structure of IPv6-Opts CALIPSO option [:rfc:`5570`]:

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
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        if schema.len < 8 and schema.len % 8 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')
        if schema.cmpt_len % 2 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_CALIPSOOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
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

    def _read_opt_smf_dpd(self, schema: 'Schema_SMFDPDOption', option: 'Option') -> 'Data_SMFDPDOption':  # pylint: disable=unused-argument,line-too-long
        """Read IPv6-Opts Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) option.

        Structure of IPv6-Opts ``SMF_DPD`` option [:rfc:`6621`]:

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
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        mode = schema.mode
        if mode == Enum_SMFDPDMode.I_DPD:  # I-DPD mode
            if TYPE_CHECKING:
                schema = cast('Schema_SMFIdentificationBasedDPDOption', schema)

            tid_type = Enum_TaggerID.get(schema.info['type'])
            tid_len = schema.info['len']

            opt = Data_SMFIdentificationBasedDPDOption(
                type=schema.type,
                action=Enum_OptionAction.get(schema.type >> 6),
                change=bool(schema.type & 0b00100000),
                length=schema.len + 2,
                dpd_type=mode,
                tid_type=tid_type,
                tid_len=tid_len,
                tid=schema.tid,
                id=schema.id,
            )  # type: Data_SMFDPDOption
        elif mode == Enum_SMFDPDMode.H_DPD:  # H-DPD mode
            if TYPE_CHECKING:
                schema = cast('Schema_SMFHashBasedDPDOption', schema)

            opt = Data_SMFHashBasedDPDOption(
                type=schema.type,
                action=Enum_OptionAction.get(schema.type >> 6),
                change=bool(schema.type & 0b00100000),
                length=schema.len + 2,
                dpd_type=mode,
                hav=schema.hav,
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid DPD mode: {mode}')
        return opt

    def _read_opt_pdm(self, schema: 'Schema_PDMOption', option: 'Option') -> 'Data_PDMOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Performance and Diagnostic Metrics (PDM) option.

        Structure of IPv6-Opts PDM option [:rfc:`8250`]:

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
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``ipv6_opts.pdm.length`` is **NOT** ``10``.

        """
        if schema.len != 10:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_PDMOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            scaledtlr=schema.scaledtlr,
            scaledtls=schema.scaledtls,
            psntp=schema.psntp,
            psnlr=schema.psnlr,
            deltatlr=schema.deltatlr << schema.scaledtlr,
            deltatls=schema.deltatls << schema.scaledtls,
        )
        return opt

    def _read_opt_qs(self, schema: 'Schema_QuickStartOption', option: 'Option') -> 'Data_QuickStartOption':  # pylint: disable=unused-argument  # pylint: disable=unused-argument
        """Read IPv6-Opts Quick Start option.

        Structure of IPv6-Opts Quick-Start option [:rfc:`4782`]:

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
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        if schema.len != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        func = schema.func
        if func == Enum_QSFunction.Quick_Start_Request:
            schema_req = cast('Schema_QuickStartRequestOption', schema)

            rate = schema_req.flags['rate']
            opt = Data_QuickStartRequestOption(
                type=schema.type,
                action=Enum_OptionAction.get(schema.type >> 6),
                change=bool(schema.type & 0b00100000),
                length=schema_req.len + 2,
                func=func,
                rate=40000 * (2 ** rate) / 1000 if rate > 0 else 0,
                ttl=datetime.timedelta(seconds=schema_req.ttl),
                nonce=schema_req.nonce['nonce'],
            )  # type: Data_QuickStartOption
        elif func == Enum_QSFunction.Report_of_Approved_Rate:
            schema_rep = cast('Schema_QuickStartReportOption', schema)

            rate = schema_rep.flags['rate']
            opt = Data_QuickStartReportOption(
                type=schema.type,
                action=Enum_OptionAction.get(schema.type >> 6),
                change=bool(schema.type & 0b00100000),
                length=schema_rep.len + 2,
                func=func,
                rate=40000 * (2 ** rate) / 1000 if rate > 0 else 0,
                nonce=schema_rep.nonce['nonce'],
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] unknown QS function: {func}')
        return opt

    def _read_opt_rpl(self, schema: 'Schema_RPLOption', option: 'Option') -> 'Data_RPLOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Routing Protocol for Low-Power and Lossy Networks (RPL) option.

        Structure of IPv6-Opts RPL option [:rfc:`6553`]:

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
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``ipv6_opts.rpl.length`` is **NOT** ``4``.

        """
        if schema.len != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_RPLOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            flags=Data_RPLFlags(
                down=bool(schema.flags['down']),
                rank_err=bool(schema.flags['rank_err']),
                fwd_err=bool(schema.flags['fwd_err']),
            ),
            id=schema.id,
            rank=schema.rank,
        )
        return opt

    def _read_opt_mpl(self, schema: 'Schema_MPLOption', option: 'Option') -> 'Data_MPLOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Multicast Protocol for Low-Power and Lossy Networks (MPL) option.

        Structure of IPv6-Opts MPL option [:rfc:`7731`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  |  Opt Data Len |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | S |M|V|  rsv  |   sequence    |      seed-id (optional)       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        kind = Enum_SeedID.get(schema.flags['type'])
        clen = schema.len

        if schema.len < 2:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')
        if kind == kind.IPV6_SOURCE_ADDRESS:
            if clen != 2:
                raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid seed-id length: {clen - 2}')
        elif kind == kind.SEEDID_16_BIT_UNSIGNED_INTEGER:
            if clen != 4:
                raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid seed-id length: {clen - 2}')
        elif kind == kind.SEEDID_64_BIT_UNSIGNED_INTEGER:
            if clen != 10:
                raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid seed-id length: {clen - 2}')
        elif kind == kind.SEEDID_128_BIT_UNSIGNED_INTEGER:
            if clen != 18:
                raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid seed-id length: {clen - 2}')
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid seed-id type: {kind}')

        opt = Data_MPLOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            seed_type=kind,
            flags=Data_MPLFlags(
                max=bool(schema.flags['max']),
                drop=bool(schema.flags['drop']),
            ),
            seq=schema.seq,
            seed_id=schema.seed if schema.seed is not NoValue else None,  # type: ignore[comparison-overlap]
        )
        return opt

    def _read_opt_ilnp(self, schema: 'Schema_ILNPOption', option: 'Option') -> 'Data_ILNPOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Identifier-Locator Network Protocol (ILNP) Nonce option.

        Structure of IPv6-Opts ILNP Nonce option [:rfc:`6744`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Next Header   | Hdr Ext Len   |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                         Nonce Value                           /
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        """
        opt = Data_ILNPOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            nonce=schema.nonce,
        )
        return opt

    def _read_opt_lio(self, schema: 'Schema_LineIdentificationOption', option: 'Option') -> 'Data_LineIdentificationOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Line-Identification option.

        Structure of IPv6-Opts Line-Identification option [:rfc:`6788`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | LineIDLen     |     Line ID...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        """
        opt = Data_LineIdentificationOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            line_id_len=schema.id_len,
            line_id=schema.id,
        )
        return opt

    def _read_opt_jumbo(self, schema: 'Schema_JumboPayloadOption', option: 'Option') -> 'Data_JumboPayloadOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Jumbo Payload option.

        Structure of IPv6-Opts Jumbo Payload option [:rfc:`2675`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  |  Opt Data Len |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                     Jumbo Payload Length                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``ipv6_opts.jumbo.length`` is **NOT** ``4``.

        """
        if schema.len != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_JumboPayloadOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            jumbo_len=schema.jumbo_len,
        )
        return opt

    def _read_opt_home(self, schema: 'Schema_HomeAddressOption', option: 'Option') -> 'Data_HomeAddressOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Home Address option.

        Structure of IPv6-Opts Home Address option [:rfc:`6275`]:

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
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``ipv6_opts.jumbo.length`` is **NOT** ``16``.

        """
        if schema.len != 16:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_HomeAddressOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            address=schema.addr,
        )
        return opt

    def _read_opt_ip_dff(self, schema: 'Schema_IPDFFOption', option: 'Option') -> 'Data_IPDFFOption':  # pylint: disable=unused-argument
        """Read IPv6-Opts Depth-First Forwarding (``IP_DFF``) option.

        Structure of IPv6-Opts ``IP_DFF`` option [:rfc:`6971`]:

        .. code-block:: text

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |  Hdr Ext Len  |  OptTypeDFF   | OptDataLenDFF |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |VER|D|R|0|0|0|0|        Sequence Number        |      Pad1     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            option: extracted IPv6-Opts options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``ipv6_opts.ip_dff.length`` is **NOT** ``2``.

        """
        if schema.len != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_IPDFFOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=schema.len + 2,
            version=schema.flags['ver'],
            flags=Data_DFFFlags(
                dup=bool(schema.flags['dup']),
                ret=bool(schema.flags['ret']),
            ),
            seq=schema.seq,
        )
        return opt

    def _make_ipv6_opts(self, options: 'list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes] | Option') -> 'tuple[list[Schema_Option | bytes], int]':
        """Make options for IPv6-Opts.

        Args:
            option: IPv6-Opts options

        Returns:
            Tuple of options and total length of options.

        """
        total_length = 0
        if isinstance(options, list):
            options_list = []  # type: list[Schema_Option | bytes]
            for schema in options:
                if isinstance(schema, bytes):
                    code = Enum_Option.get(schema[0])
                    if code in (Enum_Option.Pad1, Enum_Option.PadN):  # ignore padding options by default
                        continue

                    opt = schema  # type: bytes | Schema_Option
                    opt_len = len(schema)
                elif isinstance(schema, Schema):
                    code = schema.type
                    if code in (Enum_Option.Pad1, Enum_Option.PadN):  # ignore padding options by default
                        continue

                    opt = schema
                    opt_len = len(schema.pack())
                else:
                    code, args = cast('tuple[Enum_Option, dict[str, Any]]', schema)
                    if code in (Enum_Option.Pad1, Enum_Option.PadN):  # ignore padding options by default
                        continue

                    name = self.__option__[code]  # type: str | tuple[OptionParser, OptionConstructor]
                    if isinstance(name, str):
                        meth_name = f'_make_opt_{name}'
                        meth = cast('OptionConstructor',
                                    getattr(self, meth_name, self._make_opt_none))
                    else:
                        meth = name[1]

                    opt = meth(code, **args)
                    opt_len = len(opt.pack())

                options_list.append(opt)
                total_length += opt_len

                # force alignment to 8 octets
                if opt_len % 8:
                    pad_len = 8 - (opt_len % 8)
                    if pad_len in (1, 2):
                        pad_opt = self._make_opt_pad(Enum_Option.Pad1, length=0)  # type: ignore[arg-type]
                    else:
                        pad_opt = self._make_opt_pad(Enum_Option.PadN, length=pad_len)  # type: ignore[arg-type]

                    options_list.append(pad_opt)
                    if pad_len == 2:  # need 2 Pad1 options
                        options_list.append(pad_opt)
                    total_length += pad_len
            return options_list, total_length

        options_list = []
        for code, option in options.items(multi=True):
            # ignore padding options by default
            if code in (Enum_Option.Pad1, Enum_Option.PadN):
                continue

            name = self.__option__[code]
            if isinstance(name, str):
                meth_name = f'_make_opt_{name}'
                meth = cast('OptionConstructor',
                            getattr(self, meth_name, self._make_opt_none))
            else:
                meth = name[1]

            opt = meth(code, option)
            opt_len = len(opt.pack())

            options_list.append(opt)
            total_length += opt_len

            # force alignment to 8 octets
            if opt_len % 8:
                pad_len = 8 - (opt_len % 8)
                if pad_len in (1, 2):
                    pad_opt = self._make_opt_pad(Enum_Option.Pad1, length=0)  # type: ignore[arg-type]
                else:
                    pad_opt = self._make_opt_pad(Enum_Option.PadN, length=pad_len)  # type: ignore[arg-type]

                options_list.append(pad_opt)
                if pad_len == 2:  # need 2 Pad1 options
                    options_list.append(pad_opt)
                total_length += pad_len
        return options_list, total_length

    def _make_opt_none(self, code: 'Enum_Option', opt: 'Optional[Data_UnassignedOption]' = None, *,
                       data: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_UnassignedOption':
        """Make IPv6-Opts unassigned option.

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
        """Make IPv6-Opts pad option.

        Args:
            code: option type value
            opt: option data
            length: padding length
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if code == Enum_Option.Pad1 and length != 0:
            #raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            warn(f'{self.alias}: [OptNo {code}] invalid format', ProtocolWarning)
            code = Enum_Option.PadN  # type: ignore[assignment]
        if code == Enum_Option.PadN and length == 0:
            #raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            warn(f'{self.alias}: [OptNo {code}] invalid format', ProtocolWarning)
            code = Enum_Option.Pad1  # type: ignore[assignment]

        return Schema_PadOption(
            type=code,
            len=length,
        )

    def _make_opt_tun(self, code: 'Enum_Option', opt: 'Optional[Data_TunnelEncapsulationLimitOption]' = None, *,
                      limit: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_TunnelEncapsulationLimitOption':
        """Make IPv6-Opts tunnel encapsulation limit option.

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
        """Make IPv6-Opts router alert option.

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
            value = self._make_index(alert, alert_default, namespace=alert_namespace,  # type: ignore[assignment]
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
        """Make IPv6-Opts calipso option.

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

    def _make_opt_smf_dpd(self, code: 'Enum_Option', opt: 'Optional[Data_SMFIdentificationBasedDPDOption | Data_SMFHashBasedDPDOption]' = None, *,
                          mode: 'Enum_SMFDPDMode | StdlibEnum | AenumEnum | str | int' = Enum_SMFDPDMode.I_DPD,
                          mode_default: 'Optional[int]' = None,
                          mode_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                          mode_reversed: 'bool' = False,
                          tid: 'Optional[bytes | IPv4Address | IPv6Address]' = None,
                          id: 'bytes' = b'',
                          hav: 'bytes' = b'',
                          **kwargs: 'Any') -> 'Schema_SMFDPDOption':
        """Make IPv6-Opts SMF DPD option.

        Args:
            code: option type value
            opt: option data
            mode: DPD mode
            mode_default: default value of DPD mode
            mode_namespace: namespace of DPD mode
            mode_reversed: reversed flag of DPD mode
            tid: Tagger ID
            id: identifier
            hav: hash assist value (HAV)
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            dpd_type = opt.dpd_type
            tid = getattr(opt, 'tid', None)
            id = getattr(opt, 'id', b'')
            hav = getattr(opt, 'hav', b'')

        dpd_type = self._make_index(mode, mode_default, namespace=mode_namespace,  # type: ignore[assignment]
                                    reversed=mode_reversed, pack=False)

        if dpd_type == Enum_SMFDPDMode.I_DPD:
            if tid is None:
                schema = Schema_SMFIdentificationBasedDPDOption(
                    type=code,
                    len=1 + len(id),
                    info={
                        'mode': 0,
                        'type': Enum_TaggerID.NULL,
                        'len': 0,
                    },
                    tid=None,
                    id=id,
                )  # type: Schema_SMFDPDOption
            elif isinstance(tid, bytes):
                tid_len = len(tid)
                if tid_len == 0:
                    tid_type = Enum_TaggerID.NULL
                else:
                    try:
                        tid_ip_ver = ipaddress.ip_address(tid).version
                        if tid_ip_ver == 4:
                            tid_type = Enum_TaggerID.IPv4
                        elif tid_ip_ver == 6:
                            tid_type = Enum_TaggerID.IPv6
                        else:
                            tid_type = Enum_TaggerID.DEFAULT  # type: ignore[unreachable]
                    except ValueError:
                        tid_type = Enum_TaggerID.DEFAULT

                schema = Schema_SMFIdentificationBasedDPDOption(
                    type=code,
                    len=1 + tid_len + len(id),
                    info={
                        'mode': 0,
                        'type': tid_type,
                        'len': tid_len - 1,
                    },
                    tid=tid,
                    id=id,
                )
            else:
                tid_ver = tid.version
                if tid_ver == 4:
                    tid_type = Enum_TaggerID.IPv4
                    tid_len = 4
                elif tid_ver == 6:
                    tid_type = Enum_TaggerID.IPv6
                    tid_len = 16
                else:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid TaggerID version: {tid_ver}')

                schema = Schema_SMFIdentificationBasedDPDOption(
                    type=code,
                    len=1 + tid_len + len(id),
                    info={
                        'mode': 0,
                        'type': tid_type,
                        'len': tid_len - 1,
                    },
                    tid=tid.packed,
                    id=id,
                )
        elif dpd_type == Enum_SMFDPDMode.H_DPD:
            hav_ba = bytearray(hav)
            hav_ba[0] = hav[0] | 0x80

            schema = Schema_SMFHashBasedDPDOption(
                type=code,
                len=len(hav),
                hav=bytes(hav_ba),
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid DPD type: {dpd_type}')
        return schema

    def _make_opt_pdm(self, code: 'Enum_Option', opt: 'Optional[Data_PDMOption]' = None, *,
                      psntp: 'int' = 0,
                      psnlr: 'int' = 0,
                      deltatlr: 'int' = 0,
                      deltatls: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_PDMOption':
        """Make IPv6-Opts PDM option.

        Args:
            code: option type value
            opt: option data
            psntp: packet sequence number (PSN) this packet
            psnlr: packet sequence number (PSN) last received
            deltatlr: delta time last received (in attoseconds)
            deltatls: delta time last sent (in attoseconds)
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            psntp = opt.psntp
            psnlr = opt.psnlr
            deltatlr = opt.deltatlr
            deltatls = opt.deltatls

        dtlr_bl = deltatlr.bit_length()
        scale_dtlr = dtlr_bl - 16 if dtlr_bl > 16 else 0
        if scale_dtlr > 255:
            warn(f'{self.alias}: [OptNo {code}] too large delta time last received: {deltatlr} (scaled: {scale_dtlr})',
                 ProtocolWarning)

        dtls_bl = deltatls.bit_length()
        scale_dtls = dtls_bl - 16 if dtls_bl > 16 else 0
        if scale_dtls > 255:
            warn(f'{self.alias}: [OptNo {code}] too large delta time last sent: {deltatls} (scaled: {scale_dtls})',
                 ProtocolWarning)

        return Schema_PDMOption(
            type=code,
            len=10,
            scaledtlr=scale_dtlr,
            scaledtls=scale_dtls,
            psntp=psntp,
            psnlr=psnlr,
            deltatlr=deltatlr >> scale_dtlr,
            deltatls=deltatls >> scale_dtls,
        )

    def _make_opt_qs(self, code: 'Enum_Option', opt: 'Optional[Data_QuickStartOption]' = None, *,
                     func: 'Enum_QSFunction | StdlibEnum | AenumEnum | str | int' = Enum_QSFunction.Quick_Start_Request,
                     func_default: 'Optional[int]' = None,
                     func_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,   # pylint: disable=line-too-long
                     func_reversed: 'bool' = False,
                     rate: 'int' = 0,
                     ttl: 'timedelta | int' = 0,
                     nonce: 'int' = 0,
                     **kwargs: 'Any') -> 'Schema_QuickStartOption':
        """Make IPv6-Opts QS option.

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
        if opt is not None:
            func_enum = opt.func
            rate = opt.rate
            ttl = getattr(opt, 'ttl', 0)
            nonce = getattr(opt, 'nonce', 0)
        else:
            func_enum = self._make_index(func, func_default, namespace=func_namespace,  # type: ignore[assignment]
                                         reversed=func_reversed, pack=False)
        rate_val = math.floor(math.log2(rate * 1000 / 40000)) if rate > 0 else 0

        if func_enum == Enum_QSFunction.Quick_Start_Request:
            ttl_value = ttl if isinstance(ttl, int) else math.floor(ttl.total_seconds())

            return Schema_QuickStartRequestOption(
                type=code,
                len=6,
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
                type=code,
                len=6,
                flags={
                    'func': func_enum,
                    'rate': rate_val,
                },
                nonce={
                    'nonce': nonce,
                },
            )
        raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid QS function: {func_enum}')

    def _make_opt_rpl(self, code: 'Enum_Option', opt: 'Optional[Data_RPLOption]' = None, *,
                      down: 'bool' = False,
                      rank_err: 'bool' = False,
                      fwd_err: 'bool' = False,
                      id: 'int' = 0,
                      rank: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_RPLOption':
        """Make IPv6-Opts RPL option.

        Args:
            code: option type value
            opt: option data
            down: down flag
            rank_err: rank error flag
            fwd_err: forwarding error flag
            id: RPL instance ID
            rank: sender rank
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            down = opt.flags.down
            rank_err = opt.flags.rank_err
            fwd_err = opt.flags.fwd_err
            id = opt.id
            rank = opt.rank

        return Schema_RPLOption(
            type=code,
            len=4,
            flags={
                'down': down,
                'rank_err': rank_err,
                'fwd_err': fwd_err,
            },
            id=id,
            rank=rank,
        )

    def _make_opt_mpl(self, code: 'Enum_Option', opt: 'Optional[Data_MPLOption]' = None, *,
                      max: 'bool' = False,
                      drop: 'bool' = False,
                      seq: 'int' = 0,
                      seed: 'Optional[int]' = None,
                      **kwargs: 'Any') -> 'Schema_MPLOption':
        """Make IPv6-Opts MPL option.

        Args:
            code: option type value
            opt: option data
            max: maximum sequence number flag
            drop: drop packet flag
            seq: MPL sequence number
            seed: MPL seed ID
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            max = opt.flags.max
            drop = opt.flags.drop
            seq = opt.seq
            seed = opt.seed_id

        if seed is None:
            kind = Enum_SeedID.IPV6_SOURCE_ADDRESS
            clen = 2
        else:
            seed_bl = seed.bit_length()
            if seed_bl <= 16:
                kind = Enum_SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER
                clen = 4
            elif seed_bl <= 64:
                kind = Enum_SeedID.SEEDID_64_BIT_UNSIGNED_INTEGER
                clen = 10
            elif seed_bl <= 128:
                kind = Enum_SeedID.SEEDID_128_BIT_UNSIGNED_INTEGER
                clen = 18
            else:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] too large MPL seed ID: {seed}')

        return Schema_MPLOption(
            type=code,
            len=clen,
            flags={
                'type': kind,
                'max': max,
                'drop': drop,
            },
            seq=seq,
            seed=seed,
        )

    def _make_opt_ilnp(self, code: 'Enum_Option', opt: 'Optional[Data_ILNPOption]' = None, *,
                       nonce: 'int' = 0,
                       **kwargs: 'Any') -> 'Schema_ILNPOption':
        """Make IPv6-Opts ILNP option.

        Args:
            code: option type value
            opt: option data
            nonce: ILNP nonce value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            nonce = opt.nonce

        return Schema_ILNPOption(
            type=code,
            len=math.ceil(nonce.bit_length() // 8),
            nonce=nonce,
        )

    def _make_opt_lio(self, code: 'Enum_Option', opt: 'Optional[Data_LineIdentificationOption]' = None, *,
                      id: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_LineIdentificationOption':
        """Make IPv6-Opts LIO option.

        Args:
            code: option type value
            opt: option data
            id: line ID value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            id = opt.line_id

        return Schema_LineIdentificationOption(
            type=code,
            len=len(id) + 1,
            id_len=len(id),
            id=id,
        )

    def _make_opt_jumbo(self, code: 'Enum_Option', opt: 'Optional[Data_JumboPayloadOption]' = None, *,
                        len: 'int' = 0,
                        **kwargs: 'Any') -> 'Schema_JumboPayloadOption':
        """Make IPv6-Opts Jumbo Payload option.

        Args:
            code: option type value
            opt: option data
            len: jumbo payload length
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            len = opt.jumbo_len

        return Schema_JumboPayloadOption(
            type=code,
            len=4,
            jumbo_len=len,
        )

    def _make_opt_home(self, code: 'Enum_Option', opt: 'Optional[Data_HomeAddressOption]' = None, *,
                       addr: 'IPv6Address | str | bytes | int' = '::',
                       **kwargs: 'Any') -> 'Schema_HomeAddressOption':
        """Make IPv6-Opts Home Address option.

        Args:
            code: option type value
            opt: option data
            addr: home address value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            addr = opt.address

        return Schema_HomeAddressOption(
            type=code,
            len=16,
            addr=addr,
        )

    def _make_opt_ip_dff(self, code: 'Enum_Option', opt: 'Optional[Data_IPDFFOption]' = None, *,
                         version: 'int' = 0,
                         dup: 'bool' = False,
                         ret: 'bool' = False,
                         seq: 'int' = 0,
                         **kwargs: 'Any') -> 'Schema_IPDFFOption':
        """Make IPv6-Opts IP DFF option.

        Args:
            code: option type value
            opt: option data
            version: DFF version
            dup: duplicate packet flag
            ret: return packet flag
            seq: DFF sequence number
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructured option schema.

        """
        if opt is not None:
            version = opt.version
            dup = opt.flags.dup
            ret = opt.flags.ret
            seq = opt.seq

        return Schema_IPDFFOption(
            type=code,
            len=2,
            flags={
                'ver': version,
                'dup': dup,
                'ret': ret,
            },
            seq=seq,
        )
