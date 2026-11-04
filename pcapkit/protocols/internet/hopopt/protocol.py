# -*- coding: utf-8 -*-
"""HOPOPT - IPv6 Hop-by-Hop Options
======================================

.. module:: pcapkit.protocols.internet.hopopt.protocol

:mod:`pcapkit.protocols.internet.hopopt.protocol` contains
:class:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT`
only, which implements the extractor for IPv6 Hop-by-Hop
Options header (HOPOPT) [*]_, whose structure is
described as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``hopopt.next``             Next Header
  1           8   ``hopopt.length``           Header Extension Length
  2          16   ``hopopt.options``          Options
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
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.schema.padding import pad_length
from pcapkit.corekit.sentinels import NO_VALUE
from pcapkit.protocols.internet.hopopt.data import HOPOPT as Data_HOPOPT
from pcapkit.protocols.internet.hopopt.data import CALIPSOOption as Data_CALIPSOOption
from pcapkit.protocols.internet.hopopt.data import DFFFlags as Data_DFFFlags
from pcapkit.protocols.internet.hopopt.data import HomeAddressOption as Data_HomeAddressOption
from pcapkit.protocols.internet.hopopt.data import ILNPOption as Data_ILNPOption
from pcapkit.protocols.internet.hopopt.data import IPDFFOption as Data_IPDFFOption
from pcapkit.protocols.internet.hopopt.data import JumboPayloadOption as Data_JumboPayloadOption
from pcapkit.protocols.internet.hopopt.data import \
    LineIdentificationOption as Data_LineIdentificationOption
from pcapkit.protocols.internet.hopopt.data import MPLFlags as Data_MPLFlags
from pcapkit.protocols.internet.hopopt.data import MPLOption as Data_MPLOption
from pcapkit.protocols.internet.hopopt.data import PadOption as Data_PadOption
from pcapkit.protocols.internet.hopopt.data import PDMOption as Data_PDMOption
from pcapkit.protocols.internet.hopopt.data import \
    QuickStartReportOption as Data_QuickStartReportOption
from pcapkit.protocols.internet.hopopt.data import \
    QuickStartRequestOption as Data_QuickStartRequestOption
from pcapkit.protocols.internet.hopopt.data import RouterAlertOption as Data_RouterAlertOption
from pcapkit.protocols.internet.hopopt.data import RPLFlags as Data_RPLFlags
from pcapkit.protocols.internet.hopopt.data import RPLOption as Data_RPLOption
from pcapkit.protocols.internet.hopopt.data import \
    SMFHashBasedDPDOption as Data_SMFHashBasedDPDOption
from pcapkit.protocols.internet.hopopt.data import \
    SMFIdentificationBasedDPDOption as Data_SMFIdentificationBasedDPDOption
from pcapkit.protocols.internet.hopopt.data import \
    TunnelEncapsulationLimitOption as Data_TunnelEncapsulationLimitOption
from pcapkit.protocols.internet.hopopt.data import UnassignedOption as Data_UnassignedOption
from pcapkit.protocols.internet.hopopt.schema import HOPOPT as Schema_HOPOPT
from pcapkit.protocols.internet.hopopt.schema import CALIPSOOption as Schema_CALIPSOOption
from pcapkit.protocols.internet.hopopt.schema import HomeAddressOption as Schema_HomeAddressOption
from pcapkit.protocols.internet.hopopt.schema import ILNPOption as Schema_ILNPOption
from pcapkit.protocols.internet.hopopt.schema import IPDFFOption as Schema_IPDFFOption
from pcapkit.protocols.internet.hopopt.schema import JumboPayloadOption as Schema_JumboPayloadOption
from pcapkit.protocols.internet.hopopt.schema import \
    LineIdentificationOption as Schema_LineIdentificationOption
from pcapkit.protocols.internet.hopopt.schema import MPLOption as Schema_MPLOption
from pcapkit.protocols.internet.hopopt.schema import PadOption as Schema_PadOption
from pcapkit.protocols.internet.hopopt.schema import PDMOption as Schema_PDMOption
from pcapkit.protocols.internet.hopopt.schema import \
    QuickStartReportOption as Schema_QuickStartReportOption
from pcapkit.protocols.internet.hopopt.schema import \
    QuickStartRequestOption as Schema_QuickStartRequestOption
from pcapkit.protocols.internet.hopopt.schema import RouterAlertOption as Schema_RouterAlertOption
from pcapkit.protocols.internet.hopopt.schema import RPLOption as Schema_RPLOption
from pcapkit.protocols.internet.hopopt.schema import \
    SMFHashBasedDPDOption as Schema_SMFHashBasedDPDOption
from pcapkit.protocols.internet.hopopt.schema import \
    SMFIdentificationBasedDPDOption as Schema_SMFIdentificationBasedDPDOption
from pcapkit.protocols.internet.hopopt.schema import \
    TunnelEncapsulationLimitOption as Schema_TunnelEncapsulationLimitOption
from pcapkit.protocols.internet.hopopt.schema import UnassignedOption as Schema_UnassignedOption
from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext
from pcapkit.protocols.misc.no_payload.protocol import NoPayload
from pcapkit.protocols.schema import Schema
from pcapkit.utilities.exceptions import BaseError, CaughtByCaller, ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import timedelta
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, Callable, DefaultDict, NoReturn, Optional

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.internet.hopopt.data import Option as Data_Option
    from pcapkit.protocols.internet.hopopt.data import QuickStartOption as Data_QuickStartOption
    from pcapkit.protocols.internet.hopopt.data import SMFDPDOption as Data_SMFDPDOption
    from pcapkit.protocols.internet.hopopt.schema import Option as Schema_Option
    from pcapkit.protocols.internet.hopopt.schema import QuickStartOption as Schema_QuickStartOption
    from pcapkit.protocols.internet.hopopt.schema import SMFDPDOption as Schema_SMFDPDOption
    from pcapkit.protocols.protocol import ProtocolBase

    Option = OrderedMultiDict[Enum_Option, Data_Option]
    OptionParser = Callable[[Schema_Option, NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[[Enum_Option,
                                  DefaultArg(Optional[Data_Option]), KwArg(Any)], Schema_Option]

__all__ = ['HOPOPT']


class HOPOPT(IPv6_Ext[Data_HOPOPT, Schema_HOPOPT],
             schema=Schema_HOPOPT, data=Data_HOPOPT):
    """This class implements IPv6 Hop-by-Hop Options.

    This class parses the following IPv6 Hop-by-Hop options, which are
    registered in the
    :attr:`self.__option__ <pcapkit.protocols.internet.hopopt.protocol.HOPOPT.__option__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
         - Option Constructor
       * - :attr:`~pcapkit.const.ipv6.option.Option.Pad1`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_pad`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_pad`
       * - :attr:`~pcapkit.const.ipv6.option.Option.PadN`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_pad`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_pad`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Tunnel_Encapsulation_Limit`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_tun`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_tun`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Router_Alert`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_ra`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_ra`
       * - :attr:`~pcapkit.const.ipv6.option.Option.CALIPSO`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_calipso`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_calipso`
       * - :attr:`~pcapkit.const.ipv6.option.Option.SMF_DPD`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_smf_dpd`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_smf_dpd`
       * - :attr:`~pcapkit.const.ipv6.option.Option.PDM`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_pdm`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_pdm`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Quick_Start`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_qs`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_qs`
       * - :attr:`~pcapkit.const.ipv6.option.Option.RPL_Option_0x23`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_rpl`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_rpl`
       * - :attr:`~pcapkit.const.ipv6.option.Option.RPL_Option_0x63`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_rpl`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_rpl`
       * - :attr:`~pcapkit.const.ipv6.option.Option.MPL_Option`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_mpl`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_mpl`
       * - :attr:`~pcapkit.const.ipv6.option.Option.ILNP_Nonce`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_ilnp`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_ilnp`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Line_Identification_Option`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_lio`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_lio`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Jumbo_Payload`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_jumbo`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_jumbo`
       * - :attr:`~pcapkit.const.ipv6.option.Option.Home_Address`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_home`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_home`
       * - :attr:`~pcapkit.const.ipv6.option.Option.IP_DFF`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._read_opt_ip_dff`
         - :meth:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT._make_opt_ip_dff`

    .. versionchanged:: 1.5.0

       * The ILNP nonce is sized with a ceiling rather than a floor
         (:issue:`601`).
       * The RPL option keeps its reserved flag bits on rebuild and accepts
         :rfc:`6553` sub-TLVs (:issue:`1199`).
       * A rebuild reproduces the option area byte for byte: its padding, a
         PadN with no data, the SMF_DPD, CALIPSO, PDM and ILNP Nonce options,
         and unassigned Quick-Start function codes (:issue:`1200`,
         :issue:`1228`, :issue:`1229`, :issue:`1232` to :issue:`1234`,
         :issue:`1237`); a CALIPSO option keeps its trailing pad and its
         length (:issue:`1403`).
       * The MPL, ``IP_DFF`` and Quick-Start options keep their reserved bits
         on rebuild, and ``IP_DFF`` takes the ``Opt Data Len`` of ``3`` that
         :rfc:`6971` Errata ID 3937 gives, where it took ``2`` (:issue:`1235`).
       * A PadN option's data and the "Not Used" octet of a Quick-Start report
         are kept as captured rather than zeroed (:issue:`1223`).

    .. versionchanged:: 1.6.0

       * A Quick-Start rate the four-bit rate code cannot carry, or a TTL,
         nonce or reserved value outside its field, raises
         :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather than a bare
         :exc:`ValueError`, an :exc:`OverflowError` or a
         :exc:`~pcapkit.utilities.exceptions.FieldValueError`, or a different
         value written in its place (:issue:`2617`).
       * The Quick-Start maker builds an unassigned function code as an
         unassigned option, the form the reader keeps one in (:issue:`2617`).
       * An option maker given a value its fixed-width field cannot carry --
         negative, too wide, or a :obj:`bool` for a field wider than one bit
         -- raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather
         than writing a different value or raising another exception; so
         does :meth:`make` for options too long for the ``Hdr Ext Len``
         (:issue:`2614`).
       * A PDM scale, given or derived from its delta, that does not fit its
         octet raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`,
         where it warned and was written wrapped (:issue:`2614`).
       * Each enumeration field of :meth:`make` and of the option makers,
         including the type of each option given to :meth:`make`, takes a
         member or an :class:`int` code, resolved with the enumeration's
         ``get``; a name, a :obj:`bool` for a field wider than one bit, or a
         code the field cannot carry raises
         :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather than
         resolving against an enumeration inferred from the caller's frame,
         writing a different value or raising another exception
         (:issue:`2594`).
       * The CALIPSO option's checksum and the "Not Used" octet of a
         Quick-Start report, given the wrong number of octets, raise
         :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather than being
         padded or cut to their field (:issue:`2676`).
       * An option given to :meth:`make` as empty raw octets, which hold no
         type octet, raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`
         rather than an :exc:`IndexError` (:issue:`2723`).

    .. versionremoved:: 1.6.0

       The ``*_default``, ``*_namespace`` and ``*_reversed`` arguments that
       went with each enumeration field of :meth:`make` and of the option
       makers -- ``next``, ``alert``, ``mode``, ``tid_type``, ``func`` and
       ``seed_type``; resolve a name with
       :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` first
       (:issue:`2594`).

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Option code to method mapping, see :meth:`_read_hopopt_options` and/or
    #: :meth:`_make_hopopt_options`. A :obj:`str` value names the methods
    #: ``_read_opt_${name}`` and ``_make_opt_${name}``, falling back to
    #: ``_read_opt_none`` / ``_make_opt_none`` when they do not exist; any other
    #: value is a ``(parser, constructor)`` pair of callables.
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
            Enum_Option.RPL_Option_0x23:            'rpl',      # [RFC 9008]
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
    def alias(self) -> 'Literal["HOPOPT"]':
        """Acronym of corresponding protocol.

        Spelled out rather than left to
        :attr:`Protocol.alias <pcapkit.protocols.protocol.Protocol.alias>`'s
        class-name default, because
        :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext` sits between
        this class and that default in the MRO and carries its own
        ``'IPv6-Ext'`` (GitHub issue :issue:`917`). Inheriting it would rename
        this header in every :class:`~pcapkit.corekit.protochain.ProtoChain`
        string and in :meth:`IPv6._decode_next_layer
        <pcapkit.protocols.internet.ipv6.protocol.IPv6._decode_next_layer>`'s packet
        dict key.

        """
        return 'HOPOPT'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self) -> 'ProtocolBase | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

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
        schema = self.__header__

        hopopt = Data_HOPOPT(
            next=schema.next,
            length=(schema.len + 1) * 8,
            options=self._read_hopopt_options(schema.len * 8 + 6),
        )

        if extension:
            # NOTE: As an IPv6 extension header the upper layer belongs to the enclosing
            # IPv6 header, so hold NoPayload here so that membership does not raise (#2487).
            self._next = NoPayload()  # pylint: disable=attribute-defined-outside-init
            return hopopt
        return self._decode_next_layer(hopopt, schema.next, length - hopopt.length)

    def make(self,
             next: 'Enum_TransType | int' = Enum_TransType.UDP,
             options: 'Optional[list[Schema_Option | tuple[Enum_Option | int, dict[str, Any]] | bytes] | Option]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | ProtocolBase | Schema' = b'', *,
             len: 'Optional[int]' = None,  # pylint: disable=redefined-builtin
             **kwargs: 'Any') -> 'Schema_HOPOPT':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            options: Hop-by-Hop Options.
            payload: Payload of current protocol.
            len: ``Hdr Ext Len`` to declare, rather than the one the options
                fill. A header the capture cut short declares one its parsed
                options do not fill, which :meth:`from_data` passes on, so that
                the rebuild declares it too (:issue:`2694`). Options that fill
                less than it declares are not padded out to it, so the header
                then declares more octets than it packs, as a cut one does.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``next``, or the type of an option, is a name, a
                :obj:`bool`, or a member or code that does not fit in one
                octet; or if the options make a header too long for its
                one-octet ``Hdr Ext Len``, or longer than ``len`` declares.

        .. versionchanged:: 1.6.0

           Takes ``len``, the ``Hdr Ext Len`` of a header the capture cut short
           (:issue:`2694`).

        """
        next_value = self._make_index(next, Enum_TransType, bits=8, name='next header')

        # NOTE: No options is not the same as no options area. The header is at
        # least 8 octets, 2 of them the fixed part, so the remaining 6 must be
        # padding options. Passing the empty list through the same path produces
        # them; returning ``[], 0`` would emit the 2 fixed octets alone, under a
        # ``Hdr Ext Len`` that ``(0 - 6) // 8`` makes ``-1``.
        options_value, total_length = self._make_hopopt_options(
            options if options is not None else [])

        # NOTE: ``_make_hopopt_options`` has aligned the header, so this division
        # is exact and rounding up is unnecessary.
        length = self._make_uint((total_length - 6) // 8, bits=8, name='Hdr Ext Len')
        if len is not None:
            length = self._make_uint(len, bits=8, name='Hdr Ext Len')
            if length * 8 + 6 < total_length:
                raise ProtocolError(f'{self.alias}: Hdr Ext Len {length} declares fewer octets '
                                    f'than the options take ({total_length})')

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
            meth: Name ``X`` of the ``_read_opt_X`` and ``_make_opt_X``
                methods, or a ``(parser, constructor)`` pair of callables, see
                :attr:`__option__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten. Handing back the entry already
                stored, or one equal to it, is a silent no-op. The entry
                ``code`` shipped with is accepted like any other, so an
                override can be undone (:issue:`1362`, :issue:`1363`).

        """
        incumbent = cls.__option__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'option {code} already registered, overwriting', RegistryWarning)
        cls.__option__[code] = meth

    @classmethod
    def id(cls) -> 'tuple[Literal["HOPOPT"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('HOPOPT',)

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
            For construction arguments, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object.

        Eight octets: the two fixed ones and the options that
        :rfc:`8200#section-4.3` counts in the first 8-octet unit.

        """
        return 8

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

    @classmethod
    def _make_data(cls, data: 'Data_HOPOPT') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        # NOTE: A header the capture cut short declares an area its parsed options
        # do not fill, and is rebuilt with the Hdr Ext Len it declared (#2694).
        return {
            'next': data.next,
            'options': data.options,
            'payload': cls._make_payload(data),
            'len': data.length // 8 - 1 if data.get('__short_read__') is not None else None,
        }

    def _read_opt_type(self, kind: 'int') -> 'tuple[int, bool]':
        """Read option type field.

        Arguments:
            kind (int): option kind value

        Returns:
            Extracted HOPOPT option type field information (unknown option
            action and change flag), see [:rfc:`8200#section-4.2`].

        """
        bin_ = bin(kind)[2:].zfill(8)
        return int(bin_[:2], base=2), bool(int(bin_[2], base=2))

    @staticmethod
    def _hopopt_option_length(schema_len: 'int') -> 'int':
        """Compute a HOPOPT option's whole-option length from its on-the-wire ``Opt Data Len``.

        Per :rfc:`8200#section-4.2`, an option's ``Opt Data Len`` field
        (what each ``Schema_*Option.len`` here holds) counts *"the length of
        the Option Data field of this option, in octets"* -- i.e. it
        excludes the Option Type and Opt Data Len fields themselves, so the
        whole option, which is what every ``_read_opt_*`` below reports back
        as the parsed option's own ``.length``, is two octets more. This is
        the ``+2``/``-2`` mismatch between the two (see ``Data_PadOption.length``
        vs. ``Schema_PadOption.len`` below). The read-side half lives in this
        one helper so the arithmetic has a single home. Do NOT drop the
        ``+ 2``.

        Section 4.2 is the citation because it defines the TLV option format and
        contains the sentence quoted above. The Hop-by-Hop Options header this
        class implements is :rfc:`8200#section-4.3`, but it defers option
        encoding to Section 4.2 (*"one or more TLV-encoded options, as
        described in Section 4.2"*) and its only length field is
        ``Hdr Ext Len``, *"the length of the Hop-by-Hop Options header in
        8-octet units, not including the first 8 octets"*: the whole header, a
        different quantity from one option's ``Opt Data Len`` in octets.
        Section 4.3 remains the reference for the header itself, as in the
        ``Note:`` on the whole extension header being a multiple of 8 octets.

        Note that only the *stored-length* read-side call sites are
        collected here -- most ``_make_opt_*`` methods recompute the wire
        ``Opt Data Len`` from ``len(value)`` rather than reading a parsed
        ``.length`` back, so they have nothing to unify against this helper.

        Args:
            schema_len: raw ``Opt Data Len`` field value, as read off the wire.

        Returns:
            Whole-option length, in octets, including the Type and Opt Data Len fields.

        """
        return schema_len + 2

    def _read_hopopt_options(self, length: 'int') -> 'Option':
        """Read HOPOPT options.

        Args:
            length: Length of the options area, in octets.

        Returns:
            Extracted HOPOPT options

        Raises:
            ProtocolError: If the parsed options do not total exactly ``length``
                octets, unless the capture cut the header short, as its short
                read records. Or if the capture cut an option short and its
                parser refuses the zeros it lacks, or its maker does not write
                the octets captured back.

        .. versionchanged:: 1.6.0

           A header the capture cut short reads as the short read it is, and an
           option it cuts as its parser reads the zeros it lacks, rather than
           being refused (:issue:`2694`).

        """
        counter = 0                   # length of read options
        options = OrderedMultiDict()  # type: Option

        for schema in self.__header__.options:
            dscp = schema.type
            name = self._lookup_registry(self.__option__, dscp)

            if isinstance(name, str):
                meth_name = f'_read_opt_{name}'
                meth = cast('OptionParser',
                            getattr(self, meth_name, self._read_opt_none))
                maker = cast('OptionConstructor',
                             getattr(self, f'_make_opt_{name}', self._make_opt_none))
            else:
                meth, maker = name

            # NOTE: The capture cut this option short, as its short read records, so
            # the octets it lacks read as zeros. It stands if its parser takes those
            # zeros and its maker writes the octets captured back (#2694); otherwise
            # it is refused, as an option running past the data is (#1325).
            if '__short_read__' in schema.__dict__:
                try:
                    with CaughtByCaller(BaseError):
                        data = meth(schema, options=options)
                        made = maker(dscp, data).pack()[:len(schema)]
                except BaseError as error:
                    raise ProtocolError(f'{self.alias}: [OptNo {dscp}] option cut short: {error}') from error
                if made != bytes(schema):
                    raise ProtocolError(f'{self.alias}: [OptNo {dscp}] option cut short does not '
                                        'rebuild as captured')
            else:
                data = meth(schema, options=options)

            # record option data
            options.add(dscp, data)
            counter += len(schema)

        # check threshold, which a header the capture cut short falls short of (#2694)
        if counter != length and '__short_read__' not in self.__header__.__dict__:
            raise ProtocolError('HOPOPT: invalid format')
        return options

    def _make_hopopt_options(self, options: 'list[Schema_Option | tuple[Enum_Option | int, dict[str, Any]] | bytes] | Option') -> 'tuple[list[Schema_Option | bytes], int]':  # pylint: disable=line-too-long
        """Make options for HOPOPT.

        Args:
            options: HOPOPT options

        Returns:
            Tuple of options and total length of options.

        Raises:
            ProtocolError: If the type of an option, given in a ``(type,
                kwargs)`` pair or as the key of a container, is a name, a
                :obj:`bool` or a code its field cannot carry, or if an option
                given as raw octets is empty (:issue:`2723`).

        Note:
            Options given as a :obj:`list` are fresh input: padding options in
            it are dropped, and padding is inserted after each option to align
            the header. Options given as a mapping, such as the
            :class:`~pcapkit.corekit.infoclass.OrderedMultiInfo` of parsed
            data, are emitted in order with their own padding options kept, and
            padding is added only at the end if the header is not aligned.

            The returned length is that of the options area alone, the value
            :meth:`make` derives the ``Hdr Ext Len`` field from. Since the two
            octets of the fixed header precede it, an options area is well
            formed only when it is 2 octets short of a multiple of 8 --
            including when it holds no real options at all, in which case it is
            6 octets of pure padding rather than empty.

        """
        total_length = 0
        if isinstance(options, list):
            options_list = []  # type: list[Schema_Option | bytes]
            for schema in options:
                if isinstance(schema, bytes):
                    if not schema:
                        raise ProtocolError(f'{self.alias}: invalid option: {schema!r} holds no type octet')
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
                    kind, args = cast('tuple[Enum_Option | int, dict[str, Any]]', schema)
                    code = self._make_index(kind, Enum_Option, bits=8, name='option type')
                    if code in (Enum_Option.Pad1, Enum_Option.PadN):  # ignore padding options by default
                        continue

                    name = self._lookup_registry(self.__option__, code)
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

                # force alignment of the header (fixed part included) to 8 octets
                pad_opts, pad_len = self._make_pad_options(total_length + 2)
                options_list.extend(pad_opts)
                total_length += pad_len

            # an options area holding nothing at all is still 6 octets long
            pad_opts, pad_len = self._make_pad_options(total_length + 2)
            options_list.extend(pad_opts)
            total_length += pad_len
            return options_list, total_length

        # NOTE: Options given as parsed data are emitted as they are, padding
        # included and in place, so that a parsed header rebuilds byte for
        # byte; only a header left short of alignment gets trailing padding.
        options_list = []
        for key, option in options.items(multi=True):
            code = self._make_index(key, Enum_Option, bits=8, name='option type')
            name = self._lookup_registry(self.__option__, code)
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

        # an options area holding nothing at all is still 6 octets long
        pad_opts, pad_len = self._make_pad_options(total_length + 2)
        options_list.extend(pad_opts)
        total_length += pad_len
        return options_list, total_length

    def _read_opt_none(self, schema: 'Schema_UnassignedOption', *, options: 'Option') -> 'Data_UnassignedOption':  # pylint: disable=unused-argument
        """Read HOPOPT unassigned options.

        Structure of HOPOPT unassigned options [:rfc:`8200`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
           |  Option Type  |  Opt Data Len |  Option Data
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

        Args:
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        opt = Data_UnassignedOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            data=schema.data,
        )
        return opt

    def _read_opt_pad(self, schema: 'Schema_PadOption', *, options: 'Option') -> 'Data_PadOption':  # pylint: disable=unused-argument
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``code`` is **NOT** ``0`` or ``1``.

        Note:
            A ``Pad1`` option occupies a single octet and carries no
            ``Opt Data Len`` field, so its
            :attr:`~pcapkit.protocols.internet.hopopt.data.Option.length` is
            ``1`` rather than ``len + 2``. That one-octet wire shape is enforced
            by :class:`~pcapkit.protocols.internet.hopopt.schema.PadOption`
            itself, which sizes both the length octet and the padding data from
            the option type; ``clen`` is therefore always ``0`` here for a
            parsed ``Pad1``, and the length check this method makes only guards
            a schema built by hand. A ``PadN`` whose ``Opt Data Len`` is ``0``
            is a valid two-octet padding option [:rfc:`8200#section-4.2`].

        """
        code, clen = schema.type, schema.len

        if code not in (Enum_Option.Pad1, Enum_Option.PadN):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.Pad1 and clen != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        if code == Enum_Option.Pad1:
            _size = 1
        else:
            _size = self._hopopt_option_length(schema.len)

        opt = Data_PadOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=_size,
            pad=schema.pad,
        )
        return opt

    def _read_opt_tun(self, schema: 'Schema_TunnelEncapsulationLimitOption', *, options: 'Option') -> 'Data_TunnelEncapsulationLimitOption':  # pylint: disable=unused-argument
        """Read HOPOPT Tunnel Encapsulation Limit option.

        Structure of HOPOPT Tunnel Encapsulation Limit option [:rfc:`2473`]:

        .. code-block:: text

              Option Type     Opt Data Len   Opt Data Len
            0 1 2 3 4 5 6 7
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |0 0 0 0 0 1 0 0|       1       | Tun Encap Lim |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``1``.

        """
        if schema.len != 1:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_TunnelEncapsulationLimitOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            limit=schema.limit,
        )
        return opt

    def _read_opt_ra(self, schema: 'Schema_RouterAlertOption', *, options: 'Option') -> 'Data_RouterAlertOption':  # pylint: disable=unused-argument
        """Read HOPOPT Router Alert option.

        Structure of HOPOPT Router Alert option [:rfc:`2711`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |0 0 0|0 0 1 0 1|0 0 0 0 0 0 1 0|        Value (2 octets)       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``2``.

        """
        if schema.len != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_RouterAlertOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            value=schema.alert,
        )
        return opt

    def _read_opt_calipso(self, schema: 'Schema_CALIPSOOption', *, options: 'Option') -> 'Data_CALIPSOOption':  # pylint: disable=unused-argument
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Note:
            ``Cmpt Length`` counts 32-bit words and may be odd
            [:rfc:`5570#section-5.2`]; it only has to fit inside ``Opt Data
            Len``, which
            :func:`~pcapkit.protocols.internet.ipv6_ext.schema.calipso_pad_len`
            has already checked while the option was unpacked.

        """
        opt = Data_CALIPSOOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            domain=schema.domain,
            cmpt_len=schema.cmpt_len * 4,
            level=schema.level,
            checksum=schema.checksum,
            pad=schema.pad,
        )

        if schema.cmpt_len > 0:
            opt.__update__([
                ('cmpt_bitmap', tuple(schema.bitmap)),
            ])
        return opt

    def _read_opt_smf_dpd(self, schema: 'Schema_SMFDPDOption', *, options: 'Option') -> 'Data_SMFDPDOption':  # pylint: disable=unused-argument,line-too-long
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        mode = schema.mode
        if mode == Enum_SMFDPDMode.I_DPD:  # I-DPD mode
            if TYPE_CHECKING:
                schema = cast('Schema_SMFIdentificationBasedDPDOption', schema)

            # NOTE: An unresolvable *string* key raises KeyError rather than
            # minting a member, so only a hand-constructed schema hits this
            # guard. An unassigned *wire* value still mints via _missing_ and
            # never reaches here.
            tid_key = None
            try:
                tid_key = schema.info['type']
                tid_type = Enum_TaggerID.get(tid_key)
            except KeyError:
                raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] '
                                    f'unknown tagger-id type: {tid_key!r}') from None
            tid_len = schema.info['len']

            opt = Data_SMFIdentificationBasedDPDOption(
                type=schema.type,
                action=Enum_OptionAction.get(schema.type >> 6),
                change=bool(schema.type & 0b00100000),
                length=self._hopopt_option_length(schema.len),
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
                length=self._hopopt_option_length(schema.len),
                dpd_type=mode,
                hav=schema.hav,
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid DPD mode: {mode}')
        return opt

    def _read_opt_pdm(self, schema: 'Schema_PDMOption', *, options: 'Option') -> 'Data_PDMOption':  # pylint: disable=unused-argument
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``10``.

        """
        if schema.len != 10:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_PDMOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            scaledtlr=schema.scaledtlr,
            scaledtls=schema.scaledtls,
            psntp=schema.psntp,
            psnlr=schema.psnlr,
            deltatlr=schema.deltatlr << schema.scaledtlr,
            deltatls=schema.deltatls << schema.scaledtls,
        )
        return opt

    def _read_opt_qs(self, schema: 'Schema_QuickStartOption', *, options: 'Option') -> 'Data_QuickStartOption':  # pylint: disable=unused-argument
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        Note:
            An option whose QS function is neither of the two above has no
            defined layout, so the schema keeps it as an unassigned option and
            it is parsed as one, see :meth:`_read_opt_none`. That dispatch is
            by the schema's own class, decided from the octets a file read
            hands it; a :class:`~pcapkit.protocols.internet.hopopt.schema.QuickStartRequestOption`
            or :class:`~pcapkit.protocols.internet.hopopt.schema.QuickStartReportOption`
            built directly with an unassigned ``func`` reaches this method
            regardless, which is why it still raises below rather than
            returning early.

        """
        if isinstance(schema, Schema_UnassignedOption):
            return self._read_opt_none(schema, options=options)  # type: ignore[return-value]
        if schema.len != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        func = Enum_QSFunction.get(schema.flags['func'])
        if func == Enum_QSFunction.Quick_Start_Request:
            schema_req = cast('Schema_QuickStartRequestOption', schema)

            opt = Data_QuickStartRequestOption(
                type=schema.type,
                action=Enum_OptionAction.get(schema.type >> 6),
                change=bool(schema.type & 0b00100000),
                length=self._hopopt_option_length(schema_req.len),
                func=func,
                rate=self._read_qs_rate(schema_req.flags['rate']),
                ttl=datetime.timedelta(seconds=schema_req.ttl),
                nonce=schema_req.nonce['nonce'],
                reserved=schema_req.nonce['reserved'],
            )  # type: Data_QuickStartOption
        elif func == Enum_QSFunction.Report_of_Approved_Rate:
            schema_rep = cast('Schema_QuickStartReportOption', schema)

            opt = Data_QuickStartReportOption(
                type=schema.type,
                action=Enum_OptionAction.get(schema.type >> 6),
                change=bool(schema.type & 0b00100000),
                length=self._hopopt_option_length(schema_rep.len),
                func=func,
                rate=self._read_qs_rate(schema_rep.flags['rate']),
                nonce=schema_rep.nonce['nonce'],
                reserved=schema_rep.nonce['reserved'],
                unused=schema_rep.reserved,
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] unknown QS function: {func}')
        return opt

    def _read_opt_rpl(self, schema: 'Schema_RPLOption', *, options: 'Option') -> 'Data_RPLOption':  # pylint: disable=unused-argument
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

        The sub-TLVs, which :rfc:`6553#section-3` says MUST be skipped when
        unrecognised, are kept as raw octets in ``sub_tlvs``.

        Args:
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``schema.len`` is less than ``4``.

        """
        if schema.len < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_RPLOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            flags=Data_RPLFlags(
                down=bool(schema.flags['down']),
                rank_err=bool(schema.flags['rank_err']),
                fwd_err=bool(schema.flags['fwd_err']),
                reserved=schema.flags['reserved'],
            ),
            id=schema.id,
            rank=schema.rank,
            sub_tlvs=schema.sub_tlvs,
        )
        return opt

    def _read_opt_mpl(self, schema: 'Schema_MPLOption', *, options: 'Option') -> 'Data_MPLOption':  # pylint: disable=unused-argument
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the option is malformed.

        """
        # NOTE: An unresolvable *string* key raises KeyError rather than
        # minting a member, so only a hand-constructed schema hits this guard.
        # An unassigned *wire* value still mints via _missing_ and never
        # reaches here.
        seed_key = None
        try:
            seed_key = schema.flags['type']
            kind = Enum_SeedID.get(seed_key)
        except KeyError:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] '
                                f'unknown seed-id type: {seed_key!r}') from None
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
            length=self._hopopt_option_length(schema.len),
            seed_type=kind,
            flags=Data_MPLFlags(
                max=bool(schema.flags['max']),
                drop=bool(schema.flags['drop']),
                reserved=schema.flags['reserved'],
            ),
            seq=schema.seq,
            seed_id=schema.seed if schema.seed is not NO_VALUE else None,  # type: ignore[comparison-overlap]
        )
        return opt

    def _read_opt_ilnp(self, schema: 'Schema_ILNPOption', *, options: 'Option') -> 'Data_ILNPOption':  # pylint: disable=unused-argument
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        opt = Data_ILNPOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            nonce=schema.nonce,
        )
        return opt

    def _read_opt_lio(self, schema: 'Schema_LineIdentificationOption', *, options: 'Option') -> 'Data_LineIdentificationOption':  # pylint: disable=unused-argument
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        """
        opt = Data_LineIdentificationOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            line_id_len=schema.id_len,
            line_id=schema.id,
        )
        return opt

    def _read_opt_jumbo(self, schema: 'Schema_JumboPayloadOption', *, options: 'Option') -> 'Data_JumboPayloadOption':  # pylint: disable=unused-argument
        """Read HOPOPT Jumbo Payload option.

        Structure of HOPOPT Jumbo Payload option [:rfc:`2675`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  |  Opt Data Len |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                     Jumbo Payload Length                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``4``.

        """
        if schema.len != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_JumboPayloadOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            jumbo_len=schema.jumbo_len,
        )
        return opt

    def _read_opt_home(self, schema: 'Schema_HomeAddressOption', *, options: 'Option') -> 'Data_HomeAddressOption':  # pylint: disable=unused-argument
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
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``16``.

        """
        if schema.len != 16:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_HomeAddressOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            address=schema.addr,
        )
        return opt

    def _read_opt_ip_dff(self, schema: 'Schema_IPDFFOption', *, options: 'Option') -> 'Data_IPDFFOption':  # pylint: disable=unused-argument
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

        ``OptDataLenDFF`` is ``3``, the flags octet and the sequence number,
        as corrected by :rfc:`6971` Errata ID 3937; the RFC text says ``2``.

        Args:
            schema: parsed parameter schema
            options: extracted HOPOPT options

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``3``.

        """
        if schema.len != 3:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid format')

        opt = Data_IPDFFOption(
            type=schema.type,
            action=Enum_OptionAction.get(schema.type >> 6),
            change=bool(schema.type & 0b00100000),
            length=self._hopopt_option_length(schema.len),
            version=schema.flags['ver'],
            flags=Data_DFFFlags(
                dup=bool(schema.flags['dup']),
                ret=bool(schema.flags['ret']),
                reserved=schema.flags['reserved'],
            ),
            seq=schema.seq,
        )
        return opt

    def _make_pad_options(self, offset: 'int') -> 'tuple[list[Schema_PadOption], int]':
        """Make the padding options needed to align the header to 8 octets.

        Args:
            offset: Number of octets emitted so far, **counting the two octets
                of the fixed header** (``Next Header`` and ``Hdr Ext Len``) as
                well as every option already in the list.

        Returns:
            Tuple of the padding option schemas and the number of octets they
            occupy.

        Note:
            It is the *whole* extension header, fixed part included, that has to
            be a multiple of 8 octets [:rfc:`8200#section-4.3`], which is why
            the alignment is computed from ``offset`` rather than from the
            length of the option just emitted. Aligning each option to 8 octets
            on its own leaves the options area a multiple of 8, whereas
            :meth:`read` sizes it as ``hdr_ext_len * 8 + 6``, two short of a
            multiple of 8; the header would declare 2 octets fewer than it
            carried.

            A ``PadN`` option spends two octets on its own type and
            ``Opt Data Len`` fields before any padding data, so occupying
            ``pad_len`` octets means an ``Opt Data Len`` of ``pad_len - 2``.
            One octet is padded with a ``Pad1`` option instead, that being the
            only form which can occupy a single octet. Two octets are one
            ``PadN`` with an ``Opt Data Len`` of ``0``, not two ``Pad1``:
            :rfc:`8200#section-4.2` says a ``PadN`` should be used rather than
            multiple ``Pad1`` options.

        """
        pad_len = pad_length(offset, 8)
        if pad_len == 0:
            return [], 0
        if pad_len == 1:
            return [self._make_opt_pad(Enum_Option.Pad1, length=0)], pad_len  # type: ignore[arg-type]
        return [self._make_opt_pad(Enum_Option.PadN, length=pad_len - 2)], pad_len  # type: ignore[arg-type]

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
            Constructed option schema.

        Raises:
            ProtocolError: If ``data`` is too long for the one-octet
                ``Opt Data Len``.

        """
        if opt is not None:
            data = opt.data

        return Schema_UnassignedOption(
            type=code,
            len=self._make_uint(len(data), bits=8, name='Opt Data Len'),
            data=data,
        )

    def _make_opt_pad(self, code: 'Enum_Option', opt: 'Optional[Data_PadOption]' = None, *,
                      length: 'int' = 0,
                      pad: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_PadOption':
        """Make HOPOPT pad option.

        Args:
            code: option type value
            opt: option data
            length: value of the ``Opt Data Len`` field, i.e. the number of
                padding octets *after* the two octets of the option header
            pad: the ``PadN`` option data, truncated or zero-filled to
                ``length`` octets
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``length`` does not fit the one-octet
                ``Opt Data Len``.

        Warns:
            ProtocolWarning: If ``code`` is ``Pad1`` but ``length`` is not
                ``0``; a ``PadN`` option is made instead.

        Note:
            :attr:`Data_PadOption.length
            <pcapkit.protocols.internet.hopopt.data.Option.length>` counts the
            *whole* option, whereas :attr:`Schema_PadOption.len
            <pcapkit.protocols.internet.hopopt.schema.Option.len>` is the
            ``Opt Data Len`` field: two octets fewer, and absent altogether for a
            ``Pad1``. ``opt`` is honoured so that re-making a parsed padding
            option keeps its type and size. A ``PadN`` with ``length`` ``0`` is
            a valid two-octet option [:rfc:`8200#section-4.2`] and is kept.

        """
        if opt is not None:
            code = opt.type
            length = 0 if opt.type == Enum_Option.Pad1 else opt.length - 2
            pad = getattr(opt, 'pad', b'')

        if code == Enum_Option.Pad1 and length != 0:
            warn(f'{self.alias}: [OptNo {code}] invalid length: must be 0 for a Pad1 option, '
                 f'not {length!r}; making a PadN', ProtocolWarning)
            code = Enum_Option.PadN  # type: ignore[assignment]

        return Schema_PadOption(
            type=code,
            len=self._make_uint(length, bits=8, name='Opt Data Len'),
            pad=pad,
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
            Constructed option schema.

        Raises:
            ProtocolError: If ``limit`` does not fit in one octet.

        """
        if opt is not None:
            limit = opt.limit

        return Schema_TunnelEncapsulationLimitOption(
            type=code,
            len=1,
            limit=self._make_uint(limit, bits=8, name='tunnel encapsulation limit'),
        )

    def _make_opt_ra(self, code: 'Enum_Option', opt: 'Optional[Data_RouterAlertOption]' = None, *,
                     alert: 'Enum_RouterAlert | int' = Enum_RouterAlert.Datagram_contains_a_Multicast_Listener_Discovery_message,  # pylint: disable=line-too-long
                     **kwargs: 'Any') -> 'Schema_RouterAlertOption':
        """Make HOPOPT router alert option.

        Args:
            code: option type value
            opt: option data
            alert: router alert value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If the router alert value is a name, a :obj:`bool`,
                or a member or code that does not fit in two octets.

        """
        value = self._make_index(opt.value if opt is not None else alert, Enum_RouterAlert,
                                 bits=16, name='router alert value')
        return Schema_RouterAlertOption(
            type=code,
            len=2,
            alert=value,
        )

    def _make_opt_calipso(self, code: 'Enum_Option', opt: 'Optional[Data_CALIPSOOption]' = None, *,
                          domain: 'int' = 0,
                          level: 'int' = 0,
                          checksum: 'bytes' = b'\x00\x00',
                          bitmap: 'Optional[bytes | tuple[int, ...]]' = None,
                          pad: 'bytes' = b'',
                          **kwargs: 'Any') -> 'Schema_CALIPSOOption':
        """Make HOPOPT calipso option.

        Args:
            code: option type value
            opt: option data
            domain: CALIPSO domain of interpretation
            level: sensitivity level
            checksum: checksum of the option
            bitmap: compartment bitmap, as a bytes-like object or as an
                iterable of octets, such as the :obj:`tuple` the reader stores;
                its length must be a multiple of 4 octets
            pad: octets after the compartment bitmap, counted in ``Opt Data Len``
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``domain`` or ``level`` does not fit its field,
                if ``checksum`` is not two octets, if the bitmap is not
                bytes-like or an iterable of octets, or is
                not a whole number of 32-bit words, if ``pad`` is not
                :obj:`bytes`, or if the option data would exceed the 255 octets
                ``Opt Data Len`` can count.

        Note:
            ``Cmpt Length`` on the wire counts 32-bit words [:rfc:`5570#section-5.1`],
            whereas the bitmap here is sized in octets.

        """
        if opt is not None:
            domain = opt.domain
            level = opt.level
            checksum = opt.checksum
            bitmap = opt.cmpt_bitmap if hasattr(opt, 'cmpt_bitmap') else None
            pad = opt.pad
        domain = self._make_uint(domain, bits=32, name='CALIPSO domain of interpretation')
        level = self._make_uint(level, bits=8, name='CALIPSO sensitivity level')
        if bitmap is None:
            bitmap_bytes = b''
        elif isinstance(bitmap, (int, str)):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid CALIPSO bitmap type: '
                                f'{type(bitmap).__name__}')
        else:
            try:  # bytes-like object
                bitmap_bytes = bytes(memoryview(bitmap))
            except TypeError:  # iterable of octets
                try:
                    octets = tuple(bitmap)
                except TypeError as exc:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid CALIPSO bitmap type: '
                                        f'{type(bitmap).__name__}') from exc
                bitmap_bytes = bytes(self._make_uint(octet, bits=8, name='CALIPSO bitmap octet')
                                     for octet in octets)
        if len(bitmap_bytes) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid CALIPSO bitmap length: '
                                f'{len(bitmap_bytes)}')
        if not isinstance(pad, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid CALIPSO pad type: '
                                f'{type(pad).__name__}')
        if 8 + len(bitmap_bytes) + len(pad) > 255:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] too long CALIPSO option data: '
                                f'{8 + len(bitmap_bytes) + len(pad)}')

        return Schema_CALIPSOOption(
            type=code,
            len=8 + len(bitmap_bytes) + len(pad),
            domain=domain,
            cmpt_len=len(bitmap_bytes) // 4,
            level=level,
            checksum=self._make_octets(checksum, size=2, name='CALIPSO checksum'),
            bitmap=bitmap_bytes if bitmap_bytes else None,
            pad=pad,
        )

    def _make_opt_smf_dpd(self, code: 'Enum_Option', opt: 'Optional[Data_SMFIdentificationBasedDPDOption | Data_SMFHashBasedDPDOption]' = None, *,
                          mode: 'Enum_SMFDPDMode | int' = Enum_SMFDPDMode.I_DPD,
                          tid_type: 'Optional[Enum_TaggerID | int]' = None,
                          tid: 'Optional[bytes | IPv4Address | IPv6Address]' = None,
                          id: 'bytes' = b'',
                          hav: 'bytes' = b'',
                          **kwargs: 'Any') -> 'Schema_SMFDPDOption':
        """Make HOPOPT SMF DPD option.

        Args:
            code: option type value
            opt: option data
            mode: DPD mode
            tid_type: TaggerID type (``TidTy`` field); inferred from the
                length of ``tid`` if not given
            tid: Tagger ID
            id: identifier
            hav: hash assist value (HAV)
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If the DPD mode is a name, or a member or code
                that does not fit in one bit; if the TaggerID type is a name,
                a :obj:`bool`, or a member or code that does not fit in three
                bits; if the Tagger ID does not fit the TaggerID type, the
                H-DPD Hash Assist Value is empty, or the option data is too
                long for its one-octet ``Opt Data Len``.

        """
        if opt is not None:
            mode = opt.dpd_type
            tid_type = getattr(opt, 'tid_type', None)
            tid = getattr(opt, 'tid', None)
            id = getattr(opt, 'id', b'')
            hav = getattr(opt, 'hav', b'')

        dpd_type = self._make_index(mode, Enum_SMFDPDMode, bits=1, name='DPD mode')

        if dpd_type == Enum_SMFDPDMode.I_DPD:
            if tid is None:
                tid_bytes = b''
            elif isinstance(tid, bytes):
                tid_bytes = tid
            elif tid.version in (4, 6):
                tid_bytes = tid.packed
            else:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid TaggerID version: {tid.version}')
            tid_len = len(tid_bytes)

            if tid_type is not None:
                tid_kind = self._make_index(tid_type, Enum_TaggerID, bits=3,
                                            name='TaggerID type')  # type: Enum_TaggerID | int
            elif tid_len == 0:
                tid_kind = Enum_TaggerID.NULL
            elif tid_len == 4:
                tid_kind = Enum_TaggerID.IPv4
            elif tid_len == 16:
                tid_kind = Enum_TaggerID.IPv6
            else:
                tid_kind = Enum_TaggerID.DEFAULT

            if tid_kind == Enum_TaggerID.NULL:
                tid_ok = tid_len == 0
            elif tid_kind == Enum_TaggerID.IPv4:
                tid_ok = tid_len == 4
            elif tid_kind == Enum_TaggerID.IPv6:
                tid_ok = tid_len == 16
            else:
                # TidLen is 4 bits and holds the length minus one.
                tid_ok = 1 <= tid_len <= 16
            if not tid_ok:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid TaggerID length {tid_len} '
                                    f'for type {tid_kind}')

            schema = Schema_SMFIdentificationBasedDPDOption(
                type=code,
                len=self._make_uint(1 + tid_len + len(id), bits=8, name='Opt Data Len'),
                info={
                    'mode': 0,
                    'type': tid_kind,
                    'len': max(tid_len - 1, 0),
                },
                tid=tid_bytes if tid_len else None,
                id=id,
            )  # type: Schema_SMFDPDOption
        else:
            # H-DPD, the other value of the one-bit mode. The first octet of
            # the HAV carries the H-DPD mode bit.
            if not hav:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] empty Hash Assist Value (HAV)')
            hav_ba = bytearray(hav)
            hav_ba[0] = hav[0] | 0x80

            schema = Schema_SMFHashBasedDPDOption(
                type=code,
                len=self._make_uint(len(hav), bits=8, name='Opt Data Len'),
                hav=bytes(hav_ba),
            )
        return schema

    def _make_opt_pdm(self, code: 'Enum_Option', opt: 'Optional[Data_PDMOption]' = None, *,
                      psntp: 'int' = 0,
                      psnlr: 'int' = 0,
                      deltatlr: 'int' = 0,
                      deltatls: 'int' = 0,
                      scaledtlr: 'Optional[int]' = None,
                      scaledtls: 'Optional[int]' = None,
                      **kwargs: 'Any') -> 'Schema_PDMOption':
        """Make HOPOPT PDM option.

        Args:
            code: option type value
            opt: option data
            psntp: packet sequence number (PSN) this packet
            psnlr: packet sequence number (PSN) last received
            deltatlr: delta time last received (in attoseconds)
            deltatls: delta time last sent (in attoseconds)
            scaledtlr: scale of delta time last received; derived from
                ``deltatlr`` if not given
            scaledtls: scale of delta time last sent; derived from
                ``deltatls`` if not given
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``psntp`` or ``psnlr`` does not fit in two octets,
                a scale does not fit in one octet, or a delta is negative or,
                at the scale given for it, does not fit two octets.

        """
        if opt is not None:
            psntp = opt.psntp
            psnlr = opt.psnlr
            deltatlr = opt.deltatlr
            deltatls = opt.deltatls
            # NOTE: The parsed scales are kept so long as they still describe
            # the deltas, which they always do for a parsed option.
            if (deltatlr >> opt.scaledtlr).bit_length() <= 16:
                scaledtlr = opt.scaledtlr
            if (deltatls >> opt.scaledtls).bit_length() <= 16:
                scaledtls = opt.scaledtls

        # NOTE: A delta fits two octets at the widest scale, 255, or at none.
        deltatlr = self._make_uint(deltatlr, bits=16 + 0xFF, name='PDM delta time last received')
        deltatls = self._make_uint(deltatls, bits=16 + 0xFF, name='PDM delta time last sent')
        if scaledtlr is None:
            scaledtlr = max(0, deltatlr.bit_length() - 16)
        if scaledtls is None:
            scaledtls = max(0, deltatls.bit_length() - 16)
        scale_dtlr = self._make_uint(scaledtlr, bits=8, name='PDM scale of delta time last received')
        scale_dtls = self._make_uint(scaledtls, bits=8, name='PDM scale of delta time last sent')

        return Schema_PDMOption(
            type=code,
            len=10,
            scaledtlr=scale_dtlr,
            scaledtls=scale_dtls,
            psntp=self._make_uint(psntp, bits=16, name='PDM PSN this packet'),
            psnlr=self._make_uint(psnlr, bits=16, name='PDM PSN last received'),
            deltatlr=self._make_uint(deltatlr >> scale_dtlr, bits=16,
                                     name='PDM delta time last received'),
            deltatls=self._make_uint(deltatls >> scale_dtls, bits=16,
                                     name='PDM delta time last sent'),
        )

    def _make_opt_qs(self, code: 'Enum_Option', opt: 'Optional[Data_QuickStartOption | Data_UnassignedOption]' = None, *,  # pylint: disable=line-too-long
                     func: 'Enum_QSFunction | int' = Enum_QSFunction.Quick_Start_Request,
                     rate: 'int' = 0,
                     ttl: 'timedelta | int' = 0,
                     nonce: 'int' = 0,
                     reserved: 'int' = 0,
                     unused: 'bytes' = b'\x00',
                     **kwargs: 'Any') -> 'Schema_QuickStartOption | Schema_UnassignedOption':
        """Make HOPOPT QS option.

        Args:
            code: option type value
            opt: option data
            func: QS function type
            rate: rate (in kbps), rounded down to the nearest rate the
                four-bit rate code carries (:rfc:`4782#section-3.1`)
            ttl: time to live (in seconds)
            nonce: nonce value
            reserved: reserved bits (``R``) after the nonce
            unused: the "Not Used" octet of a report of approved rate
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema. An unassigned option schema if ``opt``
            is a Quick-Start option parsed as unassigned, see :meth:`_read_opt_qs`,
            or if ``func`` is neither of the assigned functions, in which case
            the option data takes the layout of a Quick-Start Request.

        Raises:
            ProtocolError: If ``func`` is a name, a :obj:`bool`, or a member or
                code that does not fit in four bits, the rate code cannot carry
                ``rate``, ``ttl``, ``nonce`` or ``reserved`` does not fit its
                field, or ``unused`` is not one octet.

        """
        if isinstance(opt, Data_UnassignedOption):
            return self._make_opt_none(code, opt)
        if opt is not None:
            func_enum = opt.func
            rate = opt.rate
            ttl = getattr(opt, 'ttl', 0)
            nonce = getattr(opt, 'nonce', 0)
            reserved = getattr(opt, 'reserved', 0)
            unused = getattr(opt, 'unused', b'\x00')
        else:
            func_enum = self._make_index(func, Enum_QSFunction, bits=4, name='QS function')
        rate_val = self._make_qs_rate(rate)
        ttl_value = ttl if isinstance(ttl, int) else math.floor(ttl.total_seconds())
        nonce = self._make_uint(nonce, bits=30, name='Quick-Start nonce')
        reserved = self._make_uint(reserved, bits=2, name='Quick-Start reserved')

        if func_enum == Enum_QSFunction.Quick_Start_Request:
            return Schema_QuickStartRequestOption(
                type=code,
                len=6,
                flags={
                    'func': func_enum,
                    'rate': rate_val,
                },
                ttl=self._make_uint(ttl_value, bits=8, name='Quick-Start TTL'),
                nonce={
                    'nonce': nonce,
                    'reserved': reserved,
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
                reserved=self._make_octets(unused, size=1, name='Quick-Start not-used octet'),
                nonce={
                    'nonce': nonce,
                    'reserved': reserved,
                },
            )
        func_val = self._make_uint(func_enum, bits=4, name='QS function')
        ttl_value = self._make_uint(ttl_value, bits=8, name='Quick-Start TTL')
        data = bytes([(func_val << 4) | rate_val, ttl_value]) + ((nonce << 2) | reserved).to_bytes(4, 'big')
        return self._make_opt_none(code, data=data)

    def _make_opt_rpl(self, code: 'Enum_Option', opt: 'Optional[Data_RPLOption]' = None, *,
                      down: 'bool' = False,
                      rank_err: 'bool' = False,
                      fwd_err: 'bool' = False,
                      id: 'int' = 0,
                      rank: 'int' = 0,
                      reserved: 'int' = 0,
                      sub_tlvs: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_RPLOption':
        """Make HOPOPT RPL option.

        Args:
            code: option type value
            opt: option data
            down: down flag
            rank_err: rank error flag
            fwd_err: forwarding error flag
            id: RPL instance ID
            rank: sender rank
            reserved: reserved flag bits, i.e. the low five bits of the flags octet
            sub_tlvs: sub-TLVs, as raw octets
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``reserved``, ``id`` or ``rank`` does not fit its
                field, or ``sub_tlvs`` does not fit in the option.

        """
        if opt is not None:
            down = opt.flags.down
            rank_err = opt.flags.rank_err
            fwd_err = opt.flags.fwd_err
            reserved = opt.flags.reserved
            id = opt.id
            rank = opt.rank
            sub_tlvs = opt.sub_tlvs

        reserved = self._make_uint(reserved, bits=5, name='RPL reserved flags')
        id = self._make_uint(id, bits=8, name='RPL instance ID')
        rank = self._make_uint(rank, bits=16, name='RPL sender rank')
        if len(sub_tlvs) > 251:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] too long RPL sub-TLVs: {len(sub_tlvs)}')

        return Schema_RPLOption(
            type=code,
            len=4 + len(sub_tlvs),
            flags={
                'down': down,
                'rank_err': rank_err,
                'fwd_err': fwd_err,
                'reserved': reserved,
            },
            id=id,
            rank=rank,
            sub_tlvs=sub_tlvs,
        )

    def _make_opt_mpl(self, code: 'Enum_Option', opt: 'Optional[Data_MPLOption]' = None, *,
                      seed_type: 'Optional[Enum_SeedID | int]' = None,
                      max: 'bool' = False,
                      drop: 'bool' = False,
                      reserved: 'int' = 0,
                      seq: 'int' = 0,
                      seed: 'Optional[int | IPv6Address]' = None,
                      **kwargs: 'Any') -> 'Schema_MPLOption':
        """Make HOPOPT MPL option.

        Args:
            code: option type value
            opt: option data
            seed_type: seed-id type (``S`` field); inferred from ``seed`` if not given
            max: maximum sequence number flag
            drop: drop packet flag
            reserved: reserved bits (``rsv``), i.e. the low four bits of the
                flags octet
            seq: MPL sequence number
            seed: MPL seed ID, ignored when the seed-id type is
                :attr:`~pcapkit.const.ipv6.seed_id.SeedID.IPV6_SOURCE_ADDRESS`,
                as the seed is then the IPv6 source address
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If the seed-id type is a name, a :obj:`bool`, or a
                member or code that does not fit in two bits; if the seed ID is
                missing or does not fit the seed-id type, or ``reserved`` or
                ``seq`` does not fit its field.

        """
        if opt is not None:
            seed_type = opt.seed_type
            max = opt.flags.max
            drop = opt.flags.drop
            reserved = opt.flags.reserved
            seq = opt.seq
            seed = opt.seed_id

        reserved = self._make_uint(reserved, bits=4, name='MPL reserved bits')
        seq = self._make_uint(seq, bits=8, name='MPL sequence number')

        if seed_type is not None:
            kind = self._make_index(seed_type, Enum_SeedID, bits=2,
                                    name='MPL seed-id type')  # type: Enum_SeedID | int
        elif seed is None or isinstance(seed, ipaddress.IPv6Address):
            kind = Enum_SeedID.IPV6_SOURCE_ADDRESS
        else:
            seed_bl = seed.bit_length()
            if seed_bl <= 16:
                kind = Enum_SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER
            elif seed_bl <= 64:
                kind = Enum_SeedID.SEEDID_64_BIT_UNSIGNED_INTEGER
            else:
                kind = Enum_SeedID.SEEDID_128_BIT_UNSIGNED_INTEGER

        if kind == Enum_SeedID.IPV6_SOURCE_ADDRESS:
            # The seed is the IPv6 source address, which is not on the wire.
            seed_id = None  # type: Optional[int]
            clen = 2
        else:
            if kind == Enum_SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER:
                clen = 4
            elif kind == Enum_SeedID.SEEDID_64_BIT_UNSIGNED_INTEGER:
                clen = 10
            else:  # the 128-bit seed, the last value of the two-bit type
                clen = 18

            if seed is None:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] missing MPL seed ID for type {kind}')
            seed_id = self._make_uint(int(seed) if isinstance(seed, ipaddress.IPv6Address) else seed,
                                      bits=(clen - 2) * 8, name='MPL seed ID')

        return Schema_MPLOption(
            type=code,
            len=clen,
            flags={
                'type': kind,
                'max': max,
                'drop': drop,
                'reserved': reserved,
            },
            seq=seq,
            seed=seed_id,
        )

    def _make_opt_ilnp(self, code: 'Enum_Option', opt: 'Optional[Data_ILNPOption]' = None, *,
                       nonce: 'int' = 0,
                       **kwargs: 'Any') -> 'Schema_ILNPOption':
        """Make HOPOPT ILNP option.

        Args:
            code: option type value
            opt: option data
            nonce: ILNP nonce value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``nonce`` is negative, or needs more octets than
                ``Opt Data Len`` can count.

        """
        # NOTE: A parsed nonce keeps the width it had on the wire, leading zero
        # octets and a zero-octet nonce included.
        if opt is not None:
            return Schema_ILNPOption(
                type=code,
                len=opt.length - 2,
                nonce=opt.nonce,
            )

        # NOTE: At least one octet, as RFC 6744 gives the option a Nonce Value
        # field that a nonce of 0 still fills.
        nonce = self._make_uint(nonce, bits=0xFF * 8, name='ILNP nonce')
        return Schema_ILNPOption(
            type=code,
            len=self._uint_size(nonce, minimum=1),
            nonce=nonce,
        )

    def _make_opt_lio(self, code: 'Enum_Option', opt: 'Optional[Data_LineIdentificationOption]' = None, *,
                      id: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_LineIdentificationOption':
        """Make HOPOPT LIO option.

        Args:
            code: option type value
            opt: option data
            id: line ID value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``id`` is too long for the one-octet
                ``Opt Data Len``.

        """
        if opt is not None:
            id = opt.line_id

        return Schema_LineIdentificationOption(
            type=code,
            len=self._make_uint(len(id) + 1, bits=8, name='Opt Data Len'),
            id_len=len(id),
            id=id,
        )

    def _make_opt_jumbo(self, code: 'Enum_Option', opt: 'Optional[Data_JumboPayloadOption]' = None, *,
                        len: 'int' = 0,
                        **kwargs: 'Any') -> 'Schema_JumboPayloadOption':
        """Make HOPOPT Jumbo Payload option.

        Args:
            code: option type value
            opt: option data
            len: jumbo payload length
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``len`` does not fit in four octets.

        """
        if opt is not None:
            len = opt.jumbo_len

        return Schema_JumboPayloadOption(
            type=code,
            len=4,
            jumbo_len=self._make_uint(len, bits=32, name='jumbo payload length'),
        )

    def _make_opt_home(self, code: 'Enum_Option', opt: 'Optional[Data_HomeAddressOption]' = None, *,
                       addr: 'IPv6Address | str | bytes | int' = '::',
                       **kwargs: 'Any') -> 'Schema_HomeAddressOption':
        """Make HOPOPT Home Address option.

        Args:
            code: option type value
            opt: option data
            addr: home address value
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

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
                         reserved: 'int' = 0,
                         seq: 'int' = 0,
                         **kwargs: 'Any') -> 'Schema_IPDFFOption':
        """Make HOPOPT IP DFF option.

        Args:
            code: option type value
            opt: option data
            version: DFF version
            dup: duplicate packet flag
            ret: return packet flag
            reserved: reserved bits, i.e. the low four bits of the flags octet
            seq: DFF sequence number
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``version``, ``reserved`` or ``seq`` does not fit
                its field.

        """
        if opt is not None:
            version = opt.version
            dup = opt.flags.dup
            ret = opt.flags.ret
            reserved = opt.flags.reserved
            seq = opt.seq

        # ``OptDataLenDFF`` is 3 per RFC 6971 Errata ID 3937, see _read_opt_ip_dff.
        return Schema_IPDFFOption(
            type=code,
            len=3,
            flags={
                'ver': self._make_uint(version, bits=2, name='DFF version'),
                'dup': dup,
                'ret': ret,
                'reserved': self._make_uint(reserved, bits=4, name='DFF reserved bits'),
            },
            seq=self._make_uint(seq, bits=16, name='DFF sequence number'),
        )
