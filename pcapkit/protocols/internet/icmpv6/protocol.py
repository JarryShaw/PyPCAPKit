# -*- coding: utf-8 -*-
"""ICMPv6 - Internet Control Message Protocol for IPv6
=========================================================

.. module:: pcapkit.protocols.internet.icmpv6.protocol

:mod:`pcapkit.protocols.internet.icmpv6.protocol` contains
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6` only,
which implements the extractor for Internet Control
Message Protocol for IPv6 (ICMPv6) [*]_, whose structure
is described as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``icmpv6.type``           Type
  1           8   ``icmpv6.code``           Code
  2          16   ``icmpv6.checksum``       Checksum
  4          32   ``icmpv6.data``           Message Body
======= ========= ======================= ===================================

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6

.. versionadded:: 1.6.0

"""
import collections
import ipaddress
from typing import TYPE_CHECKING, cast

from pcapkit.const.icmpv6.nd_option import NDOption as Enum_NDOption
from pcapkit.const.icmpv6.router_preference import RouterPreference as Enum_RouterPreference
from pcapkit.const.icmpv6.type import Type as Enum_Type
from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.corekit.schema.domain_name import make_name, name_to_text, read_name, text_to_labels
from pcapkit.corekit.schema.ipaddress import parse_ip_address
from pcapkit.corekit.schema.shortread import hoist_short_read
from pcapkit.protocols.internet.icmp.protocol import ICMP
from pcapkit.protocols.internet.icmpv6.const import PREF64_PREFIX_LENGTH
from pcapkit.protocols.internet.icmpv6.data import \
    AdvertisementIntervalOption as Data_AdvertisementIntervalOption
from pcapkit.protocols.internet.icmpv6.data import CaptivePortalOption as Data_CaptivePortalOption
from pcapkit.protocols.internet.icmpv6.data import \
    DestinationUnreachable as Data_DestinationUnreachable
from pcapkit.protocols.internet.icmpv6.data import DNSSLOption as Data_DNSSLOption
from pcapkit.protocols.internet.icmpv6.data import Echo as Data_Echo
from pcapkit.protocols.internet.icmpv6.data import \
    HomeAgentInformationOption as Data_HomeAgentInformationOption
from pcapkit.protocols.internet.icmpv6.data import ICMPv6 as Data_ICMPv6
from pcapkit.protocols.internet.icmpv6.data import \
    LinkLayerAddressOption as Data_LinkLayerAddressOption
from pcapkit.protocols.internet.icmpv6.data import MLDv1 as Data_MLDv1
from pcapkit.protocols.internet.icmpv6.data import MLDv2Query as Data_MLDv2Query
from pcapkit.protocols.internet.icmpv6.data import MLDv2Report as Data_MLDv2Report
from pcapkit.protocols.internet.icmpv6.data import MTUOption as Data_MTUOption
from pcapkit.protocols.internet.icmpv6.data import \
    MulticastAddressRecord as Data_MulticastAddressRecord
from pcapkit.protocols.internet.icmpv6.data import NDOption as Data_NDOption
from pcapkit.protocols.internet.icmpv6.data import \
    NeighborAdvertisement as Data_NeighborAdvertisement
from pcapkit.protocols.internet.icmpv6.data import NeighborSolicitation as Data_NeighborSolicitation
from pcapkit.protocols.internet.icmpv6.data import NonceOption as Data_NonceOption
from pcapkit.protocols.internet.icmpv6.data import PacketTooBig as Data_PacketTooBig
from pcapkit.protocols.internet.icmpv6.data import ParameterProblem as Data_ParameterProblem
from pcapkit.protocols.internet.icmpv6.data import PREF64Option as Data_PREF64Option
from pcapkit.protocols.internet.icmpv6.data import \
    PrefixInformationOption as Data_PrefixInformationOption
from pcapkit.protocols.internet.icmpv6.data import \
    RAFlagsExtensionOption as Data_RAFlagsExtensionOption
from pcapkit.protocols.internet.icmpv6.data import RDNSSOption as Data_RDNSSOption
from pcapkit.protocols.internet.icmpv6.data import Redirect as Data_Redirect
from pcapkit.protocols.internet.icmpv6.data import \
    RedirectedHeaderOption as Data_RedirectedHeaderOption
from pcapkit.protocols.internet.icmpv6.data import \
    RouteInformationOption as Data_RouteInformationOption
from pcapkit.protocols.internet.icmpv6.data import RouterAdvertisement as Data_RouterAdvertisement
from pcapkit.protocols.internet.icmpv6.data import RouterSolicitation as Data_RouterSolicitation
from pcapkit.protocols.internet.icmpv6.data import TimeExceeded as Data_TimeExceeded
from pcapkit.protocols.internet.icmpv6.data import Unknown as Data_Unknown
from pcapkit.protocols.internet.icmpv6.data import UnknownOption as Data_UnknownOption
from pcapkit.protocols.internet.icmpv6.schema import \
    AdvertisementIntervalOption as Schema_AdvertisementIntervalOption
from pcapkit.protocols.internet.icmpv6.schema import \
    CaptivePortalOption as Schema_CaptivePortalOption
from pcapkit.protocols.internet.icmpv6.schema import \
    DestinationUnreachable as Schema_DestinationUnreachable
from pcapkit.protocols.internet.icmpv6.schema import DNSSLOption as Schema_DNSSLOption
from pcapkit.protocols.internet.icmpv6.schema import Echo as Schema_Echo
from pcapkit.protocols.internet.icmpv6.schema import \
    HomeAgentInformationOption as Schema_HomeAgentInformationOption
from pcapkit.protocols.internet.icmpv6.schema import ICMPv6 as Schema_ICMPv6
from pcapkit.protocols.internet.icmpv6.schema import ICMPv6Type as Schema_ICMPv6Type
from pcapkit.protocols.internet.icmpv6.schema import \
    LinkLayerAddressOption as Schema_LinkLayerAddressOption
from pcapkit.protocols.internet.icmpv6.schema import MLDQuery as Schema_MLDQuery
from pcapkit.protocols.internet.icmpv6.schema import MLDv1 as Schema_MLDv1
from pcapkit.protocols.internet.icmpv6.schema import \
    MLDv2QueryExtension as Schema_MLDv2QueryExtension
from pcapkit.protocols.internet.icmpv6.schema import MLDv2Report as Schema_MLDv2Report
from pcapkit.protocols.internet.icmpv6.schema import MTUOption as Schema_MTUOption
from pcapkit.protocols.internet.icmpv6.schema import \
    MulticastAddressRecord as Schema_MulticastAddressRecord
from pcapkit.protocols.internet.icmpv6.schema import NDOption as Schema_NDOption
from pcapkit.protocols.internet.icmpv6.schema import \
    NeighborAdvertisement as Schema_NeighborAdvertisement
from pcapkit.protocols.internet.icmpv6.schema import \
    NeighborSolicitation as Schema_NeighborSolicitation
from pcapkit.protocols.internet.icmpv6.schema import NonceOption as Schema_NonceOption
from pcapkit.protocols.internet.icmpv6.schema import PacketTooBig as Schema_PacketTooBig
from pcapkit.protocols.internet.icmpv6.schema import ParameterProblem as Schema_ParameterProblem
from pcapkit.protocols.internet.icmpv6.schema import PREF64Option as Schema_PREF64Option
from pcapkit.protocols.internet.icmpv6.schema import \
    PrefixInformationOption as Schema_PrefixInformationOption
from pcapkit.protocols.internet.icmpv6.schema import \
    RAFlagsExtensionOption as Schema_RAFlagsExtensionOption
from pcapkit.protocols.internet.icmpv6.schema import RDNSSOption as Schema_RDNSSOption
from pcapkit.protocols.internet.icmpv6.schema import Redirect as Schema_Redirect
from pcapkit.protocols.internet.icmpv6.schema import \
    RedirectedHeaderOption as Schema_RedirectedHeaderOption
from pcapkit.protocols.internet.icmpv6.schema import \
    RouteInformationOption as Schema_RouteInformationOption
from pcapkit.protocols.internet.icmpv6.schema import \
    RouterAdvertisement as Schema_RouterAdvertisement
from pcapkit.protocols.internet.icmpv6.schema import RouterSolicitation as Schema_RouterSolicitation
from pcapkit.protocols.internet.icmpv6.schema import TimeExceeded as Schema_TimeExceeded
from pcapkit.protocols.internet.icmpv6.schema import Unknown as Schema_Unknown
from pcapkit.protocols.internet.icmpv6.schema import UnknownOption as Schema_UnknownOption
from pcapkit.protocols.misc.no_payload.protocol import NoPayload
from pcapkit.protocols.schema import Schema
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import BaseError, CaughtByCaller, ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import (Any, Callable, DefaultDict, Dict, Iterable, List, NoReturn, Optional, Tuple,
                        Union)

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo

    TypeParser = Callable[[Schema_ICMPv6Type, NamedArg(Schema_ICMPv6, 'header'), NamedArg(int, 'length')],
                          Data_ICMPv6]
    TypeConstructor = Callable[[Enum_Type, DefaultArg(Optional[Data_ICMPv6]), KwArg(Any)], Schema_ICMPv6Type]

    NDOptions = OrderedMultiDict[Enum_NDOption, Data_NDOption]
    NDOptionsLike = Union[NDOptions, List[Union[Schema_NDOption, Tuple[Union[Enum_NDOption, int], Dict[str, Any]],
                                                bytes]]]
    OptionParser = Callable[[Schema_NDOption, NamedArg(NDOptions, 'options')], Data_NDOption]
    OptionConstructor = Callable[[Enum_NDOption, DefaultArg(Optional[Data_NDOption]), KwArg(Any)],
                                 Schema_NDOption]

__all__ = ['ICMPv6']

#: The pseudo-header a payload's checksum is computed over in :meth:`ICMPv6.make`,
#: resolved there rather than imported, so its first import holds
#: :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_PSEUDO_HEADER: 'ModuleDescriptor[Any]' = \
    ModuleDescriptor('pcapkit.protocols.misc.checksum.ip_pseudo.protocol', 'pseudo_header')


class ICMPv6(ICMP[Data_ICMPv6, Schema_ICMPv6],
             schema=Schema_ICMPv6, data=Data_ICMPv6):
    """This class implements Internet Control Message Protocol for IPv6.

    This class parses the following ICMPv6 message
    types, which are registered in the
    :attr:`self.__type__ <pcapkit.protocols.internet.icmpv6.protocol.ICMPv6.__type__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Type
         - Data Parser
         - Data Constructor
       * - Destination Unreachable
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_destination_unreachable`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_destination_unreachable`
       * - Packet Too Big
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_packet_too_big`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_packet_too_big`
       * - Time Exceeded
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_time_exceeded`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_time_exceeded`
       * - Parameter Problem
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_parameter_problem`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_parameter_problem`
       * - Echo Request / Echo Reply
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_echo`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_echo`
       * - Multicast Listener Query
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_mld_query`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_mld_query`
       * - Multicast Listener Report / Multicast Listener Done
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_mldv1`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_mldv1`
       * - Router Solicitation
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_router_solicitation`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_router_solicitation`
       * - Router Advertisement
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_router_advertisement`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_router_advertisement`
       * - Neighbor Solicitation
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_neighbor_solicitation`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_neighbor_solicitation`
       * - Neighbor Advertisement
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_neighbor_advertisement`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_neighbor_advertisement`
       * - Redirect Message
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_redirect`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_redirect`
       * - Version 2 Multicast Listener Report
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_mldv2_report`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_mldv2_report`

    Any other type is kept as its raw message body, see
    :meth:`_read_data_type_none` and :meth:`_make_data_type_none`.

    The Neighbor Discovery messages (:rfc:`4861#section-4`) end in options,
    whose parsers are registered in the
    :attr:`self.__option__ <pcapkit.protocols.internet.icmpv6.protocol.ICMPv6.__option__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Option
         - Option Parser
         - Option Constructor
       * - Source and Target Link-layer Address
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_link_layer_address`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_link_layer_address`
       * - Prefix Information
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_prefix_information`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_prefix_information`
       * - Redirected Header
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_redirected_header`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_redirected_header`
       * - MTU
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_mtu`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_mtu`
       * - Advertisement Interval
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_advertisement_interval`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_advertisement_interval`
       * - Home Agent Information
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_home_agent_information`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_home_agent_information`
       * - Nonce
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_nonce`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_nonce`
       * - Route Information
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_route_information`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_route_information`
       * - Recursive DNS Server
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_rdnss`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_rdnss`
       * - RA Flags Extension
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_ra_flags_extension`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_ra_flags_extension`
       * - DNS Search List
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_dnssl`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_dnssl`
       * - Captive-Portal
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_captive_portal`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_captive_portal`
       * - PREF64
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_pref64`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_opt_pref64`

    Any other option is kept as its raw data, see :meth:`_read_opt_none` and
    :meth:`_make_opt_none`.

    .. versionchanged:: 1.6.0

       The checksum is computed when :meth:`make` is given none, over the
       ``pseudo`` it is given or by the enclosing IPv6 layer, and verified by
       that layer under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`
       (:issue:`2470`).

    .. versionchanged:: 1.7.0

       Decodes Multicast Listener Discovery, MLDv1 (:rfc:`2710`) and MLDv2
       (:rfc:`9777`).

    .. versionchanged:: 1.9.0

       Decodes Neighbor Discovery (:rfc:`4861`) and its options.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Type code to method mapping. A :obj:`str` value names the methods
    #: ``_read_data_type_${name}`` and ``_make_data_type_${name}``, falling
    #: back to ``_read_data_type_none`` / ``_make_data_type_none`` when they
    #: do not exist; any other value is a ``(parser, constructor)`` pair of
    #: callables.
    __type__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_Type.Destination_Unreachable:             'destination_unreachable',
            Enum_Type.Packet_Too_Big:                      'packet_too_big',
            Enum_Type.Time_Exceeded:                       'time_exceeded',
            Enum_Type.Parameter_Problem:                   'parameter_problem',
            Enum_Type.Echo_Request:                        'echo',
            Enum_Type.Echo_Reply:                          'echo',
            Enum_Type.Multicast_Listener_Query:            'mld_query',
            Enum_Type.Multicast_Listener_Report:           'mldv1',
            Enum_Type.Multicast_Listener_Done:             'mldv1',
            Enum_Type.Router_Solicitation:                 'router_solicitation',
            Enum_Type.Router_Advertisement:                'router_advertisement',
            Enum_Type.Neighbor_Solicitation:               'neighbor_solicitation',
            Enum_Type.Neighbor_Advertisement:              'neighbor_advertisement',
            Enum_Type.Redirect_Message:                    'redirect',
            Enum_Type.Version_2_Multicast_Listener_Report: 'mldv2_report',
        },
    )  # type: DefaultDict[Enum_Type | int, str | tuple[TypeParser, TypeConstructor]]

    #: Neighbor Discovery option type to method mapping. A :obj:`str` value
    #: names the methods ``_read_opt_${name}`` and ``_make_opt_${name}``,
    #: falling back to ``_read_opt_none`` / ``_make_opt_none`` when they do
    #: not exist; any other value is a ``(parser, constructor)`` pair of
    #: callables.
    __option__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_NDOption.Source_Link_layer_Address:     'link_layer_address',
            Enum_NDOption.Target_Link_layer_Address:     'link_layer_address',
            Enum_NDOption.Prefix_Information:            'prefix_information',
            Enum_NDOption.Redirected_Header:             'redirected_header',
            Enum_NDOption.MTU:                           'mtu',
            Enum_NDOption.Advertisement_Interval_Option: 'advertisement_interval',
            Enum_NDOption.Home_Agent_Information_Option: 'home_agent_information',
            Enum_NDOption.Nonce_option:                  'nonce',
            Enum_NDOption.Route_Information_Option:      'route_information',
            Enum_NDOption.Recursive_DNS_Server_Option:   'rdnss',
            Enum_NDOption.RA_Flags_Extension_Option:     'ra_flags_extension',
            Enum_NDOption.DNS_Search_List_Option:        'dnssl',
            Enum_NDOption.DHCP_Captive_Portal:           'captive_portal',
            Enum_NDOption.PREF64_option:                 'pref64',
        },
    )  # type: DefaultDict[Enum_NDOption | int, str | tuple[OptionParser, OptionConstructor]]

    #: Whether :meth:`make` left the checksum for the enclosing IP layer to
    #: compute, see :mod:`pcapkit.protocols.misc.checksum.ip_pseudo.protocol`.
    _checksum_pending = False

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Control Message Protocol for IPv6"]':
        """Name of current protocol."""
        return 'Internet Control Message Protocol for IPv6'

    @property
    def alias(self) -> 'Literal["ICMPv6"]':
        """Acronym of corresponding protocol."""
        return 'ICMPv6'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["ICMPv6"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('ICMPv6',)

    def read(self, length: 'Optional[int]' = None, *,
             __packet__: 'Optional[dict[str, Any]]' = None, **kwargs: 'Any') -> 'Data_ICMPv6':  # pylint: disable=unused-argument
        """Read Internet Control Message Protocol for IPv6 (ICMPv6).

        Structure of ICMPv6 header [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                         Message Body                         +
           |                                                               |

        Args:
            length: Length of packet data.
            __packet__: Optional packet data, unused.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        name = self._lookup_registry(self.__type__, schema.type)
        if isinstance(name, str):
            name = f'_read_data_type_{name}'
            meth = cast('TypeParser',
                       getattr(self, name, self._read_data_type_none))
        else:
            meth = name[0]
        icmpv6 = meth(schema.data, header=schema, length=length)

        body = schema.data
        if isinstance(body, Schema_MLDQuery):
            parts = (body, body.ext)  # type: tuple[Optional[Schema], ...]
        elif isinstance(body, Schema_MLDv2Report):
            parts = (body, *body.records)
        elif isinstance(body, (Schema_RouterSolicitation, Schema_RouterAdvertisement, Schema_NeighborSolicitation,
                               Schema_NeighborAdvertisement, Schema_Redirect)):
            parts = (body, *body.options)
        else:
            parts = (body,)
        # NOTE: Every schema in the body reads to the end of the data, so a cut
        # inside one is the message's, as a Report counting records past it.
        hoist_short_read(schema, 'data', parts)

        # NOTE: The quoted original packet stays raw in the message body,
        # so there is no next layer; the schema has no ``payload`` field.
        self._next = NoPayload.from_fields()  # pylint: disable=attribute-defined-outside-init
        self._protos = ProtoChain(self.__class__, self.alias)  # pylint: disable=attribute-defined-outside-init
        return icmpv6

    def make(self, *,
             type: 'Enum_Type | int' = Enum_Type.Echo_Request,  # pylint: disable=redefined-builtin
             code: 'int' = 0,
             checksum: 'Optional[bytes]' = None,
             # Echo identifier and sequence number, the shortest body.
             body: 'bytes | Data_ICMPv6 | Schema_ICMPv6Type | dict[str, Any]' = b'\x00\x00\x00\x00',
             pseudo: 'Optional[IP_Pseudo]' = None,
             **kwargs: 'Any') -> 'Schema_ICMPv6':
        """Make (construct) packet data.

        Args:
            type: ICMPv6 type.
            code: ICMPv6 code; meaning is entirely ``type``-dependent.
            checksum: Checksum; if :data:`None` and
                :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is on,
                computed over ``pseudo`` (:rfc:`4443#section-2.3`), or left to
                an IPv6 layer this message is the payload of; zero otherwise.
            body: Message body. :obj:`bytes` is parsed against ``type``'s own
                schema; a :obj:`dict` or a
                :class:`~pcapkit.protocols.internet.icmpv6.data.ICMPv6` data
                model is handed to that type's own constructor method (see
                :attr:`__type__`); any other
                :class:`~pcapkit.protocols.internet.icmpv6.schema.ICMPv6Type`
                is used as is.
            pseudo: Pseudo-header of the enclosing IPv6 layer; its length is
                replaced by this message's own.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``type`` is a name, a :obj:`bool`, or a member
                or code that does not fit in one octet; if ``body`` is
                :obj:`bytes` that do not parse as the message body of
                ``type``, or is of none of the accepted types; or if
                ``checksum`` is not two octets.

        """
        type_val = self._make_index(type, Enum_Type, bits=8, name='type')

        if isinstance(body, bytes):
            try:
                data_val = Schema_ICMPv6Type.registry[type_val].unpack(  # pylint: disable=unsubscriptable-object
                    body, len(body), {})  # type: Schema_ICMPv6Type
            except Exception as exc:
                raise ProtocolError(f'{self.alias}: [TypeNo {type_val}] message body '
                                    f'{body.hex()} does not parse as this type') from exc
        elif isinstance(body, (dict, Data_ICMPv6)):
            name = self._lookup_registry(self.__type__, type_val)
            if isinstance(name, str):
                name = f'_make_data_type_{name}'
                meth = cast('TypeConstructor',
                           getattr(self, name, self._make_data_type_none))
            else:
                meth = name[1]

            if isinstance(body, dict):
                data_val = meth(type_val, **body)
            else:
                data_val = meth(type_val, body)
        elif isinstance(body, Schema_ICMPv6Type):
            data_val = body
        else:
            raise ProtocolError(f'{self.alias}: invalid message body type: {body.__class__}')

        schema = Schema_ICMPv6(
            type=type_val,
            code=code,
            checksum=b'\x00\x00' if checksum is None else self._make_octets(checksum, size=2, name='checksum'),
            data=data_val,
        )

        self._checksum_pending = False
        if checksum is None and config.CHECKSUM_COMPUTE:
            if pseudo is None:
                self._checksum_pending = True
            else:
                from pcapkit.corekit.checksum.internet import compute_checksum  # isort: skip # pylint: disable=import-outside-toplevel
                pseudo_header = _PSEUDO_HEADER.klass
                octets = schema.pack()
                schema.checksum = compute_checksum(octets, prefix=pseudo_header(pseudo, len(octets)))
        return schema

    @classmethod
    def register_type(cls, code: 'Enum_Type', meth: 'str | tuple[TypeParser, TypeConstructor]') -> 'None':
        """Register a message body parser.

        Args:
            code: ICMPv6 type code.
            meth: Name ``X`` of the ``_read_data_type_X`` and
                ``_make_data_type_X`` methods, or a ``(parser, constructor)``
                pair of callables, see :attr:`__type__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten.

        """
        incumbent = cls.__type__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'type {code} already registered, overwriting', RegistryWarning)
        cls.__type__[code] = meth

    @classmethod
    def register_option(cls, code: 'Enum_NDOption', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register a Neighbor Discovery option parser.

        Args:
            code: ND option type.
            meth: Name ``X`` of the ``_read_opt_X`` and ``_make_opt_X``
                methods, or a ``(parser, constructor)`` pair of callables, see
                :attr:`__option__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten.

        .. versionadded:: 1.9.0

        """
        incumbent = cls.__option__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'option {code} already registered, overwriting', RegistryWarning)
        cls.__option__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object."""
        return 4

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IPv6_ICMP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_ICMPv6') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'type': data.type,
            'code': data.code,
            'checksum': data.checksum,
            'body': data,
        }

    def _read_data_type_none(self, schema: 'Schema_Unknown', *, header: 'Schema_ICMPv6',
                             length: 'int') -> 'Data_Unknown':
        """Read ICMPv6 message of unknown type.

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_Unknown(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            data=schema.data,
        )

    def _read_data_type_destination_unreachable(self, schema: 'Schema_DestinationUnreachable', *,
                                                header: 'Schema_ICMPv6',
                                                length: 'int') -> 'Data_DestinationUnreachable':
        """Read ICMPv6 Destination Unreachable message.

        Structure of ICMPv6 Destination Unreachable message [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                             Unused                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    As much of invoking packet                |
           |                   as will fit without the ICMPv6             |
           |                   packet exceeding the minimum IPv6 MTU      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_DestinationUnreachable(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            unused=schema.unused,
            data=schema.data,
        )

    def _read_data_type_packet_too_big(self, schema: 'Schema_PacketTooBig', *, header: 'Schema_ICMPv6',
                                       length: 'int') -> 'Data_PacketTooBig':
        """Read ICMPv6 Packet Too Big message.

        Structure of ICMPv6 Packet Too Big message [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                             MTU                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    As much of invoking packet                |
           |                   as will fit without the ICMPv6             |
           |                   packet exceeding the minimum IPv6 MTU      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_PacketTooBig(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            mtu=schema.mtu,
            data=schema.data,
        )

    def _read_data_type_time_exceeded(self, schema: 'Schema_TimeExceeded', *, header: 'Schema_ICMPv6',
                                      length: 'int') -> 'Data_TimeExceeded':
        """Read ICMPv6 Time Exceeded message.

        Structure of ICMPv6 Time Exceeded message [:rfc:`4443`] is identical
        to that of :meth:`_read_data_type_destination_unreachable`, but for
        the type code.

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_TimeExceeded(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            unused=schema.unused,
            data=schema.data,
        )

    def _read_data_type_parameter_problem(self, schema: 'Schema_ParameterProblem', *,
                                          header: 'Schema_ICMPv6',
                                          length: 'int') -> 'Data_ParameterProblem':
        """Read ICMPv6 Parameter Problem message.

        Structure of ICMPv6 Parameter Problem message [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            Pointer                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    As much of invoking packet                |
           |                   as will fit without the ICMPv6             |
           |                   packet exceeding the minimum IPv6 MTU      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_ParameterProblem(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            pointer=schema.pointer,
            data=schema.data,
        )

    def _read_data_type_echo(self, schema: 'Schema_Echo', *, header: 'Schema_ICMPv6',
                             length: 'int') -> 'Data_Echo':
        """Read ICMPv6 Echo Request/Reply message.

        Structure of ICMPv6 Echo Request/Reply message [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Identifier          |        Sequence Number        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                             Data                              +
           |                                                               |

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_Echo(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            id=schema.id,
            seq=schema.seq,
            data=schema.data,
        )

    def _read_data_type_mld_query(self, schema: 'Schema_MLDQuery', *, header: 'Schema_ICMPv6',
                                  length: 'int') -> 'Data_MLDv1 | Data_MLDv2Query':
        """Read MLD Multicast Listener Query message.

        Structure of MLDv2 Multicast Listener Query message [:rfc:`9777`], whose
        first 24 octets are the whole of an MLDv1 Query [:rfc:`2710`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Type = 130   |      Code     |           Checksum            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Maximum Response Code      |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           *                       Multicast Address                       *
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Flags |S| QRV |     QQIC      |     Number of Sources (N)     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           *                       Source Address [1..N]                   *
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        A Query of 28 or more octets is MLDv2's, and one of fewer MLDv1's
        (:rfc:`9777#section-8.1`), see
        :func:`~pcapkit.protocols.internet.icmpv6.schema.mldv2_query_present`.

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data: MLDv1's or MLDv2's.

        """
        ext = schema.ext
        if ext is None:
            return Data_MLDv1(
                type=header.type,
                code=header.code,
                checksum=header.checksum,
                length=length,
                version=1,
                max_resp_delay=schema.max_resp_code,
                reserved=schema.reserved,
                multicast_address=schema.multicast_address,
                data=schema.data,
            )
        return Data_MLDv2Query(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            version=2,
            max_resp_code=schema.max_resp_code,
            max_resp_delay=self._read_float_code(schema.max_resp_code, bits=16),
            reserved=schema.reserved,
            multicast_address=schema.multicast_address,
            flags=ext.flags['flags'],
            s_flag=bool(ext.flags['s_flag']),
            qrv=ext.flags['qrv'],
            qqic=ext.qqic,
            qqi=self._read_float_code(ext.qqic, bits=8),
            num_sources=ext.num_sources,
            sources=tuple(ext.sources),
            data=ext.data,
        )

    def _read_data_type_mldv1(self, schema: 'Schema_MLDv1', *, header: 'Schema_ICMPv6',
                              length: 'int') -> 'Data_MLDv1':
        """Read MLDv1 Multicast Listener Report/Done message.

        Structure of MLDv1 message [:rfc:`2710`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Maximum Response Delay    |          Reserved             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                       Multicast Address                       +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_MLDv1(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            version=1,
            max_resp_delay=schema.max_resp_delay,
            reserved=schema.reserved,
            multicast_address=schema.multicast_address,
            data=schema.data,
        )

    def _read_data_type_router_solicitation(self, schema: 'Schema_RouterSolicitation', *,
                                            header: 'Schema_ICMPv6',
                                            length: 'int') -> 'Data_RouterSolicitation':
        """Read Neighbor Discovery Router Solicitation message.

        Structure of Router Solicitation message [:rfc:`4861#section-4.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            Reserved                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Options ...
           +-+-+-+-+-+-+-+-+-+-+-+-

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_RouterSolicitation(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            reserved=schema.reserved,
            options=self._read_nd_options(schema.options),
        )

    def _read_data_type_router_advertisement(self, schema: 'Schema_RouterAdvertisement', *,
                                             header: 'Schema_ICMPv6',
                                             length: 'int') -> 'Data_RouterAdvertisement':
        """Read Neighbor Discovery Router Advertisement message.

        Structure of Router Advertisement message [:rfc:`4861#section-4.2`], its
        flags as IANA's Router Advertisement Flags assigns them
        [:rfc:`5175#section-3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Cur Hop Limit |M|O|H|Prf|P|S|R|       Router Lifetime         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Reachable Time                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                          Retrans Timer                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Options ...
           +-+-+-+-+-+-+-+-+-+-+-+-

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        flags = schema.flags
        return Data_RouterAdvertisement(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            cur_hop_limit=schema.cur_hop_limit,
            m_flag=bool(flags['m_flag']),
            o_flag=bool(flags['o_flag']),
            h_flag=bool(flags['h_flag']),
            prf=Enum_RouterPreference.get(flags['prf']),
            p_flag=bool(flags['p_flag']),
            s_flag=bool(flags['s_flag']),
            reserved=flags['reserved'],
            router_lifetime=schema.router_lifetime,
            reachable_time=schema.reachable_time,
            retrans_timer=schema.retrans_timer,
            options=self._read_nd_options(schema.options),
        )

    def _read_data_type_neighbor_solicitation(self, schema: 'Schema_NeighborSolicitation', *,
                                              header: 'Schema_ICMPv6',
                                              length: 'int') -> 'Data_NeighborSolicitation':
        """Read Neighbor Discovery Neighbor Solicitation message.

        Structure of Neighbor Solicitation message [:rfc:`4861#section-4.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Reserved                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                       Target Address                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Options ...
           +-+-+-+-+-+-+-+-+-+-+-+-

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_NeighborSolicitation(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            reserved=schema.reserved,
            target_address=schema.target_address,
            options=self._read_nd_options(schema.options),
        )

    def _read_data_type_neighbor_advertisement(self, schema: 'Schema_NeighborAdvertisement', *,
                                               header: 'Schema_ICMPv6',
                                               length: 'int') -> 'Data_NeighborAdvertisement':
        """Read Neighbor Discovery Neighbor Advertisement message.

        Structure of Neighbor Advertisement message [:rfc:`4861#section-4.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |R|S|O|                     Reserved                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                       Target Address                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Options ...
           +-+-+-+-+-+-+-+-+-+-+-+-

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        flags = schema.flags
        return Data_NeighborAdvertisement(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            r_flag=bool(flags['r_flag']),
            s_flag=bool(flags['s_flag']),
            o_flag=bool(flags['o_flag']),
            reserved=flags['reserved'],
            target_address=schema.target_address,
            options=self._read_nd_options(schema.options),
        )

    def _read_data_type_redirect(self, schema: 'Schema_Redirect', *, header: 'Schema_ICMPv6',
                                 length: 'int') -> 'Data_Redirect':
        """Read Neighbor Discovery Redirect message.

        Structure of Redirect message [:rfc:`4861#section-4.5`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Reserved                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                       Target Address                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                     Destination Address                       +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Options ...
           +-+-+-+-+-+-+-+-+-+-+-+-

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_Redirect(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            reserved=schema.reserved,
            target_address=schema.target_address,
            destination_address=schema.destination_address,
            options=self._read_nd_options(schema.options),
        )

    def _read_data_type_mldv2_report(self, schema: 'Schema_MLDv2Report', *, header: 'Schema_ICMPv6',
                                     length: 'int') -> 'Data_MLDv2Report':
        """Read MLDv2 Version 2 Multicast Listener Report message.

        Structure of MLDv2 Report message [:rfc:`9777`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Type = 143   |    Reserved   |           Checksum            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |             Flags             |Nr of Mcast Address Records (M)|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                  Multicast Address Record [1..M]              .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Each record has the shape of an IGMPv3 group record
        (:rfc:`3376#section-4.2.4`), with IPv6 addresses:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           *                       Multicast Address                       *
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           *                       Source Address [1..N]                   *
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                         Auxiliary Data                        .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        records = tuple(
            Data_MulticastAddressRecord(
                record_type=record.record_type,
                aux_data_len=record.aux_data_len,
                num_sources=record.num_sources,
                multicast_address=record.multicast_address,
                sources=tuple(record.sources),
                aux_data=record.aux_data,
            ) for record in schema.records
        )
        return Data_MLDv2Report(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            version=2,
            flags=schema.flags,
            num_records=schema.num_records,
            records=records,
            data=schema.data,
        )

    def _read_opt_none(self, schema: 'Schema_UnknownOption', *,
                       options: 'NDOptions') -> 'Data_UnknownOption':  # pylint: disable=unused-argument
        """Read ND option of a type not decoded.

        Structure of ND option [:rfc:`4861#section-4.6`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |              ...              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           ~                              ...                              ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        return Data_UnknownOption(
            type=schema.type,
            length=schema.length * 8,
            data=schema.data,
        )

    def _read_opt_link_layer_address(self, schema: 'Schema_LinkLayerAddressOption', *,
                                     options: 'NDOptions') -> 'Data_LinkLayerAddressOption':  # pylint: disable=unused-argument
        """Read ND Source or Target Link-layer Address option.

        Structure of Link-layer Address option [:rfc:`4861#section-4.6.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |    Link-Layer Address ...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        return Data_LinkLayerAddressOption(
            type=schema.type,
            length=schema.length * 8,
            link_layer_address=schema.link_layer_address,
        )

    def _read_opt_prefix_information(self, schema: 'Schema_PrefixInformationOption', *,
                                     options: 'NDOptions') -> 'Data_PrefixInformationOption':  # pylint: disable=unused-argument
        """Read ND Prefix Information option.

        Structure of Prefix Information option [:rfc:`4861#section-4.6.2`], its
        flags as IANA's Prefix Information Option Flags assigns them
        [:rfc:`8425`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     | Prefix Length |L|A|R|P| Rsvd1 |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Valid Lifetime                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Preferred Lifetime                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Reserved2                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                            Prefix                             +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        flags = schema.flags
        return Data_PrefixInformationOption(
            type=schema.type,
            length=schema.length * 8,
            prefix_length=schema.prefix_length,
            l_flag=bool(flags['l_flag']),
            a_flag=bool(flags['a_flag']),
            r_flag=bool(flags['r_flag']),
            p_flag=bool(flags['p_flag']),
            reserved1=flags['reserved1'],
            valid_lifetime=schema.valid_lifetime,
            preferred_lifetime=schema.preferred_lifetime,
            reserved2=schema.reserved2,
            prefix=schema.prefix,
        )

    def _read_opt_redirected_header(self, schema: 'Schema_RedirectedHeaderOption', *,
                                    options: 'NDOptions') -> 'Data_RedirectedHeaderOption':  # pylint: disable=unused-argument
        """Read ND Redirected Header option.

        Structure of Redirected Header option [:rfc:`4861#section-4.6.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |            Reserved           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Reserved                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           ~                       IP header + data                        ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        return Data_RedirectedHeaderOption(
            type=schema.type,
            length=schema.length * 8,
            reserved=schema.reserved,
            data=schema.data,
        )

    def _read_opt_mtu(self, schema: 'Schema_MTUOption', *,
                      options: 'NDOptions') -> 'Data_MTUOption':  # pylint: disable=unused-argument
        """Read ND MTU option.

        Structure of MTU option [:rfc:`4861#section-4.6.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                              MTU                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        return Data_MTUOption(
            type=schema.type,
            length=schema.length * 8,
            reserved=schema.reserved,
            mtu=schema.mtu,
        )

    def _read_opt_advertisement_interval(self, schema: 'Schema_AdvertisementIntervalOption', *,
                                         options: 'NDOptions') -> 'Data_AdvertisementIntervalOption':  # pylint: disable=unused-argument
        """Read ND Advertisement Interval option.

        Structure of Advertisement Interval option [:rfc:`6275#section-7.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                     Advertisement Interval                    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        return Data_AdvertisementIntervalOption(
            type=schema.type,
            length=schema.length * 8,
            reserved=schema.reserved,
            interval=schema.interval,
        )

    def _read_opt_home_agent_information(self, schema: 'Schema_HomeAgentInformationOption', *,
                                         options: 'NDOptions') -> 'Data_HomeAgentInformationOption':  # pylint: disable=unused-argument
        """Read ND Home Agent Information option.

        Structure of Home Agent Information option [:rfc:`6275#section-7.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Home Agent Preference     |      Home Agent Lifetime      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        return Data_HomeAgentInformationOption(
            type=schema.type,
            length=schema.length * 8,
            reserved=schema.reserved,
            preference=schema.preference,
            lifetime=schema.lifetime,
        )

    def _read_opt_nonce(self, schema: 'Schema_NonceOption', *,
                        options: 'NDOptions') -> 'Data_NonceOption':  # pylint: disable=unused-argument
        """Read ND Nonce option.

        Structure of Nonce option [:rfc:`3971#section-5.3.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |  Nonce ...                    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
           |                                                               |
           .                                                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        return Data_NonceOption(
            type=schema.type,
            length=schema.length * 8,
            nonce=schema.nonce,
        )

    def _read_opt_route_information(self, schema: 'Schema_RouteInformationOption', *,
                                    options: 'NDOptions') -> 'Data_RouteInformationOption':  # pylint: disable=unused-argument
        """Read ND Route Information option.

        Structure of Route Information option [:rfc:`4191#section-2.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     | Prefix Length |Resvd|Prf|Resvd|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Route Lifetime                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                   Prefix (Variable Length)                    |
           .                                                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the Length is above 3, leaving more of the prefix
                than an IPv6 address holds.

        """
        if len(schema.prefix) > 16:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid Route Information '
                                f'option length: {schema.length}')
        flags = schema.flags
        return Data_RouteInformationOption(
            type=schema.type,
            length=schema.length * 8,
            prefix_length=schema.prefix_length,
            reserved1=flags['reserved1'],
            prf=Enum_RouterPreference.get(flags['prf']),
            reserved2=flags['reserved2'],
            lifetime=schema.lifetime,
            prefix=ipaddress.IPv6Address(schema.prefix.ljust(16, b'\x00')),
        )

    def _read_opt_rdnss(self, schema: 'Schema_RDNSSOption', *,
                        options: 'NDOptions') -> 'Data_RDNSSOption':  # pylint: disable=unused-argument
        """Read ND Recursive DNS Server option.

        Structure of RDNSS option [:rfc:`8106#section-5.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Length    |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Lifetime                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           :            Addresses of IPv6 Recursive DNS Servers            :
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the Length is below 3 or even, the minimum and the
                parity the receiver checks (:rfc:`8106#section-5.3.1`).

        """
        if schema.length < 3 or not schema.length % 2:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid RDNSS option length: '
                                f'{schema.length}')
        # NOTE: Addresses the capture cut off read as zeros, as the octets of any other field do.
        missing = (schema.length - 1) // 2 - len(schema.addresses)
        return Data_RDNSSOption(
            type=schema.type,
            length=schema.length * 8,
            reserved=schema.reserved,
            lifetime=schema.lifetime,
            addresses=(*schema.addresses, *(ipaddress.IPv6Address(0),) * missing),
        )

    def _read_opt_ra_flags_extension(self, schema: 'Schema_RAFlagsExtensionOption', *,
                                     options: 'NDOptions') -> 'Data_RAFlagsExtensionOption':  # pylint: disable=unused-argument
        """Read ND RA Flags Extension option.

        Structure of RA Flags Extension option [:rfc:`5175#section-4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |         Bit fields available ..
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           ... for assignment                                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        return Data_RAFlagsExtensionOption(
            type=schema.type,
            length=schema.length * 8,
            bits=schema.bits,
        )

    def _read_opt_dnssl(self, schema: 'Schema_DNSSLOption', *,
                        options: 'NDOptions') -> 'Data_DNSSLOption':  # pylint: disable=unused-argument
        """Read ND DNS Search List option.

        Structure of DNSSL option [:rfc:`8106#section-5.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Length    |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Lifetime                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           :                Domain Names of DNS Search List                :
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        The names are read uncompressed, as :rfc:`1035#section-3.1` lays them
        out, up to the first zero octet that starts none: the zero padding
        :rfc:`8106#section-5.2` ends the field with.

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If the Length is below 2, the minimum the receiver
                checks (:rfc:`8106#section-5.3.1`), or a name runs past the
                field, or holds a label type other than a plain label.

        """
        if schema.length < 2:
            raise ProtocolError(f'{self.alias}: [OptNo {schema.type}] invalid DNSSL option length: '
                                f'{schema.length}')
        field = schema.names
        names = []  # type: list[str]
        pos = 0
        while pos < len(field) and field[pos]:
            labels, _, _, pos = read_name(field, pos, compression=False, alias=self.alias)
            names.append(name_to_text(labels))
        return Data_DNSSLOption(
            type=schema.type,
            length=schema.length * 8,
            reserved=schema.reserved,
            lifetime=schema.lifetime,
            domain_names=tuple(names),
            padding=field[pos:],
        )

    def _read_opt_captive_portal(self, schema: 'Schema_CaptivePortalOption', *,
                                 options: 'NDOptions') -> 'Data_CaptivePortalOption':  # pylint: disable=unused-argument
        """Read ND Captive-Portal option.

        Structure of Captive-Portal option [:rfc:`8910#section-2.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Length    |              URI              .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               .
           .                                                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        The URI is the octets ahead of the first NUL, the NUL padding the rest,
        since :rfc:`8910#section-2.3` does not have the URI NUL-terminated.

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        uri, nul, padding = schema.uri.partition(b'\x00')
        return Data_CaptivePortalOption(
            type=schema.type,
            length=schema.length * 8,
            uri=uri,
            padding=nul + padding,
        )

    def _read_opt_pref64(self, schema: 'Schema_PREF64Option', *,
                         options: 'NDOptions') -> 'Data_PREF64Option':  # pylint: disable=unused-argument
        """Read ND PREF64 option.

        Structure of PREF64 option [:rfc:`8781#section-4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |     Scaled Lifetime     | PLC |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |              Highest 96 bits of the Prefix                    |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed option schema
            options: options parsed so far

        Returns:
            Parsed option data.

        """
        lifetime = schema.lifetime
        return Data_PREF64Option(
            type=schema.type,
            length=schema.length * 8,
            scaled_lifetime=lifetime['scaled_lifetime'],
            lifetime=lifetime['scaled_lifetime'] * 8,
            plc=lifetime['plc'],
            prefix_length=PREF64_PREFIX_LENGTH.get(lifetime['plc']),
            prefix=ipaddress.IPv6Address(schema.prefix + bytes(4)),
        )

    def _make_data_type_none(self, type: 'Enum_Type', message: 'Optional[Data_Unknown]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                             data: 'bytes' = b'', **kwargs: 'Any') -> 'Schema_Unknown':
        """Make ICMPv6 message of unknown type.

        Args:
            type: ICMPv6 type.
            message: message data.
            data: raw message body as :obj:`bytes`.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            data = message.data
        return Schema_Unknown(data=data)

    def _make_data_type_destination_unreachable(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                                message: 'Optional[Data_DestinationUnreachable]' = None, *,
                                                unused: 'bytes' = b'\x00\x00\x00\x00',
                                                data: 'bytes' = b'',
                                                **kwargs: 'Any') -> 'Schema_DestinationUnreachable':
        """Make ICMPv6 Destination Unreachable message.

        Args:
            type: ICMPv6 type.
            message: message data.
            unused: the four unused octets.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``unused`` is not four octets.

        """
        if message is not None:
            unused = self._fill_short_read(getattr(message, 'unused', b'\x00\x00\x00\x00'),
                                           size=4, model=message, field='data')
            data = message.data
        return Schema_DestinationUnreachable(unused=self._make_octets(unused, size=4, name='unused octets'),
                                             data=data)

    def _make_data_type_packet_too_big(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                       message: 'Optional[Data_PacketTooBig]' = None, *,
                                       mtu: 'int' = 0, data: 'bytes' = b'',
                                       **kwargs: 'Any') -> 'Schema_PacketTooBig':
        """Make ICMPv6 Packet Too Big message.

        Args:
            type: ICMPv6 type.
            message: message data.
            mtu: MTU of the link that could not forward the invoking packet.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            mtu = message.mtu
            data = message.data
        return Schema_PacketTooBig(mtu=mtu, data=data)

    def _make_data_type_time_exceeded(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                      message: 'Optional[Data_TimeExceeded]' = None, *,
                                      unused: 'bytes' = b'\x00\x00\x00\x00',
                                      data: 'bytes' = b'', **kwargs: 'Any') -> 'Schema_TimeExceeded':
        """Make ICMPv6 Time Exceeded message.

        Args:
            type: ICMPv6 type.
            message: message data.
            unused: the four unused octets.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``unused`` is not four octets.

        """
        if message is not None:
            unused = self._fill_short_read(getattr(message, 'unused', b'\x00\x00\x00\x00'),
                                           size=4, model=message, field='data')
            data = message.data
        return Schema_TimeExceeded(unused=self._make_octets(unused, size=4, name='unused octets'),
                                   data=data)

    def _make_data_type_parameter_problem(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                          message: 'Optional[Data_ParameterProblem]' = None, *,
                                          pointer: 'int' = 0, data: 'bytes' = b'',
                                          **kwargs: 'Any') -> 'Schema_ParameterProblem':
        """Make ICMPv6 Parameter Problem message.

        Args:
            type: ICMPv6 type.
            message: message data.
            pointer: pointer to the octet offset within the invoking packet
                where the error was detected.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            pointer = message.pointer
            data = message.data
        return Schema_ParameterProblem(pointer=pointer, data=data)

    def _make_data_type_echo(self, type: 'Enum_Type', message: 'Optional[Data_Echo]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                             id: 'int' = 0, seq: 'int' = 0, data: 'bytes' = b'',  # pylint: disable=redefined-builtin
                             **kwargs: 'Any') -> 'Schema_Echo':
        """Make ICMPv6 Echo Request/Reply message.

        Args:
            type: ICMPv6 type.
            message: message data.
            id: identifier.
            seq: sequence number.
            data: data, echoed back verbatim by a reply to the same
                identifier and sequence number.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            id = message.id
            seq = message.seq
            data = message.data
        return Schema_Echo(id=id, seq=seq, data=data)

    def _make_data_type_mld_query(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                  message: 'Optional[Data_MLDv1 | Data_MLDv2Query]' = None, *,
                                  version: 'Optional[int]' = None,
                                  max_resp_code: 'Optional[int]' = None,
                                  max_resp_delay: 'int' = 0,
                                  reserved: 'bytes' = b'\x00\x00',
                                  multicast_address: 'IPv6Address | str | bytes | int' = '::',
                                  flags: 'Optional[int]' = None,
                                  s_flag: 'Optional[bool]' = None,
                                  qrv: 'Optional[int]' = None,
                                  qqic: 'Optional[int]' = None,
                                  qqi: 'Optional[int]' = None,
                                  num_sources: 'Optional[int]' = None,
                                  sources: 'Optional[Iterable[IPv6Address | str | bytes | int]]' = None,
                                  data: 'bytes' = b'',
                                  **kwargs: 'Any') -> 'Schema_MLDQuery':
        """Make MLD Multicast Listener Query message.

        Args:
            type: ICMPv6 type.
            message: message data, whose ``version`` picks the version built.
            version: MLD version, ``1`` (:rfc:`2710`) or ``2`` (:rfc:`9777`),
                which type 130 is shared by; no field picks it.
            max_resp_code: MLDv2's Maximum Response Code, as on the wire;
                encoded from ``max_resp_delay`` when not given.
            max_resp_delay: Maximum Response Delay, in milliseconds; MLDv1's
                field, or what MLDv2's ``max_resp_code`` encodes.
            reserved: the two reserved octets.
            multicast_address: multicast address queried, ``::`` for a General
                Query.
            flags: MLDv2's four flag bits, zero when not given.
            s_flag: MLDv2's Suppress Router-Side Processing flag, clear when
                not given.
            qrv: MLDv2's Querier's Robustness Variable, zero when not given.
            qqic: MLDv2's Querier's Query Interval Code, as on the wire;
                encoded from ``qqi`` when not given.
            qqi: MLDv2's Querier's Query Interval, in seconds.
            num_sources: MLDv2's number of sources, the length of ``sources``
                when not given; a count above it is written as given, as on a
                Query the capture cut inside its sources.
            sources: MLDv2's source addresses.
            data: octets past the fields of the version built; fewer than
                four for MLDv1, since a Query of 28 or more octets is MLDv2's.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``version`` is neither ``1`` nor ``2``; if an
                MLDv1 Query is given a field only MLDv2 takes, or four or more
                octets of ``data``; if a field does not fit its width, or
                ``num_sources`` is below the length of ``sources``; or if
                ``reserved`` is not two octets.

        """
        if message is not None:
            version = message.get('version')
            reserved = message.reserved
            multicast_address = message.multicast_address
            data = message.data
            if version == 2:
                query = cast('Data_MLDv2Query', message)
                max_resp_code = query.max_resp_code
                flags = query.flags
                s_flag = query.s_flag
                qrv = query.qrv
                qqic = query.qqic
                num_sources = query.num_sources
                sources = query.sources
            else:
                max_resp_delay = message.max_resp_delay
        if isinstance(version, bool) or version not in (1, 2):
            raise ProtocolError(f'{self.alias}: [TypeNo {type}] invalid MLD version: {version!r}')
        reserved = self._make_octets(reserved, size=2, name='reserved')

        if version == 1:
            # NOTE: The keyword check of the member a version names (#2574), and a length
            # that reads back as MLDv1 (RFC 9777 section 8.1).
            extra = [name for name, value in (
                ('max_resp_code', max_resp_code), ('flags', flags), ('s_flag', s_flag), ('qrv', qrv),
                ('qqic', qqic), ('qqi', qqi), ('num_sources', num_sources), ('sources', sources),
            ) if value is not None]
            if extra:
                raise ProtocolError(f'{self.alias}: [TypeNo {type}] an MLDv1 Query takes no '
                                    f'{", ".join(extra)}')
            if len(data) >= 4:
                raise ProtocolError(f'{self.alias}: [TypeNo {type}] an MLDv1 Query with {len(data)} octets '
                                    'of data reads as MLDv2')
            return Schema_MLDQuery(
                max_resp_code=self._make_uint(max_resp_delay, bits=16, name='max_resp_delay'),
                reserved=reserved,
                multicast_address=multicast_address,
                ext=None,
                data=data,
            )

        if max_resp_code is None:
            max_resp_code = self._make_float_code(max_resp_delay, bits=16, name='max_resp_delay')
        if qqic is None:
            qqic = self._make_float_code(0 if qqi is None else qqi, bits=8, name='qqi')
        source_list = [] if sources is None else list(sources)
        if num_sources is None:
            num_sources = len(source_list)
        elif self._make_uint(num_sources, bits=16, name='num_sources') < len(source_list):
            raise ProtocolError(f'{self.alias}: invalid num_sources: {num_sources!r} '
                                f'for {len(source_list)} source(s)')
        return Schema_MLDQuery(
            max_resp_code=self._make_uint(max_resp_code, bits=16, name='max_resp_code'),
            reserved=reserved,
            multicast_address=multicast_address,
            ext=Schema_MLDv2QueryExtension(
                flags={
                    'flags': self._make_uint(0 if flags is None else flags, bits=4, name='flags'),
                    's_flag': self._make_uint(False if s_flag is None else s_flag, bits=1, name='s_flag'),
                    'qrv': self._make_uint(0 if qrv is None else qrv, bits=3, name='qrv'),
                },
                qqic=self._make_uint(qqic, bits=8, name='qqic'),
                num_sources=num_sources,
                sources=source_list,
                data=data,
            ),
            data=b'',
        )

    def _make_data_type_mldv1(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                              message: 'Optional[Data_MLDv1]' = None, *,
                              max_resp_delay: 'int' = 0,
                              reserved: 'bytes' = b'\x00\x00',
                              multicast_address: 'IPv6Address | str | bytes | int' = '::',
                              data: 'bytes' = b'',
                              **kwargs: 'Any') -> 'Schema_MLDv1':
        """Make MLDv1 Multicast Listener Report/Done message.

        Args:
            type: ICMPv6 type.
            message: message data.
            max_resp_delay: Maximum Response Delay, in milliseconds; zero on
                a conformant sender.
            reserved: the two reserved octets.
            multicast_address: multicast address reported or left.
            data: octets past the 24 :rfc:`2710#section-3` defines.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``max_resp_delay`` does not fit 16 bits, or
                ``reserved`` is not two octets.

        """
        if message is not None:
            max_resp_delay = message.max_resp_delay
            reserved = message.reserved
            multicast_address = message.multicast_address
            data = message.data
        return Schema_MLDv1(
            max_resp_delay=self._make_uint(max_resp_delay, bits=16, name='max_resp_delay'),
            reserved=self._make_octets(reserved, size=2, name='reserved'),
            multicast_address=multicast_address,
            data=data,
        )

    def _make_data_type_router_solicitation(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                            message: 'Optional[Data_RouterSolicitation]' = None, *,
                                            reserved: 'bytes' = b'\x00\x00\x00\x00',
                                            options: 'Optional[NDOptionsLike]' = None,
                                            **kwargs: 'Any') -> 'Schema_RouterSolicitation':
        """Make Neighbor Discovery Router Solicitation message.

        Args:
            type: ICMPv6 type.
            message: message data.
            reserved: the four reserved octets.
            options: options, see :meth:`_make_nd_options`.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``reserved`` is not four octets, or an option is
                refused, see :meth:`_make_nd_options`.

        """
        if message is not None:
            reserved = message.reserved
            options = message.options
        return Schema_RouterSolicitation(
            reserved=self._make_octets(reserved, size=4, name='reserved'),
            options=self._make_nd_options(options),
        )

    def _make_data_type_router_advertisement(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                             message: 'Optional[Data_RouterAdvertisement]' = None, *,
                                             cur_hop_limit: 'int' = 0,
                                             m_flag: 'bool' = False,
                                             o_flag: 'bool' = False,
                                             h_flag: 'bool' = False,
                                             prf: 'Enum_RouterPreference | int' = Enum_RouterPreference.Medium,
                                             p_flag: 'bool' = False,
                                             s_flag: 'bool' = False,
                                             reserved: 'int' = 0,
                                             router_lifetime: 'int' = 0,
                                             reachable_time: 'int' = 0,
                                             retrans_timer: 'int' = 0,
                                             options: 'Optional[NDOptionsLike]' = None,
                                             **kwargs: 'Any') -> 'Schema_RouterAdvertisement':
        """Make Neighbor Discovery Router Advertisement message.

        Args:
            type: ICMPv6 type.
            message: message data.
            cur_hop_limit: current hop limit, zero for unspecified.
            m_flag: Managed Address Configuration flag.
            o_flag: Other Configuration flag.
            h_flag: Mobile IPv6 Home Agent flag.
            prf: Default Router Preference.
            p_flag: Neighbor Discovery Proxy flag.
            s_flag: SNAC Router flag.
            reserved: the octet's last bit.
            router_lifetime: router lifetime, in seconds.
            reachable_time: reachable time, in milliseconds.
            retrans_timer: retransmission timer, in milliseconds.
            options: options, see :meth:`_make_nd_options`.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If a field does not fit its width, ``prf`` is a name,
                or an option is refused, see :meth:`_make_nd_options`.

        """
        if message is not None:
            cur_hop_limit = message.cur_hop_limit
            m_flag = message.m_flag
            o_flag = message.o_flag
            h_flag = message.h_flag
            prf = message.prf
            p_flag = message.p_flag
            s_flag = message.s_flag
            reserved = message.reserved
            router_lifetime = message.router_lifetime
            reachable_time = message.reachable_time
            retrans_timer = message.retrans_timer
            options = message.options
        return Schema_RouterAdvertisement(
            cur_hop_limit=self._make_uint(cur_hop_limit, bits=8, name='cur_hop_limit'),
            flags={
                'm_flag': self._make_uint(m_flag, bits=1, name='m_flag'),
                'o_flag': self._make_uint(o_flag, bits=1, name='o_flag'),
                'h_flag': self._make_uint(h_flag, bits=1, name='h_flag'),
                'prf': self._make_index(prf, Enum_RouterPreference, bits=2, name='prf'),
                'p_flag': self._make_uint(p_flag, bits=1, name='p_flag'),
                's_flag': self._make_uint(s_flag, bits=1, name='s_flag'),
                'reserved': self._make_uint(reserved, bits=1, name='reserved'),
            },
            router_lifetime=self._make_uint(router_lifetime, bits=16, name='router_lifetime'),
            reachable_time=self._make_uint(reachable_time, bits=32, name='reachable_time'),
            retrans_timer=self._make_uint(retrans_timer, bits=32, name='retrans_timer'),
            options=self._make_nd_options(options),
        )

    def _make_data_type_neighbor_solicitation(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                              message: 'Optional[Data_NeighborSolicitation]' = None, *,
                                              reserved: 'bytes' = b'\x00\x00\x00\x00',
                                              target_address: 'IPv6Address | str | bytes | int' = '::',
                                              options: 'Optional[NDOptionsLike]' = None,
                                              **kwargs: 'Any') -> 'Schema_NeighborSolicitation':
        """Make Neighbor Discovery Neighbor Solicitation message.

        Args:
            type: ICMPv6 type.
            message: message data.
            reserved: the four reserved octets.
            target_address: target address.
            options: options, see :meth:`_make_nd_options`.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``reserved`` is not four octets, or an option is
                refused, see :meth:`_make_nd_options`.

        """
        if message is not None:
            reserved = message.reserved
            target_address = message.target_address
            options = message.options
        return Schema_NeighborSolicitation(
            reserved=self._make_octets(reserved, size=4, name='reserved'),
            target_address=target_address,
            options=self._make_nd_options(options),
        )

    def _make_data_type_neighbor_advertisement(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                               message: 'Optional[Data_NeighborAdvertisement]' = None, *,
                                               r_flag: 'bool' = False,
                                               s_flag: 'bool' = False,
                                               o_flag: 'bool' = False,
                                               reserved: 'int' = 0,
                                               target_address: 'IPv6Address | str | bytes | int' = '::',
                                               options: 'Optional[NDOptionsLike]' = None,
                                               **kwargs: 'Any') -> 'Schema_NeighborAdvertisement':
        """Make Neighbor Discovery Neighbor Advertisement message.

        Args:
            type: ICMPv6 type.
            message: message data.
            r_flag: Router flag.
            s_flag: Solicited flag.
            o_flag: Override flag.
            reserved: the 29 bits after the flags.
            target_address: target address.
            options: options, see :meth:`_make_nd_options`.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If a flag or ``reserved`` does not fit its width, or
                an option is refused, see :meth:`_make_nd_options`.

        """
        if message is not None:
            r_flag = message.r_flag
            s_flag = message.s_flag
            o_flag = message.o_flag
            reserved = message.reserved
            target_address = message.target_address
            options = message.options
        return Schema_NeighborAdvertisement(
            flags={
                'r_flag': self._make_uint(r_flag, bits=1, name='r_flag'),
                's_flag': self._make_uint(s_flag, bits=1, name='s_flag'),
                'o_flag': self._make_uint(o_flag, bits=1, name='o_flag'),
                'reserved': self._make_uint(reserved, bits=29, name='reserved'),
            },
            target_address=target_address,
            options=self._make_nd_options(options),
        )

    def _make_data_type_redirect(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                 message: 'Optional[Data_Redirect]' = None, *,
                                 reserved: 'bytes' = b'\x00\x00\x00\x00',
                                 target_address: 'IPv6Address | str | bytes | int' = '::',
                                 destination_address: 'IPv6Address | str | bytes | int' = '::',
                                 options: 'Optional[NDOptionsLike]' = None,
                                 **kwargs: 'Any') -> 'Schema_Redirect':
        """Make Neighbor Discovery Redirect message.

        Args:
            type: ICMPv6 type.
            message: message data.
            reserved: the four reserved octets.
            target_address: target address, the better first hop.
            destination_address: destination address, the one redirected.
            options: options, see :meth:`_make_nd_options`.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``reserved`` is not four octets, or an option is
                refused, see :meth:`_make_nd_options`.

        """
        if message is not None:
            reserved = message.reserved
            target_address = message.target_address
            destination_address = message.destination_address
            options = message.options
        return Schema_Redirect(
            reserved=self._make_octets(reserved, size=4, name='reserved'),
            target_address=target_address,
            destination_address=destination_address,
            options=self._make_nd_options(options),
        )

    def _make_data_type_mldv2_report(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                     message: 'Optional[Data_MLDv2Report]' = None, *,
                                     flags: 'int' = 0,
                                     num_records: 'Optional[int]' = None,
                                     records: 'Optional[Iterable[dict[str, Any] | Data_MulticastAddressRecord]]' = None,  # pylint: disable=line-too-long
                                     data: 'bytes' = b'',
                                     **kwargs: 'Any') -> 'Schema_MLDv2Report':
        """Make MLDv2 Version 2 Multicast Listener Report message.

        Args:
            type: ICMPv6 type.
            message: message data.
            flags: the 16 flag bits.
            num_records: number of multicast address records, the length of
                ``records`` when not given; a count above it is written as
                given, as on a Report the capture cut short.
            records: multicast address records, each a
                :class:`~pcapkit.protocols.internet.icmpv6.data.MulticastAddressRecord`
                or a :obj:`dict` of the keyword arguments
                :meth:`_make_address_record` takes.
            data: additional data past the last record.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``flags`` does not fit 16 bits, ``num_records`` is
                not an :obj:`int` from the length of ``records`` to 65535, or a
                record is refused, see :meth:`_make_address_record`.

        """
        if message is not None:
            flags = message.flags
            num_records = message.num_records
            records = message.records
            data = message.data
        record_list = [] if records is None else [
            self._make_address_record(record) if not isinstance(record, dict) else
            self._make_address_record(**record) for record in records
        ]
        if num_records is None:
            num_records = len(record_list)
        elif self._make_uint(num_records, bits=16, name='num_records') < len(record_list):
            raise ProtocolError(f'{self.alias}: invalid num_records: {num_records!r} '
                                f'for {len(record_list)} record(s)')
        return Schema_MLDv2Report(
            flags=self._make_uint(flags, bits=16, name='flags'),
            num_records=num_records,
            records=record_list,
            data=data,
        )

    def _make_opt_none(self, type: 'Enum_NDOption', option: 'Optional[Data_UnknownOption]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                       data: 'bytes' = b'\x00\x00\x00\x00\x00\x00',
                       **kwargs: 'Any') -> 'Schema_UnknownOption':
        """Make ND option of a type not decoded.

        It also writes back an option of any type the capture cut before its
        Length, which :meth:`_read_nd_options` reads as this one's with the
        Length of zero the cut left: the rebuild is cut back to its type.

        Args:
            type: option type.
            option: option data.
            data: option data, after the type and length.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``data`` is not :obj:`bytes`, or the option it
                makes is no whole number of 8-octet units up to 255.

        """
        if option is not None:
            if not option.length:
                return Schema_UnknownOption(type=type, length=0, data=b'')
            data = option.data
        if not isinstance(data, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid data: {data!r}')
        return Schema_UnknownOption(
            type=type,
            length=self._make_nd_length(2 + len(data), type=type),
            data=bytes(data),
        )

    def _make_opt_link_layer_address(self, type: 'Enum_NDOption',  # pylint: disable=redefined-builtin,unused-argument
                                     option: 'Optional[Data_LinkLayerAddressOption]' = None, *,
                                     link_layer_address: 'bytes' = b'\x00\x00\x00\x00\x00\x00',
                                     **kwargs: 'Any') -> 'Schema_LinkLayerAddressOption':
        """Make ND Source or Target Link-layer Address option.

        Args:
            type: option type.
            option: option data.
            link_layer_address: link-layer address, padded as the link's own
                specification gives; six octets on Ethernet
                (:rfc:`2464#section-6`).
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``link_layer_address`` is not :obj:`bytes`, or the
                option it makes is no whole number of 8-octet units up to 255.

        """
        if option is not None:
            link_layer_address = option.link_layer_address
        if not isinstance(link_layer_address, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid link_layer_address: {link_layer_address!r}')
        return Schema_LinkLayerAddressOption(
            type=type,
            length=self._make_nd_length(2 + len(link_layer_address), type=type),
            link_layer_address=bytes(link_layer_address),
        )

    def _make_opt_prefix_information(self, type: 'Enum_NDOption',  # pylint: disable=redefined-builtin,unused-argument
                                     option: 'Optional[Data_PrefixInformationOption]' = None, *,
                                     prefix_length: 'int' = 0,
                                     l_flag: 'bool' = False,
                                     a_flag: 'bool' = False,
                                     r_flag: 'bool' = False,
                                     p_flag: 'bool' = False,
                                     reserved1: 'int' = 0,
                                     valid_lifetime: 'int' = 0,
                                     preferred_lifetime: 'int' = 0,
                                     reserved2: 'bytes' = b'\x00\x00\x00\x00',
                                     prefix: 'IPv6Address | str | bytes | int' = '::',
                                     **kwargs: 'Any') -> 'Schema_PrefixInformationOption':
        """Make ND Prefix Information option.

        Args:
            type: option type.
            option: option data.
            prefix_length: prefix length, in bits.
            l_flag: On-link flag.
            a_flag: Autonomous Address Configuration flag.
            r_flag: Router Address flag.
            p_flag: DHCPv6-PD Preferred flag.
            reserved1: the flags octet's low-order 4 bits.
            valid_lifetime: valid lifetime, in seconds.
            preferred_lifetime: preferred lifetime, in seconds.
            reserved2: the four Reserved2 octets.
            prefix: prefix.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If a field does not fit its width, or ``reserved2`` is
                not four octets.

        """
        if option is not None:
            prefix_length = option.prefix_length
            l_flag = option.l_flag
            a_flag = option.a_flag
            r_flag = option.r_flag
            p_flag = option.p_flag
            reserved1 = option.reserved1
            valid_lifetime = option.valid_lifetime
            preferred_lifetime = option.preferred_lifetime
            reserved2 = option.reserved2
            prefix = option.prefix
        return Schema_PrefixInformationOption(
            type=type,
            length=4,
            prefix_length=self._make_uint(prefix_length, bits=8, name='prefix_length'),
            flags={
                'l_flag': self._make_uint(l_flag, bits=1, name='l_flag'),
                'a_flag': self._make_uint(a_flag, bits=1, name='a_flag'),
                'r_flag': self._make_uint(r_flag, bits=1, name='r_flag'),
                'p_flag': self._make_uint(p_flag, bits=1, name='p_flag'),
                'reserved1': self._make_uint(reserved1, bits=4, name='reserved1'),
            },
            valid_lifetime=self._make_uint(valid_lifetime, bits=32, name='valid_lifetime'),
            preferred_lifetime=self._make_uint(preferred_lifetime, bits=32, name='preferred_lifetime'),
            reserved2=self._make_octets(reserved2, size=4, name='reserved2'),
            prefix=prefix,
        )

    def _make_opt_redirected_header(self, type: 'Enum_NDOption',  # pylint: disable=redefined-builtin,unused-argument
                                    option: 'Optional[Data_RedirectedHeaderOption]' = None, *,
                                    reserved: 'bytes' = b'\x00\x00\x00\x00\x00\x00',
                                    data: 'bytes' = b'',
                                    **kwargs: 'Any') -> 'Schema_RedirectedHeaderOption':
        """Make ND Redirected Header option.

        Args:
            type: option type.
            option: option data.
            reserved: the six reserved octets.
            data: as much of the redirected packet, from its IP header, as fits.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``reserved`` is not six octets, ``data`` is not
                :obj:`bytes`, or the option it makes is no whole number of
                8-octet units up to 255.

        """
        if option is not None:
            reserved = option.reserved
            data = option.data
        if not isinstance(data, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid data: {data!r}')
        return Schema_RedirectedHeaderOption(
            type=type,
            length=self._make_nd_length(8 + len(data), type=type),
            reserved=self._make_octets(reserved, size=6, name='reserved'),
            data=bytes(data),
        )

    def _make_opt_mtu(self, type: 'Enum_NDOption', option: 'Optional[Data_MTUOption]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                      reserved: 'bytes' = b'\x00\x00',
                      mtu: 'int' = 1280,
                      **kwargs: 'Any') -> 'Schema_MTUOption':
        """Make ND MTU option.

        Args:
            type: option type.
            option: option data.
            reserved: the two reserved octets.
            mtu: recommended MTU of the link; the IPv6 minimum link MTU
                (:rfc:`8200#section-5`) when not given.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``reserved`` is not two octets, or ``mtu`` does not
                fit 32 bits.

        """
        if option is not None:
            reserved = option.reserved
            mtu = option.mtu
        return Schema_MTUOption(
            type=type,
            length=1,
            reserved=self._make_octets(reserved, size=2, name='reserved'),
            mtu=self._make_uint(mtu, bits=32, name='mtu'),
        )

    def _make_opt_advertisement_interval(self, type: 'Enum_NDOption',  # pylint: disable=redefined-builtin,unused-argument
                                         option: 'Optional[Data_AdvertisementIntervalOption]' = None, *,
                                         reserved: 'bytes' = b'\x00\x00',
                                         interval: 'int' = 0,
                                         **kwargs: 'Any') -> 'Schema_AdvertisementIntervalOption':
        """Make ND Advertisement Interval option.

        Args:
            type: option type.
            option: option data.
            reserved: the two reserved octets.
            interval: largest time between unsolicited Router Advertisements, in
                milliseconds.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``reserved`` is not two octets, or ``interval``
                does not fit 32 bits.

        """
        if option is not None:
            reserved = option.reserved
            interval = option.interval
        return Schema_AdvertisementIntervalOption(
            type=type,
            length=1,
            reserved=self._make_octets(reserved, size=2, name='reserved'),
            interval=self._make_uint(interval, bits=32, name='interval'),
        )

    def _make_opt_home_agent_information(self, type: 'Enum_NDOption',  # pylint: disable=redefined-builtin,unused-argument
                                         option: 'Optional[Data_HomeAgentInformationOption]' = None, *,
                                         reserved: 'bytes' = b'\x00\x00',
                                         preference: 'int' = 0,
                                         lifetime: 'int' = 0,
                                         **kwargs: 'Any') -> 'Schema_HomeAgentInformationOption':
        """Make ND Home Agent Information option.

        Args:
            type: option type.
            option: option data.
            reserved: the two reserved octets.
            preference: home agent preference.
            lifetime: home agent lifetime, in seconds.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``reserved`` is not two octets, or ``preference``
                or ``lifetime`` does not fit 16 bits.

        """
        if option is not None:
            reserved = option.reserved
            preference = option.preference
            lifetime = option.lifetime
        return Schema_HomeAgentInformationOption(
            type=type,
            length=1,
            reserved=self._make_octets(reserved, size=2, name='reserved'),
            preference=self._make_uint(preference, bits=16, name='preference'),
            lifetime=self._make_uint(lifetime, bits=16, name='lifetime'),
        )

    def _make_opt_nonce(self, type: 'Enum_NDOption', option: 'Optional[Data_NonceOption]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                        nonce: 'bytes' = b'\x00\x00\x00\x00\x00\x00',
                        **kwargs: 'Any') -> 'Schema_NonceOption':
        """Make ND Nonce option.

        Args:
            type: option type.
            option: option data.
            nonce: nonce, at least six octets (:rfc:`3971#section-5.3.2`).
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``nonce`` is not :obj:`bytes`, or the option it
                makes is no whole number of 8-octet units up to 255.

        """
        if option is not None:
            nonce = option.nonce
        if not isinstance(nonce, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid nonce: {nonce!r}')
        return Schema_NonceOption(
            type=type,
            length=self._make_nd_length(2 + len(nonce), type=type),
            nonce=bytes(nonce),
        )

    def _make_opt_route_information(self, type: 'Enum_NDOption',  # pylint: disable=redefined-builtin,unused-argument
                                    option: 'Optional[Data_RouteInformationOption]' = None, *,
                                    length: 'Optional[int]' = None,
                                    prefix_length: 'int' = 0,
                                    reserved1: 'int' = 0,
                                    prf: 'Enum_RouterPreference | int' = Enum_RouterPreference.Medium,
                                    reserved2: 'int' = 0,
                                    lifetime: 'int' = 0,
                                    prefix: 'IPv6Address | str | bytes | int' = '::',
                                    **kwargs: 'Any') -> 'Schema_RouteInformationOption':
        """Make ND Route Information option.

        Args:
            type: option type.
            option: option data.
            length: option length, in octets: 8, 16 or 24, carrying 0, 8 or 16
                octets of ``prefix``; the shortest ``prefix_length`` allows
                (:rfc:`4191#section-2.3`) when not given.
            prefix_length: prefix length, in bits.
            reserved1: the high-order 3 bits of the octet holding ``prf``.
            prf: Route Preference.
            reserved2: the low-order 3 bits of the octet holding ``prf``.
            lifetime: route lifetime, in seconds.
            prefix: prefix.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If a field does not fit its width, ``prf`` is a name,
                ``length`` is not 8, 16 or 24, or ``prefix`` has bits set past
                the octets ``length`` carries.

        """
        if option is not None:
            length = option.length
            prefix_length = option.prefix_length
            reserved1 = option.reserved1
            prf = option.prf
            reserved2 = option.reserved2
            lifetime = option.lifetime
            prefix = option.prefix
        prefix_length = self._make_uint(prefix_length, bits=8, name='prefix_length')
        if length is None:
            length = 8 if not prefix_length else 16 if prefix_length <= 64 else 24
        if isinstance(length, bool) or length not in (8, 16, 24):
            raise ProtocolError(f'{self.alias}: invalid Route Information option length: {length!r}')
        octets = parse_ip_address(prefix, f'{self.alias}: [OptNo {type}] prefix', 6).packed
        if any(octets[length - 8:]):
            raise ProtocolError(f'{self.alias}: invalid prefix: {prefix!r} does not fit '
                                f'{length - 8} octets')
        return Schema_RouteInformationOption(
            type=type,
            length=length // 8,
            prefix_length=prefix_length,
            flags={
                'reserved1': self._make_uint(reserved1, bits=3, name='reserved1'),
                'prf': self._make_index(prf, Enum_RouterPreference, bits=2, name='prf'),
                'reserved2': self._make_uint(reserved2, bits=3, name='reserved2'),
            },
            lifetime=self._make_uint(lifetime, bits=32, name='lifetime'),
            prefix=octets[:length - 8],
        )

    def _make_opt_rdnss(self, type: 'Enum_NDOption', option: 'Optional[Data_RDNSSOption]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                        reserved: 'bytes' = b'\x00\x00',
                        lifetime: 'int' = 0,
                        addresses: 'Iterable[IPv6Address | str | bytes | int]' = ('::',),
                        **kwargs: 'Any') -> 'Schema_RDNSSOption':
        """Make ND Recursive DNS Server option.

        Args:
            type: option type.
            option: option data.
            reserved: the two reserved octets.
            lifetime: lifetime, in seconds.
            addresses: addresses of the recursive DNS servers, at least one
                (:rfc:`8106#section-5.1`).
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``reserved`` is not two octets, ``lifetime`` does
                not fit 32 bits, or there is no address, or so many the option
                is longer than 255 units of 8 octets.

        """
        if option is not None:
            reserved = option.reserved
            lifetime = option.lifetime
            addresses = option.addresses
        address_list = list(addresses)
        if not address_list:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid addresses: an RDNSS option '
                                'carries at least one')
        return Schema_RDNSSOption(
            type=type,
            length=self._make_nd_length(8 + 16 * len(address_list), type=type),
            reserved=self._make_octets(reserved, size=2, name='reserved'),
            lifetime=self._make_uint(lifetime, bits=32, name='lifetime'),
            addresses=address_list,
        )

    def _make_opt_ra_flags_extension(self, type: 'Enum_NDOption',  # pylint: disable=redefined-builtin,unused-argument
                                     option: 'Optional[Data_RAFlagsExtensionOption]' = None, *,
                                     bits: 'bytes' = b'\x00\x00\x00\x00\x00\x00',
                                     **kwargs: 'Any') -> 'Schema_RAFlagsExtensionOption':
        """Make ND RA Flags Extension option.

        Args:
            type: option type.
            option: option data.
            bits: bits 8 onwards of IANA's Router Advertisement Flags; six
                octets for the option :rfc:`5175#section-4` defines.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``bits`` is not :obj:`bytes`, or the option it
                makes is no whole number of 8-octet units up to 255.

        """
        if option is not None:
            bits = option.bits
        if not isinstance(bits, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid bits: {bits!r}')
        return Schema_RAFlagsExtensionOption(
            type=type,
            length=self._make_nd_length(2 + len(bits), type=type),
            bits=bytes(bits),
        )

    def _make_opt_dnssl(self, type: 'Enum_NDOption', option: 'Optional[Data_DNSSLOption]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                        reserved: 'bytes' = b'\x00\x00',
                        lifetime: 'int' = 0,
                        domain_names: 'Iterable[str]' = (),
                        padding: 'Optional[bytes]' = None,
                        **kwargs: 'Any') -> 'Schema_DNSSLOption':
        """Make ND DNS Search List option.

        Args:
            type: option type.
            option: option data.
            reserved: the two reserved octets.
            lifetime: lifetime, in seconds.
            domain_names: domain names, in presentation form
                (:rfc:`1035#section-5.1`), each written uncompressed.
            padding: octets past the last name; the zeros that end the option
                on an 8-octet boundary (:rfc:`8106#section-5.2`) when not given.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``reserved`` is not two octets, ``lifetime`` does
                not fit 32 bits, a name is refused or is the root, whose zero
                octet would read as the padding, ``padding`` starts with a
                nonzero octet, which would read as a name, or the option is no
                whole number of 8-octet units from 2 (:rfc:`8106#section-5.2`)
                up to 255.

        """
        if option is not None:
            reserved = option.reserved
            lifetime = option.lifetime
            domain_names = option.domain_names
            padding = option.padding
        labels = [text_to_labels(name, alias=self.alias) for name in domain_names]
        if not all(labels):
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid domain_names: the root reads as padding')
        names = b''.join(make_name(item, alias=self.alias) for item in labels)
        if padding is None:
            padding = bytes(-(8 + len(names)) % 8)
        elif not isinstance(padding, (bytes, bytearray)) or padding[:1] not in (b'', b'\x00'):
            raise ProtocolError(f'{self.alias}: invalid padding: {padding!r}')
        length = self._make_nd_length(8 + len(names) + len(padding), type=type)
        if length < 2:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid DNSSL option length: {length}')
        return Schema_DNSSLOption(
            type=type,
            length=length,
            reserved=self._make_octets(reserved, size=2, name='reserved'),
            lifetime=self._make_uint(lifetime, bits=32, name='lifetime'),
            names=names + bytes(padding),
        )

    def _make_opt_captive_portal(self, type: 'Enum_NDOption',  # pylint: disable=redefined-builtin,unused-argument
                                 option: 'Optional[Data_CaptivePortalOption]' = None, *,
                                 uri: 'bytes' = b'',
                                 padding: 'Optional[bytes]' = None,
                                 **kwargs: 'Any') -> 'Schema_CaptivePortalOption':
        """Make ND Captive-Portal option.

        Args:
            type: option type.
            option: option data.
            uri: URI of the captive portal API endpoint.
            padding: octets past the URI; the NULs that end the option on an
                8-octet boundary (:rfc:`8910#section-2.3`) when not given.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``uri`` is not :obj:`bytes` or holds a NUL,
                ``padding`` starts with an octet other than NUL, or the option is
                no whole number of 8-octet units up to 255.

        """
        if option is not None:
            uri = option.uri
            padding = option.padding
        if not isinstance(uri, (bytes, bytearray)) or b'\x00' in uri:
            raise ProtocolError(f'{self.alias}: invalid uri: {uri!r}')
        if padding is None:
            padding = bytes(-(2 + len(uri)) % 8)
        elif not isinstance(padding, (bytes, bytearray)) or padding[:1] not in (b'', b'\x00'):
            raise ProtocolError(f'{self.alias}: invalid padding: {padding!r}')
        return Schema_CaptivePortalOption(
            type=type,
            length=self._make_nd_length(2 + len(uri) + len(padding), type=type),
            uri=bytes(uri) + bytes(padding),
        )

    def _make_opt_pref64(self, type: 'Enum_NDOption', option: 'Optional[Data_PREF64Option]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                         scaled_lifetime: 'Optional[int]' = None,
                         lifetime: 'int' = 0,
                         plc: 'Optional[int]' = None,
                         prefix_length: 'int' = 96,
                         prefix: 'IPv6Address | str | bytes | int' = '64:ff9b::',
                         **kwargs: 'Any') -> 'Schema_PREF64Option':
        """Make ND PREF64 option.

        Args:
            type: option type.
            option: option data.
            scaled_lifetime: Scaled Lifetime, in units of 8 seconds, as on the
                wire; encoded from ``lifetime`` when not given.
            lifetime: lifetime, in seconds, a multiple of 8.
            plc: Prefix Length Code, as on the wire; encoded from
                ``prefix_length`` when not given.
            prefix_length: prefix length, in bits: 96, 64, 56, 48, 40 or 32.
            prefix: NAT64 prefix; the Well-Known Prefix (:rfc:`6052#section-2.1`)
                when not given.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``scaled_lifetime`` does not fit 13 bits, or
                ``plc`` 3; if ``lifetime`` is no multiple of 8, or
                ``prefix_length`` has no code; or if ``prefix`` has bits set past
                its 96 carried.

        """
        if option is not None:
            scaled_lifetime = option.scaled_lifetime
            plc = option.plc
            prefix = option.prefix
        if scaled_lifetime is None:
            if self._make_uint(lifetime, bits=16, name='lifetime') % 8:
                raise ProtocolError(f'{self.alias}: invalid lifetime: {lifetime!r} is no multiple of 8')
            scaled_lifetime = lifetime // 8
        if plc is None:
            codes = {length: code for code, length in PREF64_PREFIX_LENGTH.items()}
            if isinstance(prefix_length, bool) or prefix_length not in codes:
                raise ProtocolError(f'{self.alias}: invalid prefix_length: {prefix_length!r}')
            plc = codes[prefix_length]
        octets = parse_ip_address(prefix, f'{self.alias}: [OptNo {type}] prefix', 6).packed
        if any(octets[12:]):
            raise ProtocolError(f'{self.alias}: invalid prefix: {prefix!r} has bits past its 96 carried')
        return Schema_PREF64Option(
            type=type,
            length=2,
            lifetime={
                'scaled_lifetime': self._make_uint(scaled_lifetime, bits=13, name='scaled_lifetime'),
                'plc': self._make_uint(plc, bits=3, name='plc'),
            },
            prefix=octets[:12],
        )

    def _make_address_record(self, record: 'Optional[Data_MulticastAddressRecord]' = None, *,
                             record_type: 'Enum_RecordType | int' = Enum_RecordType.MODE_IS_INCLUDE,
                             aux_data_len: 'Optional[int]' = None,
                             num_sources: 'Optional[int]' = None,
                             multicast_address: 'IPv6Address | str | bytes | int' = '::',
                             sources: 'Optional[Iterable[IPv6Address | str | bytes | int]]' = None,
                             aux_data: 'bytes' = b'',
                             **kwargs: 'Any') -> 'Schema_MulticastAddressRecord':  # pylint: disable=unused-argument
        """Make an MLDv2 multicast address record (:rfc:`9777#section-5.2`).

        Args:
            record: record data, taking precedence over the keyword arguments
                below.
            record_type: record type (:rfc:`9777#section-5.2.13`).
            aux_data_len: auxiliary data length, in 32-bit words; derived from
                ``aux_data`` when not given.
            num_sources: number of source addresses, the length of ``sources``
                when not given; a count above it is written as given, as on a
                record the capture cut inside its sources.
            multicast_address: multicast address the record pertains to.
            sources: source addresses.
            aux_data: auxiliary data; :rfc:`9777#section-5.2.11` has an MLDv2
                sender leave it empty.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed record schema.

        Raises:
            ProtocolError: If ``record_type`` is a name, a :obj:`bool`, or a
                member or code outside 0 to 255; if ``aux_data_len`` or
                ``num_sources`` does not fit its width, or ``num_sources`` is
                below the length of ``sources``; or if ``aux_data_len`` is not
                given and ``aux_data`` is no whole number of 32-bit words.

        """
        if record is not None:
            record_type = record.record_type
            aux_data_len = record.aux_data_len
            num_sources = record.num_sources
            multicast_address = record.multicast_address
            sources = record.sources
            aux_data = record.aux_data

        source_list = [] if sources is None else list(sources)
        if num_sources is None:
            num_sources = len(source_list)
        elif self._make_uint(num_sources, bits=16, name='num_sources') < len(source_list):
            raise ProtocolError(f'{self.alias}: invalid num_sources: {num_sources!r} '
                                f'for {len(source_list)} source(s)')
        if aux_data_len is None:
            if len(aux_data) % 4:
                raise ProtocolError(f'{self.alias}: invalid aux_data: {len(aux_data)} octets '
                                    'are no whole number of 32-bit words')
            aux_data_len = len(aux_data) // 4
        return Schema_MulticastAddressRecord(
            record_type=self._make_index(record_type, Enum_RecordType, bits=8, name='record type'),
            aux_data_len=self._make_uint(aux_data_len, bits=8, name='aux_data_len'),
            num_sources=num_sources,
            multicast_address=multicast_address,
            sources=source_list,
            aux_data=aux_data,
        )

    def _read_nd_options(self, options_schema: 'list[Schema_NDOption]') -> 'NDOptions':
        """Read Neighbor Discovery options.

        Structure of ND option [:rfc:`4861#section-4.6`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |    Length     |              ...              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           ~                              ...                              ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Each option is read by the method :attr:`__option__` names for its
        type, :meth:`_read_opt_none` where it names none, or where the capture
        cut the option before its Length.

        Args:
            options_schema: parsed option schemas

        Returns:
            Parsed options, by type, in the order read.

        Raises:
            ProtocolError: If an option read by a ``_read_opt_*`` method has
                fields that do not take exactly the octets its Length declares,
                a Length of zero among them (:rfc:`4861#section-4.6`); a parser
                registered as a callable is not checked. Or if the capture cut
                an option short and its parser refuses the zeros it lacks, or
                its maker does not write the octets captured back.

        """
        options = OrderedMultiDict()  # type: NDOptions
        for schema in options_schema:
            code = schema.type
            name = self._lookup_registry(self.__option__, code)
            if isinstance(name, str):
                meth = cast('OptionParser', getattr(self, f'_read_opt_{name}', self._read_opt_none))
                maker = cast('OptionConstructor', getattr(self, f'_make_opt_{name}', self._make_opt_none))
            else:
                meth, maker = name

            # NOTE: A cut-short option reads its missing octets as zeros; it stands if its parser
            # takes them and its maker writes the captured ones back, as MH's does (#2694).
            record = schema.__dict__.get('__short_read__')
            if record is not None and record[0] == 'length':
                data = Data_UnknownOption(type=code, length=0, data=b'')  # type: Data_NDOption
            elif record is not None:
                try:
                    with CaughtByCaller(BaseError):
                        data = meth(schema, options=options)
                        made = maker(code, data).pack()[:len(schema)]
                except BaseError as error:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] option cut short: {error}') from error
                if made != bytes(schema):
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] option cut short does not '
                                        'rebuild as captured')
            else:
                data = meth(schema, options=options)
                if isinstance(name, str) and (not schema.length or len(schema) != data.length):
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid option length: {schema.length}')
            options.add(code, data)
        return options

    def _make_nd_options(self, options: 'Optional[NDOptionsLike]') -> 'list[Schema_NDOption | bytes]':
        """Make Neighbor Discovery options.

        Args:
            options: options, as parsed data, keyed by type; or a list of
                ``(type, kwargs)`` pairs, option schemas, or raw octets of
                whole options. A type is an
                :class:`~pcapkit.const.icmpv6.nd_option.NDOption` member or an
                :obj:`int`. Parsed data of an option the capture cut before
                its Length is written by :meth:`_make_opt_none`, whatever its
                type.

        Returns:
            Option schema list.

        Raises:
            ProtocolError: If an option's type is a name, a :obj:`bool` or a
                code that does not fit one octet, or its maker refuses it.

        """
        if options is None:
            return []

        if isinstance(options, list):
            options_list = []  # type: list[Schema_NDOption | bytes]
            for item in options:
                if isinstance(item, (bytes, Schema)):
                    options_list.append(item)
                    continue
                kind, args = cast('tuple[Enum_NDOption | int, dict[str, Any]]', item)
                code = self._make_index(kind, Enum_NDOption, bits=8, name='option type')
                options_list.append(self._nd_option_maker(code)(code, **args))
            return options_list

        options_list = []
        for key, option in options.items(multi=True):
            code = self._make_index(key, Enum_NDOption, bits=8, name='option type')
            # NOTE: One the capture cut before its Length reads undecoded, whatever its type.
            cut = isinstance(option, Data_UnknownOption) and not option.length
            maker = cast('OptionConstructor', self._make_opt_none) if cut else self._nd_option_maker(code)
            options_list.append(maker(code, option))
        return options_list

    def _nd_option_maker(self, code: 'Enum_NDOption') -> 'OptionConstructor':
        """The maker :attr:`__option__` names for an option type.

        Args:
            code: option type

        Returns:
            The ``_make_opt_*`` method, :meth:`_make_opt_none` where none is
            named, or the constructor of a registered pair.

        """
        name = self._lookup_registry(self.__option__, code)
        if isinstance(name, str):
            return cast('OptionConstructor', getattr(self, f'_make_opt_{name}', self._make_opt_none))
        return name[1]

    def _make_nd_length(self, octets: 'int', *, type: 'Enum_NDOption') -> 'int':  # pylint: disable=redefined-builtin
        """The Length of an option of ``octets`` octets.

        Args:
            octets: the option's size, type and length included
            type: option type, for the error message

        Returns:
            ``octets`` in units of 8 octets (:rfc:`4861#section-4.6`).

        Raises:
            ProtocolError: If ``octets`` is no whole number of 8-octet units,
                or more than 255 of them.

        """
        if octets % 8 or octets > 255 * 8:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid option size: {octets} octets '
                                'is no whole number of 8-octet units up to 255')
        return octets // 8

    def _verify_pseudo_checksum(self, pseudo: 'Optional[IP_Pseudo]') -> 'None':
        """Verify the checksum over the pseudo-header of the enclosing IP layer.

        That layer calls this once parsed, see
        :func:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.verify_upper`.

        Args:
            pseudo: Pseudo-header, or :data:`None` if the IP layer gives none.

        """
        from pcapkit.corekit.checksum.internet import ChecksumStatus, verify_checksum  # isort: skip # pylint: disable=import-outside-toplevel

        if pseudo is None:
            status = ChecksumStatus.NO_PSEUDO_HEADER
        else:
            status = verify_checksum(self.alias, self._data, self._info.checksum,
                                     length=pseudo.info.len, prefix=pseudo.data)
        self._info.__update__(checksum_status=status)
