# -*- coding: utf-8 -*-
"""DHCP - Dynamic Host Configuration Protocol
================================================

.. module:: pcapkit.protocols.application.dhcp.protocol

:mod:`pcapkit.protocols.application.dhcp.protocol` holds
:class:`~pcapkit.protocols.application.dhcp.protocol.DHCP`, the abstract base of
the Bootstrap Protocol (BOOTP) [:rfc:`951`, :rfc:`1542`] and the Dynamic Host
Configuration Protocol (DHCP) [:rfc:`2131`], whose messages share one layout:

.. table::

   ====== ===== ================ =================================================
   Octets Bits  Name             Description
   ====== ===== ================ =================================================
   0          0 ``dhcp.op``      Message Op Code
   ------ ----- ---------------- -------------------------------------------------
   1          8 ``dhcp.htype``   Hardware Address Type
   ------ ----- ---------------- -------------------------------------------------
   2         16 ``dhcp.hlen``    Hardware Address Length
   ------ ----- ---------------- -------------------------------------------------
   3         24 ``dhcp.hops``    Hops
   ------ ----- ---------------- -------------------------------------------------
   4         32 ``dhcp.xid``     Transaction ID
   ------ ----- ---------------- -------------------------------------------------
   8         64 ``dhcp.secs``    Seconds Elapsed
   ------ ----- ---------------- -------------------------------------------------
   10        80 ``dhcp.flags``   Flags
   ------ ----- ---------------- -------------------------------------------------
   12        96 ``dhcp.ciaddr``  Client IP Address
   ------ ----- ---------------- -------------------------------------------------
   16       128 ``dhcp.yiaddr``  Your (Client) IP Address
   ------ ----- ---------------- -------------------------------------------------
   20       160 ``dhcp.siaddr``  Next Server IP Address
   ------ ----- ---------------- -------------------------------------------------
   24       192 ``dhcp.giaddr``  Relay Agent IP Address
   ------ ----- ---------------- -------------------------------------------------
   28       224 ``dhcp.chaddr``  Client Hardware Address
   ------ ----- ---------------- -------------------------------------------------
   44       352 ``dhcp.sname``   Server Host Name
   ------ ----- ---------------- -------------------------------------------------
   108      864 ``dhcp.file``    Boot File Name
   ------ ----- ---------------- -------------------------------------------------
   236     1888                  BOOTP's ``vend`` or DHCP's ``options``
   ====== ===== ================ =================================================

Each is a member of its own:

.. list-table::
   :header-rows: 1

   * - Message
     - Class
     - Specification
   * - BOOTP
     - :class:`~pcapkit.protocols.application.bootp.protocol.BOOTP`
     - :rfc:`951`, :rfc:`1542`, and the vendor extensions of :rfc:`2132`
       sections 3 to 8
   * - DHCP
     - :class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4`
     - :rfc:`2131`, and the options of :rfc:`2132` and its successors

A DHCP message is the one whose options carry the DHCP Message Type option
(:rfc:`2131#section-3`, :rfc:`1534#section-2`); no field gives a version. UDP
ports 67 and 68 carry either, so :attr:`UDP.__proto__
<pcapkit.protocols.transport.udp.protocol.UDP.__proto__>` binds this base and it
picks the member, by :meth:`_classify`.

.. versionadded:: 1.10.0

"""
import collections
import collections.abc
import ipaddress
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.const.dhcp.message_type import MessageType as Enum_MessageType
from pcapkit.const.dhcp.opcode import Opcode as Enum_Opcode
from pcapkit.const.dhcp.option import Option as Enum_Option
from pcapkit.const.dhcp.relay_agent_suboption import RelayAgentSubOption as Enum_RelayAgentSubOption
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.schema.domain_name import make_name, name_to_text, read_name, text_to_labels
from pcapkit.corekit.schema.ipaddress import parse_ip_address
from pcapkit.corekit.sentinels import NO_VALUE, NoValueType
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.application.dhcp.const import (CHADDR_LENGTH, HEADER_LENGTH, MAGIC_COOKIE,
                                                      MINIMUMS)
from pcapkit.protocols.application.dhcp.data import Address as Data_Address
from pcapkit.protocols.application.dhcp.data import Addresses as Data_Addresses
from pcapkit.protocols.application.dhcp.data import AddressMask as Data_AddressMask
from pcapkit.protocols.application.dhcp.data import ArchitectureTypes as Data_ArchitectureTypes
from pcapkit.protocols.application.dhcp.data import Boolean as Data_Boolean
from pcapkit.protocols.application.dhcp.data import ClasslessRoute as Data_ClasslessRoute
from pcapkit.protocols.application.dhcp.data import \
    ClasslessStaticRoutes as Data_ClasslessStaticRoutes
from pcapkit.protocols.application.dhcp.data import ClientFQDN as Data_ClientFQDN
from pcapkit.protocols.application.dhcp.data import ClientIdentifier as Data_ClientIdentifier
from pcapkit.protocols.application.dhcp.data import ClientNDI as Data_ClientNDI
from pcapkit.protocols.application.dhcp.data import DomainName as Data_DomainName
from pcapkit.protocols.application.dhcp.data import DomainSearch as Data_DomainSearch
from pcapkit.protocols.application.dhcp.data import Flags as Data_Flags
from pcapkit.protocols.application.dhcp.data import FQDNFlags as Data_FQDNFlags
from pcapkit.protocols.application.dhcp.data import MachineIdentifier as Data_MachineIdentifier
from pcapkit.protocols.application.dhcp.data import MessageType as Data_MessageType
from pcapkit.protocols.application.dhcp.data import NodeType as Data_NodeType
from pcapkit.protocols.application.dhcp.data import Number as Data_Number
from pcapkit.protocols.application.dhcp.data import Option as Data_Option
from pcapkit.protocols.application.dhcp.data import Overload as Data_Overload
from pcapkit.protocols.application.dhcp.data import ParameterList as Data_ParameterList
from pcapkit.protocols.application.dhcp.data import PolicyFilter as Data_PolicyFilter
from pcapkit.protocols.application.dhcp.data import \
    RelayAgentInformation as Data_RelayAgentInformation
from pcapkit.protocols.application.dhcp.data import RelayAgentSubOption as Data_RelayAgentSubOption
from pcapkit.protocols.application.dhcp.data import Route as Data_Route
from pcapkit.protocols.application.dhcp.data import Sizes as Data_Sizes
from pcapkit.protocols.application.dhcp.data import StaticRoutes as Data_StaticRoutes
from pcapkit.protocols.application.dhcp.data import Text as Data_Text
from pcapkit.protocols.application.dhcp.data import UserClass as Data_UserClass
from pcapkit.protocols.application.dhcp.data import VendorClass as Data_VendorClass
from pcapkit.protocols.application.dhcp.data import VendorClassEntry as Data_VendorClassEntry
from pcapkit.protocols.application.dhcp.data import VendorOption as Data_VendorOption
from pcapkit.protocols.application.dhcp.data import VendorOptions as Data_VendorOptions
from pcapkit.protocols.application.dhcp.data import VendorSpecific as Data_VendorSpecific
from pcapkit.protocols.application.dhcp.schema import DHCP as Schema_DHCP
from pcapkit.protocols.protocol import _PT, _ST, _nothing_to_parse
from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import (IO, Any, Callable, DefaultDict, Iterable, Mapping, Optional, Tuple, Type,
                        Union)

    from typing_extensions import Literal, Self

    from pcapkit.const.reg.apptype.udp import UDP as AppType_UDP
    from pcapkit.protocols.application.dhcp.data import OptionData as Data_OptionData

    #: Parser of an option's data, given its code and octets.
    OptionParser = Callable[[Enum_Option, bytes], Union[Data_OptionData, bytes]]
    #: Constructor of an option's data, given its code and fields.
    OptionConstructor = Callable[[Enum_Option, 'Mapping[str, Any]'], bytes]

    #: An option as :meth:`DHCP._split_options` reads it, its code and its
    #: data, the latter :obj:`None` for the Pad and End options.
    RawOption = Tuple[int, Optional[bytes]]

__all__ = ['DHCP']

#: UDP's AppType registry, named lazily so that importing this module does not
#: import it.
_UDP: 'ModuleDescriptor[AppType_UDP]' = ModuleDescriptor('pcapkit.const.reg.apptype.udp', 'UDP')

#: tuple[ModuleDescriptor[DHCP], ModuleDescriptor[DHCP]]: The BOOTP and DHCP members,
#: resolved in :meth:`DHCP._classify` rather than imported, so that their first
#: import holds :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_MEMBERS = (
    ModuleDescriptor('pcapkit.protocols.application.bootp.protocol', 'BOOTP'),
    ModuleDescriptor('pcapkit.protocols.application.dhcpv4.protocol', 'DHCPv4'),
)  # type: tuple[ModuleDescriptor[DHCP], ModuleDescriptor[DHCP]]

#: tuple[ModuleDescriptor[Any], ModuleDescriptor[Any]]: The members' data models,
#: by which :meth:`DHCP.from_data` picks the member, in the order of :data:`_MEMBERS`.
_DATA = (
    ModuleDescriptor('pcapkit.protocols.application.bootp.data', 'BOOTP'),
    ModuleDescriptor('pcapkit.protocols.application.dhcpv4.data', 'DHCPv4'),
)  # type: tuple[ModuleDescriptor[Any], ModuleDescriptor[Any]]


class DHCP(Application[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """This class implements the BOOTP and DHCP family.

    - Bootstrap Protocol
      (:class:`~pcapkit.protocols.application.bootp.protocol.BOOTP`) [:rfc:`951`]
    - Dynamic Host Configuration Protocol
      (:class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4`) [:rfc:`2131`]

    It is abstract, as :class:`~pcapkit.protocols.application.stp.protocol.STP`
    is, and never gives an instance of this class. Octets give the member
    :meth:`_classify` picks; no field names a member, since the family has no
    version, so fields are refused here and a member builds itself;
    :meth:`from_data` reads the data model's class. See :meth:`__new__`.

    The options either member decodes are those :attr:`__option__` registers,
    each exactly as its specification defines it; a BOOTP message decodes the
    vendor extensions alone (:data:`~pcapkit.protocols.application.bootp.const.VENDOR_EXTENSIONS`).
    An option whose data its decoder refuses, and every instance of an option
    the message carries more than once, which :rfc:`3396#section-7`
    concatenates before any is read, keep their octets; decoding the
    concatenation is :issue:`3200`.

    The data each option carries:

    .. list-table::
       :header-rows: 1

       * - Option
         - Data Model
       * - Subnet Mask, Swap Server, Broadcast Address, Router Solicitation
           Address, Requested IP Address, Server Identifier, Subnet Selection
         - :class:`~pcapkit.protocols.application.dhcp.data.Address`
       * - Router and the other server lists of :rfc:`2132`, Mobile IP Home Agent
         - :class:`~pcapkit.protocols.application.dhcp.data.Addresses`
       * - Time Offset, Boot File Size, the timers, TTLs and sizes, IPv6-Only
           Preferred
         - :class:`~pcapkit.protocols.application.dhcp.data.Number`
       * - The on/off options of :rfc:`2132`, Auto-Configure
         - :class:`~pcapkit.protocols.application.dhcp.data.Boolean`
       * - Host Name and the other text options of :rfc:`2132`, PCode, TCode,
           Captive-Portal
         - :class:`~pcapkit.protocols.application.dhcp.data.Text`
       * - Policy Filter
         - :class:`~pcapkit.protocols.application.dhcp.data.PolicyFilter`
       * - Path MTU Plateau Table
         - :class:`~pcapkit.protocols.application.dhcp.data.Sizes`
       * - Static Route
         - :class:`~pcapkit.protocols.application.dhcp.data.StaticRoutes`
       * - NetBIOS over TCP/IP Node Type
         - :class:`~pcapkit.protocols.application.dhcp.data.NodeType`
       * - Option Overload
         - :class:`~pcapkit.protocols.application.dhcp.data.Overload`
       * - DHCP Message Type
         - :class:`~pcapkit.protocols.application.dhcp.data.MessageType`
       * - Parameter Request List
         - :class:`~pcapkit.protocols.application.dhcp.data.ParameterList`
       * - Client-identifier
         - :class:`~pcapkit.protocols.application.dhcp.data.ClientIdentifier`
       * - User Class (:rfc:`3004`)
         - :class:`~pcapkit.protocols.application.dhcp.data.UserClass`
       * - Client FQDN (:rfc:`4702`)
         - :class:`~pcapkit.protocols.application.dhcp.data.ClientFQDN`
       * - Relay Agent Information (:rfc:`3046`)
         - :class:`~pcapkit.protocols.application.dhcp.data.RelayAgentInformation`
       * - Client System Architecture (:rfc:`4578`)
         - :class:`~pcapkit.protocols.application.dhcp.data.ArchitectureTypes`
       * - Client Network Interface Identifier (:rfc:`4578`)
         - :class:`~pcapkit.protocols.application.dhcp.data.ClientNDI`
       * - Client Machine Identifier (:rfc:`4578`)
         - :class:`~pcapkit.protocols.application.dhcp.data.MachineIdentifier`
       * - Domain Search (:rfc:`3397`)
         - :class:`~pcapkit.protocols.application.dhcp.data.DomainSearch`
       * - Classless Static Route (:rfc:`3442`)
         - :class:`~pcapkit.protocols.application.dhcp.data.ClasslessStaticRoutes`
       * - Vendor-Identifying Vendor Class (:rfc:`3925`)
         - :class:`~pcapkit.protocols.application.dhcp.data.VendorClass`
       * - Vendor-Identifying Vendor-Specific Information (:rfc:`3925`)
         - :class:`~pcapkit.protocols.application.dhcp.data.VendorSpecific`

    Any other option, the opaque Vendor Specific Information and Vendor Class
    Identifier of :rfc:`2132` among them, keeps its octets.

    Note:
        The subpackage does not track the dispatch tier. The family is dispatched
        from :attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.protocol.UDP.__proto__>`
        at ports 67 and 68; it configures a host rather than relaying its
        packets, so it is a *user* of the stack, as :rfc:`1122#section-1.1.3`
        places booting.

    """
    #: Octets of the message, as :meth:`read` measures them; :attr:`length`
    #: reads it.
    _length: 'int'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Option code to method mapping, which both members read through. A
    #: :obj:`str` value names the methods ``_read_opt_${name}`` and
    #: ``_make_opt_${name}``, falling back to :meth:`_read_opt_unknown` and
    #: :meth:`_make_opt_unknown`; any other value is a ``(parser,
    #: constructor)`` pair of callables.
    __option__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_Option.Subnet_Mask: 'address',                        # [RFC 2132]
            Enum_Option.Time_Offset: 'time_offset',                    # [RFC 2132]
            Enum_Option.Router: 'addresses',                           # [RFC 2132]
            Enum_Option.Time_Server: 'addresses',                      # [RFC 2132]
            Enum_Option.Name_Server: 'addresses',                      # [RFC 2132]
            Enum_Option.Domain_Server: 'addresses',                    # [RFC 2132]
            Enum_Option.Log_Server: 'addresses',                       # [RFC 2132]
            Enum_Option.Quotes_Server: 'addresses',                    # [RFC 2132]
            Enum_Option.LPR_Server: 'addresses',                       # [RFC 2132]
            Enum_Option.Impress_Server: 'addresses',                   # [RFC 2132]
            Enum_Option.RLP_Server: 'addresses',                       # [RFC 2132]
            Enum_Option.Hostname: 'text',                              # [RFC 2132]
            Enum_Option.Boot_File_Size: 'uint16',                      # [RFC 2132]
            Enum_Option.Merit_Dump_File: 'text',                       # [RFC 2132]
            Enum_Option.Domain_Name: 'text',                           # [RFC 2132]
            Enum_Option.Swap_Server: 'address',                        # [RFC 2132]
            Enum_Option.Root_Path: 'text',                             # [RFC 2132]
            Enum_Option.Extension_File: 'text',                        # [RFC 2132]
            Enum_Option.Forward_On_Off: 'boolean',                     # [RFC 2132]
            Enum_Option.SrcRte_On_Off: 'boolean',                      # [RFC 2132]
            Enum_Option.Policy_Filter: 'policy_filter',                # [RFC 2132]
            Enum_Option.Max_DG_Assembly: 'uint16',                     # [RFC 2132]
            Enum_Option.Default_IP_TTL: 'uint8',                       # [RFC 2132]
            Enum_Option.MTU_Timeout: 'uint32',                         # [RFC 2132]
            Enum_Option.MTU_Plateau: 'mtu_plateau',                    # [RFC 2132]
            Enum_Option.MTU_Interface: 'uint16',                       # [RFC 2132]
            Enum_Option.MTU_Subnet: 'boolean',                         # [RFC 2132]
            Enum_Option.Broadcast_Address: 'address',                  # [RFC 2132]
            Enum_Option.Mask_Discovery: 'boolean',                     # [RFC 2132]
            Enum_Option.Mask_Supplier: 'boolean',                      # [RFC 2132]
            Enum_Option.Router_Discovery: 'boolean',                   # [RFC 2132]
            Enum_Option.Router_Request: 'address',                     # [RFC 2132]
            Enum_Option.Static_Route: 'static_route',                  # [RFC 2132]
            Enum_Option.Trailers: 'boolean',                           # [RFC 2132]
            Enum_Option.ARP_Timeout: 'uint32',                         # [RFC 2132]
            Enum_Option.Ethernet: 'boolean',                           # [RFC 2132]
            Enum_Option.Default_TCP_TTL: 'uint8',                      # [RFC 2132]
            Enum_Option.Keepalive_Time: 'uint32',                      # [RFC 2132]
            Enum_Option.Keepalive_Data: 'boolean',                     # [RFC 2132]
            Enum_Option.NIS_Domain: 'text',                            # [RFC 2132]
            Enum_Option.NIS_Servers: 'addresses',                      # [RFC 2132]
            Enum_Option.NTP_Servers: 'addresses',                      # [RFC 2132]
            Enum_Option.NETBIOS_Name_Srv: 'addresses',                 # [RFC 2132]
            Enum_Option.NETBIOS_Dist_Srv: 'addresses',                 # [RFC 2132]
            Enum_Option.NETBIOS_Node_Type: 'node_type',                # [RFC 2132]
            Enum_Option.NETBIOS_Scope: 'text',                         # [RFC 2132]
            Enum_Option.X_Window_Font: 'addresses',                    # [RFC 2132]
            Enum_Option.X_Window_Manager: 'addresses',                 # [RFC 2132]
            Enum_Option.Address_Request: 'address',                    # [RFC 2132]
            Enum_Option.Address_Time: 'uint32',                        # [RFC 2132]
            Enum_Option.Overload: 'overload',                          # [RFC 2132]
            Enum_Option.DHCP_Msg_Type: 'message_type',                 # [RFC 2132]
            Enum_Option.DHCP_Server_Id: 'address',                     # [RFC 2132]
            Enum_Option.Parameter_List: 'parameter_list',              # [RFC 2132]
            Enum_Option.DHCP_Message: 'text',                          # [RFC 2132]
            Enum_Option.DHCP_Max_Msg_Size: 'uint16',                   # [RFC 2132]
            Enum_Option.Renewal_Time: 'uint32',                        # [RFC 2132]
            Enum_Option.Rebinding_Time: 'uint32',                      # [RFC 2132]
            Enum_Option.Client_Id: 'client_id',                        # [RFC 2132]
            Enum_Option.NIS_Domain_Name: 'text',                       # [RFC 2132]
            Enum_Option.NIS_Server_Addr: 'addresses',                  # [RFC 2132]
            Enum_Option.Server_Name: 'text',                           # [RFC 2132]
            Enum_Option.Bootfile_Name: 'text',                         # [RFC 2132]
            Enum_Option.Home_Agent_Addrs: 'home_agent',                # [RFC 2132]
            Enum_Option.SMTP_Server: 'addresses',                      # [RFC 2132]
            Enum_Option.POP3_Server: 'addresses',                      # [RFC 2132]
            Enum_Option.NNTP_Server: 'addresses',                      # [RFC 2132]
            Enum_Option.WWW_Server: 'addresses',                       # [RFC 2132]
            Enum_Option.Finger_Server: 'addresses',                    # [RFC 2132]
            Enum_Option.IRC_Server: 'addresses',                       # [RFC 2132]
            Enum_Option.StreetTalk_Server: 'addresses',                # [RFC 2132]
            Enum_Option.STDA_Server: 'addresses',                      # [RFC 2132]
            Enum_Option.User_Class: 'user_class',                      # [RFC 3004]
            Enum_Option.Client_FQDN: 'client_fqdn',                    # [RFC 4702]
            Enum_Option.Relay_Agent_Information: 'relay_agent',        # [RFC 3046]
            Enum_Option.Client_System: 'client_system',                # [RFC 4578]
            Enum_Option.Client_NDI: 'client_ndi',                      # [RFC 4578]
            Enum_Option.UUID_GUID: 'machine_id',                       # [RFC 4578]
            Enum_Option.PCode: 'text',                                 # [RFC 4833]
            Enum_Option.TCode: 'text',                                 # [RFC 4833]
            Enum_Option.IPv6_Only_Preferred: 'uint32',                 # [RFC 8925]
            Enum_Option.DHCP_Captive_Portal: 'text',                   # [RFC 8910]
            Enum_Option.Auto_Config: 'boolean',                        # [RFC 2563]
            Enum_Option.Subnet_Selection_Option: 'address',            # [RFC 3011]
            Enum_Option.Domain_Search: 'domain_search',                # [RFC 3397]
            Enum_Option.Classless_Static_Route_Option: 'classless_route',  # [RFC 3442]
            Enum_Option.V_I_Vendor_Class: 'vendor_class',              # [RFC 3925]
            Enum_Option.V_I_Vendor_Specific_Information: 'vendor_specific',  # [RFC 3925]
        },
    )  # type: DefaultDict[Enum_Option | int, str | tuple[OptionParser, OptionConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def length(self) -> 'int':
        """Header length of current protocol, i.e. the whole message."""
        return self._length

    @property
    def alias(self) -> 'str':
        """Acronym of current protocol, ``'BOOTP'`` or ``'DHCP'``."""
        return self.id()[0]

    #: NOTE: On the base, as STP's is, so a consumer finds ``dhcp`` whichever
    #: member read the message.
    @property
    def info_name(self) -> 'Literal["dhcp"]':
        """Key name of the :attr:`~pcapkit.protocols.protocol.Protocol.info` dict."""
        return 'dhcp'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["DHCP"], Literal["BOOTP"]]':
        """Index ID of the protocol.

        :rfc:`2131` names its protocol plain ``DHCP``, so the family's own name
        doubles as the canonical name of
        :class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4`, the shape
        :meth:`ICMP.id <pcapkit.protocols.internet.icmp.protocol.ICMP.id>` takes.

        Returns:
            Index ID of the protocol, the family name and BOOTP's; each member
            narrows it to its own canonical name.

        """
        return ('DHCP', 'BOOTP')

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', /, **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the member whose data
            model ``data`` is.

        Raises:
            ProtocolError: If ``data`` is no member's data model, on this class. A
                :obj:`dict` is refused, since no key picks the member.

        """
        if cls is not DHCP:
            return super().from_data(data, **kwargs)
        for member, model in zip(_MEMBERS, _DATA):
            if isinstance(data, model.klass):
                return cast('Self', member.klass.from_data(data, **kwargs))
        raise ProtocolError('DHCP: invalid data: must be a BOOTP or DHCPv4 data model')

    @classmethod
    def register_option(cls, code: 'Enum_Option', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register an option parser.

        Args:
            code: Option code.
            meth: Name of the ``_read_opt_${name}`` and ``_make_opt_${name}``
                methods, or a ``(parser, constructor)`` pair of callables; see
                :attr:`__option__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten. Handing back the entry already
                stored, or one equal to it, is a silent no-op.

        """
        incumbent = cls.__option__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'DHCP: [Option {code}] option already registered, overwriting', RegistryWarning)
        cls.__option__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'int':  # type: ignore[override]
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_ service names and
            port numbers: port 67, the port of
            :attr:`UDP.bootps <pcapkit.const.reg.apptype.udp.UDP.bootps>` as an
            :class:`int`, which every member inherits
            (:ref:`registry-protocol-index`).

        .. _IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

        """
        return int(_UDP.klass.bootps)

    def __length_hint__(self) -> 'int':
        """Return an estimated length for the object, the header and the magic cookie."""
        return HEADER_LENGTH + len(MAGIC_COOKIE)

    def __new__(cls, file: 'Optional[IO[bytes] | bytes] | NoValueType' = NO_VALUE,
                length: 'Optional[int]' = None, /, **kwargs: 'Any') -> 'DHCP':
        """Create the member a parse of this class describes.

        Octets give the member :meth:`_classify` picks, whose ``__init__`` then runs
        with the same arguments; fields are refused, as no field names a member. A
        subclass of this class is created as itself.

        Args:
            file: Source packet stream, read here without being consumed;
                omitted to construct.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            TypeError: If ``file`` is :obj:`None`, on this class.
            ProtocolError: If fields are given, on this class.

        """
        if cls is not DHCP:
            return super().__new__(cls, file, length, **kwargs)
        if isinstance(file, NoValueType):
            member = cls._construction_member(kwargs)
            return member.__new__(member)  # pragma: no cover
        if file is None:
            raise _nothing_to_parse(DHCP)
        if isinstance(file, bytes):
            data = file[:length]
        else:
            offset = file.tell()
            data = file.read(-1 if length is None else length)
            file.seek(offset)
        member = cls._classify(data)
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_opt_unknown(self, code: 'Enum_Option', data: 'bytes') -> 'bytes':  # pylint: disable=unused-argument
        """Read an option with no decoder registered: its raw octets.

        Args:
            code: Option code.
            data: Option data.

        Returns:
            ``data`` itself.

        """
        return data

    def _read_opt_address(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Address':
        """Read an option carrying one IPv4 address, four octets (:rfc:`2132`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not four octets.

        """
        if len(data) != 4:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_Address(address=ipaddress.IPv4Address(data))

    def _read_opt_time_offset(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Number':
        """Read the Time Offset option, a signed 32-bit integer (:rfc:`2132#section-3.4`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not four octets.

        """
        if len(data) != 4:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_Number(value=int.from_bytes(data, 'big', signed=True))

    def _read_opt_addresses(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Addresses':
        """Read an option carrying one IPv4 address or more (:rfc:`2132`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty or not a multiple of four octets.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_Addresses(addresses=self._read_dhcp_addresses(code, data))

    def _read_opt_text(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Text':
        """Read an option carrying ASCII text, one octet or more (:rfc:`2132#section-2`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty or not ASCII.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_Text(text=self._read_dhcp_text(code, data))

    def _read_opt_uint16(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Number':
        """Read an option carrying a 16-bit unsigned integer (:rfc:`2132`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not two octets, or the value is below
                the least :data:`~pcapkit.protocols.application.dhcp.const.MINIMUMS`
                gives the option.

        """
        return Data_Number(value=self._read_dhcp_uint(code, data, size=2))

    def _read_opt_boolean(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Boolean':
        """Read an option carrying an octet of ``0`` or ``1`` (:rfc:`2132`, :rfc:`2563`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not one octet of ``0`` or ``1``.

        """
        if data not in (b'\x00', b'\x01'):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid value: {data!r}')
        return Data_Boolean(value=data == b'\x01')

    def _read_opt_policy_filter(self, code: 'Enum_Option', data: 'bytes') -> 'Data_PolicyFilter':
        """Read the Policy Filter option (:rfc:`2132#section-4.3`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty or not a multiple of eight octets.

        """
        addresses = self._read_dhcp_pairs(code, data)
        return Data_PolicyFilter(filters=tuple(Data_AddressMask(address=addresses[index], mask=addresses[index + 1])
                                               for index in range(0, len(addresses), 2)))

    def _read_opt_uint8(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Number':
        """Read an option carrying an 8-bit unsigned integer (:rfc:`2132`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not one octet, or the value is below the
                least :data:`~pcapkit.protocols.application.dhcp.const.MINIMUMS`
                gives the option.

        """
        return Data_Number(value=self._read_dhcp_uint(code, data, size=1))

    def _read_opt_uint32(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Number':
        """Read an option carrying a 32-bit unsigned integer (:rfc:`2132`, :rfc:`8925`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not four octets.

        """
        return Data_Number(value=self._read_dhcp_uint(code, data, size=4))

    def _read_opt_mtu_plateau(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Sizes':
        """Read the Path MTU Plateau Table option (:rfc:`2132#section-4.7`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty or not a multiple of two octets,
                or a size is below 68.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        sizes = self._read_uints(data, size=2, what=f'[Option {code}] MTU sizes')
        if min(sizes) < 68:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid MTU size: {min(sizes)}')
        return Data_Sizes(sizes=sizes)

    def _read_opt_static_route(self, code: 'Enum_Option', data: 'bytes') -> 'Data_StaticRoutes':
        """Read the Static Route option (:rfc:`2132#section-5.8`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty or not a multiple of eight octets.

        """
        addresses = self._read_dhcp_pairs(code, data)
        return Data_StaticRoutes(routes=tuple(Data_Route(destination=addresses[index], router=addresses[index + 1])
                                              for index in range(0, len(addresses), 2)))

    def _read_opt_node_type(self, code: 'Enum_Option', data: 'bytes') -> 'Data_NodeType':
        """Read the NetBIOS over TCP/IP Node Type option (:rfc:`2132#section-8.7`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not one octet of ``0x1``, ``0x2``,
                ``0x4`` or ``0x8``.

        """
        if len(data) != 1 or data[0] not in (0x1, 0x2, 0x4, 0x8):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid value: {data!r}')
        return Data_NodeType(node_type=data[0])

    def _read_opt_overload(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Overload':
        """Read the Option Overload option (:rfc:`2132#section-9.3`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not one octet of ``1``, ``2`` or ``3``.

        """
        if len(data) != 1 or data[0] not in (1, 2, 3):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid value: {data!r}')
        return Data_Overload(file=bool(data[0] & 1), sname=bool(data[0] & 2))

    def _read_opt_message_type(self, code: 'Enum_Option', data: 'bytes') -> 'Data_MessageType':
        """Read the DHCP Message Type option (:rfc:`2132#section-9.6`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not one octet.

        """
        if len(data) != 1:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_MessageType(type=Enum_MessageType.get(data[0]))

    def _read_opt_parameter_list(self, code: 'Enum_Option', data: 'bytes') -> 'Data_ParameterList':
        """Read the Parameter Request List option (:rfc:`2132#section-9.8`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_ParameterList(codes=tuple(Enum_Option.get(value) for value in data))

    def _read_opt_client_id(self, code: 'Enum_Option', data: 'bytes') -> 'Data_ClientIdentifier':
        """Read the Client-identifier option (:rfc:`2132#section-9.14`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is shorter than two octets.

        """
        if len(data) < 2:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        htype = Enum_Hardware.get(data[0])
        return Data_ClientIdentifier(type=htype, identifier=self._read_hardware_address(htype, data[1:]))

    def _read_opt_home_agent(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Addresses':
        """Read the Mobile IP Home Agent option, of zero addresses or more
        (:rfc:`2132#section-8.10`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not a multiple of four octets.

        """
        return Data_Addresses(addresses=self._read_dhcp_addresses(code, data))

    def _read_opt_user_class(self, code: 'Enum_Option', data: 'bytes') -> 'Data_UserClass':
        """Read the User Class option (:rfc:`3004#section-4`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty, an instance is empty, or one
                runs past ``data``.

        """
        classes = self._read_dhcp_vectors(code, data)
        if not classes or not all(classes):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid format: empty user class')
        return Data_UserClass(classes=classes)

    def _read_opt_client_fqdn(self, code: 'Enum_Option', data: 'bytes') -> 'Data_ClientFQDN':
        """Read the Client FQDN option (:rfc:`4702#section-2`).

        The domain name is in canonical wire format, uncompressed, where the
        ``E`` flag is set, and may be partial, without the root label; else it
        is ASCII text, as :rfc:`4702#section-2.3.1` keeps for older clients.

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is shorter than three octets, or the
                domain name is malformed.

        """
        if len(data) < 3:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        flags = data[0]
        encoded = bool(flags & 0x04)
        if encoded:
            name = self._read_fqdn_name(code, data[3:])
        else:
            name = self._read_dhcp_text(code, data[3:])
        return Data_ClientFQDN(
            flags=Data_FQDNFlags(n=bool(flags & 0x08), e=encoded, o=bool(flags & 0x02), s=bool(flags & 0x01),
                                 mbz=flags >> 4),
            rcode1=data[1],
            rcode2=data[2],
            name=name,
        )

    def _read_opt_relay_agent(self, code: 'Enum_Option', data: 'bytes') -> 'Data_RelayAgentInformation':
        """Read the Relay Agent Information option (:rfc:`3046#section-2.0`).

        Each sub-option's data is kept as octets, its format being its own
        specification's.

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty, or a sub-option runs past it.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        suboptions = []  # type: list[Data_RelayAgentSubOption]
        pos = 0
        while pos < len(data):
            subcode = Enum_RelayAgentSubOption.get(data[pos])
            value, pos = self._read_vector(data, pos + 1, size=1, what=f'[Option {code}] sub-option')
            suboptions.append(Data_RelayAgentSubOption(code=subcode, length=len(value), data=value))
        return Data_RelayAgentInformation(suboptions=tuple(suboptions))

    def _read_opt_client_system(self, code: 'Enum_Option', data: 'bytes') -> 'Data_ArchitectureTypes':
        """Read the Client System Architecture Type option (:rfc:`4578#section-2.1`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty or not a multiple of two octets.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_ArchitectureTypes(types=self._read_uints(data, size=2,
                                                             what=f'[Option {code}] architecture types'))

    def _read_opt_client_ndi(self, code: 'Enum_Option', data: 'bytes') -> 'Data_ClientNDI':
        """Read the Client Network Interface Identifier option (:rfc:`4578#section-2.2`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not three octets.

        """
        if len(data) != 3:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_ClientNDI(type=data[0], major=data[1], minor=data[2])

    def _read_opt_machine_id(self, code: 'Enum_Option', data: 'bytes') -> 'Data_MachineIdentifier':
        """Read the Client Machine Identifier option (:rfc:`4578#section-2.3`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is not 17 octets.

        """
        if len(data) != 17:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return Data_MachineIdentifier(type=data[0], identifier=data[1:])

    def _read_opt_domain_search(self, code: 'Enum_Option', data: 'bytes') -> 'Data_DomainSearch':
        """Read the Domain Search option (:rfc:`3397#section-2`).

        Its names are written as :rfc:`1035#section-3.1` writes them, and a
        compression pointer is an offset into the option's data.

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty or a name is malformed.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        names = []  # type: list[Data_DomainName]
        pos = 0
        while pos < len(data):
            labels, literal, pointer, pos = read_name(data, pos, alias=self.alias)
            names.append(Data_DomainName(name=name_to_text(labels), labels=labels,
                                         literal=literal, pointer=pointer))
        return Data_DomainSearch(names=tuple(names))

    def _read_opt_classless_route(self, code: 'Enum_Option', data: 'bytes') -> 'Data_ClasslessStaticRoutes':
        """Read the Classless Static Route option (:rfc:`3442#section-2`).

        Each route is its prefix length, the significant octets of its
        destination and its router.

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is shorter than five octets, a prefix
                length exceeds 32, a route runs past ``data``, or a destination
                sets a bit past its prefix.

        """
        if len(data) < 5:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        routes = []  # type: list[Data_ClasslessRoute]
        pos = 0
        while pos < len(data):
            width = data[pos]
            if width > 32:
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid prefix length: {width}')
            size = (width + 7) // 8
            octets = self._read_octets(data, pos + 1, size=size + 4, what=f'[Option {code}] route')
            try:
                network = ipaddress.IPv4Network((octets[:size].ljust(4, b'\x00'), width))
            except ValueError as error:
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid destination: {error}') from None
            routes.append(Data_ClasslessRoute(destination=network, router=ipaddress.IPv4Address(octets[size:])))
            pos += 1 + size + 4
        return Data_ClasslessStaticRoutes(routes=tuple(routes))

    def _read_opt_vendor_class(self, code: 'Enum_Option', data: 'bytes') -> 'Data_VendorClass':
        """Read the Vendor-Identifying Vendor Class option (:rfc:`3925#section-3`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty, or a vendor's data or an item
                of it runs past its end.

        """
        vendors = []  # type: list[Data_VendorClassEntry]
        for enterprise, value in self._read_dhcp_vendors(code, data):
            vendors.append(Data_VendorClassEntry(enterprise=enterprise,
                                                 classes=self._read_dhcp_vectors(code, value)))
        return Data_VendorClass(vendors=tuple(vendors))

    def _read_opt_vendor_specific(self, code: 'Enum_Option', data: 'bytes') -> 'Data_VendorSpecific':
        """Read the Vendor-Identifying Vendor-Specific Information option (:rfc:`3925#section-4`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Parsed option data.

        Raises:
            ProtocolError: If ``data`` is empty, or a vendor's data or a
                sub-option of it runs past its end.

        """
        vendors = []  # type: list[Data_VendorOptions]
        for enterprise, value in self._read_dhcp_vendors(code, data):
            options = []  # type: list[Data_VendorOption]
            pos = 0
            while pos < len(value):
                subcode = value[pos]
                body, pos = self._read_vector(value, pos + 1, size=1, what=f'[Option {code}] sub-option')
                options.append(Data_VendorOption(code=subcode, data=body))
            vendors.append(Data_VendorOptions(enterprise=enterprise, options=tuple(options)))
        return Data_VendorSpecific(vendors=tuple(vendors))

    def _make_opt_unknown(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an option with no constructor registered.

        Args:
            code: Option code.
            data: Option fields; none can be written.

        Returns:
            Empty option data, for no fields.

        Raises:
            ProtocolError: If ``data`` holds a field.

        """
        if data:
            raise ProtocolError(f'{self.alias}: no constructor for option {code!r}; give its octets')
        return b''

    def _make_opt_address(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an option carrying one IPv4 address.

        Args:
            code: Option code.
            data: Option fields, i.e. ``address``.

        Returns:
            Option data.

        """
        return self._make_dhcp_address(code, data.get('address', '0.0.0.0'))  # nosec: B104

    def _make_opt_time_offset(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Time Offset option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``value``, in seconds.

        Returns:
            Option data.

        """
        return self._make_pack(self._make_sint(data.get('value', 0), bits=32, name=f'[Option {code}] value'),
                               size=4)

    def _make_opt_addresses(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an option carrying one IPv4 address or more.

        Args:
            code: Option code.
            data: Option fields, i.e. ``addresses``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``addresses`` is empty.

        """
        addresses = tuple(data.get('addresses', ()))
        if not addresses:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid addresses: none given')
        return b''.join(self._make_dhcp_address(code, address) for address in addresses)

    def _make_opt_text(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an option carrying ASCII text.

        Args:
            code: Option code.
            data: Option fields, i.e. ``text``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``text`` is empty.

        """
        octets = self._make_dhcp_text(code, data.get('text', ''))
        if not octets:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid text: empty')
        return octets

    def _make_opt_uint16(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an option carrying a 16-bit unsigned integer.

        Args:
            code: Option code.
            data: Option fields, i.e. ``value``.

        Returns:
            Option data.

        """
        return self._make_dhcp_uint(code, data.get('value', MINIMUMS.get(code, 0)), size=2)

    def _make_opt_boolean(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an option carrying an octet of ``0`` or ``1``.

        Args:
            code: Option code.
            data: Option fields, i.e. ``value``.

        Returns:
            Option data.

        """
        return self._make_pack(self._make_uint(data.get('value', False), bits=1, name=f'[Option {code}] value'),
                               size=1)

    def _make_opt_policy_filter(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Policy Filter option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``filters``, each an ``address`` and a ``mask``.

        Returns:
            Option data.

        """
        return self._make_dhcp_pairs(code, data.get('filters', ()), ('address', 'mask'))

    def _make_opt_uint8(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an option carrying an 8-bit unsigned integer.

        Args:
            code: Option code.
            data: Option fields, i.e. ``value``.

        Returns:
            Option data.

        """
        return self._make_dhcp_uint(code, data.get('value', MINIMUMS.get(code, 0)), size=1)

    def _make_opt_uint32(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an option carrying a 32-bit unsigned integer.

        Args:
            code: Option code.
            data: Option fields, i.e. ``value``.

        Returns:
            Option data.

        """
        return self._make_dhcp_uint(code, data.get('value', 0), size=4)

    def _make_opt_mtu_plateau(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Path MTU Plateau Table option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``sizes``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``sizes`` is empty or a size is below 68.

        """
        sizes = tuple(data.get('sizes', ()))
        if not sizes:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid MTU sizes: none given')
        values = [self._make_uint(size, bits=16, name=f'[Option {code}] MTU size') for size in sizes]
        if min(values) < 68:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid MTU size: {min(values)}')
        return self._make_uints(values, size=2)

    def _make_opt_static_route(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Static Route option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``routes``, each a ``destination`` and a ``router``.

        Returns:
            Option data.

        """
        return self._make_dhcp_pairs(code, data.get('routes', ()), ('destination', 'router'))

    def _make_opt_node_type(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the NetBIOS over TCP/IP Node Type option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``node_type``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``node_type`` is none of ``0x1``, ``0x2``, ``0x4``
                and ``0x8``.

        """
        value = self._make_uint(data.get('node_type', 0x1), bits=8, name=f'[Option {code}] node type')
        if value not in (0x1, 0x2, 0x4, 0x8):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid node type: {value:#x}')
        return self._make_pack(value, size=1)

    def _make_opt_overload(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Option Overload option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``file`` and ``sname``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If neither field is overloaded.

        """
        value = (self._make_uint(data.get('file', False), bits=1, name=f'[Option {code}] file flag')
                 | self._make_uint(data.get('sname', False), bits=1, name=f'[Option {code}] sname flag') << 1)
        if not value:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid overload: neither field')
        return self._make_pack(value, size=1)

    def _make_opt_message_type(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the DHCP Message Type option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``type``.

        Returns:
            Option data.

        """
        value = self._make_index(data.get('type', Enum_MessageType.DHCPDISCOVER), Enum_MessageType,
                                 bits=8, name=f'[Option {code}] message type')
        return self._make_pack(int(value), size=1)

    def _make_opt_parameter_list(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Parameter Request List option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``codes``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``codes`` is empty.

        """
        codes = tuple(data.get('codes', ()))
        if not codes:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid codes: none given')
        return bytes(int(self._make_index(value, Enum_Option, bits=8, name=f'[Option {code}] code'))
                     for value in codes)

    def _make_opt_client_id(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Client-identifier option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``type`` and ``identifier``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``identifier`` is empty.

        """
        htype = self._make_index(data.get('type', Enum_Hardware.Ethernet), Enum_Hardware, bits=8,
                                 name=f'[Option {code}] type')
        identifier = self._make_hardware_address(htype, data.get('identifier', b''), name=f'[Option {code}] identifier')
        if not identifier:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid identifier: empty')
        return self._make_pack(int(htype), size=1) + identifier

    def _make_opt_home_agent(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Mobile IP Home Agent option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``addresses``, which may be none.

        Returns:
            Option data.

        """
        return b''.join(self._make_dhcp_address(code, address) for address in data.get('addresses', ()))

    def _make_opt_user_class(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the User Class option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``classes``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``classes`` is empty, or holds an empty instance.

        """
        classes = tuple(data.get('classes', ()))
        if not classes or not all(classes):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid user classes: {classes!r}')
        return self._make_dhcp_vectors(code, classes)

    def _make_opt_client_fqdn(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Client FQDN option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``flags``, ``rcode1``, ``rcode2`` and
                ``name``, the last written in canonical wire format where the
                ``E`` flag is set.

        Returns:
            Option data.

        """
        flags = data.get('flags', {'e': True})
        if isinstance(flags, collections.abc.Mapping):
            encoded = bool(flags.get('e', False))
            value = (self._make_uint(flags.get('s', False), bits=1, name=f'[Option {code}] S flag')
                     | self._make_uint(flags.get('o', False), bits=1, name=f'[Option {code}] O flag') << 1
                     | self._make_uint(encoded, bits=1, name=f'[Option {code}] E flag') << 2
                     | self._make_uint(flags.get('n', False), bits=1, name=f'[Option {code}] N flag') << 3
                     | self._make_uint(flags.get('mbz', 0), bits=4, name=f'[Option {code}] MBZ bits') << 4)
        else:
            value = self._make_uint(flags, bits=8, name=f'[Option {code}] flags')
            encoded = bool(value & 0x04)
        name = data.get('name', '')
        body = self._make_fqdn_name(code, name) if encoded else self._make_dhcp_text(code, name)
        return (self._make_pack(value, size=1)
                + self._make_pack(self._make_uint(data.get('rcode1', 0), bits=8, name=f'[Option {code}] RCODE1'),
                                  size=1)
                + self._make_pack(self._make_uint(data.get('rcode2', 0), bits=8, name=f'[Option {code}] RCODE2'),
                                  size=1)
                + body)

    def _make_opt_relay_agent(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Relay Agent Information option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``suboptions``, each a ``code``, a ``data``
                and, when it is not that of ``data``, a ``length``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``suboptions`` is empty, or a sub-option is no
                mapping or its data is no octets.

        """
        suboptions = tuple(data.get('suboptions', ()))
        if not suboptions:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid sub-options: none given')
        out = bytearray()
        for suboption in suboptions:
            if not isinstance(suboption, collections.abc.Mapping):
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid sub-option: {suboption!r}')
            subcode = self._make_index(suboption.get('code', Enum_RelayAgentSubOption.Agent_Circuit_ID_Sub_option),
                                       Enum_RelayAgentSubOption, bits=8, name=f'[Option {code}] sub-option code')
            value = suboption.get('data', b'')
            if not isinstance(value, (bytes, bytearray)):
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid sub-option data: {value!r}')
            size = suboption.get('length')
            size = len(value) if size is None else size
            out += self._make_pack(int(subcode), size=1)
            out += self._make_pack(self._make_uint(size, bits=8, name=f'[Option {code}] sub-option length'), size=1)
            out += value
        return bytes(out)

    def _make_opt_client_system(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Client System Architecture Type option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``types``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``types`` is empty.

        """
        types = tuple(data.get('types', ()))
        if not types:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid architecture types: none given')
        return self._make_uints([self._make_uint(value, bits=16, name=f'[Option {code}] architecture type')
                                 for value in types], size=2)

    def _make_opt_client_ndi(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Client Network Interface Identifier option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``type``, ``major`` and ``minor``.

        Returns:
            Option data.

        """
        return bytes((self._make_uint(data.get('type', 1), bits=8, name=f'[Option {code}] type'),
                      self._make_uint(data.get('major', 0), bits=8, name=f'[Option {code}] major revision'),
                      self._make_uint(data.get('minor', 0), bits=8, name=f'[Option {code}] minor revision')))

    def _make_opt_machine_id(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Client Machine Identifier option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``type`` and the 16-octet ``identifier``.

        Returns:
            Option data.

        """
        return (self._make_pack(self._make_uint(data.get('type', 0), bits=8, name=f'[Option {code}] type'), size=1)
                + self._make_octets(data.get('identifier', bytes(16)), size=16, name=f'[Option {code}] identifier'))

    def _make_opt_domain_search(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Domain Search option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``names``: each a
                :class:`~pcapkit.protocols.application.dhcp.data.DomainName`, which
                writes the compression it records, or its presentation form,
                written in full.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``names`` is empty, or a name is malformed.

        """
        names = tuple(data.get('names', ()))
        if not names:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid names: none given')
        out = bytearray()
        for name in names:
            if isinstance(name, collections.abc.Mapping):
                out += make_name(tuple(name['labels']), literal=name.get('literal'), pointer=name.get('pointer'),
                                 alias=self.alias)
            elif isinstance(name, str):
                out += make_name(text_to_labels(name, alias=self.alias), alias=self.alias)
            else:
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid name: {name!r}')
        return bytes(out)

    def _make_opt_classless_route(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Classless Static Route option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``routes``, each a ``destination`` network
                and a ``router``.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``routes`` is empty, or a destination is no IPv4
                network.

        """
        routes = tuple(data.get('routes', ()))
        if not routes:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid routes: none given')
        out = bytearray()
        for route in routes:
            if not isinstance(route, collections.abc.Mapping):
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid route: {route!r}')
            try:
                network = ipaddress.IPv4Network(route.get('destination', '0.0.0.0/0'))  # nosec: B104
            except (TypeError, ValueError) as error:
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid destination: {error}') from None
            size = (network.prefixlen + 7) // 8
            out += self._make_pack(network.prefixlen, size=1) + network.network_address.packed[:size]
            out += self._make_dhcp_address(code, route.get('router', '0.0.0.0'))  # nosec: B104
        return bytes(out)

    def _make_opt_vendor_class(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Vendor-Identifying Vendor Class option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``vendors``, each an ``enterprise`` number
                and its ``classes``.

        Returns:
            Option data.

        """
        return self._make_dhcp_vendors(code, data.get('vendors', ()),
                                       lambda vendor: self._make_dhcp_vectors(code, tuple(vendor.get('classes', ()))))

    def _make_opt_vendor_specific(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make the Vendor-Identifying Vendor-Specific Information option.

        Args:
            code: Option code.
            data: Option fields, i.e. ``vendors``, each an ``enterprise`` number
                and its ``options``, each a ``code`` and a ``data``.

        Returns:
            Option data.

        """
        def options(vendor: 'Mapping[str, Any]') -> 'bytes':
            out = bytearray()
            for option in vendor.get('options', ()):
                if not isinstance(option, collections.abc.Mapping):
                    raise ProtocolError(f'{self.alias}: [Option {code}] invalid sub-option: {option!r}')
                value = option.get('data', b'')
                if not isinstance(value, (bytes, bytearray)) or len(value) > 255:
                    raise ProtocolError(f'{self.alias}: [Option {code}] invalid sub-option data: {value!r}')
                out += self._make_pack(self._make_uint(option.get('code', 0), bits=8,
                                                       name=f'[Option {code}] sub-option code'), size=1)
                out += self._make_vector(bytes(value), size=1)
            return bytes(out)

        return self._make_dhcp_vendors(code, data.get('vendors', ()), options)

    @classmethod
    def _construction_member(cls, fields: 'dict[str, Any]') -> 'Type[Self]':
        """The class :meth:`from_fields` and a call given no file construct.

        Args:
            fields: Construction keywords.

        Returns:
            The class itself, which must be a member.

        Raises:
            ProtocolError: On this class, since no field names the member.

        """
        if cls is DHCP:
            raise ProtocolError('DHCP: no member to build with; build BOOTP or DHCPv4')
        return cls

    @classmethod
    def _classify(cls, data: 'bytes') -> 'Type[DHCP]':
        """Pick the member a message is.

        A message whose options carry the DHCP Message Type option is a DHCP
        message (:rfc:`1534#section-2`): the options field, opening with the
        magic cookie, then the ``file`` and ``sname`` fields an Option Overload
        option there says hold options (:rfc:`2131#section-4.1`), read in that
        order. The option counts where it is whole before any option runs past
        its field, as a capture cut leaves one; any other message is a BOOTP
        message.

        Args:
            data: The message, its octets alone.

        Returns:
            :class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4` or
            :class:`~pcapkit.protocols.application.bootp.protocol.BOOTP`.

        """
        area = data[HEADER_LENGTH:]
        if area[:len(MAGIC_COOKIE)] != MAGIC_COOKIE:
            return _MEMBERS[0].klass
        entries, _, overrun = cls._split_options(area[len(MAGIC_COOKIE):])
        found = list(entries)
        if not overrun:
            for start, stop in cls._overloaded_fields(entries):
                inner, _, overrun = cls._split_options(data[start:stop])
                found.extend(inner)
                if overrun:
                    break
        if any(code == Enum_Option.DHCP_Msg_Type for code, _ in found):
            return _MEMBERS[1].klass
        return _MEMBERS[0].klass

    @staticmethod
    def _split_options(area: 'bytes') -> 'tuple[tuple[RawOption, ...], int, bool]':
        """Split an option area into its options (:rfc:`2132#section-2`).

        The Pad and End options are one octet; every other option is its code,
        its length octet and that many octets of data. The area ends at the
        End option, where its octets do, or at an option that runs past them.

        Args:
            area: The option area, after any magic cookie.

        Returns:
            The whole options, each its code and data, the latter :obj:`None`
            for the Pad and End options; the offset past the End option, of the
            option that runs past the area, or the area's length; and whether an
            option runs past the area.

        """
        entries = []  # type: list[RawOption]
        pos = 0
        while pos < len(area):
            code = area[pos]
            if code in (Enum_Option.Pad, Enum_Option.End):
                entries.append((code, None))
                pos += 1
                if code == Enum_Option.End:
                    break
                continue
            if pos + 1 >= len(area) or pos + 2 + area[pos + 1] > len(area):
                return tuple(entries), pos, True
            entries.append((code, area[pos + 2:pos + 2 + area[pos + 1]]))
            pos += 2 + area[pos + 1]
        return tuple(entries), pos, False

    @staticmethod
    def _overloaded_fields(entries: 'Iterable[RawOption]') -> 'tuple[tuple[int, int], ...]':
        """The fields an Option Overload option says hold options, in the order
        they are read (:rfc:`2131#section-4.1`).

        Args:
            entries: The options of the options field.

        Returns:
            The offsets of the ``file`` field, then of the ``sname`` field, in
            the message, each where the one Option Overload option, of a valid
            value, says it holds options.

        """
        values = [value for code, value in entries if code == Enum_Option.Overload]
        if len(values) != 1 or values[0] not in (b'\x01', b'\x02', b'\x03'):
            return ()
        fields = []  # type: list[tuple[int, int]]
        if values[0][0] & 1:
            fields.append((108, HEADER_LENGTH))
        if values[0][0] & 2:
            fields.append((44, 108))
        return tuple(fields)

    def _read_dhcp_header(self) -> 'dict[str, Any]':
        """Read the fields a BOOTP and a DHCP message share, ``op`` through ``chaddr``.

        Returns:
            The fields, as their data models' keys; :attr:`length` is set.

        """
        schema = cast('Schema_DHCP', self.__header__)
        htype = Enum_Hardware.get(schema.htype)
        size = min(schema.hlen, CHADDR_LENGTH)
        self._length = HEADER_LENGTH + len(schema.options)
        return {
            'op': Enum_Opcode.get(schema.op),
            'htype': htype,
            'hlen': schema.hlen,
            'hops': schema.hops,
            'xid': schema.xid,
            'secs': schema.secs,
            'flags': Data_Flags(broadcast=bool(schema.flags['broadcast']), reserved=schema.flags['reserved']),
            'ciaddr': schema.ciaddr,
            'yiaddr': schema.yiaddr,
            'siaddr': schema.siaddr,
            'giaddr': schema.giaddr,
            'chaddr': self._read_hardware_address(htype, schema.chaddr[:size]),
            'chaddr_padding': schema.chaddr[size:],
        }

    def _read_dhcp_area(self, area: 'bytes') -> 'tuple[tuple[RawOption, ...], bytes]':
        """Split the options field, after its magic cookie, into its options.

        An option the field ends inside is what a capture cut leaves, so it is
        recorded as the header schema records a field the data ends inside, and
        rebuilds as captured.

        Args:
            area: The options field.

        Returns:
            Its whole options, as :meth:`_split_options` gives them, and the
            octets after the End option or from the option the field ends inside.

        """
        entries, end, overrun = self._split_options(area[len(MAGIC_COOKIE):])
        rest = area[len(MAGIC_COOKIE) + end:]
        if overrun:
            missing = 1 if len(rest) < 2 else 2 + rest[1] - len(rest)
            self.__header__._note_short_read('options', len(area) + missing, area)  # pylint: disable=protected-access
        return entries, rest

    def _read_dhcp_options(self, entries: 'Iterable[RawOption]', counts: 'collections.Counter[int]',
                           codes: 'Optional[frozenset[int]]' = None) -> 'tuple[Data_Option, ...]':
        """Decode the options of an area.

        Each option's data is read by the parser :attr:`__option__` registers
        for its code, and kept as raw octets where that parser rejects it, where
        ``codes`` leaves the code out, or where ``counts`` has the code more
        than once, as :rfc:`3396#section-7` concatenates such instances.

        Args:
            entries: The options, as :meth:`_split_options` gives them.
            counts: How many times each code occurs in the message.
            codes: The codes to decode, or :obj:`None` for all.

        Returns:
            The options, in order.

        """
        options = []  # type: list[Data_Option]
        for value, data in entries:
            code = Enum_Option.get(value)
            if data is None:
                options.append(Data_Option(code=code, length=None, data=None))
                continue
            body = data  # type: Union[Data_OptionData, bytes]
            if counts[value] == 1 and (codes is None or value in codes):
                meth = self._lookup_registry(self.__option__, code)
                if isinstance(meth, str):
                    parser = cast('OptionParser', getattr(self, f'_read_opt_{meth}', self._read_opt_unknown))
                else:
                    parser = meth[0]
                try:
                    with CaughtByCaller(ProtocolError):
                        body = parser(code, data)
                except ProtocolError:
                    body = data
            options.append(Data_Option(code=code, length=len(data), data=body))
        return tuple(options)

    @staticmethod
    def _count_options(*areas: 'Iterable[RawOption]') -> 'collections.Counter[int]':
        """Count the instances of each option code in the message.

        Args:
            *areas: The options of each area that holds options.

        Returns:
            How many times each code other than Pad and End occurs.

        """
        return collections.Counter(code for area in areas for code, data in area if data is not None)

    def _make_dhcp_header(self, *, op: 'Enum_Opcode | int', htype: 'Enum_Hardware | int', hlen: 'Optional[int]',
                          hops: 'int', xid: 'int', secs: 'int', flags: 'Mapping[str, Any] | int',
                          ciaddr: 'IPv4Address | str | bytes | int', yiaddr: 'IPv4Address | str | bytes | int',
                          siaddr: 'IPv4Address | str | bytes | int', giaddr: 'IPv4Address | str | bytes | int',
                          chaddr: 'str | bytes', chaddr_padding: 'Optional[bytes]') -> 'dict[str, Any]':
        """Make the fields a BOOTP and a DHCP message share, ``op`` through ``chaddr``.

        Args:
            op: Message op code.
            htype: Hardware address type.
            hlen: Hardware address length; that of ``chaddr`` if :obj:`None`.
            hops: Hops.
            xid: Transaction ID.
            secs: Seconds elapsed.
            flags: Flags, as their data model or a mapping of its keys, or the
                two octets as an integer.
            ciaddr: Client IP address.
            yiaddr: Your (client) IP address.
            siaddr: Next server IP address.
            giaddr: Relay agent IP address.
            chaddr: Client hardware address: a MAC address, or its octets.
            chaddr_padding: Octets of the field after the address; zeros filling
                the field if :obj:`None`.

        Returns:
            The schema's keyword arguments.

        Raises:
            ProtocolError: If a field does not fit its width, or the address and
                its padding are not 16 octets.

        """
        code = self._make_index(htype, Enum_Hardware, bits=8, name='hardware type')
        address = self._make_hardware_address(code, chaddr, name='client hardware address')
        if chaddr_padding is None:
            chaddr_padding = bytes(max(CHADDR_LENGTH - len(address), 0))
        if not isinstance(chaddr_padding, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid client hardware address padding: {chaddr_padding!r}')
        field = self._make_octets(address + bytes(chaddr_padding), size=CHADDR_LENGTH,
                                  name='client hardware address and its padding')
        if isinstance(flags, collections.abc.Mapping):
            bits = {
                'broadcast': self._make_uint(flags.get('broadcast', False), bits=1, name='broadcast flag'),
                'reserved': self._make_uint(flags.get('reserved', 0), bits=15, name='reserved flags'),
            }
        else:
            value = self._make_uint(flags, bits=16, name='flags')
            bits = {'broadcast': value >> 15, 'reserved': value & 0x7FFF}
        return {
            'op': int(self._make_index(op, Enum_Opcode, bits=8, name='op code')),
            'htype': int(code),
            'hlen': self._make_uint(len(address) if hlen is None else hlen, bits=8, name='hardware address length'),
            'hops': self._make_uint(hops, bits=8, name='hops'),
            'xid': self._make_uint(xid, bits=32, name='transaction ID'),
            'secs': self._make_uint(secs, bits=16, name='seconds'),
            'flags': bits,
            'ciaddr': parse_ip_address(ciaddr, f'{self.alias}: client IP address', version=4),
            'yiaddr': parse_ip_address(yiaddr, f'{self.alias}: your IP address', version=4),
            'siaddr': parse_ip_address(siaddr, f'{self.alias}: server IP address', version=4),
            'giaddr': parse_ip_address(giaddr, f'{self.alias}: relay agent IP address', version=4),
            'chaddr': field,
        }

    def _make_dhcp_field(self, value: 'bytes', *, size: 'int', name: 'str') -> 'bytes':
        """Make the ``sname`` or ``file`` field from its text.

        Args:
            value: The text, which NULs fill out to ``size`` octets.
            size: Octets in the field.
            name: Name of the field, for the error message.

        Returns:
            The field's octets.

        Raises:
            ProtocolError: If ``value`` is no octets, or longer than ``size``.

        """
        if not isinstance(value, (bytes, bytearray)) or len(value) > size:
            raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')
        return bytes(value).ljust(size, b'\x00')

    def _make_dhcp_options(self, options: 'Iterable[Mapping[str, Any]]', padding: 'bytes', *,
                           codes: 'Optional[frozenset[int]]' = None, size: 'Optional[int]' = None) -> 'bytes':
        """Make an option area.

        Args:
            options: Each option's ``code``, ``length`` and ``data``, as
                :class:`~pcapkit.protocols.application.dhcp.data.Option` holds
                them; ``data`` is raw octets, a mapping of the fields of the
                code's data model, or :obj:`None` for the Pad and End options,
                and ``length`` is computed when not given.
            padding: Octets after the End option, or with none, an option the
                area ends inside, as :meth:`_split_options` reads one.
            codes: The codes a mapping may build, or :obj:`None` for all.
            size: Octets the area fills, for an overloaded ``sname`` or
                ``file``, or :obj:`None` for the options field.

        Returns:
            The area's octets.

        Raises:
            ProtocolError: If an option is malformed; if its data is a mapping
                for a code ``codes`` leaves out, or that ``options`` holds more
                than once; if ``padding`` follows no End option yet is no option
                the area ends inside, which for ``size`` has to run to its end;
                or if the area does not fit ``size``.

        """
        options = tuple(options)
        counts = collections.Counter()  # type: collections.Counter[int]
        for option in options:
            if not isinstance(option, collections.abc.Mapping):
                raise ProtocolError(f'{self.alias}: invalid option: {option!r}')
            counts[int(self._make_index(option.get('code', Enum_Option.Pad), Enum_Option, bits=8,
                                        name='option code'))] += 1

        out = bytearray()
        ended = False
        for option in options:
            if ended:
                raise ProtocolError(f'{self.alias}: invalid options: an option follows the End option')
            code = self._make_index(option.get('code', Enum_Option.Pad), Enum_Option, bits=8, name='option code')
            value = option.get('data')
            if code in (Enum_Option.Pad, Enum_Option.End):
                if value is not None or option.get('length') is not None:
                    raise ProtocolError(f'{self.alias}: invalid {code!r} option: it carries no length or data')
                out.append(int(code))
                ended = code == Enum_Option.End
                continue
            if isinstance(value, (bytes, bytearray)):
                body = bytes(value)
            else:
                if counts[int(code)] > 1 or (codes is not None and int(code) not in codes):
                    raise ProtocolError(f'{self.alias}: no constructor for option {code!r} here; give its octets')
                meth = self._lookup_registry(self.__option__, code)
                if isinstance(meth, str):
                    maker = cast('OptionConstructor', getattr(self, f'_make_opt_{meth}', self._make_opt_unknown))
                else:
                    maker = meth[1]
                body = maker(code, {} if value is None else value)
            length = option.get('length')
            length = len(body) if length is None else length
            if len(body) > 255:
                raise ProtocolError(f'{self.alias}: invalid option {code!r}: {len(body)} octets of data '
                                    'exceed one option; split it into several (RFC 3396)')
            out += self._make_pack(int(code), size=1)
            out += self._make_pack(self._make_uint(length, bits=8, name='option length'), size=1)
            out += body

        if not isinstance(padding, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid padding: {padding!r}')
        cut = bool(padding) and not ended
        if cut:
            entries, _, overrun = self._split_options(padding)
            if entries or not overrun:
                raise ProtocolError(f'{self.alias}: invalid padding: no End option ends the options, '
                                    'and no option runs past them')
        out += padding
        if size is not None:
            if len(out) > size or (cut and len(out) < size):
                raise ProtocolError(f'{self.alias}: invalid overloaded field: {len(out)} octets, not {size}')
            out += bytes(size - len(out))
        return bytes(out)

    def _read_dhcp_addresses(self, code: 'Enum_Option', data: 'bytes') -> 'tuple[IPv4Address, ...]':
        """Read a run of IPv4 addresses.

        Args:
            code: Option code.
            data: The addresses' octets.

        Returns:
            The addresses, in order.

        Raises:
            ProtocolError: If ``data`` is not a multiple of four octets.

        """
        if len(data) % 4:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return tuple(ipaddress.IPv4Address(data[index:index + 4]) for index in range(0, len(data), 4))

    def _read_dhcp_text(self, code: 'Enum_Option', data: 'bytes') -> 'str':
        """Read ASCII text.

        Args:
            code: Option code.
            data: The text's octets.

        Returns:
            The text.

        Raises:
            ProtocolError: If ``data`` is not ASCII.

        """
        try:
            return data.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid text: {data!r}') from None

    def _read_dhcp_uint(self, code: 'Enum_Option', data: 'bytes', *, size: 'int') -> 'int':
        """Read an unsigned integer, no less than the least its option takes.

        Args:
            code: Option code.
            data: The integer's octets.
            size: Octets in the integer.

        Returns:
            The integer.

        Raises:
            ProtocolError: If ``data`` is not ``size`` octets, or the value is
                below the least :data:`~pcapkit.protocols.application.dhcp.const.MINIMUMS`
                gives the option.

        """
        if len(data) != size:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        value = int.from_bytes(data, 'big')
        if value < MINIMUMS.get(code, 0):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid value: {value}')
        return value

    def _read_dhcp_pairs(self, code: 'Enum_Option', data: 'bytes') -> 'tuple[IPv4Address, ...]':
        """Read a run of IPv4 address pairs.

        Args:
            code: Option code.
            data: The pairs' octets.

        Returns:
            The addresses, in order, two per pair.

        Raises:
            ProtocolError: If ``data`` is empty or not a multiple of eight octets.

        """
        if not data or len(data) % 8:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        return self._read_dhcp_addresses(code, data)

    def _read_hardware_address(self, htype: 'Enum_Hardware | int', data: 'bytes') -> 'Union[str, bytes]':
        """Read a hardware address.

        Args:
            htype: Hardware type.
            data: The address's octets.

        Returns:
            A MAC address for an Ethernet or IEEE 802 type of six octets, the
            octets otherwise.

        """
        if htype in (Enum_Hardware.Ethernet, Enum_Hardware.IEEE_802_Networks) and len(data) == 6:
            return self._read_mac_addr(data)
        return data

    def _read_dhcp_vectors(self, code: 'Enum_Option', data: 'bytes') -> 'tuple[bytes, ...]':
        """Read a run of vectors, each one octet of length and that many octets.

        Args:
            code: Option code.
            data: The vectors' octets.

        Returns:
            The vectors, in order.

        Raises:
            ProtocolError: If a vector runs past ``data``.

        """
        vectors = []  # type: list[bytes]
        pos = 0
        while pos < len(data):
            value, pos = self._read_vector(data, pos, size=1, what=f'[Option {code}] item')
            vectors.append(value)
        return tuple(vectors)

    def _read_fqdn_name(self, code: 'Enum_Option', data: 'bytes') -> 'str':
        """Read the domain name of the Client FQDN option, in canonical wire format.

        Args:
            code: Option code.
            data: The name's octets.

        Returns:
            The name in presentation form, ending in ``.`` where the root label
            ends it, i.e. where it is fully qualified.

        Raises:
            ProtocolError: If a label is longer than 63 octets or runs past
                ``data``, or octets follow the root label.

        """
        labels = []  # type: list[bytes]
        pos = 0
        while pos < len(data):
            size = data[pos]
            if not size:
                if pos + 1 != len(data):
                    raise ProtocolError(f'{self.alias}: [Option {code}] invalid name: octets after the root label')
                return name_to_text(labels)
            if size > 63:
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid name: label of {size} octets')
            labels.append(self._read_octets(data, pos + 1, size=size, what=f'[Option {code}] label'))
            pos += 1 + size
        return name_to_text(labels)[:-1]

    def _read_dhcp_vendors(self, code: 'Enum_Option', data: 'bytes') -> 'tuple[tuple[int, bytes], ...]':
        """Read the per-vendor data of a Vendor-Identifying option (:rfc:`3925`).

        Args:
            code: Option code.
            data: Option data.

        Returns:
            Each vendor's enterprise number and data.

        Raises:
            ProtocolError: If ``data`` is empty, or a vendor's data runs past it.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid length: {len(data)}')
        vendors = []  # type: list[tuple[int, bytes]]
        pos = 0
        while pos < len(data):
            enterprise = self._read_uint(data, pos, size=4, what=f'[Option {code}] enterprise number')
            value, pos = self._read_vector(data, pos + 4, size=1, what=f'[Option {code}] vendor data')
            vendors.append((enterprise, value))
        return tuple(vendors)

    def _make_dhcp_address(self, code: 'Enum_Option', value: 'Any') -> 'bytes':
        """Make an IPv4 address.

        Args:
            code: Option code.
            value: The address.

        Returns:
            Its four octets.

        """
        return parse_ip_address(value, f'{self.alias}: [Option {code}] address', version=4).packed

    def _make_dhcp_text(self, code: 'Enum_Option', value: 'Any') -> 'bytes':
        """Make ASCII text.

        Args:
            code: Option code.
            value: The text.

        Returns:
            Its octets.

        Raises:
            ProtocolError: If ``value`` is no ASCII :obj:`str`.

        """
        if isinstance(value, str):
            try:
                return value.encode('ascii')
            except UnicodeEncodeError:
                pass
        raise ProtocolError(f'{self.alias}: [Option {code}] invalid text: {value!r}')

    def _make_dhcp_uint(self, code: 'Enum_Option', value: 'Any', *, size: 'int') -> 'bytes':
        """Make an unsigned integer, no less than the least its option takes.

        Args:
            code: Option code.
            value: The integer.
            size: Octets in the integer.

        Returns:
            Its octets.

        Raises:
            ProtocolError: If ``value`` does not fit, or is below the least
                :data:`~pcapkit.protocols.application.dhcp.const.MINIMUMS` gives
                the option.

        """
        number = self._make_uint(value, bits=size * 8, name=f'[Option {code}] value')
        if number < MINIMUMS.get(code, 0):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid value: {number}')
        return self._make_pack(number, size=size)

    def _make_dhcp_pairs(self, code: 'Enum_Option', pairs: 'Iterable[Mapping[str, Any]]',
                         keys: 'tuple[str, str]') -> 'bytes':
        """Make a run of IPv4 address pairs.

        Args:
            code: Option code.
            pairs: The pairs, each a mapping of ``keys``.
            keys: The keys of a pair's two addresses.

        Returns:
            The pairs' octets.

        Raises:
            ProtocolError: If ``pairs`` is empty or a pair is no mapping.

        """
        pairs = tuple(pairs)
        if not pairs:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid pairs: none given')
        out = bytearray()
        for pair in pairs:
            if not isinstance(pair, collections.abc.Mapping):
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid pair: {pair!r}')
            for key in keys:
                out += self._make_dhcp_address(code, pair.get(key, '0.0.0.0'))  # nosec: B104
        return bytes(out)

    def _make_hardware_address(self, htype: 'Enum_Hardware | int', value: 'Any', *, name: 'str') -> 'bytes':
        """Make a hardware address.

        Args:
            htype: Hardware type.
            value: A MAC address for an Ethernet or IEEE 802 type, or the octets.
            name: Name of the address, for the error message.

        Returns:
            The address's octets.

        Raises:
            ProtocolError: If ``value`` is neither.

        """
        if isinstance(value, str):
            if htype in (Enum_Hardware.Ethernet, Enum_Hardware.IEEE_802_Networks):
                return self._make_mac_addr(value, size=None, name=name)
        elif isinstance(value, (bytes, bytearray)):
            return bytes(value)
        raise ProtocolError(f'{self.alias}: invalid {name}: {value!r}')

    def _make_dhcp_vectors(self, code: 'Enum_Option', vectors: 'Iterable[Any]') -> 'bytes':
        """Make a run of vectors, each one octet of length and that many octets.

        Args:
            code: Option code.
            vectors: The vectors.

        Returns:
            Their octets.

        Raises:
            ProtocolError: If a vector is no octets or longer than 255.

        """
        out = bytearray()
        for value in vectors:
            if not isinstance(value, (bytes, bytearray)) or len(value) > 255:
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid item: {value!r}')
            out += self._make_vector(bytes(value), size=1)
        return bytes(out)

    def _make_fqdn_name(self, code: 'Enum_Option', value: 'Any') -> 'bytes':
        """Make the domain name of the Client FQDN option, in canonical wire format.

        Args:
            code: Option code.
            value: The name in presentation form, ending in ``.`` where it is
                fully qualified.

        Returns:
            The name's octets, the root label ending it where it is fully
            qualified.

        Raises:
            ProtocolError: If ``value`` is no :obj:`str`, or is malformed.

        """
        if not isinstance(value, str):
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid name: {value!r}')
        labels = text_to_labels(value, alias=self.alias)
        octets = make_name(labels, alias=self.alias)
        if value.endswith('.') and not value.endswith('\\.'):
            return octets
        return octets[:-1]

    def _make_dhcp_vendors(self, code: 'Enum_Option', vendors: 'Iterable[Mapping[str, Any]]',
                           body: 'Callable[[Mapping[str, Any]], bytes]') -> 'bytes':
        """Make the per-vendor data of a Vendor-Identifying option (:rfc:`3925`).

        Args:
            code: Option code.
            vendors: Each vendor, a mapping of its ``enterprise`` number and its data.
            body: Makes a vendor's data from its mapping.

        Returns:
            Option data.

        Raises:
            ProtocolError: If ``vendors`` is empty, a vendor is no mapping, or its
                data is longer than 255 octets.

        """
        vendors = tuple(vendors)
        if not vendors:
            raise ProtocolError(f'{self.alias}: [Option {code}] invalid vendors: none given')
        out = bytearray()
        for vendor in vendors:
            if not isinstance(vendor, collections.abc.Mapping):
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid vendor: {vendor!r}')
            value = body(vendor)
            if len(value) > 255:
                raise ProtocolError(f'{self.alias}: [Option {code}] invalid vendor data: {len(value)} octets')
            out += self._make_pack(self._make_uint(vendor.get('enterprise', 0), bits=32,
                                                   name=f'[Option {code}] enterprise number'), size=4)
            out += self._make_vector(value, size=1)
        return bytes(out)
