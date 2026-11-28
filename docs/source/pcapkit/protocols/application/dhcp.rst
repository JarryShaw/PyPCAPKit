DHCP - Dynamic Host Configuration Protocol
================================================

.. module:: pcapkit.protocols.application.dhcp
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

.. autoclass:: pcapkit.protocols.application.dhcp.protocol.DHCP
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __option__
      :no-value:

   .. rubric:: Properties

   .. autoproperty:: length
   .. autoproperty:: alias
   .. autoproperty:: info_name

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: from_data
   .. automethod:: register_option

   .. rubric:: Data Models

   .. automethod:: __index__
   .. automethod:: __length_hint__
   .. automethod:: __new__

   .. rubric:: Utilities

   .. automethod:: _read_opt_unknown
   .. automethod:: _read_opt_address
   .. automethod:: _read_opt_time_offset
   .. automethod:: _read_opt_addresses
   .. automethod:: _read_opt_text
   .. automethod:: _read_opt_uint16
   .. automethod:: _read_opt_boolean
   .. automethod:: _read_opt_policy_filter
   .. automethod:: _read_opt_uint8
   .. automethod:: _read_opt_uint32
   .. automethod:: _read_opt_mtu_plateau
   .. automethod:: _read_opt_static_route
   .. automethod:: _read_opt_node_type
   .. automethod:: _read_opt_overload
   .. automethod:: _read_opt_message_type
   .. automethod:: _read_opt_parameter_list
   .. automethod:: _read_opt_client_id
   .. automethod:: _read_opt_home_agent
   .. automethod:: _read_opt_user_class
   .. automethod:: _read_opt_client_fqdn
   .. automethod:: _read_opt_relay_agent
   .. automethod:: _read_opt_client_system
   .. automethod:: _read_opt_client_ndi
   .. automethod:: _read_opt_machine_id
   .. automethod:: _read_opt_domain_search
   .. automethod:: _read_opt_classless_route
   .. automethod:: _read_opt_vendor_class
   .. automethod:: _read_opt_vendor_specific
   .. automethod:: _make_opt_unknown
   .. automethod:: _make_opt_address
   .. automethod:: _make_opt_time_offset
   .. automethod:: _make_opt_addresses
   .. automethod:: _make_opt_text
   .. automethod:: _make_opt_uint16
   .. automethod:: _make_opt_boolean
   .. automethod:: _make_opt_policy_filter
   .. automethod:: _make_opt_uint8
   .. automethod:: _make_opt_uint32
   .. automethod:: _make_opt_mtu_plateau
   .. automethod:: _make_opt_static_route
   .. automethod:: _make_opt_node_type
   .. automethod:: _make_opt_overload
   .. automethod:: _make_opt_message_type
   .. automethod:: _make_opt_parameter_list
   .. automethod:: _make_opt_client_id
   .. automethod:: _make_opt_home_agent
   .. automethod:: _make_opt_user_class
   .. automethod:: _make_opt_client_fqdn
   .. automethod:: _make_opt_relay_agent
   .. automethod:: _make_opt_client_system
   .. automethod:: _make_opt_client_ndi
   .. automethod:: _make_opt_machine_id
   .. automethod:: _make_opt_domain_search
   .. automethod:: _make_opt_classless_route
   .. automethod:: _make_opt_vendor_class
   .. automethod:: _make_opt_vendor_specific
   .. automethod:: _construction_member
   .. automethod:: _classify
   .. automethod:: _split_options
   .. automethod:: _overloaded_fields
   .. automethod:: _read_dhcp_header
   .. automethod:: _read_dhcp_options
   .. automethod:: _count_options
   .. automethod:: _make_dhcp_header
   .. automethod:: _make_dhcp_field
   .. automethod:: _make_dhcp_options
   .. automethod:: _read_dhcp_addresses
   .. automethod:: _read_dhcp_text
   .. automethod:: _read_dhcp_uint
   .. automethod:: _read_dhcp_pairs
   .. automethod:: _read_hardware_address
   .. automethod:: _read_dhcp_vectors
   .. automethod:: _read_fqdn_name
   .. automethod:: _read_dhcp_vendors
   .. automethod:: _make_dhcp_address
   .. automethod:: _make_dhcp_text
   .. automethod:: _make_dhcp_uint
   .. automethod:: _make_dhcp_pairs
   .. automethod:: _make_hardware_address
   .. automethod:: _make_dhcp_vectors
   .. automethod:: _make_fqdn_name
   .. automethod:: _make_dhcp_vendors

Header Schemas
--------------

.. module:: pcapkit.protocols.application.dhcp.schema

.. autoclass:: pcapkit.protocols.application.dhcp.schema.DHCP
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.application.dhcp.schema.Flags
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.application.dhcp.schema.dhcp_area_length

Data Models
-----------

.. module:: pcapkit.protocols.application.dhcp.data

.. autoclass:: pcapkit.protocols.application.dhcp.data.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Option
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.OverloadedField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.DomainName
   :members:
   :show-inheritance:

Option Data
~~~~~~~~~~~

.. autoclass:: pcapkit.protocols.application.dhcp.data.OptionData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Address
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Addresses
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Number
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Boolean
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Text
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Sizes
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.AddressMask
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.PolicyFilter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Route
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.StaticRoutes
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.NodeType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.Overload
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.MessageType
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.ParameterList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.ClientIdentifier
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.UserClass
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.FQDNFlags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.ClientFQDN
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.RelayAgentSubOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.RelayAgentInformation
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.ArchitectureTypes
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.ClientNDI
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.MachineIdentifier
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.DomainSearch
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.ClasslessRoute
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.ClasslessStaticRoutes
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.VendorClassEntry
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.VendorClass
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.VendorOption
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.VendorOptions
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dhcp.data.VendorSpecific
   :members:
   :show-inheritance:

Constants
---------

.. module:: pcapkit.protocols.application.dhcp.const

.. autodata:: pcapkit.protocols.application.dhcp.const.HEADER_LENGTH

.. autodata:: pcapkit.protocols.application.dhcp.const.CHADDR_LENGTH

.. autodata:: pcapkit.protocols.application.dhcp.const.SNAME_LENGTH

.. autodata:: pcapkit.protocols.application.dhcp.const.FILE_LENGTH

.. autodata:: pcapkit.protocols.application.dhcp.const.MAGIC_COOKIE

.. autodata:: pcapkit.protocols.application.dhcp.const.MINIMUMS
