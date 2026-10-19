Protocol Family
===============

.. module:: pcapkit.protocols
.. module:: pcapkit.protocols.data
.. module:: pcapkit.protocols.schema

:mod:`pcapkit.protocols` is the collection of all protocol families.

.. toctree::
   :maxdepth: 2

   protocol
   link/index
   internet/index
   transport/index
   application/index
   misc/index

All protocol classes are :class:`~pcapkit.protocols.protocol.ProtocolBase`
subclasses, which parse extracted binary packet data and/or construct a packet
from given information. The class hierarchy of :mod:`pcapkit.protocols`:

.. mermaid::

   flowchart LR
       A{{ProtocolMeta}} -.->|metaclass| B(ProtocolBase)

       %% The layers are declared in this order so that ARP --> RARP and
       %% Raw --> FTP_DATA stay short instead of crossing the other layers.

       subgraph misc [Miscellaneous]
           subgraph pcap [PCAP Format]
               Header & Frame
           end

           subgraph pcapng [PCAP-NG Format]
               PCAPNG
           end

           Raw & NoPayload
       end

       subgraph application [Application Layer]
           Application --> HTTP & FTP & NGAP & OSPF & RARP

           subgraph http [HTTP Family]
               HTTP --> h1["HTTP/1.*"] & h2["HTTP/2"]
           end

           subgraph ftp [FTP Family]
               FTP & FTP_DATA
           end

           subgraph rarp [RARP Family]
               RARP --> DRARP
           end
       end

       subgraph link [Link Layer]
           Link --> Ethernet & L2TP & Loopback & VLAN & ARP

           subgraph arp [ARP Family]
               ARP --> InARP
           end

           subgraph vlan [VLAN Family]
               VLAN --> C_Tag & S_Tag
           end

           subgraph l2tp [L2TP Family]
               L2TP --> L2TPv2
           end
       end

       subgraph internet [Internet Layer]
           Internet --> IPX & IP & IPsec & IPv6_Ext

           subgraph ip [IP Family]
               IP --> IPv4 & IPv6
           end

           subgraph ipsec [IPsec Family]
               IPsec --> AH & ESP
           end

           subgraph ipv6ext [IPv6 Extension Header]
               IPv6_Ext --> IPv6-Frag & IPv6-Opts & IPv6-Route & HOPOPT & MH & HIP
           end
       end

       subgraph transport [Transport Layer]
           Transport --> TCP & UDP & SCTP
       end

       B --> Link & Internet & Transport & Application

       B --> Header & Frame & PCAPNG & Raw & NoPayload
       Raw --> FTP_DATA
       ARP --> RARP
       IPv6_Ext --> AH & ESP

       B --> C(Protocol)
       C --> D([user customisation ...])

       click A "protocol.html#pcapkit.protocols.protocol.ProtocolMeta"
       click B "protocol.html#pcapkit.protocols.protocol.ProtocolBase"
       click C "protocol.html#pcapkit.protocols.protocol.Protocol"
       click D "../../ext.html#what-s-in-for-protocols"

       click Link "link/link.html#pcapkit.protocols.link.link.Link"
       click Ethernet "link/ethernet.html#pcapkit.protocols.link.ethernet.Ethernet"
       click L2TP "link/l2tp.html#pcapkit.protocols.link.l2tp.L2TP"
       click L2TPv2 "link/l2tpv2.html#pcapkit.protocols.link.l2tpv2.L2TPv2"
       click Loopback "link/loopback.html#pcapkit.protocols.link.loopback.Loopback"
       click VLAN "link/vlan.html#pcapkit.protocols.link.vlan.VLAN"
       click C_Tag "link/c_tag.html#pcapkit.protocols.link.c_tag.C_Tag"
       click S_Tag "link/s_tag.html#pcapkit.protocols.link.s_tag.S_Tag"
       click ARP "link/arp.html#pcapkit.protocols.link.arp.ARP"
       click InARP "link/arp.html#pcapkit.protocols.link.arp.InARP"

       click Internet "internet/internet.html#pcapkit.protocols.internet.internet.Internet"
       click AH "internet/ah.html#pcapkit.protocols.internet.ah.AH"
       click ESP "internet/esp.html#pcapkit.protocols.internet.esp.ESP"
       click HIP "internet/hip.html#pcapkit.protocols.internet.hip.HIP"
       click HOPOPT "internet/hopopt.html#pcapkit.protocols.internet.hopopt.HOPOPT"
       click IP "internet/ip.html#pcapkit.protocols.internet.ip.IP"
       click IPsec "internet/ipsec.html#pcapkit.protocols.internet.ipsec.IPsec"
       click IPv4 "internet/ipv4.html#pcapkit.protocols.internet.ipv4.IPv4"
       click IPv6 "internet/ipv6.html#pcapkit.protocols.internet.ipv6.IPv6"
       click IPv6_Ext "internet/ipv6_ext.html#pcapkit.protocols.internet.ipv6_ext.IPv6_Ext"
       click IPv6-Frag "internet/ipv6_frag.html#pcapkit.protocols.internet.ipv6_frag.IPv6_Frag"
       click IPv6-Opts "internet/ipv6_opts.html#pcapkit.protocols.internet.ipv6_opts.IPv6_Opts"
       click IPv6-Route "internet/ipv6_route.html#pcapkit.protocols.internet.ipv6_route.IPv6_Route"
       click IPX "internet/ipx.html#pcapkit.protocols.internet.ipx.IPX"
       click MH "internet/mh.html#pcapkit.protocols.internet.mh.MH"

       click Transport "transport/transport.html#pcapkit.protocols.transport.transport.Transport"
       click TCP "transport/tcp.html#pcapkit.protocols.transport.tcp.TCP"
       click UDP "transport/udp.html#pcapkit.protocols.transport.udp.UDP"
       click SCTP "transport/sctp.html#pcapkit.protocols.transport.sctp.SCTP"

       click Application "application/application.html#pcapkit.protocols.application.application.Application"
       click HTTP "application/http.html#pcapkit.protocols.application.http.HTTP"
       click h1 "application/httpv1.html#pcapkit.protocols.application.httpv1.HTTP"
       click h2 "application/httpv2.html#pcapkit.protocols.application.httpv2.HTTP"
       click FTP "application/ftp.html#pcapkit.protocols.application.ftp.FTP"
       click FTP_DATA "application/ftp.html#pcapkit.protocols.application.ftp.FTP_DATA"
       click NGAP "application/ngap.html#pcapkit.protocols.application.ngap.NGAP"
       click OSPF "application/ospf.html#pcapkit.protocols.application.ospf.OSPF"
       click RARP "application/rarp.html#pcapkit.protocols.application.rarp.RARP"
       click DRARP "application/rarp.html#pcapkit.protocols.application.rarp.DRARP"

       click Raw "misc/raw.html#pcapkit.protocols.misc.raw.Raw"
       click NoPayload "misc/null.html#pcapkit.protocols.misc.null.NoPayload"
       click PCAPNG "misc/pcapng.html#pcapkit.protocols.misc.pcapng.PCAPNG"
       click Header "misc/pcap.html#pcapkit.protocols.misc.pcap.header.Header"
       click Frame "misc/pcap.html#pcapkit.protocols.misc.pcap.frame.Frame"

Protocol Registry
-----------------

.. autodata:: pcapkit.protocols.__proto__
   :no-value:

   .. seealso::

      Please refer to :func:`pcapkit.foundation.registry.protocols.register_protocol`
      for more information.

Header Schema
-------------

.. module:: pcapkit.protocols.schema.schema

.. autoclass:: pcapkit.protocols.schema.schema.Schema
   :no-members:
   :show-inheritance:

   .. autoattribute:: __payload__
   .. autoattribute:: __additional__
      :no-value:
   .. autoattribute:: __excluded__
      :no-value:

   .. automethod:: __init_subclass__
   .. automethod:: __new__

   .. automethod:: pack
   .. automethod:: pre_pack

   .. automethod:: unpack
   .. automethod:: pre_unpack

   .. automethod:: post_process
   .. automethod:: get_payload

   .. automethod:: from_dict
   .. automethod:: to_dict
   .. automethod:: to_bytes

   .. autoattribute:: __fields__
      :no-value:

.. autoclass:: pcapkit.protocols.schema.schema.EnumSchema
   :no-members:
   :show-inheritance:

   .. autoattribute:: __default__
      :no-value:
   .. autoattribute:: __enum__
      :no-value:

   .. autoproperty:: registry

   .. automethod:: register

   .. automethod:: __init_subclass__

.. autodecorator:: pcapkit.protocols.schema.schema.schema_final

Internal Definitions
~~~~~~~~~~~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.schema.SchemaMeta
   :no-members:
   :show-inheritance:

   .. automethod:: __prepare__

.. autoclass:: pcapkit.protocols.schema.schema.EnumMeta
   :no-members:
   :show-inheritance:

   .. autoproperty:: registry

.. autoclass:: pcapkit.protocols.schema.schema._EnumRegistry
   :no-members:
   :show-inheritance:

   .. automethod:: __missing__

Type Variables
~~~~~~~~~~~~~~

.. data:: _VT
   :type: typing.Any

.. data:: _ET
   :type: enum.Enum

.. data:: _ST
   :type: typing.Type[pcapkit.protocols.schema.schema.Schema]

Data Model
----------

.. module:: pcapkit.protocols.data.data

.. autoclass:: pcapkit.protocols.data.data.Data
   :members:
   :show-inheritance:

   .. autoattribute:: __excluded__
      :no-value:

      .. seealso::

         Please refer to :func:`Protocol._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
         for more information with the inserted names to be excluded.
