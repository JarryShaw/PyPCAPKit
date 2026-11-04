Protocol Family
===============

.. module:: pcapkit.protocols

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

           subgraph checksum [Checksum Pseudo-Headers]
               IP_Pseudo
           end

           Raw & NoPayload
       end

       subgraph application [Application Layer]
           Application --> HTTP & FTP & FTP_DATA & NGAP & OSPF & RARP & SSL

           subgraph http [HTTP Family]
               HTTP --> h1["HTTP/1.*"] & h2["HTTP/2"]
           end

           subgraph ftp [FTP Family]
               FTP & FTP_DATA
           end

           subgraph rarp [RARP Family]
               RARP --> DRARP
           end

           subgraph ssl [SSL Family]
               SSL --> TLS & DTLS & SSLv2
               TLS --> SSLv3
           end
       end

       subgraph link [Link Layer]
           Link --> Ethernet & L2TP & LinuxSLL & Loopback & VLAN & ARP

           subgraph arp [ARP Family]
               ARP --> InARP
           end

           subgraph vlan [VLAN Family]
               VLAN --> C_Tag & S_Tag
           end

           subgraph l2tp [L2TP Family]
               L2TP --> L2TPv2
           end

           subgraph sll [LinuxSLL Family]
               LinuxSLL --> LinuxSLL1 & LinuxSLL2
           end
       end

       subgraph internet [Internet Layer]
           Internet --> IPX & IP & ICMP & IPsec & IPv6_Ext & IGMP

           subgraph ip [IP Family]
               IP --> IPv4 & IPv6
           end

           subgraph icmp [ICMP Family]
               ICMP --> ICMPv4 & ICMPv6
           end

           subgraph ipsec [IPsec Family]
               IPsec --> AH & ESP
           end

           subgraph ipv6ext [IPv6 Extension Header]
               IPv6_Ext --> IPv6-Frag & IPv6-Opts & IPv6-Route & HOPOPT & MH & HIP
           end

           subgraph igmp [IGMP Family]
               IGMP --> IGMPv1 & IGMPv2 & IGMPv3
           end
       end

       subgraph transport [Transport Layer]
           Transport --> TCP & UDP & SCTP & DCCP
       end

       B --> Link & Internet & Transport & Application

       B --> Header & Frame & PCAPNG & Raw & NoPayload & IP_Pseudo
       Raw --> FTP_DATA
       ARP --> RARP
       IPv6_Ext --> AH & ESP

       B --> C(Protocol)
       C --> D([user customisation ...])

       click A "protocol.html#pcapkit.protocols.protocol.ProtocolMeta"
       click B "protocol.html#pcapkit.protocols.protocol.ProtocolBase"
       click C "protocol.html#pcapkit.protocols.protocol.Protocol"
       click D "../../ext.html#customising-protocols"

       click Link "link/link.html#pcapkit.protocols.link.link.Link"
       click Ethernet "link/ethernet.html#pcapkit.protocols.link.ethernet.protocol.Ethernet"
       click L2TP "link/l2tp.html#pcapkit.protocols.link.l2tp.protocol.L2TP"
       click L2TPv2 "link/l2tpv2.html#pcapkit.protocols.link.l2tpv2.protocol.L2TPv2"
       click LinuxSLL "link/linux_sll.html#pcapkit.protocols.link.linux_sll.protocol.LinuxSLL"
       click LinuxSLL1 "link/linux_sll1.html#pcapkit.protocols.link.linux_sll1.protocol.LinuxSLL1"
       click LinuxSLL2 "link/linux_sll2.html#pcapkit.protocols.link.linux_sll2.protocol.LinuxSLL2"
       click Loopback "link/loopback.html#pcapkit.protocols.link.loopback.protocol.Loopback"
       click VLAN "link/vlan.html#pcapkit.protocols.link.vlan.protocol.VLAN"
       click C_Tag "link/c_tag.html#pcapkit.protocols.link.c_tag.protocol.C_Tag"
       click S_Tag "link/s_tag.html#pcapkit.protocols.link.s_tag.protocol.S_Tag"
       click ARP "link/arp.html#pcapkit.protocols.link.arp.protocol.ARP"
       click InARP "link/inarp.html#pcapkit.protocols.link.inarp.protocol.InARP"

       click Internet "internet/internet.html#pcapkit.protocols.internet.internet.Internet"
       click AH "internet/ah.html#pcapkit.protocols.internet.ah.protocol.AH"
       click ESP "internet/esp.html#pcapkit.protocols.internet.esp.protocol.ESP"
       click HIP "internet/hip.html#pcapkit.protocols.internet.hip.protocol.HIP"
       click IGMP "internet/igmp.html#pcapkit.protocols.internet.igmp.protocol.IGMP"
       click IGMPv1 "internet/igmpv1.html#pcapkit.protocols.internet.igmpv1.protocol.IGMPv1"
       click IGMPv2 "internet/igmpv2.html#pcapkit.protocols.internet.igmpv2.protocol.IGMPv2"
       click IGMPv3 "internet/igmpv3.html#pcapkit.protocols.internet.igmpv3.protocol.IGMPv3"
       click HOPOPT "internet/hopopt.html#pcapkit.protocols.internet.hopopt.protocol.HOPOPT"
       click ICMP "internet/icmp.html#pcapkit.protocols.internet.icmp.protocol.ICMP"
       click ICMPv4 "internet/icmpv4.html#pcapkit.protocols.internet.icmpv4.protocol.ICMPv4"
       click ICMPv6 "internet/icmpv6.html#pcapkit.protocols.internet.icmpv6.protocol.ICMPv6"
       click IP "internet/ip.html#pcapkit.protocols.internet.ip.protocol.IP"
       click IPsec "internet/ipsec.html#pcapkit.protocols.internet.ipsec.protocol.IPsec"
       click IPv4 "internet/ipv4.html#pcapkit.protocols.internet.ipv4.protocol.IPv4"
       click IPv6 "internet/ipv6.html#pcapkit.protocols.internet.ipv6.protocol.IPv6"
       click IPv6_Ext "internet/ipv6_ext.html#pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext"
       click IPv6-Frag "internet/ipv6_frag.html#pcapkit.protocols.internet.ipv6_frag.protocol.IPv6_Frag"
       click IPv6-Opts "internet/ipv6_opts.html#pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts"
       click IPv6-Route "internet/ipv6_route.html#pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route"
       click IP_Pseudo "misc/checksum.html#pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo"
       click IPX "internet/ipx.html#pcapkit.protocols.internet.ipx.protocol.IPX"
       click MH "internet/mh.html#pcapkit.protocols.internet.mh.protocol.MH"

       click Transport "transport/transport.html#pcapkit.protocols.transport.transport.Transport"
       click TCP "transport/tcp.html#pcapkit.protocols.transport.tcp.protocol.TCP"
       click UDP "transport/udp.html#pcapkit.protocols.transport.udp.protocol.UDP"
       click SCTP "transport/sctp.html#pcapkit.protocols.transport.sctp.protocol.SCTP"
       click DCCP "transport/dccp.html#pcapkit.protocols.transport.dccp.protocol.DCCP"

       click Application "application/application.html#pcapkit.protocols.application.application.Application"
       click HTTP "application/http.html#pcapkit.protocols.application.http.protocol.HTTP"
       click h1 "application/httpv1.html#pcapkit.protocols.application.httpv1.protocol.HTTPv1"
       click h2 "application/httpv2.html#pcapkit.protocols.application.httpv2.protocol.HTTPv2"
       click FTP "application/ftp.html#pcapkit.protocols.application.ftp.protocol.FTP"
       click FTP_DATA "application/ftp_data.html#pcapkit.protocols.application.ftp_data.protocol.FTP_DATA"
       click NGAP "application/ngap.html#pcapkit.protocols.application.ngap.protocol.NGAP"
       click OSPF "application/ospf.html#pcapkit.protocols.application.ospf.protocol.OSPF"
       click RARP "application/rarp.html#pcapkit.protocols.application.rarp.protocol.RARP"
       click DRARP "application/drarp.html#pcapkit.protocols.application.drarp.protocol.DRARP"
       click SSL "application/ssl.html#pcapkit.protocols.application.ssl.protocol.SSL"
       click SSLv2 "application/sslv2.html#pcapkit.protocols.application.sslv2.protocol.SSLv2"
       click TLS "application/tls.html#pcapkit.protocols.application.tls.protocol.TLS"
       click SSLv3 "application/sslv3.html#pcapkit.protocols.application.sslv3.protocol.SSLv3"
       click DTLS "application/dtls.html#pcapkit.protocols.application.dtls.protocol.DTLS"

       click Raw "misc/raw.html#pcapkit.protocols.misc.raw.protocol.Raw"
       click NoPayload "misc/no_payload.html#pcapkit.protocols.misc.no_payload.protocol.NoPayload"
       click PCAPNG "misc/pcapng.html#pcapkit.protocols.misc.pcapng.protocol.PCAPNG"
       click Header "misc/pcap.html#pcapkit.protocols.misc.pcap.header.protocol.Header"
       click Frame "misc/pcap.html#pcapkit.protocols.misc.pcap.frame.protocol.Frame"

Protocol Registry
-----------------

The registry of protocol classes by name is
:attr:`ProtocolBase.__registry__ <pcapkit.protocols.protocol.ProtocolBase.__registry__>`.
:attr:`ProtocolMeta.registry <pcapkit.protocols.protocol.ProtocolMeta.registry>` reads it
as ``AnyProtocol.registry``, a read-only view importing nothing, and
:meth:`ProtocolBase.get_protocol <pcapkit.protocols.protocol.ProtocolBase.get_protocol>`
looks a name up in it and returns the class.

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.__proto__``, with no alias: read
   :attr:`ProtocolBase.__registry__ <pcapkit.protocols.protocol.ProtocolBase.__registry__>`
   through :meth:`ProtocolBase.get_protocol
   <pcapkit.protocols.protocol.ProtocolBase.get_protocol>` instead (:issue:`2763`).

.. seealso::

   Please refer to :func:`pcapkit.foundation.registry.protocols.protocol.register_protocol`
   for more information.

Header Schema
-------------

.. module:: pcapkit.protocols.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.schema``, with no alias: the module moved here. The
   ``pcapkit.protocols.schema.application``, ``pcapkit.protocols.schema.internet``,
   ``pcapkit.protocols.schema.link``, ``pcapkit.protocols.schema.misc``,
   ``pcapkit.protocols.schema.misc.checksum``, ``pcapkit.protocols.schema.misc.pcap``
   and ``pcapkit.protocols.schema.transport`` subpackages, and the header schemas they
   and ``pcapkit.protocols.schema`` collected, with no alias: each protocol's are in the
   ``schema`` module of its own package, such as
   :mod:`pcapkit.protocols.link.vlan.schema` (:issue:`2534`).

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.schema.keep_short_read`` and
   ``pcapkit.protocols.schema.schema.replay_short_read``, now
   :func:`pcapkit.corekit.schema.shortread.keep_short_read` and
   :func:`pcapkit.corekit.schema.shortread.replay_short_read` (:issue:`2674`).

.. autoclass:: pcapkit.protocols.schema.Schema
   :no-members:
   :show-inheritance:

   .. autoattribute:: __fields__
      :no-value:

   .. autoattribute:: __payload__
   .. autoattribute:: __additional__
      :no-value:

   .. autoattribute:: __excluded__
      :no-value:

   .. automethod:: from_dict
   .. automethod:: to_dict
   .. automethod:: to_bytes
   .. automethod:: get_payload
   .. automethod:: pack
   .. automethod:: pre_pack
   .. automethod:: unpack
   .. automethod:: pre_unpack
   .. automethod:: post_process
   .. automethod:: __init_subclass__
   .. automethod:: __new__
   .. automethod:: _cut_short_read

.. autoclass:: pcapkit.protocols.schema.EnumSchema
   :no-members:
   :show-inheritance:

   .. autoattribute:: __default__
      :no-value:
   .. autoattribute:: __enum__
      :no-value:

   .. autoproperty:: registry

   .. automethod:: register

   .. automethod:: __init_subclass__

.. autodecorator:: pcapkit.protocols.schema.schema_final

Internal Definitions
~~~~~~~~~~~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.SchemaMeta
   :no-members:
   :show-inheritance:

   .. automethod:: __prepare__

.. autoclass:: pcapkit.protocols.schema.EnumMeta
   :no-members:
   :show-inheritance:

   .. autoproperty:: registry

.. autoclass:: pcapkit.protocols.schema._EnumRegistry
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
   :type: typing.Type[pcapkit.protocols.schema.Schema]

Data Model
----------

.. module:: pcapkit.protocols.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.data`` and ``pcapkit.protocols.data.protocol``, with no
   alias: the modules merged here. The ``pcapkit.protocols.data.application``,
   ``pcapkit.protocols.data.internet``, ``pcapkit.protocols.data.link``,
   ``pcapkit.protocols.data.misc``, ``pcapkit.protocols.data.misc.checksum``,
   ``pcapkit.protocols.data.misc.pcap`` and ``pcapkit.protocols.data.transport``
   subpackages, and the data models they and ``pcapkit.protocols.data`` collected, with
   no alias: each protocol's are in the ``data`` module of its own package, such as
   :mod:`pcapkit.protocols.link.vlan.data` (:issue:`2534`).

.. autoclass:: pcapkit.protocols.data.Data
   :members:
   :show-inheritance:

   .. autoattribute:: __included__
      :no-value:

   .. autoattribute:: __excluded__
      :no-value:

      .. seealso::

         Please refer to :func:`Protocol._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
         for more information with the inserted names to be excluded.
