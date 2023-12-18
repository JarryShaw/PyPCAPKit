Protocol Family
===============

.. module:: pcapkit.protocols
.. module:: pcapkit.protocols.data
.. module:: pcapkit.protocols.schema

:mod:`pcapkit.protocols` is collection of all protocol families,
with detailed implementation and methods.

.. toctree::
   :maxdepth: 2

   protocol
   link/index
   internet/index
   transport/index
   application/index
   misc/index

All protocol classes are implemented as :class:`~pcapkit.protocols.protocol.Protocol`
subclasses, which are responsible for processing extracted binary packet data
and/or construct protocol packet from given information. Below is a brief
diagram of the class hierarchy of :mod:`pcapkit.protocols`:

.. mermaid::

   flowchart LR
       A{{ProtocolMeta}} -.->|metaclass| B(ProtocolBase)

       subgraph link [Link Layer]
           Link --> Ethernet & L2TP & OSPF & VLAN & ARP

           subgraph arp [ARP Family]
               ARP --> InARP & RARP

               subgraph rarp [RARP Family]
                   RARP --> DRARP
               end
           end
       end

       subgraph internet [Internet Layer]
           Internet --> HIP & IPX & IP & ipv6ext

           subgraph ip [IP Family]
               IP --> IPv4 & IPv6 & IPsec

               subgraph ipsec [IPsec Family]
                   IPsec --> AH
               end
           end

           subgraph ipv6ext [IPv6 Extension Header]
               IPv6-Frag & IPv6-Opts & IPv6-Route & HOPOPT & MH
           end
       end

       subgraph transport [Transport Layer]
           Transport --> TCP & UDP
       end

       subgraph application [Application Layer]
           Application --> HTTP & FTP

           subgraph http [HTTP Family]
               HTTP --> h1["HTTP/1.*"] & h2["HTTP/2"]
           end

           subgraph ftp [FTP Family]
               FTP & FTP_DATA
           end
       end

       subgraph misc [Miscellaneous]
           subgraph pcap [PCAP Format]
               Header & Frame
           end

           subgraph pcapng [PCAP-NG Format]
               PCAPNG
           end

           Raw & NoPayload
       end

       B --> Link & Internet & Transport & Application

       B --> Header & Frame & PCAPNG & Raw & NoPayload
       Raw --> FTP_DATA

       B --> C(Protocol)
       C --> D([user customisation ...])

       click A "/pcapkit/protocols/protocol.html#pcapkit.protocols.protocol.ProtocolMeta"
       click B "/pcapkit/protocols/protocol.html#pcapkit.protocols.protocol.ProtocolBase"
       click C "/pcapkit/protocols/protocol.html#pcapkit.protocols.protocol.Protocol"
       click D "/ext.html#what-s-in-for-protocols"

       click Link "/pcapkit/protocols/link/link.html#pcapkit.protocols.link.Link"
       click Ethernet "/pcapkit/protocols/link/ethernet.html#pcapkit.protocols.link.ethernet.Ethernet"
       click L2TP "/pcapkit/protocols/link/l2tp.html#pcapkit.protocols.link.l2tp.L2TP"
       click OSPF "/pcapkit/protocols/link/ospf.html#pcapkit.protocols.link.ospf.OSPF"
       click VLAN "/pcapkit/protocols/link/vlan.html#pcapkit.protocols.link.vlan.VLAN"
       click ARP "/pcapkit/protocols/link/arp.html#pcapkit.protocols.link.arp.ARP"
       click InARP "/pcapkit/protocols/link/arp.html#pcapkit.protocols.link.arp.InARP"
       click RARP "/pcapkit/protocols/link/rarp.html#pcapkit.protocols.link.rarp.RARP"
       click DRARP "/pcapkit/protocols/link/rarp.html#pcapkit.protocols.link.rarp.DRARP"

       click Internet "/pcapkit/protocols/internet/internet.html#pcapkit.protocols.internet.Internet"
       click AH "/pcapkit/protocols/internet/ah.html#pcapkit.protocols.internet.ah.AH"
       click HIP "/pcapkit/protocols/internet/hip.html#pcapkit.protocols.internet.hip.HIP"
       click HOPOPT "/pcapkit/protocols/internet/hopopt.html#pcapkit.protocols.internet.hopopt.HOPOPT"
       click IP "/pcapkit/protocols/internet/ip.html#pcapkit.protocols.internet.ip.IP"
       click IPsec "/pcapkit/protocols/internet/ipsec.html#pcapkit.protocols.internet.ipsec.IPsec"
       click IPv4 "/pcapkit/protocols/internet/ipv4.html#pcapkit.protocols.internet.ip.ipv4.IPv4"
       click IPv6 "/pcapkit/protocols/internet/ipv6.html#pcapkit.protocols.internet.ip.ipv6.IPv6"
       click IPv6-Frag "/pcapkit/protocols/internet/ipv6_frag.html#pcapkit.protocols.internet.ipv6_frag.IPv6_Frag"
       click IPv6-Opts "/pcapkit/protocols/internet/ipv6_opts.html#pcapkit.protocols.internet.ipv6_opts.IPv6_Opts"
       click IPv6-Route "/pcapkit/protocols/internet/ipv6_route.html#pcapkit.protocols.internet.ipv6_route.IPv6_Route"
       click IPX "/pcapkit/protocols/internet/ipx.html#pcapkit.protocols.internet.ipx.IPX"
       click MH "/pcapkit/protocols/internet/mh.html#pcapkit.protocols.internet.mh.MH"

       click Transport "/pcapkit/protocols/transport/transport.html#pcapkit.protocols.transport.Transport"
       click TCP "/pcapkit/protocols/transport/tcp.html#pcapkit.protocols.internet.tcp.TCP"
       click UDP "/pcapkit/protocols/transport/udp.html#pcapkit.protocols.internet.udp.UDP"

       click Application "/pcapkit/protocols/application/application.html#pcapkit.protocols.application.Application"
       click HTTP "/pcapkit/protocols/application/http.html#pcapkit.protocols.application.http.HTTP"
       click h1 "/pcapkit/protocols/application/httpv1.html#pcapkit.protocols.application.httpv1.HTTP"
       click h2 "/pcapkit/protocols/application/httpv2.html#pcapkit.protocols.application.httpv2.HTTP"
       click FTP "/pcapkit/protocols/application/ftp.html#pcapkit.protocols.application.ftp.FTP"
       click FTP_DATA "/pcapkit/protocols/application/ftp.html#pcapkit.protocols.application.ftp.FTP_DATA"

       click Raw "/pcapkit/protocols/misc/raw.html#pcapkit.protocols.misc.raw.Raw"
       click NoPayload "/pcapkit/protocols/misc/null.html#pcapkit.protocols.misc.null.NoPayload"
       click PCAPNG "/pcapkit/protocols/misc/pcapng.html#pcapkit.protocols.misc.pcapng.PCAPNG"
       click Header "/pcapkit/protocols/misc/pcap.html#pcapkit.protocols.misc.pcap.header.Header"
       click Frame "/pcapkit/protocols/misc/pcap.html#pcapkit.protocols.misc.pcap.frame.Frame"

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

.. autoclass:: pcapkit.protocols.schema.schema.EnumMeta
   :no-members:
   :show-inheritance:

Type Variables
~~~~~~~~~~~~~~

.. data:: pcapkit.protocols.schema.schema._VT
   :type: typing.Any

.. data:: pcapkit.protocols.schema.schema._ET
   :type: enum.Enum

.. data:: pcapkit.protocols.schema.schema._ST
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
