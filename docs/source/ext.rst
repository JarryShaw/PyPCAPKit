Customisation & Extensions
==========================

New protocols, layers, fields and file formats can all be added to
:mod:`pcapkit` from outside the library.

---------------------
Customising Protocols
---------------------

:class:`~pcapkit.protocols.protocol.Protocol` is the user-facing abstract base
class of a protocol, which parses and constructs its packets. The built-in
protocol classes and layer base classes derive from its internal base,
:class:`~pcapkit.protocols.protocol.ProtocolBase`, rather than from
:class:`~pcapkit.protocols.protocol.Protocol` itself.

The protocol classes :mod:`pcapkit` ships:

+------------------------------------------------------------------+----------------+-----------------------+--------------------------------------------------------------------+
| Protocol Type                                                    | Protocol Class                                                                                              |
+==================================================================+================+==============+=============================================================================+
|                                                                  |                | :class:`pcapkit.protocols.link.arp.protocol.ARP`                                           |
+                                                                  + ARP Family     +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.link.inarp.protocol.InARP`                                       |
+ Link Layer                                                       +----------------+-----------------------+--------------------------------------------------------------------+
| (:class:`~pcapkit.protocols.link.link.Link` subclasses)          | :class:`pcapkit.protocols.link.ethernet.protocol.Ethernet`                                                  |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.link.l2tp.protocol.L2TP`                                         |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  | L2TP Family    | :class:`pcapkit.protocols.link.l2tpv2.protocol.L2TPv2`                                     |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.link.linux_sll.protocol.LinuxSLL`                                |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  | LINUX_SLL      | :class:`pcapkit.protocols.link.linux_sll1.protocol.LinuxSLL1`                              |
+                                                                  + Family         +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.link.linux_sll2.protocol.LinuxSLL2`                              |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.link.loopback.protocol.Loopback`                                                  |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.link.vlan.protocol.VLAN`                                         |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  | VLAN Family    | :class:`pcapkit.protocols.link.c_tag.protocol.C_Tag`                                       |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.link.s_tag.protocol.S_Tag`                                       |
+------------------------------------------------------------------+----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.ip.protocol.IP`                                         |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.ipv4.protocol.IPv4`                                     |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.ipv6.protocol.IPv6`                                     |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext`     |
+                                                                  +                +                       +--------------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ipv6_frag.protocol.IPv6_Frag`   |
+                                                                  +                +                       +--------------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts`   |
+                                                                  + IP Family      +                       +--------------------------------------------------------------------+
| Internet Layer                                                   |                | IPv6 Extension Header | :class:`pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route` |
+ (:class:`~pcapkit.protocols.internet.internet.Internet`          +                +                       +--------------------------------------------------------------------+
| subclasses)                                                      |                |                       | :class:`pcapkit.protocols.internet.hopopt.protocol.HOPOPT`         |
+                                                                  +                +                       +--------------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.mh.protocol.MH`                 |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ipsec.protocol.IPsec`           |
+                                                                  +                + IPsec Family          +--------------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.ah.protocol.AH`                 |
+                                                                  +                +                       +--------------------------------------------------------------------+
|                                                                  |                |                       | :class:`pcapkit.protocols.internet.esp.protocol.ESP`               |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.icmp.protocol.ICMP`                                     |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  | ICMP Family    | :class:`pcapkit.protocols.internet.icmpv4.protocol.ICMPv4`                                 |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`                                 |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.internet.ipx.protocol.IPX`                                                        |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.internet.hip.protocol.HIP`                                                        |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.igmp.protocol.IGMP`                                     |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.igmpv1.protocol.IGMPv1`                                 |
+                                                                  + IGMP Family    +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.igmpv2.protocol.IGMPv2`                                 |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.internet.igmpv3.protocol.IGMPv3`                                 |
+------------------------------------------------------------------+----------------+-----------------------+--------------------------------------------------------------------+
| Transport Layer                                                  | :class:`pcapkit.protocols.transport.tcp.protocol.TCP`                                                       |
+ (:class:`~pcapkit.protocols.transport.transport.Transport`       +----------------+-----------------------+--------------------------------------------------------------------+
| subclasses)                                                      | :class:`pcapkit.protocols.transport.udp.protocol.UDP`                                                       |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.transport.sctp.protocol.SCTP`                                                     |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.transport.dccp.protocol.DCCP`                                                     |
+------------------------------------------------------------------+----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.ftp.protocol.FTP`                                    |
+                                                                  + FTP Family     +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.ftp_data.protocol.FTP_DATA`                          |
+ Application Layer                                                +----------------+-----------------------+--------------------------------------------------------------------+
| (:class:`~pcapkit.protocols.application.application.Application` |                | :class:`pcapkit.protocols.application.http.protocol.HTTP`                                  |
+ subclasses)                                                      +                +-----------------------+--------------------------------------------------------------------+
|                                                                  | HTTP Family    | :class:`pcapkit.protocols.application.httpv1.protocol.HTTPv1`                              |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.httpv2.protocol.HTTPv2`                              |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.application.ngap.protocol.NGAP`                                                   |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.application.ospf.protocol.OSPF`                                                   |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.rarp.protocol.RARP`                                  |
+                                                                  + RARP Family    +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.drarp.protocol.DRARP`                                |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.ssl.protocol.SSL`                                    |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.tls.protocol.TLS`                                    |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  | SSL Family     | :class:`pcapkit.protocols.application.sslv3.protocol.SSLv3`                                |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.dtls.protocol.DTLS`                                  |
+                                                                  +                +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.application.sslv2.protocol.SSLv2`                                |
+------------------------------------------------------------------+----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.misc.pcap.header.protocol.Header`                                |
+                                                                  + PCAP Format    +-----------------------+--------------------------------------------------------------------+
|                                                                  |                | :class:`pcapkit.protocols.misc.pcap.frame.protocol.Frame`                                  |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
| Miscellaneous Protocols                                          | PCAP-NG Format | :class:`pcapkit.protocols.misc.pcapng.protocol.PCAPNG`                                     |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.misc.raw.protocol.Raw`                                                            |
+                                                                  +----------------+-----------------------+--------------------------------------------------------------------+
|                                                                  | :class:`pcapkit.protocols.misc.no_payload.protocol.NoPayload`                                               |
+------------------------------------------------------------------+----------------+-----------------------+--------------------------------------------------------------------+

.. _ext-new-protocol:

New Protocol
------------

A protocol in an existing layer subclasses that layer's base class:
:class:`~pcapkit.protocols.link.link.Link`,
:class:`~pcapkit.protocols.internet.internet.Internet`,
:class:`~pcapkit.protocols.transport.transport.Transport` or
:class:`~pcapkit.protocols.application.application.Application`.

.. important::

   Subclass :class:`~pcapkit.protocols.protocol.Protocol` directly only for a new
   protocol stack, such as the miscellaneous protocols of
   :mod:`pcapkit.protocols.misc`.

Each protocol also needs a schema and a data model:

*  the schema, a :class:`~pcapkit.protocols.schema.Schema` subclass, lays out the
   fields that parse and construct a packet, each a class attribute set to a
   :class:`~pcapkit.corekit.fields.field.Field` instance;
*  the data model, a :class:`~pcapkit.protocols.data.Data` subclass, holds a
   parsed packet, each attribute a bare type annotation.

Then register the class through :mod:`pcapkit.foundation.registry.protocols`,
into the table of the protocol that carries it. A table belongs to the protocol
that reads it, and is keyed by that protocol's own code for its payload:

.. mermaid::

   flowchart TD
       FR["Frame.\_\_proto\_\_ for PCAP,<br/>PCAPNG.\_\_proto\_\_ for PCAP-NG<br/>keyed by LinkType<br/>register\_linktype for both,<br/>register\_pcap or register\_pcapng for one"]
       LK["Link.\_\_proto\_\_<br/>keyed by EtherType<br/>register\_ethertype<br/>a VLAN tag reads on through it"]
       LB["Loopback.\_\_proto\_\_<br/>keyed by BSD address family<br/>register\_loopback"]
       IN["Internet.\_\_proto\_\_<br/>keyed by TransType<br/>register\_transtype"]
       IPX["IPX.\_\_proto\_\_<br/>keyed by IPX Packet Type<br/>register\_ipx"]
       subgraph TR ["Transport layer tables"]
           direction TB
           TU["TCP.\_\_proto\_\_ and UDP.\_\_proto\_\_<br/>keyed by port<br/>register\_tcp, register\_udp,<br/>register\_apptype for either or both"]
           SC["SCTP.\_\_proto\_\_<br/>keyed by the DATA chunk's PPID<br/>register\_sctp"]
           DC["DCCP.\_\_proto\_\_<br/>keyed by port<br/>register\_dccp"]
           TU ~~~ SC ~~~ DC
       end
       APP["an application layer protocol"]

       FR -->|"a link layer protocol, e.g. Ethernet"| LK
       FR -->|"Loopback"| LB
       FR -->|"IPv4 or IPv6, for a raw IP link type"| IN
       LK -->|"an internet layer protocol, e.g. IPv4"| IN
       LK -->|"IPX"| IPX
       LK -->|"RARP"| APP
       LB -->|"IPv4 or IPv6"| IN
       IN -->|"TCP, UDP, SCTP or DCCP"| TR
       IN -->|"IPX_in_IP"| IPX
       IN -->|"OSPF"| APP
       TR & IPX -->|"a registered protocol"| APP

A miss in any table gives that table's fallback, normally
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, as
:ref:`protocol-next-layer-dispatch` shows.

Samples
~~~~~~~

A sketch of a new internet layer protocol, modelled on IPv4, whose full
implementation is :mod:`pcapkit.protocols.internet.ipv4.protocol`:

.. code-block:: python

   from typing import TYPE_CHECKING

   from pcapkit.protocols.internet.internet import Internet  # import base class

   from pcapkit.protocols.data import Data  # import data class
   from pcapkit.protocols.schema import Schema  # import schema class

   from pcapkit.corekit.fields.ipaddress import IPv4AddressField  # import field class

   from pcapkit.const.reg.ethertype import EtherType  # import protocol code registry
   from pcapkit.foundation.registry.protocols import register_ethertype  # import protocol registry API

   if TYPE_CHECKING:
       from ipaddress import IPv4Address
       from typing import Any, Optional


   class IPv4Data(Data):  # define data model

       ...
       src: 'IPv4Address'  # source address
       dst: 'IPv4Address'  # destination address
       ...


   class IPv4Schema(Schema):  # define fields

       ...
       src = IPv4AddressField(...)
       dst = IPv4AddressField(...)
       ...


   class MyIPv4(Internet[IPv4Data, IPv4Schema],
                schema=IPv4Schema, data=IPv4Data):  # define protocol class

       def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'IPv4Data':
           if length is None:
               length = len(self)  # infer length of packet from data
           schema = self.__header__  # get schema

           return IPv4Data(...)

       def make(self, ..., **kwargs: 'Any') -> 'IPv4Schema':
           ...

           return IPv4Schema(...)


   # register protocol class
   register_ethertype(EtherType.Internet_Protocol_version_4, MyIPv4)

.. important::

   **Declare every construction keyword your protocol accepts.** Constructing a
   protocol with a keyword no signature declares raises
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`, so a misspelling fails
   instead of building a wrong field. The accepted set, read by
   :func:`inspect.signature`, is the union of the keyword-taking parameters of
   ``make``, ``read``, ``pack``, ``unpack``, ``__post_init__`` and ``__init__``
   across the MRO: :meth:`Protocol.__post_init__
   <pcapkit.protocols.protocol.Protocol.__post_init__>` hands one ``**kwargs``
   to both construction and parse, so a keyword only ``read`` declares still
   travels through ``make``.

   A keyword no signature can express is listed in :attr:`Protocol.__keywords__
   <pcapkit.protocols.protocol.Protocol.__keywords__>` instead:

   .. code-block:: python

      class MyIPv4(Internet[IPv4Data, IPv4Schema],
                   schema=IPv4Schema, data=IPv4Data):
          #: Read out of ``**kwargs`` by name, as ``IPv6_Ext.read`` does with
          #: ``alias``; unioned down the MRO.
          __keywords__ = frozenset({'my_extra_keyword'})

          def read(self, length=None, **kwargs):
              extra = kwargs.get('my_extra_keyword')
              ...

   :obj:`None` skips the check, and is meant only for a *dispatcher* whose real
   signature belongs to a class chosen at call time, such as
   :class:`~pcapkit.protocols.application.http.protocol.HTTP`, whose
   :meth:`~pcapkit.protocols.application.http.protocol.HTTP.make` builds the
   version it is given. Unlike a set, :obj:`None` is not inherited, so a
   dispatcher's subclasses stay checked. Prefer a declared parameter to either,
   since it also documents the keyword.

   Parsing is unaffected. :meth:`Protocol.from_data
   <pcapkit.protocols.protocol.Protocol.from_data>` checks its caller's keywords
   as strictly, but only warns with
   :exc:`~pcapkit.utilities.warnings.UnknownFieldWarning` for a key from your
   ``_make_data``, a disagreement between two of your own mappings rather than a
   caller's typo.

   .. warning::

      The check lives in :meth:`Protocol.__init__
      <pcapkit.protocols.protocol.Protocol.__init__>`, where every producer's
      keywords converge, so it covers ``SomeProtocol(...)`` and the ``pack`` it
      leads to, but **not** ``make`` called on a bare instance, such as
      ``object.__new__(cls).make(...)``, which drops an undeclared keyword
      silently. This package's tests and :meth:`HTTP.make
      <pcapkit.protocols.application.http.protocol.HTTP.make>` call ``make`` that
      way. Covering it would mean interposing on every ``make`` in the tree, which
      this package deliberately does not do.

.. note::

   Instead of a ``register_*`` call, pass ``code=`` at class definition; a class
   with neither stays unregistered:

   .. code-block:: python

      class MyIPv4(Internet[IPv4Data, IPv4Schema],
                   schema=IPv4Schema, data=IPv4Data,
                   code=EtherType.Internet_Protocol_version_4):
          ...

   The key's type picks the registry -- an
   :class:`~pcapkit.const.reg.ethertype.EtherType` member means
   :class:`~pcapkit.protocols.link.link.Link`'s, a
   :class:`~pcapkit.const.reg.transtype.TransType` member
   :class:`~pcapkit.protocols.internet.internet.Internet`'s, and so on -- so a
   raw :class:`int`, such as a TCP or UDP port, names its registry explicitly:
   ``code={TCP: 21}``. An iterable of either form registers into several at
   once. :meth:`ProtocolBase.__init_subclass__
   <pcapkit.protocols.protocol.ProtocolBase.__init_subclass__>` gives the full
   rule, and
   :func:`~pcapkit.foundation.registry.protocols.protocol.register_protocol_code`
   runs underneath it.

Extending Existing Protocol
---------------------------

Several protocols carry extension points, such as the options of IPv4. To
handle a new code, register your methods against the protocol's extension
point.

.. warning::

   Do not subclass the protocol class for this, which may cause unexpected
   errors; use the registry functions in
   :mod:`pcapkit.foundation.registry.protocols`.

The extension points, with the registry function that writes each:

+-------------------+---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
| Protocol Type     | Protocol Class                                                      | Extensible Registry                                                                                    | Registry Function                                                                   |
+===================+=====================================================================+========================================================================================================+=====================================================================================+
|                   | :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`             | :attr:`IPv4.__option__ <pcapkit.protocols.internet.ipv4.protocol.IPv4.__option__>`                     | :func:`~pcapkit.foundation.registry.protocols.internet.register_ipv4_option`        |
+                   +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.hip.protocol.HIP`               | :attr:`HIP.__parameter__ <pcapkit.protocols.internet.hip.protocol.HIP.__parameter__>`                  | :func:`~pcapkit.foundation.registry.protocols.internet.register_hip_parameter`      |
+                   +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.hopopt.protocol.HOPOPT`         | :attr:`HOPOPT.__option__ <pcapkit.protocols.internet.hopopt.protocol.HOPOPT.__option__>`               | :func:`~pcapkit.foundation.registry.protocols.internet.register_hopopt_option`      |
+ Internet Layer    +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts`   | :attr:`IPv6_Opts.__option__ <pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts.__option__>`      | :func:`~pcapkit.foundation.registry.protocols.internet.register_ipv6_opts_option`   |
+                   +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route` | :attr:`IPv6_Route.__routing__ <pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route.__routing__>` | :func:`~pcapkit.foundation.registry.protocols.internet.register_ipv6_route_routing` |
+                   +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`MH.__message__ <pcapkit.protocols.internet.mh.protocol.MH.__message__>`                         | :func:`~pcapkit.foundation.registry.protocols.internet.register_mh_message`         |
+                   +                                                                     +--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.mh.protocol.MH`                 | :attr:`MH.__option__ <pcapkit.protocols.internet.mh.protocol.MH.__option__>`                           | :func:`~pcapkit.foundation.registry.protocols.internet.register_mh_option`          |
+                   +                                                                     +--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`MH.__extension__ <pcapkit.protocols.internet.mh.protocol.MH.__extension__>`                     | :func:`~pcapkit.foundation.registry.protocols.internet.register_mh_extension`       |
+                   +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.icmpv4.protocol.ICMPv4`         | :attr:`ICMPv4.__type__ <pcapkit.protocols.internet.icmpv4.protocol.ICMPv4.__type__>`                   | :func:`~pcapkit.foundation.registry.protocols.internet.register_icmp_type`          |
+                   +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`         | :attr:`ICMPv6.__type__ <pcapkit.protocols.internet.icmpv6.protocol.ICMPv6.__type__>`                   | :func:`~pcapkit.foundation.registry.protocols.internet.register_icmp_type`          |
+-------------------+---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`TCP.__option__ <pcapkit.protocols.transport.tcp.protocol.TCP.__option__>`                       | :func:`~pcapkit.foundation.registry.protocols.transport.register_tcp_option`        |
+ Transport Layer   + :class:`~pcapkit.protocols.transport.tcp.protocol.TCP`              +--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`TCP.__mp_option__ <pcapkit.protocols.transport.tcp.protocol.TCP.__mp_option__>`                 | :func:`~pcapkit.foundation.registry.protocols.transport.register_tcp_mp_option`     |
+                   +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`SCTP.__chunk__ <pcapkit.protocols.transport.sctp.protocol.SCTP.__chunk__>`                      | :func:`~pcapkit.foundation.registry.protocols.transport.register_sctp_chunk`        |
+                   +                                                                     +--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.transport.sctp.protocol.SCTP`            | :attr:`SCTP.__parameter__ <pcapkit.protocols.transport.sctp.protocol.SCTP.__parameter__>`              | :func:`~pcapkit.foundation.registry.protocols.transport.register_sctp_parameter`    |
+                   +                                                                     +--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`SCTP.__cause__ <pcapkit.protocols.transport.sctp.protocol.SCTP.__cause__>`                      | :func:`~pcapkit.foundation.registry.protocols.transport.register_sctp_cause`        |
+                   +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.transport.dccp.protocol.DCCP`            | :attr:`DCCP.__option__ <pcapkit.protocols.transport.dccp.protocol.DCCP.__option__>`                    | :func:`~pcapkit.foundation.registry.protocols.transport.register_dccp_option`       |
+-------------------+---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2`      | :attr:`HTTPv2.__frame__ <pcapkit.protocols.application.httpv2.protocol.HTTPv2.__frame__>`              | :func:`~pcapkit.foundation.registry.protocols.application.register_http_frame`      |
+ Application Layer +---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   | :class:`~pcapkit.protocols.application.ssl.protocol.SSL`            | :attr:`SSL.__extension__ <pcapkit.protocols.application.ssl.protocol.SSL.__extension__>`               | :func:`~pcapkit.foundation.registry.protocols.application.register_tls_extension`   |
+-------------------+---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`PCAPNG.__block__ <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.__block__>`                     | :func:`~pcapkit.foundation.registry.protocols.misc.register_pcapng_block`           |
+                   +                                                                     +--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`PCAPNG.__option__ <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.__option__>`                   | :func:`~pcapkit.foundation.registry.protocols.misc.register_pcapng_option`          |
+ Miscellaneous     + :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`             +--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
| Protocols         |                                                                     | :attr:`PCAPNG.__record__ <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.__record__>`                   | :func:`~pcapkit.foundation.registry.protocols.misc.register_pcapng_record`          |
+                   +                                                                     +--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
|                   |                                                                     | :attr:`PCAPNG.__secrets__ <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.__secrets__>`                 | :func:`~pcapkit.foundation.registry.protocols.misc.register_pcapng_secrets`         |
+-------------------+---------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+

.. important::

   Every extension point takes a class method: its first argument is the protocol
   class, and the rest match the built-in methods it sits beside.

--------------------------------------
And Speaking of Library Foundations...
--------------------------------------

:mod:`pcapkit.foundation` carries extraction, reassembly, flow tracing and the
registries behind them, each extensible as the protocols are.

Extractor Engines
-----------------

:mod:`pcapkit.foundation.engines` holds the engines that read packets out of a
capture file. The shipped engines derive from
:class:`~pcapkit.foundation.engines.engine.EngineBase`; build your own on
:class:`~pcapkit.foundation.engines.engine.Engine`, which carries the
``engine=`` registration hook.

The engines and the file formats they read:

+---------------------+-----------------------------------------------------------+----------------------------------------+
| Engine Type         | Engine Class                                              | Supported File Formats                 |
+=====================+===========================================================+========================================+
|                     | :class:`pcapkit.foundation.engines.pcap.PCAP`             | PCAP only                              |
+ Built-in Engines    +-----------------------------------------------------------+----------------------------------------+
|                     | :class:`pcapkit.foundation.engines.pcapng.PCAPNG`         | PCAP-NG only                           |
+---------------------+-----------------------------------------------------------+----------------------------------------+
|                     | :class:`pcapkit.foundation.engines.scapy.Scapy`           | all formats supported by `Scapy`_      |
+                     +-----------------------------------------------------------+----------------------------------------+
|                     | :class:`pcapkit.foundation.engines.dpkt.DPKT`             | all formats supported by `DPKT`_       |
|                     +-----------------------------------------------------------+----------------------------------------+
| Third-party Engines | :class:`pcapkit.foundation.engines.pyshark.PyShark`       | all formats supported by `PyShark`_    |
|                     +-----------------------------------------------------------+----------------------------------------+
|                     | :class:`pcapkit.foundation.engines.pypcap.PyPCAP`         | PCAP only, and from a file on disk     |
|                     +-----------------------------------------------------------+----------------------------------------+
|                     | :class:`pcapkit.foundation.engines.pcap_ct.PCAP_CT`       | PCAP only, and from a file on disk     |
|                     +-----------------------------------------------------------+----------------------------------------+
|                     | :class:`pcapkit.foundation.engines.pypcapfile.PyPCAPFile` | PCAP only                              |
+---------------------+-----------------------------------------------------------+----------------------------------------+

.. note::

   An engine may support less than :class:`~pcapkit.foundation.extraction.Extractor`
   offers. `PyPCAP`_ and `pcap-ct`_ dissect no protocol, so they support neither
   reassembly nor flow tracing; `PyPCAPFile`_ has no IPv6 decoder, so it
   reassembles IPv4 and TCP but not IPv6. Each engine warns, or raises, for a
   capability it cannot provide rather than silently producing an empty result.
   The exceptions pass without a warning: `PyPCAPFile`_ and `DPKT`_ leave TCP
   behind some tags, tunnels and extension headers out of TCP reassembly and
   flow tracing, `DPKT`_ also leaves IPv4 in IPv6, and IPv6 in IPv4, out of IP
   reassembly, and the `Scapy`_ engine reads IPv6 only as far as `Scapy`_
   dissects it. See
   :doc:`pcapkit/foundation/engines/index` for the full table, which names each
   case.

.. note::

   `PyPCAP`_ and `pcap-ct`_ are two distributions of one :manpage:`libpcap(3)`
   interface, both installing a top-level |pcap|_ module, and are two engines:
   ``engine='pypcap'`` and ``engine='pcap_ct'``. Both exist because upstream
   `PyPCAP`_ cannot be installed on Python 3.12 or newer and `pcap-ct`_ can.
   :doc:`pcapkit/foundation/engines/index` says which to pick.

Samples
~~~~~~~

A sketch of a new engine on :mod:`scapy`, modelled on
:class:`~pcapkit.foundation.engines.scapy.Scapy`, whose full implementation is
:mod:`pcapkit.foundation.engines.scapy`:

.. code-block:: python

   from typing import TYPE_CHECKING

   from pcapkit.foundation.engines.engine import Engine  # import base class

   if TYPE_CHECKING:
       from pcapkit.foundation.extraction import Extractor

       from scapy.packet import Packet


   # NOTE: ``engine`` registers the class under the key ``Extractor(engine=...)``
   # looks up; without it, the class is not selectable by name.
   class MyScapy(Engine['Packet'], engine='scapy'):

       __engine_name__ = 'Scapy'  # friendly name of the engine
       __engine_module__ = 'scapy'  # module name that the engine is based on

       def __init__(self, extractor: 'Extractor') -> 'None':
           # NOTE: Imported here, not at module level, so the engine's
           # library stays an optional dependency.
           from scapy import sendrecv  # import API entry point

           self._expkg = sendrecv  # store API entry point
           self._extmp = None  # iterator over the packets, set by run()

           super().__init__(extractor)  # initialise base class

       # NOTE: Open the input through ``self._expkg`` and store an iterator
       # over its packets in ``self._extmp``.
       def run(self) -> 'None':
           ext = self._extractor  # get extractor instance

           # NOTE: Replace the verbose handler only for ``verbose=True``; a
           # callable ``verbose=`` is the user's own, already in ``ext._vfunc``.

           if ext._vfunc_default:  # check if the default verbose output is requested
               # NOTE: pcapkit.toolkit bundles per-engine helpers;
               # ``packet2chain`` renders a Scapy packet as its protocol chain.
               from pcapkit.toolkit.scapy import packet2chain  # import utility function

               ext._vfunc = lambda extractor, packet: print(
                   f'Frame {extractor._frnum:>3d}: {packet2chain(packet)}'
               )  # print verbose message as `Frame XXX: Ethernet:IP:TCP:...`

           # NOTE: Parse the global header with the built-in engine and, unless
           # output is disabled, dump it and set ``ext.format``.
           ext.record_header()

           self._extmp = iter(self._expkg.sniff(offline=ext._ifnm))

       # NOTE: Return the next packet from ``self._extmp``, handling its
       # verbose output, file output, reassembly and flow tracing.
       def read_frame(self) -> 'Packet':
           from pcapkit.toolkit.scapy import (ipv4_reassembly, ipv6_reassembly, packet2dict,
                                              tcp_reassembly, tcp_traceflow)  # import utility functions
           ext = self._extractor  # get extractor instance

           packet = next(self._extmp)  # get next packet from the iterator

           ext._frnum += 1  # increment frame number
           ext._vfunc(ext, packet)  # print verbose message

           # NOTE: Dump the packet unless output is disabled.
           frnum = f'Frame {ext._frnum}'
           if not ext._flag_q:
               info = packet2dict(packet)  # convert packet to dict-like object

               # NOTE: In split mode (``ext._flag_f``) ``ext._ofile`` is a dumper
               # class, built per frame; otherwise it is one dumper instance.
               if ext._flag_f:
                   ofile = ext._ofile(f'{ext._ofnm}/{frnum}.{ext._fext}')
                   ofile(info, name=frnum)
               else:
                   ext._ofile(info, name=frnum)

           # NOTE: Each toolkit helper converts the packet to its reassembly's
           # format, or gives None for a packet it does not apply to.
           if ext._flag_r:
               if ext._ipv4:
                   data_ipv4 = ipv4_reassembly(packet, count=ext._frnum)
                   if data_ipv4 is not None:
                       ext._reasm.ipv4(data_ipv4)
               if ext._ipv6:
                   data_ipv6 = ipv6_reassembly(packet, count=ext._frnum)
                   if data_ipv6 is not None:
                       ext._reasm.ipv6(data_ipv6)
               if ext._tcp:
                   data_tcp = tcp_reassembly(packet, count=ext._frnum)
                   if data_tcp is not None:
                       ext._reasm.tcp(data_tcp)

           # NOTE: Flow tracing, likewise.
           if ext._flag_t:
               if ext._tcp:
                   data_tf_tcp = tcp_traceflow(packet, count=ext._frnum)
                   if data_tf_tcp is not None:
                       ext._trace.tcp(data_tf_tcp)

           # NOTE: Store the frame when storing is on (``ext._flag_d``).
           if ext._flag_d:
               ext._frame.append(packet)

           return packet  # return the extracted packet

Output Dumpers
--------------

:mod:`pcapkit.dumpkit` builds on :mod:`DictDumper <dictdumper>`, which writes
the extracted packets to the output file, and whose own documentation covers its
dumpers. A new output format is a dumper subclass.

The output dumpers and their formats:

+----------------------------------+------------------------------------------------+------------------+
| Dumper Format                    | Dumper Class                                   | Output Extension |
+==================================+================================================+==================+
| *No Output*                      | :class:`pcapkit.dumpkit.null.NotImplementedIO` | N/A              |
+----------------------------------+------------------------------------------------+------------------+
| PCAP (``cap``/``pcap``)          | :class:`pcapkit.dumpkit.pcap.PCAPIO`           | ``.pcap``        |
+----------------------------------+------------------------------------------------+------------------+
| XML (``xml``/``plist``)          | :class:`dictdumper.plist.PLIST`                | ``.plist``       |
+----------------------------------+------------------------------------------------+------------------+
| JSON (``json``)                  | :class:`dictdumper.json.JSON`                  | ``.json``        |
+----------------------------------+------------------------------------------------+------------------+
| Text (``txt``/``text``/``tree``) | :class:`dictdumper.tree.Tree`                  | ``.txt``         |
+----------------------------------+------------------------------------------------+------------------+

Samples
~~~~~~~

A sketch of a PCAP dumper, modelled on :class:`~pcapkit.dumpkit.pcap.PCAPIO`,
whose full implementation is :mod:`pcapkit.dumpkit.pcap`:

.. code-block:: python

   from typing import TYPE_CHECKING

   from pcapkit.dumpkit.common import Dumper  # import base class

   from pcapkit.protocols.misc.pcap.header.protocol import Header  # import PCAP header class
   from pcapkit.protocols.misc.pcap.frame.protocol import Frame  # import PCAP frame class

   if TYPE_CHECKING:
       from typing import Optional


   # NOTE: ``fmt`` registers the dumper under that output format, with ``ext``
   # its file extension; without ``fmt``, the class is not registered.
   class MyDumper(Dumper, fmt='pcap', ext='.pcap'):

       # NOTE: The format name, not the extension, which is ``ext`` above.
       @property
       def kind(self) -> 'str':
           return 'pcap'

       # NOTE: Take what the file header needs, e.g. the link-layer protocol,
       # and keep any state later frames need.
       def __init__(self, fname: 'str', *, ...) -> 'None':
           self._fnum = 1  # initialise frame number counter to 1

           super().__init__(fname, ...)  # initialise base class

       # NOTE: Overridden because PCAP is binary, so the file reopens in binary
       # rather than text mode.
       def __call__(self, value: 'Frame', name: 'Optional[str]' = None) -> 'MyDumper':
           with open(self._file, 'ab') as file:
               self._append_value(value, file, name or f'Frame {self._fnum}')  # append value to the file
           return self

       # NOTE: Called on initialisation, to write the file header.
       def _dump_header(self, *, ...) -> 'None':
           packet = Header(...)  # create PCAP header instance based on the given arguments

           with open(self._file, 'wb') as file:
               file.write(packet.data)  # write the header to the output file

       # NOTE: Write one packet, here as a PCAP frame.
       def _append_value(self, value: 'Frame', file: 'IO[bytes]', name: 'str') -> 'None':
           packet = Frame(...)  # create PCAP frame instance based on the given arguments

           file.write(packet.data)  # write the frame to the output file
           self._fnum += 1  # increment frame number counter

Reassembly and Flow Tracing
---------------------------

:mod:`pcapkit.foundation.reassembly` reassembles fragmented packets;
:mod:`pcapkit.foundation.traceflow` follows the packets of a flow. The shipped
classes derive from
:class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase` and
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowBase`; build your own on
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` or
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`, which carry the
``protocol=`` registration hook.

The reassembly and flow tracing classes, per protocol:

+------------------------------------------------------------+--------------------------------------------------+-----------------------------------------------+
| Protocol                                                   | Reassembly Class                                 | Flow Tracing Class                            |
+============================================================+==================================================+===============================================+
| :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`    | :class:`pcapkit.foundation.reassembly.ipv4.IPv4` |                                               |
+------------------------------------------------------------+--------------------------------------------------+-----------------------------------------------+
| :class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`    | :class:`pcapkit.foundation.reassembly.ipv6.IPv6` |                                               |
+------------------------------------------------------------+--------------------------------------------------+-----------------------------------------------+
| :class:`~pcapkit.protocols.transport.tcp.protocol.TCP`     | :class:`pcapkit.foundation.reassembly.tcp.TCP`   | :class:`pcapkit.foundation.traceflow.tcp.TCP` |
+------------------------------------------------------------+--------------------------------------------------+-----------------------------------------------+
| :class:`~pcapkit.protocols.application.dtls.protocol.DTLS` | :class:`pcapkit.foundation.reassembly.dtls.DTLS` |                                               |
+------------------------------------------------------------+--------------------------------------------------+-----------------------------------------------+

.. seealso::

   :mod:`pcapkit.foundation.reassembly` and :mod:`pcapkit.foundation.traceflow`
   document the classes and their algorithms.

New Implementation
~~~~~~~~~~~~~~~~~~

A sketch of an IPv4 reassembly class, modelled on
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4`, whose full implementation is
:mod:`pcapkit.foundation.reassembly.ipv4`; a flow tracing class subclasses
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` the same way:

.. code-block:: python

   from typing import TYPE_CHECKING

   from pcapkit.corekit.infoclass import Info, info_final  # import Info class for data model definitions
   from pcapkit.protocols.internet.ipv4.protocol import IPv4  # import protocol class for attribute definitions

   from pcapkit.foundation.reassembly.reassembly import Reassembly  # import base class

   if TYPE_CHECKING:
       from typing import TypeAlias

   # NOTE: First the data models the class is generic over.

   BufferID: 'TypeAlias' = ...  # key of a reassembly table entry, e.g.
                                # (src, dst, id, proto) for IPv4 and IPv6,
                                # (src, srcport, dst, dstport) for TCP


   @info_final
   class Packet(Info):

       # NOTE: An extracted packet, as the reassembly reads it.
       ...


   @info_final
   class DatagramID(Info):

       # NOTE: The key identifying a reassembled datagram.
       ...


   @info_final
   class Datagram(Info):

       # NOTE: A reassembled datagram.
       ...


   @info_final
   class Buffer(Info):

       # NOTE: A reassembly table entry, buffering fragments until complete.
       ...


   # NOTE: ``protocol`` registers the class under that key; without it, the
   # class is not selectable by name.
   class MyReassembly(Reassembly[Packet, Datagram, BufferID, Buffer],
                      protocol='ipv4'):

       __protocol_name__ = 'IPv4'  # name of the protocol
       __protocol_type__ = IPv4  # type of the protocol

       # NOTE: Buffer ``info`` in ``self._buffer``, a dict of ``BufferID`` to
       # ``Buffer``.
       def reassembly(self, info: 'Packet') -> 'None':
           ...  # reassembly algorithm implementation

           # NOTE: Once a buffer is complete, store its datagrams.
           self._dtgram.extend(
               self.submit(...)  # submit reassembled datagram
           )

       # NOTE: Convert a complete ``Buffer`` into ``Datagram`` instances.
       def submit(self, buf: 'Buffer', *, bufid: 'BufferID') -> 'list[Datagram]':
           datagram = ...  # list of ``Datagram`` instances

           # NOTE: Run the registered callbacks on the submission.
           for callback in self.__callback_fn__:
               callback(datagram)  # run callback functions
           return datagram

Callback Functions
~~~~~~~~~~~~~~~~~~

A callback registered on a reassembly or flow tracing class inspects the
datagrams or flows as they are produced.

.. seealso::

   :mod:`pcapkit.foundation.registry.foundation` holds the callback registry
   functions:

   - :func:`~pcapkit.foundation.registry.foundation.register_reassembly_ipv4_callback`
   - :func:`~pcapkit.foundation.registry.foundation.register_reassembly_ipv6_callback`
   - :func:`~pcapkit.foundation.registry.foundation.register_reassembly_tcp_callback`
   - :func:`~pcapkit.foundation.registry.foundation.register_traceflow_tcp_callback`

A reassembly callback runs on every :ref:`submission <reassembly-submissions>` and
takes one argument, the list of datagrams that submission produced. A flow tracing
callback runs as each flow is finalised and takes that flow's
:class:`~pcapkit.foundation.traceflow.data.tcp.Index`. Each should return
:obj:`None`; any return value is ignored.

A reassembly callback can discard datagrams by modifying its list in place, but
prefer not to: if the result itself is wrong for your purpose, subclass the
class and change its algorithm instead.
