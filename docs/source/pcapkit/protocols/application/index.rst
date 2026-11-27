Application Layer
=================

.. module:: pcapkit.protocols.application

:mod:`pcapkit.protocols.application` holds the application layer protocols. A
protocol's layer is decided by function rather than encapsulation; see
:doc:`/contributing/conventions/protocol-layer-placement`.

.. toctree::
   :maxdepth: 1

   application
   dns
   http
   httpv1
   httpv2
   ftp
   ftp_data
   ngap
   ospf
   ospfv1
   ospfv2
   ospfv3
   rarp
   drarp
   ssl
   sslv2
   tls
   sslv3
   dtls

.. todo::

   Implement BGP, DHCP, DHCPv6, IMAP, LDAP, MQTT, NNTP, NTP, ONC:RPC,
   POP, RIP, RTP, SIP, SMTP, SNMP, SSH, TELNET, XMPP.

Protocol Registry
-----------------

.. data:: APPTYPE
   :module: pcapkit.protocols.application

   alias of :class:`pcapkit.const.reg.apptype.apptype.AppType`
