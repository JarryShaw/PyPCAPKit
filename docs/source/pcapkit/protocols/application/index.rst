Application Layer
=================

.. module:: pcapkit.protocols.application
.. module:: pcapkit.protocols.data.application
.. module:: pcapkit.protocols.schema.application

:mod:`pcapkit.protocols.application` is the collection of all protocols in
application layer, with detailed implementation and methods. Layer is decided by
function rather than encapsulation, see
:doc:`/contributing/conventions/protocol-layer-placement`.

.. toctree::
   :maxdepth: 1

   application
   http
   httpv1
   httpv2
   ftp
   ftp_data
   ngap
   ospf
   rarp
   drarp
   ssl
   sslv2
   tls
   sslv3
   dtls

.. todo::

   Implement BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT, NNTP, NTP, ONC:RPC,
   POP, RIP, RTP, SIP, SMTP, SNMP, SSH, TELNET, XMPP.

Protocol Registry
-----------------

.. data:: APPTYPE
   :module: pcapkit.protocols.application

   alias of :class:`pcapkit.const.reg.apptype.apptype.AppType`
