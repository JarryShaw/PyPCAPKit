Application Layer
=================

.. module:: pcapkit.protocols.application
.. module:: pcapkit.protocols.data.application
.. module:: pcapkit.protocols.schema.application

:mod:`pcapkit.protocols.application` is collection of all protocols in
application layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 1

   application
   http
   httpv1
   httpv2
   ftp

.. todo::

   Implements BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT, NNTP, NTP, ONC:RPC,
   POP, RIP, RTP, SIP, SMTP, SNMP, SSH, TELNET, TLS/SSL, XMPP.

Protocol Registry
-----------------

.. data:: pcapkit.protocols.application.APPTYPE

   alias of :class:`pcapkit.const.reg.apptype.AppType`
