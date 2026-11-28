Application Layer
=================

.. module:: pcapkit.protocols.application

:mod:`pcapkit.protocols.application` holds the application layer protocols. A
protocol's layer is decided by function rather than encapsulation; see
:doc:`/contributing/conventions/protocol-layer-placement`.

.. toctree::
   :maxdepth: 1

   application
   dhcp
   bootp
   dhcpv4
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
   stp
   stpv0
   rstp
   mstp

.. todo::

   Implement BFD, BGP, DHCPv6, IKE, IMAP, Kerberos, LACP, LDAP, LLDP,
   mDNS and LLMNR, MQTT, NetBIOS, NNTP, NTP, ONC/RPC, POP, RADIUS, RIP, RSVP,
   RTP, SIP, SMB, SMTP, SNMP, SSDP, SSH, syslog, Telnet, VRRP and XMPP, and
   decode OSPF's packet bodies; :doc:`/contributing/pep` gives each its issue.

Protocol Registry
-----------------

.. data:: APPTYPE
   :module: pcapkit.protocols.application

   alias of :class:`pcapkit.const.reg.apptype.apptype.AppType`
