Help Wanted
===========

.. important::

   This is a copy of the `discussion thread <https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__
   started on the GitHub. The documentation is **only** used as a backup
   reference to the original discussion thread.

As PyPCAPKit reaches its *16k* lines of code and *800th* commit, I figure it
would be a better idea to record the project enchancement proposals here in
the discussion thread. The proposals and/or notes will be documented and
maintained here.

Pull requests for the existing proposals and any new ideas are highly welcomed
and encouraged. Should you have any questions, please leave a note either in
this thread or under the `Q&A category discussions <https://github.com/JarryShaw/PyPCAPKit/discussions/categories/q-a>`__.

Wish you enjoy **PyPCAPKit**!!!

More Protocols, More!!!
-----------------------

As you may have noticed, there are some protocol-named files under the
``NotImplemented`` folders. These protocols are what I planned to implement
but not yet done. Namely, grouped by each TCP/IP layer and ordered by protocol
name alphabetically,

* Link Layer: DSL, EAPOL, FDDI, ISDN, PPP
* Internet Layer: ECN, ESP, ICMP, ICMPv6, IGMP, NDP, Shim6
* Transport Layer: DCCP, QUIC, RSVP, SCTP
* Application Layer: BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT, NNTP, NTP,
  ONC/RPC, POP, RIP, RTP, SIP, SMTP, SNMP, SSH, Telnet, TLS/SSL, XMPP

Specifically, I have attempted to implement **ESP** several years ago, and I
abandoned the implementation in the `NotImplemented` folder due to some design
flaws within PyPCAPKit at that time. But now, the protocol should be able to
implement quite smoothly.

More over, :class:`~pcapkit.protocols.internet.mh.MH` requires some help to
implement all the *message data* types, you can find more information in the
specific file.

Logging Integration
-------------------

As PyPCAPKit now has the :data:`pcapkit.utilities.logging.logger` in place, I'm
expecting to fully extend its functionality in the entire module. Ideas and
contributions are welcomed to integrate the logging system into PyPCAPKit.

New Engines
-----------

Although PyPCAPKit already has support for some popular PCAP parsing libraries,
I'm expecting to extend the list of supported engines furthermore. The candidate
engines include:

- `pypcap <https://github.com/pynetwork/pypcap>`__
- `pycapfile <https://github.com/kisom/pypcapfile>`__

Implementation for support of new engines would include adding corresponding
handler methods and code blocks into :class:`pcapkit.foundation.extraction.Extractor`
(see support for Scapy, DPKT, and/or PyShark), as well as, the unified auxiliary
tools located in :mod:`pcapkit.toolkit`.

Test Cases
----------

PyPCAPKit still does not have a systematic testing suite to be bundled with it.
The only test cases I have worked out are those in the ``/tests`` folder - mostly
functional tests. As PyPCAPKit is growing bigger and bigger, a comprehensive test
suite is coming much more of demand for a more reliable development process.
