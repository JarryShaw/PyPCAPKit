Help Wanted
===========

.. important::

   This is a copy of the `discussion thread`_ started on the GitHub. The
   documentation is **only** used as a backup reference to the original
   discussion thread.

   _discussion thread: https://github.com/JarryShaw/PyPCAPKit/discussions/106

As PyPCAPKit reaches its *16k* lines of code and *800th* commit, I figure it
would be a better idea to record the project enchancement proposals here in
the discussion thread. The proposals and/or notes will be documented and
maintained here.

Pull requests for the existing proposals and any new ideas are highly welcomed
and encouraged. Should you have any questions, please leave a note either in
this thread or under the `**Q&A** category discussions <https://github.com/JarryShaw/PyPCAPKit/discussions/categories/q-a>`__.

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

Also, for the existing protocols, I am looking for a helping hand to implement
the construction features, as defined in the :meth:`Protocol.make <pcapkit.protocols.protocol.Protocol.make>`
method. You can find some reference from the PCAP's :class:`~pcapkit.protocols.misc.pcap.Frame`
header class.

`PCAPNG`_ Support
-----------------

As mentioned in #35, PyPCAPKit does not support parsing PCAPNG files with its
builtin default engine at the moment -- *partly because I could not understand
the file format specifications*.

If you are to help with it, please refer to the implementation of PCAP format
support in :mod:`pcapkit.protocols.misc.pcap` module.

.. _PCAPNG: https://wiki.wireshark.org/Development/PcapNg

Maybe Even Faster?
------------------

Based on my recent benchmarking, PyPCAPKit's builtin default engine is *only* 4
times slower than Scapy and 10 times to DPKT. Considering the general overhead
and verbose features provided by PyPCAPKit's builtin default engine, such
performance difference is acceptable.

However, there might still be a way to further accelerate the protocol
implementation -- merge and concatenation ``_read_xxxxxx`` methods within one
single :meth:`file.read`, such that we shall decrease the overall number of IO
calls and reduce the duplicated :func:`struct.unpack` calls, etc. I am not yet
confident about the performance improvement, but this is the most efficient way
to accelerate PyPCAPKit at the moment, inspired from the implementation of
Scapy and DPKT themselves.

Specifically, as the following code from :meth:`pcapkit.protocols.misc.pcap.Frame.read`,

.. code-block:: python

   _tsus = self._read_unpack(4, lilendian=True)
   _ilen = self._read_unpack(4, lilendian=True)
   _olen = self._read_unpack(4, lilendian=True)

we might be able to rewrite it as

.. code-block:: python

   _tsus, _ilen, _olen = self._read_fields(unpack(4, lilendian=True), unpack(4, lilendian=True), unpack(4, lilendian=True))

and the PoC of ``_read_fields`` would be something like

.. code-block:: python

   def _read_fields(self, *fields: 'Field') -> 'tuple[Any, ...]':
       # built template
       fmt = ''.join(field.template for field in fields)
       len = sum([field.length for field in fields)

       # read from buffer & do unpack
       buf = self._file.read(fmt)
       tmp = struct.unpack(fmt, buf)

       # do post-processing based on field-specific implementations
       ret = []
       for field, val in itertools.chain(fields, tmp):
            ret.append(field.post_process(val))
       return ret

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
