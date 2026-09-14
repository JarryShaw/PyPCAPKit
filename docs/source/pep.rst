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

.. note::

   **SCTP** is now **done**. It is implemented as a first-class transport layer
   protocol per :rfc:`9260`: the common header, all thirteen chunk types the
   RFC defines, chunk parameters, error causes, and CRC32c checksum
   verification. Chunk types, parameters and error causes that are registered
   but not yet implemented fall through to the generic handlers rather than
   failing the extraction.

   One note on how it differs from its siblings. The next layer is dispatched
   on the DATA chunk's *payload protocol identifier* through
   :func:`~pcapkit.foundation.registry.protocols.register_sctp`, not on port
   numbers, so :func:`~pcapkit.foundation.registry.protocols.register_apptype`
   deliberately does not fan out to it.

As you may have noticed, there are some protocol-named files under the
``NotImplemented`` folders. These protocols are what I planned to implement
but not yet done. Namely, grouped by each TCP/IP layer and ordered by protocol
name alphabetically,

* Link Layer: DSL, EAPOL, FDDI, ISDN, PPP
* Internet Layer: ECN, ICMP, ICMPv6, IGMP, NDP, Shim6
* Transport Layer: DCCP, QUIC, RSVP
* Application Layer: BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT, NNTP, NTP,
  ONC/RPC, POP, RIP, RTP, SIP, SMTP, SNMP, SSH, Telnet, TLS/SSL, XMPP

**ESP** -- abandoned in the ``NotImplemented`` folder for years, because of
design flaws within PyPCAPKit at the time -- is now implemented, c.f.
:class:`~pcapkit.protocols.internet.esp.ESP`. It parses without keys, and
decrypts when a Security Association is supplied through the protocol keyed
:mod:`pcapkit.corekit.context` channel. What is still wanted there is wider
algorithm coverage: ChaCha20-Poly1305 [:rfc:`7634`], AES-CCM [:rfc:`4309`] and
AES-XCBC integrity [:rfc:`3566`] are not implemented, and neither are Extended
Sequence Numbers.

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

.. note::

   The engine interface has since been refactored, so this no longer means adding
   handler methods to :class:`~pcapkit.foundation.extraction.Extractor`. A new
   engine subclasses :class:`pcapkit.foundation.engines.engine.Engine` and
   implements just two methods, :meth:`~pcapkit.foundation.engines.engine.Engine.run`
   and :meth:`~pcapkit.foundation.engines.engine.Engine.read_frame`; subclassing
   registers it automatically. See :doc:`ext` for a worked example. What does
   still apply is the unified auxiliary tools in :mod:`pcapkit.toolkit`, where
   each engine has a matching module.

Test Cases
----------

.. note::

   Largely **done**. There is now a systematic unit test suite under ``tests/``
   (84 modules), bundled with the distribution, and it runs in CI against Python
   3.10 through 3.14 (see ``.github/workflows/unit-tests.yml``). The sample
   captures the runtime, regression and integration tiers read are not tracked in
   git, so ``examples/generators/make_samples.py`` (``make samples``) rebuilds them
   from source.

   What remains wanted is coverage rather than infrastructure: the protocols and
   the registered-but-unhandled type codes listed above have no tests because
   they have no implementation yet.

Originally: PyPCAPKit still does not have a systematic testing suite to be
bundled with it. The only test cases I have worked out are those in the
``/tests`` folder - mostly functional tests. As PyPCAPKit is growing bigger and
bigger, a comprehensive test suite is coming much more of demand for a more
reliable development process.
