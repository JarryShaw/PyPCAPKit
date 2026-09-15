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

.. note::

   **Done**, for both candidates. ``engine='pypcapfile'`` selects
   :class:`pcapkit.foundation.engines.pypcapfile.PyPCAPFile` and
   ``engine='pypcap'`` selects :class:`pcapkit.foundation.engines.pypcap.PyPCAP`;
   each has a matching :mod:`pcapkit.toolkit` module
   (:mod:`pcapkit.toolkit.pypcapfile`, :mod:`pcapkit.toolkit.pypcap`), a
   ``pyproject.toml`` extra (``PyPCAPFile``, which ``all`` includes, and
   ``PyPCAP``, which it deliberately does not -- see below), docs
   under :doc:`pcapkit/foundation/engines/index`, and tests under
   ``tests/foundation/engines/`` and ``tests/toolkit/``. Both were verified
   end-to-end against the sample captures: each agrees with the ``default`` engine
   on frame count, per-record capture length, timestamp and Ethernet header.

   Neither library, though, is usable straight from PyPI on a current Python, and
   both of the following are worth knowing before reaching for them:

   * **pypcapfile** -- the released 0.12.0 imports the :mod:`imp` module, removed
     in Python 3.12, so it cannot be imported at all on 3.12 or newer. Upstream
     ``master`` (0.12.1, unreleased) has fixed this, and that is what the engine
     was verified against. The extra therefore installs a version that only works
     on Python 3.10 and 3.11 until 0.12.1 is published.
   * **pypcap** -- the 1.3.0 sdist ships a pre-generated ``pcap.c`` from an old
     Cython, which no longer compiles against the Python 3.12+ C API
     (``ob_digit``, ``_PyLong_AsByteArray``), and its ``setup.py`` searches a
     fixed list of prefixes for ``pcap.h``. It builds once :program:`libpcap`'s
     headers are visible under ``sys.prefix`` and ``pcap.c`` is regenerated with
     Cython 3. That is a packaging problem upstream rather than an engine problem,
     but it does mean ``pip install pypcapkit[PyPCAP]`` can fail to build. Since
     there is no wheel to fall back on, the extra is kept **out of** ``all``:
     otherwise ``pip install pypcapkit[all]`` would demand a compiler and the
     libpcap development files from every user, and it broke the docs, conda and
     release workflows -- all of which install ``.[all]`` -- on the macOS runner,
     where :file:`pcap.h` is present but no ``libpcap.dylib`` is.

   Both engines support less than the ``default`` engine does, deliberately and
   noisily: `pypcap`_ performs no protocol dissection, so it disables reassembly
   *and* flow tracing; `pypcapfile`_ has no IPv6 decoder, so it disables IPv6
   reassembly while keeping IPv4 and TCP. Each gap is announced through an
   :class:`~pcapkit.utilities.warnings.AttributeWarning` or an outright exception
   rather than by silently returning nothing --
   :doc:`pcapkit/foundation/engines/index` tabulates them.

   The engine interface has since been refactored, so this no longer means adding
   handler methods to :class:`~pcapkit.foundation.extraction.Extractor`. A new
   engine subclasses :class:`pcapkit.foundation.engines.engine.Engine` and
   implements just two methods, :meth:`~pcapkit.foundation.engines.engine.Engine.run`
   and :meth:`~pcapkit.foundation.engines.engine.Engine.read_frame`; subclassing
   registers it automatically. See :doc:`ext` for a worked example. What does
   still apply is the unified auxiliary tools in :mod:`pcapkit.toolkit`, where
   each engine has a matching module.

Originally: although PyPCAPKit already has support for some popular PCAP parsing
libraries, I'm expecting to extend the list of supported engines furthermore. The
candidate engines include:

- `pypcap <https://github.com/pynetwork/pypcap>`__
- `pypcapfile <https://github.com/kisom/pypcapfile>`__

.. _pypcap: https://github.com/pynetwork/pypcap
.. _pypcapfile: https://github.com/kisom/pypcapfile

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
