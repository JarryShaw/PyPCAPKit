Help Wanted
===========

.. important::

   This page mirrors the `discussion thread
   <https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__ started on GitHub.
   The thread holds the proposals as they were first raised, together with a
   comment recording which of them have since landed; this page is the
   maintained copy, kept in step with the code. So where a proposal has been
   implemented it is described as implemented here, and only the work that is
   genuinely still open is asked for. Please leave notes in the thread rather
   than against this page.

As PyPCAPKit reached its *16k* lines of code and *800th* commit, it seemed
better to record the project's enhancement proposals somewhere durable than to
leave them scattered. They were raised in the discussion thread, and this page
is where they are kept up to date.

Pull requests for anything still open, and new ideas of your own, are very
welcome. For questions, leave a note in the `discussion thread
<https://github.com/JarryShaw/PyPCAPKit/discussions/106>`__ or under the `Q&A
category <https://github.com/JarryShaw/PyPCAPKit/discussions/categories/q-a>`__.

Wish you enjoy **PyPCAPKit**!!!

More Protocols, More!!!
-----------------------

As you may have noticed, there are some protocol-named files under the
``NotImplemented`` folders. These protocols are what I planned to implement
but not yet done. Namely, grouped by each TCP/IP layer and ordered by protocol
name alphabetically,

* Link Layer: DSL, EAPOL, FDDI, ISDN, NDP, PPP
* Internet Layer: ECN, ICMP, ICMPv6, IGMP, Shim6
* Transport Layer: DCCP, RSVP
* Application Layer: BGP, DHCP, DHCPv6, DNS, IMAP, LDAP, MQTT, NNTP, NTP,
  ONC/RPC, POP, RIP, RTP, SIP, SMTP, SNMP, SSH, Telnet, TLS/SSL, XMPP

Each of those files is empty, so any one of them is a self-contained piece of
work: a schema class, a data class and a protocol class, as sketched in
`discussion #251 <https://github.com/JarryShaw/PyPCAPKit/discussions/251>`__.
That thread asks for **NGAP** (5G, application layer), which is not on the list
above and has no stub, and the reply to it is the closest thing the project has
to a step-by-step guide for adding a protocol -- worth reading before starting
any of these.

.. note::

   Two entries differ from the list in the discussion thread, and both are
   corrections rather than progress. **NDP** is shown under the link layer
   because that is where its stub actually lives, at
   ``pcapkit/protocols/link/NotImplemented/ndp.py``; there is no
   ``ndp.py`` under the internet layer. **QUIC** has been dropped because no
   stub for it exists anywhere in the tree -- the thread lists it, but the file
   was never created.

   **ESP** and **SCTP** have left the list because they are now implemented,
   and neither left a stub behind.

SCTP
~~~~

**Done.** :class:`~pcapkit.protocols.transport.sctp.SCTP` is a first-class
transport layer protocol implemented per :rfc:`9260`: the common header, all
thirteen chunk types the RFC defines, its eight chunk parameters, its thirteen
error causes, and CRC32c checksum verification.

One note on how it differs from its siblings. The next layer is dispatched
on the DATA chunk's *payload protocol identifier* through
:func:`~pcapkit.foundation.registry.protocols.register_sctp`, not on port
numbers, so :func:`~pcapkit.foundation.registry.protocols.register_apptype`
deliberately does not fan out to it.

What is still wanted is the registered-but-unimplemented type codes. IANA
registers considerably more than :rfc:`9260` defines, and the surplus falls
through to the generic handlers rather than failing the extraction -- so a
capture using one parses, but yields an opaque chunk instead of its fields.
As things stand that is 17 of the 30 registered chunk types, 24 of the 32
chunk parameters and 10 of the 23 error causes; :doc:`pcapkit/const/sctp`
lists them all.

ESP
~~~

**Done.** :class:`~pcapkit.protocols.internet.esp.ESP` -- abandoned in the
``NotImplemented`` folder for years, because of design flaws within PyPCAPKit
at the time -- now parses without keys, and decrypts when a Security
Association is supplied through the protocol keyed
:mod:`pcapkit.corekit.context` channel.

What is still wanted there is wider algorithm coverage. The two enumerations
under :doc:`pcapkit/const/esp` carry every transform IANA has registered, but
only five encryption and five integrity algorithms are actually applied, as
listed by :data:`~pcapkit.protocols.internet.esp.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.INTEGRITY_SUITES`. Specifically not
implemented: ChaCha20-Poly1305 [:rfc:`7634`], AES-CCM [:rfc:`4309`], AES-XCBC
integrity [:rfc:`3566`], and Extended Sequence Numbers.

Mobility Header
~~~~~~~~~~~~~~~

**Partly done**, and still the section of this page with the most work left in
it. :class:`~pcapkit.protocols.internet.mh.MH` has the FMIPv6 fast-handover
messages [:rfc:`5568`] -- Handover Initiate, Handover Acknowledge, FBU, FBack
and FNA -- along with the options they need. What remains is the rest of the
registry:

* **10 of the 24 registered message data types**, namely Home Agent Switch,
  Heartbeat, Binding Revocation, Localized Routing Initiation and
  Acknowledgment, Update Notification and its Acknowledgement, Flow Binding,
  Subscription Query and Subscription Response.
* **51 of the 71 registered options** -- broadly the PMIPv6, NEMO and
  flow-binding block, including Home Network Prefix, Handoff Indicator, Access
  Technology Type, Timestamp, GRE Key, Binding Identifier and the QoS options.
* **3 of the 4 CGA extensions**; only Multi-Prefix is implemented.

Each of those falls through to a generic handler, so nothing breaks -- the
fields simply are not decoded. The ``# TODO`` markers in
``pcapkit/protocols/internet/mh.py`` sit at the exact dispatch tables that need
entries, and the file documents the shape each handler takes.

PCAPNG Support
--------------

**Done.** The builtin default engine parses PCAP-NG files;
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` implements the format, with its
block and option enumerations under :doc:`pcapkit/const/pcapng`. This closes
the request in `#35 <https://github.com/JarryShaw/PyPCAPKit/issues/35>`__, which
the thread raised when only PCAP was supported.

Maybe Even Faster?
------------------

**Still open.** Benchmarking put the builtin default engine at roughly 4x
Scapy and 10x DPKT, which is an acceptable price for what it decodes, but the
original proposal in the thread stands: fold consecutive ``_read_xxxxxx`` calls
into a single ``file.read`` so that the number of IO calls and the duplicated
:func:`struct.unpack` work both come down.

Note that the parsing path has been rewritten since that was written. Protocols
no longer read fields inline; they declare a
:class:`~pcapkit.protocols.schema.schema.Schema` of field descriptors and let
:meth:`~pcapkit.protocols.schema.schema.Schema.unpack` drive it. The batching
idea still applies, but it belongs in the schema and field machinery now rather
than in each protocol's ``_read_`` methods, and the sketch in the thread no
longer maps onto the code. A measured benchmark showing where the time actually
goes would be the useful first contribution here.

Logging Integration
-------------------

**Done.** :mod:`pcapkit.utilities.logging` is no longer a single flat logger
with a hard-wired handler. It now provides:

- a **logger hierarchy** rooted at ``pcapkit``, with every module logging
  through its own child obtained from
  :func:`~pcapkit.utilities.logging.get_logger`, so that a subtree such as
  ``pcapkit.foundation.registry`` can be silenced independently of
  ``pcapkit.foundation.extraction``;
- **library-safe defaults** -- importing :mod:`pcapkit` attaches only a
  :class:`logging.NullHandler` and sets no level, leaving the destination and
  verbosity to the application. :envvar:`PCAPKIT_DEVMODE` still bootstraps the
  historical :obj:`sys.stderr` handler at :data:`logging.DEBUG`;
- a **runtime configuration API** --
  :func:`~pcapkit.utilities.logging.configure`,
  :func:`~pcapkit.utilities.logging.reset` and
  :func:`~pcapkit.utilities.logging.ensure_output` -- rather than a single
  environment variable read once at import;
- **levels chosen deliberately**. Registration bookkeeping across
  :mod:`pcapkit.foundation.registry` moved from ``info`` to ``debug``, since
  a library announcing its own registry entries is not news to its consumer;
  and the four :func:`print` calls that were marked
  ``# pylint: disable=logging-fstring-interpolation`` are now real logger
  calls;
- **``debug`` coverage of the extraction path** -- extractor construction,
  engine selection and fallback, frame counts, cleanup, reassembly and
  flow-tracing setup -- so that ``DEBUG`` explains what PyPCAPKit did with a
  file without descending into per-field parsing.

See :doc:`pcapkit/utilities/logging` for the configuration recipes, including
the one-line restore of the pre-existing :obj:`sys.stderr` output.

One item remains wanted, called out there as deliberately out of scope:
:func:`pcapkit.utilities.warnings.warn` still reports every warning twice, once
through :mod:`logging` and once through :mod:`warnings`, so an application that
has routed :mod:`warnings` into :mod:`logging` sees each one of them twice.

New Engines
-----------

**Done, for both candidates.** ``engine='pypcapfile'`` selects
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

* **pypcapfile** -- the released 0.12.0 imports the ``imp`` module, removed in
  Python 3.12. Precisely, ``pcapfile/linklayer.py`` imports it at module scope
  and ``pcapfile.savefile`` imports ``linklayer``, so while a bare
  ``import pcapfile`` still succeeds on 3.12+, the two modules the engine
  actually needs raise :exc:`ModuleNotFoundError`. Upstream ``master`` (0.12.1,
  unreleased) has fixed this, and that is what the engine was verified against.
  The extra therefore installs a version that only works on Python 3.10 and
  3.11 until 0.12.1 is published.
* **pypcap** -- the 1.3.0 sdist (the only distribution; there has been no wheel
  since Python 2.7) ships a ``pcap.c`` pre-generated by Cython 0.29.32 and
  compiles it verbatim -- its :file:`setup.py` never invokes Cython. That
  generated C does not compile against the Python 3.12+ C API, and the cause is
  three independent CPython removals rather than one: ``ob_digit`` and
  ``PyThreadState.curexc_traceback`` went in 3.12, ``_PyLong_AsByteArray``
  gained a sixth parameter in 3.13, and ``PyDictObject.ma_version_tag`` went in
  3.14. **The ceiling is therefore Python 3.11**, measured: given
  :program:`libpcap`, the shipped ``pcap.c`` builds unchanged on 3.10 and 3.11
  and fails on 3.12 and 3.14. Regenerating it needs Cython **3.0+** -- no
  0.29.x release, including the last, emits 3.12-compatible C.

  Separately, its :file:`setup.py` consults neither ``CFLAGS``/``LDFLAGS`` nor
  :program:`pkg-config`; it searches a fixed prefix list (:file:`/usr`,
  ``sys.prefix``, :file:`/opt/libpcap*`, :file:`../libpcap*`,
  :file:`../wpdpack*`, the macOS SDKs). ``/opt/homebrew`` is absent from that
  list, and Homebrew's ``libpcap`` is ``keg_only :provided_by_macos`` so it is
  never symlinked into a searched prefix either -- meaning
  ``brew install libpcap`` on the arm64 macOS runners would **not** have fixed
  the original failure, on either count. It builds once :program:`libpcap` is
  visible under ``sys.prefix`` *and* the interpreter is 3.11 or older.

  That is a packaging problem upstream rather than an engine problem -- and
  upstream is unmaintained, with no code commit since the 1.3.0 release and its
  Python 3.12 issue (`pynetwork/pypcap#116
  <https://github.com/pynetwork/pypcap/issues/116>`__) open and uncommented
  since May 2024. It does mean ``pip install pypcapkit[PyPCAP]`` can fail to
  build. Since there is no wheel to fall back on, the extra is kept **out of**
  ``all``: otherwise ``pip install pypcapkit[all]`` would demand a compiler and
  the libpcap development files from every user, and it broke the docs, conda
  and release workflows -- all of which install ``.[all]`` -- on the macOS
  runner, where :file:`pcap.h` is present but no ``libpcap.dylib`` is.

  This is now solved, though not by changing the ``PyPCAP`` extra. `pcap-ct
  <https://pypi.org/project/pcap-ct/>`__ re-implements the ``pypcap`` API in pure
  Python over :mod:`ctypes`, and it is wired up as a **separate engine**,
  :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT`, selected with
  ``engine='pcap_ct'`` and installed with ``pip install pypcapkit[PCAP_CT]``. It
  works on every supported interpreter, verified on 3.10 and 3.14.

  A separate engine rather than a second backend because the two are **mutually
  exclusive**: both distributions own the import name ``pcap``, and with both
  installed ``pcap-ct`` wins the import while upstream's extension module is
  shadowed and unreachable. Each engine detects which backend it actually got and
  says so, rather than one ``engine=`` string silently meaning two different
  implementations.

  Two caveats remain. Both distributions are still beta releases, and ``pcap-ct``
  targets the ``pypcap`` 1.2.3 API -- within what this engine uses, but worth
  knowing. And despite the `libpcap <https://pypi.org/project/libpcap/>`__ wheel
  bundling prebuilt binaries, a runtime ``libpcap`` shared library is still
  required: that wheel's published configuration sets ``LIBPCAP = None``, which
  sends the loader to ``find_library("pcap")``. No compiler and no
  :file:`pcap.h` are needed; a ``libpcap.so.1`` is.

Both engines support less than the ``default`` engine does, deliberately and
noisily: `pypcap`_ performs no protocol dissection, so it disables reassembly
*and* flow tracing; `pypcapfile`_ has no IPv6 decoder, so it disables IPv6
reassembly while keeping IPv4 and TCP. Each gap is announced through an
:class:`~pcapkit.utilities.warnings.AttributeWarning` or an outright exception
rather than by silently returning nothing --
:doc:`pcapkit/foundation/engines/index` tabulates them.

Adding a further engine no longer means adding handler methods to
:class:`~pcapkit.foundation.extraction.Extractor`, as the thread describes: the
engine interface has been refactored since. A new engine subclasses
:class:`pcapkit.foundation.engines.engine.Engine` and implements just two
methods, :meth:`~pcapkit.foundation.engines.engine.Engine.run`
and :meth:`~pcapkit.foundation.engines.engine.Engine.read_frame`; subclassing
registers it automatically. See :doc:`ext` for a worked example. What does
still apply is the unified auxiliary tools in :mod:`pcapkit.toolkit`, where
each engine has a matching module.

.. _pypcap: https://github.com/pynetwork/pypcap
.. _pypcapfile: https://github.com/kisom/pypcapfile

Test Cases
----------

**Largely done.** There is now a systematic test suite under ``tests/`` -- 91
modules matching ``test_*.py`` -- and it runs in CI against Python 3.10
through 3.14, plus an allowed-to-fail 3.15 leg, per
``.github/workflows/unit-tests.yml``.

The suite is split by what a test needs rather than by what it covers, and
``tests/_tiers.py`` enforces the split. The **unit** tier may read only
captures committed to the repository; the **fixture-dependent** tier -- which
is ``tests/integration/`` together with every ``*_runtime.py`` and
``*_regression.py`` module -- may also read the generated sample captures.
Those samples are not tracked in git, so
``examples/generators/make_samples.py`` (``make samples``) rebuilds them from
source, and the tier guard raises rather than letting a unit-tier module
quietly depend on a file that may not exist.

What remains wanted is **coverage rather than infrastructure**: the protocols and
the registered-but-unhandled type codes listed above have no tests because they
have no implementation yet.

The original ask also included **shipping the suite**, and that is now a
deliberate decision rather than an omission. ``tests`` is excluded from the wheel
by ``[tool.setuptools.packages.find]`` in ``pyproject.toml``; the sdist does carry
all 91 modules, so a distribution packager building from source has them. The
wheel stays lean because the suite could not run from an installed package
anyway: the generated sample captures are not shipped, and ``tests/_tiers.py``
resolves paths from a repository root that an installed package does not have.
Anyone wanting to run the tests wants the repository, which is where they are.
