=========
Changelog
=========

All notable changes to PyPCAPKit are recorded here.

   **Note** -- Versions before 1.5.0 are reconstructed from the git history, so
   they summarise each release rather than enumerate every change. The record
   starts at 0.13.0 (2018-12-08); the earlier 0.x releases are not covered.

   **Note** -- Post-releases (``X.Y.Z.postN``) are, from 1.0.1 onwards, automated
   publications of the weekly registry refresh: a bot regenerates the vendor
   constant enumerations under ``pcapkit.const`` from the upstream IANA
   registries and bumps the version. They carry no library changes, and are
   collapsed into a single line per release below. Where a post-release did
   carry something real, it is called out.

1.5.0 -- unreleased
===================

The largest release since 1.0, and the first recorded here as it happened rather
than reconstructed. Three more extraction engines, ESP with payload decryption,
SCTP and NGAP over SCTP, a library logger that no longer hijacks the consumer's,
and a defect programme run through the issue tracker across some 140 issues and
pull requests between #326 and #509.

* **Added** -- three extraction engines: ``engine='pypcap'`` and
  ``engine='pcap_ct'``, two independent distributions of the same ``libpcap``
  interface, and ``engine='pypcapfile'`` (#386, #405). They buy speed by doing
  less -- neither ``pypcap`` nor ``pcap_ct`` dissects at all, so they offer
  neither reassembly nor flow tracing, and ``pypcapfile`` has no IPv6 decoder.
  Install only **one** of ``pypcap`` and ``pcap-ct``: both own the top-level
  ``pcap`` module, and with both present ``pcap-ct`` wins the import and the
  other becomes unselectable. The matching interface constants ``PyPCAP``,
  ``PCAP_CT`` and ``PyPCAPFile`` were missing and are now exported alongside
  ``DPKT``, ``Scapy``, ``PyShark`` and ``PCAPKit`` (#412). That brings the
  built-in set to seven engines; 3.11 is the last interpreter on which every one
  of them can run, and even there two of them cannot coexist.
* **Added** -- ``EngineBase.unsupported_reason``, a preflight every engine
  answers and ``Extractor.run`` consults before anything is imported. Asking for
  an engine that cannot run in the current environment now gives one warning
  naming the real cause -- a Python version, a missing ``tshark``, a missing
  ``libpcap``, the wrong ``pcap`` distribution -- and a clean fall back to
  ``pcapkit``'s own parser, rather than an error from inside the third-party
  package (#396, #405).
* **Added** -- ESP parsing and construction [:rfc:`4303`], with optional payload
  decryption and ICV verification through ``cryptography``
  (``pip install pypcapkit[crypto]``) (#378). Keys reach the dissector through a
  new caller-state channel, ``pcapkit.corekit.context``, surfaced as the
  ``context=`` keyword on ``extract()`` and ``Extractor``, carrying an
  ``esp.SecurityAssociation``. Nothing here raises: with no association the SPI
  and sequence number are still reported and the ciphertext is left opaque, with
  ``status=NO_SA``, and a failed decryption or ICV check is recorded on the
  parsed result the same way. Extended Sequence Numbers, TFC padding and
  anti-replay are not implemented, and an unsupported cipher or MAC is refused
  with a clear error rather than half-processed.
* **Added** -- SCTP as a transport protocol [:rfc:`9260`]: all 13 chunk types, 8
  chunk parameters and 13 error causes, with the CRC32c both recorded and
  verifiable -- it covers the SCTP packet alone, with no IP pseudo-header, so it
  can be checked from the SCTP bytes. Upper layers register on the DATA chunk's
  Payload Protocol Identifier through ``register_sctp``, not on a port (#379).
* **Added** -- NGAP over SCTP (3GPP TS 38.413), decoding aligned PER through
  ``pycrate`` (``pip install pypcapkit[NGAP]``) (#251, #417). Decoding is generic
  by ASN.1 shape rather than per-procedure, so all 81 elementary procedures and
  438 protocol IEs work and a new 3GPP release needs no code change. Registered
  as a default on PPID 60 and 66, but only 60 decodes: PPID 66 is an NGAP PDU
  inside a DTLS record, and there is no DTLS dissector. ``pycrate`` is
  deliberately excluded from the ``all`` extra -- it is LGPL-2.1+ where this
  package is BSD-3-Clause, and lands some 238 MB to obtain one module.
* **Added** -- the Mobility Header registry, completed (#383, #437). The
  :rfc:`5568` fast-handover messages and options first, then all 24 registered
  message data types, 70 of the 71 registered options -- with nested sub-option
  registries for the flow identification, access network identifier,
  quality-of-service and LMA-controlled MAG parameter families -- and all 4 CGA
  extensions. Only the CGA Parameters option remains on the generic handler.
* **Added** -- dispatch entries for dissectors that existed but were reachable
  from no registry (#436): FTP-DATA on TCP 20, HTTP/1 on TCP 8080, HTTP on UDP
  8080, ``L2TPv2`` on UDP 1701 and OSPF at ``TransType`` 89. ``VLAN`` became an
  abstract base with ``C_Tag`` (802.1Q) and ``S_Tag`` (802.1ad) as concrete
  subclasses, so a Q-in-Q frame no longer collapses into one opaque ``Raw``;
  ``L2TP`` likewise became a base, with ``L2TPv2`` carrying the :rfc:`2661`
  implementation.
* **Added** -- ``pcapkit.utilities.logging`` as a real interface:
  ``get_logger()`` for per-module children, ``configure()`` to set level,
  handler, stream, format or propagation at runtime, ``reset()`` to return to
  library-neutral, and ``ensure_output()``. Seventeen modules now log under their
  own ``__name__``, so a consumer can silence ``pcapkit.foundation.registry``
  while keeping ``pcapkit.foundation.extraction`` (#384).
* **Added** -- ``conflict`` on the reassembly data models: absolute, inclusive
  ranges where two fragments claimed the same span with different bytes, which
  was previously lost silently on both the IP (#482) and TCP (#443, #478) paths.
* **Added** -- an end-to-end test tier (#376), sample-capture generators so a
  fresh clone can rebuild every fixture (#340), a Dockerised engine benchmark
  covering every supported Python version (#410), and registry round-trip
  coverage that records the entries which cannot close the cycle rather than
  skipping them (#440, #504).
* **Changed** -- ``pcapkit`` no longer configures logging at import. It
  installs a ``NullHandler`` and sets no level, so verbosity is inherited from
  the application instead of being seized by whichever library was imported
  second; the old stderr handler stays as the ``PCAPKIT_DEVMODE`` opt-in. Three
  consequences worth knowing: the previous behaviour is
  ``configure(logging.INFO, stream=sys.stderr)``; 38 registry and extractor
  ``info`` calls became ``debug``, so those messages are invisible even at
  ``INFO``; and the handler is no longer ``logger.handlers[0]``. ``verbose=``
  output stays on stdout and is not logging (#384).
* **Changed** -- each warning is reported once per channel, and ``pcapkit`` no
  longer inserts a ``simplefilter('ignore', ...)`` at the front of the
  process-global ``warnings.filters`` (#362--#364, #390). The application's own
  filter therefore wins now, which is the point of the change and also the sharp
  edge in it: under ``-W error``, or pytest's ``filterwarnings = error``, a
  pcapkit warning that used to be suppressed will raise. Suppress them
  deliberately with
  ``warnings.filterwarnings('ignore', category=BaseWarning)``. ``quiet=True``
  now means no record at any level and no longer sets ``sys.tracebacklimit``,
  and the ``pcapkit.utilities.warnings.DEVMODE`` re-export is gone -- its
  canonical home is ``pcapkit.utilities.logging``.
* **Changed** -- ``layer=`` and ``protocol=`` are honoured rather than inert.
  Both were read under the wrong names, so every value a caller passed was
  dropped into ``**kwargs`` and discarded; the CLI's ``-L`` also now validates
  its argument instead of accepting anything. The packet context reaches the
  schema layer for the first time as well, so a field the wire elides can be
  resolved from its enclosing packet (#404). ``follow_tcp_stream`` dispatches on
  the engine type, where both branches of the old test were dead and the native
  adapter ran against every engine's frames (#402).
* **Changed** -- two reassembly and flow-tracing defaults moved (#435), and both
  are visible to a caller. ``Datagram.completed`` widened from ``bool`` to a
  ``Completion`` enumeration (``COMPLETE``, ``PARTIAL``, ``TIMEOUT``); only
  ``COMPLETE`` is truthy, so ``if datagram.completed:`` is unaffected but
  ``datagram.completed == True`` no longer holds. TCP flow tracing is
  **bidirectional by default**, which merges each flow's two halves and closes
  one only once both have FINed -- 331 flows become 111 on the sample HTTP
  capture, the difference being single-frame stray tails; pass
  ``trace_bidirectional=False`` for the old behaviour. IP reassembly also gained
  the 60-second timeout [:rfc:`1122`, :rfc:`8200`], clocked off the capture's own
  timestamps rather than the wall clock, tunable with ``reasm_timeout=``; TCP
  reassembly gets no timeout by default. ``trace_analyse=`` is new, and
  reassembles each traced flow's application layer.
* **Changed** -- conflicting TCP overlaps resolve first-write-wins, per
  :rfc:`9293` section 3.10, where they had silently resolved last-write-wins
  (#443, #478). A deliberate behaviour break, and a narrow one: a conforming
  retransmission carries identical bytes, so nothing changes for it. IP fragment
  reassembly keeps last-write-wins, because :rfc:`791` specifies the opposite
  resolution, and records the disagreement instead (#482).
* **Changed** -- ``Probe``, ``CipherSuite`` and ``IntegritySuite`` are ``Info``
  subclasses rather than ``typing.NamedTuple``, and no ``NamedTuple`` remains in
  the package. They are Mappings now, so ``len()`` and iteration yield field
  names rather than values.
* **Changed** -- renames with no compatibility alias left behind:
  ``HoleDiscriptor`` is spelled ``HoleDescriptor`` and its package alias
  ``TCP_HoleDiscriptor`` is ``TCP_HoleDescriptor`` (#350); PCAP-NG ``Option``
  subclasses spell the namespace class keyword ``ns=`` instead of ``namespace=``
  (#439); and ``examples/sample`` and ``examples/samples`` -- one letter apart,
  holding different things -- are now ``examples/captures`` and
  ``examples/generators``.
* **Changed** -- extraction is around 46% faster on a 1,117-frame HTTP capture,
  with byte-identical output (#420). A reassembled datagram's payload is now
  analysed on first read rather than eagerly, which cuts IP reassembly's own
  cost by 90.7% and TCP's by 23.7% -- IP reassembly submits a datagram for every
  frame, fragmented or not (#424). Flow tracing over the same capture went from
  1416.6 ms to 744.0 ms, because the flow dumper had been handing each record to
  a ``Frame`` constructor that re-dissected the whole protocol stack to return
  bytes it had just been given; options are no longer parsed twice either
  (#427). All output compared byte-for-byte across the sample captures in each
  case.
* **Fixed** -- next-layer, option, chunk, block and parameter dispatch all read
  ``defaultdict`` registries, so a lookup miss inserted the key into class-level
  state shared by every later instance, after which a legitimate ``register_*``
  call warned that the code was already registered. Every read now goes through
  a lookup that does not grow the table, and ``IPv4.__option__`` and
  ``HIP.__parameter__`` became inspectable class attributes rather than names
  assembled at call time (#426, #428, #429, #434). One break comes with it: a
  tuple-registered handler pair written to the documented
  ``OptionParser``/``OptionConstructor`` signature now works where it could
  previously never be called at all, and a pair written with an explicit leading
  ``self`` -- the only shape that used to work -- now does not.
* **Fixed** -- on Python 3.10 and older, no ``Schema`` subclass got its own
  ``_abc_impl``: all of them fell through to ``collections.abc.Mapping``'s, so a
  single ``isinstance`` or ``issubclass`` answer poisoned every later question
  about that class for the rest of the process. A terminating PCAP-NG
  ``EndRecord`` tested ``True`` as an ``IPv4Record`` (#439).
* **Fixed** -- construction, which was broken in several places at once: the
  generated typed ``__init__`` was never installed, so ``__post_init__`` did not
  run and a schema built from a subset of its fields could not be packed at all
  -- ``UDP(srcport=53, dstport=5353)`` now packs (#430); IPv6 and Mobility Header
  option padding was wrong, leaving construction wholly broken (#398);
  ``HTTP.make`` called the versioned ``make`` unbound, so every real call raised
  ``TypeError`` (#452, #462); and ``IPv4._make_data`` returned the fragment
  offset in octets where the wire wants 8-octet units, and read ``data.options``
  on a packet that has none (#494, #499).
* **Fixed** -- a truncated or under-declared area no longer parses
  "successfully", and no longer wedges the process. The option and list loops
  could spin forever with no exception on a truncated area, reachable from
  untrusted input through HOPOPT, IPv6-Opts, MH, HIP and SCTP; each iteration
  must now advance the stream by at least one octet, and the error names the
  option, the offset and the octets remaining (#431, #432). Separately,
  wire-derived lengths in ``ipv6_opts``, CALIPSO, MPL, REG_INFO and four HIP list
  callbacks underflowed below zero, which ``ListField``'s own
  ``while length > 0`` then turned into a silent empty list; they are floored and
  raise instead (#449, #456, #460, #463).
* **Fixed** -- field widths and units, each measured against the specification
  rather than inferred: HIP's ``TRANSPORT_FORMAT_LIST``, ``NAT_TRAVERSAL_MODE``
  and ``ESP_TRANSFORM`` list entries are two octets, not one [:rfc:`7401`,
  :rfc:`5770`, :rfc:`7402`] (#463, #472); the MN-ID option sizes from its
  subtype, not from ``identifier``'s Python type (#448, #464, #467);
  IPv6-Route's ``Hdr Ext Len`` is computed in 8-octet units on both sides
  [:rfc:`8200`] (#487, #489); and the Fast Binding Update and Acknowledgment
  Lifetimes are plain seconds [:rfc:`5568`], not :rfc:`6275`'s four-second units
  (#502).
* **Fixed** -- stdlib exceptions leaking out where the library's own were
  promised: a malformed IP field value raised a bare ``ValueError`` instead of
  ``FieldValueError`` (#465); a ``bool`` address was silently packed as
  ``0.0.0.1`` or ``0.0.0.0``, ``bool`` being an ``int`` subclass (#491, #500);
  and ``@prepare`` discarded extra arguments silently and treated a *declared*
  zero length as end of stream, which is now distinguished from a genuinely
  exhausted one and raises ``StreamEOFError`` (#454, #458).
* **Fixed** -- the engine adapters, which were quietly wrong rather than loud.
  The ``dpkt`` toolkit split TCP and IPv4 headers at their fixed struct size
  instead of their real length, so option octets overwrote payload in the
  sequence-indexed reassembly buffer; it also read an ``ipv6_frag.nh`` that
  ``dpkt`` does not have, and passed fragment offsets unscaled (#351, #370,
  #385, #395). ``scapy`` never loaded its layer registry, so that engine did not
  dissect at all (#409), and its IPv4 fragment offset reached reassembly
  unscaled (#483, #484). The four IPv6 adapters disagreed about whether the
  8-octet Fragment header belongs to ``ihl``, ``header`` and ``tl``; per
  :rfc:`8200` section 4.5 it belongs to none of them, and all four now agree
  (#415, #424).
* **Fixed** -- PCAP and PCAP-NG output and parsing: ``bytes(frame)`` returned the
  *next* frame's octets, ``files=True`` wrote names like ``Frame 1..json``, and a
  PCAP-NG ``timestamp_epoch`` was shifted by the reading host's timezone (#403);
  seven further parser defects (#341--#347, #371) and, on the write path, four
  more block-parsing ones (#388); ``BitField`` packed every named bit as set
  (#359, #374); the extension-header walk failed to advance past the last IPv6
  extension header (#348, #373); and IPv6 fragment offsets went unscaled, with
  reassembly keyed on the flow label -- optional, and routinely zero, so distinct
  datagrams collapsed together -- rather than on the fragment identification
  (#389).
* **Fixed** -- TCP reassembly mixed absolute sequence numbers with
  buffer-relative slicing, so on any capture carrying a SYN with a realistic
  initial sequence number incomplete datagrams were dropped silently, and the
  ``completed=False`` branch of the public API was unreachable (#349, #376).
* **Fixed** -- constant lookups that rejected a value the registry defines.
  ``RouterAlert(0)`` is the only value :rfc:`2113` defines and the one IGMP,
  RSVP and MLD actually send, and it was discarded because the vendor crawler
  skipped a header row IANA's CSV does not have; IPX ``Socket(0)`` is that
  protocol's own default, so ``bytes(IPX(...))`` crashed on its own defaults;
  and two FTP ``_missing_`` overrides were plain methods rather than
  classmethods, so every unregistered value raised ``TypeError`` instead of
  extending the enumeration (#492, #503).
* **Fixed** -- ``format='text'`` raised ``AttributeError`` before writing
  anything, naming a ``dictdumper.Text`` that has never existed. It now points
  at ``Tree``, as the ``'txt'`` alias beside it already did.
* **Fixed** -- 45 places where a documentation page contradicted the code
  (#413), ambiguous cross-references and five autodoc signature failures (#416),
  and ``Extractor``'s documented exception plus 40 phantom or stale ``Args:``
  labels (#501).

Preceded by ``1.5.0a1`` (2026-09-15), ``1.5.0b1`` and ``1.5.0b2`` (both
2026-09-18) and ``1.5.0b3`` (2026-09-19), all published as prereleases and so
resolved only by ``pip install --pre``. ``1.5.0b1`` half-shipped: the tag, the
GitHub release and the Conda deployments landed, but PyPI rejected the wheel
because ``twine check`` found a Sphinx-only ``:mod:`` role in ``README.rst``,
which ``pyproject.toml`` declares as the dynamic long description. ``1.5.0b2``
is what reshipped it -- the release workflow is version-driven, so an existing
version cannot republish -- and ``1.5.0b3`` followed the CI change that stops a
TestPyPI outage from costing a release its wheels (#497, #498).

1.4.1 -- 2026-08-22
===================

Release engineering only -- no library behaviour changed.

* **Added** -- a unit-test CI workflow, and the packaging, vendor-cron and
  documentation workflows are now gated on it, so a release can no longer be cut
  from a tree whose tests fail.
* **Changed** -- the vendor cron refuses to publish when the registry update
  itself failed, rather than shipping a half-refreshed release.
* **Fixed** -- unit-test compatibility on Python 3.10.

*Also released:* ``1.4.1.post1``, ``1.4.1.post2`` (through 2026-09-12).

1.4.0 -- 2026-08-21
===================

The first release in nearly two years to carry code changes, and the first with
a test suite.

* **Added** -- a unit-test suite under ``tests/``, covering ``pcapkit.corekit``,
  the extraction engines, reassembly and flow tracing, the protocol schemas, the
  CLI and the utility modules.
* **Fixed** -- PCAP-NG option dispatch regressions; the fallback name generated
  by the ``linktype`` vendor crawler.
* **Changed** -- CI tests current Python versions again; every GitHub Actions
  job carries an explicit permissions block; the conda and cron release tooling
  was repaired, and Anaconda uploads use the official upload action.

1.3.5 -- 2024-11-16
===================

**Fixed** -- transport-layer payloads were not decoded at all. An inverted
``payload is None`` check in ``pcapkit.protocols.internet.internet`` left every
TCP and UDP frame under IPv4/IPv6 reported as ``raw``, typically with
``'int' object has no attribute 'port'``. The regression was introduced by the
IPv6 extension-header fix in 1.3.4, so 1.3.4 should be skipped entirely.

*Also released:* ``1.3.5.post1`` through ``1.3.5.post43`` (through 2026-08-21),
all registry refreshes except ``post41``, which switched the Anaconda upload to
the official action.

1.3.4 -- 2024-11-14
===================

* **Fixed** -- IPv6 Routing header length handling, and extraction of the IPv6
  extension header chain (#218).
* **Changed** -- the build matrix moved to Python 3.13 and stopped testing 3.8.

This release also introduced the transport-layer parsing regression fixed in
1.3.5; upgrade past it rather than to it.

1.3.3 -- 2024-11-03
===================

* **Fixed** -- errors reading PCAP files from both the CLI and the library
  (#240): missing optional CLI dependencies are handled gracefully and console
  output is far less verbose; installation from source, which ``setup.py`` had
  broken (#221); PCAP output during flow tracing (#180).
* **Changed** -- the base protocol data class carries ``packet``; ``Info``
  iteration skips excluded fields.

1.3.2 was never released. The version string existed in-tree for a few hours on
2024-11-03 and was superseded by 1.3.3 the same day, so there is no ``v1.3.2``
tag and no distribution.

*Also released:* ``1.3.3.post1``, ``1.3.3.post2`` (through 2024-11-14);
``post1`` fixed a PyPI metadata problem.

1.3.1 -- 2023-12-21
===================

* **Changed** -- ``register_port()`` was renamed ``register_apptype()``, with no
  alias left behind; callers registering application-layer protocols by port
  must be updated.
* **Changed** -- the documentation was revised across the whole project --
  ``pcapkit.protocols``, ``pcapkit.corekit`` and ``pcapkit.dumpkit`` in
  particular.

*Also released:* ``1.3.1.post1`` through ``1.3.1.post28`` (through 2024-10-26).

1.3.0 -- 2023-10-04
===================

A redesign of the extension points, on metaclasses.

* **Changed** -- the protocol, reassembly, flow-tracing, engine, vendor and
  field base classes are all built on metaclasses, which is what registers a
  subclass and fixes its name and module.
* **Added** -- ``ModuleDescriptor``, so a registry entry can name a module and
  class that are imported lazily on first use rather than at registration; the
  registry functions accept it throughout. ``VersionInfo`` gained a ``version``
  property.
* **Changed** -- ``_Engine`` renamed ``EngineBase``; the ``beholder`` decorator
  logs the error it swallows under devmode and verbose mode.

1.2.2 -- 2023-09-14
===================

**Fixed** -- extraction failing outright (#166).

*Also released:* ``1.2.2.post1``, ``1.2.2.post2`` (through 2023-10-04).

1.2.1 -- 2023-08-27
===================

**Fixed** -- bugs in the ``SeekableReader`` introduced one day earlier in 1.2.0.

*Also released:* ``1.2.1.post1`` through ``1.2.1.post3`` (through 2023-09-09).

1.2.0 -- 2023-08-26
===================

* **Added** -- streaming input. ``pcapkit.corekit.io.SeekableReader`` buffers a
  non-seekable stream so a capture can be read from ``stdin`` or a pipe, which
  is what live ``tcpdump`` output needs (#156).
* **Fixed** -- reassembly, broken since 0.16.3 (#155). ``Extractor`` now raises
  an explicit unsupported-call error, and logs a notice, when reassembly or flow
  tracing is requested where it cannot be provided.

1.1.1 -- 2023-08-15
===================

**Fixed** -- ``AppType`` enumeration lookups; ``typing.TypeAlias`` compatibility
on older interpreters; the output file name chosen by flow tracing; dumping of
``Schema`` objects through a custom dumper.

*Also released:* ``1.1.1.post1``, ``1.1.1.post2`` (through 2023-08-23).

1.1.0 -- 2023-07-09
===================

* **Changed** -- the schema and field classes were rebuilt on metaclasses, with
  ``EnumSchema`` for enum-dispatched schemas, and every protocol schema was
  revised onto them: IPv4, HOPOPT, IPv6-Opts, IPv6-Route, HIP, MH, TCP, HTTP/2
  and PCAP-NG.
* **Added** -- schema registration through the protocol registry APIs;
  persistent additional and excluded fields on ``Info``; numeric and comparison
  support on the PCAP-NG option code and application-layer port enumerations.

*Also released:* ``1.1.0.post1`` through ``1.1.0.post3`` (through 2023-08-12).

1.0.3 -- 2023-06-29
===================

* **Added** -- the IANA service name and transport protocol port number registry
  as the ``AppType`` enumeration [:rfc:`6335`], wired into TCP and UDP parsing
  so ports resolve to service names; a generated enumeration for the TCP header
  flags; an undefined-command member for FTP commands.
* **Changed** -- registry management was redesigned; the MPTCP and PCAP-NG
  option enumerations were revised.

*Also released:* ``1.0.3.post1`` through ``1.0.3.post3`` (through 2023-07-04).

1.0.2 -- 2023-06-05
===================

* **Added** -- Mobility Header (MH) parsing and construction [:rfc:`6275`],
  including the message types, mobility options, CGA parameters and link-layer
  address option codes, and the binding error status codes.
* **Fixed** -- ``pcapkit.extract`` failing on interpreters where
  ``decimal.localcontext`` takes no keyword arguments (#139); wheel filenames
  now carry the correct Python tags.

*Also released:* ``1.0.2.post1`` through ``1.0.2.post8`` (through 2023-06-27);
``post6`` also reset the conda build number.

1.0.1 -- 2023-05-14
===================

**Changed** -- ``Info`` and ``Schema`` subclasses are finalised when the class is
created rather than on each instantiation, which is a straight runtime saving on
parsing.

*Also released:* ``1.0.1.post1`` through ``1.0.1.post3`` (through 2023-05-27).

1.0.0 -- 2023-05-09
===================

The 1.0 rewrite: parsing and construction are one declarative definition per
protocol, and the extraction backend became pluggable. Roughly 55,000 lines
changed across 617 files, released after 21 beta builds and a release candidate.

* **Added** -- the schema and field layer, ``pcapkit.protocols.schema`` and
  ``pcapkit.corekit.fields``. A protocol declares its wire format once, as
  fields (numbers, strings, IP addresses, payloads, options, lists, switches),
  and both parsing and construction follow from it.
* **Added** -- PCAP-NG support [1]_: the protocol implementation covering every
  block type, the generic and per-block options, name-resolution records and
  decryption secrets, plus a matching extraction engine, toolkit functions and
  ``pcapkit.protocols.schema.misc.pcapng``.
* **Added** -- ``pcapkit.foundation.engines``, making the extraction backend a
  registered, swappable component: the built-in PCAP and PCAP-NG engines
  alongside DPKT, Scapy and PyShark, with engine registry APIs.
* **Added** -- ``SchemaWarning``, ``DeprecatedFormatWarning`` and
  ``RegistryWarning``; ``Protocol._get_payload`` for customised payload
  retrieval; ``packet`` passed down the protocol chain so a layer can see its
  parent's context, which is how IPv6 hands source and destination addresses to
  the transport layer.
* **Changed** -- flow tracing became the ``pcapkit.foundation.traceflow``
  package, and reassembly gained data-model modules;
  ``pcapkit.toolkit.default`` was renamed ``pcapkit.toolkit.pcap``;
  ``pcapkit.foundation.engine`` became ``engines``; ``IPField`` was split into
  ``IPAddressField`` and ``IPInterfaceField``; the option and parameter
  registries for HIP and IPv4 warn on overwrite.

.. [1] PCAP-NG is specified by ``draft-tuexen-opsawg-pcapng``, not by an RFC.

0.16.3 -- 2022-10-31
====================

**Fixed** -- import crashes on some interpreters (#114, #116); the reassembly
property caches; README rendering for PyPI. The build chain was revised.

0.16.2 -- 2022-08-03
====================

**Fixed** -- ``Info`` ``__init__`` generation for classes without annotations
(#113); the IP reassembly algorithm (#82).

0.16.1 -- 2022-06-07
====================

**Changed** -- warnings are raised through ``pcapkit.utilities.warnings``
instead of ``warnings.warn`` directly, and a missing optional dependency now
warns for the CLI and vendor extras too.

0.16.0 -- 2022-05-31
====================

A project-wide revision, and the last release of the pre-1.0 design.

* **Changed** -- type annotations throughout, and linter compliance
  (pylint, mypy, bandit, vermin) across every module.
* **Changed** -- protocol classes were separated from their data models, which
  moved to ``pcapkit.protocols.data``; a single ``Protocol`` class handles both
  parsing and construction, and subclassing it to add a protocol is far less
  work.
* **Added** -- ``pcapkit.foundation.registry``, so protocols can be subscribed
  by name; ``Protocol.analyze`` for analysing a payload directly, used by the
  reassembly classes; ``pcapkit.corekit.multidict``, adapted from Werkzeug.
* **Changed** -- reassembly became a package (IP, IPv4, IPv6, TCP) with revised
  data models; PCAP and the auxiliary protocols moved under ``pcapkit.misc``.
* **Removed** -- the ``validators`` module, several decorators from
  ``pcapkit.utilities``, and multiprocessing support in ``Extractor``.
* **Fixed** -- the DPKT toolkit (#101), IP reassembly, and missing ``id``
  methods on subclassed protocols.

The PyPCAPKit Enhancement Proposals discussion channel was opened with this
release (#106).

0.15.5 -- 2020-10-11
====================

**Fixed** -- a fallback encoder was added so that data DictDumper cannot encode
no longer raises out of the dumper (#65).

0.15.4 -- 2020-08-28
====================

**Fixed** -- the missing ``stacklevel`` attribute on ``pcapkit.utilities`` (#58).
Travis CI was set up.

0.15.3 -- 2020-08-17
====================

* **Fixed** -- ARP parsing (#55).
* **Added** -- logging, through a ``pcapkit`` logger.

0.15.2 -- 2020-06-27
====================

* **Added** -- a register interface on the protocol classes, and the same on
  ``pcapkit.foundation.analysis``, so both can be extended without patching the
  library.
* **Fixed** -- flow tracing output format and content consistency.

0.15.1 -- 2020-06-18
====================

Maintenance release: the constant enumerations and the vendor crawlers that
generate them were revised.

*Also released:* ``0.15.1.post1`` (2020-06-19), a refresh of the constant
enumerations.

0.15.0 -- 2020-06-07
====================

* **Changed** -- the parsing and construction logic was merged, so a protocol is
  no longer implemented twice; TCP flow tracing and several interfaces were
  revised.
* **Added** -- full API documentation, published at
  https://pypcapkit.jarryshaw.me.
* **Fixed** -- the DictDumper dependency and the failures it caused (#37, #40).

Preceded by ``0.15.0rc1`` (2020-06-06).

0.14.5 -- 2019-10-24
====================

* **Added** -- a CLI for the vendor crawlers.
* **Changed** -- vendor imports are deferred, so the crawler dependencies are
  not needed to import ``pcapkit``; dependencies revised.

0.14.4 -- 2019-09-01
====================

* **Added** -- the vendor crawler scripts ship in the distribution.
* **Changed** -- the CLI and vendor dependencies are separate extras in
  ``setup.py``; constant enumerations regenerated.

0.14.3 -- 2019-08-08
====================

**Fixed** -- reported bugs (#29, #30), and a Wikipedia block that broke a vendor
crawler. Constant enumerations and the sample output were regenerated.

0.14.2 -- 2019-03-28
====================

**Fixed** -- the exception classes, and the TCP reassembly algorithm.

0.14.1 -- 2019-03-07
====================

**Added** -- the ``PCAPKIT_DEVMODE`` environment variable, which turns on
development-mode behaviour without a code change.

0.14.0 -- 2019-03-02
====================

**Changed** -- the TCP reassembly pipeline handles the RST flag. Docker build
files were added.

0.13.3 -- 2019-02-26
====================

**Fixed** -- numeric literals in the constant modules that were incompatible
with Python 3.5.

*Also released:* ``0.13.3.post1``, ``0.13.3.post2`` (through 2019-03-01);
``post1`` declared official support for Python 3.5 and below, and ``post2``
refreshed the dependencies.

0.13.2 -- 2019-01-24
====================

Maintenance release: the ``tbtrim`` dependency was updated.

0.13.1 -- 2019-01-23
====================

* **Added** -- ``tbtrim`` is used to trim PyPCAPKit's own frames out of
  tracebacks through a custom ``excepthook``, so a traceback points at the
  caller's code.
* **Fixed** -- compatibility issues, with a new ``pcapkit.utilities.compat``
  module.

0.13.0 -- 2018-12-08
====================

No library changes -- a licence and packaging metadata refresh.

*Also released:* ``0.13.0.post1``, ``0.13.0.post2`` (through 2018-12-12);
``post2`` fixed encoding errors in ``setup.py``.
