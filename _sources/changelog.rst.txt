.. The changelog's index. Every entry is its own document under
   ``changelog/``, one per released version; this page is the title, the
   preamble, a one- or two-line summary of each entry with a link to its own
   page, and the table of contents behind them -- there is exactly one copy of
   each entry and nothing to keep in step by hand.

   The repository root carries ``CHANGELOG.md`` rather than a second copy of
   this history. It holds only the version being released, in Markdown, because
   its consumers are the ``Create Release`` workflow's release body and the
   source distribution, and both of those read Markdown. It is generated from
   ``changelog/<version>.rst``, so this tree stays the single source.

   The toctree at the bottom carries ``:hidden:`` -- the summary list above it
   is this page's real, readable table of contents, and a second, unannotated
   list of the same links would only repeat them. ``util/changelog_md.py``
   still reads that toctree to find the newest entry (see its own docstring),
   so it has to keep existing, stay newest-first, and list exactly the pages
   the summary list does.

   The preamble below is verbatim from the single-file changelog it replaces.

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

Each release below has a short summary and a link to its own page, newest
first. The repository root's :file:`CHANGELOG.md` carries only the version
currently being released; this is the whole history.

* **1.5.0** (unreleased) -- The largest release since 1.0, and the first
  recorded here as it happened rather than reconstructed: three more
  extraction engines, ESP with payload decryption, SCTP and NGAP over SCTP,
  and a logger that no longer hijacks the consumer's. :doc:`Full changelog
  <changelog/1.5.0>`.
* **1.4.1** (2026-08-22) -- Release engineering only -- no library behaviour
  changed: a new unit-test CI workflow now gates the packaging, vendor-cron
  and documentation workflows, the vendor cron refuses to publish when the
  registry update itself failed, and unit-test compatibility on Python 3.10
  was fixed. :doc:`Full changelog <changelog/1.4.1>`.
* **1.4.0** (2026-08-21) -- The first release in nearly two years to carry
  code changes, and the first with a test suite, covering the core kit, the
  extraction engines, reassembly, flow tracing, the protocol schemas, the CLI
  and the utility modules. :doc:`Full changelog <changelog/1.4.0>`.
* **1.3.5** (2024-11-16) -- Fixed a regression, introduced by 1.3.4, that
  mis-decoded every TCP and UDP frame under IPv4/IPv6 as raw payload -- skip
  1.3.4 entirely. :doc:`Full changelog <changelog/1.3.5>`.
* **1.3.4** (2024-11-14) -- Fixed IPv6 Routing header length handling and
  extension-header chain extraction (#218), but introduced the
  transport-layer regression fixed in 1.3.5 -- upgrade past this version
  rather than to it. :doc:`Full changelog <changelog/1.3.4>`.
* **1.3.3** (2024-11-03) -- Fixed PCAP reading from the CLI and library
  (#240), a source install broken by ``setup.py`` (#221), and PCAP output
  during flow tracing (#180); 1.3.2 was never released. :doc:`Full changelog
  <changelog/1.3.3>`.
* **1.3.1** (2023-12-21) -- Renamed ``register_port()`` to
  ``register_apptype()`` with no alias left behind, and revised the
  documentation across ``pcapkit.protocols``, ``pcapkit.corekit`` and
  ``pcapkit.dumpkit``. :doc:`Full changelog <changelog/1.3.1>`.
* **1.3.0** (2023-10-04) -- A redesign of the extension points onto
  metaclasses, adding ``ModuleDescriptor`` so a registry entry can name a
  module and class imported lazily on first use. :doc:`Full changelog
  <changelog/1.3.0>`.
* **1.2.2** (2023-09-14) -- Fixed extraction failing outright (#166).
  :doc:`Full changelog <changelog/1.2.2>`.
* **1.2.1** (2023-08-27) -- Fixed bugs in ``SeekableReader`` introduced one
  day earlier in 1.2.0. :doc:`Full changelog <changelog/1.2.1>`.
* **1.2.0** (2023-08-26) -- Added streaming input through
  ``SeekableReader``, so a capture can be read from ``stdin`` or a pipe
  (#156), and fixed reassembly, broken since 0.16.3 (#155). :doc:`Full
  changelog <changelog/1.2.0>`.
* **1.1.1** (2023-08-15) -- Fixed ``AppType`` enumeration lookups,
  ``typing.TypeAlias`` compatibility on older interpreters, the flow-tracing
  output file name, and ``Schema`` dumping through a custom dumper. :doc:`Full
  changelog <changelog/1.1.1>`.
* **1.1.0** (2023-07-09) -- Rebuilt the schema and field classes on
  metaclasses, with ``EnumSchema`` for enum-dispatched schemas, and revised
  the IPv4, HOPOPT, IPv6-Opts, IPv6-Route, HIP, MH, TCP, HTTP/2 and PCAP-NG
  schemas onto them. :doc:`Full changelog <changelog/1.1.0>`.
* **1.0.3** (2023-06-29) -- Added the IANA service-name and port registry as
  the ``AppType`` enumeration [:rfc:`6335`], wiring TCP and UDP parsing to
  resolve ports to service names. :doc:`Full changelog <changelog/1.0.3>`.
* **1.0.2** (2023-06-05) -- Added Mobility Header parsing and construction
  [:rfc:`6275`], and fixed ``pcapkit.extract`` failing on interpreters where
  ``decimal.localcontext`` takes no keyword arguments (#139). :doc:`Full
  changelog <changelog/1.0.2>`.
* **1.0.1** (2023-05-14) -- Changed ``Info`` and ``Schema`` subclasses to
  finalise at class creation rather than on each instantiation, a straight
  runtime saving on parsing. :doc:`Full changelog <changelog/1.0.1>`.
* **1.0.0** (2023-05-09) -- The 1.0 rewrite: parsing and construction became
  one declarative schema and field definition per protocol, the extraction
  backend became pluggable (with PCAP-NG support and the DPKT, Scapy and
  PyShark engines), and roughly 55,000 lines changed across 617 files.
  :doc:`Full changelog <changelog/1.0.0>`.
* **0.16.3** (2022-10-31) -- Fixed import crashes on some interpreters (#114,
  #116), the reassembly property caches, and README rendering for PyPI; the
  build chain was revised. :doc:`Full changelog <changelog/0.16.3>`.
* **0.16.2** (2022-08-03) -- Fixed ``Info`` ``__init__`` generation for
  classes without annotations (#113), and the IP reassembly algorithm (#82).
  :doc:`Full changelog <changelog/0.16.2>`.
* **0.16.1** (2022-06-07) -- Changed warnings to raise through
  ``pcapkit.utilities.warnings`` instead of ``warnings.warn`` directly, and
  warn on a missing optional CLI or vendor dependency too. :doc:`Full
  changelog <changelog/0.16.1>`.
* **0.16.0** (2022-05-31) -- A project-wide revision and the last release of
  the pre-1.0 design: type annotations and linter compliance throughout,
  protocol classes separated from their data models, and
  ``pcapkit.foundation.registry`` for subscribing protocols by name. :doc:`Full
  changelog <changelog/0.16.0>`.
* **0.15.5** (2020-10-11) -- Added a fallback encoder so ``DictDumper`` no
  longer raises on data it cannot encode (#65). :doc:`Full changelog
  <changelog/0.15.5>`.
* **0.15.4** (2020-08-28) -- Fixed the missing ``stacklevel`` attribute on
  ``pcapkit.utilities`` (#58); Travis CI was set up. :doc:`Full changelog
  <changelog/0.15.4>`.
* **0.15.3** (2020-08-17) -- Fixed ARP parsing (#55), and added logging
  through a ``pcapkit`` logger. :doc:`Full changelog <changelog/0.15.3>`.
* **0.15.2** (2020-06-27) -- Added a register interface on the protocol
  classes and on ``pcapkit.foundation.analysis``, so both extend without
  patching the library, and fixed flow-tracing output consistency. :doc:`Full
  changelog <changelog/0.15.2>`.
* **0.15.1** (2020-06-18) -- Maintenance release: revised the constant
  enumerations and the vendor crawlers that generate them. :doc:`Full
  changelog <changelog/0.15.1>`.
* **0.15.0** (2020-06-07) -- Merged the parsing and construction logic so a
  protocol is no longer implemented twice, added full API documentation, and
  fixed the ``DictDumper`` dependency (#37, #40). :doc:`Full changelog
  <changelog/0.15.0>`.
* **0.14.5** (2019-10-24) -- Added a CLI for the vendor crawlers, and
  deferred vendor imports so the crawler dependencies are not needed just to
  import ``pcapkit``. :doc:`Full changelog <changelog/0.14.5>`.
* **0.14.4** (2019-09-01) -- Shipped the vendor crawler scripts in the
  distribution, and split the CLI and vendor dependencies into separate
  ``setup.py`` extras. :doc:`Full changelog <changelog/0.14.4>`.
* **0.14.3** (2019-08-08) -- Fixed reported bugs (#29, #30) and a Wikipedia
  block that broke a vendor crawler; the constant enumerations and sample
  output were regenerated. :doc:`Full changelog <changelog/0.14.3>`.
* **0.14.2** (2019-03-28) -- Fixed the exception classes and the TCP
  reassembly algorithm. :doc:`Full changelog <changelog/0.14.2>`.
* **0.14.1** (2019-03-07) -- Added the ``PCAPKIT_DEVMODE`` environment
  variable, turning on development-mode behaviour without a code change.
  :doc:`Full changelog <changelog/0.14.1>`.
* **0.14.0** (2019-03-02) -- Changed the TCP reassembly pipeline to handle
  the RST flag, and added Docker build files. :doc:`Full changelog
  <changelog/0.14.0>`.
* **0.13.3** (2019-02-26) -- Fixed numeric literals in the constant modules
  incompatible with Python 3.5. :doc:`Full changelog <changelog/0.13.3>`.
* **0.13.2** (2019-01-24) -- Maintenance release: updated the ``tbtrim``
  dependency. :doc:`Full changelog <changelog/0.13.2>`.
* **0.13.1** (2019-01-23) -- Added ``tbtrim`` to trim ``pcapkit``'s own
  frames out of tracebacks through a custom ``excepthook``, and fixed
  compatibility issues via a new ``pcapkit.utilities.compat`` module.
  :doc:`Full changelog <changelog/0.13.1>`.
* **0.13.0** (2018-12-08) -- No library changes -- a licence and packaging
  metadata refresh. :doc:`Full changelog <changelog/0.13.0>`.

.. toctree::
   :hidden:
   :maxdepth: 1

   changelog/1.5.0
   changelog/1.4.1
   changelog/1.4.0
   changelog/1.3.5
   changelog/1.3.4
   changelog/1.3.3
   changelog/1.3.1
   changelog/1.3.0
   changelog/1.2.2
   changelog/1.2.1
   changelog/1.2.0
   changelog/1.1.1
   changelog/1.1.0
   changelog/1.0.3
   changelog/1.0.2
   changelog/1.0.1
   changelog/1.0.0
   changelog/0.16.3
   changelog/0.16.2
   changelog/0.16.1
   changelog/0.16.0
   changelog/0.15.5
   changelog/0.15.4
   changelog/0.15.3
   changelog/0.15.2
   changelog/0.15.1
   changelog/0.15.0
   changelog/0.14.5
   changelog/0.14.4
   changelog/0.14.3
   changelog/0.14.2
   changelog/0.14.1
   changelog/0.14.0
   changelog/0.13.3
   changelog/0.13.2
   changelog/0.13.1
   changelog/0.13.0
