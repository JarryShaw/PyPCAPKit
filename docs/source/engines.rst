.. The engine comparison, moved off the root document so the landing page stays
   short: which engines exist, what each costs in support, where each runs, what
   each needs installed, and how fast each is. ``index.rst`` keeps a summary and a
   link here.

   The Test Environment, Test Results and Test Results (Relative) sections are
   pasted from ``examples/benchmark/report.py``'s snippets. Its row markers are
   literal symbols with a hand-written legend; here they are reStructuredText
   footnotes, so a fresh paste needs its markers turned into footnotes too.

Engine Comparison
=================

Being a **comprehensive** packet processor costs speed: :mod:`pcapkit`'s own
engine is slower than every third-party engine below except `PyShark`_, as
`Test Results`_ measures.

:mod:`pcapkit` also supports alternative extraction engines for speed:
`Scapy`_, `DPKT`_, `PyShark`_, `PyPCAP`_, `pcap-ct`_ and `PyPCAPFile`_,
selected through ``engine='scapy'``, ``'dpkt'``, ``'pyshark'``, ``'pypcap'``,
``'pcap_ct'`` and ``'pypcapfile'`` respectively; ``engine='default'`` (also
spelled ``'pcapkit'``) is :mod:`pcapkit`'s own parser and the only one with no
third-party requirement.

`PyPCAP`_ and `pcap-ct`_ are two independent distributions of the same
:manpage:`libpcap(3)` interface and both install a top-level |pcap|_ module,
so they are two engines rather than one: upstream `PyPCAP`_ stops at Python 3.11,
`pcap-ct`_ covers 3.10 and newer. **Install exactly one of them** -- with both
present, ``pcap-ct`` wins the import and the other becomes unselectable.

Speed is not free. Every third-party engine supports **less** than the
``default`` one, and the newest ones support markedly less --
:class:`~pcapkit.foundation.engines.pypcap.PyPCAP` and
:class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` perform no protocol
dissection at all, so they offer neither reassembly nor flow tracing, and
:class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile` has no IPv6 decoder,
so IPv6 reassembly is unavailable. Each gap is announced with a warning or an
exception rather than silently returning nothing, except for these, which pass
without a warning:

- :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile` leaves TCP behind a
  VLAN tag, in a tunnel or behind an extension header (an IPv6 one, or AH in
  IPv4) out of TCP reassembly and flow tracing;
- :class:`~pcapkit.foundation.engines.dpkt.DPKT` leaves TCP in an IP-in-IP
  tunnel or behind an AH or IPv6 extension header in IPv4 out of TCP reassembly
  and flow tracing, and IPv4 in IPv6 or IPv6 in IPv4 out of IP reassembly;
- :class:`~pcapkit.foundation.engines.scapy.Scapy` reads IPv6 only as far as
  `Scapy`_ dissects it, so IPv6 behind some BSD loopback headers, and TCP and
  IPv6 fragments behind some IPv6 extension headers, go undissected.

:doc:`pcapkit/foundation/engines/index` tabulates them.

Every engine also answers a preflight check --
:meth:`~pcapkit.foundation.engines.engine.EngineBase.unsupported_reason`, which
:meth:`Extractor.run <pcapkit.foundation.extraction.Extractor.run>` consults
before anything is imported -- so asking for one that cannot run in the current
environment gives a single warning naming the actual cause (a Python version, a
missing :program:`tshark`, a missing :manpage:`libpcap(3)`, the wrong |pcap|_
distribution) and a clean fall back, rather than an error from inside the
third-party package.

.. note::

   The figures under `Test Environment`_, `Test Results`_ and
   `Test Results (Relative)`_ are copied here by hand from a benchmark report;
   nothing regenerates them on this page. The ``Engine Benchmark`` workflow,
   :file:`.github/workflows/benchmark.yml`, measures every engine on every
   interpreter they are tested on, weekly and on dispatch, and posts its
   environment and ratio tables to the ``benchmark: weekly engine benchmark
   report`` thread in the ``CI reports`` Discussions category (see
   :ref:`ci reports`); the per-version table is in the run's job summary and its
   ``benchmark-out`` artifact. :file:`examples/benchmark/run.sh` produces the same
   tables on any machine with Docker, and :file:`examples/benchmark/README.md`
   explains what each one measures. `Test Environment`_ records where the
   figures on this page came from.

Engine Support by Python Version
--------------------------------

Which engines can run at all, by interpreter. Verified by installing each engine
and extracting a capture on 3.10 through 3.15.

================== ======== ======== ======== ======== ======== ========
Engine              3.10     3.11     3.12     3.13     3.14     3.15
================== ======== ======== ======== ======== ======== ========
``pcapkit``         yes      yes      yes      yes      yes      yes
``dpkt``            yes      yes      yes      yes      yes      yes
``scapy``           yes      yes      yes      yes      yes      yes
``pcap_ct``         yes      yes      yes      yes      yes      yes
``pypcap``          yes      yes      no       no       no       no
``pypcapfile``      yes      yes      no       no       no       no
``pyshark``         yes      yes      yes      yes      no       no
================== ======== ======== ======== ======== ======== ========

``pypcap`` and ``pypcapfile`` stop at 3.11, and ``pyshark`` at 3.13, for the
reasons under `Engine Prerequisites`_. **Python 3.11 is the last version on which
every engine can run** -- and even there ``pypcap`` and ``pcap_ct`` remain
mutually exclusive for the reason given above, so no single environment ever has
every engine at once.

.. _engine-prerequisites:

Engine Prerequisites
--------------------

Some of the engines need something beyond a ``pip install``. Each constraint
below is also enforced in code, by the
:meth:`~pcapkit.foundation.engines.engine.EngineBase.unsupported_reason`
preflight described at the top of this page.

:class:`~pcapkit.foundation.engines.pyshark.PyShark`
   None of its requirements is visible to an import: the package imports
   cleanly and then fails when used.

   - Drives Wireshark's :program:`tshark` binary. It need not be on ``PATH``:
     |pyshark|_ looks at ``tshark_path`` in its :file:`config.ini` first, then
     ``PATH`` on POSIX, both Program Files directories on Windows, and
     :file:`/Applications/Wireshark.app` on macOS. Install Wireshark (or just
     :program:`tshark`) from your platform's package manager.
   - Requires Python **3.13 or older**. |pyshark|_ 0.6 builds its event loop
     with ``asyncio.get_event_loop_policy().get_event_loop()``, and from Python
     **3.14** :func:`asyncio.get_event_loop` raises :exc:`RuntimeError` when there
     is no current event loop instead of quietly creating one. Measured: a loop is
     returned silently on 3.10 and 3.11, returned with a
     :exc:`DeprecationWarning` on 3.12, and refused on 3.14. 3.13 sits on the
     deprecated-but-functional side of that change, and |pyshark|_ extracted a
     capture there.

:class:`~pcapkit.foundation.engines.pypcap.PyPCAP`
   `PyPCAP`_ ships **no wheels** -- only an sdist -- so :program:`pip` compiles
   it, and the build needs both `libpcap`_'s headers (:file:`pcap.h`) and its
   shared or static library:

   .. code-block:: shell

      # Debian/Ubuntu
      sudo apt-get install libpcap-dev
      # RHEL/Fedora/Amazon Linux
      sudo dnf install libpcap-devel
      # macOS
      brew install libpcap

   Caveats, each an upstream packaging problem rather than a :mod:`pcapkit` one:

   - ``pypcap`` 1.3.0 ships a **pre-generated** :file:`pcap.c` produced by Cython
     0.29.x, which does not compile against the Python **3.12+** C API. Having
     `libpcap`_ installed is therefore necessary but *not* sufficient: on 3.12 or
     newer the build fails whatever else is present. Use Python **3.11 or older**
     for this engine, or regenerate :file:`pcap.c` with Cython 3 yourself.
   - Its :file:`setup.py` does not consult ``CFLAGS``/``LDFLAGS`` or
     :program:`pkg-config`. It searches a fixed list of prefixes --
     :file:`/usr`, :data:`sys.prefix`, :file:`/opt/libpcap*`,
     :file:`../libpcap*`, :file:`../wpdpack*` and the macOS SDKs -- so a
     `libpcap`_ installed anywhere else, notably Homebrew's keg-only prefix on
     Apple Silicon (:file:`/opt/homebrew/opt/libpcap`), is not found even though
     it is installed. Installing into :data:`sys.prefix`, or into
     :file:`/opt/libpcap`, is what that search will pick up.

:class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT`
   The way to drive the same `libpcap`_ interface on Python **3.12 and newer**,
   where ``pypcap`` cannot be built. Nothing to compile and no :file:`pcap.h`
   needed: `pcap-ct`_ is a :mod:`ctypes` reimplementation, and both it and its
   ``libpcap`` dependency ship ``py3-none-any`` wheels. Verified reading a capture
   on Python 3.10 and 3.14.

   Caveats:

   - **A system** :manpage:`libpcap(3)` **is still required at run time.** The
     ``libpcap`` distribution ships a vendored :file:`libpcap.so` and, as
     published, does not use it: its :file:`libpcap.cfg` says ``LIBPCAP = None``,
     which sends its loader to :func:`ctypes.util.find_library`. So the library
     actually loaded is the host's ``libpcap.so.1``, and with none present
     ``import pcap`` raises :exc:`OSError` rather than :exc:`ImportError`. Set
     ``LIBPCAP = tcpdump`` in :file:`libpcap.cfg` to use the vendored copy instead.
   - Both distributions are **pre-releases**, and ``pcap-ct`` documents itself as
     tracking the ``pypcap`` *1.2.3* interface. Every attribute the engine uses was
     measured behaving identically to ``pypcap`` 1.3.0, but that is a statement
     about the versions tested.

:class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile`
   `PyPCAPFile`_ 0.12.0 imports the ``imp`` module, which was **removed in
   Python 3.12**, so ``pcapfile.savefile`` -- the module needed to read a
   capture -- cannot be imported at all on 3.12 or newer. Upstream ``master``
   has fixed this but no release carries the fix, so this engine also
   requires Python **3.11 or older** until 0.12.1 is published.

.. note::

   Only the engines above carry extra constraints. :mod:`pcapkit` itself and
   its ``default``, ``dpkt`` and ``scapy`` engines need nothing beyond their
   ``pip install`` -- |dpkt|_ 1.9.8 and ``scapy`` 2.7.0 were both measured
   reading a capture on Python 3.14. The ``scapy`` engine needs **scapy 2.6.0 or
   newer**, which the ``Scapy`` extra requires: 2.5.0 can drop a PCAP-NG
   interface's timestamp resolution, reading nanoseconds as microseconds
   (:issue:`1572`). :mod:`pcapkit` does not check the version at run time, so
   upgrade a scapy installed some other way.

Test Environment
----------------

These figures come from one run of the Engine Benchmark workflow on a GitHub-hosted
runner, measured natively rather than in the :file:`examples/benchmark/run.sh`
container images, so the interpreters' patch releases, :program:`tshark` and
`libpcap`_ are the runner's own, as recorded below.

.. list-table::

   * - Run
     - Engine Benchmark run `40062653380
       <https://github.com/JarryShaw/PyPCAPKit/actions/runs/40062653380>`__, on
       GitHub's hosted ``ubuntu-26.04-arm`` runner
   * - Image
     - ``GitHub-hosted ubuntu-26.04-arm, image ubuntu26-arm64 20261023.150.3``
   * - ``pcapkit`` revision
     - ``c264485``
   * - Python
     - CPython 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8, 3.15.1
   * - Architecture
     - ``aarch64``
   * - Capture
     - ``in.pcap`` -- 605 bytes, SHA-256 ``7aabadca49b329c6...``
   * - Packets per extraction
     - 6
   * - Iterations
     - 1000 timed extractions per engine per pass, the first discarded as a warm-up
   * - Passes
     - 3 over the whole engine set, in 8 environments: ``3.10-pcap_ct``, ``3.10-pypcap``, ``3.11-pcap_ct``, ``3.11-pypcap``, ``3.12-pcap_ct``, ``3.13-pcap_ct``, ``3.14-pcap_ct``, ``3.15-pcap_ct``
   * - tshark
     - ``TShark (Wireshark) 4.6.4.``
   * - libpcap
     - ``libpcap version 1.10.6 (64-bit time_t, with TPACKET_V3)``

Resolved package versions:

============== ============ =========== ============ =========== ============ ============ ============ ============
Package        3.10-pcap_ct 3.10-pypcap 3.11-pcap_ct 3.11-pypcap 3.12-pcap_ct 3.13-pcap_ct 3.14-pcap_ct 3.15-pcap_ct
============== ============ =========== ============ =========== ============ ============ ============ ============
``dpkt``       1.9.8        1.9.8       1.9.8        1.9.8       1.9.8        1.9.8        1.9.8        1.9.8
``libpcap``    1.11.0b29    *absent*    1.11.0b29    *absent*    1.11.0b29    1.11.0b29    1.11.0b29    1.11.0b29
``lxml``       6.1.3        6.1.3       6.1.3        6.1.3       6.1.3        6.1.3        6.1.3        6.1.3
``pcap-ct``    1.3.0b3      *absent*    1.3.0b3      *absent*    1.3.0b3      1.3.0b3      1.3.0b3      1.3.0b3
``pypcap``     *absent*     1.3.0       *absent*     1.3.0       *absent*     *absent*     *absent*     *absent*
``pypcapfile`` 0.12.0       0.12.0      0.12.0       0.12.0      0.12.0       0.12.0       0.12.0       0.12.0
``pypcapkit``  1.5.0b14     1.5.0b14    1.5.0b14     1.5.0b14    1.5.0b14     1.5.0b14     1.5.0b14     1.5.0b14
``pyshark``    0.6          0.6         0.6          0.6         0.6          0.6          0.6          0.6
``scapy``      2.8.0        2.8.0       2.8.0        2.8.0       2.8.0        2.8.0        2.8.0        2.8.0
============== ============ =========== ============ =========== ============ ============ ============ ============

Test Results
------------

Measured with ``examples/benchmark/native.sh``, which the Engine Benchmark
workflow runs: 1000 timed extractions of ``examples/captures/in.pcap`` per
engine and Python version.
The first extraction is discarded as a warm-up. Values are milliseconds per
packet, the median of 3 passes.

All columns come from one run on one machine, differing in the interpreter
and nothing else, so they may be compared with each other. They may not be
compared with figures from another machine: absolute times are a property of
the host as much as of the engine.

==================== ======= ======= ======= ======= ======= =======
Engine               3.10    3.11    3.12    3.13    3.14    3.15
==================== ======= ======= ======= ======= ======= =======
``pypcapfile`` [*]_   0.0375  0.0262      --      --      --      --
``pypcap`` [*]_       0.0479  0.0342      --      --      --      --
``pcap_ct``           0.0667  0.0489  0.0564  0.0565  0.0613  0.0534
``dpkt``              0.0796  0.0599  0.0607  0.0616  0.0631  0.0858
``scapy``             0.2399  0.2028  0.2085  0.2021  0.2083  0.2208
``pcapkit``           0.6962  0.5709  0.5837  0.5660  0.6025  0.6128
``pyshark`` [*]_     17.0812 17.6570 17.2537 17.1367      --      --
==================== ======= ======= ======= ======= ======= =======

The unavailable cells were attempted. They are not zeroes and must not be
compared with a measured row.

.. [*] Not measured, for the reason recorded at the time:

   * on 3.12 -- pypcapfile does not support Python 3.12; its linklayer module imports \`imp\`, removed in Python 3.12
   * on 3.13 -- pypcapfile does not support Python 3.13; its linklayer module imports \`imp\`, removed in Python 3.12
   * on 3.14 -- pypcapfile does not support Python 3.14; its linklayer module imports \`imp\`, removed in Python 3.12
   * on 3.15 -- pypcapfile does not support Python 3.15; its linklayer module imports \`imp\`, removed in Python 3.12

.. [*] Not measured, for the reason recorded at the time:

   * on 3.12, 3.13, 3.14, 3.15 -- pypcap is not installable on this interpreter, so it was not built here: pypcap 1.3.0 ships a pcap.c pre-generated by Cython 0.29.32, which does not compile against the Python 3.12+ C API. The engine is unsupported here rather than broken here.

.. [*] Not measured, for the reason recorded at the time:

   * on 3.14 -- pyshark does not support Python 3.14; it builds its event loop with \`asyncio.get\_event\_loop\_policy().get\_event\_loop()\`, which raises RuntimeError from Python 3.14 when no current event loop exists
   * on 3.15 -- pyshark does not support Python 3.15; it builds its event loop with \`asyncio.get\_event\_loop\_policy().get\_event\_loop()\`, which raises RuntimeError from Python 3.14 when no current event loop exists

Test Results (Relative)
-----------------------

Times relative to ``pcapkit``, which is 1 by definition; lower is
faster. Each ratio is taken against the baseline measured in the same
environment on the same pass, so the machine cancels out. "Observed range" is
the smallest and largest ratio actually seen across the passes.

Ratios are pooled across every environment in the run, which means across
every Python version measured as well as both ``pcap`` providers. The
observed range therefore includes any disagreement between interpreters
about an engine; the per-version table is where that is broken out.

================== ============= ============== =======
Engine             Relative time Observed range Samples
================== ============= ============== =======
``pypcapfile``     0.0496        0.0456-0.0542  12
``pypcap``         0.0650        0.0600-0.0702  6
``pcap_ct``        0.0967        0.0852-0.103   18
``dpkt``           0.107         0.103-0.141    24
``scapy``          0.353         0.340-0.369    24
``pcapkit``        1             *baseline*     24
``pyshark`` [*]_   29.7          23.4-31.5      18
================== ============= ============== =======

.. [*] Measured, but on less evidence than the rows beside it. What was
   collected is real; what was lost is named here rather than left to be
   inferred from the pass count: 3 individual extraction(s) failed and were
   discarded.

The single absolute figure, for converting the ratios back: ``pcapkit``
itself ran at **0.5917 ms per packet** on this run
(0.566-0.715 across 24 passes). Absolute times are a property of the
machine as much as of the engine, which is why every other figure here is a
ratio.

Run-to-run spread: the median row varied by 17% of its ratio across
the passes and the widest by 35%. A gap between two rows that is
smaller than that is noise, not a result.

.. _libpcap: https://www.tcpdump.org
