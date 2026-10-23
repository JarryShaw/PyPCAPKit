.. The documentation's root document. It must carry the root ``toctree``
   directives, which is what populates the global sidebar on every page.

=========================================================
PyPCAPKit - Comprehensive Network Packet Analysis Library
=========================================================

PyPCAPKit is an open source Python library for
`PCAP <https://en.wikipedia.org/wiki/Pcap>`__ file extraction, construction and
analysis.

.. important::

   The whole project requires **Python 3.8** or later. CI supports 3.11 to 3.15, and
   still tests the end-of-life 3.8 to 3.10 without letting a failure block anything.

.. .. contents::
..    :depth: 2
..    :local:

.. toctree::
   :maxdepth: 1
   :caption: API Reference
   :hidden:

   pcapkit/index

.. toctree::
   :maxdepth: 1
   :caption: Guides & Changelog
   :hidden:

   ext
   demo
   glossary
   changelog

.. toctree::
   :maxdepth: 1
   :caption: Contributing
   :hidden:

   contributing/testing
   contributing/conventions/index
   contributing/releasing
   contributing/workflows
   contributing/pep

About
=====

:mod:`PyPCAPKit <pcapkit>` is an independent open source library, with
:mod:`DictDumper <dictdumper>` as its formatted output dumper.

.. note::

   There is a project called |jspcapy|_ that works on :mod:`pcapkit`, which is
   a command line tool for PCAP extraction.

   .. deprecated:: 0.8.0

      The |jspcapy|_ project is deprecated and has been merged into the
      :mod:`PyPCAPKit <pcapkit>` project as its CLI support.

Unlike popular PCAP extractors such as :mod:`Scapy <scapy>`,
`DPKT`_ and `PyShark`_, :mod:`pcapkit` aims to be more
comprehensive: more detailed packet information, and a more *Pythonic*
interface.

----------------
Module Structure
----------------

:mod:`pcapkit` is made of these subpackages.

- Interface (:mod:`pcapkit.interface`)

  User interface for the :mod:`pcapkit` library, which
  standardises and simplifies the usage of this library.

- Foundation (:mod:`pcapkit.foundation`)

  Synthesises file I/O and protocol analysis, coordinates
  information exchange in all network layers, and
  provides the fundamental functions for :mod:`pcapkit`.

- Protocols (:mod:`pcapkit.protocols`)

  Collection of all protocol families, with detailed
  implementation and methods.

- Utilities (:mod:`pcapkit.utilities`)

  Auxiliary functions and tools for :mod:`pcapkit`.

- CoreKit (:mod:`pcapkit.corekit`)

  Core utilities for :mod:`pcapkit` implementation, mainly
  for internal data structure and processing.

- ToolKit (:mod:`pcapkit.toolkit`)

  Auxiliary tools for :mod:`pcapkit` to support the multiple
  extraction engines with a unified interface.

- DumpKit (:mod:`pcapkit.dumpkit`)

  File output formatters for :mod:`pcapkit`.

- Constants (:mod:`pcapkit.const`)

  Constant enumerations used in :mod:`pcapkit` for protocol
  family extraction and representation.

- Vendor (:mod:`pcapkit.vendor`)

  Crawlers that regenerate the :mod:`pcapkit.const` enumerations
  from the upstream registries.

-----------------
Engine Comparison
-----------------

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
reasons under `Engine prerequisites`_. **Python 3.11 is the last version on which
every engine can run** -- and even there ``pypcap`` and ``pcap_ct`` remain
mutually exclusive for the reason given above, so no single environment ever has
every engine at once.

Test Environment
----------------

.. list-table::

   * - Image (3.10)
     - ``pcapkit-benchmark:py3.10 (sha256:6308e38915a2613714069a05800c1a14e4486ee260eddb5619727e82b971a004)``
   * - Image (3.11)
     - ``pcapkit-benchmark:py3.11 (sha256:1af87ef232d03c867d0c504d75586132994a41bc4f6c3da36db0d6dd37d22fa7)``
   * - Image (3.12)
     - ``pcapkit-benchmark:py3.12 (sha256:26a6605738070c5ff5670a12a41c88086745865096363e680577523e5957546a)``
   * - Image (3.13)
     - ``pcapkit-benchmark:py3.13 (sha256:584e631d430bd7abdd696492229dd4b0e13a0d92687dba8968c0910ef4727b67)``
   * - Image (3.14)
     - ``pcapkit-benchmark:py3.14 (sha256:6c09093cf744db366ad7f1e5fa00ccf8f6ba9e167c298acc52e87acf393d2fa3)``
   * - Image (3.15)
     - ``pcapkit-benchmark:py3.15 (sha256:78d25409346c3c97f1df809a69cd021418c6146ba2c096ff00e7d97530addd53)``
   * - ``pcapkit`` revision
     - ``cfabfb2d3``
   * - Python
     - CPython 3.10.21, 3.11.16, 3.12.14, 3.13.15, 3.14.7, 3.15.1
   * - Architecture
     - ``x86_64``
   * - Capture
     - ``in.pcap`` -- 605 bytes, SHA-256 ``7aabadca49b329c6...``
   * - Packets per extraction
     - 6
   * - Iterations
     - 1000 timed extractions per engine per pass, the first discarded as a warm-up
   * - Passes
     - 3 over the whole engine set, in 8 environments: ``3.10-pcap_ct``, ``3.10-pypcap``, ``3.11-pcap_ct``, ``3.11-pypcap``, ``3.12-pcap_ct``, ``3.13-pcap_ct``, ``3.14-pcap_ct``, ``3.15-pcap_ct``
   * - tshark
     - ``TShark (Wireshark) 4.0.17 (Git v4.0.17 packaged as 4.0.17-0+deb12u3).``
   * - libpcap
     - ``libpcap version 1.10.3 (with TPACKET_V3)``

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

Measured with ``examples/benchmark/run.sh``: 1000 timed
extractions of ``examples/captures/in.pcap`` per engine and Python version.
The first extraction is discarded as a warm-up. Values are milliseconds per
packet, the median of 3 passes.

All columns come from one run on one machine, differing in the interpreter
and nothing else, so they may be compared with each other. They may not be
compared with figures from another machine: absolute times are a property of
the host as much as of the engine.

================ ======= ======= ======= ======= ======= =======
Engine           3.10    3.11    3.12    3.13    3.14    3.15
================ ======= ======= ======= ======= ======= =======
``pypcapfile`` †  0.0320  0.0259      --      --      --      --
``dpkt``          0.0583  0.0465  0.0503  0.0533  0.0530  0.0523
``pypcap`` †      0.1018  0.0890      --      --      --      --
``pcap_ct``       0.1134  0.0988  0.1149  0.1167  0.1178  0.2702
``scapy``         0.1896  0.1607  0.1882  0.1813  0.1816  0.1776
``pcapkit``       0.5204  0.4301  0.4869  0.4949  0.4887  0.4814
``pyshark`` †    30.9862 31.0405 30.7182 31.4615      --      --
================ ======= ======= ======= ======= ======= =======

The unavailable cells were attempted. They are not zeroes and must not be
compared with a measured row.

``†`` not measured, or not measured in full, for the
reason recorded at the time:

* ``pypcapfile`` on 3.12 -- pypcapfile does not support Python 3.12; its linklayer module imports \`imp\`, removed in Python 3.12
* ``pypcapfile`` on 3.13 -- pypcapfile does not support Python 3.13; its linklayer module imports \`imp\`, removed in Python 3.12
* ``pypcapfile`` on 3.14 -- pypcapfile does not support Python 3.14; its linklayer module imports \`imp\`, removed in Python 3.12
* ``pypcapfile`` on 3.15 -- pypcapfile does not support Python 3.15; its linklayer module imports \`imp\`, removed in Python 3.12
* ``pypcap`` on 3.12, 3.13, 3.14, 3.15 -- pypcap is not installable on this interpreter, so it was not built into this image: pypcap 1.3.0 ships a pcap.c pre-generated by Cython 0.29.32, which does not compile against the Python 3.12+ C API. The engine is unsupported here rather than broken here.
* ``pyshark`` on 3.14 -- pyshark does not support Python 3.14; it builds its event loop with \`asyncio.get\_event\_loop\_policy().get\_event\_loop()\`, which raises RuntimeError from Python 3.14 when no current event loop exists
* ``pyshark`` on 3.15 -- pyshark does not support Python 3.15; it builds its event loop with \`asyncio.get\_event\_loop\_policy().get\_event\_loop()\`, which raises RuntimeError from Python 3.14 when no current event loop exists

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

============== ============= ============== =======
Engine         Relative time Observed range Samples
============== ============= ============== =======
``pypcapfile`` 0.0613        0.0597-0.0623  12
``dpkt``       0.108         0.101-0.139    24
``pypcap``     0.203         0.198-0.209    6
``pcap_ct`` ‡  0.236         0.215-0.566    18
``scapy`` ‡    0.372         0.355-0.388    24
``pcapkit``    1             *baseline*     24
``pyshark`` ¶  63.6          58.7-72.9      18
============== ============= ============== =======

The single absolute figure, for converting the ratios back: ``pcapkit``
itself ran at **0.4879 ms per packet** on this run
(0.425-0.522 across 24 passes). Absolute times are a property of the
machine as much as of the engine, which is why every other figure here is a
ratio.

Run-to-run spread: the median row varied by 8.9% of its ratio across
the passes and the widest by 149%. A gap between two rows that is
smaller than that is noise, not a result.

``‡`` this run does not separate these rows: their observed
ranges overlap, so the order their medians suggest is not established.

``¶`` measured, but on less evidence than the rows beside it.
What was collected is real; what was lost is named here rather than left to
be inferred from the pass count:

* ``pyshark`` -- 2 individual extraction(s) failed and were discarded

Installation
============

.. note::

   The sources use 3.8 syntax, so ``requires-python`` is ``>=3.8`` and pip
   refuses an older interpreter. Before 1.5.0 the ``bpc-*`` backport tools
   converted it at install time; they are no longer maintained, and the
   conversion is gone (:issue:`2051`).

.. note::

   3.8 to 3.10 are end-of-life and best-effort: CI builds and tests them, but a
   failure there blocks nothing. Individual *engines* also stop earlier than the
   library does; see `Engine prerequisites`_.

Run the following to install the current version from PyPI:

.. code-block:: shell

   pip install pypcapkit

Or install the latest version from the git repository:

.. code-block:: shell

   git clone https://github.com/JarryShaw/PyPCAPKit.git
   cd PyPCAPKit
   pip install -e .
   # and to update at any time
   git pull

For local development with ``pipenv``, the repository already includes a
:file:`Pipfile` and :file:`Makefile` targets that keep both the virtualenv and
the package caches inside the project directory:

.. code-block:: shell

   make setup

This resolves common local setup issues on macOS/Homebrew installations:
``pipenv`` cache permission errors under :file:`~/Library/Caches`, and ``lxml``
builds failing to locate Homebrew's ``libxml2``/``libxslt`` headers.

If you prefer to run ``pipenv`` directly, use the same local cache layout and
skip any stale, user-local :file:`Pipfile.lock`:

.. code-block:: shell

   PIPENV_VENV_IN_PROJECT=1 \
   PIPENV_CACHE_DIR=$PWD/.pipenv-cache \
   PIP_CACHE_DIR=$PWD/.pip-cache \
   pipenv install --skip-lock --dev

And since :mod:`pcapkit` supports various extraction engines, and extensive
plug-in functions, you may want to install the optional ones:

.. code-block:: shell

   # for DPKT only
   pip install pypcapkit[DPKT]
   # for Scapy only
   pip install pypcapkit[Scapy]
   # for PyShark only
   pip install pypcapkit[PyShark]
   # for PyPCAPFile only
   pip install pypcapkit[PyPCAPFile]
   # for PyPCAP only -- see the note below, this one builds from source
   pip install pypcapkit[PyPCAP]
   # for pcap-ct only -- the pure-Python alternative to PyPCAP, and the one that
   # works on Python 3.12+; do not install it alongside PyPCAP
   pip install pypcapkit[PCAP_CT]
   # for ESP payload decryption
   pip install pypcapkit[crypto]
   # and to install every core addon at once -- CLI display, ESP decryption
   # and NGAP decoding; none of the engines above are included, install each
   # on demand as shown
   pip install pypcapkit[all]
   # or to do this explicitly
   pip install pypcapkit emoji cryptography pycrate

.. important::

   The ``all`` extra deliberately excludes both ``pypcap`` and ``pcap-ct``, for
   different reasons. Everything
   else in ``all`` is a pure-Python wheel, whereas ``pypcap`` compiles a C
   extension; pulling it into ``all`` would demand a working compiler and the
   `libpcap`_ development files from everyone installing ``pypcapkit[all]``.
   ``pcap-ct`` needs no compiler, but it and its ``libpcap`` dependency are
   published only as **pre-releases** (1.3.0b3 and 1.11.0b29), and ``all`` should
   not be how somebody ends up with a beta they did not ask for. Install either
   explicitly: ``pip install pypcapkit[PyPCAP]`` or
   ``pip install pypcapkit[PCAP_CT]``.

.. versionchanged:: 1.5.0

   ``all`` installs the core addons only: ``emoji``, ``cryptography`` and
   ``pycrate``. The engines and vendor-crawler dependencies it carried in 1.4
   -- ``dpkt``, ``scapy``, ``pyshark``, ``requests`` and ``beautifulsoup4`` --
   moved to the ``dev`` extra, alongside ``pypcapfile`` (:issue:`910`).

.. warning::

   **Install only one of** ``pypcap`` **and** ``pcap-ct``. Both own the top-level
   |pcap|_ module, and ``pip`` will install both without complaint. With both
   present the ``pcap-ct`` package wins the import and ``pypcap``'s extension
   module is shadowed and unreachable, so ``engine='pypcap'`` stops working --
   measured on Python 3.10. :mod:`pcapkit` detects that state and warns with an
   :class:`~pcapkit.utilities.warnings.EngineWarning` naming both distributions
   and which one won, but it cannot undo it.

--------------------
Engine Prerequisites
--------------------

Some of the engines need something beyond a ``pip install``. Each constraint
below is also enforced in code, by the
:meth:`~pcapkit.foundation.engines.engine.EngineBase.unsupported_reason`
preflight described under `Engine Comparison`_.

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

For CLI usage, you will need to install the optional packages:

.. code-block:: shell

   pip install pypcapkit[cli]
   # or explicitly...
   pip install pypcapkit emoji

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _libpcap: https://www.tcpdump.org
