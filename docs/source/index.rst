.. PyPCAPKit documentation master file, created by
   sphinx-quickstart on Sat Mar 28 21:29:54 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

=========================================================
PyPCAPKit - Comprehensive Network Packet Analysis Library
=========================================================

The PyPCAPKit project is an open source Python program focus on network packet
parsing and analysis, which works as a comprehensive `PCAP`_ file extraction,
construction and analysis library.

.. important::

   The whole project supports **Python 3.6** or later; CI verifies 3.10 to 3.15.

.. .. contents::
..    :depth: 2
..    :local:

.. toctree::
   :maxdepth: 1

   pcapkit/index

.. toctree::
   :maxdepth: 2

   ext
   demo
   pep

About
=====

:mod:`PyPCAPKit <pcapkit>` is an independent open source library, with
:mod:`DictDumper <dictdumper>` as its formatted output dumper.

.. note::

   There is a project called |jspcapy|_ works on :mod:`pcapkit`, which is a
   command line tool for PCAP extraction.

   .. |jspcapy| replace:: ``jspcapy``
   .. _jspcapy: https://github.com/JarryShaw/jspcapy

   .. deprecated:: 0.8.0

      The |jspcapy|_ project is deprecated and has been merged into the
      :mod:`PyPCAPKit <pcapkit>` project as its CLI support.

Unlike popular PCAP file extractors, such as :mod:`Scapy <scapy>`,
:mod:`dpkt <dpkt>`, `PyShark`_, and etc, :mod:`pcapkit` is
designed to be much more comprehensive, which means it is able to provide
more detailed information about the packet, as well as a more *Pythonic*
interface for users to interact with.

----------------
Module Structure
----------------

In :mod:`pcapkit`, all files can be described as following eight parts.

- Interface (:mod:`pcapkit.interface`)

  User interface for the :mod:`pcapkit` library, which
  standardises and simplifies the usage of this library.

- Foundation (:mod:`pcapkit.foundation`)

  Synthesises file I/O and protocol analysis, coordinates
  information exchange in all network layers, as well as
  provides the foundamental functions for :mod:`pcapkit`.

- Protocols (:mod:`pcapkit.protocols`)

  Collection of all protocol family, with detailed
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

-----------------
Engine Comparison
-----------------

Due to the general overhead of :mod:`pcapkit`, its extraction procedure takes
around *0.2* milliseconds per packet, which is already impressive but not enough
comparing to other popular extraction engines available on the market, given the
fact that :mod:`pcapkit` is a **comprehensive** packet processing module.

Additionally, :mod:`pcapkit` introduced alternative extraction engines to
accelerate this procedure. By now :mod:`pcapkit` supports `Scapy`_, `DPKT`_,
`PyShark`_, `PyPCAP`_, `pcap-ct`_ and `PyPCAPFile`_, selected through
``engine='scapy'``, ``'dpkt'``, ``'pyshark'``, ``'pypcap'``, ``'pcap_ct'`` and
``'pypcapfile'`` respectively; ``engine='default'`` (also spelled ``'pcapkit'``)
is :mod:`pcapkit`'s own parser and the only one with no third-party requirement.

`PyPCAP`_ and `pcap-ct`_ are two independent distributions of the same
:manpage:`libpcap(3)` interface and both install a top-level :mod:`pcap` module,
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
exception rather than silently returning nothing;
:doc:`pcapkit/foundation/engines/index` tabulates them.

Every engine also answers a preflight check --
:meth:`~pcapkit.foundation.engines.engine.EngineBase.unsupported_reason`, which
:meth:`Extractor.run <pcapkit.foundation.extraction.Extractor.run>` consults
before anything is imported -- so asking for one that cannot run in the current
environment gives a single warning naming the actual cause (a Python version, a
missing :program:`tshark`, a missing :manpage:`libpcap(3)`, the wrong ``pcap``
distribution) and a clean fall back, rather than an error from inside the
third-party package.

Engine support by Python version
--------------------------------

Which engines can run at all, by interpreter. Verified by installing each engine
and extracting a capture on 3.10, 3.11, 3.12 and 3.14; 3.13 and 3.15 were not
available and are marked accordingly.

============== ======== ======== ======== ======== ======== ========
Engine          3.10     3.11     3.12     3.13     3.14     3.15
============== ======== ======== ======== ======== ======== ========
``pcapkit``     yes      yes      yes      yes*     yes      yes*
``dpkt``        yes      yes      yes      yes*     yes      yes*
``scapy``       yes      yes      yes      yes*     yes      yes*
``pcap_ct``     yes      yes      yes      yes*     yes      yes*
``pypcap``      yes      yes      no       no       no       no
``pypcapfile``  yes      yes      no       no       no       no
``pyshark``     yes†     yes†     yes†     yes*†    no       no
============== ======== ======== ======== ======== ======== ========

``*`` inferred, not measured -- no 3.13 or 3.15 interpreter was available.
``†`` also needs Wireshark's :program:`tshark`, which was absent, so only the
interpreter half was verified for ``pyshark``.

``pypcap`` and ``pypcapfile`` stop at 3.11, and ``pyshark`` at 3.13, for the
reasons under `Engine prerequisites`_. **Python 3.11 is the last version on which
every engine can run** -- and even there ``pypcap`` and ``pcap_ct`` are mutually
exclusive, since both provide the :mod:`pcap` module, so no single environment ever
has all seven at once.

Test Environment
----------------

.. list-table::

   * - Operating System
     - macOS Ventura 13.4.1
   * - Chip
     - Apple M2 Pro
   * - Memory
     - 16 GB

Test Results
------------

Measured with ``examples/legacy_smoke/test_time.py`` over 1,000 timed
extractions of ``examples/captures/in.pcap`` per engine, on the environment
above.

============== ===========================
Engine         Performance (ms per packet)
============== ===========================
``dpkt``        0.010390_056723
``scapy``       0.091690_233567
``pcapkit``     0.200390_390390
``pyshark``    24.682185_018351 [#pyshark-historical]_
``pypcap``      *not measured* [#pypcap-not-measured]_
``pcap_ct``     *not measured* [#pcap-ct-not-measured]_
``pypcapfile``  *not measured* [#pypcapfile-not-measured]_
============== ===========================

.. warning::

   **These figures are historical, and three of the rows can no longer be
   reproduced on a current Python.** The table was taken on the environment above,
   whose interpreter still ran every engine. Since then ``pyshark``, ``pypcap``
   and ``pypcapfile`` have each acquired a hard Python ceiling -- 3.13, 3.11 and
   3.11 respectively, for the reasons under `Engine prerequisites`_ -- so on the
   latest Python only ``pcapkit``, ``dpkt``, ``scapy`` and ``pcap_ct`` can be timed
   at all. A re-run on a modern interpreter would not extend this table; it would
   replace it with a shorter one, measured on different hardware and not
   comparable row-for-row with what is here.

The empty cells stay empty for the same reason: a figure taken on a different
host, capture or iteration count is not comparable with these, and inventing one
would be worse than admitting the gap.

Installation
============

.. note::

   :mod:`pcapkit` declares support for **Python 3.6 and later**, and CI verifies
   **3.10 through 3.15**.

   The sources themselves use 3.8 syntax; the ``bpc-walrus``/``bpc-poseur``
   backport tools in :file:`setup.py` convert it at install time, which is what
   makes the lower bound possible. Measured: 3.9 and 3.8 import and extract
   straight from source with no conversion needed, and 3.7 needs the conversion.

.. warning::

   **The conversion is currently blocked by an upstream bug**, so below 3.8 the
   declaration is intent rather than something that works today. ``bpc-poseur``
   0.4.3.post1 crashes on positional-only parameters declared on a *method*
   rather than a plain function, and exits 0 so the build does not notice; the 12
   such parameters in :mod:`pcapkit.corekit.io` then survive into the installed
   package and ``import pcapkit`` fails with :exc:`SyntaxError`.

   It is a one-line fix upstream -- ``poseur.py:744`` passes ``cls_ctx=name.name``
   where ``name`` is already a parso ``Name`` and wants ``.value`` -- and with it
   applied, ``walrus`` then ``poseur`` produce a file Python 3.7 parses cleanly.

.. note::

   3.8 and 3.9 are end-of-life and best-effort. Individual *engines* also stop
   earlier than the library does; see `Engine prerequisites`_.

Simply run the following to install the current version from PyPI:

.. code-block:: shell

   pip install pypcapkit

Or install the latest version from the gi repository:

.. code-block:: shell

   git clone https://github.com/JarryShaw/PyPCAPKit.git
   cd pypcapkit
   pip install -e .
   # and to update at any time
   git pull

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
   # and to install the optional packages -- note this excludes PyPCAP and pcap-ct
   pip install pypcapkit[all]
   # or to do this explicitly
   pip install pypcapkit dpkt scapy pyshark pypcapfile

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

.. warning::

   **Install only one of ``pypcap`` and ``pcap-ct``.** Both own the top-level
   :mod:`pcap` module, and ``pip`` will install both without complaint. With both
   present the ``pcap-ct`` package wins the import and ``pypcap``'s extension
   module is shadowed and unreachable, so ``engine='pypcap'`` stops working --
   measured on Python 3.10. :mod:`pcapkit` detects that state and warns with an
   :class:`~pcapkit.utilities.warnings.EngineWarning` naming both distributions
   and which one won, but it cannot undo it.

--------------------
Engine prerequisites
--------------------

Four of the engines need something beyond a ``pip install``. Each constraint is
also enforced in code, through the engine's
:meth:`~pcapkit.foundation.engines.engine.EngineBase.unsupported_reason`, so
hitting one produces a warning naming the cause and a fall back to
:mod:`pcapkit`'s own parser rather than an error from inside the third-party
package.

:class:`~pcapkit.foundation.engines.pyshark.PyShark`
   Two requirements, and neither is visible to an import: the package imports
   cleanly and then fails when used.

   - Drives Wireshark's :program:`tshark` binary. It need not be on ``PATH``:
     ``pyshark`` looks at ``tshark_path`` in its :file:`config.ini` first, then
     ``PATH`` on POSIX, both Program Files directories on Windows, and
     :file:`/Applications/Wireshark.app` on macOS. Install Wireshark (or just
     :program:`tshark`) from your platform's package manager.
   - Requires Python **3.13 or older**. ``pyshark`` 0.6 builds its event loop
     with ``asyncio.get_event_loop_policy().get_event_loop()``, and from Python
     **3.14** :func:`asyncio.get_event_loop` raises :exc:`RuntimeError` when there
     is no current event loop instead of quietly creating one. Measured: a loop is
     returned silently on 3.10 and 3.11, returned with a
     :exc:`DeprecationWarning` on 3.12, and refused on 3.14. (3.13 was not
     available to test and is expected to work, being on the
     deprecated-but-functional side of that change.)

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

   Two caveats, both upstream packaging problems rather than :mod:`pcapkit` ones:

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

   Two caveats:

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
   has fixed this but no release carries the fix yet, so this engine also
   requires Python **3.11 or older** until 0.12.1 is published.

.. note::

   :mod:`pcapkit` itself, and its ``default``, ``dpkt`` and ``scapy`` engines,
   work fine on current Python versions -- ``dpkt`` 1.9.8 and ``scapy`` 2.7.0 were
   both measured reading a capture on Python 3.14. Only the four engines above
   carry extra constraints, and asking for an engine that cannot run in the
   current environment emits an
   :class:`~pcapkit.utilities.warnings.EngineWarning` naming the reason and falls
   back to :mod:`pcapkit`'s own parser rather than failing outright.

For CLI usage, you will need to install the optional packages:

.. code-block:: shell

   pip install pypcapkit[cli]
   # or explicitly...
   pip install pypcapkit emoji

==================
Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _PCAP: https://en.wikipedia.org/wiki/Pcap
.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark
.. _PyPCAP: https://github.com/pynetwork/pypcap
.. _pcap-ct: https://pypi.org/project/pcap-ct/
.. _PyPCAPFile: https://github.com/kisom/pypcapfile
.. _libpcap: https://www.tcpdump.org
.. _DictDumper: https://github.com/JarryShaw/DictDumper

.. [#pyshark-historical] This figure is **historical**. `PyShark`_ 0.6 builds its event loop with
   ``asyncio.get_event_loop_policy().get_event_loop()``, and Python 3.14 made
   :func:`asyncio.get_event_loop` raise :exc:`RuntimeError` when no current event
   loop exists rather than quietly creating one -- measured working on 3.10 and
   3.11, working with a :exc:`DeprecationWarning` on 3.12, and raising on 3.14. The
   number cannot be reproduced on a current interpreter; it stands as what was
   measured when it could be.

.. [#pypcap-not-measured] `PyPCAP`_ could not be installed on the machine available for
   benchmarking, so no figure was taken. Its 1.3.0 sdist compiles a C extension
   and needs `libpcap`_'s headers *and* shared library present, and the
   pre-generated ``pcap.c`` it ships does not compile on Python 3.12 or newer
   (see `Installation`_). Rather than publish a number measured on different
   hardware and a different Python from the rows above -- which would not be
   comparable with them -- the cell is left empty.

.. [#pcap-ct-not-measured] `pcap-ct`_ was verified working on Python 3.10 and 3.14, so unlike the two
   rows above it *could* be timed -- but only on the machine this engine was added
   on, which is neither the hardware nor the operating system the rows above were
   measured with. A number from it would not be comparable, so the cell is left
   empty rather than filled with something misleading.

.. [#pypcapfile-not-measured] `PyPCAPFile`_ 0.12.0 cannot be imported on Python 3.12 or newer, so it
   could only be timed on an older interpreter than the rows above were measured
   with. That number would not be comparable, so the cell is left empty.
