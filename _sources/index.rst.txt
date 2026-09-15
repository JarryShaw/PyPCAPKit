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

   The whole project supports **Python 3.6** or later.

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
`PyShark`_, `PyPCAP`_ and `PyPCAPFile`_, selected through ``engine='scapy'``,
``'dpkt'``, ``'pyshark'``, ``'pypcap'`` and ``'pypcapfile'`` respectively;
``engine='default'`` (also spelled ``'pcapkit'``) is :mod:`pcapkit`'s own parser
and the only one with no third-party requirement.

Speed is not free. Every third-party engine supports **less** than the
``default`` one, and the two newest support markedly less --
:class:`~pcapkit.foundation.engines.pypcap.PyPCAP` performs no protocol
dissection at all, so it offers neither reassembly nor flow tracing, and
:class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile` has no IPv6 decoder,
so IPv6 reassembly is unavailable. Each gap is announced with a warning or an
exception rather than silently returning nothing;
:doc:`pcapkit/foundation/engines/index` tabulates them.

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
``pyshark``    24.682185_018351
``pypcap``      *not measured* [1]_
``pypcapfile``  *not measured* [2]_
============== ===========================

.. [1] `PyPCAP`_ could not be installed on the machine available for
   benchmarking, so no figure was taken. Its 1.3.0 sdist compiles a C extension
   and needs `libpcap`_'s headers *and* shared library present, and the
   pre-generated ``pcap.c`` it ships does not compile on Python 3.12 or newer
   (see `Installation`_). Rather than publish a number measured on different
   hardware and a different Python from the rows above -- which would not be
   comparable with them -- the cell is left empty.

.. [2] `PyPCAPFile`_ 0.12.0 cannot be imported on Python 3.12 or newer, so it
   could only be timed on an older interpreter than the rows above were measured
   with. That number would not be comparable, so the cell is left empty.

Both figures will be filled in once the two engines can be timed on the same
host, capture and iteration count as the existing rows.

Installation
============

.. note::

   :mod:`pcapkit` supports Python versions **since 3.6**.

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
   # for ESP payload decryption
   pip install pypcapkit[crypto]
   # and to install the optional packages -- note this excludes PyPCAP
   pip install pypcapkit[all]
   # or to do this explicitly
   pip install pypcapkit dpkt scapy pyshark pypcapfile

.. important::

   The ``all`` extra deliberately does **not** include ``pypcap``. Everything
   else in ``all`` is a pure-Python wheel, whereas ``pypcap`` compiles a C
   extension; pulling it into ``all`` would demand a working compiler and the
   `libpcap`_ development files from everyone installing ``pypcapkit[all]``.
   Install it explicitly with ``pip install pypcapkit[PyPCAP]``.

--------------------
Engine prerequisites
--------------------

Three of the engines need something beyond a ``pip install``:

:class:`~pcapkit.foundation.engines.pyshark.PyShark`
   Drives Wireshark's :program:`tshark` binary, which must be on ``PATH``.
   Install Wireshark (or just :program:`tshark`) from your platform's package
   manager.

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

:class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile`
   `PyPCAPFile`_ 0.12.0 imports the ``imp`` module, which was **removed in
   Python 3.12**, so ``pcapfile.savefile`` -- the module needed to read a
   capture -- cannot be imported at all on 3.12 or newer. Upstream ``master``
   has fixed this but no release carries the fix yet, so this engine also
   requires Python **3.11 or older** until 0.12.1 is published.

.. note::

   :mod:`pcapkit` itself, and its ``default``, ``dpkt`` and ``scapy`` engines,
   work fine on current Python versions. Only the three engines above carry these
   extra constraints, and asking for an engine whose package is unavailable emits
   an :class:`~pcapkit.utilities.warnings.EngineWarning` and falls back to
   :mod:`pcapkit`'s own parser rather than failing outright.

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
.. _PyPCAPFile: https://github.com/kisom/pypcapfile
.. _libpcap: https://www.tcpdump.org
.. _DictDumper: https://github.com/JarryShaw/DictDumper
