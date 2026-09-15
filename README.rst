PyPCAPKit - Comprehensive Network Packet Analysis Library
=========================================================

   For any technical and/or maintenance information,
   please kindly refer to the |docs|_.

.. |docs| replace:: **Official Documentation**
.. _docs: https://jarryshaw.github.io/PyPCAPKit/

The PyPCAPKit project is an open source Python program focus on network packet
parsing and analysis, which works as a comprehensive `PCAP`_ file extraction,
construction and analysis library.

   The whole project supports **Python 3.6** or later.

-----
About
-----

PyPCAPKit is a comprehensive Python-native network packet analysis library,
with `DictDumper`_ as its formatted output dumper.

Unlike popular PCAP file extractors, such as `Scapy`_, `DPKT`_, `PyShark`_,
and etc, ``pcapkit`` is designed to be much more comprehensive, which means
it is able to provide more detailed information about the packet, as well as
a more *Pythonic* interface for users to interact with.

Module Structure
----------------

In ``pcapkit``, all files can be described as following eight parts.

- Interface (``pcapkit.interface``)

  User interface for the ``pcapkit`` library, which
  standardises and simplifies the usage of this library.

- Foundation (``pcapkit.foundation``)

  Synthesises file I/O and protocol analysis, coordinates
  information exchange in all network layers, as well as
  provides the foundamental functions for ``pcapkit``.

- Protocols (``pcapkit.protocols``)

  Collection of all protocol family, with detailed
  implementation and methods.

- Utilities (``pcapkit.utilities``)

  Auxiliary functions and tools for ``pcapkit``.

- CoreKit (``pcapkit.corekit``)

  Core utilities for ``pcapkit`` implementation, mainly
  for internal data structure and processing.

- ToolKit (``pcapkit.toolkit``)

  Auxiliary tools for ``pcapkit`` to support the multiple
  extraction engines with a unified interface.

- DumpKit (``pcapkit.dumpkit``)

  File output formatters for ``pcapkit``.

- Constants (``pcapkit.const``)

  Constant enumerations used in ``pcapkit`` for protocol
  family extraction and representation.

Engine Comparison
-----------------

Due to the general overhead of ``pcapkit``, its extraction procedure takes
around *0.2* milliseconds per packet, which is already impressive but not enough
comparing to other popular extraction engines available on the market, given the
fact that ``pcapkit`` is a **comprehensive** packet processing module.

Additionally, ``pcapkit`` introduced alternative extraction engines to accelerate
this procedure. By now ``pcapkit`` supports `Scapy`_, `DPKT`_, `PyShark`_,
`PyPCAP`_ and `PyPCAPFile`_, selected through ``engine='scapy'``,
``'dpkt'``, ``'pyshark'``, ``'pypcap'`` and ``'pypcapfile'`` respectively;
``engine='default'`` (also spelled ``'pcapkit'``) is ``pcapkit``'s own parser
and the only one with no third-party requirement.

Speed is not free. Every third-party engine supports **less** than the
``default`` one, and the two newest support markedly less:

- `PyPCAP`_ performs no protocol dissection at all, so it offers neither
  reassembly nor flow tracing, and reads PCAP savefiles from disk only.
- `PyPCAPFile`_ has no IPv6 decoder, so IPv6 reassembly is unavailable; IPv4
  and TCP reassembly still work, and it too is PCAP-only.
- `PyShark`_ performs no reassembly.

Each gap is announced with a warning or an exception rather than silently
returning nothing. The `engine support documentation`_ tabulates them.

Test Environment
~~~~~~~~~~~~~~~~

.. list-table::

   * - Operating System
     - macOS Ventura 13.4.1
   * - Chip
     - Apple M2 Pro
   * - Memory
     - 16 GB

Test Results
~~~~~~~~~~~~

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

------------
Installation
------------

..

   **Note** -- ``pcapkit`` supports Python versions **since 3.6**.

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

For local development with ``pipenv``, the repository already includes a
``Pipfile`` and ``Makefile`` targets that keep both the virtualenv and the
package caches inside the project directory:

.. code-block:: shell

   make setup

This resolves two common local setup issues on macOS/Homebrew installations:
``pipenv`` cache permission errors under ``~/Library/Caches`` and ``lxml``
builds failing to locate Homebrew's ``libxml2``/``libxslt`` headers.

If you prefer to run ``pipenv`` directly, use the same local cache layout and
skip any stale, user-local ``Pipfile.lock``:

.. code-block:: shell

   PIPENV_VENV_IN_PROJECT=1 \
   PIPENV_CACHE_DIR=$PWD/.pipenv-cache \
   PIP_CACHE_DIR=$PWD/.pip-cache \
   pipenv install --skip-lock --dev

And since ``pcapkit`` supports various extraction engines, and extensive
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

..

   **Important** -- The ``all`` extra deliberately does **not** include
   ``pypcap``. Everything
   else in ``all`` is a pure-Python wheel, whereas ``pypcap`` compiles a C
   extension; pulling it into ``all`` would demand a working compiler and the
   `libpcap`_ development files from everyone installing ``pypcapkit[all]``.
   Install it explicitly with ``pip install pypcapkit[PyPCAP]``.

Engine prerequisites
--------------------

Three of the engines need something beyond a ``pip install``:

``pyshark``
   Drives Wireshark's ``tshark`` binary, which must be on ``PATH``. Install
   Wireshark (or just ``tshark``) from your platform's package manager.

``pypcap``
   Ships **no wheels** -- only an sdist -- so ``pip`` compiles it, and the build
   needs both `libpcap`_'s headers (``pcap.h``) and its shared or static library:

   .. code-block:: shell

      # Debian/Ubuntu
      sudo apt-get install libpcap-dev
      # RHEL/Fedora/Amazon Linux
      sudo dnf install libpcap-devel
      # macOS
      brew install libpcap

   Two caveats, both upstream problems rather than ``pcapkit`` ones:

   - ``pypcap`` 1.3.0 ships a **pre-generated** ``pcap.c`` produced by Cython
     0.29.x, which does not compile against the Python **3.12+** C API. Having
     ``libpcap`` installed is therefore necessary but *not* sufficient: on 3.12
     or newer the build fails whatever else is present. Use Python **3.11 or
     older** for this engine, or regenerate ``pcap.c`` with Cython 3 yourself.
   - Its ``setup.py`` does not consult ``CFLAGS``/``LDFLAGS`` or
     ``pkg-config``. It searches a fixed list of prefixes -- ``/usr``,
     ``sys.prefix``, ``/opt/libpcap*``, ``../libpcap*``, ``../wpdpack*`` and the
     macOS SDKs -- so a `libpcap`_ installed anywhere else, notably Homebrew's
     keg-only prefix on Apple Silicon (``/opt/homebrew/opt/libpcap``), is not
     found even though it is installed. Installing into ``sys.prefix``, or into
     ``/opt/libpcap``, is what that search will pick up.

``pypcapfile``
   Version 0.12.0 imports the ``imp`` module, which was **removed in Python
   3.12**, so ``pcapfile.savefile`` -- the module needed to read a capture --
   cannot be imported at all on 3.12 or newer. Upstream ``master`` has fixed
   this but no release carries the fix yet, so this engine also requires Python
   **3.11 or older** until 0.12.1 is published.

..

   **Note** -- ``pcapkit`` itself, and its ``default``, ``dpkt`` and ``scapy``
   engines, work
   fine on current Python versions. Only the three engines above carry these
   extra constraints, and asking for an engine whose package is unavailable
   emits a warning and falls back to ``pcapkit``'s own parser rather than
   failing outright.

For CLI usage, you will need to install the optional packages:

.. code-block:: shell

   pip install pypcapkit[cli]
   # or explicitly...
   pip install pypcapkit emoji

-------
Testing
-------

The unit tests need nothing beyond the package itself and the sample captures
tracked in the repository:

.. code-block:: shell

   make test

The runtime, regression and integration tests additionally read sample captures
that are **not** tracked (see ``.gitignore``);
``examples/generators/make_samples.py`` reconstructs them into ``examples/captures/``,
and ``make test-all`` regenerates them before running the whole suite:

.. code-block:: shell

   make samples     # write examples/captures/*.pcap and *.pcapng
   make test-all    # regenerate the fixtures, then run every test

The same fixtures back the demonstration scripts in
``examples/legacy_smoke/``, which read them as ``../captures/…``.

Continuous integration runs the ``make test`` selection, since the fixtures are
not in the repository. ``tshark`` is only required to exercise the PyShark
engine, and is not needed by the test suite.

.. _PCAP: https://en.wikipedia.org/wiki/Pcap
.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark
.. _PyPCAP: https://github.com/pynetwork/pypcap
.. _PyPCAPFile: https://github.com/kisom/pypcapfile
.. _libpcap: https://www.tcpdump.org
.. _DictDumper: https://github.com/JarryShaw/DictDumper
.. _engine support documentation: https://jarryshaw.github.io/PyPCAPKit/pcapkit/foundation/engines/index.html
