PyPCAPKit - Comprehensive Network Packet Analysis Library
=========================================================

   For any technical and/or maintenance information,
   please kindly refer to the |docs|_.

.. |docs| replace:: **Official Documentation**
.. _docs: https://jarryshaw.github.io/PyPCAPKit/

The PyPCAPKit project is an open source Python program focus on network packet
parsing and analysis, which works as a comprehensive `PCAP`_ file extraction,
construction and analysis library.

   The whole project supports **Python 3.6** or later; CI verifies 3.10 to 3.15.

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
`PyPCAP`_, `pcap-ct`_ and `PyPCAPFile`_, selected through ``engine='scapy'``,
``'dpkt'``, ``'pyshark'``, ``'pypcap'``, ``'pcap_ct'`` and ``'pypcapfile'``
respectively; ``engine='default'`` (also spelled ``'pcapkit'``) is ``pcapkit``'s
own parser and the only one with no third-party requirement.

`PyPCAP`_ and `pcap-ct`_ are two independent distributions of the same
:manpage:`libpcap(3)` interface, and both install a top-level ``pcap`` module, so
they are two engines rather than one. Upstream `PyPCAP`_ stops at Python 3.11;
`pcap-ct`_ covers 3.10 and newer. **Install exactly one of them** -- with both
present, ``pcap-ct`` wins the import and the other becomes unselectable, which
each engine detects and reports.

Speed is not free. Every third-party engine supports **less** than the
``default`` one, and the newest ones support markedly less:

- `PyPCAP`_ performs no protocol dissection at all, so it offers neither
  reassembly nor flow tracing, and reads PCAP savefiles from disk only.
- `pcap-ct`_ reads the same interface, so it has exactly the same gaps.
- `PyPCAPFile`_ has no IPv6 decoder, so IPv6 reassembly is unavailable; IPv4
  and TCP reassembly still work, and it too is PCAP-only.
- `PyShark`_ performs no reassembly.

Each gap is announced with a warning or an exception rather than silently
returning nothing. The `engine support documentation`_ tabulates them.

Every engine also answers a preflight check before it is used --
``unsupported_reason()`` -- so asking for one that cannot run in the current
environment produces a single warning naming the actual cause (a Python version, a
missing ``tshark``, a missing ``libpcap``, the wrong ``pcap`` distribution) and a
clean fall back to ``pcapkit``'s own parser, rather than an error from inside the
third-party package.

Engine support by Python version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
``†`` also needs Wireshark's ``tshark``, which was absent, so only the
interpreter half was verified for ``pyshark``.

``pypcap`` and ``pypcapfile`` stop at 3.11, and ``pyshark`` at 3.13, for the
reasons under `Engine prerequisites`_. **Python 3.11 is the last version on which
every engine can run** -- and even there ``pypcap`` and ``pcap_ct`` are mutually
exclusive, since both provide the ``pcap`` module, so no single environment ever
has all seven at once.

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
``pyshark``    24.682185_018351 [3]_
``pypcap``      *not measured* [1]_
``pcap_ct``     *not measured* [4]_
``pypcapfile``  *not measured* [2]_
============== ===========================

**These figures are historical, and three of the rows can no longer be
reproduced on a current Python.** The table was taken on the environment above,
whose interpreter still ran every engine. Since then ``pyshark``, ``pypcap`` and
``pypcapfile`` have each acquired a hard Python ceiling -- 3.13, 3.11 and 3.11
respectively, for the reasons under `Engine prerequisites`_ -- so on the latest
Python only ``pcapkit``, ``dpkt``, ``scapy`` and ``pcap_ct`` can be timed at all.
A re-run on a modern interpreter would therefore not extend this table; it would
replace it with a shorter one, measured on different hardware and not comparable
row-for-row with what is here.

The empty cells stay empty for the same reason: a figure taken on a different
host, capture or iteration count is not comparable with these, and inventing one
would be worse than admitting the gap.

------------
Installation
------------

   **Note** -- ``pcapkit`` declares support for **Python 3.6 and later**, and CI
   verifies **3.10 through 3.15**.

   The sources themselves use 3.8 syntax; the ``bpc-walrus``/``bpc-poseur``
   backport tools in ``setup.py`` convert it at install time, which is what makes
   the lower bound possible. Measured: 3.9 and 3.8 import and extract straight
   from source with no conversion needed, and 3.7 needs the conversion.

   **That conversion is currently blocked by an upstream bug**, so below 3.8 the
   declaration is intent rather than something that works today: ``bpc-poseur``
   0.4.3.post1 crashes on positional-only parameters declared on a *method*
   rather than a plain function, and exits 0 so the build does not notice. The
   12 such parameters in ``pcapkit/corekit/io.py`` then survive into the
   installed package and ``import pcapkit`` fails. It is a one-line fix
   upstream -- ``poseur.py:744`` passes ``cls_ctx=name.name`` where ``name`` is
   already a parso ``Name`` and wants ``.value`` -- and with it applied,
   ``walrus`` then ``poseur`` produce a file Python 3.7 parses cleanly. Tracking
   that fix is what will make 3.6/3.7 real again.

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
   # for pcap-ct only -- the pure-Python alternative to PyPCAP, and the one that
   # works on Python 3.12+; do not install it alongside PyPCAP
   pip install pypcapkit[PCAP_CT]
   # for ESP payload decryption
   pip install pypcapkit[crypto]
   # and to install the optional packages -- note this excludes PyPCAP and pcap-ct
   pip install pypcapkit[all]
   # or to do this explicitly
   pip install pypcapkit dpkt scapy pyshark pypcapfile

   **Important** -- The ``all`` extra deliberately excludes both ``pypcap`` and
   ``pcap-ct``, for different reasons. Everything
   else in ``all`` is a pure-Python wheel, whereas ``pypcap`` compiles a C
   extension; pulling it into ``all`` would demand a working compiler and the
   `libpcap`_ development files from everyone installing ``pypcapkit[all]``.
   ``pcap-ct`` needs no compiler, but it and its ``libpcap`` dependency are
   published only as **pre-releases** (1.3.0b3 and 1.11.0b29), and ``all`` should
   not be how somebody ends up with a beta they did not ask for. Install either
   explicitly: ``pip install pypcapkit[PyPCAP]`` or
   ``pip install pypcapkit[PCAP_CT]``.

   **Install only one of them.** Both distributions own the top-level ``pcap``
   module, and ``pip`` will install both without complaint. With both present the
   ``pcap-ct`` package wins the import and ``pypcap``'s extension module is
   shadowed and unreachable, so ``engine='pypcap'`` stops working. ``pcapkit``
   detects that state and warns, naming both distributions and which one won, but
   it cannot undo it.

Engine prerequisites
--------------------

Four of the engines need something beyond a ``pip install``. Each constraint is
also enforced in code -- the engine's ``unsupported_reason()`` is consulted before
anything is imported -- so hitting one produces a warning naming the cause and a
fall back to ``pcapkit``'s own parser, not an error from inside the third-party
package.

``pyshark``
   Two requirements, and neither is visible to an import: the package imports
   cleanly and then fails when used.

   - Drives Wireshark's ``tshark`` binary. It need not be on ``PATH``:
     ``pyshark`` looks at ``tshark_path`` in its ``config.ini`` first, then
     ``PATH`` on POSIX, both Program Files directories on Windows, and
     ``/Applications/Wireshark.app`` on macOS. Install Wireshark (or just
     ``tshark``) from your platform's package manager.
   - Requires Python **3.13 or older**. ``pyshark`` 0.6 builds its event loop
     with ``asyncio.get_event_loop_policy().get_event_loop()``, and from Python
     **3.14** :func:`asyncio.get_event_loop` raises ``RuntimeError`` when there
     is no current event loop instead of quietly creating one. Measured: a loop
     is returned silently on 3.10 and 3.11, returned with a
     ``DeprecationWarning`` on 3.12, and refused on 3.14. (3.13 was not available
     to test and is expected to work, being on the deprecated-but-functional side
     of that change.)

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

``pcap_ct``
   The way to drive the same `libpcap`_ interface on Python **3.12 and newer**,
   where ``pypcap`` cannot be built. Nothing to compile and no ``pcap.h`` needed:
   `pcap-ct`_ is a ``ctypes`` reimplementation, and both it and its ``libpcap``
   dependency ship ``py3-none-any`` wheels. Verified reading a capture on Python
   3.10 and 3.14.

   Two caveats:

   - **A system ``libpcap`` is still required at run time.** The ``libpcap``
     distribution ships a vendored ``libpcap.so`` and, as published, does not use
     it: its ``libpcap.cfg`` says ``LIBPCAP = None``, which sends its loader to
     ``ctypes.util.find_library('pcap')``. So the library actually loaded is the
     host's ``libpcap.so.1``, and with none present ``import pcap`` raises
     ``OSError`` rather than ``ImportError``. Set ``LIBPCAP = tcpdump`` in
     ``libpcap.cfg`` to use the vendored copy instead.
   - Both distributions are **pre-releases**, and ``pcap-ct`` documents itself as
     tracking the ``pypcap`` *1.2.3* interface. Every attribute the engine uses
     was measured behaving identically to ``pypcap`` 1.3.0, but that is a
     statement about the versions tested.

``pypcapfile``
   Version 0.12.0 imports the ``imp`` module, which was **removed in Python
   3.12**, so ``pcapfile.savefile`` -- the module needed to read a capture --
   cannot be imported at all on 3.12 or newer. Upstream ``master`` has fixed
   this but no release carries the fix yet, so this engine also requires Python
   **3.11 or older** until 0.12.1 is published.

   **Note** -- ``pcapkit`` itself, and its ``default``, ``dpkt`` and ``scapy``
   engines, work
   fine on current Python versions -- ``dpkt`` 1.9.8 and ``scapy`` 2.7.0 were both
   measured reading a capture on Python 3.14. Only the four engines above carry
   extra constraints, and asking for an engine that cannot run in the current
   environment emits a warning naming the reason and falls back to ``pcapkit``'s
   own parser rather than failing outright.

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
.. _pcap-ct: https://pypi.org/project/pcap-ct/
.. _PyPCAPFile: https://github.com/kisom/pypcapfile
.. _libpcap: https://www.tcpdump.org
.. _DictDumper: https://github.com/JarryShaw/DictDumper
.. _engine support documentation: https://jarryshaw.github.io/PyPCAPKit/pcapkit/foundation/engines/index.html

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

.. [3] This figure is **historical**. `PyShark`_ 0.6 builds its event loop with
   ``asyncio.get_event_loop_policy().get_event_loop()``, and Python 3.14 made
   :func:`asyncio.get_event_loop` raise ``RuntimeError`` when no current event
   loop exists rather than quietly creating one -- measured working on 3.10 and
   3.11, working with a ``DeprecationWarning`` on 3.12, and raising on 3.14. The
   number therefore cannot be reproduced on a current interpreter; it stands as
   what was measured when it could be.

.. [4] `pcap-ct`_ was verified working on Python 3.10 and 3.14, so unlike the two
   rows above it *could* be timed -- but only on the machine this engine was added
   on, which is neither the hardware nor the operating system the rows above were
   measured with. A number from it would not be comparable, so the cell is left
   empty rather than filled with something misleading.
