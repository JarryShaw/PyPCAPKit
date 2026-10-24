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

   engines
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

Besides its own parser, :mod:`pcapkit` can extract through `Scapy`_, `DPKT`_,
`PyShark`_, `PyPCAP`_, `pcap-ct`_ and `PyPCAPFile`_: every one of them but
`PyShark`_ is faster, and every one supports less. :doc:`engines` compares them
-- what each supports, which Python versions each runs on, what each needs
installed, and how fast each measured per packet.

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
   library does; see :ref:`engine-prerequisites`.

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

Some engines need more than a ``pip install`` -- a :program:`tshark` binary, a C
compiler and the `libpcap`_ headers, or an older interpreter.
:ref:`engine-prerequisites` gives each constraint and its reason.

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
