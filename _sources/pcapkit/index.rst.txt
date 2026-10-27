====================
Module Documentation
====================

.. module:: pcapkit

:mod:`pcapkit` is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

Unlike popular PCAP file extractors, such as `Scapy`_, `DPKT`_ and
`PyShark`_, :mod:`pcapkit` tends to provide comprehensive
support to all protocols, including but not limited to their
parameters and/or options, etc. Therefore, :mod:`pcapkit` contains
enumeration registries used by protocols, independent protocol
schema definitions as well as various customisable interfaces.

.. toctree::
   :maxdepth: 1
   :caption: Subpackages

   interface/index
   foundation/index
   protocols/index
   utilities/index
   corekit/index
   toolkit/index
   dumpkit/index
   const/index
   vendor/index

Package Metadata
================

.. autodata:: pcapkit.__version__

   .. seealso::

      :doc:`../contributing/releasing` for how this value is bumped and
      consumed by the release pipeline.

Library Index
=============

.. module:: pcapkit.all

:mod:`pcapkit` has defined various and numerous functions
and classes, which have different features and purposes.
To make a simple index for this library, :mod:`pcapkit.all`
contains all things from :mod:`pcapkit`.

Command Line Tool
=================

.. module:: pcapkit.__main__

.. note::

   The |emoji|_ package (the ``cli`` extra) decorates the ``-v`` output.
   Without it, importing the module warns with
   :class:`~pcapkit.utilities.warnings.EmojiWarning` and the CLI prints plain
   text instead.

:mod:`pcapkit.__main__` provides the CLI, merged in from the deprecated
|jspcapy|_ project.

.. code-block:: text

   usage: pcapkit-cli [-h] [-V] [-o file-name] [-f format] [-j] [-p] [-t] [-a]
                      [-v] [-F] [-E PKG] [-P PROTOCOL] [-L LAYER] [-B]
                      [-O file-name]
                      input-file-name

   PCAP file extractor and formatted dumper

   positional arguments:
     input-file-name       The name of the input PCAP or PCAP-NG file. With
                           `--auto-extension`, ".pcap" is appended unless its
                           extension is already ".pcap", ".cap" or ".pcapng". Use
                           "-" to read from standard input.

   options:
     -h, --help            show this help message and exit
     -V, --version         show program's version number and exit
     -o, --output file-name
                           The name of the output report file. If it is omitted,
                           "out" is used. With `--auto-extension`, the extension
                           of the output format (e.g. ".json") is appended if
                           absent. With `--files`, the directory each frame's
                           report is written to.
     -f, --format format   The format of the report: "json", "plist" (or "xml"),
                           "tree" (or "text", "txt") or "pcap" (or "cap"). Takes
                           precedence over `--json`, `--plist` and `--tree`. With
                           no format option, "tree" is used.
     -j, --json            Write the report as JSON, as `--format json` does.
                           Ignored if `--format` is given.
     -p, --plist           Write the report as a macOS property list, as
                           `--format plist` does. Ignored if `--format` or
                           `--json` is given.
     -t, --tree            Write the report as tree view text, as `--format tree`
                           does; this is the default. Ignored if `--format`,
                           `--json` or `--plist` is given.
     -a, --auto-extension  Append missing file extensions: ".pcap" to the input
                           file name, and the extension of the output format
                           (e.g. ".json") to the output file name unless
                           `--files` is set.
     -v, --verbose         Print the input name, the protocol chain of each
                           frame, and where the report is stored.
     -F, --files           Write a report file per frame, in the directory named
                           by `--output`.
     -E, --engine PKG      The extraction engine, case-insensitive: "default" (or
                           "pcapkit"), or a third-party one such as "dpkt" or
                           "scapy", which needs its package installed. An unknown
                           or unavailable engine falls back to "default".
     -P, --protocol PROTOCOL
                           Stop dissecting each frame after this protocol, e.g.
                           "IPv4" (case-insensitive); the rest of the frame is
                           kept as raw data. Third-party engines ignore it.
     -L, --layer LAYER     Stop dissecting each frame after its protocol in this
                           layer: "link", "internet", "transport" or
                           "application" (case-insensitive); "none", the default,
                           sets no limit. Third-party engines ignore it.
     -B, --buffer-save     Save a copy of the input to a file as it is read. Only
                           an input that is not seekable, such as a pipe on
                           standard input, is saved.
     -O, --buffer-path file-name
                           The name of the file `--buffer-save` writes. If it is
                           omitted, a temporary file is used and then deleted.

.. versionchanged:: 1.5.0

   ``-P`` and ``-L`` stop the extraction where they say, which 1.4.x ignored, and
   ``-L`` accepts only ``link``, ``internet``, ``transport``, ``application`` or
   ``none``, in any case (:issue:`356`).

Environment Variables
=====================

.. envvar:: PCAPKIT_DEVMODE

   If set to ``1`` (or ``yes``, ``true`` or ``on``, in any case), :mod:`pcapkit`
   will run in development mode.

   .. seealso::

      :data:`pcapkit.utilities.logging.DEVMODE`

.. envvar:: PCAPKIT_VERBOSE

   If set to ``1`` (or ``yes``, ``true`` or ``on``, in any case), :mod:`pcapkit`
   will run with verbose output.

   .. seealso::

      :data:`pcapkit.utilities.logging.VERBOSE`

.. envvar:: PCAPKIT_SPHINX

   If set to ``1`` (or ``yes``, ``true`` or ``on``, in any case), :mod:`pcapkit`
   will run with Sphinx additional typing hints and docstrings support.

   .. seealso::

      :data:`pcapkit.utilities.logging.SPHINX_TYPE_CHECKING`

The ``PCAPKIT_*`` tunable limits, such as
:data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`, are read by
:mod:`pcapkit.utilities.config`, which lists each
with its default, its accepted range and its risks. The :mod:`pcapkit.vendor`
crawlers' :envvar:`PCAPKIT_VENDOR_RETRY`, :envvar:`PCAPKIT_CI_MODE`,
:envvar:`PCAPKIT_HTTP_PROXY` and :envvar:`PCAPKIT_HTTPS_PROXY` are read by
:mod:`pcapkit.vendor.default`, and listed under :ref:`vendor-variables`.

.. versionchanged:: 1.5.0

   :envvar:`PCAPKIT_HTTP_PROXY` and :envvar:`PCAPKIT_HTTPS_PROXY` are documented
   with :mod:`pcapkit.vendor.default` rather than here, and are still read on
   every request. The tunable limits are new as variables (:issue:`1726`). A
   bad value of :envvar:`PCAPKIT_DEVMODE`, :envvar:`PCAPKIT_VERBOSE`,
   :envvar:`PCAPKIT_SPHINX`, :envvar:`PCAPKIT_CI_MODE` or
   :envvar:`PCAPKIT_VENDOR_RETRY` warns with
   :exc:`~pcapkit.utilities.warnings.ConfigWarning` instead of being taken
   silently, or, for :envvar:`PCAPKIT_VENDOR_RETRY`, crashing the import.
