==============
Logging System
==============

.. module:: pcapkit.utilities.logging

:mod:`pcapkit.utilities.logging` owns :mod:`pcapkit`'s logger hierarchy, rooted
at :data:`~pcapkit.utilities.logging.logger`, and the API through which an
application decides what, if anything, :mod:`pcapkit` emits.

.. autodata:: pcapkit.utilities.logging.logger
   :no-value:

The Logger Hierarchy
====================

``pcapkit`` is the root. Each module logs through a child logger named after
the module, obtained from :func:`~pcapkit.utilities.logging.get_logger`, so any
subtree can be addressed on its own:

.. code-block:: python

   import logging

   # quieten the registry's bookkeeping, keep everything else
   logging.getLogger('pcapkit.foundation.registry').setLevel(logging.WARNING)

   # or follow just the extraction path
   logging.getLogger('pcapkit.foundation.extraction').setLevel(logging.DEBUG)

Logger names are the module paths, e.g. ``pcapkit.foundation.extraction``, ``pcapkit.foundation.registry.protocols``,
``pcapkit.foundation.engines.pcap``, ``pcapkit.foundation.reassembly.reassembly``,
``pcapkit.foundation.traceflow.tcp``, ``pcapkit.utilities.warnings``.

.. autofunction:: pcapkit.utilities.logging.get_logger

.. autodata:: pcapkit.utilities.logging.ROOT_LOGGER_NAME

What ``DEBUG`` Will Tell You
============================

At :data:`logging.DEBUG` the library reports what it did with a file: which
input was opened, which engine was requested and which was actually used
(including a fallback when an optional dependency is missing), the file format
identified from the magic number, the output format and dumper, whether
reassembly and flow tracing were enabled and with which flags, how many frames
were read, and when cleanup ran. Reassembly reports datagram counts on flush and
flow tracing reports flows opening and closing.

.. note::

   Nothing is logged from inside per-frame or per-field parsing loops, so
   :data:`~logging.DEBUG` on a million-packet capture does not yield a million
   records. Registration bookkeeping in :mod:`pcapkit.foundation.registry` is
   at :data:`~logging.DEBUG` rather than :data:`~logging.INFO`, since a library
   announcing its own registry entries is not news to its consumer.

Configuring the Output
======================

Importing :mod:`pcapkit` configures **no** logging output: the only handler
attached to :data:`~pcapkit.utilities.logging.logger` is a
:class:`logging.NullHandler`, and no level is set. This is the convention for
libraries: the application keeps control of its logging, and :mod:`pcapkit`'s
records propagate into whatever it has configured, e.g. via
:func:`logging.basicConfig` or :mod:`logging.config`.

An application that would rather let :mod:`pcapkit` set up its own output calls
:func:`~pcapkit.utilities.logging.configure`:

.. code-block:: python

   import logging
   import sys

   from pcapkit.utilities.logging import configure, reset

   # everything pcapkit does, on stderr
   configure(logging.DEBUG, stream=sys.stderr)

   # to a file, with a format of your own
   configure(logging.INFO, handler=logging.FileHandler('pcapkit.log'),
             fmt='%(asctime)s %(name)s %(levelname)s %(message)s')

   # loud in general, quiet about the registry
   configure(logging.DEBUG, stream=sys.stderr)
   configure(logging.WARNING, name='pcapkit.foundation.registry')

   # and back to the pristine, library-neutral state
   reset()

.. autofunction:: pcapkit.utilities.logging.configure

.. autofunction:: pcapkit.utilities.logging.reset

.. autofunction:: pcapkit.utilities.logging.ensure_output

Formatting
----------

.. autodata:: pcapkit.utilities.logging.DEFAULT_FORMAT

.. autodata:: pcapkit.utilities.logging.DEFAULT_DATE_FORMAT

.. autodata:: pcapkit.utilities.logging.formatter
   :no-value:

.. autodata:: pcapkit.utilities.logging.handler
   :no-value:

Environment Variables
=====================

.. autodata:: pcapkit.utilities.logging.DEVMODE
   :no-value:

   .. seealso::

      Set through the environment variable :envvar:`PCAPKIT_DEVMODE`.

.. autodata:: pcapkit.utilities.logging.VERBOSE
   :no-value:

   .. seealso::

      Set through the environment variable :envvar:`PCAPKIT_VERBOSE`.

.. autodata:: pcapkit.utilities.logging.SPHINX_TYPE_CHECKING
   :no-value:

   .. seealso::

      Set through the environment variable :envvar:`PCAPKIT_SPHINX`.

.. _logging-compatibility:

Compatibility Note
==================

.. warning::

   Before 1.5.0, importing :mod:`pcapkit` attached a
   :class:`logging.StreamHandler` on :obj:`sys.stderr` and forced the level to
   :data:`logging.INFO` (or :data:`logging.DEBUG` under
   :envvar:`PCAPKIT_DEVMODE`). It no longer does, because that hijacked the
   logging configuration of every application importing :mod:`pcapkit`. Two
   consequences are visible to existing code:

   1. **Nothing reaches stderr by default.** The ``registered ...`` bookkeeping
      is at :data:`logging.DEBUG`, not :data:`logging.INFO`. To restore the
      stderr output:

      .. code-block:: python

         import logging, sys
         from pcapkit.utilities.logging import configure
         configure(logging.INFO, stream=sys.stderr)

      Equivalently, re-attach the module's own handler, which is still built
      with the historical format:

      .. code-block:: python

         from pcapkit.utilities.logging import handler, logger
         logger.setLevel(logging.INFO)
         logger.addHandler(handler)

   2. **The handler is not at** ``logger.handlers[0]``. Code that reached into
      that list to remove or reconfigure it should call
      :func:`~pcapkit.utilities.logging.reset` or
      :func:`~pcapkit.utilities.logging.configure` instead.

   Unchanged: :data:`~pcapkit.utilities.logging.logger` is public, importable
   from both :mod:`pcapkit.utilities.logging` and :mod:`pcapkit.utilities`, and
   named ``pcapkit``; :envvar:`PCAPKIT_DEVMODE` attaches the stderr handler at
   :data:`logging.DEBUG`; and ``Extractor(verbose=True)`` -- like the CLI's
   ``-v`` -- prints a line per frame to :data:`sys.stdout`. That output is a
   feature of the tool rather than diagnostics, so it deliberately stays on
   :func:`print`: routing it through :mod:`logging` would move it to another
   stream and hide it until the consumer configured a handler.

.. note::

   The warning channel is documented in :doc:`warnings`. In short,
   :func:`pcapkit.utilities.warnings.warn` reports each warning exactly once per
   channel -- one :data:`logging.WARNING` record and one :func:`warnings.warn`
   -- and constructing a warning does not touch the process-wide warning
   filters, so suppression is the application's to configure.
