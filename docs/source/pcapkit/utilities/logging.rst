==============
Logging System
==============

.. module:: pcapkit.utilities.logging

:mod:`pcapkit.utilities.logging` integrates :mod:`pcapkit` with the standard
:mod:`logging` system. It owns the package-wide logger hierarchy rooted at
:data:`~pcapkit.utilities.logging.logger` and the configuration API through
which an application decides what, if anything, :mod:`pcapkit` emits.

.. autodata:: pcapkit.utilities.logging.logger
   :no-value:

The Logger Hierarchy
====================

``pcapkit`` is the root. Every module inside the package logs through its own
child logger, named after the module and obtained from
:func:`~pcapkit.utilities.logging.get_logger`, so a record carries the name of
the code that emitted it and any subtree can be addressed on its own:

.. code-block:: python

   import logging

   # quieten the registry's bookkeeping, keep everything else
   logging.getLogger('pcapkit.foundation.registry').setLevel(logging.WARNING)

   # or follow just the extraction path
   logging.getLogger('pcapkit.foundation.extraction').setLevel(logging.DEBUG)

The names in use are the module paths themselves, e.g.
``pcapkit.foundation.extraction``, ``pcapkit.foundation.registry.protocols``,
``pcapkit.foundation.engines.pcap``, ``pcapkit.foundation.reassembly.reassembly``,
``pcapkit.foundation.traceflow.tcp``, ``pcapkit.utilities.warnings``.

.. autofunction:: pcapkit.utilities.logging.get_logger

.. autodata:: pcapkit.utilities.logging.ROOT_LOGGER_NAME

What ``DEBUG`` Will Tell You
============================

At :data:`logging.DEBUG` the library explains what it did with a file, without
descending to per-field parsing: which input was opened, which engine was
requested and which was actually used (including a fallback when an optional
dependency is missing), the file format identified from the magic number, the
output format and dumper, whether reassembly and flow tracing were enabled and
with which flags, how many frames were read, and when cleanup ran. Reassembly
reports datagram counts on flush and flow tracing reports flows opening and
closing.

.. note::

   Nothing is logged from inside per-frame or per-field parsing loops, so
   enabling :data:`~logging.DEBUG` does not turn a capture with a million
   packets into a million records. Registration bookkeeping across
   :mod:`pcapkit.foundation.registry` is also at :data:`~logging.DEBUG` rather
   than :data:`~logging.INFO`, since a library announcing its own registry
   entries is not news to its consumer.

Configuring the Output
======================

Importing :mod:`pcapkit` configures **no** logging output: the only handler
attached to :data:`~pcapkit.utilities.logging.logger` is a
:class:`logging.NullHandler`, and no level is set. This is the behaviour
recommended for libraries -- the application keeps control of its own logging,
and :mod:`pcapkit`'s records simply propagate into whatever it has configured,
typically via :func:`logging.basicConfig` or :mod:`logging.config`.

For an application that would rather let :mod:`pcapkit` set up its own output,
:func:`~pcapkit.utilities.logging.configure` does so at runtime:

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

      This variable can be configured through the environment variable
      :envvar:`PCAPKIT_DEVMODE`.

.. autodata:: pcapkit.utilities.logging.VERBOSE
   :no-value:

   .. seealso::

      This variable can be configured through the environment variable
      :envvar:`PCAPKIT_VERBOSE`.

.. autodata:: pcapkit.utilities.logging.SPHINX_TYPE_CHECKING
   :no-value:

   .. seealso::

      This variable can be configured through the environment variable
      :envvar:`PCAPKIT_SPHINX`.

.. _logging-compatibility:

Compatibility Note
==================

.. warning::

   :mod:`pcapkit` used to attach a :class:`logging.StreamHandler` on
   :obj:`sys.stderr` and force the level to :data:`logging.INFO` (or
   :data:`logging.DEBUG` under :envvar:`PCAPKIT_DEVMODE`) **at import time**.
   That is no longer done, because it hijacked the logging configuration of
   every application that imported :mod:`pcapkit`.

   Two consequences are visible to existing code:

   1. **Messages that used to appear on stderr no longer do.** In particular the
      ``registered ...`` bookkeeping is now at :data:`logging.DEBUG` rather than
      :data:`logging.INFO`. Restore the old output in one line:

      .. code-block:: python

         import logging, sys
         from pcapkit.utilities.logging import configure
         configure(logging.INFO, stream=sys.stderr)

      Equivalently, re-attach the module's own handler, which is still built and
      still carries the historical format:

      .. code-block:: python

         from pcapkit.utilities.logging import handler, logger
         logger.setLevel(logging.INFO)
         logger.addHandler(handler)

   2. **The handler is no longer at** ``logger.handlers[0]``. Code that reached
      into that list to remove or reconfigure the handler should call
      :func:`~pcapkit.utilities.logging.reset` or
      :func:`~pcapkit.utilities.logging.configure` instead.

   Unaffected: :data:`~pcapkit.utilities.logging.logger` remains public,
   importable from both :mod:`pcapkit.utilities.logging` and
   :mod:`pcapkit.utilities`, and named ``pcapkit``;
   :envvar:`PCAPKIT_DEVMODE` still produces the stderr handler at
   :data:`logging.DEBUG`; and ``Extractor(verbose=True)`` still prints a line per
   frame, now through :data:`logging.DEBUG` with a destination guaranteed by
   :func:`~pcapkit.utilities.logging.ensure_output` when the application has
   configured none.

.. note::

   Two related issues are deliberately left alone for now:
   :func:`pcapkit.utilities.warnings.warn` reports every warning twice, once
   through :mod:`logging` and once through :mod:`warnings`; and
   :class:`~pcapkit.utilities.warnings.BaseWarning` calls
   :func:`warnings.simplefilter` outside development mode, which mutates the
   process-wide warning filters. Both change observable behaviour well beyond
   logging and belong in their own change.
