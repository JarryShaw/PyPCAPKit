Null Dumper
===========

.. module:: pcapkit.dumper.null

:mod:`pcapkit.dumpkit.null` is the dumper for :mod:`pcapkit` implementation,
specifically for **NotImplemented** format, which is alike those described in
:mod:`dictdumper`.

.. note::

   This dumper is used when the given format is not supported, as a fallback.
   It shall not produce any output.

.. autoclass:: pcapkit.dumpkit.null.NotImplementedIO
   :no-members:
   :show-inheritance:

   .. autoproperty:: kind
