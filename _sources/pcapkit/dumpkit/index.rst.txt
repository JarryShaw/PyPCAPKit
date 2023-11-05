==============
Dump Utilities
==============

.. module:: pcapkit.dumpkit

:mod:`pcapkit.dumpkit` is the collection of dumpers for
:mod:`pcapkit` implementation, which is alike those described
in :mod:`dictdumper`.

.. toctree::
   :maxdepth: 2

   null
   pcap

Common Utilities
================

.. module:: pcapkit.dumpkit.common

:mod:`pcapkit.dumpkit.common` is the collection of common utility
functions for :mod:`pcapkit.dumpkit` implementation, which is
generally the customised hooks for :class:`dictdumper.Dumper`
classes.

.. autoclass:: pcapkit.dumpkit.common.Dumper
   :members:
   :show-inheritance:

.. autofunction:: pcapkit.dumpkit.common.make_dumper

Internal Definitions
--------------------

.. autoclass:: pcapkit.dumpkit.common.DumperBase
   :members:
   :show-inheritance:
