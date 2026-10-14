Common Utilities
================

.. module:: pcapkit.dumpkit.common

:mod:`pcapkit.dumpkit.common` holds the utilities shared by
:mod:`pcapkit.dumpkit`, chiefly customised hooks for :class:`dictdumper.Dumper`
classes.

.. versionremoved:: 1.5.0

   ``pcapkit.dumpkit.common.FALLBACK_LIMIT``, now
   :data:`pcapkit.utilities.config.FALLBACK_LIMIT`, set with
   :envvar:`PCAPKIT_FALLBACK_LIMIT` (:issue:`1726`).

.. autofunction:: pcapkit.dumpkit.common.make_dumper

.. autoclass:: pcapkit.dumpkit.common.Dumper
   :members:
   :show-inheritance:

Internal Definitions
--------------------

.. autofunction:: pcapkit.dumpkit.common.render_enum

.. autoclass:: pcapkit.dumpkit.common.DumperBase
   :members:
   :show-inheritance:
