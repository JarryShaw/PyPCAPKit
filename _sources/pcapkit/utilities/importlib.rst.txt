Lazy Imports
============

.. module:: pcapkit.utilities.importlib

:mod:`pcapkit.utilities.importlib` holds :func:`lazy_exports`, which gives a package the
:pep:`562` ``__getattr__`` and ``__dir__`` that import each name it exports the first
time the name is reached, rather than with the package itself. Every package under
:mod:`pcapkit.const` imports its enumerations that way (:issue:`2729`), so a caller
pays only for the enumerations it uses. Those first imports, and that of a
:class:`~pcapkit.corekit.module.ModuleDescriptor`, hold :data:`import_lock`, one
thread at a time (:issue:`2771`). This module imports nothing from :mod:`pcapkit`;
see :ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

.. autofunction:: pcapkit.utilities.importlib.lazy_exports

.. autodata:: pcapkit.utilities.importlib.import_lock
   :no-value:
