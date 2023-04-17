Utility Functions & Classes
===========================

.. module:: pcapkit.utilities

:mod:`pcapkit.utilities` contains several useful functions
and classes which are fundations of :mod:`pcapkit`, including
decorater function :func:`~pcapkit.utilities.decorators.seekset`
and :func:`~pcapkit.utilities.decorators.beholder`, and
several user-refined exceptions and warnings.

.. toctree::
   :maxdepth: 2

   logging
   decorators
   exceptions
   warnings

Version Compatibility
---------------------

.. module:: pcapkit.utilities.compat

:mod:`pcapkit` further provides a compatibility layer for the
following objects and functions:

.. list-table::

   * - :exc:`ModuleNotFoundError`
     - Python 3.6+
   * - :class:`collections.abc.Collection`
     - Python 3.6+
   * - :mod:`pathlib`
     - Python 3.5+
   * - :func:`functools.cached_property`
     - Python 3.8+
