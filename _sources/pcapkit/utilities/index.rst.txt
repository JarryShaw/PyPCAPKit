================
Module Utilities
================

.. module:: pcapkit.utilities

:mod:`pcapkit.utilities` contains several useful functions
and classes which are fundations of :mod:`pcapkit`, including
decorater function :func:`~pcapkit.utilities.decorators.seekset`
and :func:`~pcapkit.utilities.decorators.beholder`, and
several user-refined exceptions and warnings.

.. toctree::
   :maxdepth: 2

   functools
   exceptions
   warnings

Logging System
==============

.. module:: pcapkit.utilities.logging

:mod:`pcapkit.utilities.logging` contains naïve integration
of the Python logging system, i.e. a :class:`logging.Logger`
instance as :data:`~pcapkit.utilities.logging.logger`.

.. autodata:: pcapkit.utilities.logging.logger
   :no-value:

Environment Variables
---------------------

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

Version Compatibility
=====================

.. module:: pcapkit.utilities.compat

:mod:`pcapkit` further provides a compatibility layer for the
following objects and functions:

.. list-table::
   :header-rows: 1

   * - Compatibility Target
     - Minimal Required Version
   * - :mod:`pathlib`
     - Python 3.5
   * - :exc:`ModuleNotFoundError`
     - Python 3.6
   * - :class:`collections.abc.Collection`
     - Python 3.6
   * - :func:`functools.cached_property`
     - Python 3.8
   * - :class:`collections.abc.Mapping[KT, VT] <collections.abc.Mapping>`
     - Python 3.9
   * - :class:`tuple[T, ...] <tuple>`
     - Python 3.9
   * - :class:`list[T] <list>`
     - Python 3.9
   * - :class:`dict[KT, VT] <dict>`
     - Python 3.9
   * - :class:`enum.StrEnum`
     - Python 3.11
   * - :func:`typing.final`
     - Python 3.8
   * - :func:`decimal.localcontext(ctx=None, **kwargs) <decimal.localcontext>`
     - Python 3.11
   * - :func:`enum.show_flag_values`
     - Python 3.11
   * - :data:`typing.TypeAlias`
     - Python 3.10
