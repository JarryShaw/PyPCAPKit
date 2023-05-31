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

   exceptions
   warnings

Auxiliary Functions
===================

.. autofunction:: pcapkit.utilities.exceptions.stacklevel

.. autofunction:: pcapkit.utilities.warnings.warn

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

Decorator Functions
===================

.. module:: pcapkit.utilities.decorators

:mod:`pcapkit.utilities.decorators` contains several useful
decorators, including :func:`~pcapkit.utilities.decorators.seekset`,
:func:`~pcapkit.utilities.decorators.beholder` and
:func:`~pcapkit.utilities.decorators.prepare`.

.. autodecorator:: pcapkit.utilities.decorators.seekset

.. autodecorator:: pcapkit.utilities.decorators.beholder

.. autodecorator:: pcapkit.utilities.decorators.prepare

.. important::

   All three decorators above are designed for decorating *class methods*.
   For more information, please refer to the documentation of each
   decorator function.

Version Compatibility
=====================

.. module:: pcapkit.utilities.compat

:mod:`pcapkit` further provides a compatibility layer for the
following objects and functions:

.. list-table::

   * - :mod:`pathlib`
     - ≥ 3.5
   * - :exc:`ModuleNotFoundError`
     - ≥ 3.6
   * - :class:`collections.abc.Collection`
     - ≥ 3.6
   * - :func:`functools.cached_property`
     - ≥ 3.8
   * - :class:`collections.abc.Mapping[KT, VT] <collections.abc.Mapping>`
     - ≥ 3.9
   * - :class:`tuple[T, ...] <tuple>`
     - ≥ 3.9
   * - :class:`list[T] <list>`
     - ≥ 3.9
   * - :class:`dict[KT, VT] <dict>`
     - ≥ 3.9
   * - :class:`enum.StrEnum`
     - ≥ 3.11
   * - :func:`typing.final`
     - ≥ 3.8
   * - :func:`decimal.localcontext(ctx=None, **kwargs) <decimal.localcontext>`
     - ≥ 3.11
