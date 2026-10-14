================
Module Utilities
================

.. module:: pcapkit.utilities

:mod:`pcapkit.utilities` holds the cross-cutting services :mod:`pcapkit` is
built with: user-refined exceptions and warnings, logging, a compatibility
layer, and wrappers around third-party libraries. It imports nothing from
:mod:`pcapkit` outside itself; see :ref:`utilities-or-corekit`.

.. toctree::
   :maxdepth: 2

   exceptions
   warnings
   logging
   config
   chardet

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
   * - :func:`urllib.parse.unquote` on :obj:`bytes`
     - Python 3.9
   * - :class:`enum.StrEnum`
     - Python 3.11
   * - :func:`typing.final`
     - Python 3.11
   * - :func:`decimal.localcontext(ctx=None, **kwargs) <decimal.localcontext>`
     - Python 3.11
   * - :func:`enum.show_flag_values`
     - Python 3.11
   * - :data:`typing.TypeAlias`
     - Python 3.10
   * - :data:`threading.__excepthook__`, as ``default_threading_excepthook``
     - Python 3.10
   * - :func:`inspect.get_annotations`, of a class
     - Python 3.10
   * - :class:`types.UnionType`, or :data:`None` below it
     - Python 3.10
