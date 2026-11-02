================
Module Utilities
================

.. module:: pcapkit.utilities

:mod:`pcapkit.utilities` holds the cross-cutting services :mod:`pcapkit` is
built with: user-refined exceptions and warnings, logging, the tunable limits
of :mod:`~pcapkit.utilities.config`, a compatibility layer, timestamp
conversion, the :mod:`context variables <pcapkit.utilities.contextvars>` its
modules share, and wrappers around third-party libraries. It imports nothing from
:mod:`pcapkit` outside itself; see :ref:`utilities-or-corekit`.

.. toctree::
   :maxdepth: 2

   exceptions
   warnings
   logging
   config
   chardet
   datetime
   contextvars

Version Compatibility
=====================

.. module:: pcapkit.utilities.compat

:mod:`pcapkit` further provides a compatibility layer for the
following objects and functions:

.. list-table::
   :header-rows: 1

   * - Compatibility Target
     - Minimal Required Version
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

It also exports :mod:`pathlib`, :exc:`ModuleNotFoundError`,
:class:`collections.abc.Collection` and :func:`functools.cached_property` as the
standard library has them, with no fallback, since 1.5.0 requires Python 3.8 or
later (:issue:`2051`).

.. function:: final(f)

   :func:`typing.final` from Python 3.11 on, and ``typing_extensions.final``
   below it. Both record ``__final__ = True`` on the decorated object at
   runtime, which :class:`~pcapkit.corekit.infoclass.Info` and
   :class:`~pcapkit.protocols.schema.schema.Schema` read to refuse a class
   marked ``@final`` without :func:`~pcapkit.corekit.infoclass.info_final` or
   :func:`~pcapkit.protocols.schema.schema.schema_final`. Plain
   :func:`typing.final` records nothing below 3.11 (gh-90500).

   .. versionchanged:: 1.5.0

      Taken from ``typing_extensions`` below Python 3.11 rather than 3.8, so
      that ``__final__`` is recorded on every supported version (:issue:`778`).

.. function:: unquote(string, encoding='utf-8', errors='replace')

   :func:`urllib.parse.unquote`, which accepts :class:`bytes` from Python 3.9 on.
   Below 3.9, a :class:`bytes` ``string`` is unquoted to octets with
   :func:`urllib.parse.unquote_to_bytes` and then decoded with ``encoding`` and
   ``errors``.

.. data:: default_threading_excepthook

   The interpreter's own default thread exception hook, even when
   :func:`threading.excepthook` has been replaced:
   :data:`threading.__excepthook__` from Python 3.10 on, and ``_thread._excepthook``
   on 3.8 and 3.9.

.. class:: cached_property(func)

   :func:`functools.cached_property` itself.

   .. versionchanged:: 1.5.0

      No longer a backport below Python 3.8, which 1.5.0 does not install on
      (:issue:`2051`).
