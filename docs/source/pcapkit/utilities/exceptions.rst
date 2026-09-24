User Defined Exceptions
=======================

.. module:: pcapkit.utilities.exceptions

:mod:`pcapkit.utilities.exceptions` refined built-in exceptions.
Make it possible to show only user error stack information [*]_,
when exception raised on user's operation.

Loud and Quiet Errors
---------------------

Raising a :class:`~pcapkit.utilities.exceptions.BaseError` is, by default, a
**loud** act: the error is logged once at :data:`logging.CRITICAL` on the
:data:`~pcapkit.utilities.logging.logger` logger, and outside development mode
:data:`sys.tracebacklimit` is set to ``0``, which suppresses the traceback frames
entirely so the user sees the exception line rather than a walk through
:mod:`pcapkit`'s internals.

``quiet=True`` marks an error that :mod:`pcapkit` raises as **internal control
flow** and expects to catch itself -- the
:exc:`~pcapkit.utilities.exceptions.MissingKeyError` behind
:meth:`MultiDict.get <pcapkit.corekit.multidict.MultiDict.get>` is the archetype.
Such an error emits nothing on any channel and touches no process-global state.
It is still an ordinary exception carrying its message, so ``except`` clauses and
:func:`repr` are unaffected.

.. attention::

   Up to and including v1.4.1, ``quiet=True`` meant "log at ``ERROR`` instead of
   ``CRITICAL``" rather than "do not log", and :data:`sys.tracebacklimit` was set
   on both paths. A single ``MultiDict.get()`` miss therefore produced an
   ``ERROR`` record -- one per frame when parsing a capture containing
   unfragmented IPv6 with reassembly enabled -- and truncated the tracebacks of
   unrelated exceptions for the remainder of the process. A consumer who was
   watching for those ``ERROR`` records will no longer see them; they never
   corresponded to a fault. Anything that genuinely wants to observe internal
   lookup misses should catch the exception rather than read the log.

.. autoexception:: pcapkit.utilities.exceptions.BaseError
   :no-members:
   :show-inheritance:

   :param quiet: If :data:`True`, the error is neither logged nor allowed to
      alter :data:`sys.tracebacklimit`; it is raised silently, as internal
      control flow.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

:exc:`TypeError` Category
-------------------------

.. autoexception:: pcapkit.utilities.exceptions.DigitError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.IntError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.RealError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.ComplexError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.BoolError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.BytesError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.StringError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.BytearrayError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.DictError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.ListError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.TupleError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.IterableError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.IOObjError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.ProtocolUnbound
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.CallableError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.InfoError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.IPError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.EnumError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.ComparisonError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.RegistryError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.FieldError
   :no-members:
   :show-inheritance:

:exc:`AttributeError` Category
------------------------------

.. autoexception:: pcapkit.utilities.exceptions.FormatError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.UnsupportedCall
   :no-members:
   :show-inheritance:

:exc:`IOError` Category
-----------------------

.. autoexception:: pcapkit.utilities.exceptions.FileError
   :no-members:
   :show-inheritance:

:exc:`FileExistsError` Category
-------------------------------

.. autoexception:: pcapkit.utilities.exceptions.FileExists
   :no-members:
   :show-inheritance:

:exc:`FileNotFoundError` Category
---------------------------------

.. autoexception:: pcapkit.utilities.exceptions.FileNotFound
   :no-members:
   :show-inheritance:

:exc:`IndexError` Category
--------------------------

.. autoexception:: pcapkit.utilities.exceptions.ProtocolNotFound
   :no-members:
   :show-inheritance:

:exc:`ValueError` Category
--------------------------

.. autoexception:: pcapkit.utilities.exceptions.VersionError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.IndexNotFound
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.ProtocolError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.EndianError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.KeyExists
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.NoDefaultValue
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.FieldValueError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.SchemaError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.SeekError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.TruncateError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.VendorPathNotFound
   :no-members:
   :show-inheritance:

:exc:`NotImplementedError` Category
-----------------------------------

.. autoexception:: pcapkit.utilities.exceptions.ProtocolNotImplemented
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.VendorNotImplemented
   :no-members:
   :show-inheritance:

:exc:`struct.error` Category
----------------------------

.. autoexception:: pcapkit.utilities.exceptions.StructError
   :no-members:
   :show-inheritance:

:exc:`EOFError` Category
------------------------

.. autoexception:: pcapkit.utilities.exceptions.StreamEOFError
   :no-members:
   :show-inheritance:

:exc:`KeyError` Category
------------------------

.. autoexception:: pcapkit.utilities.exceptions.MissingKeyError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.FragmentError
   :no-members:
   :show-inheritance:

.. autoexception:: pcapkit.utilities.exceptions.PacketError
   :no-members:
   :show-inheritance:

:exc:`ModuleNotFoundError` Category
-----------------------------------

.. autoexception:: pcapkit.utilities.exceptions.ModuleNotFound
   :no-members:
   :show-inheritance:

:exc:`io.UnsupportedOperation` Category
---------------------------------------

.. autoexception:: pcapkit.utilities.exceptions.UnsupportedOperation
   :no-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] See |tbtrim|_ project for a modern Pythonic implementation.

.. |tbtrim| replace:: ``tbtrim``
.. _tbtrim: https://github.com/gousaiyang/tbtrim
