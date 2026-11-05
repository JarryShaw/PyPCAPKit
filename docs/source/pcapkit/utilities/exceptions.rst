User Defined Exceptions
=======================

.. module:: pcapkit.utilities.exceptions

:mod:`pcapkit.utilities.exceptions` holds :mod:`pcapkit`'s exceptions, each
refining a built-in one, grouped below by that built-in.

Loud and Quiet Errors
---------------------

A :class:`~pcapkit.utilities.exceptions.BaseError` is **loud** by default: it is
logged once at :data:`logging.CRITICAL` on the ``pcapkit`` logger
(:data:`~pcapkit.utilities.logging.logger`), and outside development mode an
exception hook is installed on :func:`sys.excepthook` and
:func:`threading.excepthook`, the first time a loud error needs it, so the user
sees the exception line rather than a walk through :mod:`pcapkit`'s
internals [*]_. The hook shortens only a
:class:`~pcapkit.utilities.exceptions.BaseError`; it hands every other exception,
unchanged, to the hook installed before it.

``quiet=True`` marks an error :mod:`pcapkit` raises as **internal control flow**
and catches itself -- the :exc:`~pcapkit.utilities.exceptions.MissingKeyError`
behind :meth:`MultiDict.get <pcapkit.corekit.multidict.MultiDict.get>` is the
archetype. It emits nothing on any channel and touches no process-global state,
but is otherwise an ordinary exception carrying its message.

An error constructed inside a
:class:`~pcapkit.utilities.exceptions.CaughtByCaller` block naming one of its
classes is quiet too. That is how :mod:`pcapkit` marks as control flow an error
raised by code it calls but does not own, such as a generated
``_validate_value`` override, which cannot pass ``quiet=True`` itself
(:issue:`1845`).
:func:`~pcapkit.corekit.decorators.beholder` runs the whole call to a next layer in
such a block for :exc:`~pcapkit.utilities.exceptions.ProtocolError`, so a refusal it
keeps as :class:`~pcapkit.protocols.misc.raw.protocol.Raw` is recorded on that layer's ``error``
alone (:issue:`2588`).

What decides whether a constructed error is loud:

.. mermaid::

   flowchart TD
       NEW["a BaseError<br/>is constructed"] --> QUIET{"quiet=True?"}
       QUIET -->|yes| SILENT["quiet: nothing logged,<br/>no hook touched"]
       QUIET -->|no| CAUGHT{"inside a CaughtByCaller<br/>block naming one<br/>of its classes?"}
       CAUGHT -->|yes| SILENT
       CAUGHT -->|no| DEV{"PCAPKIT_DEVMODE?"}
       DEV -->|yes| DEVLOG["logger.critical, with<br/>traceback and stack<br/>under PCAPKIT_VERBOSE"]
       DEV -->|no| LOG["logger.critical"]
       LOG --> HOOK["\_install\_excepthook<br/>sys.excepthook and<br/>threading.excepthook"]
       SILENT --> RAISE["an ordinary exception<br/>for the caller to catch"]
       DEVLOG --> RAISE
       HOOK --> RAISE

       click CAUGHT "exceptions.html#pcapkit.utilities.exceptions.CaughtByCaller"

.. versionchanged:: 1.5.0

   ``quiet=True`` logs nothing, where 1.4.x logged at ``ERROR``, and neither path
   sets :data:`sys.tracebacklimit`. In 1.4.x a single :meth:`MultiDict.get()
   <pcapkit.corekit.multidict.MultiDict.get>` miss gave an ``ERROR`` record -- one per
   frame when parsing unfragmented IPv6 with reassembly on -- and truncated unrelated
   tracebacks for the rest of the process, though no such record was a fault. To
   observe internal lookup misses, catch the exception rather than read the log
   (:issue:`362`).

.. autoexception:: pcapkit.utilities.exceptions.BaseError
   :no-members:
   :show-inheritance:

   .. automethod:: __init__

.. autoclass:: pcapkit.utilities.exceptions.CaughtByCaller
   :no-members:

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

.. autoexception:: pcapkit.utilities.exceptions.EnumValueError
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

.. autoexception:: pcapkit.utilities.exceptions.EnumKeyError
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

Error Handling Utilities
------------------------

.. autofunction:: pcapkit.utilities.exceptions.stacklevel

.. autofunction:: pcapkit.utilities.exceptions._install_excepthook

.. autofunction:: pcapkit.utilities.exceptions._excepthook

.. autofunction:: pcapkit.utilities.exceptions._threading_excepthook

.. rubric:: Footnotes

.. [*] See |tbtrim|_ project for a modern Pythonic implementation.
