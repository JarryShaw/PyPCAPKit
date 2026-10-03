# -*- coding: utf-8 -*-
"""User Defined Exceptions
=============================

.. module:: pcapkit.utilities.exceptions

:mod:`pcapkit.utilities.exceptions` refined built-in exceptions.
Make it possible to show only user error stack infomation [*]_,
when exception raised on user's operation.

.. [*] See |tbtrim|_ project for Pythonic implementation.

.. |tbtrim| replace:: ``tbtrim``
.. _tbtrim: https://github.com/gousaiyang/tbtrim

"""
import inspect
import io
import os
import struct
import sys
import threading
import traceback
from typing import TYPE_CHECKING

from pcapkit.utilities.compat import ModuleNotFoundError  # pylint: disable=redefined-builtin
from pcapkit.utilities.logging import DEVMODE, VERBOSE, get_logger

if TYPE_CHECKING:
    from threading import ExceptHookArgs
    from types import TracebackType
    from typing import Any, Callable, Optional, Type

__all__ = [
    'stacklevel',

    'BaseError',                                                    # Exception
    'DigitError', 'IntError', 'RealError', 'ComplexError',          # TypeError
    'BoolError', 'BytesError', 'StringError', 'BytearrayError',     # TypeError
    'DictError', 'ListError', 'TupleError', 'IterableError',        # TypeError
    'IOObjError', 'ProtocolUnbound', 'CallableError',               # TypeError
    'InfoError', 'IPError', 'EnumError', 'ComparisonError',         # TypeError
    'RegistryError', 'FieldError',                                  # TypeError
    'FormatError', 'UnsupportedCall',                               # AttributeError
    'FileError', 'UnsupportedOperation',                            # IOError
    'FileExists',                                                   # FileExistsError
    'FileNotFound',                                                 # FileNotFoundError
    'ProtocolNotFound',                                             # IndexError
    'VersionError', 'IndexNotFound', 'ProtocolError',               # ValueError
    'EndianError', 'KeyExists', 'NoDefaultValue', 'EnumValueError', # ValueError
    'FieldValueError', 'SchemaError', 'SeekError', 'TruncateError', # ValueError
    'VendorPathNotFound',                                           # ValueError
    'ProtocolNotImplemented', 'VendorNotImplemented',               # NotImplementedError
    'StructError',                                                  # struct.error
    'StreamEOFError',                                               # EOFError
    'MissingKeyError', 'FragmentError', 'PacketError',              # KeyError
    'EnumKeyError',                                                 # KeyError
    'ModuleNotFound',                                               # ModuleNotFoundError
]


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


def stacklevel() -> 'int':
    """Stack level of the innermost frame outside :mod:`pcapkit`.

    The value is a *relative* level, in the sense both :func:`warnings.warn` and
    the :mod:`logging` module use: level ``1`` is the frame that called
    :func:`stacklevel`, level ``2`` its caller, and so on outwards. Handing it to
    either of them attributes the complaint to the caller who reached into
    :mod:`pcapkit`, rather than to whichever :mod:`pcapkit` internal happened to
    notice the problem -- which is the whole point of the function, since the
    internal frames are noise to the user reading the report.

    The arithmetic, since it is easy to get backwards. Number the frames outwards
    from this one, so that a number *is* the relative level a consumer wants::

        level 0             stacklevel() itself
        level 1             whoever called stacklevel()
        ...
        level ``boundary``  the outermost frame inside pcapkit
        ...
        level ``outermost`` the interpreter entry point

    The frame to name is the first one *past* the boundary, hence
    ``boundary + 1``. What makes this a fix rather than a rewrite is that
    ``boundary`` is measured from the *inside* out: it depends only on how deep the
    :mod:`pcapkit` frames run, never on how deep the caller's own stack is.
    Numbering from the outside in, as this function once did, grew with the outer
    stack, so the frame it named drifted one further out for every extra frame
    above the boundary -- under :program:`pytest`, dozens of them.

    Both bounds are enforced, as neither consumer copes with a level outside them:

    * Never below ``1``. ``0`` and negative values mean "do not walk out at all"
      to :meth:`logging.Logger.findCaller`, which then attributes the record to
      :mod:`logging` itself; :func:`warnings.warn` treats them as ``1``.
    * Never above ``outermost``. That bound is reached when the whole stack is
      inside :mod:`pcapkit`, e.g. running the package as a script, and walking
      past the outermost frame makes :func:`warnings.warn` fall back to blaming
      the :mod:`sys` module.

    The walk goes through :func:`inspect.currentframe` and ``f_back`` rather than
    :func:`traceback.extract_stack`, which *used to* be unusable here for a sharper
    reason than cost: :meth:`traceback.StackSummary.extract` honours
    :data:`sys.tracebacklimit`, and :class:`BaseError` used to set that to ``0`` for
    every loud error outside development mode. One such error therefore made
    ``extract_stack()`` return an *empty* list for the rest of the process, which is
    where the old ``-1`` came from -- so in ordinary use the first error silently
    broke the attribution of every warning after it. :class:`BaseError` no longer
    touches :data:`sys.tracebacklimit` at all (it prints its terse line through an
    exception hook instead), which removes that failure mode -- but the frame walk
    remains the right approach regardless of it: it skips building the
    :class:`~traceback.FrameSummary` objects and the :mod:`linecache` lookups
    :func:`traceback.extract_stack` does for every frame, which is worth avoiding on
    a function called once per warning.

    Important:
        The level is relative to the *caller* of :func:`stacklevel`. A function
        that forwards it to :func:`warnings.warn` on its caller's behalf has to
        add one for its own frame -- see :func:`pcapkit.utilities.warnings.warn`,
        which does exactly that.

    Returns:
        Number of frames from the caller of :func:`stacklevel` outwards to the
        innermost frame whose path does not contain ``/pcapkit/``.

    """
    pcapkit = f'{os.path.sep}pcapkit{os.path.sep}'

    frame = inspect.currentframe()
    if frame is None:  # pragma: no cover
        # No Python stack frame support, so there is no boundary to find. Blaming
        # the immediate caller is the least wrong answer available.
        return 1

    try:
        boundary = 0   # level of the outermost pcapkit frame seen so far
        outermost = 0  # level of the outermost frame there is
        level = 0      # level 0 is this function's own frame, which is in pcapkit
        while frame is not None:
            if pcapkit in frame.f_code.co_filename:
                boundary = level
            outermost = level
            frame = frame.f_back
            level += 1
    finally:
        # A frame reachable from a local keeps its whole chain alive as soon as a
        # traceback references this one, so the name is dropped rather than left
        # bound. The loop exits with `frame` at :data:`None` anyway; this covers
        # leaving it early.
        del frame

    return max(1, min(boundary + 1, outermost))


##############################################################################
# BaseError (abc of exceptions) session.
##############################################################################


class BaseError(Exception):
    """Base error class of all kinds.

    A loud error -- the default -- is reported once, at
    :data:`logging.CRITICAL` level, on the
    :data:`~pcapkit.utilities.logging.logger` logger. Outside development mode it
    also installs :func:`_excepthook` as :data:`sys.excepthook` and
    :func:`_threading_excepthook` as :data:`threading.excepthook`, the first time
    a loud error needs them, so that error -- and every loud error reaching the
    top level after it, on the main thread or any other -- prints its one-line
    exception message rather than a walk through :mod:`pcapkit`'s internals.

    A **quiet** error (``quiet=True``) is one :mod:`pcapkit` raises as internal
    control flow and expects to catch itself, such as the
    :exc:`~pcapkit.utilities.exceptions.MissingKeyError` behind
    :meth:`MultiDict.get <pcapkit.corekit.multidict.MultiDict.get>`. It is
    therefore silent and free of side effects: nothing is logged, and neither
    :data:`sys.excepthook` nor :data:`threading.excepthook` is touched. It is
    still a perfectly ordinary exception, carrying its message for whoever
    catches it.

    Important:

        * This terseness used to come from setting :data:`sys.tracebacklimit` to
          ``0``, which is process-global: one loud error truncated the tracebacks
          of every *other*, unrelated exception for the rest of the process,
          including ones that had nothing to do with :mod:`pcapkit`. It also,
          incidentally, was what kept a loud error raised on a worker thread
          terse, since the interpreter's default :data:`threading.excepthook`
          itself consults :data:`sys.tracebacklimit`. The two hooks here replace
          that mechanism precisely because neither has that reach -- each
          shortens the printing of a :class:`BaseError` only, and hands every
          other exception, unchanged, to whatever hook :mod:`pcapkit` found
          installed before it first needed its own.
        * Both hooks are installed lazily, from here, rather than at import
          time, so a program that imports :mod:`pcapkit` but never raises one of
          its errors never has :data:`sys.excepthook` or
          :data:`threading.excepthook` touched.
        * The two hooks still do not cover *every* path an exception can take.
          A traceback a caller formats itself with :mod:`traceback` -- rather
          than letting it reach the top level uncaught -- passes through
          neither. See GitHub issue :issue:`719`.
        * The ``stacklevel`` of the log record is the relative level
          :func:`stacklevel` computes, so the record is attributed to the caller
          whose operation failed rather than to this module. It used to be
          *negated*, which :meth:`logging.Logger.findCaller` reads as "do not walk
          out at all" and which therefore blamed :mod:`logging` itself for every
          error pcapkit raised.

    See Also:
        :func:`pcapkit.utilities.exceptions.stacklevel`

    """

    def __init__(self, *args: 'Any', quiet: 'bool' = False, **kwargs: 'Any') -> 'None':
        # log error -- a quiet error emits nothing and mutates nothing
        if not quiet:
            if DEVMODE:
                logger.critical('%s: %s', type(self).__name__, str(self),
                                exc_info=self if VERBOSE else False,
                                stack_info=VERBOSE, stacklevel=stacklevel())
            else:
                logger.critical('%s: %s', type(self).__name__, str(self))
                _install_excepthook()
        super().__init__(*args, **kwargs)


#: Callable[[Type[BaseException], BaseException, Optional[TracebackType]], None]:
#: Whatever :data:`sys.excepthook` was installed immediately before
#: :func:`_install_excepthook` last replaced it -- :data:`None` until that
#: happens. This is what a non-:class:`BaseError` is delegated to from
#: :func:`_excepthook`.
#:
#: Not a durable, one-time capture: an in-place :func:`importlib.reload` of
#: *this exact module* re-executes the line below, resetting this back to
#: :data:`None` in the very globals the already-installed :func:`_excepthook`
#: still reads from on every call (a global lookup, not a value closed over at
#: definition time). The old hook -- still installed, since a reload does not
#: retroactively change what :data:`sys.excepthook` points at -- then falls
#: back to :data:`sys.__excepthook__` for a non-:class:`BaseError`, silently
#: losing whatever had been captured before the reload (a host application's
#: own hook, or ``tbtrim``'s). Measured: a delegate trimmed to one frame before
#: such a reload, the bare default's full walk after it. Harmless for
#: :class:`BaseError` printing, which does not consult this at all, and for
#: the far more common case this module exercises -- a *fresh* module object
#: per load, as :func:`tests._support.load_module` and a plain re-``import``
#: both are -- where the old instance's own globals, including this one, are
#: simply left alone.
_previous_excepthook = None  # type: Optional[Callable[..., None]]

#: bool: Set for the duration of :func:`_excepthook`, so a re-entrant call -- the
#: delegate somehow routing back through :data:`sys.excepthook` -- falls back to
#: the interpreter's own hook rather than recursing or printing twice. A single
#: shared flag is correct here, unlike the threading analogue below: nothing
#: but the main thread's own unwind ever calls :data:`sys.excepthook`, so there
#: is no concurrent, unrelated invocation for one flag to be confused with.
_excepthook_running = False


def _excepthook(etype: 'Type[BaseException]', value: 'BaseException',
                tb: 'Optional[TracebackType]') -> 'None':
    """Print a loud :class:`BaseError` tersely; chain through everything else.

    Installed by :func:`_install_excepthook`, which is also what records
    ``_previous_excepthook``. A :class:`BaseError` reaching here is printed with
    ``limit=0`` against its *real* traceback -- not a bare one-liner built by
    discarding the traceback outright, which is close but not the same thing.
    :func:`traceback.print_exception` is also what formats a chained exception
    (``raise ... from err``, or a bare ``raise`` inside an ``except`` block),
    and it does so by walking from the outermost cause or context *inward*,
    applying ``limit`` to each link's own frames as it goes. Passing ``tb=None``
    only ever hands it the top exception's own traceback -- the chain's inner
    links keep their *real* ``__cause__``/``__context__`` traceback attributes
    regardless, untouched by this call, and get printed in full. ``limit=0``
    against the real ``tb`` is what reaches every link, matching exactly what
    :data:`sys.tracebacklimit` set to ``0`` used to produce for the same
    exception -- the one-line answer for a plain :class:`BaseError` and the
    *same* chain-without-frames answer this used to get wrong.

    Anything else is handed to ``_previous_excepthook`` exactly as received, so
    a program with its own hook installed before :mod:`pcapkit` needed one --
    or none, in which case that is :data:`sys.__excepthook__` -- keeps seeing
    exactly what it would have seen without :mod:`pcapkit` in the process at
    all.

    """
    global _excepthook_running  # pylint: disable=global-statement

    if _excepthook_running:
        sys.__excepthook__(etype, value, tb)
        return

    _excepthook_running = True
    try:
        if isinstance(value, BaseError):
            traceback.print_exception(etype, value, tb, 0)
        else:
            delegate = _previous_excepthook or sys.__excepthook__
            delegate(etype, value, tb)
    finally:
        _excepthook_running = False


# A generic, external marker -- "some pcapkit instance's hook is active" -- for
# a caller that only has :data:`sys.excepthook` and no reference to a particular
# loaded copy of this module. Diagnostic only: :func:`_install_excepthook`'s own
# guard below does *not* use this, and must not go back to doing so. The marker
# is a plain :obj:`True`, identical on every reloaded copy of this function, so
# it cannot tell "my own instance's hook" from "some *other* instance's" --
# which is exactly the distinction the guard needs and a shared value cannot
# give it.
_excepthook.installed_by_pcapkit = True  # type: ignore[attr-defined]


#: Callable[[ExceptHookArgs], object]: The thread analogue of
#: ``_previous_excepthook`` -- whatever :data:`threading.excepthook` was
#: installed immediately before :func:`_install_excepthook` last replaced it.
#: Subject to the same reload caveat documented on ``_previous_excepthook``.
#: Typed to return :class:`object` rather than :data:`None`, matching
#: :data:`threading.excepthook` itself in typeshed -- unlike
#: :data:`sys.excepthook`, which is typed as returning :data:`None`.
_previous_threading_excepthook = None  # type: Optional[Callable[..., object]]

#: threading.local: Per-thread re-entrancy guard for
#: :func:`_threading_excepthook`, kept separate from ``_excepthook_running``
#: rather than shared with it. Unlike :data:`sys.excepthook`, which only ever
#: fires once, on the main thread's own unwind, :data:`threading.excepthook`
#: can genuinely be running in *two different threads at once* -- each with its
#: own uncaught exception, entirely unrelated to the other. A single shared
#: flag would make one thread's hook see the other's unrelated, concurrent
#: call and mistake it for its own re-entrancy, falling back when it should
#: not. Scoping the flag per thread is what keeps the guard meaningful only
#: against a thread routing back through its *own* call.
_threading_hook_state = threading.local()


def _threading_excepthook(args: 'ExceptHookArgs') -> 'None':
    """Thread analogue of :func:`_excepthook`; same contract, one argument.

    :data:`threading.excepthook` is called with a single
    :class:`threading.ExceptHookArgs`, carrying ``exc_type``, ``exc_value``,
    ``exc_traceback`` and ``thread`` -- not the three positional parameters
    :data:`sys.excepthook` takes. Everything else here mirrors :func:`_excepthook`
    as closely as the default thread hook's own output allows: a loud
    :class:`BaseError` prints the ``"Exception in thread ...:"`` header the
    default hook always prints first -- the one piece of that output
    :data:`sys.tracebacklimit` never touched, since it only ever bounded the
    traceback -- then its own message tersely, with ``limit=0`` against the real
    traceback so a chained exception still comes out right. Anything else is
    handed to ``_previous_threading_excepthook`` -- or
    :data:`threading.__excepthook__`, the interpreter's own default, if nothing
    was previously installed -- unchanged, header included, since that path
    does not touch the default hook's own printing at all.

    Replacing this hook is the other half of why :data:`sys.tracebacklimit`
    cannot simply be dropped without a replacement: the interpreter's *default*
    :data:`threading.excepthook` itself consults :data:`sys.tracebacklimit` when
    printing an uncaught exception from a worker thread, which is what made a
    loud :class:`BaseError` there terse before this hook existed, incidentally
    rather than by any thread-aware design on this module's part. Without this,
    removing the global would have *regressed* that path from one line to a
    full default traceback, even though the defect it was fixing is itself
    thread-independent.

    """
    if getattr(_threading_hook_state, 'running', False):
        threading.__excepthook__(args)
        return

    _threading_hook_state.running = True
    try:
        if isinstance(args.exc_value, BaseError):
            # The thread identity the default hook would have named, replicated
            # rather than borrowed: there is no way to ask the default hook for
            # *only* its header line, and ``args.thread`` is documented as
            # possibly ``None`` -- in which case the default hook names the
            # current thread's bare identifier instead, which is exactly what
            # calling it from here, on that same thread, reproduces.
            name = args.thread.name if args.thread is not None else str(threading.get_ident())
            print(f'Exception in thread {name}:', file=sys.stderr)
            traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback, 0)
        else:
            delegate = _previous_threading_excepthook or threading.__excepthook__
            delegate(args)
    finally:
        _threading_hook_state.running = False


_threading_excepthook.installed_by_pcapkit = True  # type: ignore[attr-defined]


def _install_excepthook() -> 'None':
    """Install :func:`_excepthook` and :func:`_threading_excepthook`, once each.

    Called from :class:`BaseError`'s constructor rather than at import time, so
    that a program that never raises a :mod:`pcapkit` error never has
    :data:`sys.excepthook` or :data:`threading.excepthook` touched merely for
    having imported the package.

    Idempotent for *this* module instance, independently for each of the two
    hooks: if a given hook slot already holds this instance's own function --
    checked by identity, ``is``, not by the ``installed_by_pcapkit`` marker --
    installing it again does nothing, so a loud error later in the same run
    never wraps either hook in another copy of itself. That distinction matters
    because the identical check is wrong one level up: a hook slot already
    holding *some* function of the same name from an *earlier* loaded copy of
    this module -- a genuine :func:`importlib.reload`, or a test harness
    re-executing the file fresh -- is not this instance's own hook, and must
    not be skipped over. A fresh instance installs over it exactly as it would
    over a host application's own hook, capturing it as the matching
    ``_previous_*`` and delegating to it for whatever that older instance's own
    hook does not claim as one of its own :class:`BaseError` instances --
    which, correctly, includes a :class:`BaseError` raised by that *older*
    instance, since ``isinstance`` does not hold across the reload and
    delegating down the chain is what lets the older instance's own hook
    recognise it instead.

    """
    global _previous_excepthook, _previous_threading_excepthook  # pylint: disable=global-statement

    current = sys.excepthook
    if current is not _excepthook:
        _previous_excepthook = current
        sys.excepthook = _excepthook

    current_threading = threading.excepthook
    if current_threading is not _threading_excepthook:
        _previous_threading_excepthook = current_threading
        threading.excepthook = _threading_excepthook


##############################################################################
# TypeError session.
##############################################################################


class DigitError(BaseError, TypeError):
    """The argument(s) must be (a) number(s)."""


class IntError(BaseError, TypeError):
    """The argument(s) must be integral."""


class RealError(BaseError, TypeError):
    """The function is not defined for real number."""


class ComplexError(BaseError, TypeError):
    """The function is not defined for complex instance."""


class BytesError(BaseError, TypeError):
    """The argument(s) must be :obj:`bytes` type."""


class BytearrayError(BaseError, TypeError):
    """The argument(s) must be :obj:`bytearray` type."""


class BoolError(BaseError, TypeError):
    """The argument(s) must be :obj:`bool` type."""


class StringError(BaseError, TypeError):
    """The argument(s) must be :obj:`str` type."""


class DictError(BaseError, TypeError):
    """The argument(s) must be :obj:`dict` type."""


class ListError(BaseError, TypeError):
    """The argument(s) must be :obj:`list` type."""


class TupleError(BaseError, TypeError):
    """The argument(s) must be :obj:`tuple` type."""


class IterableError(BaseError, TypeError):
    """The argument(s) must be *iterable*."""


class CallableError(BaseError, TypeError):
    """The argument(s) must be *callable*."""


class ProtocolUnbound(BaseError, TypeError):
    """Protocol slice unbound."""


class IOObjError(BaseError, TypeError):
    """The argument(s) must be *file-like object*."""


class InfoError(BaseError, TypeError):
    """The argument(s) must be :class:`~pcapkit.corekit.infoclass.Info` instance."""


class IPError(BaseError, TypeError):
    """The argument(s) must be *IP address*."""


class EnumError(BaseError, TypeError):
    """The argument(s) must be *enumeration protocol* type."""


class ComparisonError(BaseError, TypeError):
    """Rich comparison not supported between instances."""


class RegistryError(BaseError, TypeError):
    """The argument(s) must be *registry* type."""


class FieldError(BaseError, TypeError):
    """The argument(s) must be *field* type."""


##############################################################################
# AttributeError session.
##############################################################################


class FormatError(BaseError, AttributeError):
    """Unknown format(s)."""


class UnsupportedCall(BaseError, AttributeError):
    """Unsupported function or property call."""


##############################################################################
# IOError session.
##############################################################################


class FileError(BaseError, IOError):
    """[Errno 5] Wrong file format."""
    # args: errno, strerror, filename, winerror, filename2


##############################################################################
# FileExistsError session.
##############################################################################


class FileExists(BaseError, FileExistsError):
    """[Errno 17] File already exists."""
    # args: errno, strerror, filename, winerror, filename2


##############################################################################
# FileNotFoundError session.
##############################################################################


class FileNotFound(BaseError, FileNotFoundError):
    """[Errno 2] File not found."""
    # args: errno, strerror, filename, winerror, filename2


##############################################################################
# IndexError session.
##############################################################################


class ProtocolNotFound(BaseError, IndexError):
    """Protocol not found in ProtoChain."""


##############################################################################
# ValueError session.
##############################################################################


class VersionError(BaseError, ValueError):
    """Unknown IP version."""


class IndexNotFound(BaseError, ValueError):
    """Protocol not in ProtoChain."""


class ProtocolError(BaseError, ValueError):
    """Invalid protocol format."""


class EndianError(BaseError, ValueError):
    """Invalid endian (byte order)."""


class KeyExists(BaseError, ValueError):
    """Key already exists."""


class NoDefaultValue(BaseError, ValueError):
    """No default value."""


class EnumValueError(BaseError, ValueError):
    """No member of an enumeration carries this value.

    The value-miss half of the pair whose name-miss half is
    :exc:`~pcapkit.utilities.exceptions.EnumKeyError`; see that one for the
    stdlib :class:`~enum.Enum` shape both follow, and for why the two halves
    derive from different builtins.

    """


class FieldValueError(BaseError, ValueError):
    """Invalid field value."""


class SchemaError(BaseError, ValueError):
    """Invalid schema."""


class SeekError(BaseError, ValueError):
    """Invalid seek position."""


class TruncateError(BaseError, ValueError):
    """Invalid truncate size."""


class VendorPathNotFound(BaseError, ValueError):
    """Crawler module is not inside the ``vendor`` package root."""


##############################################################################
# NotImplementedError session.
##############################################################################


class ProtocolNotImplemented(BaseError, NotImplementedError):
    """Protocol not implemented."""


class VendorNotImplemented(BaseError, NotImplementedError):
    """Vendor not implemented."""


##############################################################################
# struct.error session.
##############################################################################


class StructError(BaseError, struct.error):
    """Unpack failed."""

    def __init__(self, *args: 'Any', eof: 'bool' = False, **kwargs: 'Any') -> 'None':
        self.eof = eof
        super().__init__(*args, **kwargs)


##############################################################################
# EOFError session.
##############################################################################


class StreamEOFError(BaseError, EOFError):
    """Underlying stream exhausted; no data left to read.

    Raised by :func:`~pcapkit.utilities.decorators.prepare` when the *length*
    of a schema's read was derived by measuring what is actually left in the
    stream -- rather than declared by the caller -- and that measurement came
    back zero. This is the frame reader's "no more packets" signal, so it
    subclasses :exc:`EOFError` rather than replacing it: existing ``except
    (EOFError, StopIteration)`` handlers keep working unchanged, and a caller
    that wants to be more specific can catch this instead.

    A *declared* zero length -- a nested schema legitimately sized to have
    nothing to read -- is a different situation and does not raise this.

    Note:
        :func:`~pcapkit.utilities.decorators.prepare` always raises this with
        ``quiet=True``: reaching end of stream is the frame reader's ordinary
        way of finding out there is nothing left to parse, not a fault to
        log -- the same convention
        :exc:`~pcapkit.utilities.exceptions.StructError` follows for the
        same situation via its own ``eof=True``.

    """


##############################################################################
# KeyError session.
##############################################################################


class MissingKeyError(BaseError, KeyError):
    """Key not found."""


class FragmentError(BaseError, KeyError):
    """Invalid fragment dict."""


class PacketError(BaseError, KeyError):
    """Invalid packet dict."""


class EnumKeyError(BaseError, KeyError):
    """No member of an enumeration carries this name.

    The name-miss half of the pair whose value-miss half is
    :exc:`~pcapkit.utilities.exceptions.EnumValueError`, and the split between
    them follows stdlib :class:`~enum.Enum` rather than this package's own
    taste: ``E['nosuch']`` raises :exc:`KeyError` and ``E(999)`` raises
    :exc:`ValueError`, so a lookup that misses by *name* is
    :exc:`KeyError`-derived and one that misses by *value* is
    :exc:`ValueError`-derived. That is a ruling given in review of :issue:`877`'s
    phase-2 re-parenting, carried out by GitHub issue :issue:`923`: raise
    whichever of the two stdlib :class:`~enum.Enum` would raise in the same
    circumstances, and raise it from this module rather than as a builtin.

    Deriving from :exc:`KeyError` is what makes that ruling cheap to carry out:
    :meth:`~pcapkit.corekit.enum.EnumLookup.get` raised a bare builtin
    :exc:`KeyError` on a name miss until :issue:`923`, and six in-library call sites
    catch it -- :meth:`~pcapkit.const.http.method.Method.get` catches it in
    order to *mint*, so for that one a failed name lookup is part of a
    successful call. Every one of them keeps catching, unchanged.

    Note:
        Distinct from :exc:`~pcapkit.utilities.exceptions.MissingKeyError`,
        which is deliberately not reused here: that one reports an absent
        *mapping* key, as :class:`~pcapkit.corekit.multidict.MultiDict` and the
        :mod:`pcapkit.toolkit` extractors raise it, and conflating the two
        would leave a caller unable to tell a registry that has no such member
        from a packet dict that has no such field.

    """


##############################################################################
# ModuleNotFoundError session.
##############################################################################


class ModuleNotFound(BaseError, ModuleNotFoundError):
    """Module not found."""
    # kwargs: name, path


##############################################################################
# io.UnsupportedOperation session.
##############################################################################


class UnsupportedOperation(BaseError, io.UnsupportedOperation):
    """Unsupported operation."""
