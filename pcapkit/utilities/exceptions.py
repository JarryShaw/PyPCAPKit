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
from typing import TYPE_CHECKING

from pcapkit.utilities.compat import ModuleNotFoundError  # pylint: disable=redefined-builtin
from pcapkit.utilities.logging import DEVMODE, VERBOSE, get_logger

if TYPE_CHECKING:
    from typing import Any

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
    'EndianError', 'KeyExists', 'NoDefaultValue',                   # ValueError
    'FieldValueError', 'SchemaError', 'SeekError', 'TruncateError', # ValueError
    'ProtocolNotImplemented', 'VendorNotImplemented',               # NotImplementedError
    'StructError',                                                  # struct.error
    'StreamEOFError',                                               # EOFError
    'MissingKeyError', 'FragmentError', 'PacketError',              # KeyError
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
    :func:`traceback.extract_stack`, which cannot be used here:
    :meth:`traceback.StackSummary.extract` honours :data:`sys.tracebacklimit`, and
    :class:`BaseError` sets that to ``0`` for every loud error outside development
    mode. One such error therefore made ``extract_stack()`` return an *empty* list
    for the rest of the process, which is where the old ``-1`` came from -- so in
    ordinary use the first error silently broke the attribution of every warning
    after it. Walking frames also skips building the :class:`~traceback.FrameSummary`
    objects and the :mod:`linecache` lookups behind them, which is worth having on
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
    also sets :data:`sys.tracebacklimit` to ``0``, which suppresses the traceback
    frames entirely, so a user sees the exception line rather than a walk through
    :mod:`pcapkit`'s internals.

    A **quiet** error (``quiet=True``) is one :mod:`pcapkit` raises as internal
    control flow and expects to catch itself, such as the
    :exc:`~pcapkit.utilities.exceptions.MissingKeyError` behind
    :meth:`MultiDict.get <pcapkit.corekit.multidict.MultiDict.get>`. It is
    therefore silent and free of side effects: nothing is logged, and
    :data:`sys.tracebacklimit` is left alone. It is still a perfectly ordinary
    exception, carrying its message for whoever catches it.

    Important:

        * :data:`sys.tracebacklimit` is process-global, so it is only set for a
          loud error -- a quiet one used as control flow must not truncate the
          tracebacks of unrelated exceptions for the rest of the process.
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
                sys.tracebacklimit = 0
        super().__init__(*args, **kwargs)


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


class FieldValueError(BaseError, ValueError):
    """Invalid field value."""


class SchemaError(BaseError, ValueError):
    """Invalid schema."""


class SeekError(BaseError, ValueError):
    """Invalid seek position."""


class TruncateError(BaseError, ValueError):
    """Invalid truncate size."""


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
