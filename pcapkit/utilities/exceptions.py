# -*- coding: utf-8 -*-
"""user defined exceptions

`pcapkit.exceptions` refined built-in exceptions. Make it
possible to show only user error stack infomation, when
exception raised on user's operation.

"""
import os
import struct
import sys
import traceback

from pcapkit.utilities.compat import ModuleNotFoundError  # pylint: disable=redefined-builtin

__all__ = [
    'BaseError',                                                    # Exception
    'DigitError', 'IntError', 'RealError', 'ComplexError',          # TypeError
    'BoolError', 'BytesError', 'StringError', 'BytearrayError',     # TypeError
    'DictError', 'ListError', 'TupleError', 'IterableError',        # TypeError
    'IOObjError', 'ProtocolUnbound', 'CallableError',               # TypeError
    'InfoError', 'IPError', 'EnumError', 'ComparisonError',         # TypeError
    'FormatError', 'UnsupportedCall',                               # AttributeError
    'FileError',                                                    # IOError
    'FileExists',                                                   # FileExistsError
    'FileNotFound',                                                 # FileNotFoundError
    'ProtocolNotFound',                                             # IndexError
    'VersionError', 'IndexNotFound', 'ProtocolError',               # ValueError
    'EndianError',                                                  # ValueError
    'ProtocolNotImplemented', 'VendorNotImplemented',               # NotImplementedError
    'StructError',                                                  # struct.error
    'FragmentError', 'PacketError',                                 # KeyError
    'ModuleNotFound',                                               # ModuleNotFoundError
]

# boolean mappings
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}

# DEVMODE flag
DEVMODE = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_DEVMODE', 'false').casefold(), False)


def stacklevel():
    """Fetch current stack level."""
    pcapkit = f'{os.path.sep}pcapkit{os.path.sep}'
    tb = traceback.extract_stack()
    for index, tbitem in enumerate(tb):
        if pcapkit in tbitem[0]:
            break
    else:
        index = len(tb)
    return index-1


##############################################################################
# BaseError (abc of exceptions) session.
##############################################################################


class BaseError(Exception):
    """Base error class of all kinds.

    Cautions:
        * Turn off system-default traceback function by set `sys.tracebacklimit` to 0.
        * But bugs appear in Python 3.6, so we have to set `sys.tracebacklimit` to None.
            > this note is deprecated since Python fixed the problem above
        * In Python 2.7, `trace.print_stack(limit)` dose not support negative limit.

    """
    def __init__(self, *args, quiet=False, **kwargs):
        if DEVMODE:
            index = stacklevel()
            if not quiet and index:
                fmt_exc = traceback.format_exc(limit=-index)
                if len(fmt_exc.splitlines(True)) > 1:
                    print(fmt_exc, file=sys.stderr)
        else:
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
    """The argument(s) must be bytes type."""


class BytearrayError(BaseError, TypeError):
    """The argument(s) must be bytearray type."""


class BoolError(BaseError, TypeError):
    """The argument(s) must be bool type."""


class StringError(BaseError, TypeError):
    """The argument(s) must be str type."""


class DictError(BaseError, TypeError):
    """The argument(s) must be dict type."""


class ListError(BaseError, TypeError):
    """The argument(s) must be list type."""


class TupleError(BaseError, TypeError):
    """The argument(s) must be tuple type."""


class IterableError(BaseError, TypeError):
    """The argument(s) must be iterable."""


class CallableError(BaseError, TypeError):
    """The argument(s) must be callable."""


class ProtocolUnbound(BaseError, TypeError):
    """Protocol slice unbound."""


class IOObjError(BaseError, TypeError):
    """The argument(s) must be file-like object."""


class InfoError(BaseError, TypeError):
    """The argument(s) must be Info instance."""


class IPError(BaseError, TypeError):
    """The argument(s) must be IP address."""


class EnumError(BaseError, TypeError):
    """The argument(s) must be enumeration protocol type."""


class ComparisonError(BaseError, TypeError):
    """Rich comparison not supported between instances."""


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


##############################################################################
# KeyError session.
##############################################################################


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
