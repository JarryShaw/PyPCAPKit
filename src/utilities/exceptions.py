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
    'ProtocolNotImplemented',                                       # NotImplementedError
    'StructError',                                                  # struct.error
    'FragmentError', 'PacketError',                                 # KeyError
    'ModuleNotFound',                                               # ModuleNotFoundError
]


def stacklevel():
    """Fetch current stack level."""
    pcapkit = '{}pcapkit{}'.format(os.path.sep, os.path.sep)
    tb = traceback.extract_stack()
    for index, tbitem in enumerate(tb):
        if pcapkit in tbitem[0]:
            break
    else:
        index = len(tb)
    return (index-1)


##############################################################################
# BaseError (abc of exceptions) session.
##############################################################################


class BaseError(Exception):
    """Base error class of all kinds.

    Cautions:
        * Turn off system-default traceback function by set `sys.tracebacklimit` to 0.
        * But bugs appear in Python 3.6, so we have to set `sys.tracebacklimit` to None.
            > this note is deprecated since Python fixed the problem above
        * In Python 2.7, `trace.print_stack(limit=None)` dose not support negative limit.

    """
    def __init__(self, *args, **kwargs):
        index = stacklevel()
        quiet = kwargs.pop('quiet', False)
        if not quiet and index:
            fmt_exc = traceback.format_exc(limit=-index)
            if len(fmt_exc.splitlines(True)) > 1:
                print(fmt_exc, file=sys.stderr)

        sys.tracebacklimit = 0
        super().__init__(*args, **kwargs)


##############################################################################
# TypeError session.
##############################################################################


class DigitError(BaseError, TypeError):
    """The argument(s) must be (a) number(s)."""
    pass


class IntError(BaseError, TypeError):
    """The argument(s) must be integral."""
    pass


class RealError(BaseError, TypeError):
    """The function is not defined for real number."""
    pass


class ComplexError(BaseError, TypeError):
    """The function is not defined for complex instance."""
    pass


class BytesError(BaseError, TypeError):
    """The argument(s) must be bytes type."""
    pass


class BytearrayError(BaseError, TypeError):
    """The argument(s) must be bytearray type."""
    pass


class BoolError(BaseError, TypeError):
    """The argument(s) must be bool type."""
    pass


class StringError(BaseError, TypeError):
    """The argument(s) must be str type."""
    pass


class DictError(BaseError, TypeError):
    """The argument(s) must be dict type."""
    pass


class ListError(BaseError, TypeError):
    """The argument(s) must be list type."""
    pass


class TupleError(BaseError, TypeError):
    """The argument(s) must be tuple type."""
    pass


class IterableError(BaseError, TypeError):
    """The argument(s) must be iterable."""
    pass


class CallableError(BaseError, TypeError):
    """The argument(s) must be callable."""
    pass


class ProtocolUnbound(BaseError, TypeError):
    """Protocol slice unbound."""
    pass


class IOObjError(BaseError, TypeError):
    """The argument(s) must be file-like object."""
    pass


class InfoError(BaseError, TypeError):
    """The argument(s) must be Info instance."""
    pass


class IPError(BaseError, TypeError):
    """The argument(s) must be IP address."""
    pass


class EnumError(BaseError, TypeError):
    """The argument(s) must be enumeration protocol type."""
    pass


class ComparisonError(BaseError, TypeError):
    """Rich comparison not supported between instances."""
    pass


##############################################################################
# AttributeError session.
##############################################################################


class FormatError(BaseError, AttributeError):
    """Unknown format(s)."""
    pass


class UnsupportedCall(BaseError, AttributeError):
    """Unsupported function or property call."""
    pass


##############################################################################
# IOError session.
##############################################################################


class FileError(BaseError, IOError):
    """[Errno 5] Wrong file format."""

    def __init__(self, errno=None, strerror=None, filename=None, winerror=None, filename2=None, *args, **kwargs):
        super().__init__(errno, strerror, filename, winerror, filename2, *args, **kwargs)


##############################################################################
# FileExistsError session.
##############################################################################


class FileExists(BaseError, FileExistsError):
    """[Errno 17] File already exists."""

    def __init__(self, errno=None, strerror=None, filename=None, winerror=None, filename2=None, *args, **kwargs):
        super().__init__(errno, strerror, filename, winerror, filename2, *args, **kwargs)


##############################################################################
# FileNotFoundError session.
##############################################################################


class FileNotFound(BaseError, FileNotFoundError):
    """[Errno 2] File not found."""
    def __init__(self, errno=None, strerror=None, filename=None, winerror=None, filename2=None, *args, **kwargs):
        super().__init__(errno, strerror, filename, winerror, filename2, *args, **kwargs)


##############################################################################
# IndexError session.
##############################################################################


class ProtocolNotFound(BaseError, IndexError):
    """Protocol not found in ProtoChain."""
    pass


##############################################################################
# ValueError session.
##############################################################################


class VersionError(BaseError, ValueError):
    """Unknown IP version."""
    pass


class IndexNotFound(BaseError, ValueError):
    """Protocol not in ProtoChain."""
    pass


class ProtocolError(BaseError, ValueError):
    """Invalid protocol format."""
    pass


class EndianError(BaseError, ValueError):
    """Invalid endian (byte order)."""
    pass


##############################################################################
# NotImplementedError session.
##############################################################################


class ProtocolNotImplemented(BaseError, NotImplementedError):
    """Protocol not implemented."""
    pass


##############################################################################
# struct.error session.
##############################################################################


class StructError(BaseError, struct.error):
    """Unpack failed."""
    pass


##############################################################################
# KeyError session.
##############################################################################


class FragmentError(BaseError, KeyError):
    """Invalid fragment dict."""
    pass


class PacketError(BaseError, KeyError):
    """Invalid packet dict."""
    pass


##############################################################################
# ModuleNotFoundError session.
##############################################################################


class ModuleNotFound(BaseError, ModuleNotFoundError):
    """Module not found."""
    def __init__(self, msg=None, *args, name=None, path=None, **kwargs):
        super().__init__(msg, *args, name=name, path=path, **kwargs)
