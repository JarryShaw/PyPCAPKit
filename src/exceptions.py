#!/usr/bin/python3
# -*- coding: utf-8 -*-


import sys
import traceback


# user defined exceptions
# show refined infomation when exceptions raised


__all__ = [
    'BaseError',
    'DigitError', 'IntError', 'RealError', 'ComplexError', 'BoolError',
    'BytesError', 'StringError', 'DictError', 'ListError', 'TupleError', 'ProtocolUnbound',
    'FormatError', 'UnsupportedCall',
    'FileError',
    'ProtocolNotFound',
    'VersionError', 'IndexNotFound',
]


##############################################################################
# BaseError (abc of exceptions) session.
##############################################################################

class BaseError(Exception):
    """Base error class of all kinds.

    Cautions:

    * Turn off system-default traceback function by set `sys.tracebacklimit` to 0.
    * But bugs appear in Python 3.6, so we have to set `sys.tracebacklimit` to None.
    * In Python 2.7, `trace.print_stack(limit=None)` dose not support negative limit.

    """
    def __init__(self, message):
        tb = traceback.extract_stack()
        for tbitem in tb:
            if 'jspcap' in tbitem[0]:
                break
        index = tb.index(tbitem)

        print('Traceback (most recent call last):')
        traceback.print_stack(limit=-index)
        sys.tracebacklimit = None
        super().__init__(message)


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

class ProtocolUnbound(BaseError, TypeError):
    """Protocol slice unbound."""
    pass


##############################################################################
# AttributeError session.
##############################################################################

class FormatError(BaseError, AttributeError):
    """Unknow format(s)."""
    pass

class UnsupportedCall(BaseError, AttributeError):
    """Unsupported function or property call."""
    pass


##############################################################################
# IOError session.
##############################################################################

class FileError(BaseError, IOError):
    """Wrong file format."""
    pass


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
