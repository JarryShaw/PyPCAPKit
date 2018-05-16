# -*- coding: utf-8 -*-
"""validation utilities

`jspcap.validations` contains functions to validate
arguments for functions and classes. It was first used in
[`jsntlib`](https://github.com/JarryShaw/jspcapy) as
validators.

"""
import inspect
import io
import numbers


# Validation utilities
# Validates arguments for functions


from jspcap.exceptions import BoolError, BytesError, BytearrayError, DictError, DigitError, FragmentError, IntError, IOObjError, ListError, RealError, TupleError


__all__ = [
    'int_check', 'real_check', 'complex_check', 'number_check',
    'bool_check', 'bytes_check', 'bytearray_check', 'str_check',
    'list_check', 'dict_check', 'tuple_check',
    'io_check', 'frag_check',
]


def int_check(*args, func=None):
    """Check if arguments are integrals."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Complex):
            name = type(var).__name__
            raise ComplexError(f'Function {func} expected integral number, {name} got instead.')


def real_check(*args, func=None):
    """Check if arguments are real numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Complex):
            name = type(var).__name__
            raise ComplexError(f'Function {func} expected real number, {name} got instead.')


def complex_check(*args, func=None):
    """Check if arguments are complex numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Complex):
            name = type(var).__name__
            raise ComplexError(f'Function {func} expected complex number, {name} got instead.')


def number_check(*args, func=None):
    """Check if arguments are numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Number):

            raise DigitError(f'Function {func} expected number, {name} got instead.')


def bytes_check(*args, func=None):
    """Check if arguments are bytes type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, bytes):
            name = type(var).__name__
            raise BytesError(f'Function {func} expected bytes, {name} got instead.')


def bytearray_check(*args, func=None):
    """Check if arguments are bytearray type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, bytearray):
            name = type(var).__name__
            raise BytearrayError(f'Function {func} expected bytearray, {name} got instead.')


def str_check(*args, func=None):
    """Check if arguments are str type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, str):
            name = type(var).__name__
            raise StringError(f'Function {func} expected str, {name} got instead.')


def bool_check(*args, func=None):
    """Check if arguments are bytes type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, bool):
            name = type(var).__name__
            raise BoolError(f'Function {func} expected bool, {name} got instead.')


def list_check(*args, func=None):
    """Check if arguments are list type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, list):
            name = type(var).__name__
            raise ListError(f'Function {func} expected list, {name} got instead.')


def dict_check(*args, func=None):
    """Check if arguments are dict type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, dict):
            name = type(var).__name__
            raise DictError(f'Function {func} expected dict, {name} got instead.')


def tuple_check(*args, func=None):
    """Check if arguments are tuple type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, tuple):
            name = type(var).__name__
            raise TupleError(f'Function {func} expected tuple, {name} got instead.')


def io_check(*args, func=None):
    """Check if arguments are file-like type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, io.IOBase):
            name = type(var).__name__
            raise IOObjError(f'Function {func} expected file-like object, {name} got instead.')


def frag_check(*args, protocol, func=None):
    """Check if arguments are valid fragments."""
    func = func or inspect.stack()[2][3]
    if 'IP' in protocol:
        _ip_frag_check(*args, func=func)
    elif 'TCP' in protocol:
        _tcp_frag_check(*args, func=func)
    else:
        raise FragmentError(f'Unknown fragmented protocol {protocol}.')


def _ip_frag_check(*args, func=None):
    """Check if arguments are valid IP fragments."""
    func = func or inspect.stack()[2][3]
    for var in args:
        dict_check(var, func=func)
        bufid = var.get('bufid')
        bool_check(var.get('mf'), func=func)
        str_check(bufid[0], bufid[1], bufid[3], func=func)
        bytearray_check(var.get('header'), var.get('payload'), func=func)
        int_check(bufid[2], var.get('num'), var.get('fo'), var.get('ihl'), var.get('tl'), func=func)


def _tcp_frag_check(*args, func=None):
    """Check if arguments are valid TCP fragments."""
    func = func or inspect.stack()[2][3]
    for var in args:
        dict_check(var, func=func)
        bufid = var.get('bufid')
        str_check(bufid[0], bufid[1], func=func)
        bytearray_check(var.get('payload'), func=func)
        bool_check(var.get('syn'), var.get('fin'), func=func)
        int_check(bufid[2], bufid[3], var.get('num'), var.get('ack'), var.get('dsn'),
                    var.get('first'), var.get('last'), var.get('len'), func=func)


###############################################################################
# Test Codes
# 
# func = sys._getframe().f_back.f_code.co_name
# spec = inspect.getfullargspec(test)
# argv = spec.args + spec.kwonlyargs
# for index, var in enumerate(args):
#     if not isinstance(var, numbers.Integral):
#         raise IntError( f'Function {func.__name__} expected argument {argv[index]} '
#                         f'to be integral number, {type(var).__name__} got instead.' )
# 
###############################################################################
