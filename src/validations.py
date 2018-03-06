#!/usr/bin/python3
# -*- coding: utf-8 -*-


import inspect
import numbers


# Validation utilities
# Validates arguments for functions


from jspcap.exceptions import BoolError, DictError, DigitError, IntError, ListError, RealError, TupleError


__all__ = [
    'int_check', 'real_check', 'complex_check', 'number_check', 'bool_check',
    'bytes_check', 'str_check', 'list_check', 'dict_check', 'tuple_check',
]


def int_check(*args):
    """Check if arguments are integrals."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Integral):
            name = type(var).__name__
            raise IntError(f'Function {func} expected int, {name} got instead.')


def real_check(*args):
    """Check if arguments are real numbers."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Real):
            name = type(var).__name__
            raise RealError('Function {func} expected real number, {name} got instead.')


def complex_check(*args):
    """Check if arguments are complex numbers."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Complex):
            name = type(var).__name__
            raise ComplexError(f'Function {func} expected complex number, {name} got instead.')


def number_check(*args):
    """Check if arguments are numbers."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Number):

            raise DigitError(f'Function {func} expected number, {name} got instead.')


def bytes_check(*args):
    """Check if arguments are bytes type."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, bytes):
            name = type(var).__name__
            raise BytesError(f'Function {func} expected bytes, {name} got instead.')


def str_check(*args):
    """Check if arguments are str type."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, str):
            name = type(var).__name__
            raise StringError(f'Function {func} expected str, {name} got instead.')


def bool_check(*args):
    """Check if arguments are bytes type."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, bool):
            name = type(var).__name__
            raise BoolError(f'Function {func} expected bool, {name} got instead.')


def list_check(*args):
    """Check if arguments are list type."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, list):
            name = type(var).__name__
            raise ListError(f'Function {func} expected list, {name} got instead.')


def dict_check(*args):
    """Check if arguments are dict type."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, dict):
            name = type(var).__name__
            raise DictError(f'Function {func} expected dict, {name} got instead.')


def tuple_check(*args):
    """Check if arguments are tuple type."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, tuple):
            raise TupleError(f'Function {func} expected tuple, {name} got instead.')
