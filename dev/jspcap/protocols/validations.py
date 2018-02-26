#!/usr/bin/python3
# -*- coding: utf-8 -*-


import inspect
import numbers


# Validation utilities
# Validates arguments for functions


from .exceptions import BoolError, IntError


def bool_check(*args):
    """Check if arguments are bytes type."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, bool):
            name = type(var).__name__
            raise BoolError(f'Function {func} expected bool, {name} got instead.')


def int_check(*args):
    """Check if arguments are integrals."""
    func = inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Integral):
            name = type(var).__name__
            raise IntError(f'Function {func} expected int, {name} got instead.')
