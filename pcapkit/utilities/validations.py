# -*- coding: utf-8 -*-
"""validation utilities

`pcapkit.utilities.validations` contains functions to validate
arguments for functions and classes. It was first used in
[`ntlib`](https://github.com/JarryShaw/pyntlib) as
validators.

"""
# TODO: considering reconstructing validations with `typing` module

import collections.abc
import enum
import inspect
import io
import ipaddress
import numbers

import aenum

from pcapkit.utilities.exceptions import (BoolError, BytearrayError,
                                          BytesError, ComplexError, DictError,
                                          DigitError, EnumError, FragmentError,
                                          InfoError, IntError, IOObjError,
                                          IPError, ListError, PacketError,
                                          RealError, StringError, TupleError)

__all__ = [
    'int_check', 'real_check', 'complex_check', 'number_check',
    'bool_check', 'bytes_check', 'bytearray_check', 'str_check',
    'list_check', 'dict_check', 'tuple_check', 'io_check',
    'frag_check', 'pkt_check', 'info_check', 'ip_check'
]


def int_check(*args, func=None):
    """Check if arguments are integrals."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Integral):
            name = type(var).__name__
            raise ComplexError(
                f'Function {func} expected integral number, {name} got instead.')


def real_check(*args, func=None):
    """Check if arguments are real numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Real):
            name = type(var).__name__
            raise ComplexError(
                f'Function {func} expected real number, {name} got instead.')


def complex_check(*args, func=None):
    """Check if arguments are complex numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Complex):
            name = type(var).__name__
            raise ComplexError(
                f'Function {func} expected complex number, {name} got instead.')


def number_check(*args, func=None):
    """Check if arguments are numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Number):
            name = type(var).__name__
            raise DigitError(
                f'Function {func} expected number, {name} got instead.')


def bytes_check(*args, func=None):
    """Check if arguments are bytes type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (bytes, collections.abc.ByteString)):
            name = type(var).__name__
            raise BytesError(
                f'Function {func} expected bytes, {name} got instead.')


def bytearray_check(*args, func=None):
    """Check if arguments are bytearray type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (bytearray, collections.abc.ByteString, collections.abc.MutableSequence)):
            name = type(var).__name__
            raise BytearrayError(
                f'Function {func} expected bytearray, {name} got instead.')


def str_check(*args, func=None):
    """Check if arguments are str type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (str, collections.UserString, collections.abc.Sequence)):
            name = type(var).__name__
            raise StringError(
                f'Function {func} expected str, {name} got instead.')


def bool_check(*args, func=None):
    """Check if arguments are bytes type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, bool):
            name = type(var).__name__
            raise BoolError(
                f'Function {func} expected bool, {name} got instead.')


def list_check(*args, func=None):
    """Check if arguments are list type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (list, collections.UserList, collections.abc.MutableSequence)):
            name = type(var).__name__
            raise ListError(
                f'Function {func} expected list, {name} got instead.')


def dict_check(*args, func=None):
    """Check if arguments are dict type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (dict, collections.UserDict, collections.abc.MutableMapping)):
            name = type(var).__name__
            raise DictError(
                f'Function {func} expected dict, {name} got instead.')


def tuple_check(*args, func=None):
    """Check if arguments are tuple type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (tuple, collections.abc.Sequence)):
            name = type(var).__name__
            raise TupleError(
                f'Function {func} expected tuple, {name} got instead.')


def io_check(*args, func=None):
    """Check if arguments are file-like object."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, io.IOBase):
            name = type(var).__name__
            raise IOObjError(
                f'Function {func} expected file-like object, {name} got instead.')


def info_check(*args, func=None):
    """Check if arguments are Info instance."""
    from pcapkit.corekit.infoclass import Info

    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, Info):
            name = type(var).__name__
            raise InfoError(
                f'Function {func} expected Info instance, {name} got instead.')


def ip_check(*args, func=None):
    """Check if arguments are IP addresses."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, ipaddress._IPAddressBase):
            name = type(var).__name__
            raise IPError(
                f'Function {func} expected IP address, {name} got instead.')


def enum_check(*args, func=None):
    """Check if arguments are of protocol type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (enum.EnumMeta, aenum.EnumMeta)):
            name = type(var).__name__
            raise EnumError(
                f'Function {func} expected enumeration, {name} got instead.')


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
        str_check(bufid[3], func=func)
        bool_check(var.get('mf'), func=func)
        ip_check(bufid[0], bufid[1], func=func)
        bytearray_check(var.get('header'), var.get('payload'), func=func)
        int_check(bufid[2], var.get('num'), var.get('fo'),
                  var.get('ihl'), var.get('tl'), func=func)


def _tcp_frag_check(*args, func=None):
    """Check if arguments are valid TCP fragments."""
    func = func or inspect.stack()[2][3]
    for var in args:
        dict_check(var, func=func)
        bufid = var.get('bufid')
        ip_check(bufid[0], bufid[1], func=func)
        bytearray_check(var.get('payload'), func=func)
        bool_check(var.get('syn'), var.get('fin'), func=func)
        int_check(bufid[2], bufid[3], var.get('num'), var.get('ack'), var.get('dsn'),
                  var.get('first'), var.get('last'), var.get('len'), func=func)


def pkt_check(*args, func=None):
    """Check if arguments are valid packets."""
    func = func or inspect.stack()[2][3]
    for var in args:
        dict_check(var, func=func)
        dict_check(var.get('frame'), func=func)
        enum_check(var.get('protocol'), func=func)
        real_check(var.get('timestamp'), func=func)
        ip_check(var.get('src'), var.get('dst'), func=func)
        bool_check(var.get('syn'), var.get('fin'), func=func)
        int_check(var.get('srcport'), var.get('dstport'), var.get('index'), func=func)


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
