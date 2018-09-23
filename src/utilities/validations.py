# -*- coding: utf-8 -*-
"""validation utilities

`pcapkit.utilities.validations` contains functions to validate
arguments for functions and classes. It was first used in
[`ntlib`](https://github.com/JarryShaw/pyntlib) as
validators.

"""
import collections.abc
import enum
import inspect
import ipaddress
import numbers

import aenum
from pcapkit.utilities.exceptions import (BoolError, BytearrayError,
                                          BytesError, ComplexError, DictError,
                                          DigitError, EnumError, FragmentError,
                                          InfoError, IntError, IOObjError,
                                          IPError, ListError, PacketError,
                                          RealError, StringError, TupleError)

# TODO: considering reconstructing validations with `typing` module
import _io

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
                'Function {} expected integral number, {} got instead.'.format(func, name))


def real_check(*args, func=None):
    """Check if arguments are real numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Real):
            name = type(var).__name__
            raise ComplexError(
                'Function {} expected real number, {} got instead.'.format(func, name))


def complex_check(*args, func=None):
    """Check if arguments are complex numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Complex):
            name = type(var).__name__
            raise ComplexError(
                'Function {} expected complex number, {} got instead.'.format(func, name))


def number_check(*args, func=None):
    """Check if arguments are numbers."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, numbers.Number):
            name = type(var).__name__
            raise DigitError(
                'Function {} expected number, {} got instead.'.format(func, name))


def bytes_check(*args, func=None):
    """Check if arguments are bytes type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (bytes, collections.abc.ByteString)):
            name = type(var).__name__
            raise BytesError(
                'Function {} expected bytes, {} got instead.'.format(func, name))


def bytearray_check(*args, func=None):
    """Check if arguments are bytearray type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (bytearray, collections.abc.ByteString, collections.abc.MutableSequence)):
            name = type(var).__name__
            raise BytearrayError(
                'Function {} expected bytearray, {} got instead.'.format(func, name))


def str_check(*args, func=None):
    """Check if arguments are str type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (str, collections.UserString, collections.abc.Sequence)):
            name = type(var).__name__
            raise StringError(
                'Function {} expected str, {} got instead.'.format(func, name))


def bool_check(*args, func=None):
    """Check if arguments are bytes type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, bool):
            name = type(var).__name__
            raise BoolError(
                'Function {} expected bool, {} got instead.'.format(func, name))


def list_check(*args, func=None):
    """Check if arguments are list type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (list, collections.UserList, collections.abc.MutableSequence)):
            name = type(var).__name__
            raise ListError(
                'Function {} expected list, {} got instead.'.format(func, name))


def dict_check(*args, func=None):
    """Check if arguments are dict type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (dict, collections.UserDict, collections.abc.MutableMapping)):
            name = type(var).__name__
            raise DictError(
                'Function {} expected dict, {} got instead.'.format(func, name))


def tuple_check(*args, func=None):
    """Check if arguments are tuple type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (tuple, collections.abc.Sequence)):
            name = type(var).__name__
            raise TupleError(
                'Function {} expected tuple, {} got instead.'.format(func, name))


def io_check(*args, func=None):
    """Check if arguments are file-like object."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, _io._IOBase):
            name = type(var).__name__
            raise IOObjError(
                'Function {} expected file-like object, {} got instead.'.format(func, name))


def info_check(*args, func=None):
    """Check if arguments are Info instance."""
    from pcapkit.corekit.infoclass import Info

    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, Info):
            name = type(var).__name__
            raise InfoError(
                'Function {} expected Info instance, {} got instead.'.format(func, name))


def ip_check(*args, func=None):
    """Check if arguments are IP addresses."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, ipaddress._IPAddressBase):
            name = type(var).__name__
            raise IPError(
                'Function {} expected IP address, {} got instead.'.format(func, name))


def enum_check(*args, func=None):
    """Check if arguments are of protocol type."""
    func = func or inspect.stack()[2][3]
    for var in args:
        if not isinstance(var, (enum.EnumMeta, aenum.EnumMeta)):
            name = type(var).__name__
            raise EnumError(
                'Function {} expected enumeration, {} got instead.'.format(func, name))


def frag_check(*args, protocol, func=None):
    """Check if arguments are valid fragments."""
    func = func or inspect.stack()[2][3]
    if 'IP' in protocol:
        _ip_frag_check(*args, func=func)
    elif 'TCP' in protocol:
        _tcp_frag_check(*args, func=func)
    else:
        raise FragmentError('Unknown fragmented protocol {}.'.format(protocol))


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
        int_check(var.get('srcport'), var.get(
            'dstport'), var.get('index'), func=func)


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
