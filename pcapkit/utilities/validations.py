# -*- coding: utf-8 -*-
"""validation utilities

:mod:`pcapkit.utilities.validations` contains functions to
validate arguments for functions and classes. It was first
used in `PyNTLib`_ as validators.

.. _PyNTLib: https://github.com/JarryShaw/pyntlib

"""
import collections.abc
import enum
import inspect
import io
import ipaddress
import numbers

import aenum

from pcapkit.utilities.exceptions import (BoolError, BytearrayError, BytesError, ComplexError,
                                          DictError, DigitError, EnumError, FragmentError,
                                          InfoError, IntError, IOObjError, IPError, ListError,
                                          PacketError, RealError, StringError, TupleError)

__all__ = [
    'int_check', 'real_check', 'complex_check', 'number_check',
    'bool_check', 'bytes_check', 'bytearray_check', 'str_check',
    'list_check', 'dict_check', 'tuple_check', 'io_check',
    'frag_check', 'pkt_check', 'info_check', 'ip_check'
]


def int_check(*args, stacklevel=2):
    """Check if arguments are *integrals* (``int``).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        IntError: If any of the arguments is **NOT** *integral* (``int``).

    """
    for var in args:
        if not isinstance(var, numbers.Integral):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise IntError(f'Function {func} expected integral number, {name} got instead.')


def real_check(*args, stacklevel=2):
    """Check if arguments are *real numbers* (``int`` and/or ``float``).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        RealError: If any of the arguments is **NOT** *real number* (``int`` and/or ``float``).

    """
    for var in args:
        if not isinstance(var, numbers.Real):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise RealError(f'Function {func} expected real number, {name} got instead.')


def complex_check(*args, stacklevel=2):
    """Check if arguments are *complex numbers* (``complex``).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        ComplexError: If any of the arguments is **NOT** *complex number* (``complex``).

    """
    for var in args:
        if not isinstance(var, numbers.Complex):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise ComplexError(f'Function {func} expected complex number, {name} got instead.')


def number_check(*args, stacklevel=2):
    """Check if arguments are *numbers*.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        DigitError: If any of the arguments is **NOT** *number* (``int``, ``float`` and/or ``complex``).

    """
    for var in args:
        if not isinstance(var, numbers.Number):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise DigitError(f'Function {func} expected number, {name} got instead.')


def bytes_check(*args, stacklevel=2):
    """Check if arguments are :obj:`bytes` type.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        BytesError: If any of the arguments is **NOT** :obj:`bytes` type.

    """
    for var in args:
        if not isinstance(var, (bytes, collections.abc.ByteString)):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise BytesError(f'Function {func} expected bytes, {name} got instead.')


def bytearray_check(*args, stacklevel=2):
    """Check if arguments are ``bytearray`` type.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        BytearrayError: If any of the arguments is **NOT** ``bytearray`` type.

    """
    for var in args:
        if not isinstance(var, (bytearray, collections.abc.ByteString, collections.abc.MutableSequence)):
            name = type(var).__name__func = inspect.stack()[stacklevel][3]
            func = inspect.stack()[stacklevel][3]
            raise BytearrayError(f'Function {func} expected bytearray, {name} got instead.')


def str_check(*args, stacklevel=2):
    """Check if arguments are :obj:`str` type.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        StringError: If any of the arguments is **NOT** :obj:`str` type.

    """
    for var in args:
        if not isinstance(var, (str, collections.UserString, collections.abc.Sequence)):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise StringError(f'Function {func} expected str, {name} got instead.')


def bool_check(*args, stacklevel=2):
    """Check if arguments are ``bool`` type.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        BoolError: If any of the arguments is **NOT** ``bool`` type.

    """
    for var in args:
        if not isinstance(var, bool):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise BoolError(f'Function {func} expected bool, {name} got instead.')


def list_check(*args, stacklevel=2):
    """Check if arguments are ``list`` type.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        ListError: If any of the arguments is **NOT** ``list`` type.

    """
    for var in args:
        if not isinstance(var, (list, collections.UserList, collections.abc.MutableSequence)):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise ListError(f'Function {func} expected list, {name} got instead.')


def dict_check(*args, stacklevel=2):
    """Check if arguments are :obj:`dict` type.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        DictError: If any of the arguments is **NOT** :obj:`dict` type.

    """
    for var in args:
        if not isinstance(var, (dict, collections.UserDict, collections.abc.MutableMapping)):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise DictError(f'Function {func} expected dict, {name} got instead.')


def tuple_check(*args, stacklevel=2):
    """Check if arguments are :obj:`tuple` type.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        TupleError: If any of the arguments is **NOT** :obj:`tuple` type.

    """
    for var in args:
        if not isinstance(var, (tuple, collections.abc.Sequence)):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise TupleError(f'Function {func} expected tuple, {name} got instead.')


def io_check(*args, stacklevel=2):
    """Check if arguments are *file-like object* (``io.IOBase``).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        IOObjError: If any of the arguments is **NOT** *file-like object* (``io.IOBase``).

    """
    for var in args:
        if not isinstance(var, io.IOBase):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise IOObjError(f'Function {func} expected file-like object, {name} got instead.')


def info_check(*args, stacklevel=2):
    """Check if arguments are :class:`~pcapkit.corekit.infoclass.Info` instances.

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        InfoError: If any of the arguments is **NOT** :class:`~pcapkit.corekit.infoclass.Info` instance.

    """
    from pcapkit.corekit.infoclass import Info  # pylint: disable=import-outside-toplevel

    for var in args:
        if not isinstance(var, Info):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise InfoError(f'Function {func} expected Info instance, {name} got instead.')


def ip_check(*args, stacklevel=2):
    """Check if arguments are *IP addresses* (``ipaddress.IPv4Address`` and/or ``ipaddress.IPv6Address``).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        IPError: If any of the arguments is **NOT** *IP address*
            (``ipaddress.IPv4Address`` and/or ``ipaddress.IPv6Address``).

    """
    for var in args:
        if not isinstance(var, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise IPError(f'Function {func} expected IP address, {name} got instead.')


def enum_check(*args, stacklevel=2):
    """Check if arguments are of *enumeration protocol* type (``enum.EnumMeta`` and/or ``aenum.EnumMeta``).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        EnumError: If any of the arguments is **NOT** *enumeration protocol* type
            (``enum.EnumMeta`` and/or ``aenum.EnumMeta``).

    """
    for var in args:
        if not isinstance(var, (enum.EnumMeta, aenum.EnumMeta)):
            name = type(var).__name__
            func = inspect.stack()[stacklevel][3]
            raise EnumError(f'Function {func} expected enumeration, {name} got instead.')


def frag_check(*args, protocol, stacklevel=3):
    """Check if arguments are valid fragments.

    Args:
        *args: Arguments to check.
        protocol (str): Originated fragmentation protocol (IPv4, IPv6 or TCP).
        stacklevel (int): Stack level to fetch originated function name.

    - If the protocol is IPv4, the fragment should be as an IPv4 :term:`fragmentation <ipv4.packet>`.
    - If the protocol is IPv6, the fragment should be as an IPv6 :term:`fragmentation <ipv6.packet>`.
    - If the protocol is TCP, the fragment should be as an TCP :term:`fragmentation <tcp.packet>`.

    Raises:
        FragmentError: If any of the arguments is **NOT** valid fragment.

    See Also:
        * :func:`pcapkit.utilities.validations._ip_frag_check`
        * :func:`pcapkit.utilities.validations._tcp_frag_check`

    """
    if 'IP' in protocol:
        try:
            _ip_frag_check(*args, stacklevel=stacklevel)
        except KeyError as error:
            raise FragmentError(f'Missing fragment key: {error.args[0]}')
        except Exception as error:
            raise FragmentError(f'Malformed fragment object: {error}')
    elif 'TCP' in protocol:
        try:
            _tcp_frag_check(*args, stacklevel=stacklevel)
        except KeyError as error:
            raise FragmentError(f'Missing fragment key: {error.args[0]}')
        except Exception as error:
            raise FragmentError(f'Malformed fragment object: {error}')
    else:
        raise FragmentError(f'Unknown fragmented protocol {protocol}.')


def _ip_frag_check(*args, stacklevel=3):
    """Check if arguments are valid IP fragments (:term:`IPv4 <ipv4.packet>` and/or :term:`IPv6 <ipv6.packet>` packet).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    See Also:
        * :func:`pcapkit.toolkit.default.ipv4_reassembly`
        * :func:`pcapkit.toolkit.default.ipv6_reassembly`

    """
    for var in args:
        dict_check(var, stacklevel=stacklevel)
        bufid = var['bufid']
        str_check(bufid[3], stacklevel=stacklevel)
        bool_check(var['mf'], stacklevel=stacklevel)
        ip_check(bufid[0], bufid[1], stacklevel=stacklevel)
        bytearray_check(var['header'], var['payload'], stacklevel=stacklevel)
        int_check(bufid[2], var['num'], var['fo'],
                  var['ihl'], var['tl'], stacklevel=stacklevel)


def _tcp_frag_check(*args, stacklevel=3):
    """Check if arguments are valid TCP fragments (:term:`TCP packet <tcp.packet>`).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    See Also:
        :func:`pcapkit.toolkit.default.tcp_reassembly`

    """
    for var in args:
        dict_check(var, stacklevel=stacklevel)
        bufid = var['bufid']
        ip_check(bufid[0], bufid[1], stacklevel=stacklevel)
        bytearray_check(var['payload'], stacklevel=stacklevel)
        bool_check(var['syn'], var['fin'], stacklevel=stacklevel)
        int_check(bufid[2], bufid[3], var['num'], var['ack'], var['dsn'],
                  var['first'], var['last'], var['len'], stacklevel=stacklevel)


def pkt_check(*args, stacklevel=3):
    """Check if arguments are valid packets (:term:`TCP packet <trace.packet>`).

    Args:
        *args: Arguments to check.
        stacklevel (int): Stack level to fetch originated function name.

    Raises:
        PacketError: If any of the arguments is **NOT** valid packet.

    See Also:
        :func:`pcapkit.toolkit.default.tcp_traceflow`

    """
    try:
        for var in args:
            dict_check(var, stacklevel=stacklevel)
            dict_check(var['frame'], stacklevel=stacklevel)
            enum_check(var['protocol'], stacklevel=stacklevel)
            real_check(var['timestamp'], stacklevel=stacklevel)
            ip_check(var['src'], var['dst'], stacklevel=stacklevel)
            bool_check(var['syn'], var['fin'], stacklevel=stacklevel)
            int_check(var['srcport'], var['dstport'], var['index'], stacklevel=stacklevel)
    except KeyError as error:
        raise PacketError(f'Missing packet key: {error.args[0]}')
    except Exception as error:
        raise PacketError(f'Malformed packet object: {error}')


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
