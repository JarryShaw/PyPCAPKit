# -*- coding: utf-8 -*-
"""Foundation Registries
===========================

.. module:: pcapkit.foundation.registry.foundation

This module provides the foundation registries for :mod:`pcapkit`.

"""
from typing import TYPE_CHECKING, cast, overload

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
from pcapkit.foundation.reassembly.ipv6 import IPv6 as IPv6_Reassembly
from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
from pcapkit.foundation.traceflow import TraceFlow
from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow
from pcapkit.utilities.logging import logger

if TYPE_CHECKING:
    from typing import Type

    from dictdumper import Dumper

    from pcapkit.foundation.engines import Engine
    from pcapkit.foundation.reassembly.reassembly import CallbackFn as Reasm_CallbackFn
    from pcapkit.foundation.reassembly.reassembly import Reassembly
    from pcapkit.foundation.traceflow.traceflow import CallbackFn as Trace_CallbackFn

__all__ = [
    'register_extractor_engine',

    'register_dumper',
    'register_extractor_dumper', 'register_traceflow_dumper',

    'register_reassembly_ipv4_callback', 'register_reassembly_ipv6_callback',
    'register_reassembly_tcp_callback',
    'register_traceflow_tcp_callback',

    'register_extractor_reassembly', 'register_extractor_traceflow',
]

NULL = '(null)'

###############################################################################
# Engine Registries
###############################################################################


@overload
def register_extractor_engine(name: 'str', module: 'ModuleDescriptor[Engine] | Type[Engine]') -> 'None': ...
@overload
def register_extractor_engine(name: 'str', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.foundation.extraction.Extractor.__engine__
def register_extractor_engine(name: 'str', module: 'ModuleDescriptor[Engine] | Type[Engine] | str',
                              class_: 'str' = NULL) -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new engine class.

    Notes:
        The full qualified class name of the new engine class
        should be as ``{module}.{class_}``.

    The function will register the given engine class to the
    :data:`pcapkit.foundation.extraction.Extractor.__engine__` registry.

    Arguments:
        engine: engine name
        module: module name or module descriptor or an
            :class:`~pcapkit.foundation.engines.engine.Engine` subclass
        class\_: class name

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Engine]', ModuleDescriptor(module, class_))

    Extractor.register_engine(name, module)
    logger.info('registered extractor engine: %s', name)


###############################################################################
# Dumper Registries
###############################################################################


@overload
def register_dumper(format: 'str', module: 'ModuleDescriptor[Dumper] | Type[Dumper]', *, ext: 'str') -> 'None': ...
@overload
def register_dumper(format: 'str', module: 'str', class_: 'str', *, ext: 'str') -> 'None': ...


def register_dumper(format: 'str', module: 'ModuleDescriptor[Dumper] | Type[Dumper] | str',
                    class_: 'str' = NULL, *, ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__` and
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registry.

    Arguments:
        format: format name
        module: module name or module descriptor or a
            :class:`~dictdumper.dumper.Dumper` subclass
        class\_: class name
        ext: file extension

    See Also:
        * :func:`pcapkit.foundation.registry.foundation.register_extractor_dumper`
        * :func:`pcapkit.foundation.registry.foundation.register_traceflow_dumper`

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Dumper]', ModuleDescriptor(module, class_))

    Extractor.register_dumper(format, module, ext)
    TraceFlow.register_dumper(format, module, ext)
    logger.info('registered output format: %s', format)


@overload
def register_extractor_dumper(format: 'str', module: 'ModuleDescriptor[Dumper] | Type[Dumper]', *, ext: 'str') -> 'None': ...
@overload
def register_extractor_dumper(format: 'str', module: 'str', class_: 'str', *, ext: 'str') -> 'None': ...


# NOTE: pcapkit.foundation.extraction.Extractor.__output__
def register_extractor_dumper(format: 'str', module: 'ModuleDescriptor[Dumper] | Type[Dumper] | str',
                              class_: 'str' = NULL, *, ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registry.

    Arguments:
        format: format name
        module: module name or module descriptor or a
            :class:`~dictdumper.dumper.Dumper` subclass
        class\_: class name
        ext: file extension

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Dumper]', ModuleDescriptor(module, class_))

    Extractor.register_dumper(format, module, ext)
    logger.info('registered extractor output dumper: %s', format)


@overload
def register_traceflow_dumper(format: 'str', module: 'ModuleDescriptor[Dumper] | Type[Dumper]', *, ext: 'str') -> 'None': ...
@overload
def register_traceflow_dumper(format: 'str', module: 'str', class_: 'str', *, ext: 'str') -> 'None': ...


# NOTE: pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__
def register_traceflow_dumper(format: 'str', module: 'ModuleDescriptor[Dumper] | Type[Dumper] | str',
                              class_: 'str' = NULL, *, ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__` registry.

    Arguments:
        format: format name
        module: module name or module descriptor or a
            :class:`~dictdumper.dumper.Dumper` subclass
        class\_: class name
        ext: file extension

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Dumper]', ModuleDescriptor(module, class_))

    TraceFlow.register_dumper(format, module, ext)
    logger.info('registered traceflow output: %s', format)


###############################################################################
# Callback Registries
###############################################################################


# NOTE: pcapkit.foundation.reassembly.ipv4.IPv4.__callback_fn__
def register_reassembly_ipv4_callback(callback: 'Reasm_CallbackFn') -> 'None':
    """Registered a new callback function.

    The function will register the given callback function to the
    :attr:`IPv4.__callback_fn__ <pcapkit.foundation.reassembly.reassembly.Reassembly.__callback_fn__>`
    registry.

    Arguments:
        callback: callback function

    """
    IPv4_Reassembly.register(callback)
    logger.info('registered IPv4 reassembly callback: %r', callback)


# NOTE: pcapkit.foundation.reassembly.ipv6.IPv6.__callback_fn__
def register_reassembly_ipv6_callback(callback: 'Reasm_CallbackFn') -> 'None':
    """Registered a new callback function.

    The function will register the given callback function to the
    :attr:`IPv6.__callback_fn__ <pcapkit.foundation.reassembly.reassembly.Reassembly.__callback_fn__>`
    registry.

    Arguments:
        callback: callback function

    """
    IPv6_Reassembly.register(callback)
    logger.info('registered IPv6 reassembly callback: %r', callback)


# NOTE: pcapkit.foundation.reassembly.tcp.TCP.__callback_fn__
def register_reassembly_tcp_callback(callback: 'Reasm_CallbackFn') -> 'None':
    """Registered a new callback function.

    The function will register the given callback function to the
    :attr:`TCP.__callback_fn__ <pcapkit.foundation.reassembly.reassembly.Reassembly.__callback_fn__>`
    registry.

    Arguments:
        callback: callback function

    """
    TCP_Reassembly.register(callback)
    logger.info('registered TCP reassembly callback: %r', callback)


# NOTE: pcapkit.foundation.traceflow.tcp.TCP.__callback_fn__
def register_traceflow_tcp_callback(callback: 'Trace_CallbackFn') -> 'None':
    """Registered a new callback function.

    The function will register the given callback function to the
    :attr:`TCP.__callback_fn__ <pcapkit.foundation.traceflow.traceflow.TraceFlow.__callback_fn__>`
    registry.

    Arguments:
        callback: callback function

    """
    TCP_TraceFlow.register_callback(callback)
    logger.info('registered TCP flow tracing callback: %r', callback)


###############################################################################
# Extractor Registries
###############################################################################


@overload
def register_extractor_reassembly(protocol: 'str', module: 'ModuleDescriptor[Reassembly] | Type[Reassembly]') -> 'None': ...
@overload
def register_extractor_reassembly(protocol: 'str', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.foundation.extraction.Extractor.__reassembly__
def register_extractor_reassembly(protocol: 'str', module: 'str | ModuleDescriptor[Reassembly] | Type[Reassembly]',
                                  class_: 'str' = NULL) -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new reassembly class.

    Notes:
        The full qualified class name of the new reassembly class
        should be as ``{module}.{class_}``.

    The function will register the given reassembly class to the
    :data:`pcapkit.foundation.extraction.Extractor.__reassembly__` registry.

    Arguments:
        protocol: protocol name
        module: module name or module descriptor or a
            :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` subclass
        class\_: class name

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Reassembly]', ModuleDescriptor(module, class_))

    Extractor.register_reassembly(protocol, module)
    logger.info('registered extractor reassembly: %s', protocol)


@overload
def register_extractor_traceflow(protocol: 'str', module: 'ModuleDescriptor[TraceFlow] | Type[TraceFlow]') -> 'None': ...
@overload
def register_extractor_traceflow(protocol: 'str', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.foundation.extraction.Extractor.__traceflow__
def register_extractor_traceflow(protocol: 'str', module: 'str | ModuleDescriptor[TraceFlow] | Type[TraceFlow]',
                                 class_: 'str' = NULL) -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new flow tracing class.

    Notes:
        The full qualified class name of the new flow tracing class
        should be as ``{module}.{class_}``.

    The function will register the given flow tracing class to the
    :data:`pcapkit.foundation.extraction.Extractor.__traceflow__` registry.

    Arguments:
        protocol: protocol name
        module: module name or module descriptor or a
            :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` subclass
        class\_: class name

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[TraceFlow]', ModuleDescriptor(module, class_))

    Extractor.register_traceflow(protocol, module)
    logger.info('registered extractor flow tracing: %s', protocol)
