# -*- coding: utf-8 -*-
"""Foundation Registries
===========================

.. module:: pcapkit.foundation.registry.foundation

This module provides the foundation registries for :mod:`pcapkit`.

"""
import importlib
from typing import TYPE_CHECKING

from dictdumper import Dumper

from pcapkit.foundation.engines import Engine
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
from pcapkit.foundation.reassembly.ipv6 import IPv6 as IPv6_Reassembly
from pcapkit.foundation.reassembly.reassembly import Reassembly
from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
from pcapkit.foundation.traceflow import TraceFlow
from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import logger

if TYPE_CHECKING:
    from pcapkit.foundation.reassembly.reassembly import CallbackFn as Reasm_CallbackFn
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


###############################################################################
# Engine Registries
###############################################################################


# NOTE: pcapkit.foundation.extraction.Extractor.__engine__
def register_extractor_engine(engine: 'str', module: 'str', class_: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new engine class.

    Notes:
        The full qualified class name of the new engine class
        should be as ``{module}.{class_}``.

    The function will register the given engine class to the
    :data:`pcapkit.foundation.extraction.Extractor.__engine__` registry.

    Arguments:
        engine: engine name
        module: module name
        class\_: class name

    """
    engine_cls = getattr(importlib.import_module(module), class_)
    if not issubclass(engine_cls, Engine):
        raise RegistryError('engine must be a Engine subclass')

    Extractor.register_engine(engine, module, class_)
    logger.info('registered extractor engine: %s', engine)


###############################################################################
# Dumper Registries
###############################################################################


def register_dumper(format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.TraceFlow.__output__` and
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registry.

    See Also:
        * :func:`pcapkit.foundation.registry.register_extractor_dumper`
        * :func:`pcapkit.foundation.registry.register_traceflow`

    Arguments:
        format: format name
        module: module name
        class\_: class name
        ext: file extension

    """
    dumper = getattr(importlib.import_module(module), class_)
    if not issubclass(dumper, Dumper):
        raise RegistryError('dumper must be a Dumper subclass')

    Extractor.register_dumper(format, module, class_, ext)
    TraceFlow.register_dumper(format, module, class_, ext)
    logger.info('registered output format: %s', dumper.__name__)


# NOTE: pcapkit.foundation.extraction.Extractor.__output__
def register_extractor_dumper(format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registry.

    Arguments:
        format: format name
        module: module name
        class\_: class name
        ext: file extension

    """
    dumper = getattr(importlib.import_module(module), class_)
    if not issubclass(dumper, Dumper):
        raise RegistryError('dumper must be a Dumper subclass')

    Extractor.register_dumper(format, module, class_, ext)
    logger.info('registered extractor output dumper: %s', format)


# NOTE: pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__
def register_traceflow_dumper(format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__` registry.

    Arguments:
        format: format name
        module: module name
        class\_: class name
        ext: file extension

    """
    dumper = getattr(importlib.import_module(module), class_)
    if not issubclass(dumper, Dumper):
        raise RegistryError('dumper must be a Dumper subclass')

    TraceFlow.register_dumper(format, module, class_, ext)
    logger.info('registered traceflow output: %s', format)


###############################################################################
# Callback Registries
###############################################################################


# NOTE: pcapkit.foundation.reassembly.ipv4.IPv4.__callback_fn__
def register_reassembly_ipv4_callback(callback: 'Reasm_CallbackFn') -> 'None':
    """Registered a new callback function.

    The function will register the given callback function to the
    :data:`pcapkit.foundation.reassembly.ipv4.IPv4.__callback_fn__` registry.

    Arguments:
        callback: callback function

    """
    IPv4_Reassembly.register(callback)
    logger.info('registered IPv4 reassembly callback: %r', callback)


# NOTE: pcapkit.foundation.reassembly.ipv6.IPv6.__callback_fn__
def register_reassembly_ipv6_callback(callback: 'Reasm_CallbackFn') -> 'None':
    """Registered a new callback function.

    The function will register the given callback function to the
    :data:`pcapkit.foundation.reassembly.ipv6.IPv6.__callback_fn__` registry.

    Arguments:
        callback: callback function

    """
    IPv6_Reassembly.register(callback)
    logger.info('registered IPv6 reassembly callback: %r', callback)


# NOTE: pcapkit.foundation.reassembly.tcp.TCP.__callback_fn__
def register_reassembly_tcp_callback(callback: 'Reasm_CallbackFn') -> 'None':
    """Registered a new callback function.

    The function will register the given callback function to the
    :data:`pcapkit.foundation.reassembly.tcp.TCP.__callback_fn__` registry.

    Arguments:
        callback: callback function

    """
    TCP_Reassembly.register(callback)
    logger.info('registered TCP reassembly callback: %r', callback)


# NOTE: pcapkit.foundation.traceflow.tcp.TCP.__callback_fn__
def register_traceflow_tcp_callback(callback: 'Trace_CallbackFn') -> 'None':
    """Registered a new callback function.

    The function will register the given callback function to the
    :data:`pcapkit.foundation.traceflow.tcp.TCP.__callback_fn__` registry.

    Arguments:
        callback: callback function

    """
    TCP_TraceFlow.register_callback(callback)
    logger.info('registered TCP flow tracing callback: %r', callback)


###############################################################################
# Extractor Registries
###############################################################################


# NOTE: pcapkit.foundation.extraction.Extractor.__reassembly__
def register_extractor_reassembly(protocol: 'str', module: 'str', class_: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new engine class.

    Notes:
        The full qualified class name of the new engine class
        should be as ``{module}.{class_}``.

    The function will register the given engine class to the
    :data:`pcapkit.foundation.extraction.Extractor.__reassembly__` registry.

    Arguments:
        engine: engine name
        module: module name
        class\_: class name

    """
    engine_cls = getattr(importlib.import_module(module), class_)
    if not issubclass(engine_cls, Reassembly):
        raise RegistryError('engine must be a Reassembly subclass')

    Extractor.register_reassembly(protocol, module, class_)
    logger.info('registered extractor reassembly: %s', protocol)


# NOTE: pcapkit.foundation.extraction.Extractor.__traceflow__
def register_extractor_traceflow(protocol: 'str', module: 'str', class_: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new engine class.

    Notes:
        The full qualified class name of the new engine class
        should be as ``{module}.{class_}``.

    The function will register the given engine class to the
    :data:`pcapkit.foundation.extraction.Extractor.__traceflow__` registry.

    Arguments:
        engine: engine name
        module: module name
        class\_: class name

    """
    engine_cls = getattr(importlib.import_module(module), class_)
    if not issubclass(engine_cls, TraceFlow):
        raise RegistryError('engine must be a TraceFlow subclass')

    Extractor.register_traceflow(protocol, module, class_)
    logger.info('registered extractor flow tracing: %s', protocol)
