# -*- coding: utf-8 -*-
"""Foundation Registries
===========================

.. module:: pcapkit.foundation.registry.foundation

This module provides the foundation registries for :mod:`pcapkit`.

"""
import importlib

from dictdumper import Dumper

from pcapkit.foundation.engines import Engine
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.traceflow import TraceFlow
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import logger

__all__ = [
    'register_extractor_engine',

    'register_dumper',
    'register_extractor_dumper', 'register_traceflow_dumper',
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
    TraceFlow.register(format, module, class_, ext)
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

    TraceFlow.register(format, module, class_, ext)
    logger.info('registered traceflow output: %s', format)
