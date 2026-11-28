# -*- coding: utf-8 -*-
"""Foundation Registries
===========================

.. module:: pcapkit.foundation.registry.foundation

This module provides the foundation registries for :mod:`pcapkit`.

.. versionchanged:: 1.5.0

   ``NULL``, the default of every ``class_`` argument here, is now the
   :data:`pcapkit.corekit.sentinels.NULL` sentinel; in 1.4.x it was the
   string ``'(null)'`` (:issue:`833`).

.. versionchanged:: 1.7.0

   Each registrar takes the one entry its classmethod takes, under that
   classmethod's parameter name, where it took ``module`` and ``class_``, and
   :func:`register_reassembly_callback` and :func:`register_traceflow_callback`
   replace the per-protocol callback registrars, with no shim (:issue:`2838`).

"""
from typing import TYPE_CHECKING

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.foundation.engines.engine import EngineBase
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.traceflow import TraceFlow
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from dictdumper import Dumper

    from pcapkit.foundation.engines import Engine
    from pcapkit.foundation.engines.engine import Adapter
    from pcapkit.foundation.reassembly.reassembly import CallbackFn as Reasm_CallbackFn
    from pcapkit.foundation.reassembly.reassembly import Reassembly
    from pcapkit.foundation.traceflow.traceflow import CallbackFn as Trace_CallbackFn

__all__ = [
    'register_extractor_engine',

    'register_dumper',
    'register_extractor_dumper', 'register_traceflow_dumper',

    'register_reassembly_callback', 'register_traceflow_callback',

    'register_extractor_reassembly', 'register_engine_reassembly', 'register_extractor_traceflow',
    'register_engine_traceflow',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)

###############################################################################
# Engine Registries
###############################################################################


# NOTE: pcapkit.foundation.extraction.Extractor.__engine__
def register_extractor_engine(name: 'str', engine: 'ModuleDescriptor[Engine] | Type[Engine]') -> 'None':
    r"""Register a new engine class.

    The function will register the given engine class to the
    :data:`pcapkit.foundation.extraction.Extractor.__engine__` registry.

    Arguments:
        name: engine name, stored lower-cased
        engine: module descriptor or an
            :class:`~pcapkit.foundation.engines.engine.Engine` subclass (a class
            deriving only from :class:`~pcapkit.foundation.engines.engine.EngineBase`
            is refused: that is the base for pcapkit's own engines, unless it is
            the engine ``name`` shipped with, which restores it)

    Raises:
        RegistryError: If ``name`` is not a :class:`str`, or ``engine`` is
            refused as above.

    .. versionchanged:: 1.3.0

       The engine name, which was ``engine``, is ``name``, with no alias.

    .. versionchanged:: 1.7.0

       ``engine`` is the class, where ``module`` and ``class_`` named it
       (:issue:`2838`), and ``name`` is stored lower-cased (:issue:`2879`).

    """
    Extractor.register_engine(name, engine)
    logger.debug('registered extractor engine: %s', name)


###############################################################################
# Dumper Registries
###############################################################################


def register_dumper(format: 'str', dumper: 'ModuleDescriptor[Dumper] | Type[Dumper]', *,  # pylint: disable=redefined-builtin
                    ext: 'str') -> 'None':
    r"""Register a new dumper class.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__` and
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registries.

    Arguments:
        format: format name
        dumper: module descriptor or a :class:`~dictdumper.dumper.Dumper` subclass
        ext: file extension

    See Also:
        * :func:`pcapkit.foundation.registry.foundation.register_extractor_dumper`
        * :func:`pcapkit.foundation.registry.foundation.register_traceflow_dumper`

    .. versionchanged:: 1.3.0

       ``ext`` is keyword-only.

    .. versionchanged:: 1.7.0

       ``dumper`` is the class, where ``module`` and ``class_`` named it
       (:issue:`2838`).

    """
    Extractor.register_dumper(format, dumper, ext)
    TraceFlow.register_dumper(format, dumper, ext=ext)
    logger.debug('registered output format: %s', format)


# NOTE: pcapkit.foundation.extraction.Extractor.__output__
def register_extractor_dumper(format: 'str', dumper: 'ModuleDescriptor[Dumper] | Type[Dumper]', *,  # pylint: disable=redefined-builtin
                              ext: 'str') -> 'None':
    r"""Register a new dumper class.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registry.

    Arguments:
        format: format name
        dumper: module descriptor or a :class:`~dictdumper.dumper.Dumper` subclass
        ext: file extension

    .. versionchanged:: 1.3.0

       ``ext`` is keyword-only.

    .. versionchanged:: 1.7.0

       ``dumper`` is the class, where ``module`` and ``class_`` named it
       (:issue:`2838`).

    """
    Extractor.register_dumper(format, dumper, ext)
    logger.debug('registered extractor output dumper: %s', format)


# NOTE: pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__
def register_traceflow_dumper(format: 'str', dumper: 'ModuleDescriptor[Dumper] | Type[Dumper]', *,  # pylint: disable=redefined-builtin
                              ext: 'str') -> 'None':
    r"""Register a new dumper class.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__` registry.

    Arguments:
        format: format name
        dumper: module descriptor or a :class:`~dictdumper.dumper.Dumper` subclass
        ext: file extension

    .. versionchanged:: 1.3.0

       ``ext`` is keyword-only.

    .. versionchanged:: 1.7.0

       ``dumper`` is the class, where ``module`` and ``class_`` named it
       (:issue:`2838`).

    """
    TraceFlow.register_dumper(format, dumper, ext=ext)
    logger.debug('registered traceflow output: %s', format)


###############################################################################
# Callback Registries
###############################################################################


def _registered_class(registry: 'dict[str, Any]', protocol: 'str', kind: 'str') -> 'Any':
    """The class ``registry`` holds under the name ``protocol``, case-insensitively.

    Arguments:
        registry: :attr:`Extractor.__reassembly__
            <pcapkit.foundation.extraction.Extractor.__reassembly__>` or
            :attr:`Extractor.__traceflow__
            <pcapkit.foundation.extraction.Extractor.__traceflow__>`
        protocol: registered name, looked up lower-cased as the extractor does
        kind: entry kind, for the error message

    Raises:
        RegistryError: If ``protocol`` is not a :class:`str`, or names no entry.

    """
    if not isinstance(protocol, str):
        raise RegistryError(f'protocol must be a registered {kind} name, not {protocol!r}')
    entry = registry.get(protocol.lower())
    if entry is None:
        raise RegistryError(f'no {kind} is registered under {protocol!r}')
    if isinstance(entry, ModuleDescriptor):
        entry = entry.klass
    return entry


def _check_callback(callback: 'Any') -> 'None':
    """Reject a ``callback`` that is not callable, before any list is written.

    Raises:
        RegistryError: If ``callback`` is not callable.

    """
    if not callable(callback):
        raise RegistryError(f'callback must be callable, not {callback!r}')


# NOTE: pcapkit.foundation.reassembly.reassembly.ReassemblyBase.__callback_fn__
def register_reassembly_callback(protocol: 'str', callback: 'Reasm_CallbackFn', *,
                                 index: 'Optional[int]' = None) -> 'None':
    """Register a callback function of a reassembler.

    The function will register the given callback function to the
    ``__callback_fn__`` list of the reassembly class registered under ``protocol``
    in :data:`pcapkit.foundation.extraction.Extractor.__reassembly__`, through its
    :meth:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase.register_callback`. It
    reaches every reassembler registered there, one added with
    :func:`register_extractor_reassembly` included.

    Arguments:
        protocol: name the reassembler is registered by, case-insensitively,
            such as ``'ipv4'`` or ``'dtls'``
        callback: callback function, which will be called when reassembled
            datagram is obtained, with the list of reassembled datagrams as its
            only argument
        index: index to be inserted in the callback list; by default, the
            callback will be appended to the end of the list

    Raises:
        RegistryError: If ``protocol`` is not a :class:`str` or names no
            registered reassembler, or if ``callback`` is not callable.

    .. versionadded:: 1.7.0

    """
    reassembly = _registered_class(Extractor.__reassembly__, protocol, 'reassembly')
    _check_callback(callback)
    reassembly.register_callback(callback, index=index)
    logger.debug('registered %s reassembly callback: %r', reassembly.__name__, callback)


# NOTE: pcapkit.foundation.traceflow.traceflow.TraceFlowBase.__callback_fn__
def register_traceflow_callback(protocol: 'str', callback: 'Trace_CallbackFn', *,
                                index: 'Optional[int]' = None) -> 'None':
    """Register a callback function of a flow tracer.

    The function will register the given callback function to the
    ``__callback_fn__`` list of the flow tracing class registered under
    ``protocol`` in :data:`pcapkit.foundation.extraction.Extractor.__traceflow__`,
    through its
    :meth:`~pcapkit.foundation.traceflow.traceflow.TraceFlowBase.register_callback`.

    Arguments:
        protocol: name the flow tracer is registered by, case-insensitively,
            such as ``'tcp'``
        callback: callback function, which will be called when a traced flow
            is finalised, with the flow's index entry as its only argument
        index: index to be inserted in the callback list; by default, the
            callback will be appended to the end of the list

    Raises:
        RegistryError: If ``protocol`` is not a :class:`str` or names no
            registered flow tracer, or if ``callback`` is not callable.

    .. versionadded:: 1.7.0

    """
    traceflow = _registered_class(Extractor.__traceflow__, protocol, 'traceflow')
    _check_callback(callback)
    traceflow.register_callback(callback, index=index)
    logger.debug('registered %s flow tracing callback: %r', traceflow.__name__, callback)


###############################################################################
# Extractor Registries
###############################################################################


# NOTE: pcapkit.foundation.extraction.Extractor.__reassembly__
def register_extractor_reassembly(protocol: 'str',
                                  reassembly: 'ModuleDescriptor[Reassembly] | Type[Reassembly]') -> 'None':
    r"""Register a new reassembly class.

    The function will register the given reassembly class to the
    :data:`pcapkit.foundation.extraction.Extractor.__reassembly__` registry.

    Arguments:
        protocol: protocol name, stored lower-cased
        reassembly: module descriptor or a
            :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` subclass (a class
            deriving only from :class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase`
            is refused: that is the base for pcapkit's own classes, unless it is
            the class ``protocol`` shipped with, which restores it)

    Raises:
        RegistryError: If ``protocol`` is not a :class:`str`, or ``reassembly``
            is refused as above.

    .. versionchanged:: 1.7.0

       ``reassembly`` is the class, where ``module`` and ``class_`` named it
       (:issue:`2838`), and ``protocol`` is stored lower-cased, one that is not
       a :class:`str` raising :exc:`~pcapkit.utilities.exceptions.RegistryError`
       (:issue:`2879`).

    """
    Extractor.register_reassembly(protocol, reassembly)
    logger.debug('registered extractor reassembly: %s', protocol)


# NOTE: pcapkit.foundation.engines.engine.EngineBase.__reassembly__
def register_engine_reassembly(engine: 'str | Type[EngineBase]', protocol: 'str',
                               adapter: 'ModuleDescriptor[Adapter] | Adapter') -> 'None':
    r"""Register a new reassembly adapter of an engine.

    The function will register the given :mod:`pcapkit.toolkit` adapter to the
    :attr:`EngineBase.__reassembly__
    <pcapkit.foundation.engines.engine.EngineBase.__reassembly__>` registry of
    ``engine``, which then feeds the reassembler registered under ``protocol``
    from its frames.

    Arguments:
        engine: engine name, as registered in
            :data:`pcapkit.foundation.extraction.Extractor.__engine__`, or an
            :class:`~pcapkit.foundation.engines.engine.EngineBase` subclass;
            :class:`~pcapkit.foundation.engines.pcap.PCAP` and
            :class:`~pcapkit.foundation.engines.pcapng.PCAPNG` have no name, so
            take the class
        protocol: reassembly name
        adapter: module descriptor or the adapter itself

    Raises:
        RegistryError: If ``engine`` names no registered engine, or is not an
            :class:`~pcapkit.foundation.engines.engine.EngineBase` subclass.

    .. versionadded:: 1.7.0

    """
    engine_cls = _engine_class(engine)
    engine_cls.register_reassembly(protocol, adapter)
    logger.debug('registered %s engine reassembly: %s', engine_cls.name, protocol)


def _engine_class(engine: 'str | Type[EngineBase]') -> 'Type[EngineBase]':
    """Resolve the engine an engine adapter registrar writes to.

    Arguments:
        engine: engine name, as registered in
            :data:`pcapkit.foundation.extraction.Extractor.__engine__`, or an
            :class:`~pcapkit.foundation.engines.engine.EngineBase` subclass

    Raises:
        RegistryError: If ``engine`` names no registered engine, or is not an
            :class:`~pcapkit.foundation.engines.engine.EngineBase` subclass.

    """
    engine_cls = engine  # type: ModuleDescriptor[EngineBase] | Type[EngineBase] | str | None
    if isinstance(engine, str):
        engine_cls = Extractor.__engine__.get(engine.lower())
        if isinstance(engine_cls, ModuleDescriptor):
            engine_cls = engine_cls.klass
    if not isinstance(engine_cls, type) or not issubclass(engine_cls, EngineBase):
        raise RegistryError(f'engine must be a registered engine name or an EngineBase subclass, '
                            f'not {engine!r}')
    return engine_cls


# NOTE: pcapkit.foundation.extraction.Extractor.__traceflow__
def register_extractor_traceflow(protocol: 'str',
                                 traceflow: 'ModuleDescriptor[TraceFlow] | Type[TraceFlow]') -> 'None':
    r"""Register a new flow tracing class.

    The function will register the given flow tracing class to the
    :data:`pcapkit.foundation.extraction.Extractor.__traceflow__` registry.

    Arguments:
        protocol: protocol name, stored lower-cased
        traceflow: module descriptor or a
            :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` subclass (a class
            deriving only from :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowBase`
            is refused: that is the base for pcapkit's own classes, unless it is
            the class ``protocol`` shipped with, which restores it)

    Raises:
        RegistryError: If ``protocol`` is not a :class:`str`, or ``traceflow``
            is refused as above.

    .. versionchanged:: 1.7.0

       ``traceflow`` is the class, where ``module`` and ``class_`` named it
       (:issue:`2838`), and ``protocol`` is stored lower-cased, one that is not
       a :class:`str` raising :exc:`~pcapkit.utilities.exceptions.RegistryError`
       (:issue:`2879`).

    """
    Extractor.register_traceflow(protocol, traceflow)
    logger.debug('registered extractor flow tracing: %s', protocol)


# NOTE: pcapkit.foundation.engines.engine.EngineBase.__traceflow__
def register_engine_traceflow(engine: 'str | Type[EngineBase]', protocol: 'str',
                              adapter: 'ModuleDescriptor[Adapter] | Adapter') -> 'None':
    r"""Register a new flow tracing adapter of an engine.

    The function will register the given :mod:`pcapkit.toolkit` adapter to the
    :attr:`EngineBase.__traceflow__
    <pcapkit.foundation.engines.engine.EngineBase.__traceflow__>` registry of
    ``engine``, which then feeds the flow tracer registered under ``protocol``
    from its frames.

    Arguments:
        engine: engine name, as registered in
            :data:`pcapkit.foundation.extraction.Extractor.__engine__`, or an
            :class:`~pcapkit.foundation.engines.engine.EngineBase` subclass;
            :class:`~pcapkit.foundation.engines.pcap.PCAP` and
            :class:`~pcapkit.foundation.engines.pcapng.PCAPNG` have no name, so
            take the class
        protocol: flow tracing name
        adapter: module descriptor or the adapter itself

    Raises:
        RegistryError: If ``engine`` names no registered engine, or is not an
            :class:`~pcapkit.foundation.engines.engine.EngineBase` subclass.

    .. versionadded:: 1.7.0

    """
    engine_cls = _engine_class(engine)
    engine_cls.register_traceflow(protocol, adapter)
    logger.debug('registered %s engine flow tracing: %s', engine_cls.name, protocol)
