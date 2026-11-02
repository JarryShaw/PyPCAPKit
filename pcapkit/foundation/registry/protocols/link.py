# -*- coding: utf-8 -*-
"""Link Layer Protocol Registries
====================================

.. module:: pcapkit.foundation.registry.protocols.link

This module provides the registries of the link layer protocols in
:mod:`pcapkit.protocols.link`.

.. versionadded:: 1.6.0

   Moved here from the single :file:`pcapkit/foundation/registry/protocols.py`
   module. The :mod:`pcapkit.foundation.registry.protocols` package exports
   this module's functions (:issue:`2578`).

"""
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.linux.arphrd import ARPHRD as Enum_ARPHRD
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.sentinels import NULL
from pcapkit.foundation.registry.protocols.protocol import _check_code, _register_name
from pcapkit.protocols.link.frad import FRAD
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.link.linux_sll import LinuxSLL
from pcapkit.protocols.link.loopback import Loopback
from pcapkit.protocols.link.netlink import Netlink
from pcapkit.protocols.link.radiotap import Radiotap
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Type

    from pcapkit.const.reg.ethertype import EtherType
    from pcapkit.corekit.sentinels import NullType
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = [
    'register_ethertype',
    'register_loopback',
    'register_arphrd', 'register_frad', 'register_netlink', 'register_radiotap',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


###############################################################################
# Link Layer Registries
###############################################################################


@overload
def register_ethertype(code: 'EtherType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_ethertype(code: 'EtherType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.link.link.Link.__proto__
def register_ethertype(code: 'EtherType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                       class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.link.Link.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.ethertype.EtherType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_EtherType, Link)  # type: ignore[type-abstract]
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Link.register(code, module)
    logger.debug('registered ethertype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Link, code))


@overload
def register_loopback(code: 'int', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_loopback(code: 'int', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.link.loopback.Loopback.__proto__
def register_loopback(code: 'int', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                      class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.loopback.Loopback.__proto__` registry.

    Arguments:
        code: BSD address family
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Important:
        Unlike :func:`register_ethertype`, ``code`` is an address family,
        **not** an EtherType: :class:`~pcapkit.protocols.link.loopback.Loopback`
        keeps a registry of its own.

    Raises:
        RegistryError: If ``code`` is not an :class:`int` (a :class:`bool` is
            not accepted, even though it is one), or is a member of an enum, or
            ``module`` is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    .. versionadded:: 1.6.0

    """
    _check_code(code, None, Loopback)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Loopback.register(code, module)
    logger.debug('registered loopback address family: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Loopback, code))


@overload
def register_arphrd(code: 'Enum_ARPHRD', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_arphrd(code: 'Enum_ARPHRD', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__
def register_arphrd(code: 'Enum_ARPHRD', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                    class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__` registry, so
    that a Linux "cooked" capture on that ``arphrd_type`` dispatches to it
    instead of reading ``protocol_type`` as an EtherType.

    Arguments:
        code: ARP hardware type as in :class:`~pcapkit.const.linux.arphrd.ARPHRD`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.linux.arphrd.ARPHRD`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_ARPHRD, LinuxSLL)  # type: ignore[type-abstract]
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    LinuxSLL.register(code, module)
    logger.debug('registered ARPHRD protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (LinuxSLL, code))


@overload
def register_frad(code: 'int', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_frad(code: 'int', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.link.frad.FRAD.__proto__
def register_frad(code: 'int', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                  class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.frad.FRAD.__proto__` registry.

    Arguments:
        code: NLPID, after resolving the ``0x00`` pad ahead of a SNAP header
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not an :class:`int` (a :class:`bool` is
            not accepted, even though it is one), or is a member of an enum.

    """
    _check_code(code, None, FRAD)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    FRAD.register(code, module)
    logger.debug('registered FRAD NLPID: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (FRAD, code))


@overload
def register_netlink(code: 'int', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_netlink(code: 'int', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.link.netlink.Netlink.__proto__
def register_netlink(code: 'int', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                     class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.netlink.Netlink.__proto__` registry.

    Arguments:
        code: ``nlmsg_type`` of the dissected message
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not an :class:`int` (a :class:`bool` is
            not accepted, even though it is one), or is a member of an enum.

    """
    _check_code(code, None, Netlink)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Netlink.register(code, module)
    logger.debug('registered Netlink message type: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Netlink, code))


@overload
def register_radiotap(code: 'Enum_LinkType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_radiotap(code: 'Enum_LinkType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.link.radiotap.Radiotap.__proto__
def register_radiotap(code: 'Enum_LinkType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                      class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.radiotap.Radiotap.__proto__` registry, keyed
    by the link type of the frame a radiotap header precedes. Any link type is
    accepted, but :meth:`Radiotap.read <pcapkit.protocols.link.radiotap.Radiotap.read>`
    consults :attr:`LinkType.IEEE802_11 <pcapkit.const.reg.linktype.LinkType.IEEE802_11>`
    alone: registering that key replaces the 802.11 dissector, and an entry
    under any other key is stored and never reached.

    Arguments:
        code: link type as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.linktype.LinkType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_LinkType, Radiotap)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Radiotap.register(code, module)
    logger.debug('registered radiotap link type: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Radiotap, code))
