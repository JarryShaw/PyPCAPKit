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
from typing import TYPE_CHECKING

from pcapkit.const.linux.arphrd import ARPHRD as Enum_ARPHRD
from pcapkit.const.llc.lsap import LSAP as Enum_LSAP
from pcapkit.const.ppp.protocol import Protocol as Enum_PPP_Protocol
from pcapkit.const.radiotap.field_type import FieldType as Radiotap_FieldType
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.foundation.registry.protocols.protocol import _check_code, _check_meth, _register_name
from pcapkit.protocols.link.frad.protocol import FRAD
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
from pcapkit.protocols.link.llc.protocol import LLC
from pcapkit.protocols.link.loopback.protocol import Loopback
from pcapkit.protocols.link.netlink.protocol import Netlink
from pcapkit.protocols.link.ppp.protocol import PPP
from pcapkit.protocols.link.ppp.schema import ControlPacket as Schema_PPP_ControlPacket
from pcapkit.protocols.link.radiotap.protocol import Radiotap
from pcapkit.protocols.link.radiotap.schema import RadiotapField as Schema_Radiotap_Field
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.const.reg.ethertype import EtherType
    from pcapkit.protocols.link.ppp.protocol import ControlConstructor as PPP_ControlConstructor
    from pcapkit.protocols.link.ppp.protocol import ControlParser as PPP_ControlParser
    from pcapkit.protocols.link.radiotap.protocol import \
        FieldConstructor as Radiotap_FieldConstructor
    from pcapkit.protocols.link.radiotap.protocol import FieldParser as Radiotap_FieldParser
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = [
    'register_ethertype',
    'register_loopback',
    'register_arphrd', 'register_frad', 'register_lsap', 'register_netlink', 'register_ppp',
    'register_ppp_control', 'register_radiotap', 'register_radiotap_field',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


###############################################################################
# Link Layer Registries
###############################################################################


# NOTE: pcapkit.protocols.link.link.Link.__proto__
def register_ethertype(code: 'EtherType', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.link.Link.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.ethertype.EtherType`
            member, e.g. a member of another enum, or ``protocol``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_EtherType, Link)  # type: ignore[type-abstract]

    Link.register(code, protocol)
    logger.debug('registered ethertype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (Link, code))


# NOTE: pcapkit.protocols.link.loopback.protocol.Loopback.__proto__
def register_loopback(code: 'int', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.loopback.protocol.Loopback.__proto__` registry.

    Arguments:
        code: BSD address family
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Important:
        Unlike :func:`register_ethertype`, ``code`` is an address family,
        **not** an EtherType: :class:`~pcapkit.protocols.link.loopback.protocol.Loopback`
        keeps a registry of its own.

    Raises:
        RegistryError: If ``code`` is not an :class:`int` (a :class:`bool` is
            not accepted, even though it is one), or is a member of an enum, or
            ``protocol`` is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    .. versionadded:: 1.6.0

    """
    _check_code(code, None, Loopback)

    Loopback.register(code, protocol)
    logger.debug('registered loopback address family: %s', code)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (Loopback, code))


# NOTE: pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__
def register_arphrd(code: 'Enum_ARPHRD', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__` registry, so
    that a Linux "cooked" capture on that ``arphrd_type`` dispatches to it
    instead of reading ``protocol_type`` as an EtherType.

    Arguments:
        code: ARP hardware type as in :class:`~pcapkit.const.linux.arphrd.ARPHRD`
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.linux.arphrd.ARPHRD`
            member, e.g. a member of another enum, or ``protocol``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_ARPHRD, LinuxSLL)  # type: ignore[type-abstract]

    LinuxSLL.register(code, protocol)
    logger.debug('registered ARPHRD protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (LinuxSLL, code))


# NOTE: pcapkit.protocols.link.frad.protocol.FRAD.__proto__
def register_frad(code: 'int', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.frad.protocol.FRAD.__proto__` registry.

    Arguments:
        code: NLPID, after resolving the ``0x00`` pad ahead of a SNAP header
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Raises:
        RegistryError: If ``code`` is not an :class:`int` (a :class:`bool` is
            not accepted, even though it is one), or is a member of an enum.

    """
    _check_code(code, None, FRAD)

    FRAD.register(code, protocol)
    logger.debug('registered FRAD NLPID: %s', code)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (FRAD, code))


# NOTE: pcapkit.protocols.link.llc.protocol.LLC.__proto__, pcapkit.protocols.link.llc.protocol.LLC.__paired__
def register_lsap(code: 'Enum_LSAP', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]', *,
                  paired: 'bool' = False) -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.llc.protocol.LLC.__proto__` registry, which
    the information field of an I or UI PDU is dispatched by its DSAP through,
    and its paired flag to :data:`pcapkit.protocols.link.llc.protocol.LLC.__paired__`,
    as :meth:`LLC.register <pcapkit.protocols.link.llc.protocol.LLC.register>`
    writes them.

    Arguments:
        code: DSAP address as in :class:`~pcapkit.const.llc.lsap.LSAP`
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        paired: Whether a PDU to ``code`` is handed on only when its SSAP,
            less the C/R bit, is ``code`` too.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.llc.lsap.LSAP`
            member, e.g. a member of another enum, ``protocol`` is not a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass, or
            ``paired`` is not a :obj:`bool`.

    .. versionadded:: 1.9.0

    """
    _check_code(code, Enum_LSAP, LLC)
    if not isinstance(paired, bool):
        raise RegistryError(f'paired must be a bool, not {paired!r}')

    LLC.register(code, protocol, paired=paired)
    logger.debug('registered LLC LSAP: %s', code.name)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (LLC, code))


# NOTE: pcapkit.protocols.link.netlink.protocol.Netlink.__proto__
def register_netlink(code: 'int', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.netlink.protocol.Netlink.__proto__` registry.

    Arguments:
        code: ``nlmsg_type`` of the dissected message
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Raises:
        RegistryError: If ``code`` is not an :class:`int` (a :class:`bool` is
            not accepted, even though it is one), or is a member of an enum.

    """
    _check_code(code, None, Netlink)

    Netlink.register(code, protocol)
    logger.debug('registered Netlink message type: %s', code)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (Netlink, code))


# NOTE: pcapkit.protocols.link.ppp.protocol.PPP.__proto__
def register_ppp(code: 'Enum_PPP_Protocol', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.ppp.protocol.PPP.__proto__` registry.

    Arguments:
        code: PPP protocol number as in :class:`~pcapkit.const.ppp.protocol.Protocol`
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.ppp.protocol.Protocol`
            member, e.g. a member of another enum, or ``protocol`` is not a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

    .. versionadded:: 1.7.0

    """
    _check_code(code, Enum_PPP_Protocol, PPP)

    PPP.register(code, protocol)
    logger.debug('registered PPP protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (PPP, code))


# NOTE: pcapkit.protocols.link.ppp.protocol.PPP.__control__
def register_ppp_control(code: 'Enum_PPP_Protocol',
                         meth: 'str | tuple[PPP_ControlParser, PPP_ControlConstructor]', *,
                         schema: 'Optional[Type[Schema_PPP_ControlPacket]]' = None) -> 'None':
    """Register a PPP control packet parser.

    The function will register the given parser to the
    :data:`pcapkit.protocols.link.ppp.protocol.PPP.__control__` registry. A
    frame of that protocol number is read as a control packet at header level,
    rather than dispatched as a next layer, once the schema registry holds a
    layout for it.

    Args:
        code: PPP protocol number as in :class:`~pcapkit.const.ppp.protocol.Protocol`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the control packet. A name names the
            ``_read_control_*`` and ``_make_control_*`` methods, and has to name
            an existing ``_read_control_*`` one.
        schema: Layout the packets are read with, opening with Code,
            Identifier and Length. It should be a subclass of
            :class:`pcapkit.protocols.link.ppp.schema.ControlPacket`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.ppp.protocol.Protocol`
            member, ``meth`` is a name with no matching ``_read_control_*``
            method or neither a name nor a pair of two callables, or ``schema`` is not a
            :class:`~pcapkit.protocols.link.ppp.schema.ControlPacket` subclass.

    .. versionadded:: 1.7.0

    """
    _check_code(code, Enum_PPP_Protocol, PPP)
    _check_meth(meth, PPP)
    if isinstance(meth, str) and not hasattr(PPP, f'_read_control_{meth}'):
        raise RegistryError('method must be a PPP control packet parser function')
    if schema is not None and not (isinstance(schema, type) and issubclass(schema, Schema_PPP_ControlPacket)):
        raise RegistryError('schema must be a PPP control packet schema')

    PPP.register_control(code, meth)
    if schema is not None:
        Schema_PPP_ControlPacket.register(code, schema)
    logger.debug('registered PPP control packet parser: %s', code.name)


# NOTE: pcapkit.protocols.link.radiotap.protocol.Radiotap.__proto__
def register_radiotap(code: 'Enum_LinkType', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.radiotap.protocol.Radiotap.__proto__` registry, keyed
    by the link type of the frame a radiotap header precedes. Any link type is
    accepted, but :meth:`Radiotap.read <pcapkit.protocols.link.radiotap.protocol.Radiotap.read>`
    consults :attr:`LinkType.IEEE802_11 <pcapkit.const.reg.linktype.LinkType.IEEE802_11>`
    alone: registering that key replaces the 802.11 dissector, and an entry
    under any other key is stored and never reached.

    Arguments:
        code: link type as in :class:`~pcapkit.const.reg.linktype.LinkType`
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.linktype.LinkType`
            member, e.g. a member of another enum, or ``protocol``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_LinkType, Radiotap)

    Radiotap.register(code, protocol)
    logger.debug('registered radiotap link type: %s', code.name)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (Radiotap, code))


# NOTE: pcapkit.protocols.link.radiotap.protocol.Radiotap.__field__
def register_radiotap_field(code: 'Radiotap_FieldType',
                            meth: 'str | tuple[Radiotap_FieldParser, Radiotap_FieldConstructor]', *,
                            schema: 'Optional[Type[Schema_Radiotap_Field]]' = None) -> 'None':
    """Register a radiotap field parser.

    The function will register the given field parser to the
    :data:`pcapkit.protocols.link.radiotap.protocol.Radiotap.__field__` registry. A
    field type is decoded once both it and the schema registry hold an entry
    for it. A presence bit 28 to 30 follows rules of its own, as does a vendor
    namespace TLV item, so an entry for one is stored and not reached there; a
    type from 32 on is reached only as a TLV item.

    Args:
        code: :class:`~pcapkit.protocols.link.radiotap.protocol.Radiotap` field type as
            in :class:`~pcapkit.const.radiotap.field_type.FieldType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the field. A name names the
            ``_read_field_*`` and ``_make_field_*`` methods, and has to name
            an existing ``_read_field_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the
            field, whose fields are its subfields and whose ``__align__`` is its
            alignment. It should be a subclass of
            :class:`pcapkit.protocols.link.radiotap.schema.RadiotapField`.

    Raises:
        RegistryError: If ``code`` is not a
            :class:`~pcapkit.const.radiotap.field_type.FieldType` member, e.g.
            a member of another enum, or ``meth`` is a name with no matching
            ``_read_field_*`` method, or neither a name
            nor a pair of two callables.

    .. versionadded:: 1.6.0

    """
    _check_code(code, Radiotap_FieldType, Radiotap)
    _check_meth(meth, Radiotap)
    if isinstance(meth, str) and not hasattr(Radiotap, f'_read_field_{meth}'):
        raise RegistryError('method must be a radiotap field parser function')

    Radiotap.register_field(code, meth)
    if schema is not None:
        Schema_Radiotap_Field.register(code, schema)
    logger.debug('registered radiotap field parser: %s', code.name)
