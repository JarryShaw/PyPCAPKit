# -*- coding: utf-8 -*-
"""Miscellaneous Protocol Registries
=======================================

.. module:: pcapkit.foundation.registry.protocols.misc

This module provides the registries of the protocols in
:mod:`pcapkit.protocols.misc`: the top-level registries of the PCAP and
PCAP-NG frames, and the PCAP-NG block, option, record and secrets
registries.

.. versionadded:: 1.6.0

   Moved here from the single :file:`pcapkit/foundation/registry/protocols.py`
   module. The :mod:`pcapkit.foundation.registry.protocols` package exports
   this module's functions (:issue:`2578`).

"""
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.pcapng.block_type import BlockType as PCAPNG_BlockType
from pcapkit.const.pcapng.option_type import OptionType as PCAPNG_OptionType
from pcapkit.const.pcapng.record_type import RecordType as PCAPNG_RecordType
from pcapkit.const.pcapng.secrets_type import SecretsType as PCAPNG_SecretsType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.sentinels import NULL
from pcapkit.foundation.registry.protocols.protocol import _check_code, _register_name
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcapng import PCAPNG
from pcapkit.protocols.schema.misc.pcapng import BlockType as Schema_PCAPNG_BlockType
from pcapkit.protocols.schema.misc.pcapng import DSBSecrets as Schema_PCAPNG_DSBSecrets
from pcapkit.protocols.schema.misc.pcapng import \
    NameResolutionRecord as Schema_PCAPNG_NameResolutionRecord
from pcapkit.protocols.schema.misc.pcapng import Option as Schema_PCAPNG_Option
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.corekit.sentinels import NullType
    from pcapkit.protocols.misc.pcapng import BlockConstructor as PCAPNG_BlockConstructor
    from pcapkit.protocols.misc.pcapng import BlockParser as PCAPNG_BlockParser
    from pcapkit.protocols.misc.pcapng import OptionConstructor as PCAPNG_OptionConstructor
    from pcapkit.protocols.misc.pcapng import OptionParser as PCAPNG_OptionParser
    from pcapkit.protocols.misc.pcapng import RecordConstructor as PCAPNG_RecordConstructor
    from pcapkit.protocols.misc.pcapng import RecordParser as PCAPNG_RecordParser
    from pcapkit.protocols.misc.pcapng import SecretsConstructor as PCAPNG_SecretsConstructor
    from pcapkit.protocols.misc.pcapng import SecretsParser as PCAPNG_SecretsParser
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = [
    'register_linktype',
    'register_pcap', 'register_pcapng',

    'register_pcapng_block', 'register_pcapng_option', 'register_pcapng_secrets',
    'register_pcapng_record',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


###############################################################################
# Top-Level Registries
###############################################################################


@overload
def register_linktype(code: 'LinkType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_linktype(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


def register_linktype(code: 'LinkType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                      class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    following registries:

    - :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__`
    - :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__proto__`

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    See Also:
        * :func:`pcapkit.foundation.registry.protocols.misc.register_pcap`
        * :func:`pcapkit.foundation.registry.protocols.misc.register_pcapng`

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.linktype.LinkType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    # NOTE: this writes into both Frame's and PCAP-NG's registries, which are
    # keyed alike, so the key check is the same for either and Frame names it.
    # :func:`register_pcap` and :func:`register_pcapng` name one each.
    _check_code(code, Enum_LinkType, Frame)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Frame.register(code, module)
    PCAPNG.register(code, module)
    logger.debug('registered linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Frame, code), (PCAPNG, code))


@overload
def register_pcap(code: 'LinkType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_pcap(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.misc.pcap.frame.Frame.__proto__
def register_pcap(code: 'LinkType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                  class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.linktype.LinkType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_LinkType, Frame)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Frame.register(code, module)
    logger.debug('registered PCAP linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Frame, code))


@overload
def register_pcapng(code: 'LinkType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_pcapng(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__proto__
def register_pcapng(code: 'LinkType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                    class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.linktype.LinkType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_LinkType, PCAPNG)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    PCAPNG.register(code, module)
    logger.debug('registered PCAP-NG linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (PCAPNG, code))


###############################################################################
# Miscellaneous Protocol Registries
###############################################################################


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__block__
def register_pcapng_block(code: 'PCAPNG_BlockType', meth: 'str | tuple[PCAPNG_BlockParser, PCAPNG_BlockConstructor]', *,
                          schema: 'Optional[Type[Schema_PCAPNG_BlockType]]' = None) -> 'None':
    """Register a block parser.

    The function will register the given block parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__block__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` block type
            code as in :class:`~pcapkit.const.pcapng.block_type.BlockType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the block. A name names the
            ``_read_block_*`` and ``_make_block_*`` methods, and has to name
            an existing ``_read_block_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the block.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.BlockType`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.pcapng.block_type.BlockType`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_block_*`` method.

    """
    _check_code(code, PCAPNG_BlockType, PCAPNG)
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_block_{meth}'):
        raise RegistryError('method must be a block parser function')

    PCAPNG.register_block(code, meth)
    if schema is not None:
        Schema_PCAPNG_BlockType.register(code, schema)
    logger.debug('registered PCAP-NG block parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__option__
def register_pcapng_option(code: 'PCAPNG_OptionType', meth: 'str | tuple[PCAPNG_OptionParser, PCAPNG_OptionConstructor]', *,
                           schema: 'Optional[Type[Schema_PCAPNG_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__option__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` option type
            code as in :class:`~pcapkit.const.pcapng.option_type.OptionType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_option_*`` and ``_make_option_*`` methods, and has to name
            an existing ``_read_option_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.Option`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.pcapng.option_type.OptionType`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_option_*`` method.

    """
    _check_code(code, PCAPNG_OptionType, PCAPNG)
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_option_{meth}'):
        raise RegistryError('method must be a option parser function')

    PCAPNG.register_option(code, meth)
    if schema is not None:
        Schema_PCAPNG_Option.register(code, schema)
    logger.debug('registered PCAP-NG option parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__record__
def register_pcapng_record(code: 'PCAPNG_RecordType', meth: 'str | tuple[PCAPNG_RecordParser, PCAPNG_RecordConstructor]', *,
                           schema: 'Optional[Type[Schema_PCAPNG_NameResolutionRecord]]' = None) -> 'None':
    """Register a name resolution record parser.

    The function will register the given name resolution record parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__record__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` name
            resolution record type code as in :class:`~pcapkit.const.pcapng.record_type.RecordType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the name resolution record. A name names the
            ``_read_record_*`` and ``_make_record_*`` methods, and has to name
            an existing ``_read_record_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the name resolution record.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.NameResolutionRecord`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.pcapng.record_type.RecordType`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_record_*`` method.

    """
    _check_code(code, PCAPNG_RecordType, PCAPNG)
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_record_{meth}'):
        raise RegistryError('method must be a name resolution record parser function')

    PCAPNG.register_record(code, meth)
    if schema is not None:
        Schema_PCAPNG_NameResolutionRecord.register(code, schema)
    logger.debug('registered PCAP-NG name resolution record parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__
def register_pcapng_secrets(code: 'PCAPNG_SecretsType', meth: 'str | tuple[PCAPNG_SecretsParser, PCAPNG_SecretsConstructor]', *,
                            schema: 'Optional[Type[Schema_PCAPNG_DSBSecrets]]' = None) -> 'None':
    """Register a decryption secrets parser.

    The function will register the given decryption secrets parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` decryption
            secrets type code as in :class:`~pcapkit.const.pcapng.secrets_type.SecretsType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the decryption secrets. A name names the
            ``_read_secrets_*`` and ``_make_secrets_*`` methods, and has to name
            an existing ``_read_secrets_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the decryption secrets.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.DSBSecrets`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.pcapng.secrets_type.SecretsType`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_secrets_*`` method.

    """
    _check_code(code, PCAPNG_SecretsType, PCAPNG)
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_secrets_{meth}'):
        raise RegistryError('method must be a decryption secrets parser function')

    PCAPNG.register_secrets(code, meth)
    if schema is not None:
        Schema_PCAPNG_DSBSecrets.register(code, schema)
    logger.debug('registered PCAP-NG decryption secrets parser: %s', code.name)
