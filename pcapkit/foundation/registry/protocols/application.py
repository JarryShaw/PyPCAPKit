# -*- coding: utf-8 -*-
"""Application Layer Protocol Registries
===========================================

.. module:: pcapkit.foundation.registry.protocols.application

This module provides the registries of the application layer protocols in
:mod:`pcapkit.protocols.application`.

.. versionadded:: 1.6.0

   Moved here from the single :file:`pcapkit/foundation/registry/protocols.py`
   module. The :mod:`pcapkit.foundation.registry.protocols` package exports
   this module's functions (:issue:`2578`).

"""
from typing import TYPE_CHECKING

from pcapkit.const.dns.option import Option as DNS_Option
from pcapkit.const.dns.rr_type import RRType as DNS_RRType
from pcapkit.const.http.frame import Frame as HTTP_Frame
from pcapkit.const.tls.extension_type import ExtensionType as TLS_ExtensionType
from pcapkit.foundation.registry.protocols.protocol import _check_code, _check_meth
from pcapkit.protocols.application.dns.protocol import DNS
from pcapkit.protocols.application.httpv2.protocol import HTTPv2
from pcapkit.protocols.application.httpv2.schema import FrameType as Schema_HTTP_FrameType
from pcapkit.protocols.application.ssl.protocol import SSL
from pcapkit.protocols.application.ssl.schema import Extension as Schema_TLS_Extension
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.protocols.application.dns.protocol import \
        OptionConstructor as DNS_OptionConstructor
    from pcapkit.protocols.application.dns.protocol import OptionParser as DNS_OptionParser
    from pcapkit.protocols.application.dns.protocol import RDataConstructor as DNS_RDataConstructor
    from pcapkit.protocols.application.dns.protocol import RDataParser as DNS_RDataParser
    from pcapkit.protocols.application.httpv2.protocol import \
        FrameConstructor as HTTP_FrameConstructor
    from pcapkit.protocols.application.httpv2.protocol import FrameParser as HTTP_FrameParser
    from pcapkit.protocols.application.ssl.protocol import \
        ExtensionConstructor as TLS_ExtensionConstructor
    from pcapkit.protocols.application.ssl.protocol import ExtensionParser as TLS_ExtensionParser

__all__ = [
    'register_dns_rdata', 'register_dns_option',
    'register_http_frame',
    'register_tls_extension',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


###############################################################################
# Application Layer Registries
###############################################################################


# NOTE: pcapkit.protocols.application.dns.protocol.DNS.__rdata__
def register_dns_rdata(code: 'DNS_RRType', meth: 'str | tuple[DNS_RDataParser, DNS_RDataConstructor]') -> 'None':
    """Register an RDATA parser.

    The function will register the given RDATA parser to the
    :data:`pcapkit.protocols.application.dns.protocol.DNS.__rdata__` registry.

    Args:
        code: :class:`DNS <pcapkit.protocols.application.dns.protocol.DNS>` RR type
            as in :class:`~pcapkit.const.dns.rr_type.RRType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the RDATA. A name names the ``_read_rdata_*``
            and ``_make_rdata_*`` methods, and has to name an existing
            ``_read_rdata_*`` one.

    Raises:
        RegistryError: If ``code`` is not an
            :class:`~pcapkit.const.dns.rr_type.RRType` member, e.g. a member
            of another enum, or ``meth`` is a name with no matching
            ``_read_rdata_*`` method, or neither a name
            nor a pair of two callables.

    .. versionadded:: 1.7.0

    """
    _check_code(code, DNS_RRType, DNS)
    _check_meth(meth, DNS)
    if isinstance(meth, str) and not hasattr(DNS, f'_read_rdata_{meth}'):
        raise RegistryError('method must be a valid DNS RDATA parser function')

    DNS.register_rdata(code, meth)
    logger.debug('registered DNS RDATA parser: %s', code.name)


# NOTE: pcapkit.protocols.application.dns.protocol.DNS.__option__
def register_dns_option(code: 'DNS_Option', meth: 'str | tuple[DNS_OptionParser, DNS_OptionConstructor]') -> 'None':
    """Register an EDNS(0) option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.application.dns.protocol.DNS.__option__` registry.

    Args:
        code: :class:`DNS <pcapkit.protocols.application.dns.protocol.DNS>` EDNS(0)
            option code as in :class:`~pcapkit.const.dns.option.Option`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the OPTION-DATA. A name names the
            ``_read_opt_*`` and ``_make_opt_*`` methods, and has to name an
            existing ``_read_opt_*`` one.

    Raises:
        RegistryError: If ``code`` is not an
            :class:`~pcapkit.const.dns.option.Option` member, e.g. a member of
            another enum, or ``meth`` is a name with no matching
            ``_read_opt_*`` method, or neither a name
            nor a pair of two callables.

    .. versionadded:: 1.7.0

    """
    _check_code(code, DNS_Option, DNS)
    _check_meth(meth, DNS)
    if isinstance(meth, str) and not hasattr(DNS, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid DNS option parser function')

    DNS.register_option(code, meth)
    logger.debug('registered DNS option parser: %s', code.name)


# NOTE: pcapkit.protocols.application.httpv2.protocol.HTTPv2.__frame__
def register_http_frame(code: 'HTTP_Frame', meth: 'str | tuple[HTTP_FrameParser, HTTP_FrameConstructor]', *,
                        schema: 'Optional[Type[Schema_HTTP_FrameType]]' = None) -> 'None':
    """Register a frame parser.

    The function will register the given frame parser to the
    :data:`pcapkit.protocols.application.httpv2.protocol.HTTPv2.__frame__` registry.

    Args:
        code: :class:`HTTP/2 <pcapkit.protocols.application.httpv2.protocol.HTTPv2>` frame type
            code as in :class:`~pcapkit.const.http.frame.Frame`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the frame. A name names the
            ``_read_http_*`` and ``_make_http_*`` methods, and has to name
            an existing ``_read_http_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the frame.
            It should be a subclass of :class:`pcapkit.protocols.application.httpv2.schema.FrameType`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.http.frame.Frame`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_http_*`` method, or neither a name
            nor a pair of two callables.

    """
    _check_code(code, HTTP_Frame, HTTPv2)
    _check_meth(meth, HTTPv2)
    if isinstance(meth, str) and not hasattr(HTTPv2, f'_read_http_{meth}'):
        raise RegistryError('method must be a frame parser function')

    HTTPv2.register_frame(code, meth)
    if schema is not None:
        Schema_HTTP_FrameType.register(code, schema)
    logger.debug('registered HTTP/2 frame parser: %s', code.name)


# NOTE: pcapkit.protocols.application.ssl.protocol.SSL.__extension__
def register_tls_extension(code: 'TLS_ExtensionType',
                           meth: 'str | tuple[TLS_ExtensionParser, TLS_ExtensionConstructor]', *,
                           schema: 'Optional[Type[Schema_TLS_Extension]]' = None) -> 'None':
    """Register an extension parser.

    The function will register the given extension parser to the
    :data:`pcapkit.protocols.application.ssl.protocol.SSL.__extension__` registry, which
    :class:`~pcapkit.protocols.application.tls.protocol.TLS` and
    :class:`~pcapkit.protocols.application.dtls.protocol.DTLS` share.

    Args:
        code: TLS/DTLS extension type as in
            :class:`~pcapkit.const.tls.extension_type.ExtensionType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the ``extension_data``. A name names the
            ``_read_ext_*`` and ``_make_ext_*`` methods, and has to name an
            existing ``_read_ext_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the ``extension_data``.
            It should be a subclass of :class:`pcapkit.protocols.application.ssl.schema.Extension`.

    Raises:
        RegistryError: If ``code`` is not an
            :class:`~pcapkit.const.tls.extension_type.ExtensionType` member,
            e.g. a member of another enum, or ``meth`` is a name with no
            matching ``_read_ext_*`` method, or neither a name
            nor a pair of two callables.

    .. versionadded:: 1.6.0

    .. versionchanged:: 1.7.0

       Takes ``schema``. The parser is handed the ``extension_data`` unpacked
       by that schema, and the constructor returns one, rather than octets
       (:issue:`2833`).

    """
    _check_code(code, TLS_ExtensionType, SSL)  # type: ignore[type-abstract]
    _check_meth(meth, SSL)  # type: ignore[type-abstract]
    if isinstance(meth, str) and not hasattr(SSL, f'_read_ext_{meth}'):
        raise RegistryError('method must be a valid TLS extension parser function')

    SSL.register_extension(code, meth)
    if schema is not None:
        Schema_TLS_Extension.register(code, schema)
    logger.debug('registered TLS extension parser: %s', code.name)
