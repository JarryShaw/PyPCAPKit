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

from pcapkit.const.http.frame import Frame as HTTP_Frame
from pcapkit.const.tls.extension_type import ExtensionType as TLS_ExtensionType
from pcapkit.foundation.registry.protocols.protocol import _check_code
from pcapkit.protocols.application.httpv2.protocol import HTTPv2
from pcapkit.protocols.application.httpv2.schema import FrameType as Schema_HTTP_FrameType
from pcapkit.protocols.application.ssl.protocol import SSL
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.protocols.application.httpv2.protocol import \
        FrameConstructor as HTTP_FrameConstructor
    from pcapkit.protocols.application.httpv2.protocol import FrameParser as HTTP_FrameParser
    from pcapkit.protocols.application.ssl.protocol import \
        ExtensionConstructor as TLS_ExtensionConstructor
    from pcapkit.protocols.application.ssl.protocol import ExtensionParser as TLS_ExtensionParser

__all__ = [
    'register_http_frame',
    'register_tls_extension',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


###############################################################################
# Application Layer Registries
###############################################################################


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
            is a name with no matching ``_read_http_*`` method.

    """
    _check_code(code, HTTP_Frame, HTTPv2)
    if isinstance(meth, str) and not hasattr(HTTPv2, f'_read_http_{meth}'):
        raise RegistryError('method must be a frame parser function')

    HTTPv2.register_frame(code, meth)
    if schema is not None:
        Schema_HTTP_FrameType.register(code, schema)
    logger.debug('registered HTTP/2 frame parser: %s', code.name)


# NOTE: pcapkit.protocols.application.ssl.protocol.SSL.__extension__
def register_tls_extension(code: 'TLS_ExtensionType',
                           meth: 'str | tuple[TLS_ExtensionParser, TLS_ExtensionConstructor]') -> 'None':
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

    Raises:
        RegistryError: If ``code`` is not an
            :class:`~pcapkit.const.tls.extension_type.ExtensionType` member,
            e.g. a member of another enum, or ``meth`` is a name with no
            matching ``_read_ext_*`` method.

    .. versionadded:: 1.6.0

    """
    _check_code(code, TLS_ExtensionType, SSL)  # type: ignore[type-abstract]
    if isinstance(meth, str) and not hasattr(SSL, f'_read_ext_{meth}'):
        raise RegistryError('method must be a valid TLS extension parser function')

    SSL.register_extension(code, meth)
    logger.debug('registered TLS extension parser: %s', code.name)
