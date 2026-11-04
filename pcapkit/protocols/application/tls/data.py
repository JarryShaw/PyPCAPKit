# -*- coding: utf-8 -*-
"""data models for TLS protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.const.tls.content_type import ContentType as Enum_ContentType

__all__ = [
    'TLS',
]


@info_final
class TLS(Protocol):
    """Data model for TLS protocol."""

    #: Content type.
    content_type: 'Enum_ContentType'
    #: Legacy record version (``major << 8 | minor``).
    version: 'int'
    #: Length of the record fragment.
    length: 'int'
    #: Decoded record content. For ``handshake``, ``alert``, and
    #: ``change_cipher_spec``, this is a tuple of :class:`~pcapkit.protocols.application.ssl.data.Handshake`, an
    #: :class:`~pcapkit.protocols.application.ssl.data.Alert`, or a
    #: :class:`~pcapkit.protocols.application.ssl.data.ChangeCipherSpec` respectively *only when the record is
    #: cleartext* (as decided by
    #: :meth:`SSL._tls_content_is_cleartext
    #: <pcapkit.protocols.application.ssl.protocol.SSL._tls_content_is_cleartext>`) --
    #: an encrypted record of any of those three types, which is the common
    #: case for TLS 1.2 post-handshake traffic, stays raw :obj:`bytes` instead,
    #: same as every other content type.
    content: 'Any'

    if TYPE_CHECKING:
        def __init__(self, content_type: 'Enum_ContentType', version: 'int', length: 'int', content: 'Any') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
