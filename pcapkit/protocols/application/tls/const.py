# -*- coding: utf-8 -*-
"""constants for TLS protocol

.. versionadded:: 1.7.0

"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = []  # type: list[str]

#: Length of the record header -- content type, legacy version and length
#: (:rfc:`9846#section-5.1`).
_RECORD_HEADER_LENGTH = 5

#: Legacy record version SSLv3 carries, the one tier with its own
#: :attr:`~pcapkit.protocols.application.tls.protocol.TLS.name`.
_SSLV3_VERSION = 0x0300

#: Legacy record version to alias. TLS 1.3 reuses ``0x0303``; see
#: :data:`_TLS13_LEGACY_VERSIONS`.
_TLS_VERSION_ALIASES = {
    _SSLV3_VERSION: 'SSLv3',
    0x0301: 'TLS 1.0',
    0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2',
}  # type: dict[int, Literal["SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2"]]

#: Legacy record versions a TLS 1.3 record may carry -- ``0x0303`` always, and
#: ``0x0301`` on an initial ``ClientHello`` (:rfc:`9846#section-5.1`).
_TLS13_LEGACY_VERSIONS = frozenset({0x0301, 0x0303})
