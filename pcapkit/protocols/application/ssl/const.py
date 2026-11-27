# -*- coding: utf-8 -*-
"""constants the SSL family shares

.. versionadded:: 1.7.0

"""

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType

__all__ = ['TLS13_VERSION', 'DTLS13_VERSION']

#: Legacy record-version major octet TLS records carry (SSLv3 through the
#: TLS 1.3 wire value, all ``0x03xx``).
_TLS_VERSION_MAJOR = 0x03
#: Legacy record-version major octet DTLS records carry (``0xFExx`` --
#: DTLS encodes its legacy version as the one's complement of TLS's).
_DTLS_VERSION_MAJOR = 0xFE

#: The longest fragment a legacy record header may declare, that of a TLSCiphertext
#: of SSLv3 to TLS 1.2 (:rfc:`6101#section-5.2.3`, :rfc:`5246#section-6.2.3`), which
#: DTLS 1.0 and 1.2 keep (:rfc:`4347#section-4`, :rfc:`6347#section-4`). TLS 1.3's
#: ``2 ** 14 + 256`` (:rfc:`9846#section-5.2`) and every plaintext's ``2 ** 14`` are
#: within it, and the header does not tell the versions apart. A peer that
#: receives a longer record sends ``record_overflow``.
_RECORD_MAX_LENGTH = 2 ** 14 + 2048

#: The content types a genuine record may carry. An allowlist rather than
#: every :class:`~pcapkit.const.tls.content_type.ContentType` member: 0 is
#: never assigned, a value :rfc:`9846#section-5.1` rejects outright, and the
#: enum mints an ``Unassigned``/``Reserved`` member for any value IANA has
#: not named.
#:
#: ``tls12_cid`` (25, :rfc:`9146#section-4`) is left out: its connection ID
#: precedes ``length`` and has a negotiated length the record does not carry,
#: so reading ``length`` at the fixed offset would fabricate a fragment.
_WIRE_CONTENT_TYPES = frozenset({
    Enum_ContentType.change_cipher_spec,
    Enum_ContentType.alert,
    Enum_ContentType.handshake,
    Enum_ContentType.application_data,
    Enum_ContentType.heartbeat,
    Enum_ContentType.ack,
    Enum_ContentType.return_routability_check,
})

#: The ``supported_versions`` value for TLS 1.3 (:rfc:`9846#section-4.3.1`).
TLS13_VERSION = 0x0304
#: The ``supported_versions`` value for DTLS 1.3 (:rfc:`9147#section-5.3`).
DTLS13_VERSION = 0xFEFC

#: The ``random`` that makes a ``ServerHello`` a ``HelloRetryRequest`` -- the
#: SHA-256 of ``"HelloRetryRequest"`` (:rfc:`9846#section-4.2.3`).
_HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')

#: The ``host_name`` ``NameType`` of ``server_name``, the only one defined
#: (:rfc:`6066#section-3`).
_HOST_NAME = 0

#: The ``outer`` and ``inner`` ``ECHClientHelloType`` of ``encrypted_client_hello``
#: (:rfc:`9849#section-5`).
_ECH_OUTER, _ECH_INNER = 0, 1
#: Length of an ``ECHHelloRetryRequest``'s ``confirmation`` (:rfc:`9849#section-5`).
_ECH_CONFIRMATION_LENGTH = 8
#: The ``ECHConfig`` version whose ``contents`` :rfc:`9849#section-4` defines, which
#: is the ``encrypted_client_hello`` code point.
_ECH_CONFIG_VERSION = int(Enum_ExtensionType.encrypted_client_hello)
