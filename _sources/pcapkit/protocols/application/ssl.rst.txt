SSL - Secure Sockets Layer
===============================

.. module:: pcapkit.protocols.application.ssl
.. module:: pcapkit.protocols.application.ssl.protocol

:mod:`pcapkit.protocols.application.ssl.protocol` contains
:class:`~pcapkit.protocols.application.ssl.protocol.SSL`,
which is the umbrella base class for the Secure Sockets Layer protocol
family [*]_ -- the SSL versions, Transport Layer Security and Datagram TLS:

* :class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2` -- SSL 2.0, whose
  record layer shares no wire format with the others;
* :class:`~pcapkit.protocols.application.tls.protocol.TLS` -- SSLv3 and TLS 1.0
  through TLS 1.3, with :class:`~pcapkit.protocols.application.sslv3.protocol.SSLv3` as
  its thin subclass for explicit construction;
* :class:`~pcapkit.protocols.application.dtls.protocol.DTLS` -- DTLS 1.0, 1.2 and 1.3.

:meth:`SSL.id <pcapkit.protocols.application.ssl.protocol.SSL.id>` lists the direct
concrete subclasses, so a lookup keyed on ``SSL`` matches any of them.

The TLS record header (:rfc:`9846#section-5.1`) is a
:class:`~pcapkit.const.tls.content_type.ContentType`, a legacy record version
and a length. The DTLS ``DTLSPlaintext`` header (:rfc:`9147#section-4`) has
the same fields plus an epoch and a 48-bit sequence number *between* the
version and the length, and DTLS adds a fragment header to each handshake
message. Each record header is declared in its subclass's own schema, and
:class:`~pcapkit.protocols.application.dtls.protocol.DTLS` reads the epoch and sequence
number. This base class carries the logic TLS and DTLS share -- content-type
dispatch, handshake-message decoding (including the DTLS fragment header), the
extension registry and the header schema of each extension's ``extension_data``
(:mod:`pcapkit.protocols.application.ssl.schema`), and the record-level validation that keeps dispatch from
accepting bytes that cannot be a genuine record.

.. versionadded:: 1.6.0

.. versionremoved:: 1.7.0

   ``pcapkit.protocols.application.ssl.protocol.TLS13_VERSION`` and
   ``pcapkit.protocols.application.ssl.protocol.DTLS13_VERSION``, now
   :data:`pcapkit.protocols.application.ssl.const.TLS13_VERSION` and
   :data:`pcapkit.protocols.application.ssl.const.DTLS13_VERSION` (:issue:`2896`).

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.ssl.protocol.SSL
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __extension__
      :no-value:

   .. autoattribute:: _dtls

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: register_extension

   .. rubric:: Utilities

   .. automethod:: _read_ext_unknown
   .. automethod:: _read_ext_server_name
   .. automethod:: _read_ext_status_request
   .. automethod:: _read_ext_supported_groups
   .. automethod:: _read_ext_ec_point_formats
   .. automethod:: _read_ext_signature_algorithms
   .. automethod:: _read_ext_alpn
   .. automethod:: _read_ext_signed_certificate_timestamp
   .. automethod:: _read_ext_padding
   .. automethod:: _read_ext_extended_main_secret
   .. automethod:: _read_ext_compress_certificate
   .. automethod:: _read_ext_record_size_limit
   .. automethod:: _read_ext_session_ticket
   .. automethod:: _read_ext_pre_shared_key
   .. automethod:: _read_ext_early_data
   .. automethod:: _read_ext_supported_versions
   .. automethod:: _read_ext_cookie
   .. automethod:: _read_ext_psk_key_exchange_modes
   .. automethod:: _read_ext_post_handshake_auth
   .. automethod:: _read_ext_key_share
   .. automethod:: _read_ext_connection_id
   .. automethod:: _read_ext_ech
   .. automethod:: _read_ext_renegotiation_info
   .. automethod:: _make_ext_unknown
   .. automethod:: _make_ext_server_name
   .. automethod:: _make_ext_status_request
   .. automethod:: _make_ext_supported_groups
   .. automethod:: _make_ext_ec_point_formats
   .. automethod:: _make_ext_signature_algorithms
   .. automethod:: _make_ext_alpn
   .. automethod:: _make_ext_signed_certificate_timestamp
   .. automethod:: _make_ext_padding
   .. automethod:: _make_ext_extended_main_secret
   .. automethod:: _make_ext_compress_certificate
   .. automethod:: _make_ext_record_size_limit
   .. automethod:: _make_ext_session_ticket
   .. automethod:: _make_ext_pre_shared_key
   .. automethod:: _make_ext_early_data
   .. automethod:: _make_ext_supported_versions
   .. automethod:: _make_ext_cookie
   .. automethod:: _make_ext_psk_key_exchange_modes
   .. automethod:: _make_ext_post_handshake_auth
   .. automethod:: _make_ext_key_share
   .. automethod:: _make_ext_connection_id
   .. automethod:: _make_ext_ech
   .. automethod:: _make_ext_renegotiation_info
   .. automethod:: _validate_tls_record
   .. automethod:: _tls_negotiates
   .. automethod:: _tls_content_is_cleartext
   .. automethod:: _read_tls_content
   .. automethod:: _read_tls_handshake_messages
   .. automethod:: _make_tls_handshake_messages
   .. automethod:: _read_tls_client_hello
   .. automethod:: _read_tls_server_hello
   .. automethod:: _read_tls_encrypted_extensions
   .. automethod:: _read_tls_extensions
   .. automethod:: _read_ext_schema
   .. automethod:: _make_tls_content
   .. automethod:: _make_tls_client_hello
   .. automethod:: _make_tls_server_hello
   .. automethod:: _make_tls_encrypted_extensions
   .. automethod:: _make_tls_extensions
   .. automethod:: _make_ext_values
   .. automethod:: _make_ext_value

Header Schemas
--------------

.. module:: pcapkit.protocols.application.ssl.schema

.. versionadded:: 1.7.0

.. autoclass:: pcapkit.protocols.application.ssl.schema.Extension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.UnknownExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.Empty
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.Opaque8
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.Opaque16
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ServerName
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ServerNameList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ServerNameExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.OCSPStatusRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.CertificateStatusRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.StatusRequestExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.NamedGroupList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SupportedGroupsExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECPointFormatList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECPointFormatsExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SignatureSchemeList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SignatureAlgorithmsExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ProtocolNameList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ALPNExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SignedCertificateTimestampList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SignedCertificateTimestampExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.Padding
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.PaddingExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ExtendedMainSecretExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.CertificateCompressionAlgorithms
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.CompressCertificateExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.RecordSizeLimit
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.RecordSizeLimitExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SessionTicket
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SessionTicketExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.PskIdentity
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.OfferedPsks
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.PreSharedKeyServerHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.PreSharedKeyExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.EarlyDataExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SupportedVersionsClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SupportedVersionsServerHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.SupportedVersionsExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.Cookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.CookieExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.PskKeyExchangeModes
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.PskKeyExchangeModesExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.PostHandshakeAuthExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.KeyShareEntry
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.KeyShareClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.KeyShareHelloRetryRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.KeyShareServerHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.KeyShareExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ConnectionId
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ConnectionIdExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.HpkeSymmetricCipherSuite
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECHClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECHHelloRetryRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECHConfigExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECHConfigContents
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECHConfig
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECHEncryptedExtensions
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.ECHExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.RenegotiationInfo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.schema.RenegotiationInfoExtension
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.application.ssl.data

.. autoclass:: pcapkit.protocols.application.ssl.data.Handshake
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ServerHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.EncryptedExtensions
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.Extension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ExtensionData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ServerNameList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ServerName
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.NamedGroupList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.SignatureSchemeList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ProtocolNameList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.SupportedVersionsClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.SupportedVersionsServerHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.KeyShareClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.KeyShareHelloRetryRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.KeyShareServerHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.KeyShareEntry
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ConnectionId
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.Empty
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.CertificateStatusRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.OCSPStatusRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ECPointFormatList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.SignedCertificateTimestampList
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.Padding
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.CertificateCompressionAlgorithms
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.RecordSizeLimit
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.SessionTicket
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.OfferedPsks
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.PskIdentity
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.PreSharedKeyServerHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.Cookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.PskKeyExchangeModes
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ECHClientHelloOuter
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ECHClientHelloInner
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ECHHelloRetryRequest
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ECHEncryptedExtensions
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ECHConfig
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ECHConfigContents
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.HpkeKeyConfig
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.HpkeSymmetricCipherSuite
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ECHConfigExtension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.RenegotiationInfo
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.Alert
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ssl.data.ChangeCipherSpec
   :members:
   :show-inheritance:

Constants
---------

.. module:: pcapkit.protocols.application.ssl.const

.. versionadded:: 1.7.0

.. autodata:: pcapkit.protocols.application.ssl.const.TLS13_VERSION

.. autodata:: pcapkit.protocols.application.ssl.const.DTLS13_VERSION

.. autodata:: pcapkit.protocols.application.ssl.const._HRR_RANDOM
   :no-value:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security
