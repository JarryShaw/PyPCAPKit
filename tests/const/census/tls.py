# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.tls`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.tls.certificate_compression_algorithm:CertificateCompressionAlgorithm': 'int',
    'pcapkit.const.tls.certificate_status_type:CertificateStatusType': 'int',
    'pcapkit.const.tls.content_type:ContentType': 'int',
    'pcapkit.const.tls.ec_point_format:ECPointFormat': 'int',
    'pcapkit.const.tls.extension_type:ExtensionType': 'int',
    'pcapkit.const.tls.handshake_type:HandshakeType': 'int',
    'pcapkit.const.tls.hpke_aead_id:HpkeAeadId': 'int',
    'pcapkit.const.tls.hpke_kdf_id:HpkeKdfId': 'int',
    'pcapkit.const.tls.hpke_kem_id:HpkeKemId': 'int',
    'pcapkit.const.tls.psk_key_exchange_mode:PskKeyExchangeMode': 'int',
}
