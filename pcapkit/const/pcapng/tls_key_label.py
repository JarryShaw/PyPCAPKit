# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TLS Key Log Labels
========================

.. module:: pcapkit.const.pcapng.tls_key_label

This module contains the constant enumeration for **TLS Key Log Labels**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.tls_key_label.TLSKeyLabel`.

"""

from aenum import StrEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['TLSKeyLabel']


class TLSKeyLabel(EnumRegistry, StrEnum):
    """[TLSKeyLabel] TLS Key Log Labels"""

    #: NSS-historical: not a registered label of :rfc:`9850#section-4.2`'s "TLS
    #: SSLKEYLOGFILE Labels" registry. Defined by the Mozilla NSS
    #: ``SSLKEYLOGFILE`` convention and removed in NSS 3.34; kept here only so
    #: that key logs predating :rfc:`9850` still read.
    RSA = 'RSA'

    #: Master secret in TLS 1.2 and earlier, c.f., :rfc:`9850#section-4.2`.
    CLIENT_RANDOM = 'CLIENT_RANDOM'

    #: Secret for client early data records, c.f., :rfc:`9850#section-4.2`.
    CLIENT_EARLY_TRAFFIC_SECRET = 'CLIENT_EARLY_TRAFFIC_SECRET'  # nosec B105

    #: Early exporter secret, c.f., :rfc:`9850#section-4.2`.
    EARLY_EXPORTER_SECRET = 'EARLY_EXPORTER_SECRET'  # nosec B105

    #: Secret protecting client handshake, c.f., :rfc:`9850#section-4.2`.
    CLIENT_HANDSHAKE_TRAFFIC_SECRET = 'CLIENT_HANDSHAKE_TRAFFIC_SECRET'  # nosec B105

    #: Secret protecting server handshake, c.f., :rfc:`9850#section-4.2`.
    SERVER_HANDSHAKE_TRAFFIC_SECRET = 'SERVER_HANDSHAKE_TRAFFIC_SECRET'  # nosec B105

    #: Secret protecting client records post handshake, c.f.,
    #: :rfc:`9850#section-4.2`.
    CLIENT_TRAFFIC_SECRET_0 = 'CLIENT_TRAFFIC_SECRET_0'  # nosec B105

    #: Secret protecting server records post handshake, c.f.,
    #: :rfc:`9850#section-4.2`.
    SERVER_TRAFFIC_SECRET_0 = 'SERVER_TRAFFIC_SECRET_0'  # nosec B105

    #: Exporter secret after handshake, c.f., :rfc:`9850#section-4.2`.
    EXPORTER_SECRET = 'EXPORTER_SECRET'  # nosec B105

    #: HPKE KEM shared secret used in the ECH, c.f., :rfc:`9850#section-4.2`.
    ECH_SECRET = 'ECH_SECRET'  # nosec B105

    #: ECHConfig used for construction of the ECH, c.f., :rfc:`9850#section-4.2`.
    ECH_CONFIG = 'ECH_CONFIG'
