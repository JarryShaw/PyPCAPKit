# -*- coding: utf-8 -*-
"""constants for DTLS protocol

.. versionadded:: 1.7.0

"""

__all__ = []  # type: list[str]

#: Length of a legacy record header -- content type, legacy version, epoch,
#: sequence number and length (:rfc:`9147#section-4`).
_LEGACY_HEADER_LENGTH = 13

#: Legacy record version DTLS 1.0 carries (:rfc:`4347#section-4.1`).
_DTLSV1_0_VERSION = 0xFEFF
#: Legacy record version DTLS 1.2 carries, and the value DTLS 1.3 freezes its
#: own legacy-format records at (:rfc:`9147#section-4`).
_DTLSV1_2_VERSION = 0xFEFD
#: Legacy record versions a DTLS 1.3 record may carry -- DTLS 1.2's always, and
#: DTLS 1.0's on an initial ``ClientHello`` (:rfc:`9147#section-4`).
_DTLS13_LEGACY_VERSIONS = frozenset({_DTLSV1_0_VERSION, _DTLSV1_2_VERSION})
#: Top three bits of a unified-header first octet, ``001`` (:rfc:`9147#section-4.1`).
_UNIFIED_PREFIX = 0b001
#: Shortest ciphertext a unified-header record may carry. The record-number
#: sample is taken from its first 16 octets (:rfc:`9147#section-4.2.3`).
_CIPHERTEXT_MIN_LENGTH = 16
#: Offset of a ``tls12_cid`` record's connection ID, after its content type,
#: legacy version, epoch and sequence number (:rfc:`9146#section-4`).
_CID_OFFSET = 11
#: Longest connection ID. Its length is one octet (:rfc:`9146#section-3`).
_CID_MAX_LENGTH = 255
