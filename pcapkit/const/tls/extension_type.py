# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TLS/DTLS ExtensionType Values
===================================

.. module:: pcapkit.const.tls.extension_type

This module contains the constant enumeration for **TLS/DTLS ExtensionType Values**,
which is automatically generated from :class:`pcapkit.vendor.tls.extension_type.ExtensionType`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ExtensionType']


class ExtensionType(EnumRegistry, IntEnum):
    """[ExtensionType] TLS/DTLS ExtensionType Values"""

    #: server_name [:rfc:`6066`][:rfc:`9261`]
    server_name = 0

    #: max_fragment_length [:rfc:`6066`][:rfc:`8449`]
    max_fragment_length = 1

    #: client_certificate_url [:rfc:`6066`]
    client_certificate_url = 2

    #: trusted_ca_keys [:rfc:`6066`]
    trusted_ca_keys = 3

    #: truncated_hmac [:rfc:`6066`][IESG Action 2018-08-16][:rfc:`9847`][Tag Size
    #: Does Matter: Attacks and Proofs for the TLS Record Protocol]
    truncated_hmac = 4

    #: status_request [:rfc:`6066`][:rfc:`9846`]
    status_request = 5

    #: user_mapping [:rfc:`4681`]
    user_mapping = 6

    #: client_authz [:rfc:`5878`]
    client_authz = 7

    #: server_authz [:rfc:`5878`]
    server_authz = 8

    #: cert_type [:rfc:`6091`]
    cert_type = 9

    #: supported_groups [:rfc:`8422`][:rfc:`7919`][:rfc:`9846`]
    supported_groups = 10

    #: ec_point_formats [:rfc:`8422`]
    ec_point_formats = 11

    #: srp [:rfc:`5054`]
    srp = 12

    #: signature_algorithms [:rfc:`9846`]
    signature_algorithms = 13

    #: use_srtp [:rfc:`5764`]
    use_srtp = 14

    #: heartbeat [:rfc:`6520`]
    heartbeat = 15

    #: application_layer_protocol_negotiation [:rfc:`7301`]
    application_layer_protocol_negotiation = 16

    #: status_request_v2 [:rfc:`6961`]
    status_request_v2 = 17

    #: signed_certificate_timestamp [:rfc:`6962`]
    signed_certificate_timestamp = 18

    #: client_certificate_type [:rfc:`7250`]
    client_certificate_type = 19

    #: server_certificate_type [:rfc:`7250`]
    server_certificate_type = 20

    #: padding [:rfc:`7685`]
    padding = 21

    #: encrypt_then_mac [:rfc:`7366`]
    encrypt_then_mac = 22

    #: extended_main_secret [:rfc:`7627`][:rfc:`9846`]
    extended_main_secret = 23

    #: token_binding [:rfc:`8472`]
    token_binding = 24

    #: cached_info [:rfc:`7924`][:rfc:`9846`]
    cached_info = 25

    #: tls_lts [draft-gutmann-tls-lts-11]
    tls_lts = 26

    #: compress_certificate [:rfc:`8879`]
    compress_certificate = 27

    #: record_size_limit [:rfc:`8449`]
    record_size_limit = 28

    #: pwd_protect [:rfc:`8492`]
    pwd_protect = 29

    #: pwd_clear [:rfc:`8492`]
    pwd_clear = 30

    #: password_salt [:rfc:`8492`]
    password_salt = 31

    #: ticket_pinning [:rfc:`8672`]
    ticket_pinning = 32

    #: tls_cert_with_extern_psk [:rfc:`9973`]
    tls_cert_with_extern_psk = 33

    #: delegated_credential [:rfc:`9345`]
    delegated_credential = 34

    #: session_ticket [:rfc:`5077`][:rfc:`8447`]
    session_ticket = 35

    #: TLMSP [ETSI TS 103 523-2]
    TLMSP = 36

    #: TLMSP_proxying [ETSI TS 103 523-2]
    TLMSP_proxying = 37

    #: TLMSP_delegate [ETSI TS 103 523-2]
    TLMSP_delegate = 38

    #: supported_ekt_ciphers [:rfc:`8870`]
    supported_ekt_ciphers = 39

    #: Reserved [:rfc:`9847`][tls-reg-review mailing list]
    Reserved_40 = 40

    #: pre_shared_key [:rfc:`9846`]
    pre_shared_key = 41

    #: early_data [:rfc:`9846`]
    early_data = 42

    #: supported_versions [:rfc:`9846`]
    supported_versions = 43

    #: cookie [:rfc:`9846`]
    cookie = 44

    #: psk_key_exchange_modes [:rfc:`9846`]
    psk_key_exchange_modes = 45

    #: Reserved [:rfc:`9847`][tls-reg-review mailing list]
    Reserved_46 = 46

    #: certificate_authorities [:rfc:`9846`]
    certificate_authorities = 47

    #: oid_filters [:rfc:`9846`]
    oid_filters = 48

    #: post_handshake_auth [:rfc:`9846`]
    post_handshake_auth = 49

    #: signature_algorithms_cert [:rfc:`9846`]
    signature_algorithms_cert = 50

    #: key_share [:rfc:`9846`][RFC Errata 5483]
    key_share = 51

    #: transparency_info [:rfc:`9162`]
    transparency_info = 52

    #: connection_id (deprecated) [:rfc:`9146`][:rfc:`9847`]
    connection_id_deprecated = 53

    #: connection_id [:rfc:`9146`]
    connection_id = 54

    #: external_id_hash [:rfc:`8844`]
    external_id_hash = 55

    #: external_session_id [:rfc:`8844`]
    external_session_id = 56

    #: quic_transport_parameters [:rfc:`9001`]
    quic_transport_parameters = 57

    #: ticket_request [:rfc:`9149`]
    ticket_request = 58

    #: dnssec_chain [:rfc:`9102`][RFC Errata 6860]
    dnssec_chain = 59

    #: sequence_number_encryption_algorithms
    #: [draft-pismenny-tls-dtls-plaintext-sequence-number-01]
    sequence_number_encryption_algorithms = 60

    #: rrc [:rfc:`9853`]
    rrc = 61

    #: tls_flags [draft-ietf-tls-tlsflags-14]
    tls_flags = 62

    #: Reserved [:rfc:`8701`]
    Reserved_2570 = 2570

    #: Reserved [:rfc:`8701`]
    Reserved_6682 = 6682

    #: Reserved [:rfc:`8701`]
    Reserved_10794 = 10794

    #: Reserved [:rfc:`8701`]
    Reserved_14906 = 14906

    #: Reserved [:rfc:`8701`]
    Reserved_19018 = 19018

    #: Reserved [:rfc:`8701`]
    Reserved_23130 = 23130

    #: Reserved [:rfc:`8701`]
    Reserved_27242 = 27242

    #: Reserved [:rfc:`8701`]
    Reserved_31354 = 31354

    #: Reserved [:rfc:`8701`]
    Reserved_35466 = 35466

    #: Reserved [:rfc:`8701`]
    Reserved_39578 = 39578

    #: Reserved [:rfc:`8701`]
    Reserved_43690 = 43690

    #: Reserved [:rfc:`8701`]
    Reserved_47802 = 47802

    #: Reserved [:rfc:`8701`]
    Reserved_51914 = 51914

    #: Reserved [:rfc:`8701`]
    Reserved_56026 = 56026

    #: Reserved [:rfc:`8701`]
    Reserved_60138 = 60138

    #: Reserved [:rfc:`8701`]
    Reserved_64250 = 64250

    #: ech_outer_extensions [:rfc:`9849`] -- Only appears in inner CH.
    ech_outer_extensions = 64768

    #: encrypted_client_hello [:rfc:`9849`]
    encrypted_client_hello = 65037

    #: Reserved for Private Use [:rfc:`9846`]
    Reserved_for_Private_Use = 65280

    #: renegotiation_info [:rfc:`5746`]
    renegotiation_info = 65281

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'ExtensionType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 63 <= value <= 2569:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 2571 <= value <= 6681:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 6683 <= value <= 10793:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 10795 <= value <= 14905:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 14907 <= value <= 19017:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 19019 <= value <= 23129:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 23131 <= value <= 27241:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 27243 <= value <= 31353:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 31355 <= value <= 35465:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 35467 <= value <= 39577:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 39579 <= value <= 43689:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 43691 <= value <= 47801:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 47803 <= value <= 51913:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 51915 <= value <= 56025:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 56027 <= value <= 60137:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 60139 <= value <= 64249:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 64251 <= value <= 64767:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 64769 <= value <= 65036:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 65038 <= value <= 65279:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 65282 <= value <= 65535:
            #: Reserved for Private Use [:rfc:`9846`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        return super()._missing_(value)
