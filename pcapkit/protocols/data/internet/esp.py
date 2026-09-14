# -*- coding: utf-8 -*-
"""data model for ESP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.internet.esp import ESPStatus

__all__ = ['ESP']


@info_final
class ESP(Protocol):
    """Data model for ESP protocol.

    The trailer fields (:attr:`next`, :attr:`pad_len`, :attr:`padding`) and
    :attr:`plaintext` are recovered from the *decrypted* payload, and are
    therefore :data:`None` whenever the payload could not be decrypted --
    :rfc:`4303` places them inside the ciphertext, so guessing them from an
    encrypted payload is not possible. :attr:`status` says which of those
    two cases applies, and :attr:`error` says why.

    Important:
        No key material is recorded here, by design. This data model is what
        :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` returns
        and hence what reaches the output dumpers, so the Security
        Association -- and the keys it holds -- is deliberately kept out of
        it.

    """

    #: Security parameters index.
    spi: 'int'
    #: Sequence number field.
    seq: 'int'
    #: Total length of the ESP header, payload, trailer and ICV, i.e. every
    #: byte of the packet that ESP owns.
    length: 'int'
    #: Payload data exactly as transmitted -- ciphertext, prefixed by any
    #: cryptographic synchronisation data (IV) -- excluding the ICV.
    payload_data: 'bytes'
    #: Integrity check value as transmitted; empty when absent, or when no
    #: Security Association was available to say how long it is.
    icv: 'bytes'
    #: Outcome of the decryption and integrity check.
    status: 'ESPStatus'
    #: Reason the payload was not decrypted, if it was not.
    error: 'Optional[str]'
    #: Next header, from the decrypted ESP trailer.
    next: 'Optional[TransType]'
    #: Pad length, from the decrypted ESP trailer.
    pad_len: 'Optional[int]'
    #: Padding bytes, from the decrypted ESP trailer.
    padding: 'Optional[bytes]'
    #: Decrypted payload, with the ESP trailer stripped, i.e. the next
    #: layer's data.
    plaintext: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, spi: 'int', seq: 'int', length: 'int', payload_data: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,too-many-arguments
                     icv: 'bytes', status: 'ESPStatus', error: 'Optional[str]',
                     next: 'Optional[TransType]', pad_len: 'Optional[int]',
                     padding: 'Optional[bytes]', plaintext: 'Optional[bytes]') -> 'None': ...
