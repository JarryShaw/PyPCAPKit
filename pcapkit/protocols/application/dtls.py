# -*- coding: utf-8 -*-
"""DTLS - Datagram Transport Layer Security
==============================================

.. module:: pcapkit.protocols.application.dtls

:mod:`pcapkit.protocols.application.dtls` contains
:class:`~pcapkit.protocols.application.dtls.DTLS` only, which implements an
extractor for the DTLS record-layer family -- DTLS 1.0 (:rfc:`4347`), DTLS
1.2 (:rfc:`6347`), and DTLS 1.3's legacy-format and unified-header records
(:rfc:`9147`). :attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>`
binds it at port 5684. As with :class:`~pcapkit.protocols.application.tls.TLS`,
:meth:`~DTLS.read` sets :attr:`~DTLS.alias` from the record's legacy version,
or to ``DTLS 1.3`` for a unified-header record.

Known Limitations
-----------------

**A handshake message split across DTLS records is not decoded here**
(:rfc:`6347#section-4.2.3`, :issue:`2440`). Each fragment's body stays raw
octets, flagged
:attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.is_fragmented`.
``Extractor(reassembly=True, dtls=True)`` reassembles the message
(:class:`~pcapkit.foundation.reassembly.dtls.DTLS`), and
:func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` decodes it with
:meth:`DTLS.read_handshake`. Only the first record of each datagram is
reassembled.

**A unified-header record with a connection ID is not decoded**
(:rfc:`9147#section-4.1`). Its length is negotiated, not carried in the
record, so it degrades to :class:`~pcapkit.protocols.misc.raw.Raw`. The same
holds for ``tls12_cid`` records (:rfc:`9146`).

**A unified-header record carries only the low two bits of the epoch**, and
its sequence number is header-protected, so the values it reports are the
ones on the wire.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.protocols.application.ssl import DTLS13_VERSION, SSL
from pcapkit.protocols.data.application.dtls import DTLS as Data_DTLS
from pcapkit.protocols.data.application.dtls import DTLSCiphertext as Data_DTLSCiphertext
from pcapkit.protocols.schema.application.dtls import DTLS as Schema_DTLS
from pcapkit.protocols.schema.application.dtls import DTLSCiphertext as Schema_DTLSCiphertext
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.data.application.dtls import DTLSHandshake as Data_DTLSHandshake
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['DTLS']

#: Legacy record version DTLS 1.0 carries (:rfc:`4347#section-4.1`).
_DTLSV1_0_VERSION = 0xFEFF
#: Legacy record version DTLS 1.2 carries, and the value DTLS 1.3 freezes its
#: own legacy-format records at (:rfc:`9147#section-4`).
_DTLSV1_2_VERSION = 0xFEFD
#: Legacy record versions a DTLS 1.3 record may carry: DTLS 1.2's always, and
#: DTLS 1.0's on an initial ``ClientHello`` (:rfc:`9147#section-4`).
_DTLS13_LEGACY_VERSIONS = frozenset({_DTLSV1_0_VERSION, _DTLSV1_2_VERSION})
#: Top three bits of a unified-header first octet, ``001`` (:rfc:`9147#section-4.1`).
_UNIFIED_PREFIX = 0b001
#: Shortest ciphertext a unified-header record may carry: the record-number
#: sample is taken from its first 16 octets (:rfc:`9147#section-4.2.3`).
_CIPHERTEXT_MIN_LENGTH = 16


def _is_unified_header(octet: int) -> bool:
    """Whether ``octet`` opens a unified-header record.

    Legacy records open with a content type of 20 through 27, whose top three
    bits are ``000``, so the ``001`` prefix never matches one of them.

    Args:
        octet: First octet of the record.

    Returns:
        Whether the octet's top three bits are the unified-header prefix.

    """
    return octet >> 5 == _UNIFIED_PREFIX


def _ciphertext_header_length(flags: 'dict[str, int]') -> 'int':
    """Length of a unified header, from its first octet's decoded flags.

    Args:
        flags: Decoded first octet, as the header schema holds it.

    Returns:
        First octet, sequence number and, if present, the length field.

    """
    return 1 + (2 if flags['sequence_long'] else 1) + (2 if flags['length_present'] else 0)


class DTLS(SSL[Data_DTLS, Schema_DTLS], schema=Schema_DTLS, data=Data_DTLS):
    """This class implements all protocols in the DTLS record-layer family.

    - Datagram Transport Layer Security 1.0 [:rfc:`4347`]
    - Datagram Transport Layer Security 1.2 [:rfc:`6347`]
    - Datagram Transport Layer Security 1.3, legacy-format and unified-header records [:rfc:`9147`]

    Note:
        The subpackage does not track the dispatch tier: DTLS is dispatched
        from :attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>`
        at port 5684 (``coaps``, :rfc:`7252`) only, though IANA registers
        other DTLS-borne services; bind more with
        :func:`pcapkit.foundation.registry.protocols.register_udp`.

    """

    #: Tier :meth:`read` identified, e.g. ``'DTLS 1.2'``; ``'DTLS'`` until then.
    _alias = 'DTLS'  # type: Literal["DTLS", "DTLS 1.0", "DTLS 1.2", "DTLS 1.3"]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Datagram Transport Layer Security"]':
        """Name of current protocol."""
        return 'Datagram Transport Layer Security'

    @property
    def alias(self) -> 'Literal["DTLS", "DTLS 1.0", "DTLS 1.2", "DTLS 1.3"]':
        """Acronym of current protocol -- the concrete tier :meth:`read` identified."""
        return self._alias

    @property
    def length(self) -> 'int':
        """Header length of current protocol -- the record header, the
        fragment excluded. Fixed at 13 octets for a legacy record; a unified
        header's length follows from its first octet.

        """
        schema = getattr(self, '__header__', None)
        if isinstance(schema, Schema_DTLSCiphertext):
            return _ciphertext_header_length(schema.flags)
        return 13

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["DTLS"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol. Fixed, regardless of which tier
            :meth:`read` identifies the record as -- see
            :meth:`TLS.id <pcapkit.protocols.application.tls.TLS.id>` for why.

        """
        return ('DTLS',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS':
        """Read Datagram Transport Layer Security (DTLS).

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the record cannot be a genuine DTLS record --
                see :meth:`_read_dtls_record`.

        """
        return self._read_dtls_record(length, **kwargs)

    def make(self,
             content_type: 'Enum_ContentType | StdlibEnum | AenumEnum | str | int' = Enum_ContentType.application_data,  # pylint: disable=line-too-long
             content_type_default: 'Optional[int]' = None,
             content_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             content_type_reversed: 'bool' = False,
             version: 'int' = 0xFEFD,
             epoch: 'int' = 0,
             sequence_number: 'int' = 0,
             content: 'Any' = b'',
             data: 'Optional[bytes]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             ciphertext: 'bool' = False,
             sequence_long: 'bool' = False,
             length_present: 'bool' = True,
             **kwargs: 'Any') -> 'Schema_DTLS | Schema_DTLSCiphertext':
        """Make (construct) packet data, for every tier: ``version`` is written as is.

        Args:
            content_type: Record content type.
            content_type_default: Default value for ``content_type``.
            content_type_namespace: Namespace for ``content_type``.
            content_type_reversed: Reverse namespace for ``content_type``.
            version: Legacy record version (``major << 8 | minor``), e.g.
                ``0xFEFD`` for DTLS 1.2 and (the legacy value DTLS 1.3 keeps
                here) DTLS 1.3.
            epoch: Epoch. A unified-header record carries only its low two
                bits, so a larger value is refused.
            sequence_number: Sequence number within ``epoch`` (48-bit); for a
                unified-header record, 8 or 16 bits as ``sequence_long`` says.
            content: Record content: a :obj:`tuple` of
                :class:`~pcapkit.protocols.data.application.dtls.DTLSHandshake`
                for ``handshake``, an
                :class:`~pcapkit.protocols.data.application.tls.Alert`, a
                :class:`~pcapkit.protocols.data.application.tls.ChangeCipherSpec`,
                or raw :obj:`bytes`, as :meth:`read` would decode it. For a
                unified-header record, the ciphertext as :obj:`bytes`.
            data: Pre-encoded record fragment. When given, it is used
                verbatim in place of ``content`` and ``length`` is computed
                from it.
            payload: Octets after the record, e.g. a further record
                coalesced in the same buffer.
            ciphertext: Make a unified-header record (:rfc:`9147#section-4.1`)
                instead of a legacy one; ``content_type``, ``version`` and
                ``data`` do not apply.
            sequence_long: Whether a unified-header record's sequence number is
                16 bits rather than 8.
            length_present: Whether a unified-header record carries its length;
                if not, it runs to the end of the datagram.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        if ciphertext:
            return Schema_DTLSCiphertext(
                flags={
                    'fixed': _UNIFIED_PREFIX,
                    'connection_id': 0,
                    'sequence_long': int(sequence_long),
                    'length_present': int(length_present),
                    'epoch': epoch,
                },
                sequence_number=sequence_number,
                length=len(content) if length_present else None,
                fragment=content,
                payload=payload,
            )

        content_type_ = cast('Enum_ContentType', self._make_index(
            content_type, content_type_default, namespace=content_type_namespace,
            reversed=content_type_reversed, pack=False))

        fragment = data if data is not None else self._make_tls_content(content_type_, content, dtls=True)
        return Schema_DTLS(
            content_type=content_type_,
            version=version,
            epoch=epoch,
            sequence_number=sequence_number,
            length=len(fragment),
            fragment=fragment,
            payload=payload,
        )

    def unpack(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS | Data_DTLSCiphertext':
        """Unpack (parse) packet data, with the header schema its first octet selects.

        A unified-header record (:rfc:`9147#section-4.1`) is parsed by
        :class:`~pcapkit.protocols.schema.application.dtls.DTLSCiphertext`
        rather than the legacy header; every other record uses the inherited
        behaviour.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        octets = self._data[:1]
        if self.__header__ is None and octets and _is_unified_header(octets[0]):
            packet = kwargs.get('__packet__', {})  # packet data
            self.__header__ = Schema_DTLSCiphertext.unpack(self._file, length, packet)  # type: ignore[assignment]
            return self.read(length, **kwargs)
        return super().unpack(length, **kwargs)

    @classmethod
    def read_handshake(cls, message: 'bytes') -> 'Data_DTLSHandshake':
        """Read one handshake message from its own octets, outside any record.

        A message's ``length`` is 24-bit (:rfc:`6347#section-4.2.2`) but a
        record's is 16-bit, so a message reassembled from its fragments may be
        too long for any record to carry to :meth:`read`.

        Args:
            message: The handshake header, fragment header and body.

        Returns:
            The message, decoded as :meth:`read` decodes one in a record.

        Raises:
            ProtocolError: If ``message`` is not exactly one handshake message,
                or its body is malformed for its ``msg_type``.

        """
        # NOTE: a bare instance, for the ``alias`` the shared decoders name in an error.
        self = cls.__new__(cls)
        messages = self._read_tls_handshake_messages(message, dtls=True)
        if len(messages) != 1:
            raise ProtocolError(f'{self.alias}: invalid format: {len(messages)} handshake '
                                'messages where exactly one is expected')
        return cast('Data_DTLSHandshake', messages[0])

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[13]':
        """Return an estimated length for the object."""
        return 13

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_DTLS | Data_DTLSCiphertext') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        if isinstance(data, Data_DTLSCiphertext):
            return {
                'ciphertext': True,
                'epoch': data.epoch,
                'sequence_number': data.sequence_number,
                'sequence_long': data.sequence_long,
                'length_present': data.length is not None,
                'content': data.content,
                'payload': cls._make_payload(data),
            }
        return {
            'content_type': data.content_type,
            'version': data.version,
            'epoch': data.epoch,
            'sequence_number': data.sequence_number,
            'content': data.content,
            'payload': cls._make_payload(data),
        }

    def _read_dtls_record(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS | Data_DTLSCiphertext':  # pylint: disable=unused-argument
        """Read a DTLS record, identifying its concrete tier as it goes.

        A unified-header record is handed to :meth:`_read_dtls_ciphertext`.

        Structure of DTLS record layer [:rfc:`9147#section-4`]:

        .. code-block:: text

           struct {
               ContentType type;
               ProtocolVersion legacy_record_version;
               uint16 epoch = 0;
               uint48 sequence_number;
               uint16 length;
               opaque fragment[DTLSPlaintext.length];
           } DTLSPlaintext;

        The legacy version names the tier, except that DTLS 1.3 reuses
        ``0xFEFD`` (or ``0xFEFF`` on an initial ``ClientHello``) and is found
        by peeking ``supported_versions`` (:meth:`SSL._tls_negotiates
        <pcapkit.protocols.application.ssl.SSL._tls_negotiates>`). An unknown
        ``0xFExx`` keeps the generic ``'DTLS'`` alias.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the record header cannot be a genuine DTLS
                record -- an unrecognised content type, a legacy version
                outside DTLS's range, or a declared ``length`` that runs past
                the end of the buffer -- or if the record fragment is
                malformed for its content type.

        """
        if isinstance(self.__header__, Schema_DTLSCiphertext):
            return self._read_dtls_ciphertext(length, **kwargs)

        schema = self.__header__
        available = length if length is not None else len(self)
        self._validate_tls_record(schema, available=available, dtls=True)

        # NOTE: DTLS 1.3 is checked first, at 0xFEFF too: an initial ClientHello may carry
        # {254, 255} (RFC 9147, section 4). Unknown versions keep the generic alias.
        if schema.version in _DTLS13_LEGACY_VERSIONS and self._tls_negotiates(schema, DTLS13_VERSION, dtls=True):
            self._alias = 'DTLS 1.3'
        elif schema.version == _DTLSV1_0_VERSION:
            self._alias = 'DTLS 1.0'
        elif schema.version == _DTLSV1_2_VERSION:
            self._alias = 'DTLS 1.2'
        else:
            self._alias = 'DTLS'

        content = self._read_tls_content(schema.content_type, schema.fragment,
                                         dtls=True, epoch=schema.epoch)
        dtls = Data_DTLS(
            content_type=schema.content_type,
            version=schema.version,
            epoch=schema.epoch,
            sequence_number=schema.sequence_number,
            length=schema.length,
            content=content,
        )

        remaining = available - (self.length + schema.length)
        return self._decode_next_layer(dtls, -1, remaining)

    def _read_dtls_ciphertext(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLSCiphertext':  # pylint: disable=unused-argument
        """Read a unified-header ciphertext record (:rfc:`9147#section-4.1`).

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the header carries a connection ID, whose length
                is negotiated and not in the record; if the header or its
                declared length runs past the buffer; or if the ciphertext is
                shorter than the record-number sample (:rfc:`9147#section-4.2.3`).

        """
        self._alias = 'DTLS 1.3'
        schema = self.__header__
        flags = schema.flags
        available = length if length is not None else len(self)

        if flags['connection_id']:
            raise ProtocolError(f'{self.alias}: invalid format: connection ID records are not decoded')
        needed = self.length + (schema.length or 0)
        if needed > available:
            raise ProtocolError(f'{self.alias}: invalid format: record of {needed} octets '
                                'runs past the end of the buffer')
        # Receivers MUST reject shorter records as if they failed deprotection.
        if len(schema.fragment or b'') < _CIPHERTEXT_MIN_LENGTH:
            raise ProtocolError(f'{self.alias}: invalid format: ciphertext is shorter than the '
                                'record-number sample (RFC 9147 section 4.2.3)')

        dtls = Data_DTLSCiphertext(
            epoch=flags['epoch'],
            sequence_number=schema.sequence_number,
            sequence_long=bool(flags['sequence_long']),
            length=schema.length,
            content=schema.fragment,
        )
        remaining = available - (self.length + len(schema.fragment))
        return self._decode_next_layer(dtls, -1, remaining)
