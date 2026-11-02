# -*- coding: utf-8 -*-
"""DTLS - Datagram Transport Layer Security
==============================================

.. module:: pcapkit.protocols.application.dtls

:mod:`pcapkit.protocols.application.dtls` contains
:class:`~pcapkit.protocols.application.dtls.DTLS`, which implements an
extractor for the DTLS record-layer family -- DTLS 1.0 (:rfc:`4347`), DTLS
1.2 (:rfc:`6347`) and its connection-ID records (:rfc:`9146`), and DTLS 1.3's
legacy-format and unified-header records (:rfc:`9147`) -- and
:class:`~pcapkit.protocols.application.dtls.DTLSContext`, which holds the
connection IDs those records carry.
:attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>`
binds it at port 5684. As with :class:`~pcapkit.protocols.application.tls.TLS`,
:meth:`~DTLS.read` sets :attr:`~DTLS.alias` from the record's legacy version,
or to ``DTLS 1.3`` for a unified-header record.

Connection IDs
--------------

A ``tls12_cid`` record carries a connection ID between its sequence number
and its length (:rfc:`9146#section-4`), and the ID's length is negotiated
rather than carried. :class:`DTLSContext` resolves it, in this order:

* a connection ID the record begins with that a ``ClientHello`` or
  ``ServerHello`` ``connection_id`` extension negotiated earlier in the
  capture, each peer naming the one it receives (:rfc:`9146#section-3`);
* the ``cid_length`` the caller gives :class:`DTLSContext`.

Without either the record stays :class:`~pcapkit.protocols.misc.raw.Raw`.
A dissected one reports its epoch, sequence number, connection ID and length,
and keeps its encrypted content as octets. The context reaches DTLS through
:mod:`pcapkit.corekit.context`:

.. code-block:: python

   import pcapkit
   from pcapkit.protocols.application.dtls import DTLSContext

   extraction = pcapkit.extract('dtls.pcap', context=DTLSContext(cid_length=8))

The connection IDs a :class:`DTLSContext` learns belong to that instance. A
new instance starts with none, and one the caller reuses keeps what it has
learned. An extraction given none gets its own in its own registry, so it
carries what its handshakes negotiate across its capture and no further.
A registry passed as ``__context__`` to several parses carries its instance
across them.

A rebuild parses each layer's octets again, so ``from_data`` takes the same
``__context__``. Without it the octets still rebuild exactly, and
``DTLS.from_data`` keeps its chain, but a ``tls12_cid`` record under a
rebuilt UDP layer reads as :class:`~pcapkit.protocols.misc.raw.Raw`.

Records in One Datagram
-----------------------

A whole record after the first in a UDP datagram is dissected as a further
:class:`DTLS` layer, the previous record's payload (:rfc:`6347#section-4.1.1`,
:rfc:`9147#section-4.3`, :issue:`2535`): a ``ChangeCipherSpec`` followed by an
``Alert`` reads ``UDP:DTLS 1.2:DTLS 1.2``. A unified-header record is delimited
by its length; one without a length runs to the end of the datagram, so it is
the last (:rfc:`9147#section-4`). The exceptions:

* A whole record that fails to decode becomes
  :class:`~pcapkit.protocols.misc.raw.Raw` together with everything after it.
* Octets that open no whole record stay raw, with no error: an unsupported
  content type, a legacy version outside ``0xFExx``, a header cut short, a
  length past the end of the datagram, a unified header with a connection
  ID, or a ``tls12_cid`` record whose connection ID is not known, either of
  which leaves the record's end unknown.
* A parse told to stop at DTLS (``protocol='DTLS'`` or ``layer='Application'``)
  keeps the rest of the datagram raw.
* Each record is a layer, so :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`
  bounds how many are dissected.

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
record, so it degrades to :class:`~pcapkit.protocols.misc.raw.Raw`.

**A connection ID negotiated in a fragmented hello is not learned**: the
message is not decoded here, so its ``connection_id`` extension is not read.

**A unified-header record carries only the low two bits of the epoch**, and
its sequence number is header-protected, so the values it reports are the
ones on the wire.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
from pcapkit.corekit.context import ProtocolContext
from pcapkit.corekit.decorators import beholder
from pcapkit.protocols.application.ssl import (_DTLS_VERSION_MAJOR, _WIRE_CONTENT_TYPES,
                                               DTLS13_VERSION, SSL)
from pcapkit.protocols.data.application.dtls import DTLS as Data_DTLS
from pcapkit.protocols.data.application.dtls import DTLSCIDCiphertext as Data_DTLSCIDCiphertext
from pcapkit.protocols.data.application.dtls import DTLSCiphertext as Data_DTLSCiphertext
from pcapkit.protocols.data.application.tls import ConnectionId as Data_ConnectionId
from pcapkit.protocols.schema.application.dtls import DTLS as Schema_DTLS
from pcapkit.protocols.schema.application.dtls import DTLSCIDCiphertext as Schema_DTLSCIDCiphertext
from pcapkit.protocols.schema.application.dtls import DTLSCiphertext as Schema_DTLSCiphertext
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Iterable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.data.application.dtls import DTLSHandshake as Data_DTLSHandshake
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['DTLS', 'DTLSContext']

#: Length of a legacy record header: content type, legacy version, epoch,
#: sequence number and length (:rfc:`9147#section-4`).
_LEGACY_HEADER_LENGTH = 13

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
#: Offset of a ``tls12_cid`` record's connection ID, after its content type,
#: legacy version, epoch and sequence number (:rfc:`9146#section-4`).
_CID_OFFSET = 11
#: Longest connection ID: its length is one octet (:rfc:`9146#section-3`).
_CID_MAX_LENGTH = 255


def _is_cid(value: 'Any') -> 'bool':
    """Whether ``value`` can be a record's connection ID.

    A ``tls12_cid`` record's is one or more octets (:rfc:`9146#section-4`),
    and at most :data:`_CID_MAX_LENGTH`.

    Args:
        value: Candidate connection ID.

    Returns:
        Whether ``value`` is :obj:`bytes` of an allowed length.

    """
    return isinstance(value, bytes) and 1 <= len(value) <= _CID_MAX_LENGTH


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


def _opens_whole_record(data: 'bytes', context: 'Optional[DTLSContext]') -> 'bool':
    """Whether ``data`` opens with a whole DTLS record.

    Only the record header is read. A legacy header gets the checks of
    :meth:`SSL._validate_tls_record
    <pcapkit.protocols.application.ssl.SSL._validate_tls_record>`: a content
    type a genuine record carries, a ``0xFExx`` legacy version, and a fragment
    that ends inside ``data``. A ``tls12_cid`` header needs DTLS 1.2's version
    and a connection ID ``context`` knows the length of. A unified header must
    carry no connection ID, whose negotiated length leaves the record's end
    unknown, and a fragment that ends inside ``data``; without a length it runs
    to the end of ``data``, as the last record of a datagram does
    (:rfc:`9147#section-4`).

    Args:
        data: Octets after a record.
        context: Connection IDs known to the parse, if any.

    Returns:
        Whether a further record opens ``data`` and ends inside it.

    """
    if not data:
        return False
    if _is_unified_header(data[0]):
        # NOTE: the ``C``, ``S`` and ``L`` bits of ``001CSLEE``, as the header schema reads them.
        flags = {'connection_id': data[0] >> 4 & 1, 'sequence_long': data[0] >> 3 & 1,
                 'length_present': data[0] >> 2 & 1}
        header = _ciphertext_header_length(flags)
        if flags['connection_id'] or len(data) < header:
            return False
        if not flags['length_present']:
            return True
    elif data[0] == Enum_ContentType.tls12_cid:
        cid_length = None if context is None else context.match(data[_CID_OFFSET:])
        if cid_length is None or int.from_bytes(data[1:3], 'big') != _DTLSV1_2_VERSION:
            return False
        header = _LEGACY_HEADER_LENGTH + cid_length
        if len(data) < header:
            return False
    else:
        header = _LEGACY_HEADER_LENGTH
        if len(data) < header or data[0] not in _WIRE_CONTENT_TYPES or data[1] != _DTLS_VERSION_MAJOR:
            return False
    # Every header ends with its 16-bit length.
    return header + int.from_bytes(data[header - 2:header], 'big') <= len(data)


class DTLSContext(ProtocolContext):
    """Connection IDs for the :class:`DTLS` records that carry one (:rfc:`9146`).

    A ``tls12_cid`` record does not carry its connection ID's length, so
    :meth:`match` finds it: from the connection IDs registered here, then from
    :attr:`cid_length`. :class:`DTLS` registers those a ``ClientHello`` or
    ``ServerHello`` negotiates, and those of the records a constructed one
    carries as its payload.

    The IDs belong to the instance: a new one starts with none, one reused
    across parses or extractions keeps what it has learned, and nothing is
    kept anywhere else. An extraction given no instance gets its own, in its
    own registry, the first time a hello negotiates an ID.

    Matching by value relies on IDs being self-delineating
    (:rfc:`9146#section-4`): with ``c1c2c3c4`` registered, a record whose ID
    is ``c1c2c3c400010203`` reads as carrying ``c1c2c3c4``.

    Args:
        *connection_ids: Connection IDs known out of band.
        cid_length: Connection ID length of a record that no registered one opens.

    Raises:
        ProtocolError: If a connection ID is not 1 to 255 octets, or
            ``cid_length`` is not an :class:`int` from 1 to 255.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def connection_ids(self) -> 'tuple[bytes, ...]':
        """Registered connection IDs, in the order registered."""
        return tuple(self.__connection_ids__)

    @property
    def cid_length(self) -> 'Optional[int]':
        """Connection ID length of a record that no registered one opens."""
        return self.__cid_length__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def protocol(cls) -> 'tuple[Literal["DTLS"]]':
        """Index ID of the protocol this context applies to."""
        return ('DTLS',)

    def register(self, cid: 'bytes') -> 'None':
        """Add a connection ID; one already registered is left as it is.

        Args:
            cid: Connection ID to add.

        Raises:
            ProtocolError: If ``cid`` is not 1 to 255 octets.

        """
        if not _is_cid(cid):
            raise ProtocolError(f'DTLS: invalid connection ID: {cid!r}')
        if cid not in self.__connection_ids__:
            self.__connection_ids__.append(cid)

    def match(self, octets: 'bytes') -> 'Optional[int]':
        """Find the length of the connection ID that ``octets`` opens with.

        Each registered connection ID that ``octets`` begins with is a
        candidate, longest first, and :attr:`cid_length` comes last. The first
        whose record -- a 16-bit length after the ID, then that many octets --
        ends inside ``octets`` is the answer. Failing that it is the first
        candidate, so that reading the record reports what runs past the end.

        Args:
            octets: A ``tls12_cid`` record from its connection ID on.

        Returns:
            The connection ID's length, or :data:`None` with no candidate.

        """
        candidates = sorted({len(cid) for cid in self.__connection_ids__ if octets.startswith(cid)},
                            reverse=True)
        if self.__cid_length__ is not None:
            candidates.append(self.__cid_length__)
        for length in candidates:
            end = length + 2
            if end + int.from_bytes(octets[length:end], 'big') <= len(octets):
                return length
        return candidates[0] if candidates else None

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, *connection_ids: 'bytes', cid_length: 'Optional[int]' = None) -> 'None':
        if cid_length is not None and (isinstance(cid_length, bool) or not isinstance(cid_length, int)
                                       or not 1 <= cid_length <= _CID_MAX_LENGTH):
            raise ProtocolError(f'DTLS: invalid connection ID length: {cid_length!r}')
        self.__cid_length__ = cid_length  # type: Optional[int]
        self.__connection_ids__ = []  # type: list[bytes]
        for cid in connection_ids:
            self.register(cid)


class DTLS(SSL[Data_DTLS, Schema_DTLS], schema=Schema_DTLS, data=Data_DTLS):
    """This class implements all protocols in the DTLS record-layer family.

    - Datagram Transport Layer Security 1.0 [:rfc:`4347`]
    - Datagram Transport Layer Security 1.2 [:rfc:`6347`], and its connection-ID records [:rfc:`9146`]
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
        fragment excluded. Fixed at 13 octets for a legacy record, and the
        connection ID's length more for a ``tls12_cid`` one; a unified
        header's length follows from its first octet.

        """
        schema = getattr(self, '__header__', None)
        if isinstance(schema, Schema_DTLSCiphertext):
            return _ciphertext_header_length(schema.flags)
        if isinstance(schema, Schema_DTLSCIDCiphertext):
            return _LEGACY_HEADER_LENGTH + len(schema.cid)
        return _LEGACY_HEADER_LENGTH

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
             cid: 'Optional[bytes]' = None,
             **kwargs: 'Any') -> 'Schema_DTLS | Schema_DTLSCiphertext | Schema_DTLSCIDCiphertext':
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
                unified-header or ``tls12_cid`` record, the ciphertext as
                :obj:`bytes`.
            data: Pre-encoded record fragment. When given, it is used
                verbatim in place of ``content`` and ``length`` is computed
                from it.
            payload: Octets after the record, e.g. a further record
                coalesced in the same buffer. The connection IDs of the
                ``tls12_cid`` records a :class:`DTLS` payload carries are
                registered, so that its octets parse again
                (:class:`DTLSContext`).
            ciphertext: Make a unified-header record (:rfc:`9147#section-4.1`)
                instead of a legacy one; ``content_type``, ``version`` and
                ``data`` do not apply.
            sequence_long: Whether a unified-header record's sequence number is
                16 bits rather than 8.
            length_present: Whether a unified-header record carries its length;
                if not, it runs to the end of the datagram.
            cid: Connection ID of a ``tls12_cid`` record (:rfc:`9146#section-4`),
                1 to 255 octets; no other record takes one.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``cid`` is missing or invalid for a ``tls12_cid``
                record, or given for any other.

        """
        self._learn_payload_connection_ids(payload)
        if ciphertext:
            if cid is not None:
                raise ProtocolError(f'{self.alias}: invalid connection ID: only a tls12_cid record carries one')
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
        if int(content_type_) == Enum_ContentType.tls12_cid:
            if cid is None or not _is_cid(cid):
                raise ProtocolError(f'{self.alias}: invalid connection ID: {cid!r} '
                                    '(a tls12_cid record carries 1 to 255 octets)')
            return Schema_DTLSCIDCiphertext(
                content_type=content_type_,
                version=version,
                epoch=epoch,
                sequence_number=sequence_number,
                cid=cid,
                length=len(fragment),
                fragment=fragment,
                payload=payload,
            )
        if cid is not None:
            raise ProtocolError(f'{self.alias}: invalid connection ID: only a tls12_cid record carries one')
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
        :class:`~pcapkit.protocols.schema.application.dtls.DTLSCiphertext`,
        and a ``tls12_cid`` one (:rfc:`9146#section-4`) by
        :class:`~pcapkit.protocols.schema.application.dtls.DTLSCIDCiphertext`
        with the connection ID length :class:`DTLSContext` finds, rather than
        the legacy header; every other record uses the inherited behaviour.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If a ``tls12_cid`` record's connection ID length is
                not known.

        """
        octets = self._data[:1]
        if cast('Optional[Schema_DTLS]', self.__header__) is not None or not octets:
            return super().unpack(length, **kwargs)
        if _is_unified_header(octets[0]):
            packet = kwargs.get('__packet__', {})  # packet data
            self.__header__ = Schema_DTLSCiphertext.unpack(self._file, length, packet)  # type: ignore[call-arg,misc]
            return self.read(length, **kwargs)
        if octets[0] == Enum_ContentType.tls12_cid:
            context = self._get_context(DTLSContext)
            data = self._data if length is None else self._data[:length]
            cid_length = None if context is None else context.match(data[_CID_OFFSET:])
            if cid_length is None:
                raise ProtocolError(f'{self.alias}: invalid format: no connection ID length is known '
                                    'for a tls12_cid record (RFC 9146 section 4)')
            packet = {**kwargs.get('__packet__', {}), '__cid_length__': cid_length}
            self.__header__ = Schema_DTLSCIDCiphertext.unpack(self._file, length, packet)  # type: ignore[call-arg,misc]
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
        return _LEGACY_HEADER_LENGTH  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_DTLS | Data_DTLSCiphertext | Data_DTLSCIDCiphertext') -> 'dict[str, Any]':  # type: ignore[override] # pylint: disable=line-too-long
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        if isinstance(data, Data_DTLSCIDCiphertext):
            return {
                'content_type': data.content_type,
                'version': data.version,
                'epoch': data.epoch,
                'sequence_number': data.sequence_number,
                'cid': data.cid,
                'content': data.content,
                'payload': cls._make_payload(data),
            }
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

    def _read_dtls_record(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS | Data_DTLSCiphertext | Data_DTLSCIDCiphertext':  # pylint: disable=unused-argument,line-too-long
        """Read a DTLS record, identifying its concrete tier as it goes.

        A unified-header record is handed to :meth:`_read_dtls_ciphertext`,
        and a ``tls12_cid`` one to :meth:`_read_dtls_cid_ciphertext`. A
        handshake record registers the connection IDs its hellos negotiate
        before the next record is read (:meth:`_learn_connection_ids`).

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
        if isinstance(self.__header__, Schema_DTLSCIDCiphertext):
            return self._read_dtls_cid_ciphertext(length, **kwargs)

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
        self._learn_connection_ids(content)
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

    def _learn_payload_connection_ids(self, payload: 'Any') -> 'None':
        """Register the connection IDs of the ``tls12_cid`` records in ``payload``.

        A constructed record parses its payload's octets again, which needs
        the connection IDs that the payload's records carry.

        Args:
            payload: Payload given to :meth:`make`.

        """
        cids = []  # type: list[bytes]
        layer = payload
        while isinstance(layer, DTLS):
            if isinstance(layer.info, Data_DTLSCIDCiphertext):
                cids.append(layer.info.cid)
            layer = layer.payload
        self._register_connection_ids(cids)

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

    def _read_dtls_cid_ciphertext(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLSCIDCiphertext':  # pylint: disable=unused-argument,line-too-long
        """Read a DTLS 1.2 record with a connection ID.

        Structure of a ``tls12_cid`` record [:rfc:`9146#section-4`]:

        .. code-block:: text

           struct {
               ContentType outer_type = tls12_cid;
               ProtocolVersion version;
               uint16 epoch;
               uint48 sequence_number;
               opaque cid[cid_length];
               uint16 length;
               opaque enc_content[DTLSCiphertext.length];
           } DTLSCiphertext;

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the legacy version is not DTLS 1.2's, the only
                one ``tls12_cid`` applies to (:rfc:`9146#section-10.3`); if the
                connection ID is empty; or if the record runs past the end of
                the buffer.

        """
        schema = cast('Schema_DTLSCIDCiphertext', self.__header__)
        available = length if length is not None else len(self)

        if schema.version != _DTLSV1_2_VERSION:
            raise ProtocolError(f'{self.alias}: invalid format: legacy record version {schema.version:#06x} '
                                'is not DTLS 1.2, which tls12_cid needs')
        self._alias = 'DTLS 1.2'
        if not _is_cid(schema.cid):
            raise ProtocolError(f'{self.alias}: invalid format: a tls12_cid record carries no connection ID')
        if self.length + schema.length > available:
            raise ProtocolError(f'{self.alias}: invalid format: record length {schema.length} runs past '
                                'the end of the buffer')

        dtls = Data_DTLSCIDCiphertext(
            content_type=schema.content_type,
            version=schema.version,
            epoch=schema.epoch,
            sequence_number=schema.sequence_number,
            cid=schema.cid,
            length=schema.length,
            content=schema.fragment,
        )
        remaining = available - (self.length + schema.length)
        # NOTE: the class is generic in the legacy record's data model, which this one is not.
        return cast('Data_DTLSCIDCiphertext', self._decode_next_layer(cast('Data_DTLS', dtls), -1, remaining))

    def _learn_connection_ids(self, content: 'Any') -> 'None':
        """Register the connection IDs the hellos in ``content`` negotiate.

        Each peer's ``connection_id`` extension names the connection ID it
        receives, and an empty one asks for none (:rfc:`9146#section-3`).

        Args:
            content: Decoded record content.

        """
        if not isinstance(content, tuple):
            return
        self._register_connection_ids(
            extension.data.cid
            for message in content
            for extension in getattr(getattr(message, 'body', None), 'extensions', None) or ()
            if extension.type == Enum_ExtensionType.connection_id and isinstance(extension.data, Data_ConnectionId)
        )

    def _register_connection_ids(self, cids: 'Iterable[bytes]') -> 'None':
        """Register ``cids`` with the parse's :class:`DTLSContext`, adding one if it has none.

        Args:
            cids: Connection IDs; any a ``tls12_cid`` record cannot carry are skipped.

        """
        registry = self._exctx
        valid = [cid for cid in cids if _is_cid(cid)]
        if not valid or registry is None:
            return
        context = registry.match(self.id(), DTLSContext)
        if context is None:
            if any(name in registry for name in self.id()):
                return  # a context of another type holds the name
            context = DTLSContext()
            registry.register(context)
        for cid in valid:
            context.register(cid)

    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[override]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor: a further whole record, or the rest undissected.

        A UDP datagram may carry several records (:rfc:`9147#section-4.3`,
        :issue:`2535`). So the ``-1`` remainder is dissected as this class when
        :func:`_opens_whole_record` finds a whole record opening it, and is
        otherwise kept as :class:`~pcapkit.protocols.misc.raw.Raw`, as
        :meth:`Application._import_next_layer
        <pcapkit.protocols.application.application.Application._import_next_layer>`
        keeps it.

        Arguments:
            proto: next layer protocol index; only the ``-1`` sentinel
                (the rest of the datagram) is accepted
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of this class for a further record, or as
            :meth:`Application._import_next_layer
            <pcapkit.protocols.application.application.Application._import_next_layer>`
            returns otherwise.

        """
        if (proto == -1 and not self._sigterm
                and _opens_whole_record(self._get_payload()[:length], self._get_context(DTLSContext))):
            return self._import_next_record(proto, length, packet=packet)  # type: ignore[misc,call-arg]
        return super()._import_next_layer(proto, length, packet=packet)

    @beholder  # type: ignore[arg-type]
    def _import_next_record(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[misc]
                            packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import the further record :meth:`_import_next_layer` found.

        Arguments:
            proto: next layer protocol index, the ``-1`` sentinel
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of this class, or of :class:`~pcapkit.protocols.misc.raw.Raw`
            when :func:`~pcapkit.corekit.decorators.beholder` replaces a record
            that fails to parse.

        """
        file_ = self._get_payload()
        return self._parse_next_layer(type(self), file_, len(file_) if length is None else length,
                                      alias=proto, packet=packet, layer=self._exlayer,
                                      protocol=self._exproto, __context__=self._exctx)
