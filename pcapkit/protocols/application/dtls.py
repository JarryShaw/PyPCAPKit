# -*- coding: utf-8 -*-
"""DTLS - Datagram Transport Layer Security
==============================================

.. module:: pcapkit.protocols.application.dtls

:mod:`pcapkit.protocols.application.dtls` contains
:class:`~pcapkit.protocols.application.dtls.DTLS` only, which implements an
extractor for the DTLS record-layer family -- DTLS 1.0 (:rfc:`4347`), DTLS
1.2 (:rfc:`6347`), and DTLS 1.3's legacy-format records (:rfc:`9147`). The
epoch and sequence number in the record header, which set DTLS apart from
:class:`~pcapkit.protocols.application.tls.TLS`, are declared in
:class:`~pcapkit.protocols.schema.application.dtls.DTLS` and read here; the
handshake-message fragment header is read by the handshake decoding shared
with TLS in :class:`~pcapkit.protocols.application.ssl.SSL`.
:attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>` binds
this class at port 5684; its own :meth:`read` parses the ``DTLSPlaintext``
record header, then sets :attr:`~DTLS.alias` according to
the record's legacy version -- mirroring
:class:`~pcapkit.protocols.link.arp.ARP`'s own dynamic dispatch over
RARP/DRARP/InARP by operation code, and
:class:`~pcapkit.protocols.application.tls.TLS`'s own dispatch over its
family.

Known Limitations
-----------------

**A handshake message split across several DTLS records is not reassembled.**
DTLS fragments a handshake message when it does not fit in one datagram
(:rfc:`6347#section-4.2.3`); reassembling that would need
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` keyed on the
UDP 5-tuple plus epoch (:issue:`2440`). A fragment's
:attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.is_fragmented`
says whether this is the case; such a message's
:attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.body` is kept
as that one fragment's raw octets rather than attempted as a (necessarily
wrong, since only a slice of it is present) decode. An *unfragmented* message
-- ``fragment_offset == 0`` and ``fragment_length == length`` -- decodes
exactly as :class:`~pcapkit.protocols.application.tls.TLS` would, which is
the common case: a ``ClientHello`` or ``ServerHello`` that fits one datagram
never fragments.

**DTLS 1.3's unified record header is not decoded** (:issue:`2467`). DTLS 1.3
sends its cleartext records with the legacy ``DTLSPlaintext`` header this
module reads -- the DTLS 1.2 shape, with ``legacy_record_version`` frozen at
DTLS 1.2's value (:rfc:`9147#section-4`). The *unified header* the same
section defines for encrypted records has no content-type octet, so
:meth:`SSL._validate_tls_record <pcapkit.protocols.application.ssl.SSL._validate_tls_record>`
rejects it -- its first octet is never an accepted content type -- and it
degrades to :class:`~pcapkit.protocols.misc.raw.Raw`.

**Connection ID records are not decoded** (``tls12_cid``, :rfc:`9146`). Their
connection ID precedes ``length``, and its length is negotiated during the
handshake rather than carried in the record, so
:meth:`SSL._validate_tls_record <pcapkit.protocols.application.ssl.SSL._validate_tls_record>`
rejects content type 25 and the record degrades to
:class:`~pcapkit.protocols.misc.raw.Raw`.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.protocols.application.ssl import DTLS13_VERSION, SSL
from pcapkit.protocols.data.application.dtls import DTLS as Data_DTLS
from pcapkit.protocols.schema.application.dtls import DTLS as Schema_DTLS

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

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


class DTLS(SSL[Data_DTLS, Schema_DTLS], schema=Schema_DTLS, data=Data_DTLS):
    """This class implements all protocols in the DTLS record-layer family.

    - Datagram Transport Layer Security 1.0 [:rfc:`4347`]
    - Datagram Transport Layer Security 1.2 [:rfc:`6347`]
    - Datagram Transport Layer Security 1.3, legacy-format records only [:rfc:`9147`]

    Note:
        The subpackage does not track the dispatch tier: DTLS is dispatched
        from :attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>`
        at port 5684, the ``coaps`` (CoAP over DTLS, :rfc:`7252`) service name
        IANA assigns there. It is not the only such port -- IANA registers
        DTLS-borne services at several, among them 853 (``domain-s``), 4740
        (``ipfixs``), 5349 (``stuns``/``turns``), 6514 (``syslog-tls``) and
        10161/10162 (``snmpdtls``) -- so binding 5684 alone is a choice about
        what is common on the wire rather than an exhaustive reading of the
        registry, and plenty of deployments negotiate DTLS on a dynamic port
        no registry can name. Binding another is one
        :func:`pcapkit.foundation.registry.protocols.register_udp` call.

    """

    #: Resolved alias once :meth:`read` has identified the concrete tier --
    #: e.g. ``'DTLS 1.2'``. The class name itself until then, same as the
    #: unversioned default every :class:`~pcapkit.protocols.protocol.ProtocolBase`
    #: falls back to. Mirrors :attr:`ARP._acnm <pcapkit.protocols.link.arp.ARP._acnm>`.
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
    def length(self) -> 'Literal[13]':
        """Header length of current protocol -- the fixed record header,
        :attr:`~pcapkit.protocols.data.application.dtls.DTLS.length`'s
        fragment excluded.

        """
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

        Parses the record and identifies its concrete tier -- DTLS 1.0, DTLS
        1.2, or DTLS 1.3's legacy-format records -- setting :attr:`alias`
        accordingly, mirroring :meth:`TLS.read
        <pcapkit.protocols.application.tls.TLS.read>`'s own dispatch over its
        family.

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
             **kwargs: 'Any') -> 'Schema_DTLS':
        """Make (construct) packet data.

        Shared by every tier in the DTLS family -- DTLS 1.0 through 1.3's
        legacy-format records wrap the identical record header and content
        shapes, so there is nothing version-specific for this to dispatch
        on; the ``version`` argument is simply written through to the
        record's legacy version field.

        Args:
            content_type: Record content type.
            content_type_default: Default value for ``content_type``.
            content_type_namespace: Namespace for ``content_type``.
            content_type_reversed: Reverse namespace for ``content_type``.
            version: Legacy record version (``major << 8 | minor``), e.g.
                ``0xFEFD`` for DTLS 1.2 and (the legacy value DTLS 1.3 keeps
                here) DTLS 1.3.
            epoch: Epoch.
            sequence_number: Sequence number within ``epoch`` (48-bit).
            content: Record content: a :obj:`tuple` of
                :class:`~pcapkit.protocols.data.application.dtls.DTLSHandshake`
                for ``handshake``, an
                :class:`~pcapkit.protocols.data.application.tls.Alert`, a
                :class:`~pcapkit.protocols.data.application.tls.ChangeCipherSpec`,
                or raw :obj:`bytes`, as :meth:`read` would decode it.
            data: Pre-encoded record fragment. When given, it is used
                verbatim in place of ``content`` and ``length`` is computed
                from it.
            payload: Octets after the record, e.g. a further record
                coalesced in the same buffer.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
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
    def _make_data(cls, data: 'Data_DTLS') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'content_type': data.content_type,
            'version': data.version,
            'epoch': data.epoch,
            'sequence_number': data.sequence_number,
            'content': data.content,
            'payload': cls._make_payload(data),
        }

    def _read_dtls_record(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS':  # pylint: disable=unused-argument
        """Read a DTLS record, identifying its concrete tier as it goes.

        Structure of DTLS record layer, the ``DTLSPlaintext`` form
        [:rfc:`9147#section-4`] -- the full header this module reads;
        ``DTLSCiphertext``, defined in that same section, is instead the
        on-the-wire *compact* header an encrypted record may use once epoch 0
        has passed, which this module does not decode:

        .. code-block:: text

           struct {
               ContentType type;
               ProtocolVersion legacy_record_version;
               uint16 epoch = 0;
               uint48 sequence_number;
               uint16 length;
               opaque fragment[DTLSPlaintext.length];
           } DTLSPlaintext;

        Parses the record first, then identifies the concrete tier from its
        legacy version and sets :attr:`alias` accordingly -- mirroring
        :meth:`ARP.read <pcapkit.protocols.link.arp.ARP.read>`'s own
        ``self._acnm = ...`` dispatch by operation code. DTLS 1.3's
        legacy-format records freeze theirs at DTLS 1.2's value -- or DTLS
        1.0's on an initial ``ClientHello`` (:rfc:`9147#section-4`) -- and
        are told apart by peeking the ``supported_versions`` extension
        (:meth:`SSL._tls_negotiates <pcapkit.protocols.application.ssl.SSL._tls_negotiates>`).
        Otherwise DTLS 1.0 (``0xFEFF``) and DTLS 1.2 (``0xFEFD``) are named
        directly by the record's legacy version, and any other ``0xFExx``
        value keeps the generic ``'DTLS'`` alias rather than claiming a tier.
        A legacy version outside ``0xFExx`` never reaches this
        dispatch at all: :meth:`SSL._validate_tls_record
        <pcapkit.protocols.application.ssl.SSL._validate_tls_record>`, called
        first, already raises for it.

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

        Notes:
            A ``handshake``, ``alert``, or ``change_cipher_spec`` record is
            decoded structurally only at epoch 0, the cleartext initial
            handshake; at any later epoch the same content types carry
            ciphertext, whose octets are kept as-is -- an encrypted
            ``alert`` (including the ``close_notify`` that ends nearly every
            TLS 1.2 connection) is the same shape of problem as an encrypted
            ``handshake``, just one epoch later than the initial flight. See
            :meth:`SSL._tls_content_is_cleartext
            <pcapkit.protocols.application.ssl.SSL._tls_content_is_cleartext>`.

        """
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
