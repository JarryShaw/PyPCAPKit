# -*- coding: utf-8 -*-
"""DTLS - Datagram Transport Layer Security
==============================================

.. module:: pcapkit.protocols.application.dtls

:mod:`pcapkit.protocols.application.dtls` contains
:class:`~pcapkit.protocols.application.dtls.DTLS`, which is a version
dispatcher for the DTLS record-layer family -- DTLS 1.0 (:rfc:`4347`), DTLS
1.2 (:rfc:`6347`), and DTLS 1.3's legacy-format records (:rfc:`9147`) -- the
epoch/sequence-number fields and the handshake-message fragment header that
set the family apart from :class:`~pcapkit.protocols.application.tls.TLS`,
whose reliable, ordered transport needs neither, stay shared across all
three tiers via :class:`~pcapkit.protocols.application.ssl.SSL`.
:attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>` binds
this class at port 5684; its own :meth:`read` identifies the concrete tier
and delegates to it, rather than parsing content itself -- the same shape
:class:`~pcapkit.protocols.application.tls.TLS` uses for its own family.

Known Limitation
-----------------

**A handshake message split across several DTLS records is not reassembled.**
DTLS fragments a handshake message when it does not fit in one datagram
(:rfc:`6347#section-4.2.3`); reassembling that would need
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` keyed on the
UDP 5-tuple plus epoch, which is substantial enough that it did not fit
cleanly alongside this dissector in the same PR (:issue:`2437`; see the
follow-up issue it links for exactly what is missing). A fragment's
:attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.is_fragmented`
says whether this is the case; such a message's
:attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.body` is kept
as that one fragment's raw octets rather than attempted as a (necessarily
wrong, since only a slice of it is present) decode. An *unfragmented* message
-- ``fragment_offset == 0`` and ``fragment_length == length`` -- decodes
exactly as :class:`~pcapkit.protocols.application.tls.TLS` would, which is
the common case: a ``ClientHello`` or ``ServerHello`` that fits one datagram
never fragments.

**DTLS 1.3's unified record header is not decoded** (:issue:`2467`, which
depends on this PR landing first). DTLS 1.3 records before the handshake
completes still use the legacy ``DTLSPlaintext`` header this module reads --
the same shape DTLS 1.2 uses, with ``legacy_record_version`` frozen at DTLS
1.2's value (:rfc:`9147#section-4.1`) -- so :class:`DTLSv1_3
<pcapkit.protocols.application.dtlsv1_3.DTLSv1_3>` decodes exactly that
traffic. The *unified header* :rfc:`9147#section-4` introduces for records
once a connection has a negotiated epoch has no content-type byte at all, so
:meth:`SSL._validate_tls_record <pcapkit.protocols.application.ssl.SSL._validate_tls_record>`
rejects it outright -- its first octet never falls inside the assigned
content-type range this module checks -- and it degrades to
:class:`~pcapkit.protocols.misc.raw.Raw`, which is the honest answer until
that follow-up lands.

.. versionadded:: 1.6.0

.. versionchanged:: 1.6.0

   :class:`DTLS` is now a version dispatcher rather than a single generic
   parser: it identifies DTLS 1.0, DTLS 1.2, or DTLS 1.3's legacy-format
   records and delegates to the matching concrete class --
   :mod:`~pcapkit.protocols.application.dtlsv1_0`,
   :mod:`~pcapkit.protocols.application.dtlsv1_2`, or
   :mod:`~pcapkit.protocols.application.dtlsv1_3` -- the same shape
   :class:`~pcapkit.protocols.application.tls.TLS` already uses for its own
   family (:issue:`2437`).

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.protocols.application.ssl import DTLS13_VERSION, SSL
from pcapkit.protocols.data.application.dtls import DTLS as Data_DTLS
from pcapkit.protocols.schema.application.dtls import DTLS as Schema_DTLS

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional
    from typing import Type as _Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['DTLS']

#: Legacy record version DTLS 1.0 carries (:rfc:`4347#section-4.1`).
_DTLSV1_0_VERSION = 0xFEFF
#: Legacy record version DTLS 1.2 carries, and the value DTLS 1.3 freezes its
#: own legacy-format records at (:rfc:`9147#section-4.1`).
_DTLSV1_2_VERSION = 0xFEFD


class DTLS(SSL[Data_DTLS, Schema_DTLS], schema=Schema_DTLS, data=Data_DTLS):
    """This class implements Datagram Transport Layer Security.

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
    #: e.g. ``'DTLS 1.2'`` -- mirroring
    #: :attr:`TLS._alias <pcapkit.protocols.application.tls.TLS._alias>`.
    _alias = 'DTLS'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Datagram Transport Layer Security"]':
        """Name of current protocol."""
        return 'Datagram Transport Layer Security'

    @property
    def alias(self) -> 'str':
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
    def id(cls) -> 'tuple[Literal["DTLS"], Literal["DTLSv1_0"], Literal["DTLSv1_2"], Literal["DTLSv1_3"]]':  # type: ignore[override] # pylint: disable=line-too-long
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol -- the canonical name first, then every
            concrete tier this dispatcher may delegate to.

        """
        return ('DTLS', 'DTLSv1_0', 'DTLSv1_2', 'DTLSv1_3')

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Any':
        """Read Datagram Transport Layer Security (DTLS).

        Identifies the concrete tier -- DTLS 1.0, DTLS 1.2, or DTLS 1.3's
        legacy-format records -- and delegates to it, mirroring
        :meth:`TLS.read <pcapkit.protocols.application.tls.TLS.read>`'s own
        dispatch over its family.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data, from whichever concrete tier :meth:`_guess_version`
            identified.

        Raises:
            ProtocolError: If the identified tier's own parse fails -- see
                :meth:`_read_dtls_record`, shared by every tier.

        """
        if length is None:
            length = len(self)

        obj = self._guess_version(length, **kwargs)
        return self._adopt_dispatched(obj)

    def make(self,
             content_type: 'Enum_ContentType | StdlibEnum | AenumEnum | str | int' = Enum_ContentType.application_data,  # pylint: disable=line-too-long
             content_type_default: 'Optional[int]' = None,
             content_type_namespace: 'Optional[dict[str, int] | dict[int, str] | _Type[StdlibEnum] | _Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
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

    def _guess_version(self, length: 'int', **kwargs: 'Any') -> 'Any':
        """Identify the concrete tier of the payload, and parse it as that tier.

        DTLS 1.0 and DTLS 1.2 are named directly by the record's legacy
        version. DTLS 1.3's legacy-format records freeze theirs at DTLS
        1.2's value, and are told apart by peeking the
        ``supported_versions`` extension (:meth:`SSL._tls_negotiates
        <pcapkit.protocols.application.ssl.SSL._tls_negotiates>`), falling
        back to DTLS 1.2 -- the common case -- when that peek is
        inconclusive. Any legacy version naming neither falls back to the
        DTLS 1.2 tier too, so that its own :meth:`SSL._validate_tls_record
        <pcapkit.protocols.application.ssl.SSL._validate_tls_record>` reports
        the real reason the payload is not a genuine record.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data from whichever concrete tier was identified.

        """
        from pcapkit.protocols.application.dtlsv1_0 import DTLSv1_0  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.application.dtlsv1_2 import DTLSv1_2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.application.dtlsv1_3 import DTLSv1_3  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel

        schema = self.__header__

        protocol: '_Type[DTLS]' = DTLSv1_2
        if schema.version == _DTLSV1_0_VERSION:
            protocol = DTLSv1_0
        elif schema.version == _DTLSV1_2_VERSION and self._tls_negotiates(schema, DTLS13_VERSION, dtls=True):
            protocol = DTLSv1_3
        return protocol(self._data, length, **kwargs)

    def _read_dtls_record(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS':  # pylint: disable=unused-argument
        """Read a DTLS record -- the real parse every concrete tier shares.

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
