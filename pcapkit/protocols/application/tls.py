# -*- coding: utf-8 -*-
"""TLS/SSL - Transport Layer Security
========================================

.. module:: pcapkit.protocols.application.tls

:mod:`pcapkit.protocols.application.tls` contains
:class:`~pcapkit.protocols.application.tls.TLS` and
:class:`~pcapkit.protocols.application.tls.SSLv3`,
which implement an extractor for the TLS/SSLv3+ record-layer family --
SSLv3, TLS 1.0, TLS 1.1, TLS 1.2 (:rfc:`5246`) and TLS 1.3 (:rfc:`9846`,
which obsoletes :rfc:`5077`, :rfc:`5246`, :rfc:`6961`, :rfc:`7627`,
:rfc:`8422` and :rfc:`8446`). :attr:`TCP.__proto__
<pcapkit.protocols.transport.tcp.TCP.__proto__>` binds :class:`TLS` at port
443. Every tier shares one record header, so :meth:`~TLS.read` sets
:attr:`~TLS.alias` (and, for SSLv3, :attr:`~TLS.name`) from the record's
legacy version, as :class:`~pcapkit.protocols.link.arp.ARP` does by
operation code, rather than dispatching to per-version classes.

Decoded Fields
--------------

* The record header, always: it is never encrypted.
* A **cleartext** ``handshake``, ``alert`` or ``change_cipher_spec`` record
  (:meth:`SSL._tls_content_is_cleartext <pcapkit.protocols.application.ssl.SSL._tls_content_is_cleartext>`
  decides which are):

  * ``ClientHello``/``ServerHello`` down to their cipher suites, compression
    methods and extensions (type and length only).
  * Every other handshake message at type and length only.
  * ``Alert`` and ``ChangeCipherSpec`` in full.

* Everything else -- the same types once encrypted, ``application_data``
  and every other content type -- as opaque :obj:`bytes`.

Records in One Segment
----------------------

Every whole record in a TCP segment is dissected, each as a :class:`TLS`
layer whose payload is the next record (:issue:`2517`): a ``ServerHello``
followed by a ``ChangeCipherSpec`` reads ``TCP:TLS 1.3:TLS 1.2``. Each record
is a layer, so :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT` bounds how
many are dissected.

Known Limitation
----------------

**A record split across two TCP segments is not reassembled**, and decodes as
:class:`~pcapkit.protocols.misc.raw.Raw`, as does the partial record a segment
ends inside. A record may be up to 16 KiB against a typical 1460-octet MSS, so
this is routine.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.corekit.decorators import _beholding, beholder
from pcapkit.protocols.application.ssl import (_TLS_VERSION_MAJOR, _WIRE_CONTENT_TYPES, SSL,
                                               TLS13_VERSION)
from pcapkit.protocols.application.sslv2 import SSLv2
from pcapkit.protocols.data.application.sslv2 import ClientHello as SSLv2_ClientHello
from pcapkit.protocols.data.application.sslv2 import ServerHello as SSLv2_ServerHello
from pcapkit.protocols.data.application.sslv2 import SSLv2 as SSLv2_Data
from pcapkit.protocols.data.application.tls import TLS as Data_TLS
from pcapkit.protocols.schema.application.tls import TLS as Schema_TLS
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import hold_warnings

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional
    from typing import Type as _Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['TLS', 'SSLv3']

#: Legacy record version SSLv3 carries, the one tier with its own :attr:`~TLS.name`.
_SSLV3_VERSION = 0x0300

#: Legacy record version to alias. TLS 1.3 reuses ``0x0303``; see
#: :data:`_TLS13_LEGACY_VERSIONS`.
_TLS_VERSION_ALIASES = {
    _SSLV3_VERSION: 'SSLv3',
    0x0301: 'TLS 1.0',
    0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2',
}  # type: dict[int, Literal["SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2"]]

#: Legacy record versions a TLS 1.3 record may carry: ``0x0303`` always, and
#: ``0x0301`` on an initial ``ClientHello`` (:rfc:`9846#section-5.1`).
_TLS13_LEGACY_VERSIONS = frozenset({0x0301, 0x0303})


def _opens_whole_record(data: 'bytes') -> 'bool':
    """Whether ``data`` opens with a whole TLS record.

    Only the record header is read, against the same checks as
    :meth:`SSL._validate_tls_record
    <pcapkit.protocols.application.ssl.SSL._validate_tls_record>`: a content
    type a genuine record carries, a ``0x03xx`` legacy version, and a fragment
    that ends inside ``data``.

    Args:
        data: Octets after a record.

    Returns:
        Whether a further record opens ``data`` and ends inside it.

    """
    if len(data) < 5:
        return False
    return (data[0] in _WIRE_CONTENT_TYPES and data[1] == _TLS_VERSION_MAJOR
            and 5 + int.from_bytes(data[3:5], 'big') <= len(data))


class TLS(SSL[Data_TLS, Schema_TLS], schema=Schema_TLS, data=Data_TLS):
    """This class implements all protocols in the TLS/SSLv3+ record-layer family.

    - Secure Sockets Layer version 3 (:class:`SSLv3`)
    - Transport Layer Security 1.0 [:rfc:`2246`]
    - Transport Layer Security 1.1 [:rfc:`4346`]
    - Transport Layer Security 1.2 [:rfc:`5246`]
    - Transport Layer Security 1.3 [:rfc:`9846`]

    Note:
        The subpackage does not track the dispatch tier: TLS is dispatched
        from :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>`
        at port 443, the ``https`` service name IANA assigns there. See
        :func:`pcapkit.foundation.registry.protocols.register_tcp`.

    """

    #: Name of corresponding protocol; only SSLv3 has a different one.
    _name = 'Transport Layer Security'  # type: Literal["Transport Layer Security", "Secure Sockets Layer version 3"]  # pylint: disable=line-too-long

    #: Tier :meth:`read` identified, e.g. ``'TLS 1.2'``; ``'TLS'`` until then.
    _alias = 'TLS'  # type: Literal["TLS", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]

    #: Header length of the SSLv2 record :meth:`unpack` adopted; ``None`` for TLS's own.
    _adopted_length = None  # type: Optional[int]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Transport Layer Security", "Secure Sockets Layer version 3"]':
        """Name of current protocol."""
        return self._name

    @property
    def alias(self) -> 'Literal["TLS", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]':
        """Acronym of current protocol -- the concrete tier :meth:`read` identified."""
        return self._alias

    @property
    def length(self) -> 'int':
        """Header length of current protocol -- the fixed record header,
        :attr:`~pcapkit.protocols.data.application.tls.TLS.length`'s fragment
        excluded; or, once :meth:`unpack` has adopted an SSLv2 record, that
        record's own 2- or 3-octet header.

        """
        if self._adopted_length is not None:
            return self._adopted_length
        return 5

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["TLS"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol. Fixed whatever tier :meth:`read`
            identifies, so a lookup by ID matches every record; inspect
            :attr:`alias` for the tier.

        """
        return ('TLS',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TLS':
        """Read Transport Layer Security (TLS).

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the payload is not a TLS record (see
                :meth:`_read_tls_record`), which :meth:`unpack` then offers
                to :class:`~pcapkit.protocols.application.sslv2.SSLv2`.

        """
        if length is None:
            length = len(self)
        return self._read_tls_record(length, **kwargs)

    def make(self,
             content_type: 'Enum_ContentType | StdlibEnum | AenumEnum | str | int' = Enum_ContentType.application_data,  # pylint: disable=line-too-long
             content_type_default: 'Optional[int]' = None,
             content_type_namespace: 'Optional[dict[str, int] | dict[int, str] | _Type[StdlibEnum] | _Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             content_type_reversed: 'bool' = False,
             version: 'int' = 0x0303,
             content: 'Any' = b'',
             data: 'Optional[bytes]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_TLS':
        """Make (construct) packet data, for every tier: ``version`` is written as is.

        Args:
            content_type: Record content type.
            content_type_default: Default value for ``content_type``.
            content_type_namespace: Namespace for ``content_type``.
            content_type_reversed: Reverse namespace for ``content_type``.
            version: Legacy record version (``major << 8 | minor``), e.g.
                ``0x0303`` for TLS 1.2 and (the legacy value TLS 1.3 keeps
                here) TLS 1.3.
            content: Record content: a :obj:`tuple` of
                :class:`~pcapkit.protocols.data.application.tls.Handshake`
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

        fragment = data if data is not None else self._make_tls_content(content_type_, content, dtls=False)
        return Schema_TLS(
            content_type=content_type_,
            version=version,
            length=len(fragment),
            fragment=fragment,
            payload=payload,
        )

    def unpack(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Any':
        """Unpack (parse) packet data: TLS, or the SSLv2 record port 443 may carry.

        TLS is tried first: the record header and :meth:`read`. Only when
        that trial rejects the record is the payload offered to
        :class:`~pcapkit.protocols.application.sslv2.SSLv2`, whose own header
        checks are strict, so a genuine TLS record is never taken as SSLv2.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the payload is neither a TLS record (see
                :meth:`_read_tls_record`) nor an SSLv2 record.

        Note:
            The TLS trial's warnings are held back
            (:class:`~pcapkit.utilities.warnings.hold_warnings`) and dropped
            when SSLv2 parses the record, since they describe a TLS record the
            result does not have -- ``packet length < 0`` for an SSLv2
            CLIENT-HELLO advertising ``0x0301`` (:issue:`2525`). The SSLv2
            trial's are dropped when it fails. When both fail, the TLS
            trial's are handled as :meth:`Protocol._parse_next_layer
            <pcapkit.protocols.protocol.Protocol._parse_next_layer>` handles a
            raising one: dropped under :func:`~pcapkit.corekit.decorators.beholder`,
            which replaces the layer, and reported as the error leaves outside
            it (:issue:`2308`).

        """
        with hold_warnings() as trial:
            try:
                return super().unpack(length, **kwargs)
            except ProtocolError:
                trial.discard = True
                with hold_warnings() as fallback:
                    parsed = self._read_sslv2_fallback(len(self) if length is None else length, **kwargs)
                    fallback.discard = parsed is None
                if parsed is None:
                    trial.discard = _beholding.get()
                    raise
                return parsed

    @classmethod
    def from_data(cls, data: 'Any', **kwargs: 'Any') -> 'Any':
        """Create protocol instance from data.

        An SSLv2 record that :meth:`unpack` adopted from port 443 is rebuilt as
        the SSLv2 record it was parsed from, since TLS's record layout cannot
        carry its 2- or 3-octet header.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance: an :class:`~pcapkit.protocols.application.sslv2.SSLv2`
            for an SSLv2 record, otherwise a TLS instance.

        """
        if isinstance(data, SSLv2_Data):
            return SSLv2.from_data(data, **kwargs)
        return super().from_data(data, **kwargs)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[5]':
        """Return an estimated length for the object."""
        return 5

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_TLS') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'content_type': data.content_type,
            'version': data.version,
            'content': data.content,
            'payload': cls._make_payload(data),
        }

    def _read_tls_record(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TLS':  # pylint: disable=unused-argument
        """Read a TLS/SSLv3+ record, identifying its concrete tier as it goes.

        Structure of TLS record layer [:rfc:`9846#section-5.1`]:

        .. code-block:: text

           struct {
               ContentType type;
               ProtocolVersion legacy_record_version;
               uint16 length;
               opaque fragment[TLSPlaintext.length];
           } TLSPlaintext;

        The legacy version names the tier, except that TLS 1.3 reuses
        ``0x0303`` (or ``0x0301`` on an initial ``ClientHello``) and is found
        by peeking ``supported_versions`` (:meth:`SSL._tls_negotiates
        <pcapkit.protocols.application.ssl.SSL._tls_negotiates>`). An unknown
        ``0x03xx`` keeps the generic ``'TLS'`` alias.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the record header cannot be a genuine TLS
                record -- an unrecognised content type, a legacy version
                outside TLS's range, or a declared ``length`` that runs past
                the end of the buffer -- or if the record fragment is
                malformed for its content type.

        """
        schema = self.__header__
        available = length if length is not None else len(self)
        self._validate_tls_record(schema, available=available, dtls=False)

        # NOTE: TLS 1.3 is checked first, at 0x0301 too: an initial ClientHello may carry
        # 0x0301 (RFC 9846, section 5.1). Unknown versions keep the generic alias.
        self._name = 'Transport Layer Security'
        if schema.version in _TLS13_LEGACY_VERSIONS and self._tls_negotiates(schema, TLS13_VERSION, dtls=False):
            self._alias = 'TLS 1.3'
        elif schema.version in _TLS_VERSION_ALIASES:
            self._alias = _TLS_VERSION_ALIASES[schema.version]
            if schema.version == _SSLV3_VERSION:
                self._name = 'Secure Sockets Layer version 3'
        else:
            self._alias = 'TLS'

        content = self._read_tls_content(schema.content_type, schema.fragment, dtls=False)
        tls = Data_TLS(
            content_type=schema.content_type,
            version=schema.version,
            length=schema.length,
            content=content,
        )

        remaining = available - (self.length + schema.length)
        return self._decode_next_layer(tls, -1, remaining)

    def _read_sslv2_fallback(self, length: 'int', **kwargs: 'Any') -> 'Optional[Any]':
        """Parse the payload as SSLv2 once TLS has rejected it.

        Only a complete CLIENT-HELLO or SERVER-HELLO is accepted: the whole
        record must sit in this segment, and its body must pass the hello
        length probe. Anything else stays :class:`~pcapkit.protocols.misc.raw.Raw`.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            The SSLv2 data model, adopted as this dispatcher's own, or
            :data:`None` if the payload is not a complete SSLv2 hello.

        """
        try:
            obj = SSLv2(self._data, length, **kwargs)
        except ProtocolError:
            return None
        info = obj.info
        if info.header_len + info.record_length > length:
            return None
        if not isinstance(info.body, (SSLv2_ClientHello, SSLv2_ServerHello)):
            return None
        return self._adopt_dispatched(obj)

    def _adopt_dispatched(self, obj: 'Any') -> 'Any':
        """Adopt the SSLv2 parse, including its 2- or 3-octet header length.

        :attr:`length` and :attr:`packet` must describe the header the record
        really has, as a direct SSLv2 parse does.

        Args:
            obj: The SSLv2 instance, already parsed.

        Returns:
            ``obj``'s parsed data model, as :meth:`SSL._adopt_dispatched` returns it.

        """
        self._adopted_length = obj.length  # pylint: disable=attribute-defined-outside-init
        return super()._adopt_dispatched(obj)

    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[override]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor: a further whole record, or the rest undissected.

        A TCP segment may carry several records (:issue:`2517`). So the ``-1``
        remainder is dissected as this class when :func:`_opens_whole_record`
        finds a whole record opening it, and is otherwise kept as
        :class:`~pcapkit.protocols.misc.raw.Raw`, as
        :meth:`Application._import_next_layer
        <pcapkit.protocols.application.application.Application._import_next_layer>`
        keeps it. A partial record, which the segment ends inside, is the
        reassembly limit, and stays raw.

        Arguments:
            proto: next layer protocol index; only the ``-1`` sentinel
                (the rest of the segment) is accepted
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of this class for a further record, or as
            :meth:`Application._import_next_layer
            <pcapkit.protocols.application.application.Application._import_next_layer>`
            returns otherwise.

        """
        if proto == -1 and not self._sigterm and _opens_whole_record(self._get_payload()[:length]):
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



class SSLv3(TLS, schema=Schema_TLS, data=Data_TLS):
    """This class implements Secure Sockets Layer version 3.

    Dispatch never constructs it: an SSLv3 record parses as :class:`TLS` with
    :attr:`~TLS.alias` ``'SSLv3'``. Like :class:`~pcapkit.protocols.link.arp.InARP`
    to :class:`~pcapkit.protocols.link.arp.ARP`, it narrows :meth:`id` only.

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["SSLv3"]]':  # type: ignore[override]
        """Index ID of the protocol."""
        return ('SSLv3',)
