# -*- coding: utf-8 -*-
"""TLS/SSL - Transport Layer Security
========================================

.. module:: pcapkit.protocols.application.tls.protocol

:mod:`pcapkit.protocols.application.tls.protocol` holds
:class:`~pcapkit.protocols.application.tls.protocol.TLS`, the extractor for the
TLS/SSLv3+ record-layer family --
SSLv3, TLS 1.0, TLS 1.1, TLS 1.2 (:rfc:`5246`) and TLS 1.3 (:rfc:`9846`,
which obsoletes :rfc:`5077`, :rfc:`5246`, :rfc:`6961`, :rfc:`7627`,
:rfc:`8422` and :rfc:`8446`). :attr:`TCP.__proto__
<pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>` binds :class:`TLS` at port
443. Every tier shares one record header, so :meth:`~TLS.read` sets
:attr:`~TLS.alias` (and, for SSLv3, :attr:`~TLS.name`) from the record's
legacy version, as :class:`~pcapkit.protocols.link.arp.protocol.ARP` does by
operation code, rather than dispatching to per-version classes.

Decoded Fields
--------------

* The record header, always: it is never encrypted.
* A **cleartext** ``handshake``, ``alert`` or ``change_cipher_spec`` record
  (:meth:`SSL._tls_content_is_cleartext <pcapkit.protocols.application.ssl.protocol.SSL._tls_content_is_cleartext>`
  decides which are):

  * ``ClientHello``/``ServerHello`` down to their cipher suites, compression
    methods and extensions, and ``EncryptedExtensions`` down to its
    extensions; an extension's body decodes where
    :attr:`SSL.__extension__ <pcapkit.protocols.application.ssl.protocol.SSL.__extension__>`
    registers a decoder for its type.
  * Every other handshake message at type and length only.
  * ``Alert`` and ``ChangeCipherSpec`` in full.

* Everything else -- the same types once encrypted, ``application_data``
  and every other content type -- as opaque :obj:`bytes`.

Records in One Segment
----------------------

A whole record after the first in a TCP segment is dissected as a further
:class:`TLS` layer, the previous record's payload (:issue:`2517`): a
``ServerHello`` followed by a ``ChangeCipherSpec`` reads
``TCP:TLS 1.3:TLS 1.2``. The exceptions:

* A whole record that fails to decode becomes
  :class:`~pcapkit.protocols.misc.raw.protocol.Raw` together with everything after it,
  with no SSLv2 trial.
* Octets that open no record -- an unsupported content type, a legacy
  version outside ``0x03xx``, or a header cut short -- stay raw, with no error.
* A parse told to stop at TLS (``protocol='TLS'`` or ``layer='Application'``)
  keeps the rest of the segment raw.
* Each record is a layer, so :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`
  bounds how many are dissected.

Known Limitation
----------------

**A record split across two TCP segments is not reassembled**, and decodes as
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, as does the partial record a segment
ends inside. A record may be up to 16 KiB against a typical 1460-octet MSS, so
this is routine.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.corekit.decorators import beholder
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.application.ssl.protocol import (_TLS_VERSION_MAJOR, _WIRE_CONTENT_TYPES,
                                                        SSL, TLS13_VERSION)
from pcapkit.protocols.application.sslv2.data import ClientHello as SSLv2_ClientHello
from pcapkit.protocols.application.sslv2.data import ServerHello as SSLv2_ServerHello
from pcapkit.protocols.application.sslv2.data import SSLv2 as SSLv2_Data
from pcapkit.protocols.application.sslv2.protocol import SSLv2
from pcapkit.protocols.application.tls.data import TLS as Data_TLS
from pcapkit.protocols.application.tls.schema import TLS as Schema_TLS
from pcapkit.utilities.contextvars import beholding
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import hold_warnings

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.const.reg.apptype.tcp import TCP as AppType_TCP
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['TLS']

#: The TCP port registry :meth:`TLS.__index__` reads its port from, resolved
#: there rather than imported, as ``import pcapkit`` leaves it unloaded
#: (:issue:`1538`), so its first import holds
#: :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_TCP: 'ModuleDescriptor[AppType_TCP]' = ModuleDescriptor('pcapkit.const.reg.apptype.tcp', 'TCP')

#: Length of the record header -- content type, legacy version and length
#: (:rfc:`9846#section-5.1`).
_RECORD_HEADER_LENGTH = 5

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

#: Legacy record versions a TLS 1.3 record may carry -- ``0x0303`` always, and
#: ``0x0301`` on an initial ``ClientHello`` (:rfc:`9846#section-5.1`).
_TLS13_LEGACY_VERSIONS = frozenset({0x0301, 0x0303})


def _opens_whole_record(data: 'bytes') -> 'bool':
    """Whether ``data`` opens with a whole TLS record.

    Only the record header is read, against the same checks as
    :meth:`SSL._validate_tls_record
    <pcapkit.protocols.application.ssl.protocol.SSL._validate_tls_record>`: a content
    type a genuine record carries, a ``0x03xx`` legacy version, and a fragment
    that ends inside ``data``.

    Args:
        data: Octets after a record.

    Returns:
        Whether a further record opens ``data`` and ends inside it.

    """
    if len(data) < _RECORD_HEADER_LENGTH:
        return False
    return (data[0] in _WIRE_CONTENT_TYPES and data[1] == _TLS_VERSION_MAJOR
            and _RECORD_HEADER_LENGTH + int.from_bytes(data[3:5], 'big') <= len(data))


class TLS(SSL[Data_TLS, Schema_TLS], schema=Schema_TLS, data=Data_TLS):
    """This class implements all protocols in the TLS/SSLv3+ record-layer family.

    - Secure Sockets Layer version 3 (:class:`~pcapkit.protocols.application.sslv3.protocol.SSLv3`)
    - Transport Layer Security 1.0 [:rfc:`2246`]
    - Transport Layer Security 1.1 [:rfc:`4346`]
    - Transport Layer Security 1.2 [:rfc:`5246`]
    - Transport Layer Security 1.3 [:rfc:`9846`]

    Note:
        The subpackage does not track the dispatch tier: TLS is dispatched
        from :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>`
        at port 443, the ``https`` service name IANA assigns there. See
        :func:`pcapkit.foundation.registry.protocols.transport.register_tcp`.

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
        :attr:`~pcapkit.protocols.application.tls.data.TLS.length`'s fragment
        excluded; or, once :meth:`unpack` has adopted an SSLv2 record, that
        record's own 2- or 3-octet header.

        """
        if self._adopted_length is not None:
            return self._adopted_length
        return _RECORD_HEADER_LENGTH

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
                to :class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2`.

        """
        if length is None:
            length = len(self)
        return self._read_tls_record(length, **kwargs)

    def make(self,
             content_type: 'Enum_ContentType | int' = Enum_ContentType.application_data,
             version: 'int' = 0x0303,
             content: 'Any' = b'',
             data: 'Optional[bytes]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_TLS':
        """Make (construct) packet data, for every tier: ``version`` is written as is.

        Args:
            content_type: Record content type.
            version: Legacy record version (``major << 8 | minor``), e.g.
                ``0x0303`` for TLS 1.2 and (the legacy value TLS 1.3 keeps
                here) TLS 1.3.
            content: Record content: a :obj:`tuple` of
                :class:`~pcapkit.protocols.application.ssl.data.Handshake`
                for ``handshake``, an
                :class:`~pcapkit.protocols.application.ssl.data.Alert`, a
                :class:`~pcapkit.protocols.application.ssl.data.ChangeCipherSpec`,
                or raw :obj:`bytes`, as :meth:`read` would decode it.
            data: Pre-encoded record fragment. When given, it is used
                verbatim in place of ``content`` and ``length`` is computed
                from it.
            payload: Octets after the record, e.g. a further record
                coalesced in the same buffer.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``content_type`` is a name, a :obj:`bool`, or a
                member or code the 8-bit content type field cannot carry, or
                an extension of ``content`` given as a ``(type, kwargs)`` pair
                has such a type for its 16-bit field.
            StructError: If ``version`` or the record length, or a field of
                ``content``, does not fit its width.

        """
        content_type_ = self._make_index(content_type, Enum_ContentType, bits=8, name='content type')

        fragment = data if data is not None else self._make_tls_content(content_type_, content, dtls=False)
        # NOTE: the schema masks a field to its width, so each is packed here first, to
        # refuse a wider value with the StructError the content makers raise.
        for value, size in ((version, 2), (len(fragment), 2)):
            self._make_pack(value, size=size)
        return Schema_TLS(
            content_type=content_type_,
            version=version,
            length=len(fragment),
            fragment=fragment,
            payload=payload,
        )

    def unpack(self, length: 'Optional[int]' = None, *, chained: 'bool' = False,  # pylint: disable=arguments-differ
               **kwargs: 'Any') -> 'Any':
        """Unpack (parse) packet data: TLS, or the SSLv2 record port 443 may carry.

        TLS is tried first: the record header and :meth:`read`. Only when
        that trial rejects the first record of a segment is the payload offered
        to :class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2`, whose own header
        checks are strict, so a genuine TLS record is never taken as SSLv2.

        Args:
            length: Length of packet data.
            chained: Whether the record follows another in its segment; such
                a record gets no SSLv2 trial, since SSLv2 only opens a
                connection (:issue:`2517`).
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the payload is neither a TLS record (see
                :meth:`_read_tls_record`) nor an SSLv2 record.

        Note:
            The TLS trial's warnings are dropped when SSLv2 parses the record
            (:issue:`2525`), and the SSLv2 trial's when it fails. When the record
            is not parsed, the TLS trial's are dropped only under
            :func:`~pcapkit.corekit.decorators.beholder` (:issue:`2308`).

        """
        with hold_warnings() as trial:
            try:
                return super().unpack(length, **kwargs)
            except ProtocolError:
                parsed = None
                if not chained:
                    trial.discard = True
                    with hold_warnings() as fallback:
                        parsed = self._read_sslv2_fallback(len(self) if length is None else length, **kwargs)
                        fallback.discard = parsed is None
                if parsed is None:
                    trial.discard = beholding.get()
                    raise
                return parsed

    @classmethod
    def from_data(cls, data: 'Any', **kwargs: 'Any') -> 'Any':
        """Create protocol instance from data.

        An SSLv2 record that :meth:`unpack` adopted from port 443 is rebuilt as
        the SSLv2 record it was parsed from, since TLS's record layout cannot
        carry its 2- or 3-octet header. Its :obj:`dict`, as :meth:`Info.to_dict
        <pcapkit.corekit.infoclass.Info.to_dict>` exports it, carries no data
        model, so it is told apart by the ``two_byte_header`` that records the
        header's form, a field no TLS record has (:issue:`2762`).

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance: an :class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2`
            for an SSLv2 record, otherwise a TLS instance.

        """
        if isinstance(data, SSLv2_Data) or 'two_byte_header' in data:
            return SSLv2.from_data(data, **kwargs)
        return super().from_data(data, **kwargs)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[5]':
        """Return an estimated length for the object."""
        return _RECORD_HEADER_LENGTH  # type: ignore[return-value]

    @classmethod
    def __index__(cls) -> 'int':  # type: ignore[override]
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_ service names and
            port numbers: TCP port 443, the port of
            :attr:`TCP.https_443 <pcapkit.const.reg.apptype.tcp.TCP.https_443>`
            as an :class:`int`, which
            :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>`
            dispatches here (:ref:`registry-protocol-index`).
            :class:`~pcapkit.protocols.application.sslv3.protocol.SSLv3` inherits it.

        .. _IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

        """
        return int(_TCP.klass.https_443)  # type: ignore[call-overload]

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
        <pcapkit.protocols.application.ssl.protocol.SSL._tls_negotiates>`). An unknown
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
        length probe. Anything else stays :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            The SSLv2 data model, adopted as this dispatcher's own, or
            :data:`None` if the payload is not a complete SSLv2 hello.

        """
        # NOTE: ``__init__`` consumed the stops, so they are handed on; a stop this
        # dispatcher matched (``'TLS'``, ``'SSL'``) is passed as its layer (#2567).
        stops = {'layer': self.__layer__} if self._sigterm else {'layer': self._exlayer, 'protocol': self._exproto}
        try:
            obj = SSLv2(self._data, length, __context__=self._exctx, **stops, **kwargs)
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
        :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, as
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
            Instance of this class, or of :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
            when :func:`~pcapkit.corekit.decorators.beholder` replaces a record
            that fails to parse, with no SSLv2 trial (see :meth:`unpack`).

        """
        file_ = self._get_payload()
        return self._parse_next_layer(type(self), file_, len(file_) if length is None else length,
                                      alias=proto, packet=packet, layer=self._exlayer,
                                      protocol=self._exproto, __context__=self._exctx, chained=True)
