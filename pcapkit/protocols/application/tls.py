# -*- coding: utf-8 -*-
"""TLS/SSL - Transport Layer Security
========================================

.. module:: pcapkit.protocols.application.tls

:mod:`pcapkit.protocols.application.tls` contains
:class:`~pcapkit.protocols.application.tls.TLS`, which is a version
dispatcher for the TLS/SSLv3+ record-layer family -- SSLv3, TLS 1.0, TLS 1.1,
TLS 1.2 (:rfc:`5246`) and TLS 1.3 (:rfc:`9846`, which obsoletes :rfc:`8446`)
-- mirroring :class:`~pcapkit.protocols.application.http.HTTP`'s dispatch
over :mod:`~pcapkit.protocols.application.httpv1` and
:mod:`~pcapkit.protocols.application.httpv2`. :attr:`TCP.__proto__
<pcapkit.protocols.transport.tcp.TCP.__proto__>` binds this class at port
443; its own :meth:`read` identifies the concrete tier -- or, where the
payload is SSLv2-shaped instead, :class:`~pcapkit.protocols.application.ssl2.SSL2`
-- and delegates to it, rather than parsing content itself.

Decoded Fields
--------------

* The record header -- content type, legacy version, length -- in full,
  regardless of encryption: this part is always in the clear.
* For a **cleartext** ``handshake``, ``alert``, or ``change_cipher_spec``
  record -- i.e. one that has not yet started carrying ciphertext, decided
  per-record by
  :meth:`SSL._tls_content_is_cleartext <pcapkit.protocols.application.ssl.SSL._tls_content_is_cleartext>`:

  * ``ClientHello``/``ServerHello`` down to their cipher suite(s),
    compression method(s), and extension list, TYPE+LENGTH framed (extension
    bodies are not decoded).
  * Every other handshake message (``Certificate``, ``ServerKeyExchange``,
    ``ClientKeyExchange``, etc.) at the message-type/length level only: its
    body is kept undecoded. ``Finished`` is always ciphertext -- there is no
    cleartext ``Finished`` -- so it is never decoded even at this level and
    always stays opaque bytes.
  * ``Alert`` and ``ChangeCipherSpec`` records in full.

* An **encrypted** ``handshake``, ``alert``, or ``change_cipher_spec``
  record -- which is the common case for TLS 1.2 traffic once the handshake
  completes -- plus ``application_data`` and every other content type, as
  opaque :obj:`bytes`.

The record header is visible on the wire regardless of encryption, but the
record *content* is not: once the handshake has derived keys, a
``handshake``/``alert``/``change_cipher_spec`` record may carry ciphertext
indistinguishable at the header level from its cleartext counterpart, and
only the content stays undecoded in that case -- see
:meth:`SSL._tls_content_is_cleartext <pcapkit.protocols.application.ssl.SSL._tls_content_is_cleartext>`
for how each case is told apart. Decrypting ``application_data`` is out of
scope.

Known Limitation
-----------------

**A record split across two TCP segments is not reassembled**, and so decodes
as :class:`~pcapkit.protocols.misc.raw.Raw` rather than as the record it is the
start of. A record may be up to 16 KiB against a typical 1460-octet MSS, so
this is routine rather than rare. See
:meth:`SSL._validate_tls_record <pcapkit.protocols.application.ssl.SSL._validate_tls_record>`
for why rejecting such a fragment is the honest answer at this layer.

.. versionadded:: 1.6.0

.. versionchanged:: 1.6.0

   :class:`TLS` is now a version dispatcher rather than a single generic
   parser: it identifies SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, or TLS 1.3 (and,
   where available, SSLv2) and delegates to the matching concrete class --
   :mod:`~pcapkit.protocols.application.sslv3`,
   :mod:`~pcapkit.protocols.application.tlsv1_0`,
   :mod:`~pcapkit.protocols.application.tlsv1_1`,
   :mod:`~pcapkit.protocols.application.tlsv1_2`, or
   :mod:`~pcapkit.protocols.application.tlsv1_3` -- the same shape
   :class:`~pcapkit.protocols.application.http.HTTP` already uses for its own
   family (:issue:`2437`).

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.protocols.application.ssl import SSL, TLS13_VERSION
from pcapkit.protocols.data.application.tls import TLS as Data_TLS
from pcapkit.protocols.schema.application.tls import TLS as Schema_TLS

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional
    from typing import Type as _Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['TLS']

#: Legacy record-version major octet TLS/SSLv3+ records carry (``0x03xx``,
#: SSLv3 through the TLS 1.3 wire value). Mirrors
#: :data:`~pcapkit.protocols.application.ssl._TLS_VERSION_MAJOR`, which this
#: module does not import -- that constant is private to
#: :mod:`~pcapkit.protocols.application.ssl` -- but the value the two check
#: is the same one by definition.
_TLS_VERSION_MAJOR = 0x03

#: The content types IANA's registry assigns that a genuine *first* record on
#: a fresh connection carries on the wire -- the four
#: :func:`_looks_like_sslv2` tests the second octet of, to tell a real
#: TLS/SSLv3+ record from SSLv2's wire-incompatible, content-type-less header.
#: Deliberately narrower than
#: :data:`~pcapkit.protocols.application.ssl._WIRE_CONTENT_TYPES`: ``heartbeat``
#: and the DTLS-only ``ack``/``return_routability_check`` do not open a
#: connection, and widening this set only widens the window in which a
#: genuine SSLv2 record (whose second octet is an arbitrary length octet, not
#: always a version byte) could be misread as TLS.
_SSLV3_PLUS_FIRST_OCTETS = frozenset({
    int(Enum_ContentType.change_cipher_spec),
    int(Enum_ContentType.alert),
    int(Enum_ContentType.handshake),
    int(Enum_ContentType.application_data),
})


def _looks_like_sslv2(data: 'bytes') -> 'bool':
    """Whether ``data`` opens with an SSLv2 record header rather than a TLS one.

    SSLv2 carries no content-type byte at all: its record header is either 2
    octets, with the top bit of the first set, or 3, with the top two bits
    ``01`` for the escaped form or ``00`` for the plain one (see
    :mod:`~pcapkit.protocols.application.ssl2`'s module docstring for the
    exact bit layout). A genuine TLS/SSLv3+ record's first octet is always
    one of the content types :data:`_SSLV3_PLUS_FIRST_OCTETS` names, and its
    second is always :data:`_TLS_VERSION_MAJOR`.

    Only the plain (``00``) 3-octet SSLv2 form is genuinely ambiguous with a
    real content-type byte, since content types 20-23 also carry top bits
    ``00`` -- resolved the same way the positive identification is, by
    testing the second octet too, so only a match on *both* conditions reads
    as TLS; everything else, including a buffer too short to carry even one
    octet, reads as SSLv2.

    Args:
        data: The payload, from its first octet.

    Returns:
        :data:`False` only when ``data`` opens with a content type this
        module recognises as a TLS/SSLv3+ one immediately followed by
        :data:`_TLS_VERSION_MAJOR`; :data:`True` otherwise.

    """
    if not data:
        return True
    first = data[0]
    if first & 0x80:            # SSLv2, 2-octet header
        return True
    if (first & 0xC0) == 0x40:  # SSLv2, 3-octet header, escaped
        return True
    if first in _SSLV3_PLUS_FIRST_OCTETS and len(data) >= 2 and data[1] == _TLS_VERSION_MAJOR:
        return False
    return True                 # SSLv2, 3-octet header, plain -- or too short to tell


class TLS(SSL[Data_TLS, Schema_TLS], schema=Schema_TLS, data=Data_TLS):
    """This class implements Transport Layer Security.

    Note:
        The subpackage does not track the dispatch tier: TLS is dispatched
        from :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>`
        at port 443, the ``https`` service name IANA assigns there, now that
        this module parses the record layer it carries. See
        :func:`pcapkit.foundation.registry.protocols.register_tcp`.

    """

    #: Resolved alias once :meth:`read` has identified the concrete tier --
    #: e.g. ``'SSLv3'`` or ``'TLS 1.2'`` -- mirroring
    #: :attr:`HTTP._version <pcapkit.protocols.application.http.HTTP._version>`.
    #: The class name itself until then, same as the unversioned default
    #: every :class:`~pcapkit.protocols.protocol.ProtocolBase` falls back to.
    _alias = 'TLS'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Transport Layer Security"]':
        """Name of current protocol."""
        return 'Transport Layer Security'

    @property
    def alias(self) -> 'str':
        """Acronym of current protocol -- the concrete tier :meth:`read` identified."""
        return self._alias

    @property
    def length(self) -> 'Literal[5]':
        """Header length of current protocol -- the fixed record header,
        :attr:`~pcapkit.protocols.data.application.tls.TLS.length`'s fragment
        excluded.

        """
        return 5

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["TLS"], Literal["SSLv3"], Literal["TLSv1_0"], Literal["TLSv1_1"], Literal["TLSv1_2"], Literal["TLSv1_3"]]':  # type: ignore[override] # pylint: disable=line-too-long
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol -- the canonical name first, then every
            concrete tier this dispatcher may delegate to. SSLv2 is
            deliberately not among them: :meth:`read` may still delegate to
            it when the payload is shaped that way (see
            :func:`_looks_like_sslv2`), but this tuple is checked against
            *every* instance of this class regardless of which tier it
            actually resolved to, and genuine TLS 1.2 traffic must not match
            an ``SSL2`` lookup just because *some* port-443 payload could
            have been SSLv2. Inspect :attr:`alias`, or the type of
            :attr:`info <pcapkit.protocols.protocol.ProtocolBase.info>`,
            to tell SSLv2 traffic apart instead.

        """
        return ('TLS', 'SSLv3', 'TLSv1_0', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3')

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Any':
        """Read Transport Layer Security (TLS), or whatever port 443 actually carries.

        Identifies the concrete tier -- SSLv2, SSLv3, or one of TLS 1.0
        through 1.3 -- and delegates to it, mirroring
        :meth:`HTTP.read <pcapkit.protocols.application.http.HTTP.read>`'s
        own dispatch over its family.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data, from whichever concrete tier :meth:`_guess_version`
            identified.

        Raises:
            ProtocolError: If the identified tier's own parse fails -- see
                :meth:`SSLv3._read_tls_record <pcapkit.protocols.application.tls.TLS._read_tls_record>`
                (shared by every TLS-family tier) or
                :class:`~pcapkit.protocols.application.ssl2.SSL2`'s own
                :meth:`read <pcapkit.protocols.application.ssl2.SSL2.read>`.

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
             version: 'int' = 0x0303,
             content: 'Any' = b'',
             data: 'Optional[bytes]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_TLS':
        """Make (construct) packet data.

        Shared by every tier in the TLS family -- SSLv3 through TLS 1.3 wrap
        the identical record header and content shapes, so there is nothing
        version-specific for this to dispatch on; the ``version`` argument is
        simply written through to the record's legacy version field.

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

    def _guess_version(self, length: 'int', **kwargs: 'Any') -> 'Any':
        """Identify the concrete tier of the payload, and parse it as that tier.

        Positive identification first, same philosophy as
        :meth:`HTTP._guess_version <pcapkit.protocols.application.http.HTTP._guess_version>`:
        SSLv2 is told apart from the modern family by its wire-incompatible
        header shape (:func:`_looks_like_sslv2`), not by trial-parsing. Within
        the modern family, SSLv3/TLS 1.0/TLS 1.1 are named directly by the
        record's legacy version; TLS 1.2 and TLS 1.3 share the same legacy
        value (``0x0303``) and are told apart by peeking the
        ``supported_versions`` extension (:meth:`SSL._tls_negotiates
        <pcapkit.protocols.application.ssl.SSL._tls_negotiates>`), falling
        back to TLS 1.2 -- the common case -- when that peek is inconclusive.
        Any legacy version outside SSLv3+'s ``0x03xx`` range also falls back
        to the TLS 1.2 tier, so that its own :meth:`SSL._validate_tls_record
        <pcapkit.protocols.application.ssl.SSL._validate_tls_record>` reports
        the real reason the payload is not a genuine record, rather than this
        method guessing at one.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data from whichever concrete tier was identified.

        """
        schema = self.__header__

        if _looks_like_sslv2(self._data[:length]):
            try:
                from pcapkit.protocols.application.ssl2 import SSL2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
            except ImportError:
                pass  # SSLv2 support (#2457) is not present on this
                      # checkout -- fall through to the TLS-family dispatch
                      # below, exactly as if this identification did not exist.
            else:
                return SSL2(self._data, length, **kwargs)

        from pcapkit.protocols.application.sslv3 import SSLv3  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.application.tlsv1_0 import TLSv1_0  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.application.tlsv1_1 import TLSv1_1  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.application.tlsv1_2 import TLSv1_2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.application.tlsv1_3 import TLSv1_3  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel

        major = schema.version >> 8
        minor = schema.version & 0xFF

        protocol: '_Type[TLS]' = TLSv1_2
        if major == _TLS_VERSION_MAJOR:
            if not minor:
                protocol = SSLv3
            elif minor == 0x01:
                protocol = TLSv1_0
            elif minor == 0x02:
                protocol = TLSv1_1
            elif minor == 0x03 and self._tls_negotiates(schema, TLS13_VERSION, dtls=False):
                protocol = TLSv1_3
        return protocol(self._data, length, **kwargs)

    def _read_tls_record(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TLS':  # pylint: disable=unused-argument
        """Read a TLS/SSLv3+ record -- the real parse every concrete tier shares.

        Structure of TLS record layer [:rfc:`9846#section-5.1`]:

        .. code-block:: text

           struct {
               ContentType type;
               ProtocolVersion legacy_record_version;
               uint16 length;
               opaque fragment[TLSPlaintext.length];
           } TLSPlaintext;

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

        content = self._read_tls_content(schema.content_type, schema.fragment, dtls=False)
        tls = Data_TLS(
            content_type=schema.content_type,
            version=schema.version,
            length=schema.length,
            content=content,
        )

        remaining = available - (self.length + schema.length)
        return self._decode_next_layer(tls, -1, remaining)
