# -*- coding: utf-8 -*-
"""TLS/SSL - Transport Layer Security
========================================

.. module:: pcapkit.protocols.application.tls

:mod:`pcapkit.protocols.application.tls` contains
:class:`~pcapkit.protocols.application.tls.TLS` only, which implements an
extractor for Transport Layer Security (TLS) [*]_ -- TLS 1.2 (:rfc:`5246`) and
TLS 1.3 (:rfc:`9846`, which obsoletes :rfc:`8446`) -- at the record layer, plus
handshake message TYPE-level framing.

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

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.protocols.application.ssl import SSL
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


class TLS(SSL[Data_TLS, Schema_TLS], schema=Schema_TLS, data=Data_TLS):
    """This class implements Transport Layer Security.

    Note:
        The subpackage does not track the dispatch tier: TLS is dispatched
        from :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>`
        at port 443, the ``https`` service name IANA assigns there, now that
        this module parses the record layer it carries. See
        :func:`pcapkit.foundation.registry.protocols.register_tcp`.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Transport Layer Security"]':
        """Name of current protocol."""
        return 'Transport Layer Security'

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

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TLS':  # pylint: disable=unused-argument
        """Read Transport Layer Security (TLS).

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
