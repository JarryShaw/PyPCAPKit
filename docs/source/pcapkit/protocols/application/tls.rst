TLS/SSL - Transport Layer Security
========================================

.. module:: pcapkit.protocols.application.tls

:mod:`pcapkit.protocols.application.tls` contains
:class:`~pcapkit.protocols.application.tls.TLS` and
:class:`~pcapkit.protocols.application.tls.SSLv3`, which implement an
extractor for the TLS/SSLv3+ record-layer family [*]_ -- SSLv3 (:rfc:`6101`),
TLS 1.0 (:rfc:`2246`), TLS 1.1 (:rfc:`4346`), TLS 1.2 (:rfc:`5246`) and TLS
1.3 (:rfc:`9846`, which obsoletes :rfc:`8446`) -- at the record layer, plus
handshake message TYPE-level framing.

Version Identification
----------------------

The record layer is wire-identical across the family, so one
:class:`~pcapkit.protocols.application.tls.TLS` class parses all of it and
reports the version it identified through
:attr:`~pcapkit.protocols.application.tls.TLS.alias` and
:attr:`~pcapkit.protocols.application.tls.TLS.name`, set by
:meth:`~pcapkit.protocols.application.tls.TLS.read` -- the same shape
:class:`~pcapkit.protocols.link.arp.ARP` uses for RARP/DRARP/InARP.
:meth:`~pcapkit.protocols.application.tls.TLS.id` stays ``('TLS',)``
whatever the version.

.. list-table::
   :header-rows: 1

   * - Legacy record version
     - :attr:`~pcapkit.protocols.application.tls.TLS.alias`
     - :attr:`~pcapkit.protocols.application.tls.TLS.name`
   * - ``0x0300``
     - ``SSLv3``
     - ``Secure Sockets Layer version 3``
   * - ``0x0301``
     - ``TLS 1.0``
     - ``Transport Layer Security``
   * - ``0x0302``
     - ``TLS 1.1``
     - ``Transport Layer Security``
   * - ``0x0303``
     - ``TLS 1.2``
     - ``Transport Layer Security``
   * - ``0x0301`` or ``0x0303``, on a ``ClientHello`` or ``ServerHello``
       whose ``supported_versions`` extension lists ``0x0304``
     - ``TLS 1.3``
     - ``Transport Layer Security``
   * - any other ``0x03xx``
     - ``TLS``
     - ``Transport Layer Security``

TLS 1.3 never puts its own ``0x0304`` on the record layer
(:rfc:`9846#section-5.1`), so it is told apart only by the
``supported_versions`` peek. A version the table does not name keeps the
generic ``TLS`` alias rather than claiming a specific one.

Each record is branded by its own legacy version, not by the connection's
negotiated one. So in a TLS 1.3 connection, every record after the hellos
carries ``0x0303`` and reads ``TLS 1.2``; and a TLS 1.2 ``ClientHello`` sent
at record version ``0x0301`` reads ``TLS 1.0``.

:class:`~pcapkit.protocols.application.tls.SSLv3` is for explicit
construction only, mirroring :class:`~pcapkit.protocols.link.arp.InARP`: it
narrows :meth:`~pcapkit.protocols.application.tls.SSLv3.id` to ``('SSLv3',)``
and inherits :meth:`~pcapkit.protocols.application.tls.TLS.read` unchanged,
so the alias still follows the wire. Dispatch never constructs one.

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

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.tls.TLS
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __length_hint__

   .. automethod:: _make_data

.. autoclass:: pcapkit.protocols.application.tls.SSLv3
   :no-members:
   :show-inheritance:

   .. automethod:: id

Header Schema
-------------

.. module:: pcapkit.protocols.schema.application.tls

.. autoclass:: pcapkit.protocols.schema.application.tls.TLS
   :members:
   :show-inheritance:

Data Model
----------

.. currentmodule:: pcapkit.protocols.data.application.tls

.. autoclass:: pcapkit.protocols.data.application.tls.TLS
   :members:
   :show-inheritance:

See :doc:`ssl` for ``ClientHello``, ``ServerHello``, ``Handshake``, ``Extension``,
``Alert`` and ``ChangeCipherSpec``, shared verbatim with
:class:`~pcapkit.protocols.application.dtls.DTLS`.

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security
