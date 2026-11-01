DTLS - Datagram Transport Layer Security
==============================================

.. module:: pcapkit.protocols.application.dtls

:mod:`pcapkit.protocols.application.dtls` contains
:class:`~pcapkit.protocols.application.dtls.DTLS` only, which implements an
extractor for Datagram Transport Layer Security (DTLS) [*]_ -- DTLS 1.0
(:rfc:`4347`), DTLS 1.2 (:rfc:`6347`) and DTLS 1.3's legacy-format and
unified-header records (:rfc:`9147`) -- at the record layer, plus the epoch/sequence-number fields and
the handshake-message fragment header that set DTLS apart from
:class:`~pcapkit.protocols.application.tls.TLS`, whose reliable, ordered
transport needs neither.

Version Identification
----------------------

As with :class:`~pcapkit.protocols.application.tls.TLS`, one class parses
every version and :meth:`~pcapkit.protocols.application.dtls.DTLS.read` sets
:attr:`~pcapkit.protocols.application.dtls.DTLS.alias` from the record;
:meth:`~pcapkit.protocols.application.dtls.DTLS.id` stays ``('DTLS',)``.

.. list-table::
   :header-rows: 1

   * - Legacy record version
     - :attr:`~pcapkit.protocols.application.dtls.DTLS.alias`
   * - ``0xFEFF``
     - ``DTLS 1.0``
   * - ``0xFEFD``
     - ``DTLS 1.2``
   * - ``0xFEFD``, or ``0xFEFF`` on an initial ``ClientHello``, whose
       ``supported_versions`` extension lists ``0xFEFC``
     - ``DTLS 1.3``
   * - any other ``0xFExx``
     - ``DTLS``
   * - unified header (first octet ``001CSLEE``, :rfc:`9147#section-4.1`)
     - ``DTLS 1.3``

DTLS 1.3 never puts its own ``0xFEFC`` on the record layer
(:rfc:`9147#section-4`), so a legacy-format record is told apart only by the
``supported_versions`` peek. A version the table does not name keeps the
generic ``DTLS`` alias rather than claiming a specific one.

A unified-header record has no legacy version to read. Its first octet's top
three bits are ``001``, which no legacy content type (20 through 27) sets, so
the two formats are told apart by that octet alone.

Records in One Datagram
-----------------------

A whole record after the first in a UDP datagram is dissected as a further
:class:`~pcapkit.protocols.application.dtls.DTLS` layer, the previous record's
payload (:rfc:`6347#section-4.1.1`, :rfc:`9147#section-4.3`, :issue:`2535`): a
``ChangeCipherSpec`` followed by an ``Alert`` reads ``UDP:DTLS 1.2:DTLS 1.2``.
A unified-header record is delimited by its length; one without a length runs
to the end of the datagram, so it is the last (:rfc:`9147#section-4`). The
exceptions:

* A whole record that fails to decode becomes
  :class:`~pcapkit.protocols.misc.raw.Raw` together with everything after it.
* Octets that open no whole record stay raw, with no error: an unsupported
  content type, a legacy version outside ``0xFExx``, a header cut short, a
  length past the end of the datagram, or a unified header with a connection
  ID, which leaves the record's end unknown.
* A parse told to stop at DTLS (``protocol='DTLS'`` or ``layer='Application'``)
  keeps the rest of the datagram raw.
* Each record is a layer, so :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`
  bounds how many are dissected.

Known Limitations
-----------------

**A handshake message split across DTLS records is not decoded here**
(:rfc:`6347#section-4.2.3`, :issue:`2440`). Each fragment is flagged
:attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.is_fragmented`
and its :attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.body`
kept as raw octets. ``Extractor(reassembly=True, dtls=True)`` reassembles the
message, and :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` decodes it
with :meth:`~pcapkit.protocols.application.dtls.DTLS.read_handshake`.

**A unified-header record with a connection ID is not decoded**
(:rfc:`9147#section-4.1`, :issue:`2467`). Its length is negotiated, not carried
in the record, so it degrades to :class:`~pcapkit.protocols.misc.raw.Raw`. The
same holds for ``tls12_cid`` records (:rfc:`9146`).

**A unified-header record carries only the low two bits of the epoch**, and
its sequence number is header-protected, so the values it reports are the
ones on the wire.

.. versionadded:: 1.6.0

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.dtls.DTLS
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make
   .. automethod:: unpack
   .. automethod:: read_handshake

   .. automethod:: __length_hint__

   .. automethod:: _make_data

Header Schema
-------------

.. module:: pcapkit.protocols.schema.application.dtls

.. autoclass:: pcapkit.protocols.schema.application.dtls.DTLS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.application.dtls.DTLSCiphertext
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.application.dtls

.. autoclass:: pcapkit.protocols.data.application.dtls.DTLS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.dtls.DTLSCiphertext
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.dtls.DTLSHandshake
   :members:
   :show-inheritance:

See :doc:`ssl` for ``ClientHello``, ``ServerHello``, ``Extension``, ``Alert``
and ``ChangeCipherSpec``, shared verbatim with
:class:`~pcapkit.protocols.application.tls.TLS`.

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security
