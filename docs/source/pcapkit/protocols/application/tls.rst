TLS/SSL - Transport Layer Security
========================================

.. module:: pcapkit.protocols.application.tls

:mod:`pcapkit.protocols.application.tls` contains
:class:`~pcapkit.protocols.application.tls.TLS` and
:class:`~pcapkit.protocols.application.tls.SSLv3`, which implement an
extractor for the TLS/SSLv3+ record-layer family [*]_ -- SSLv3 (:rfc:`6101`),
TLS 1.0 (:rfc:`2246`), TLS 1.1 (:rfc:`4346`), TLS 1.2 (:rfc:`5246`) and TLS
1.3 (:rfc:`9846`, which obsoletes :rfc:`5077`, :rfc:`5246`, :rfc:`6961`,
:rfc:`7627`, :rfc:`8422` and :rfc:`8446`) -- at the record layer, plus
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
construction only, mirroring :class:`~pcapkit.protocols.link.inarp.InARP`: it
narrows :meth:`~pcapkit.protocols.application.tls.SSLv3.id` to ``('SSLv3',)``
and inherits :meth:`~pcapkit.protocols.application.tls.TLS.read` unchanged,
so the alias still follows the wire. Dispatch never constructs one.

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

A whole record after the first in a TCP segment is dissected as a further
:class:`~pcapkit.protocols.application.tls.TLS` layer, the previous record's
payload (:issue:`2517`): a ``ServerHello`` followed by a ``ChangeCipherSpec``
reads ``TCP:TLS 1.3:TLS 1.2``. The exceptions:

* A whole record that fails to decode becomes
  :class:`~pcapkit.protocols.misc.raw.Raw` together with everything after it,
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
:class:`~pcapkit.protocols.misc.raw.Raw`, as does the partial record a segment
ends inside. A record may be up to 16 KiB against a typical 1460-octet MSS, so
this is routine.

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
   .. automethod:: unpack

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
