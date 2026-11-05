NGAP - NG Application Protocol
==============================

.. module:: pcapkit.protocols.application.ngap
.. module:: pcapkit.protocols.application.ngap.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.application.ngap._PYCRATE``,
   ``pcapkit.protocols.application.ngap._PDU_LOCK``,
   ``pcapkit.protocols.application.ngap.load_pycrate``,
   ``pcapkit.protocols.application.ngap.PDUKind``,
   ``pcapkit.protocols.application.ngap.Criticality``,
   ``pcapkit.protocols.application.ngap._convert`` and
   ``pcapkit.protocols.application.ngap._revert``, with no alias: they are in this
   module, and :mod:`pcapkit.protocols.application.ngap` exports the protocol class
   alone (:issue:`2534`).

:mod:`pcapkit.protocols.application.ngap.protocol` contains
:class:`~pcapkit.protocols.application.ngap.protocol.NGAP`,
which implements an extractor for the NG Application Protocol
(NGAP) [*]_, as specified in 3GPP TS 38.413, and the enumerations its
data models report with:
:class:`~pcapkit.protocols.application.ngap.protocol.PDUKind`,
:class:`~pcapkit.protocols.application.ngap.protocol.Criticality`,
:class:`~pcapkit.const.ngap.procedure_code.ProcedureCode` and
:class:`~pcapkit.const.ngap.protocol_ie.ProtocolIE`.

NGAP is the control plane between a 5G RAN node (gNB or ng-eNB) and an AMF.
It runs over SCTP and is named by the DATA chunk's *payload protocol
identifier* rather than by a port, so :class:`NGAP` is registered on
:attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__>` under
PPID 60
(:attr:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NG_Application_Protocol`)
and PPID 66
(:attr:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP`);
see
:func:`pcapkit.foundation.registry.protocols.transport.register_sctp`.

An SCTP DATA chunk that names NGAP carries exactly one ``NGAP-PDU``, encoded
in **aligned PER** (ALIGNED PACKED ENCODING RULES, :abbr:`APER`). There is no
header to read and no framing to resolve: the whole payload is the encoding,
and none of its structure is visible until an ASN.1 decoder has run over it.

Decoding needs the optional |pycrate|_ dependency
(``pip install pypcapkit[NGAP]``). Without it :mod:`pcapkit` still works, and an
NGAP payload falls back to :class:`~pcapkit.protocols.misc.raw.protocol.Raw` as an
unregistered PPID's does:
:meth:`~pcapkit.protocols.protocol.Protocol._import_next_layer`, which
:class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` inherits, is wrapped in
:func:`~pcapkit.corekit.decorators.beholder`.

.. autoclass:: pcapkit.protocols.application.ngap.protocol.NGAP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __length_hint__
   .. automethod:: __index__
   .. automethod:: _make_data

Decoder Dependency
------------------

|pycrate|_ is used rather than a PER codec of our own. It
**ships NGAP already compiled**, at ``pycrate_asn1dir/NGAP.py``, so the 3GPP
ASN.1 source does not have to be vendored here and tracked across releases; and
it is **pure Python**, with no compiled extension to build on any platform.
Decoding costs 0.15 ms per PDU, the same order as :mod:`pcapkit`'s own
per-packet cost, so the generic strategy below is not paying for the
convenience.

Generic Conversion
------------------

The decoded value tree is mapped into :class:`~pcapkit.corekit.infoclass.Info`
objects **structurally**, by ASN.1 shape rather than by procedure:

==========================================================  ==========================================================
ASN.1 / |pycrate|_ shape                                    :mod:`pcapkit` model
==========================================================  ==========================================================
``SEQUENCE`` / ``SET`` (a dict)                             :class:`~pcapkit.protocols.application.ngap.data.Sequence`
``SEQUENCE OF`` (a list)                                    :obj:`list`
``CHOICE`` / open type                                      :class:`~pcapkit.protocols.application.ngap.data.Choice`
``BIT STRING``                                              :class:`~pcapkit.protocols.application.ngap.data.BitString`
``INTEGER``, ``OCTET STRING``, ``ENUMERATED``, ``BOOLEAN``  kept as :obj:`int`, :obj:`bytes`, :obj:`str`, :obj:`bool`
==========================================================  ==========================================================

That is a deliberate trade: every elementary procedure and protocol IE the
decoder knows is converted, and a new 3GPP release needs no code change here;
what is given up is per-IE typing, so an IE's value keeps the specification's
own shape rather than a :mod:`pcapkit`-specific model. The PDU kind, procedure
code, criticality, message type name and IE list are first-class fields on
:class:`~pcapkit.protocols.application.ngap.data.NGAP` regardless.

Known Limitations
-----------------

* **PPID 66 payloads are not decoded.** NGAP over DTLS over SCTP wraps the
  ``NGAP-PDU`` in a DTLS record, and :attr:`SCTP.__proto__
  <pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__>` maps PPID 66 to
  :class:`~pcapkit.protocols.application.ngap.protocol.NGAP` rather than
  through :class:`~pcapkit.protocols.application.dtls.protocol.DTLS`, so the bytes
  reaching :meth:`NGAP.read` are not an APER encoding. The PPID is
  registered so that it is *named* rather than anonymous; the payload itself
  degrades to :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.
* **The specification version is that of the installed decoder, not this
  package's.** The IE and procedure enumerations were generated from
  ``NGAP_Constants`` of |pycrate|_ 0.8.1 (Release-18-era). A |pycrate|_ that
  carries a newer NGAP will decode values that
  :class:`~pcapkit.const.ngap.procedure_code.ProcedureCode` and
  :class:`~pcapkit.const.ngap.protocol_ie.ProtocolIE` do not name. Such a
  value resolves to a non-registering member called ``Unassigned`` rather than
  failing or adding a member to either enumeration.
* **NGAP over a fragmented SCTP association is not reassembled.** A DATA chunk
  is decoded on its own, so an ``NGAP-PDU`` split across chunks by SCTP
  fragmentation fails to decode rather than being reassembled first.
* **Private IEs** (``PrivateMessage``) **carry no schema.** Their contents are
  vendor defined, so the generic conversion reports whatever ASN.1 shape the
  encoding declares and cannot name the fields.

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.protocols.application.ngap.protocol.load_pycrate

.. autofunction:: pcapkit.protocols.application.ngap.protocol._convert

.. autofunction:: pcapkit.protocols.application.ngap.protocol._revert

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.application.ngap.protocol.PDUKind
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ngap.protocol.Criticality
   :members:
   :show-inheritance:

.. autodata:: pcapkit.protocols.application.ngap.protocol._PYCRATE
   :no-value:

.. autodata:: pcapkit.protocols.application.ngap.protocol._PDU_LOCK
   :no-value:

Header Schemas
--------------

.. module:: pcapkit.protocols.application.ngap.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.application.ngap``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.application.ngap.schema.NGAP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.application.ngap.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.application.ngap``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.application.ngap.data.NGAP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ngap.data.IE
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ngap.data.Choice
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ngap.data.BitString
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ngap.data.Sequence
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/NG_Application_Protocol
