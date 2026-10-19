NGAP - NG Application Protocol
==============================

.. module:: pcapkit.protocols.application.ngap

:mod:`pcapkit.protocols.application.ngap` contains
:class:`~pcapkit.protocols.application.ngap.NGAP`,
which implements an extractor for the NG Application Protocol
(NGAP) [*]_, as specified in 3GPP TS 38.413, and the enumerations its
data models report with:
:class:`~pcapkit.protocols.application.ngap.PDUKind`,
:class:`~pcapkit.protocols.application.ngap.Criticality`,
:class:`~pcapkit.const.ngap.procedure_code.ProcedureCode` and
:class:`~pcapkit.const.ngap.protocol_ie.ProtocolIE`.

NGAP is the control plane between a 5G RAN node (gNB or ng-eNB) and an AMF.
It runs over SCTP and is named by the DATA chunk's *payload protocol
identifier* rather than by a port, so :class:`NGAP` is registered on
:attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.SCTP.__proto__>` under
PPID 60 (``NG_Application_Protocol``) and PPID 66
(``NGAP_over_DTLS_over_SCTP``); see
:func:`pcapkit.foundation.registry.protocols.register_sctp`.

An SCTP DATA chunk that names NGAP carries exactly one ``NGAP-PDU``, encoded
in **aligned PER** (ALIGNED PACKED ENCODING RULES, :abbr:`APER`). There is no
header to read and no framing to resolve: the whole payload is the encoding,
and none of its structure is visible until an ASN.1 decoder has run over it.

Decoding therefore needs the optional |pycrate|_ dependency
(``pip install pypcapkit[NGAP]``). :mod:`pcapkit` imports and works without
it; an NGAP payload simply degrades to the opaque payload path, exactly as an
unregistered PPID would, because
:meth:`~pcapkit.protocols.protocol.Protocol._import_next_layer`, which
:class:`~pcapkit.protocols.transport.sctp.SCTP` inherits, is wrapped in
:func:`~pcapkit.corekit.decorators.beholder` and falls back to
:class:`~pcapkit.protocols.misc.raw.Raw`.

.. autoclass:: pcapkit.protocols.application.ngap.NGAP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __length_hint__
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
``SEQUENCE`` / ``SET`` (a dict)                             :class:`~pcapkit.protocols.data.application.ngap.Sequence`
``SEQUENCE OF`` (a list)                                    :obj:`list`
``CHOICE`` / open type                                      :class:`~pcapkit.protocols.data.application.ngap.Choice`
``BIT STRING``                                              :class:`~pcapkit.protocols.data.application.ngap.BitString`
``INTEGER``, ``OCTET STRING``, ``ENUMERATED``, ``BOOLEAN``  kept as :obj:`int`, :obj:`bytes`, :obj:`str`, :obj:`bool`
==========================================================  ==========================================================

That is a deliberate trade. Every elementary procedure and protocol IE
works on the day it is decoded, and a new 3GPP release needs no
code change here; what is given up is per-IE typing, so an IE's value is
reported in the specification's own shape rather than as a
:mod:`pcapkit`-specific model. The fields worth reading at a glance -- the PDU
kind, procedure code, criticality, message type name and the IE list -- are
surfaced as first-class fields on
:class:`~pcapkit.protocols.data.application.ngap.NGAP` regardless.

Known Limitations
-----------------

* **PPID 66 payloads are not decoded.** ``NGAP_over_DTLS_over_SCTP`` wraps the
  ``NGAP-PDU`` in a DTLS record, and :mod:`pcapkit` implements no DTLS, so the
  bytes reaching :meth:`NGAP.read` are not an APER encoding. The PPID is
  registered so that it is *named* rather than anonymous; the payload itself
  degrades to :class:`~pcapkit.protocols.misc.raw.Raw`.
* **The specification version is that of the installed decoder, not this
  package's.** The IE and procedure enumerations were generated from
  ``NGAP_Constants`` of |pycrate|_ 0.8.1 (Release-18-era). A |pycrate|_ that
  carries a newer NGAP will decode IEs that
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

.. autofunction:: pcapkit.protocols.application.ngap.load_pycrate

.. autofunction:: pcapkit.protocols.application.ngap._convert

.. autofunction:: pcapkit.protocols.application.ngap._revert

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.application.ngap.PDUKind
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ngap.Criticality
   :members:
   :show-inheritance:

.. autodata:: pcapkit.protocols.application.ngap._PYCRATE
   :no-value:

.. autodata:: pcapkit.protocols.application.ngap._PDU_LOCK
   :no-value:

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.application.ngap

.. autoclass:: pcapkit.protocols.schema.application.ngap.NGAP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.application.ngap

.. autoclass:: pcapkit.protocols.data.application.ngap.NGAP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.ngap.IE
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.ngap.Choice
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.ngap.BitString
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.ngap.Sequence
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/NG_Application_Protocol
