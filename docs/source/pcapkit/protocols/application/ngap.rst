NGAP - NG Application Protocol
==============================

.. module:: pcapkit.protocols.application.ngap

:mod:`pcapkit.protocols.application.ngap` contains
:class:`~pcapkit.protocols.application.ngap.NGAP` only,
which implements extractor for the NG Application Protocol
(NGAP) [*]_, as specified in 3GPP TS 38.413.

NGAP is the control plane between a 5G RAN node (gNB or ng-eNB) and an AMF.
It runs over SCTP and is named by the DATA chunk's *payload protocol
identifier* rather than by a port, so :class:`NGAP` is registered on
:attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.SCTP.__proto__>` under
PPID 60 (``NG_Application_Protocol``) and PPID 66
(``NGAP_over_DTLS_over_SCTP``), c.f.
:func:`pcapkit.foundation.registry.protocols.register_sctp`.

An SCTP DATA chunk that names NGAP carries exactly one ``NGAP-PDU``, encoded
in **aligned PER** (ALIGNED PACKED ENCODING RULES, :abbr:`APER`). There is no
header to read and no framing to resolve: the whole payload is the encoding,
and none of its structure is visible until an ASN.1 decoder has run over it.

Decoding therefore needs the optional |pycrate|_ dependency
(``pip install pypcapkit[NGAP]``). :mod:`pcapkit` imports and works without
it; an NGAP payload simply degrades to the opaque payload path, exactly as an
unregistered PPID would, because
:meth:`SCTP._import_next_layer <pcapkit.protocols.transport.sctp.SCTP._import_next_layer>`
is wrapped in :func:`~pcapkit.utilities.decorators.beholder` and falls back to
:class:`~pcapkit.protocols.misc.raw.Raw`.

Why |pycrate|_ rather than a PER codec of our own
-------------------------------------------------

Two things make it the cheaper answer. |pycrate|_ **ships NGAP already
compiled**, at ``pycrate_asn1dir/NGAP.py``, so the 3GPP ASN.1 source does not
have to be vendored here and tracked across releases; and it is **pure
Python**, with no compiled extension to build on any platform. Decoding costs
0.15 ms per PDU, the same order as :mod:`pcapkit`'s own per-packet cost, so
the generic strategy below is not paying for the convenience.

Generic conversion, not 51 hand-written procedures
--------------------------------------------------

The decoded value tree is mapped into :class:`~pcapkit.corekit.infoclass.Info`
objects **structurally**, by ASN.1 shape rather than by procedure:

===============================  ==========================================================
ASN.1 / |pycrate|_ shape          :mod:`pcapkit` model
===============================  ==========================================================
``SEQUENCE`` / ``SET`` (a dict)   :class:`~pcapkit.protocols.data.application.ngap.Sequence`
``SEQUENCE OF`` (a list)          :obj:`list`
``CHOICE`` / open type            :class:`~pcapkit.protocols.data.application.ngap.Choice`
``BIT STRING``                    :class:`~pcapkit.protocols.data.application.ngap.BitString`
``INTEGER``, ``OCTET STRING``,    kept as :obj:`int`, :obj:`bytes`, :obj:`str`
``ENUMERATED``, ``BOOLEAN``
===============================  ==========================================================

That is a deliberate trade. Every one of the 81 elementary procedures and 438
protocol IEs works on the day it is decoded, and a new 3GPP release needs no
code change here; what is given up is per-IE typing, so an IE's value is
reported in the specification's own shape rather than as a
:mod:`pcapkit`-specific model. The fields worth reading at a glance -- the PDU
kind, procedure code, criticality, message type name and the IE list -- are
surfaced as first-class fields on
:class:`~pcapkit.protocols.data.application.ngap.NGAP` regardless.

Known limitations
-----------------

* **PPID 66 payloads are not decoded.** ``NGAP_over_DTLS_over_SCTP`` wraps the
  ``NGAP-PDU`` in a DTLS record, and :mod:`pcapkit` implements no DTLS, so the
  bytes reaching :meth:`NGAP.read` are not an APER encoding. The PPID is
  registered so that it is *named* rather than anonymous; the payload itself
  degrades to :class:`~pcapkit.protocols.misc.raw.Raw`.
* **The specification version is |pycrate|_'s, not this package's.** The IE and
  procedure enumerations were generated from ``NGAP_Constants`` of |pycrate|_
  0.8.1 (Release-18-era: 81 procedure codes, 438 protocol IE IDs, highest 443).
  A |pycrate|_ that carries a newer NGAP will decode IEs that
  :class:`~pcapkit.protocols.application.ngap.ProcedureCode` and
  :class:`~pcapkit.protocols.application.ngap.ProtocolIE` do not name; both
  extend themselves at lookup time rather than failing, so such a value is
  reported as ``Unassigned_<n>``.
* **NGAP over a fragmented SCTP association is not reassembled.** A DATA chunk
  is decoded on its own, so an ``NGAP-PDU`` split across chunks by SCTP
  fragmentation fails to decode rather than being reassembled first.
* **Private IEs (``PrivateMessage``) carry no schema.** Their contents are
  vendor defined, so the generic conversion reports whatever ASN.1 shape the
  encoding declares and cannot name the fields.

.. autoclass:: pcapkit.protocols.application.ngap.NGAP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __length_hint__
   .. automethod:: _make_data

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.protocols.application.ngap.load_pycrate

.. autodata:: pcapkit.protocols.application.ngap._PYCRATE

.. autodata:: pcapkit.protocols.application.ngap._PDU_LOCK
   :no-value:

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

.. autoclass:: pcapkit.protocols.application.ngap.ProcedureCode
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ngap.ProtocolIE
   :no-members:
   :show-inheritance:

.. note::

   :class:`~pcapkit.protocols.application.ngap.ProcedureCode` and
   :class:`~pcapkit.protocols.application.ngap.ProtocolIE` are rendered without
   their members on purpose: between them they carry 519 of them, each named for
   the 3GPP identifier it comes from, and a page listing all of them is longer
   than the specification's own tables and no more useful. Read them from
   ``pcapkit/protocols/application/ngap.py``, or from
   ``pycrate_asn1dir.NGAP.NGAP_Constants``, which is where they were generated
   from.

   Unlike the enumerations under :mod:`pcapkit.const`, these are not crawled
   from an IANA registry -- 3GPP publishes them in the ASN.1 of TS 38.413 rather
   than in a registry with a stable page -- so there is no matching module under
   :mod:`pcapkit.vendor`.

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

.. |pycrate| replace:: ``pycrate``
.. _pycrate: https://github.com/pycrate-org/pycrate

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/NG_Application_Protocol
