# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""NGAP - NG application protocol
====================================

.. module:: pcapkit.protocols.application.ngap.protocol

:mod:`pcapkit.protocols.application.ngap.protocol` holds
:class:`~pcapkit.protocols.application.ngap.protocol.NGAP`, the extractor for the
NG Application Protocol (NGAP) [*]_ of 3GPP TS 38.413, and the enumerations its
decoded fields resolve to.

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
in **aligned PER** (ALIGNED PACKED ENCODING RULES, :abbr:`APER`). The whole
payload is the encoding, with no header or framing of its own, so none of its
structure is visible until an ASN.1 decoder has run over it.

Decoding therefore needs the optional |pycrate|_ dependency
(``pip install pypcapkit[NGAP]``). Without it an NGAP payload degrades as an
unregistered PPID would, because
:meth:`~pcapkit.protocols.protocol.Protocol._import_next_layer`, which
:class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` inherits, is wrapped in
:func:`~pcapkit.corekit.decorators.beholder` and falls back to
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

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

That is a deliberate trade: every elementary procedure and protocol IE
decodes, and a new 3GPP release needs no code change here, at the cost of
per-IE typing, so an IE's value is reported in the specification's own shape.
The PDU kind, procedure code, criticality, message type name and IE list are
first-class fields on :class:`~pcapkit.protocols.application.ngap.data.NGAP`
regardless.

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
  package's.** :class:`~pcapkit.const.ngap.procedure_code.ProcedureCode` and
  :class:`~pcapkit.const.ngap.protocol_ie.ProtocolIE` were generated from
  ``NGAP_Constants`` of |pycrate|_ 0.8.1 (Release-18-era), so a newer NGAP in
  |pycrate|_ decodes values these enumerations do not name. Such a value
  resolves to a non-registering member called ``Unassigned`` rather than
  failing or adding a member to either enumeration -- see
  :meth:`pcapkit.corekit.enum.EnumRegistry._unregistered_member`.
* **NGAP over a fragmented SCTP association is not reassembled.** A DATA chunk
  is decoded on its own, so an ``NGAP-PDU`` split across chunks by SCTP
  fragmentation fails to decode.
* **Private IEs** (``PrivateMessage``) **carry no schema.** Their contents are
  vendor defined, so the generic conversion reports whatever ASN.1 shape the
  encoding declares and cannot name the fields.

.. [*] https://en.wikipedia.org/wiki/NG_Application_Protocol

"""
import threading
from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.const.ngap.procedure_code import ProcedureCode as Enum_ProcedureCode
from pcapkit.const.ngap.protocol_ie import ProtocolIE as Enum_ProtocolIE
from pcapkit.const.reg.apptype.sctp import SCTP as Enum_SCTP
from pcapkit.corekit.enum import EnumLookup
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.application.ngap.data import IE as Data_IE
from pcapkit.protocols.application.ngap.data import NGAP as Data_NGAP
from pcapkit.protocols.application.ngap.data import BitString as Data_BitString
from pcapkit.protocols.application.ngap.data import Choice as Data_Choice
from pcapkit.protocols.application.ngap.data import Sequence as Data_Sequence
from pcapkit.protocols.application.ngap.schema import NGAP as Schema_NGAP
from pcapkit.utilities.compat import StrEnum
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['NGAP', 'PDUKind', 'Criticality']

#: Cached ``NGAP-PDU`` object; see :func:`load_pycrate`. :data:`NotImplemented`
#: means the import has not been attempted yet, :data:`None` that it was
#: attempted and |pycrate|_ is not installed, and anything else is the loaded
#: object. "Not installed" is kept apart from "not attempted" so that a capture
#: full of NGAP packets does not pay for a failing import on every frame.
_PYCRATE = NotImplemented  # type: Any

#: Guards the module-level ``NGAP-PDU`` object returned by :func:`load_pycrate`.
#: That object is *stateful*: ``from_aper`` stores the decoded value on it
#: and ``get_val`` hands back the decoder's own containers rather than
#: copies, so two decodes running concurrently through it would each see the
#: other's tree. The lock is held across the conversion, not merely across the
#: decode, for that second reason.
_PDU_LOCK = threading.Lock()


def load_pycrate() -> 'Optional[Any]':
    """Load the optional |pycrate|_ ``NGAP-PDU`` object.

    Returns:
        ``pycrate_asn1dir.NGAP.NGAP_PDU_Descriptions.NGAP_PDU``, the ``CHOICE``
        over ``initiatingMessage`` / ``successfulOutcome`` /
        ``unsuccessfulOutcome`` that is the entry point of the compiled
        specification, or :data:`None` when |pycrate|_ is not installed.

    Notes:
        The import is attempted at most once and the outcome is cached. It is
        not free even when it succeeds -- ``pycrate_asn1dir.NGAP`` is a 4.9 MB
        module -- which is the other reason it happens here rather than at
        module import: neither ``import pcapkit`` nor the documentation build
        should pay for it.

    """
    global _PYCRATE  # pylint: disable=global-statement

    if _PYCRATE is NotImplemented:
        try:
            from pycrate_asn1dir.NGAP import \
                NGAP_PDU_Descriptions  # pylint: disable=import-outside-toplevel
        except ImportError:
            _PYCRATE = None
        else:
            _PYCRATE = NGAP_PDU_Descriptions.NGAP_PDU
    return _PYCRATE


##############################################################################
# Enumerations.
#
# PDUKind and Criticality are closed ASN.1 ENUMERATED types, so they are
# hand-written here, like the closed mh.py helper enums (#877).
#
# ProcedureCode and ProtocolIE grow with 3GPP TS 38.413, which is published
# only as a PDF, so they are generated from pycrate's compiled specification
# (pycrate_asn1dir.NGAP's NGAP_Constants, #880) into pcapkit.const.ngap by
# pcapkit.vendor.ngap.procedure_code and pcapkit.vendor.ngap.protocol_ie, and
# imported here with no re-export (#1744). Only the crawler needs pycrate.
#
# The SCTP payload protocol identifiers are IANA's, from
# pcapkit.const.sctp.payload_protocol_identifier.
##############################################################################


class PDUKind(EnumLookup, StrEnum):
    """Which alternative of the ``NGAP-PDU`` ``CHOICE`` a PDU is.

    The values are spelled as the ASN.1 identifiers, so that a name decoded by
    |pycrate|_ resolves by value.

    Built on :class:`~pcapkit.corekit.enum.EnumLookup`, the lookup contract
    shared by every non-registry enumeration (:issue:`877`). The class defines
    neither ``get`` nor ``_missing_`` of its own.

    """

    #: A procedure's request, or a class 2 procedure's only message.
    INITIATING_MESSAGE = 'initiatingMessage'
    #: A class 1 procedure's successful response.
    SUCCESSFUL_OUTCOME = 'successfulOutcome'
    #: A class 1 procedure's unsuccessful response.
    UNSUCCESSFUL_OUTCOME = 'unsuccessfulOutcome'


class Criticality(EnumLookup, IntEnum):
    """[Criticality] What a receiver must do with an IE it does not understand.

    Members are named for the ASN.1 identifiers rather than upper-cased, so
    that :meth:`~pcapkit.corekit.enum.EnumLookup.get` resolves a name decoded
    by |pycrate|_ through the standard member map. The values are the
    ``ENUMERATED`` indices, which is what goes on the wire.

    Carries no ``get`` of its own: the inherited
    :meth:`~pcapkit.corekit.enum.EnumLookup.get` is used as is, so an unknown
    *name* is :exc:`KeyError`-shaped, exactly as ``E['nosuch']`` is on a stdlib
    :class:`~enum.Enum` (:issue:`923`), and an unknown *value* raises
    :exc:`ValueError`.

    A ``default`` is honoured only when it names a registered value:
    ``get('nosuch', Criticality.reject)`` answers ``reject``, and
    ``get('nosuch', 99)`` raises. A member-valued ``default`` resolves through
    ``_value2member_map_`` and never through the constructor, so on this closed
    ASN.1 ``ENUMERATED`` with no extension marker no path can mint a fourth
    value; see :meth:`_missing_`, which refuses one outright.

    """

    #: Reject the whole message.
    reject = 0
    #: Ignore the IE and carry on.
    ignore = 1
    #: Ignore the IE, carry on, and report it.
    notify = 2


    @classmethod
    def _missing_(cls, value: 'int') -> 'NoReturn':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        Raises:
            ValueError: Always. :class:`~pcapkit.protocols.application.ngap.protocol.Criticality` is an ``ENUMERATED``
                with no extension marker, so a fourth value cannot be encoded and a
                lookup for one is a bug rather than a newer specification.

        """
        raise ValueError('%r is not a valid %s' % (value, cls.__name__))




##############################################################################
# Value tree conversion.
##############################################################################


def _convert(value: 'Any') -> 'Any':
    """Convert a |pycrate|_ decoded value into :mod:`pcapkit` data models.

    Args:
        value: A node of the tree returned by ``NGAP_PDU.get_val()``.

    Returns:
        The same tree, with mappings as
        :class:`~pcapkit.protocols.application.ngap.data.Sequence`, ``CHOICE``
        pairs as :class:`~pcapkit.protocols.application.ngap.data.Choice`, and
        ``BIT STRING`` pairs as
        :class:`~pcapkit.protocols.application.ngap.data.BitString`.

    Notes:
        The 2-tuple shapes are told apart by their first element, which is
        unambiguous: |pycrate|_ spells a ``CHOICE`` as ``(name, value)`` with a
        :obj:`str` name and a ``BIT STRING`` as ``(bits, length)`` with two
        :obj:`int`. Any other tuple is passed through with its members
        converted, so an ASN.1 construct not listed above degrades to its own
        shape rather than being mangled into one of these.

    """
    if isinstance(value, dict):
        return Data_Sequence({key: _convert(val) for key, val in value.items()})
    if isinstance(value, list):
        return [_convert(item) for item in value]
    if isinstance(value, tuple):
        if len(value) == 2:
            if isinstance(value[0], str):
                return Data_Choice(name=value[0], value=_convert(value[1]))
            if isinstance(value[0], int) and isinstance(value[1], int):
                return Data_BitString(value=value[0], length=value[1])
        return tuple(_convert(item) for item in value)
    return value


def _revert(value: 'Any') -> 'Any':
    """Convert :mod:`pcapkit` data models back into a |pycrate|_ value.

    Args:
        value: A node of a tree produced by :func:`_convert`, or the equivalent
            plain Python value.

    Returns:
        The same tree in the shape ``NGAP_PDU.set_val()`` expects.

    Notes:
        :class:`~pcapkit.protocols.application.ngap.data.Choice` and
        :class:`~pcapkit.protocols.application.ngap.data.BitString` are tested
        before :class:`~pcapkit.corekit.infoclass.Info`, since they are
        subclasses of it and would otherwise be reverted to mappings.

    """
    if isinstance(value, Data_Choice):
        return (value.name, _revert(value.value))
    if isinstance(value, Data_BitString):
        return (value.value, value.length)
    if isinstance(value, Info):
        return {key: _revert(value[key]) for key in value}
    if isinstance(value, list):
        return [_revert(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_revert(item) for item in value)
    return value


##############################################################################
# Protocol.
##############################################################################


class NGAP(Application[Data_NGAP, Schema_NGAP],
           data=Data_NGAP, schema=Schema_NGAP):
    """This class implements NG Application Protocol.

    .. versionchanged:: 1.6.0

       ``procedure`` and ``criticality`` of :meth:`make` take a member or an
       :class:`int` code, resolved with the enumeration's ``get``; a name or a
       :obj:`bool` raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`,
       where a name resolved to its member and a :obj:`bool` was taken as a
       code (:issue:`2594`).

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["NG Application Protocol"]':
        """Name of current protocol."""
        return 'NG Application Protocol'

    @property
    def length(self) -> 'int':
        """Header length of current protocol.

        NGAP prefixes its payload with nothing and carries no next layer, so the
        whole ``NGAP-PDU`` *is* the header and this is its length. That is not
        :meth:`self.__length_hint__ <NGAP.__length_hint__>`, which reports the
        four-octet prefix common to every PDU rather than this PDU's size.

        """
        return len(self.__header__.data)

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_NGAP':  # pylint: disable=unused-argument
        """Read NG Application Protocol (NGAP).

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If |pycrate|_ is not installed, if the payload is
                not a well formed aligned PER ``NGAP-PDU``, or if octets follow
                the ``NGAP-PDU``. A whole octet left over is not part of it: an
                SCTP DATA chunk holds one whole message (RFC 9260 §1.3, §3.3.1),
                and APER pads to the octet (X.691 (02/2021) §11.1.4-5).

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        pdu = load_pycrate()
        if pdu is None:
            raise ProtocolError('NGAP: decoding needs the optional "pycrate" dependency, '
                                'which is not installed; pip install pypcapkit[NGAP]')

        with _PDU_LOCK:
            try:
                # NOTE: No `reset_val()`: it costs ~105 ms against the decode's
                # ~0.15 ms, and `from_aper()` overwrites the stored value anyway.
                from pycrate_core.charpy import Charpy  # pylint: disable=import-outside-toplevel

                # NOTE: Decoded from a `Charpy`, so the unconsumed suffix that a
                # bare `from_aper(bytes)` ignores can be measured.
                char = Charpy(schema.data)
                pdu.from_aper(char)
                trailing = char.len_byte()
                if trailing:
                    raise ProtocolError(f'NGAP: {trailing} octet(s) after the NGAP-PDU')
                kind, body = pdu.get_val()

                message, message_body = body['value']

                # NOTE: Converted under the lock: `get_val()` returns the decoder's own
                # containers, which the next decode through this shared object rewrites.
                value = _convert(message_body)

                ies = []  # type: list[Data_IE]
                for ie in value.get('protocolIEs') or ():
                    choice = ie['value']
                    ies.append(Data_IE(
                        id=Enum_ProtocolIE.get(ie['id']),
                        criticality=Criticality.get(ie['criticality']),
                        type=choice.name,
                        value=choice.value,
                    ))

                ngap = Data_NGAP(
                    kind=PDUKind(kind),
                    procedure=Enum_ProcedureCode.get(body['procedureCode']),
                    criticality=Criticality.get(body['criticality']),
                    message=message,
                    ies=tuple(ies),
                    value=value,
                )
            except ProtocolError:
                # NOTE: Already specific, such as the trailing-octet check, so
                # not relabelled "malformed NGAP-PDU" below.
                raise
            except Exception as exc:
                # NOTE: `Exception` on purpose: pycrate raises `ASN1Err`, `CharpyErr`,
                # `KeyError` or `IndexError` (when truncated), none a pcapkit exception.
                raise ProtocolError(f'NGAP: malformed NGAP-PDU: {exc}') from exc
        return ngap

    def make(self,
             kind: 'PDUKind | str' = PDUKind.INITIATING_MESSAGE,
             procedure: 'Optional[Enum_ProcedureCode | int]' = None,
             criticality: 'Criticality | int' = Criticality.reject,
             message: 'Optional[str]' = None,
             value: 'Any' = None,
             data: 'Optional[bytes]' = None,
             **kwargs: 'Any') -> 'Schema_NGAP':
        """Make (construct) packet data.

        Args:
            kind: Which ``NGAP-PDU`` alternative to construct.
            procedure: Procedure code.
            criticality: Criticality of the procedure.
            message: Name of the message type, e.g. ``NGSetupRequest``.
            value: Message body, either as
                :class:`~pcapkit.protocols.application.ngap.data.Sequence` from
                a previous :meth:`read` or as the plain Python value
                |pycrate|_ expects.
            data: Pre-encoded ``NGAP-PDU``. When given, it is used verbatim and
                every other argument is ignored, which is also the only path
                that does not need |pycrate|_.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``data`` is not given and either ``procedure`` or
                ``message`` is missing, if ``procedure`` (``0..255``) or
                ``criticality`` (two bits) is a name, a :obj:`bool`, or a
                member or code its field cannot carry, if |pycrate|_ is not
                installed, or if the arguments do not describe a message the
                specification can encode.

        """
        if data is not None:
            return Schema_NGAP(data=bytes(data))

        if procedure is None or message is None:
            raise ProtocolError("NGAP: 'procedure' and 'message' are required "
                                "when 'data' is not given")
        # NOTE: ProcedureCode is INTEGER (0..255); Criticality, an ENUMERATED of
        # three, takes two bits in aligned PER (3GPP TS 38.413).
        procedure_ = self._make_index(procedure, Enum_ProcedureCode, bits=8, name='procedure code')
        criticality_ = self._make_index(criticality, Criticality, bits=2, name='criticality')

        pdu = load_pycrate()
        if pdu is None:
            raise ProtocolError('NGAP: encoding needs the optional "pycrate" dependency, '
                                'which is not installed; pip install pypcapkit[NGAP]')

        with _PDU_LOCK:
            try:
                pdu.set_val((PDUKind(kind).value, {
                    'procedureCode': int(procedure_),
                    'criticality': getattr(criticality_, 'name', criticality_),
                    'value': (message, _revert(value)),
                }))
                encoded = pdu.to_aper()
            except Exception as exc:
                # NOTE: same reasoning as the read path -- pycrate's encoder
                # raises from its own hierarchies, none of them pcapkit's.
                raise ProtocolError(f'NGAP: cannot encode NGAP-PDU: {exc}') from exc
        return Schema_NGAP(data=encoded)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object.

        Every ``NGAP-PDU`` opens with the same four octets under aligned PER --
        the ``CHOICE`` index, the procedure code, the criticality, and the
        first octet of the open type's length determinant -- so four is the
        fixed prefix NGAP has in place of a header. It is not a minimum PDU
        length: the smallest complete ``NGAP-PDU`` measured here, a message
        whose ``protocolIEs`` list is empty, is seven octets.

        """
        return 4

    @classmethod
    def __index__(cls) -> 'int':  # type: ignore[override]
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_ service names and
            port numbers: SCTP port 38412, the port of
            :attr:`SCTP.ng_control <pcapkit.const.reg.apptype.sctp.SCTP.ng_control>`
            as an :class:`int`.
            :attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__>`
            dispatches by payload protocol identifier rather than by port, so
            this value keys no dispatch (:ref:`registry-protocol-index`).

        .. _IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

        .. versionchanged:: 1.6.0

           Returns SCTP port 38412, where it raised
           :exc:`~pcapkit.utilities.exceptions.IntError` (:issue:`2627`).

        """
        return int(Enum_SCTP.ng_control)  # type: ignore[call-overload]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_NGAP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'kind': data.kind,
            'procedure': data.procedure,
            'criticality': data.criticality,
            'message': data.message,
            'value': data.value,
            'data': None,
        }
