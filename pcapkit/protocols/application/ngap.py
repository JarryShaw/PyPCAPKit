# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""NGAP - NG application protocol
====================================

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

Generic conversion, not 81 hand-written procedures
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
  procedure enumerations below were generated from ``NGAP_Constants`` of
  |pycrate|_ 0.8.1 (Release-18-era: 81 procedure codes, 438 protocol IE IDs,
  highest 443). A |pycrate|_ that carries a newer NGAP will decode IEs that
  :class:`ProcedureCode` and :class:`ProtocolIE` do not name; both extend
  themselves at lookup time rather than failing, so such a value is reported
  as ``Unassigned_<n>``.
* **NGAP over a fragmented SCTP association is not reassembled.** A DATA chunk
  is decoded on its own, so an ``NGAP-PDU`` split across chunks by SCTP
  fragmentation fails to decode rather than being reassembled first.
* **Private IEs (``PrivateMessage``) carry no schema.** Their contents are
  vendor defined, so the generic conversion reports whatever ASN.1 shape the
  encoding declares and cannot name the fields.

.. |pycrate| replace:: ``pycrate``
.. _pycrate: https://github.com/pycrate-org/pycrate

.. [*] https://en.wikipedia.org/wiki/NG_Application_Protocol

"""
import threading
from typing import TYPE_CHECKING

from aenum import IntEnum, extend_enum

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.data.application.ngap import IE as Data_IE
from pcapkit.protocols.data.application.ngap import NGAP as Data_NGAP
from pcapkit.protocols.data.application.ngap import BitString as Data_BitString
from pcapkit.protocols.data.application.ngap import Choice as Data_Choice
from pcapkit.protocols.data.application.ngap import Sequence as Data_Sequence
from pcapkit.protocols.schema.application.ngap import NGAP as Schema_NGAP
from pcapkit.utilities.compat import StrEnum
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['NGAP', 'PDUKind', 'Criticality', 'ProcedureCode', 'ProtocolIE']

#: Cached ``NGAP-PDU`` object, c.f. :func:`load_pycrate`. :data:`NotImplemented`
#: means the import has not been attempted yet, and :data:`None` that it was
#: attempted and |pycrate|_ is not installed -- three states, so a capture full
#: of NGAP packets does not pay for a failing import on every frame.
_PYCRATE = NotImplemented  # type: Any

#: Guards the module-level ``NGAP-PDU`` object returned by :func:`load_pycrate`.
#: That object is *stateful*: :meth:`from_aper` stores the decoded value on it
#: and :meth:`get_val` hands back the decoder's own containers rather than
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
# These are 3GPP TS 38.413 specification values, not an IANA registry with a
# crawlable page, so they live here rather than in pcapkit.const and have no
# vendor crawler. The SCTP payload protocol identifiers *are* IANA's, and are
# used from pcapkit.const.sctp.payload_protocol_identifier rather than
# duplicated here.
#
# The two large enumerations below were generated from pycrate 0.8.1's
# ``NGAP_Constants`` at authoring time and pasted in. Nothing at import time
# needs pycrate to define them.
##############################################################################


class PDUKind(StrEnum):
    """Which alternative of the ``NGAP-PDU`` ``CHOICE`` a PDU is.

    The values are spelled as the ASN.1 identifiers, so that a name decoded by
    |pycrate|_ resolves by value.

    """

    #: A procedure's request, or a class 2 procedure's only message.
    INITIATING_MESSAGE = 'initiatingMessage'
    #: A class 1 procedure's successful response.
    SUCCESSFUL_OUTCOME = 'successfulOutcome'
    #: A class 1 procedure's unsuccessful response.
    UNSUCCESSFUL_OUTCOME = 'unsuccessfulOutcome'


class Criticality(IntEnum):
    """[Criticality] What a receiver must do with an IE it does not understand.

    Members are named for the ASN.1 identifiers rather than upper-cased, so
    that :meth:`Criticality.get` resolves a name decoded by |pycrate|_ through
    the standard member map. The values are the ``ENUMERATED`` indices, which
    is what goes on the wire.

    """

    #: Reject the whole message.
    reject = 0
    #: Ignore the IE and carry on.
    ignore = 1
    #: Ignore the IE, carry on, and report it.
    notify = 2

    @staticmethod
    def get(key: 'int | str | Criticality') -> 'Criticality':
        """Backport support for original codes.

        Unlike :meth:`ProcedureCode.get` and :meth:`ProtocolIE.get`, this takes
        no ``default``: those two extend themselves through
        :func:`~aenum.extend_enum` when a newer specification names a code this
        release does not, which is the right answer for a registry that grows.
        ``Criticality`` cannot grow. It is an ASN.1 ``ENUMERATED`` with no
        extension marker, so a fourth value is unencodable and a lookup for one
        is a bug rather than a version skew -- see :meth:`_missing_`. A
        ``default`` parameter here would have to be ignored, and one that is
        declared, documented and ignored is worse than one that is absent.

        Args:
            key: Key to get enum item.

        Returns:
            The matching member.

        Raises:
            ValueError: If ``key`` names no member. Raised for an unknown name as
                well as an unknown value, so that the two ways of getting this
                wrong do not report differently.

        :meta private:
        """
        if isinstance(key, Criticality):
            return key
        if isinstance(key, int):
            return Criticality(key)
        try:
            return Criticality[key]  # type: ignore[misc]
        except KeyError:
            raise ValueError('%r is not a valid %s' % (key, Criticality.__name__)) from None

    @classmethod
    def _missing_(cls, value: 'int') -> 'NoReturn':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        Raises:
            ValueError: Always. ``Criticality`` is an ``ENUMERATED`` with no
                extension marker, so a fourth value cannot be encoded and a
                lookup for one is a bug rather than a newer specification.

        """
        raise ValueError('%r is not a valid %s' % (value, cls.__name__))


class ProcedureCode(IntEnum):
    """[ProcedureCode] NGAP elementary procedure codes, 3GPP TS 38.413."""

    AMFConfigurationUpdate = 0
    AMFStatusIndication = 1
    CellTrafficTrace = 2
    DeactivateTrace = 3
    DownlinkNASTransport = 4
    DownlinkNonUEAssociatedNRPPaTransport = 5
    DownlinkRANConfigurationTransfer = 6
    DownlinkRANStatusTransfer = 7
    DownlinkUEAssociatedNRPPaTransport = 8
    ErrorIndication = 9
    HandoverCancel = 10
    HandoverNotification = 11
    HandoverPreparation = 12
    HandoverResourceAllocation = 13
    InitialContextSetup = 14
    InitialUEMessage = 15
    LocationReportingControl = 16
    LocationReportingFailureIndication = 17
    LocationReport = 18
    NASNonDeliveryIndication = 19
    NGReset = 20
    NGSetup = 21
    OverloadStart = 22
    OverloadStop = 23
    Paging = 24
    PathSwitchRequest = 25
    PDUSessionResourceModify = 26
    PDUSessionResourceModifyIndication = 27
    PDUSessionResourceRelease = 28
    PDUSessionResourceSetup = 29
    PDUSessionResourceNotify = 30
    PrivateMessage = 31
    PWSCancel = 32
    PWSFailureIndication = 33
    PWSRestartIndication = 34
    RANConfigurationUpdate = 35
    RerouteNASRequest = 36
    RRCInactiveTransitionReport = 37
    TraceFailureIndication = 38
    TraceStart = 39
    UEContextModification = 40
    UEContextRelease = 41
    UEContextReleaseRequest = 42
    UERadioCapabilityCheck = 43
    UERadioCapabilityInfoIndication = 44
    UETNLABindingRelease = 45
    UplinkNASTransport = 46
    UplinkNonUEAssociatedNRPPaTransport = 47
    UplinkRANConfigurationTransfer = 48
    UplinkRANStatusTransfer = 49
    UplinkUEAssociatedNRPPaTransport = 50
    WriteReplaceWarning = 51
    SecondaryRATDataUsageReport = 52
    UplinkRIMInformationTransfer = 53
    DownlinkRIMInformationTransfer = 54
    RetrieveUEInformation = 55
    UEInformationTransfer = 56
    RANCPRelocationIndication = 57
    UEContextResume = 58
    UEContextSuspend = 59
    UERadioCapabilityIDMapping = 60
    HandoverSuccess = 61
    UplinkRANEarlyStatusTransfer = 62
    DownlinkRANEarlyStatusTransfer = 63
    AMFCPRelocationIndication = 64
    ConnectionEstablishmentIndication = 65
    BroadcastSessionModification = 66
    BroadcastSessionRelease = 67
    BroadcastSessionSetup = 68
    DistributionSetup = 69
    DistributionRelease = 70
    MulticastSessionActivation = 71
    MulticastSessionDeactivation = 72
    MulticastSessionUpdate = 73
    MulticastGroupPaging = 74
    BroadcastSessionReleaseRequired = 75
    TimingSynchronisationStatus = 76
    TimingSynchronisationStatusReport = 77
    MTCommunicationHandling = 78
    RANPagingRequest = 79
    BroadcastSessionTransport = 80

    @staticmethod
    def get(key: 'int | str | ProcedureCode', default: 'int' = -1) -> 'ProcedureCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, ProcedureCode):
            return key
        if isinstance(key, int):
            return ProcedureCode(key)
        if key not in ProcedureCode._member_map_:  # pylint: disable=no-member
            return extend_enum(ProcedureCode, key, default)
        return ProcedureCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ProcedureCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)


class ProtocolIE(IntEnum):
    """[ProtocolIE-ID] NGAP protocol IE identifiers, 3GPP TS 38.413.

    An IE's ID name and the name of the open type its value is keyed under
    differ in places -- IE 21 is ``id-DefaultPagingDRX`` but its value arrives
    keyed ``PagingDRX`` -- so
    :attr:`IE.type <pcapkit.protocols.data.application.ngap.IE.type>` carries
    the latter alongside this.

    """

    AllowedNSSAI = 0
    AMFName = 1
    AMFOverloadResponse = 2
    AMFSetID = 3
    AMF_TNLAssociationFailedToSetupList = 4
    AMF_TNLAssociationSetupList = 5
    AMF_TNLAssociationToAddList = 6
    AMF_TNLAssociationToRemoveList = 7
    AMF_TNLAssociationToUpdateList = 8
    AMFTrafficLoadReductionIndication = 9
    AMF_UE_NGAP_ID = 10
    AssistanceDataForPaging = 11
    BroadcastCancelledAreaList = 12
    BroadcastCompletedAreaList = 13
    CancelAllWarningMessages = 14
    Cause = 15
    CellIDListForRestart = 16
    ConcurrentWarningMessageInd = 17
    CoreNetworkAssistanceInformationForInactive = 18
    CriticalityDiagnostics = 19
    DataCodingScheme = 20
    DefaultPagingDRX = 21
    DirectForwardingPathAvailability = 22
    EmergencyAreaIDListForRestart = 23
    EmergencyFallbackIndicator = 24
    EUTRA_CGI = 25
    FiveG_S_TMSI = 26
    GlobalRANNodeID = 27
    GUAMI = 28
    HandoverType = 29
    IMSVoiceSupportIndicator = 30
    IndexToRFSP = 31
    InfoOnRecommendedCellsAndRANNodesForPaging = 32
    LocationReportingRequestType = 33
    MaskedIMEISV = 34
    MessageIdentifier = 35
    MobilityRestrictionList = 36
    NASC = 37
    NAS_PDU = 38
    NASSecurityParametersFromNGRAN = 39
    NewAMF_UE_NGAP_ID = 40
    NewSecurityContextInd = 41
    NGAP_Message = 42
    NGRAN_CGI = 43
    NGRANTraceID = 44
    NR_CGI = 45
    NRPPa_PDU = 46
    NumberOfBroadcastsRequested = 47
    OldAMF = 48
    OverloadStartNSSAIList = 49
    PagingDRX = 50
    PagingOrigin = 51
    PagingPriority = 52
    PDUSessionResourceAdmittedList = 53
    PDUSessionResourceFailedToModifyListModRes = 54
    PDUSessionResourceFailedToSetupListCxtRes = 55
    PDUSessionResourceFailedToSetupListHOAck = 56
    PDUSessionResourceFailedToSetupListPSReq = 57
    PDUSessionResourceFailedToSetupListSURes = 58
    PDUSessionResourceHandoverList = 59
    PDUSessionResourceListCxtRelCpl = 60
    PDUSessionResourceListHORqd = 61
    PDUSessionResourceModifyListModCfm = 62
    PDUSessionResourceModifyListModInd = 63
    PDUSessionResourceModifyListModReq = 64
    PDUSessionResourceModifyListModRes = 65
    PDUSessionResourceNotifyList = 66
    PDUSessionResourceReleasedListNot = 67
    PDUSessionResourceReleasedListPSAck = 68
    PDUSessionResourceReleasedListPSFail = 69
    PDUSessionResourceReleasedListRelRes = 70
    PDUSessionResourceSetupListCxtReq = 71
    PDUSessionResourceSetupListCxtRes = 72
    PDUSessionResourceSetupListHOReq = 73
    PDUSessionResourceSetupListSUReq = 74
    PDUSessionResourceSetupListSURes = 75
    PDUSessionResourceToBeSwitchedDLList = 76
    PDUSessionResourceSwitchedList = 77
    PDUSessionResourceToReleaseListHOCmd = 78
    PDUSessionResourceToReleaseListRelCmd = 79
    PLMNSupportList = 80
    PWSFailedCellIDList = 81
    RANNodeName = 82
    RANPagingPriority = 83
    RANStatusTransfer_TransparentContainer = 84
    RAN_UE_NGAP_ID = 85
    RelativeAMFCapacity = 86
    RepetitionPeriod = 87
    ResetType = 88
    RoutingID = 89
    RRCEstablishmentCause = 90
    RRCInactiveTransitionReportRequest = 91
    RRCState = 92
    SecurityContext = 93
    SecurityKey = 94
    SerialNumber = 95
    ServedGUAMIList = 96
    SliceSupportList = 97
    SONConfigurationTransferDL = 98
    SONConfigurationTransferUL = 99
    SourceAMF_UE_NGAP_ID = 100
    SourceToTarget_TransparentContainer = 101
    SupportedTAList = 102
    TAIListForPaging = 103
    TAIListForRestart = 104
    TargetID = 105
    TargetToSource_TransparentContainer = 106
    TimeToWait = 107
    TraceActivation = 108
    TraceCollectionEntityIPAddress = 109
    UEAggregateMaximumBitRate = 110
    UE_associatedLogicalNG_connectionList = 111
    UEContextRequest = 112
    UE_NGAP_IDs = 114
    UEPagingIdentity = 115
    UEPresenceInAreaOfInterestList = 116
    UERadioCapability = 117
    UERadioCapabilityForPaging = 118
    UESecurityCapabilities = 119
    UnavailableGUAMIList = 120
    UserLocationInformation = 121
    WarningAreaList = 122
    WarningMessageContents = 123
    WarningSecurityInfo = 124
    WarningType = 125
    AdditionalUL_NGU_UP_TNLInformation = 126
    DataForwardingNotPossible = 127
    DL_NGU_UP_TNLInformation = 128
    NetworkInstance = 129
    PDUSessionAggregateMaximumBitRate = 130
    PDUSessionResourceFailedToModifyListModCfm = 131
    PDUSessionResourceFailedToSetupListCxtFail = 132
    PDUSessionResourceListCxtRelReq = 133
    PDUSessionType = 134
    QosFlowAddOrModifyRequestList = 135
    QosFlowSetupRequestList = 136
    QosFlowToReleaseList = 137
    SecurityIndication = 138
    UL_NGU_UP_TNLInformation = 139
    UL_NGU_UP_TNLModifyList = 140
    WarningAreaCoordinates = 141
    PDUSessionResourceSecondaryRATUsageList = 142
    HandoverFlag = 143
    SecondaryRATUsageInformation = 144
    PDUSessionResourceReleaseResponseTransfer = 145
    RedirectionVoiceFallback = 146
    UERetentionInformation = 147
    S_NSSAI = 148
    PSCellInformation = 149
    LastEUTRAN_PLMNIdentity = 150
    MaximumIntegrityProtectedDataRate_DL = 151
    AdditionalDLForwardingUPTNLInformation = 152
    AdditionalDLUPTNLInformationForHOList = 153
    AdditionalNGU_UP_TNLInformation = 154
    AdditionalDLQosFlowPerTNLInformation = 155
    SecurityResult = 156
    ENDC_SONConfigurationTransferDL = 157
    ENDC_SONConfigurationTransferUL = 158
    OldAssociatedQosFlowList_ULendmarkerexpected = 159
    CNTypeRestrictionsForEquivalent = 160
    CNTypeRestrictionsForServing = 161
    NewGUAMI = 162
    ULForwarding = 163
    ULForwardingUP_TNLInformation = 164
    CNAssistedRANTuning = 165
    CommonNetworkInstance = 166
    NGRAN_TNLAssociationToRemoveList = 167
    TNLAssociationTransportLayerAddressNGRAN = 168
    EndpointIPAddressAndPort = 169
    LocationReportingAdditionalInfo = 170
    SourceToTarget_AMFInformationReroute = 171
    AdditionalULForwardingUPTNLInformation = 172
    SCTP_TLAs = 173
    SelectedPLMNIdentity = 174
    RIMInformationTransfer = 175
    GUAMIType = 176
    SRVCCOperationPossible = 177
    TargetRNC_ID = 178
    RAT_Information = 179
    ExtendedRATRestrictionInformation = 180
    QosMonitoringRequest = 181
    SgNB_UE_X2AP_ID = 182
    AdditionalRedundantDL_NGU_UP_TNLInformation = 183
    AdditionalRedundantDLQosFlowPerTNLInformation = 184
    AdditionalRedundantNGU_UP_TNLInformation = 185
    AdditionalRedundantUL_NGU_UP_TNLInformation = 186
    CNPacketDelayBudgetDL = 187
    CNPacketDelayBudgetUL = 188
    ExtendedPacketDelayBudget = 189
    RedundantCommonNetworkInstance = 190
    RedundantDL_NGU_TNLInformationReused = 191
    RedundantDL_NGU_UP_TNLInformation = 192
    RedundantDLQosFlowPerTNLInformation = 193
    RedundantQosFlowIndicator = 194
    RedundantUL_NGU_UP_TNLInformation = 195
    TSCTrafficCharacteristics = 196
    RedundantPDUSessionInformation = 197
    UsedRSNInformation = 198
    IAB_Authorized = 199
    IAB_Supported = 200
    IABNodeIndication = 201
    NB_IoT_PagingDRX = 202
    NB_IoT_Paging_eDRXInfo = 203
    NB_IoT_DefaultPagingDRX = 204
    Enhanced_CoverageRestriction = 205
    Extended_ConnectedTime = 206
    PagingAssisDataforCEcapabUE = 207
    WUS_Assistance_Information = 208
    UE_DifferentiationInfo = 209
    NB_IoT_UEPriority = 210
    UL_CP_SecurityInformation = 211
    DL_CP_SecurityInformation = 212
    TAI = 213
    UERadioCapabilityForPagingOfNB_IoT = 214
    LTEV2XServicesAuthorized = 215
    NRV2XServicesAuthorized = 216
    LTEUESidelinkAggregateMaximumBitrate = 217
    NRUESidelinkAggregateMaximumBitrate = 218
    PC5QoSParameters = 219
    AlternativeQoSParaSetList = 220
    CurrentQoSParaSetIndex = 221
    CEmodeBrestricted = 222
    EUTRA_PagingeDRXInformation = 223
    CEmodeBSupport_Indicator = 224
    LTEM_Indication = 225
    EndIndication = 226
    EDT_Session = 227
    UECapabilityInfoRequest = 228
    PDUSessionResourceFailedToResumeListRESReq = 229
    PDUSessionResourceFailedToResumeListRESRes = 230
    PDUSessionResourceSuspendListSUSReq = 231
    PDUSessionResourceResumeListRESReq = 232
    PDUSessionResourceResumeListRESRes = 233
    UE_UP_CIoT_Support = 234
    Suspend_Request_Indication = 235
    Suspend_Response_Indication = 236
    RRC_Resume_Cause = 237
    RGLevelWirelineAccessCharacteristics = 238
    W_AGFIdentityInformation = 239
    GlobalTNGF_ID = 240
    GlobalTWIF_ID = 241
    GlobalW_AGF_ID = 242
    UserLocationInformationW_AGF = 243
    UserLocationInformationTNGF = 244
    AuthenticatedIndication = 245
    TNGFIdentityInformation = 246
    TWIFIdentityInformation = 247
    UserLocationInformationTWIF = 248
    DataForwardingResponseERABList = 249
    IntersystemSONConfigurationTransferDL = 250
    IntersystemSONConfigurationTransferUL = 251
    SONInformationReport = 252
    UEHistoryInformationFromTheUE = 253
    ManagementBasedMDTPLMNList = 254
    MDTConfiguration = 255
    PrivacyIndicator = 256
    TraceCollectionEntityURI = 257
    NPN_Support = 258
    NPN_AccessInformation = 259
    NPN_PagingAssistanceInformation = 260
    NPN_MobilityInformation = 261
    TargettoSource_Failure_TransparentContainer = 262
    NID = 263
    UERadioCapabilityID = 264
    UERadioCapability_EUTRA_Format = 265
    DAPSRequestInfo = 266
    DAPSResponseInfoList = 267
    EarlyStatusTransfer_TransparentContainer = 268
    NotifySourceNGRANNode = 269
    ExtendedSliceSupportList = 270
    ExtendedTAISliceSupportList = 271
    ConfiguredTACIndication = 272
    Extended_RANNodeName = 273
    Extended_AMFName = 274
    GlobalCable_ID = 275
    QosMonitoringReportingFrequency = 276
    QosFlowParametersList = 277
    QosFlowFeedbackList = 278
    BurstArrivalTimeDownlink = 279
    ExtendedUEIdentityIndexValue = 280
    PduSessionExpectedUEActivityBehaviour = 281
    MicoAllPLMN = 282
    QosFlowFailedToSetupList = 283
    SourceTNLAddrInfo = 284
    ExtendedReportIntervalMDT = 285
    SourceNodeID = 286
    NRNTNTAIInformation = 287
    UEContextReferenceAtSource = 288
    LastVisitedPSCellList = 289
    IntersystemSONInformationRequest = 290
    IntersystemSONInformationReply = 291
    EnergySavingIndication = 292
    IntersystemResourceStatusUpdate = 293
    SuccessfulHandoverReportList = 294
    MBS_AreaSessionID = 295
    MBS_QoSFlowsToBeSetupList = 296
    MBS_QoSFlowsToBeSetupModList = 297
    MBS_ServiceArea = 298
    MBS_SessionID = 299
    MBS_DistributionReleaseRequestTransfer = 300
    MBS_DistributionSetupRequestTransfer = 301
    MBS_DistributionSetupResponseTransfer = 302
    MBS_DistributionSetupUnsuccessfulTransfer = 303
    MulticastSessionActivationRequestTransfer = 304
    MulticastSessionDeactivationRequestTransfer = 305
    MulticastSessionUpdateRequestTransfer = 306
    MulticastGroupPagingAreaList = 307
    MBS_SupportIndicator = 309
    MBSSessionFailedtoSetupList = 310
    MBSSessionFailedtoSetuporModifyList = 311
    MBSSessionSetupResponseList = 312
    MBSSessionSetuporModifyResponseList = 313
    MBSSessionSetupFailureTransfer = 314
    MBSSessionSetupRequestTransfer = 315
    MBSSessionSetupResponseTransfer = 316
    MBSSessionToReleaseList = 317
    MBSSessionSetupRequestList = 318
    MBSSessionSetuporModifyRequestList = 319
    MBS_ActiveSessionInformation_SourcetoTargetList = 323
    MBS_ActiveSessionInformation_TargettoSourceList = 324
    OnboardingSupport = 325
    TimeSyncAssistanceInfo = 326
    SurvivalTime = 327
    QMCConfigInfo = 328
    QMCDeactivation = 329
    PDUSessionPairID = 331
    NR_PagingeDRXInformation = 332
    RedCapIndication = 333
    TargetNSSAIInformation = 334
    UESliceMaximumBitRateList = 335
    M4ReportAmount = 336
    M5ReportAmount = 337
    M6ReportAmount = 338
    M7ReportAmount = 339
    IncludeBeamMeasurementsIndication = 340
    ExcessPacketDelayThresholdConfiguration = 341
    PagingCause = 342
    PagingCauseIndicationForVoiceService = 343
    PEIPSassistanceInformation = 344
    FiveG_ProSeAuthorized = 345
    FiveG_ProSeUEPC5AggregateMaximumBitRate = 346
    FiveG_ProSePC5QoSParameters = 347
    MBSSessionModificationFailureTransfer = 348
    MBSSessionModificationRequestTransfer = 349
    MBSSessionModificationResponseTransfer = 350
    MBS_QoSFlowToReleaseList = 351
    MBS_SessionTNLInfo5GC = 352
    TAINSAGSupportList = 353
    SourceNodeTNLAddrInfo = 354
    NGAPIESupportInformationRequestList = 355
    NGAPIESupportInformationResponseList = 356
    MBS_SessionFSAIDList = 357
    MBSSessionReleaseResponseTransfer = 358
    ManagementBasedMDTPLMNModificationList = 359
    EarlyMeasurement = 360
    BeamMeasurementsReportConfiguration = 361
    HFCNode_ID_new = 362
    GlobalCable_ID_new = 363
    TargetHomeENB_ID = 364
    HashedUEIdentityIndexValue = 365
    ExtendedMobilityInformation = 366
    NetworkControlledRepeaterAuthorized = 367
    AdditionalCancelledlocationReportingReferenceIDList = 368
    Selected_Target_SNPN_Identity = 369
    EquivalentSNPNsList = 370
    SelectedNID = 371
    SupportedUETypeList = 372
    AerialUEsubscriptionInformation = 373
    NR_A2X_ServicesAuthorized = 374
    LTE_A2X_ServicesAuthorized = 375
    NR_A2X_UE_PC5_AggregateMaximumBitRate = 376
    LTE_A2X_UE_PC5_AggregateMaximumBitRate = 377
    A2X_PC5_QoS_Parameters = 378
    FiveGProSeLayer2Multipath = 379
    FiveGProSeLayer2UEtoUERelay = 380
    FiveGProSeLayer2UEtoUERemote = 381
    CandidateRelayUEInformationList = 382
    SuccessfulPSCellChangeReportList = 383
    IntersystemMobilityFailureforVoiceFallback = 384
    TargetCellCRNTI = 385
    TimeSinceFailure = 386
    RANTimingSynchronisationStatusInfo = 387
    RAN_TSSRequestType = 388
    RAN_TSSScope = 389
    ClockQualityReportingControlInfo = 390
    RANfeedbacktype = 391
    QoSFlowTSCList = 392
    TSCTrafficCharacteristicsFeedback = 393
    DownlinkTLContainer = 394
    UplinkTLContainer = 395
    ANPacketDelayBudgetUL = 396
    QosFlowAdditionalInfoList = 397
    AssistanceInformationQoE_Meas = 398
    MBSCommServiceType = 399
    MobileIAB_Authorized = 400
    MobileIAB_MTUserLocationInformation = 401
    MobileIABNodeIndication = 402
    NoPDUSessionIndication = 403
    MobileIAB_Supported = 404
    CN_MT_CommunicationHandling = 405
    FiveGCAction = 406
    PagingPolicyDifferentiation = 407
    DL_Signalling = 408
    PNI_NPN_AreaScopeofMDT = 409
    PNI_NPNBasedMDT = 410
    SNPN_CellBasedMDT = 411
    SNPN_TAIBasedMDT = 412
    SNPN_BasedMDT = 413
    Partially_Allowed_NSSAI = 414
    AssociatedSessionID = 415
    MBS_AssistanceInformation = 416
    BroadcastTransportFailureTransfer = 417
    BroadcastTransportRequestTransfer = 418
    BroadcastTransportResponseTransfer = 419
    TimeBasedHandoverInformation = 420
    DLDiscarding = 421
    PDUsetQoSParameters = 422
    PDUSetbasedHandlingIndicator = 423
    N6JitterInformation = 424
    ECNMarkingorCongestionInformationReportingRequest = 425
    ECNMarkingorCongestionInformationReportingStatus = 426
    ERedCapIndication = 427
    XrDeviceWith2Rx = 428
    UserPlaneErrorIndicator = 429
    SLPositioningRangingServiceInfo = 430
    PDUSessionListMTCommHReq = 431
    MaximumDataBurstVolume = 432
    MN_only_MDT_collection = 433
    MBS_NGUFailureIndication = 434
    UserPlaneFailureIndication = 435
    UserPlaneFailureIndicationReport = 436
    SourceSN_to_TargetSN_QMCInfo = 437
    QoERVQoEReportingPaths = 438
    UserLocationInformationN3IWF_without_PortNumber = 439
    AUN3DeviceAccessInfo = 440
    TAIMBSSupportList = 441
    ExtendedBackupAMFName = 442
    ExtendedOldAMF = 443

    @staticmethod
    def get(key: 'int | str | ProtocolIE', default: 'int' = -1) -> 'ProtocolIE':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, ProtocolIE):
            return key
        if isinstance(key, int):
            return ProtocolIE(key)
        if key not in ProtocolIE._member_map_:  # pylint: disable=no-member
            return extend_enum(ProtocolIE, key, default)
        return ProtocolIE[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ProtocolIE':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)


##############################################################################
# Value tree conversion.
##############################################################################


def _convert(value: 'Any') -> 'Any':
    """Convert a |pycrate|_ decoded value into :mod:`pcapkit` data models.

    Args:
        value: A node of the tree returned by ``NGAP_PDU.get_val()``.

    Returns:
        The same tree, with mappings as
        :class:`~pcapkit.protocols.data.application.ngap.Sequence`, ``CHOICE``
        pairs as :class:`~pcapkit.protocols.data.application.ngap.Choice`, and
        ``BIT STRING`` pairs as
        :class:`~pcapkit.protocols.data.application.ngap.BitString`.

    Notes:
        The two 2-tuple shapes are told apart by their first element, which is
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
        :class:`~pcapkit.protocols.data.application.ngap.Choice` and
        :class:`~pcapkit.protocols.data.application.ngap.BitString` are tested
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
    """This class implements NG Application Protocol."""

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
            ProtocolError: If |pycrate|_ is not installed, or if the payload is
                not a well formed aligned PER ``NGAP-PDU``.

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
                # NOTE: `reset_val()` must not be called here, tempting though it
                # looks before a decode into a reused object. It walks all 318
                # submodules of the compiled specification and costs ~105 ms,
                # some 700x the ~0.15 ms of the decode itself; and `from_aper()`
                # overwrites the stored value outright, so it would buy nothing
                # even if it were free.
                pdu.from_aper(schema.data)
                kind, body = pdu.get_val()

                message, message_body = body['value']

                # NOTE: converted while the lock is held, because `get_val()`
                # returns the decoder's own containers rather than copies -- the
                # next decode through this module-level object rewrites them.
                value = _convert(message_body)

                ies = []  # type: list[Data_IE]
                for ie in value.get('protocolIEs') or ():
                    choice = ie['value']
                    ies.append(Data_IE(
                        id=ProtocolIE.get(ie['id']),
                        criticality=Criticality.get(ie['criticality']),
                        type=choice.name,
                        value=choice.value,
                    ))

                ngap = Data_NGAP(
                    kind=PDUKind(kind),
                    procedure=ProcedureCode.get(body['procedureCode']),
                    criticality=Criticality.get(body['criticality']),
                    message=message,
                    ies=tuple(ies),
                    value=value,
                )
            except ProtocolError:
                # NOTE: a ProtocolError raised inside this block is already
                # specific about what went wrong, so it must not be caught below
                # and relabelled "malformed NGAP-PDU". Nothing here raises one
                # today; this is what keeps that true of the next edit.
                raise
            except Exception as exc:
                # NOTE: `Exception` rather than something narrower on purpose.
                # pycrate signals a bad encoding from two unrelated hierarchies
                # -- `pycrate_asn1rt.err.ASN1Err` and `pycrate_core.charpy.
                # CharpyErr` -- and a truncated payload can also surface as
                # `KeyError` or `IndexError` from inside the codec. None of them
                # is a pcapkit exception, and letting one escape would make an
                # NGAP packet fail differently from every other protocol.
                raise ProtocolError(f'NGAP: malformed NGAP-PDU: {exc}') from exc
        return ngap

    def make(self,
             kind: 'PDUKind | str' = PDUKind.INITIATING_MESSAGE,
             procedure: 'Optional[ProcedureCode | int]' = None,
             criticality: 'Criticality | int | str' = Criticality.reject,
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
                :class:`~pcapkit.protocols.data.application.ngap.Sequence` from
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
                ``message`` is missing, if |pycrate|_ is not installed, or if
                the arguments do not describe a message the specification can
                encode.

        """
        if data is not None:
            return Schema_NGAP(data=bytes(data))

        if procedure is None or message is None:
            raise ProtocolError("NGAP: 'procedure' and 'message' are required "
                                "when 'data' is not given")

        pdu = load_pycrate()
        if pdu is None:
            raise ProtocolError('NGAP: encoding needs the optional "pycrate" dependency, '
                                'which is not installed; pip install pypcapkit[NGAP]')

        with _PDU_LOCK:
            try:
                pdu.set_val((PDUKind(kind).value, {
                    'procedureCode': int(ProcedureCode.get(procedure)),
                    'criticality': Criticality.get(criticality).name,
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
