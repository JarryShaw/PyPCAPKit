# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""NGAP protocol IE identifiers, 3GPP TS 38.413.
===================================================

.. module:: pcapkit.const.ngap.protocol_ie

This module contains the constant enumeration for **NGAP protocol IE identifiers, 3GPP TS 38.413.**,
which is automatically generated from :class:`pcapkit.vendor.ngap.protocol_ie.ProtocolIE`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ProtocolIE']


class ProtocolIE(EnumRegistry, IntEnum):
    """[ProtocolIE] NGAP protocol IE identifiers, 3GPP TS 38.413."""

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

    @classmethod
    def _missing_(cls, value: 'int') -> 'ProtocolIE':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
