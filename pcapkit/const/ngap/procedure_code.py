# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""NGAP elementary procedure codes, 3GPP TS 38.413.
======================================================

.. module:: pcapkit.const.ngap.procedure_code

This module contains the constant enumeration for **NGAP elementary procedure codes, 3GPP TS 38.413.**,
which is automatically generated from :class:`pcapkit.vendor.ngap.procedure_code.ProcedureCode`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ProcedureCode']


class ProcedureCode(EnumRegistry, IntEnum):
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

    @classmethod
    def _missing_(cls, value: 'int') -> 'ProcedureCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
