# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""SCTP Payload Protocol Identifiers
=======================================

.. module:: pcapkit.const.sctp.payload_protocol_identifier

This module contains the constant enumeration for **SCTP Payload Protocol Identifiers**,
which is maintained manually against the `IANA`_ registry, as there
is currently no vendor crawler for SCTP under :mod:`pcapkit.vendor`.

.. _IANA: https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25

"""

from aenum import IntEnum, extend_enum

__all__ = ['PayloadProtocolIdentifier']


class PayloadProtocolIdentifier(IntEnum):
    """[PayloadProtocolIdentifier] SCTP Payload Protocol Identifiers"""

    #: Reserved by SCTP [:rfc:`9260`]
    Reserved_by_SCTP = 0

    #: IUA [:rfc:`4233`]
    IUA = 1

    #: M2UA [:rfc:`3331`]
    M2UA = 2

    #: M3UA [:rfc:`4666`]
    M3UA = 3

    #: SUA [:rfc:`3868`]
    SUA = 4

    #: M2PA [:rfc:`4165`]
    M2PA = 5

    #: V5UA [:rfc:`3807`]
    V5UA = 6

    #: H.248 [ITU-T Recommendation H.248 Annex H, "Transport over SCTP",November
    #: 2000.]
    H_248 = 7

    #: BICC/Q.2150.3 [ITU-T Recommendation Q.1902.1, "Bearer Independent
    #: CallControl protocol (Capability Set 2): Functional description",July
    #: 2001.][ITU-T Recommendation Q.2150.3, "Signalling Transport ConverterOn
    #: SCTP", to be published.]
    BICC_Q_2150_3 = 8

    #: TALI [:rfc:`3094`]
    TALI = 9

    #: DUA [:rfc:`4129`]
    DUA = 10

    #: ASAP [:rfc:`5352`]
    ASAP = 11

    #: ENRP [:rfc:`5353`]
    ENRP = 12

    #: H.323 [http://standard.pictel.com/ftp/avc-site/0206 Bru/AVD-2198.zip][H.323
    #: over SCTP October 2002.]
    H_323 = 13

    #: Q.IPC/Q.2150.3 [ITU-T Recommendation Q.2631.1 "IP Connection Control
    #: SignalingProtocol - Capability Set 1", to be published.][ITU-T
    #: Recommendation Q.2150.3, "Signalling Transport ConverterOn SCTP", to be
    #: published.]
    Q_IPC_Q_2150_3 = 14

    #: SIMCO <draft-kiesel-midcom-simco-sctp-00.txt> [draft-kiesel-midcom-simco-
    #: sctp-00][Sebastian Kiesel]
    SIMCO_draft_kiesel_midcom_simco_sctp_00_txt = 15

    #: DDP Segment Chunk [:rfc:`5043`]
    DDP_Segment_Chunk = 16

    #: DDP Stream Session Control [:rfc:`5043`]
    DDP_Stream_Session_Control = 17

    #: S1 Application Protocol (S1AP) [3GPP TS 23.401][3GPP TS 36.413][Rajeev
    #: Koodli]
    S1_Application_Protocol = 18

    #: RUA [3GPP TS 25.467][3GPP TS 25.468][Dongwook Kim]
    RUA = 19

    #: HNBAP [3GPP TS 25.467][3GPP TS 25.469][Dongwook Kim]
    HNBAP = 20

    #: ForCES-HP [:rfc:`5811`]
    ForCES_HP = 21

    #: ForCES-MP [:rfc:`5811`]
    ForCES_MP = 22

    #: ForCES-LP [:rfc:`5811`]
    ForCES_LP = 23

    #: SBc-AP [3GPP TS 29.168][Kimmo Kymalainen]
    SBc_AP = 24

    #: NBAP [3GPP TS 25.433][Kimmo Kymalainen]
    NBAP = 25

    #: Unassigned
    Unassigned_26 = 26

    #: X2AP [3GPP TS 36.423][Kimmo Kymalainen]
    X2AP = 27

    #: IRCP - Inter Router Capability Protocol [Randall Stewart]
    IRCP_Inter_Router_Capability_Protocol = 28

    #: LCS-AP [3GPP TS 29.271][Kimmo Kymalainen]
    LCS_AP = 29

    #: MPICH2 [Michael Tuexen][http://www.mcs.anl.gov/research/projects/mpich2/]
    MPICH2 = 30

    #: Service Area Broadcast Protocol (SABP) [3GPP TS 25.467][3GPP TS
    #: 25.419][Dongwook Kim]
    Service_Area_Broadcast_Protocol = 31

    #: Fractal Generator Protocol (FGP) [Thomas
    #: Dreibholz][https://www.nntb.no/~dreibh/rserpool/]
    Fractal_Generator_Protocol = 32

    #: Ping Pong Protocol (PPP) [Thomas
    #: Dreibholz][https://www.nntb.no/~dreibh/rserpool/]
    Ping_Pong_Protocol = 33

    #: CalcApp Protocol (CALCAPP) [Thomas
    #: Dreibholz][https://www.nntb.no/~dreibh/rserpool/]
    CalcApp_Protocol = 34

    #: Scripting Service Protocol (SSP) [Thomas
    #: Dreibholz][https://www.nntb.no/~dreibh/rserpool/]
    Scripting_Service_Protocol = 35

    #: NetPerfMeter Protocol Control Channel (NPMP-CONTROL) [Thomas
    #: Dreibholz][https://www.nntb.no/~dreibh/netperfmeter/]
    NetPerfMeter_Protocol_Control_Channel = 36

    #: NetPerfMeter Protocol Data Channel (NPMP-DATA) [Thomas
    #: Dreibholz][https://www.nntb.no/~dreibh/netperfmeter/]
    NetPerfMeter_Protocol_Data_Channel = 37

    #: Echo (ECHO) [Thomas Dreibholz][https://www.nntb.no/~dreibh/rserpool/]
    Echo = 38

    #: Discard (DISCARD) [Thomas Dreibholz][https://www.nntb.no/~dreibh/rserpool/]
    Discard = 39

    #: Daytime (DAYTIME) [Thomas Dreibholz][https://www.nntb.no/~dreibh/rserpool/]
    Daytime = 40

    #: Character Generator (CHARGEN) [Thomas
    #: Dreibholz][https://www.nntb.no/~dreibh/rserpool/]
    Character_Generator = 41

    #: 3GPP RNA [Tonesi][3GPP TS 25.471]
    PayloadProtocolIdentifier_3GPP_RNA = 42

    #: 3GPP M2AP [Tonesi][3GPP TS 36.442][3GPP TS 36.443]
    PayloadProtocolIdentifier_3GPP_M2AP = 43

    #: 3GPP M3AP [Tonesi][3GPP TS 36.442][3GPP TS 36.444]
    PayloadProtocolIdentifier_3GPP_M3AP = 44

    #: SSH over SCTP [Michael Tuexen]
    SSH_over_SCTP = 45

    #: Diameter in a SCTP DATA chunk [:rfc:`6733`]
    Diameter_in_a_SCTP_DATA_chunk = 46

    #: Diameter in a DTLS/SCTP DATA chunk [:rfc:`6733`]
    Diameter_in_a_DTLS_SCTP_DATA_chunk = 47

    #: R14P. BER Encoded ASN.1 over SCTP [Josip
    #: Djuricic][http://www.release14.org/wp-content/uploads/2012/07/r14p.asn]
    R14P_BER_Encoded_ASN_1_over_SCTP = 48

    #: Generic Data Transfer (GDT) Protocol [Damir
    #: Franusic][https://github.com/link-mink]
    Generic_Data_Transfer_Protocol = 49

    #: WebRTC DCEP [:rfc:`8832`]
    WebRTC_DCEP = 50

    #: WebRTC String [:rfc:`8831`]
    WebRTC_String = 51

    #: WebRTC Binary Partial (deprecated) [:rfc:`8831`]
    WebRTC_Binary_Partial = 52

    #: WebRTC Binary [:rfc:`8831`]
    WebRTC_Binary = 53

    #: WebRTC String Partial (deprecated) [:rfc:`8831`]
    WebRTC_String_Partial = 54

    #: 3GPP PUA [Dario S Tonesi][3GPP TS 25.470][3GPP TS 25.467]
    PayloadProtocolIdentifier_3GPP_PUA = 55

    #: WebRTC String Empty [:rfc:`8831`]
    WebRTC_String_Empty = 56

    #: WebRTC Binary Empty [:rfc:`8831`]
    WebRTC_Binary_Empty = 57

    #: 3GPP XwAP [        3GPP TS 36.462][KIMBA DIT ADAMOU Boubacar]
    PayloadProtocolIdentifier_3GPP_XwAP = 58

    #: 3GPP Xw-Control Plane [        3GPP TS 36.462][KIMBA DIT ADAMOU Boubacar]
    PayloadProtocolIdentifier_3GPP_Xw_Control_Plane = 59

    #: 3GPP NG Application Protocol (NGAP) [        3GPP TS 38.413][Luis Lopes]
    PayloadProtocolIdentifier_3GPP_NG_Application_Protocol = 60

    #: 3GPP Xn Application Protocol (XnAP) [        3GPP TS 38.423][Luis Lopes]
    PayloadProtocolIdentifier_3GPP_Xn_Application_Protocol = 61

    #: 3GPP F1 Application Protocol (F1 AP) [        3GPP TS 38.473][Luis Lopes]
    PayloadProtocolIdentifier_3GPP_F1_Application_Protocol = 62

    #: HTTP/SCTP [Michael Tuexen]
    HTTP_SCTP = 63

    #: 3GPP E1 Application Protocol (E1AP) [        3GPP TS 38.463][Yang Xudong]
    PayloadProtocolIdentifier_3GPP_E1_Application_Protocol = 64

    #: ELE2 Lawful Interception [http://ele2.io][Damir Franusic]
    ELE2_Lawful_Interception = 65

    #: 3GPP NGAP over DTLS over SCTP [        3GPP TS 38.413][Yang Xudong]
    PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP = 66

    #: 3GPP XnAP over DTLS over SCTP [        3GPP TS 38.423][Yang Xudong]
    PayloadProtocolIdentifier_3GPP_XnAP_over_DTLS_over_SCTP = 67

    #: 3GPP F1AP over DTLS over SCTP [        3GPP TS 38.473][Yang Xudong]
    PayloadProtocolIdentifier_3GPP_F1AP_over_DTLS_over_SCTP = 68

    #: 3GPP E1AP over DTLS over SCTP [        3GPP TS 38.463][Yang Xudong]
    PayloadProtocolIdentifier_3GPP_E1AP_over_DTLS_over_SCTP = 69

    #: E2-CP [O-RAN Alliance][Jun Hyuk Song]
    E2_CP = 70

    #: O-RAN D2 [O-RAN Alliance][Jun Hyuk Song]
    O_RAN_D2 = 71

    #: E2-DU [O-RAN Alliance][Jun Hyuk Song]
    E2_DU = 72

    #: 3GPP W1AP [3GPP TS 37.473][Lionel Morand]
    PayloadProtocolIdentifier_3GPP_W1AP = 73

    #: DTLS Chunk Key-Management Messages [draft-westerlund-tsvwg-sctp-dtls-
    #: chunk-01]
    DTLS_Chunk_Key_Management_Messages = 4242

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'PayloadProtocolIdentifier':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return PayloadProtocolIdentifier(key)
        if key not in PayloadProtocolIdentifier._member_map_:  # pylint: disable=no-member
            return extend_enum(PayloadProtocolIdentifier, key, default)
        return PayloadProtocolIdentifier[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'PayloadProtocolIdentifier':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 4294967295):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 74 <= value <= 4241:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 4243 <= value <= 4294967295:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
