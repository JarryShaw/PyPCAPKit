# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Application Layer Protocol Numbers (SCTP)
===============================================

.. module:: pcapkit.const.reg.apptype.sctp

This module contains the constant enumeration for **Application Layer Protocol Numbers (SCTP)**,
which is automatically generated from :class:`pcapkit.vendor.reg.apptype.sctp.SCTP`.

"""
from pcapkit.const.reg.apptype.apptype import AppType, TransportProtocol
from pcapkit.corekit.multidict import MultiDict

__all__ = ['SCTP']


class SCTP(AppType):
    """[SCTP] Application Layer Protocol Numbers (SCTP)

    Every member's :attr:`~pcapkit.const.reg.apptype.apptype.AppType.proto` is
    ``sctp`` and nothing else, so it labels the registry the member lives in
    rather than restating the whole set IANA assigned the service. A service
    registered on several transports is a separate member of each of their
    registries, which is where that set is read off.

    Note:
        The rows below are this transport's registry entries with **no port
        number assigned**. IANA leaves the port column empty for historic
        service names it never gave a port, so there is nothing for a member to
        be valued on and they are documented here instead.

    .. list-table:: Service names assigned no port number
       :header-rows: 1
       :widths: 30 70

       * - Service Name
         - Description
       * - ``dhanda-g``
         - [TCP] DHANDAg is going for a site; [UDP] DHANDAg is going for a
           site; [SCTP] DHANDAg is going for a site
       * - ``twosnakes``
         - [TCP] Service to enable multiplayer game called two snakes.; [SCTP]
           Service to enable multiplayer game called two snakes.

    """

    #: Transport protocol whose assignments this registry holds.
    __transport__: 'TransportProtocol' = TransportProtocol.sctp

    #: Members of this registry, keyed on port number. Declared per registry
    #: rather than inherited, since one mapping shared by all four would put
    #: every transport's ports in the same key space.
    __registry__: 'MultiDict[int, SCTP]' = MultiDict()

    #: The canonical service for each port IANA assigns more than one to, i.e.
    #: what :meth:`~pcapkit.const.reg.apptype.apptype.AppType.get` answers with.
    #: Taken from :file:`/etc/services`, which is what
    #: :func:`socket.getservbyport` reads -- IANA names no precedence among the
    #: services it registers on one port, and registry row order does not supply
    #: one either. The rest stay reachable through
    #: :meth:`~pcapkit.const.reg.apptype.apptype.AppType.get_all`.
    __canonical__: 'dict[int, str]' = {}

    #: - [TCP] Discard
    #: - [UDP] Discard
    #: - [SCTP] Discard [:rfc:`9260`]
    #: - [DCCP] Discard [:rfc:`4340`]
    discard = 9, 'discard', TransportProtocol.sctp

    #: - [TCP] File Transfer [Default Data]
    #: - [UDP] File Transfer [Default Data]
    #: - [SCTP] FTP [:rfc:`9260`]
    ftp_data = 20, 'ftp-data', TransportProtocol.sctp

    #: - [TCP] File Transfer Protocol [Control] [:rfc:`959`]
    #: - [UDP] File Transfer Protocol [Control] [:rfc:`959`]
    #: - [SCTP] FTP [:rfc:`9260`]
    ftp = 21, 'ftp', TransportProtocol.sctp

    #: - [TCP] World Wide Web HTTP [:rfc:`9110`]
    #: - [UDP] World Wide Web HTTP [:rfc:`9110`]
    #: - [SCTP] HTTP [:rfc:`9260`]
    http = 80, 'http', TransportProtocol.sctp

    #: - [TCP] Border Gateway Protocol
    #: - [UDP] Border Gateway Protocol
    #: - [SCTP] BGP [:rfc:`9260`]
    bgp = 179, 'bgp', TransportProtocol.sctp

    #: - [TCP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [UDP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [SCTP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [DCCP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    exp1 = 1021, 'exp1', TransportProtocol.sctp

    #: - [TCP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [UDP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [SCTP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [DCCP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    exp2 = 1022, 'exp2', TransportProtocol.sctp

    #: - [TCP] Cisco IP SLAs Control Protocol
    #: - [UDP] Cisco IP SLAs Control Protocol
    #: - [SCTP] Cisco IP SLAs Control Protocol
    cisco_ipsla = 1167, 'cisco-ipsla', TransportProtocol.sctp

    #: - [TCP] Not Only a Routeing Protocol
    #: - [UDP] Not Only a Routeing Protocol
    #: - [SCTP] Not Only a Routeing Protocol
    norp = 1528, 'norp', TransportProtocol.sctp

    #: - [TCP] H.323 Call Control Signalling
    #: - [UDP] H.323 Call Control Signalling
    #: - [SCTP] H.323 Call Control
    h323hostcall = 1720, 'h323hostcall', TransportProtocol.sctp

    #: - [TCP] Network File System - Sun Microsystems
    #: - [UDP] Network File System - Sun Microsystems
    #: - [SCTP] Network File System [:rfc:`5665`]
    nfs = 2049, 'nfs', TransportProtocol.sctp

    #: - [TCP] Resource Connection Initiation Protocol
    #: - [SCTP] Resource Connection Initiation Protocol
    rcip_itu = 2225, 'rcip-itu', TransportProtocol.sctp

    #: - [TCP] M2UA
    #: - [UDP] M2UA
    #: - [SCTP] M2UA
    m2ua = 2904, 'm2ua', TransportProtocol.sctp

    #: - [TCP] M3UA [:rfc:`4666`]
    #: - [SCTP] M3UA [:rfc:`4666`]
    m3ua = 2905, 'm3ua', TransportProtocol.sctp

    #: - [TCP] Megaco H-248
    #: - [UDP] Megaco H-248
    #: - [SCTP] Megaco-H.248 text
    megaco_h248 = 2944, 'megaco-h248', TransportProtocol.sctp

    #: - [TCP] H248 Binary
    #: - [UDP] H248 Binary
    #: - [SCTP] Megaco/H.248 binary
    h248_binary = 2945, 'h248-binary', TransportProtocol.sctp

    #: [SCTP] ITU-T Q.1902.1/Q.2150.3
    itu_bicc_stc = 3097, 'itu-bicc-stc', TransportProtocol.sctp

    #: - [TCP] M2PA [:rfc:`4165`]
    #: - [SCTP] M2PA [:rfc:`4165`]
    m2pa = 3565, 'm2pa', TransportProtocol.sctp

    #: [SCTP] asap sctp [:rfc:`5352`]
    asap_sctp = 3863, 'asap-sctp', TransportProtocol.sctp

    #: [SCTP] asap-sctp/tls [:rfc:`5352`]
    asap_sctp_tls = 3864, 'asap-sctp-tls', TransportProtocol.sctp

    #: - [TCP] DIAMETER
    #: - [SCTP] DIAMETER [:rfc:`3588`]
    diameter = 3868, 'diameter', TransportProtocol.sctp

    #: - [TCP] AWS protocol for cloud remoting solution
    #: - [UDP] AWS protocol for cloud remoting solution
    #: - [SCTP] AWS protocol for cloud remoting solution
    #: - [DCCP] AWS protocol for cloud remoting solution
    aws_wsp = 4195, 'aws-wsp', TransportProtocol.sctp

    #: - [TCP] ArrowHead Service Protocol (AHSP)
    #: - [UDP] ArrowHead Service Protocol (AHSP)
    #: - [SCTP] ArrowHead Service Protocol (AHSP)
    ahsp = 4333, 'ahsp', TransportProtocol.sctp

    #: [SCTP] A25 (FAP-FGW)
    a25_fap_fgw = 4502, 'a25-fap-fgw', TransportProtocol.sctp

    #: - [TCP] Trinity Trust Network Node Communication
    #: - [UDP] Trinity Trust Network Node Communication
    #: - [SCTP] Trinity Trust Network Node Communication
    trinity_dist = 4711, 'trinity-dist', TransportProtocol.sctp

    #: - [TCP] IP Flow Info Export
    #: - [UDP] IP Flow Info Export
    #: - [SCTP] IP Flow Info Export
    ipfix = 4739, 'ipfix', TransportProtocol.sctp

    #: - [TCP] ipfix protocol over TLS
    #: - [SCTP] ipfix protocol over DTLS
    #: - [UDP] ipfix protocol over DTLS
    ipfixs = 4740, 'ipfixs', TransportProtocol.sctp

    #: - [TCP] SIP [:rfc:`3263`]
    #: - [UDP] SIP [:rfc:`3263`]
    #: - [SCTP] SIP [:rfc:`4168`]
    sip = 5060, 'sip', TransportProtocol.sctp

    #: - [TCP] SIP-TLS [:rfc:`3263`]
    #: - [UDP] SIP-TLS [:rfc:`3263`]
    #: - [SCTP] SIP-TLS [:rfc:`4168`]
    sips = 5061, 'sips', TransportProtocol.sctp

    #: [SCTP] Candidate AR
    car = 5090, 'car', TransportProtocol.sctp

    #: [SCTP] Context Transfer Protocol [:rfc:`4065`]
    cxtp = 5091, 'cxtp', TransportProtocol.sctp

    #: - [TCP] NOTEZA Data Safety Service
    #: - [SCTP] NOTEZA Data Safety Service
    noteza = 5215, 'noteza', TransportProtocol.sctp

    #: - [TCP] Server Message Block over Remote Direct Memory Access
    #: - [SCTP] Server Message Block over Remote Direct Memory Access
    smbdirect = 5445, 'smbdirect', TransportProtocol.sctp

    #: - [TCP] AMQP
    #: - [UDP] AMQP
    #: - [SCTP] AMQP
    amqp = 5672, 'amqp', TransportProtocol.sctp

    #: - [TCP] V5UA application port [:rfc:`3807`]
    #: - [UDP] V5UA application port [:rfc:`3807`]
    #: - [SCTP] V5UA application port [:rfc:`3807`]
    v5ua = 5675, 'v5ua', TransportProtocol.sctp

    #: - [TCP] Diameter over TLS/TCP [:rfc:`6733`]
    #: - [SCTP] Diameter over DTLS/SCTP [:rfc:`6733`]
    diameters = 5868, 'diameters', TransportProtocol.sctp

    #: - [TCP] Flight & Flow Info for Collaborative Env
    #: - [UDP] Flight & Flow Info for Collaborative Env
    #: - [SCTP] Flight & Flow Info for Collaborative Env
    ff_ice = 5903, 'ff-ice', TransportProtocol.sctp

    #: - [TCP] Air-Ground SWIM
    #: - [UDP] Air-Ground SWIM
    #: - [SCTP] Air-Ground SWIM
    ag_swim = 5904, 'ag-swim', TransportProtocol.sctp

    #: - [TCP] Adv Surface Mvmnt and Guidance Cont Sys
    #: - [UDP] Adv Surface Mvmnt and Guidance Cont Sys
    #: - [SCTP] Adv Surface Mvmnt and Guidance Cont Sys
    asmgcs = 5905, 'asmgcs', TransportProtocol.sctp

    #: - [TCP] Remotely Piloted Vehicle C&C
    #: - [UDP] Remotely Piloted Vehicle C&C
    #: - [SCTP] Remotely Piloted Vehicle C&C
    rpas_c2 = 5906, 'rpas-c2', TransportProtocol.sctp

    #: - [TCP] Distress and Safety Data App
    #: - [UDP] Distress and Safety Data App
    #: - [SCTP] Distress and Safety Data App
    dsd = 5907, 'dsd', TransportProtocol.sctp

    #: - [TCP] IPS Management Application
    #: - [UDP] IPS Management Application
    #: - [SCTP] IPS Management Application
    ipsma = 5908, 'ipsma', TransportProtocol.sctp

    #: - [TCP] Air-ground media advisory
    #: - [UDP] Air-ground media advisory
    #: - [SCTP] Air-ground media advisory
    agma = 5909, 'agma', TransportProtocol.sctp

    #: [SCTP] Context Management
    cm = 5910, 'cm', TransportProtocol.sctp

    #: [SCTP] Controller Pilot Data Link Communication
    cpdlc = 5911, 'cpdlc', TransportProtocol.sctp

    #: [SCTP] Flight Information Services
    fis = 5912, 'fis', TransportProtocol.sctp

    #: [SCTP] Automatic Dependent Surveillance
    ads_c = 5913, 'ads-c', TransportProtocol.sctp

    #: - [TCP] Security for Internet Protocol Suite
    #: - [UDP] Security for Internet Protocol Suite
    #: - [SCTP] Security for Internet Protocol Suite
    ipsdtls = 5914, 'ipsdtls', TransportProtocol.sctp

    #: [SCTP] Unassigned
    unassigned_6701 = 6701, 'unassigned', TransportProtocol.sctp

    #: [SCTP] Unassigned
    unassigned_6702 = 6702, 'unassigned', TransportProtocol.sctp

    #: [SCTP] ForCES HP (High Priority) channel [:rfc:`5811`]
    frc_hp = 6704, 'frc-hp', TransportProtocol.sctp

    #: [SCTP] ForCES MP (Medium Priority) channel [:rfc:`5811`]
    frc_mp = 6705, 'frc-mp', TransportProtocol.sctp

    #: [SCTP] ForCES LP (Low priority) channel [:rfc:`5811`]
    frc_lp = 6706, 'frc-lp', TransportProtocol.sctp

    #: [SCTP] conductor for multiplex
    conductor_mpx = 6970, 'conductor-mpx', TransportProtocol.sctp

    #: - [TCP] SImple Middlebox COnfiguration (SIMCO) Server [:rfc:`4540`]
    #: - [SCTP] SImple Middlebox COnfiguration (SIMCO)
    simco = 7626, 'simco', TransportProtocol.sctp

    #: [SCTP] SCF nFAPI defining MAC/PHY split
    nfapi = 7701, 'nfapi', TransportProtocol.sctp

    #: - [TCP] Open-Source Virtual Reality
    #: - [UDP] Open-Source Virtual Reality
    #: - [SCTP] Open-Source Virtual Reality
    osvr = 7728, 'osvr', TransportProtocol.sctp

    #: - [SCTP] Reserved
    #: - [DCCP] Reserved
    reserved_8282 = 8282, 'reserved', TransportProtocol.sctp

    #: - [TCP] PIM over Reliable Transport [:rfc:`6559`]
    #: - [SCTP] PIM over Reliable Transport [:rfc:`6559`]
    pim_port = 8471, 'pim-port', TransportProtocol.sctp

    #: [SCTP] LCS Application Protocol
    lcs_ap = 9082, 'lcs-ap', TransportProtocol.sctp

    #: - [TCP] IBM AURORA Performance Visualizer
    #: - [UDP] IBM AURORA Performance Visualizer
    #: - [SCTP] IBM AURORA Performance Visualizer
    aurora = 9084, 'aurora', TransportProtocol.sctp

    #: - [TCP] IUA
    #: - [UDP] IUA
    #: - [SCTP] IUA
    iua = 9900, 'iua', TransportProtocol.sctp

    #: [SCTP] enrp server channel [:rfc:`5353`]
    enrp_sctp = 9901, 'enrp-sctp', TransportProtocol.sctp

    #: [SCTP] enrp/tls server channel [:rfc:`5353`]
    enrp_sctp_tls = 9902, 'enrp-sctp-tls', TransportProtocol.sctp

    #: - [TCP] numerical systems messaging
    #: - [SCTP] numerical systems messaging
    xcompute = 11235, 'xcompute', TransportProtocol.sctp

    #: [SCTP] WorldMailExpress
    wmereceiving = 11997, 'wmereceiving', TransportProtocol.sctp

    #: [SCTP] WorldMailExpress
    wmedistribution = 11998, 'wmedistribution', TransportProtocol.sctp

    #: [SCTP] WorldMailExpress
    wmereporting = 11999, 'wmereporting', TransportProtocol.sctp

    #: - [TCP] SUA
    #: - [UDP] De-Registered
    #: - [SCTP] SUA
    sua = 14001, 'sua', TransportProtocol.sctp

    #: - [TCP] Distributed Network Protocol - Secure
    #: - [UDP] Distributed Network Protocol - Secure
    #: - [SCTP] Distributed Network Protocol - secured
    dnp_sec = 19999, 'dnp-sec', TransportProtocol.sctp

    #: - [TCP] DNP
    #: - [UDP] DNP
    #: - [SCTP] Distributed Network Protocol
    dnp = 20000, 'dnp', TransportProtocol.sctp

    #: - [TCP] Network File System (NFS) over RDMA [:rfc:`8267`]
    #: - [UDP] Network File System (NFS) over RDMA [:rfc:`8267`]
    #: - [SCTP] Network File System (NFS) over RDMA [:rfc:`8267`]
    nfsrdma = 20049, 'nfsrdma', TransportProtocol.sctp

    #: [SCTP] RNSAP User Adaptation for Iurh
    rna = 25471, 'rna', TransportProtocol.sctp

    #: [SCTP] SGsAP in 3GPP
    sgsap = 29118, 'sgsap', TransportProtocol.sctp

    #: [SCTP] SBcAP in 3GPP
    sbcap = 29168, 'sbcap', TransportProtocol.sctp

    #: [SCTP] HNBAP and RUA Common Association
    iuhsctpassoc = 29169, 'iuhsctpassoc', TransportProtocol.sctp

    #: - [TCP] Remote Window Protocol
    #: - [SCTP] Remote Window Protocol
    rwp = 30100, 'rwp', TransportProtocol.sctp

    #: [SCTP] S1-Control Plane (3GPP)
    s1_control = 36412, 's1-control', TransportProtocol.sctp

    #: [SCTP] X2-Control Plane (3GPP)
    x2_control = 36422, 'x2-control', TransportProtocol.sctp

    #: [SCTP] SLm Interface Application Protocol
    slmap = 36423, 'slmap', TransportProtocol.sctp

    #: [SCTP] Nq and Nq' Application Protocol
    nq_ap = 36424, 'nq-ap', TransportProtocol.sctp

    #: [SCTP] M2 Application Part
    m2ap = 36443, 'm2ap', TransportProtocol.sctp

    #: [SCTP] M3 Application Part
    m3ap = 36444, 'm3ap', TransportProtocol.sctp

    #: [SCTP] Xw-Control Plane (3GPP)
    xw_control = 36462, 'xw-control', TransportProtocol.sctp

    #: [SCTP] W1 signalling transport
    SCTP_3gpp_w1ap = 37472, '3gpp-w1ap', TransportProtocol.sctp

    #: [SCTP] NG Control Plane (3GPP)
    ng_control = 38412, 'ng-control', TransportProtocol.sctp

    #: [SCTP] Xn Control Plane (3GPP)
    xn_control = 38422, 'xn-control', TransportProtocol.sctp

    #: [SCTP] E1 signalling transport (3GPP)
    e1_interface = 38462, 'e1-interface', TransportProtocol.sctp

    #: [SCTP] F1 Control Plane (3GPP)
    f1_control = 38472, 'f1-control', TransportProtocol.sctp

    #: - [TCP] http protocol over TLS/SSL [:rfc:`9110`]
    #: - [UDP] http protocol over TLS/SSL [:rfc:`9110`]
    #: - [SCTP] HTTPS [:rfc:`9260`]
    https_443 = 443, 'https', TransportProtocol.sctp

    #: - [TCP] The Secure Shell (SSH) Protocol [:rfc:`4251`]
    #: - [UDP] The Secure Shell (SSH) Protocol [:rfc:`4251`]
    #: - [SCTP] SSH [:rfc:`9260`]
    ssh_22 = 22, 'ssh', TransportProtocol.sctp
