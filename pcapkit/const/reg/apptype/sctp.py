# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long,consider-using-f-string
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

    Members carry the **whole** transport protocol set IANA assigned the service,
    not just ``sctp``, so a service registered on several transports appears in
    each of their registries with its
    :attr:`~pcapkit.const.reg.apptype.apptype.AppType.proto` intact.

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
    discard: 'SCTP' = 9, 'discard', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp') | TransportProtocol.get('dccp')

    #: - [TCP] File Transfer [Default Data]
    #: - [UDP] File Transfer [Default Data]
    #: - [SCTP] FTP [:rfc:`9260`]
    ftp_data: 'SCTP' = 20, 'ftp-data', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] File Transfer Protocol [Control] [:rfc:`959`]
    #: - [UDP] File Transfer Protocol [Control] [:rfc:`959`]
    #: - [SCTP] FTP [:rfc:`9260`]
    ftp: 'SCTP' = 21, 'ftp', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] World Wide Web HTTP [:rfc:`9110`]
    #: - [UDP] World Wide Web HTTP [:rfc:`9110`]
    #: - [SCTP] HTTP [:rfc:`9260`]
    http: 'SCTP' = 80, 'http', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Border Gateway Protocol
    #: - [UDP] Border Gateway Protocol
    #: - [SCTP] BGP [:rfc:`9260`]
    bgp: 'SCTP' = 179, 'bgp', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [UDP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [SCTP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [DCCP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    exp1: 'SCTP' = 1021, 'exp1', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp') | TransportProtocol.get('dccp')

    #: - [TCP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [UDP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [SCTP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [DCCP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    exp2: 'SCTP' = 1022, 'exp2', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp') | TransportProtocol.get('dccp')

    #: - [TCP] Cisco IP SLAs Control Protocol
    #: - [UDP] Cisco IP SLAs Control Protocol
    #: - [SCTP] Cisco IP SLAs Control Protocol
    cisco_ipsla: 'SCTP' = 1167, 'cisco-ipsla', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Not Only a Routeing Protocol
    #: - [UDP] Not Only a Routeing Protocol
    #: - [SCTP] Not Only a Routeing Protocol
    norp: 'SCTP' = 1528, 'norp', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] H.323 Call Control Signalling
    #: - [UDP] H.323 Call Control Signalling
    #: - [SCTP] H.323 Call Control
    h323hostcall: 'SCTP' = 1720, 'h323hostcall', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Network File System - Sun Microsystems
    #: - [UDP] Network File System - Sun Microsystems
    #: - [SCTP] Network File System [:rfc:`5665`]
    nfs: 'SCTP' = 2049, 'nfs', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Resource Connection Initiation Protocol
    #: - [SCTP] Resource Connection Initiation Protocol
    rcip_itu: 'SCTP' = 2225, 'rcip-itu', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: - [TCP] M2UA
    #: - [UDP] M2UA
    #: - [SCTP] M2UA
    m2ua: 'SCTP' = 2904, 'm2ua', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] M3UA [:rfc:`4666`]
    #: - [SCTP] M3UA [:rfc:`4666`]
    m3ua: 'SCTP' = 2905, 'm3ua', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: - [TCP] Megaco H-248
    #: - [UDP] Megaco H-248
    #: - [SCTP] Megaco-H.248 text
    megaco_h248: 'SCTP' = 2944, 'megaco-h248', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] H248 Binary
    #: - [UDP] H248 Binary
    #: - [SCTP] Megaco/H.248 binary
    h248_binary: 'SCTP' = 2945, 'h248-binary', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: [SCTP] ITU-T Q.1902.1/Q.2150.3
    itu_bicc_stc: 'SCTP' = 3097, 'itu-bicc-stc', TransportProtocol.get('sctp')

    #: - [TCP] M2PA [:rfc:`4165`]
    #: - [SCTP] M2PA [:rfc:`4165`]
    m2pa: 'SCTP' = 3565, 'm2pa', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: [SCTP] asap sctp [:rfc:`5352`]
    asap_sctp: 'SCTP' = 3863, 'asap-sctp', TransportProtocol.get('sctp')

    #: [SCTP] asap-sctp/tls [:rfc:`5352`]
    asap_sctp_tls: 'SCTP' = 3864, 'asap-sctp-tls', TransportProtocol.get('sctp')

    #: - [TCP] DIAMETER
    #: - [SCTP] DIAMETER [:rfc:`3588`]
    diameter: 'SCTP' = 3868, 'diameter', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: - [TCP] AWS protocol for cloud remoting solution
    #: - [UDP] AWS protocol for cloud remoting solution
    #: - [SCTP] AWS protocol for cloud remoting solution
    #: - [DCCP] AWS protocol for cloud remoting solution
    aws_wsp: 'SCTP' = 4195, 'aws-wsp', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp') | TransportProtocol.get('dccp')

    #: - [TCP] ArrowHead Service Protocol (AHSP)
    #: - [UDP] ArrowHead Service Protocol (AHSP)
    #: - [SCTP] ArrowHead Service Protocol (AHSP)
    ahsp: 'SCTP' = 4333, 'ahsp', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: [SCTP] A25 (FAP-FGW)
    a25_fap_fgw: 'SCTP' = 4502, 'a25-fap-fgw', TransportProtocol.get('sctp')

    #: - [TCP] Trinity Trust Network Node Communication
    #: - [UDP] Trinity Trust Network Node Communication
    #: - [SCTP] Trinity Trust Network Node Communication
    trinity_dist: 'SCTP' = 4711, 'trinity-dist', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] IP Flow Info Export
    #: - [UDP] IP Flow Info Export
    #: - [SCTP] IP Flow Info Export
    ipfix: 'SCTP' = 4739, 'ipfix', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] ipfix protocol over TLS
    #: - [SCTP] ipfix protocol over DTLS
    #: - [UDP] ipfix protocol over DTLS
    ipfixs: 'SCTP' = 4740, 'ipfixs', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] SIP [:rfc:`3263`]
    #: - [UDP] SIP [:rfc:`3263`]
    #: - [SCTP] SIP [:rfc:`4168`]
    sip: 'SCTP' = 5060, 'sip', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] SIP-TLS [:rfc:`3263`]
    #: - [UDP] SIP-TLS [:rfc:`3263`]
    #: - [SCTP] SIP-TLS [:rfc:`4168`]
    sips: 'SCTP' = 5061, 'sips', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: [SCTP] Candidate AR
    car: 'SCTP' = 5090, 'car', TransportProtocol.get('sctp')

    #: [SCTP] Context Transfer Protocol [:rfc:`4065`]
    cxtp: 'SCTP' = 5091, 'cxtp', TransportProtocol.get('sctp')

    #: - [TCP] NOTEZA Data Safety Service
    #: - [SCTP] NOTEZA Data Safety Service
    noteza: 'SCTP' = 5215, 'noteza', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: - [TCP] Server Message Block over Remote Direct Memory Access
    #: - [SCTP] Server Message Block over Remote Direct Memory Access
    smbdirect: 'SCTP' = 5445, 'smbdirect', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: - [TCP] AMQP
    #: - [UDP] AMQP
    #: - [SCTP] AMQP
    amqp: 'SCTP' = 5672, 'amqp', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] V5UA application port [:rfc:`3807`]
    #: - [UDP] V5UA application port [:rfc:`3807`]
    #: - [SCTP] V5UA application port [:rfc:`3807`]
    v5ua: 'SCTP' = 5675, 'v5ua', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Diameter over TLS/TCP [:rfc:`6733`]
    #: - [SCTP] Diameter over DTLS/SCTP [:rfc:`6733`]
    diameters: 'SCTP' = 5868, 'diameters', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: - [TCP] Flight & Flow Info for Collaborative Env
    #: - [UDP] Flight & Flow Info for Collaborative Env
    #: - [SCTP] Flight & Flow Info for Collaborative Env
    ff_ice: 'SCTP' = 5903, 'ff-ice', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Air-Ground SWIM
    #: - [UDP] Air-Ground SWIM
    #: - [SCTP] Air-Ground SWIM
    ag_swim: 'SCTP' = 5904, 'ag-swim', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Adv Surface Mvmnt and Guidance Cont Sys
    #: - [UDP] Adv Surface Mvmnt and Guidance Cont Sys
    #: - [SCTP] Adv Surface Mvmnt and Guidance Cont Sys
    asmgcs: 'SCTP' = 5905, 'asmgcs', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Remotely Piloted Vehicle C&C
    #: - [UDP] Remotely Piloted Vehicle C&C
    #: - [SCTP] Remotely Piloted Vehicle C&C
    rpas_c2: 'SCTP' = 5906, 'rpas-c2', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Distress and Safety Data App
    #: - [UDP] Distress and Safety Data App
    #: - [SCTP] Distress and Safety Data App
    dsd: 'SCTP' = 5907, 'dsd', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] IPS Management Application
    #: - [UDP] IPS Management Application
    #: - [SCTP] IPS Management Application
    ipsma: 'SCTP' = 5908, 'ipsma', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Air-ground media advisory
    #: - [UDP] Air-ground media advisory
    #: - [SCTP] Air-ground media advisory
    agma: 'SCTP' = 5909, 'agma', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: [SCTP] Context Management
    cm: 'SCTP' = 5910, 'cm', TransportProtocol.get('sctp')

    #: [SCTP] Controller Pilot Data Link Communication
    cpdlc: 'SCTP' = 5911, 'cpdlc', TransportProtocol.get('sctp')

    #: [SCTP] Flight Information Services
    fis: 'SCTP' = 5912, 'fis', TransportProtocol.get('sctp')

    #: [SCTP] Automatic Dependent Surveillance
    ads_c: 'SCTP' = 5913, 'ads-c', TransportProtocol.get('sctp')

    #: - [TCP] Security for Internet Protocol Suite
    #: - [UDP] Security for Internet Protocol Suite
    #: - [SCTP] Security for Internet Protocol Suite
    ipsdtls: 'SCTP' = 5914, 'ipsdtls', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: [SCTP] Unassigned
    unassigned_6701: 'SCTP' = 6701, 'unassigned', TransportProtocol.get('sctp')

    #: [SCTP] Unassigned
    unassigned_6702: 'SCTP' = 6702, 'unassigned', TransportProtocol.get('sctp')

    #: [SCTP] ForCES HP (High Priority) channel [:rfc:`5811`]
    frc_hp: 'SCTP' = 6704, 'frc-hp', TransportProtocol.get('sctp')

    #: [SCTP] ForCES MP (Medium Priority) channel [:rfc:`5811`]
    frc_mp: 'SCTP' = 6705, 'frc-mp', TransportProtocol.get('sctp')

    #: [SCTP] ForCES LP (Low priority) channel [:rfc:`5811`]
    frc_lp: 'SCTP' = 6706, 'frc-lp', TransportProtocol.get('sctp')

    #: [SCTP] conductor for multiplex
    conductor_mpx: 'SCTP' = 6970, 'conductor-mpx', TransportProtocol.get('sctp')

    #: - [TCP] SImple Middlebox COnfiguration (SIMCO) Server [:rfc:`4540`]
    #: - [SCTP] SImple Middlebox COnfiguration (SIMCO)
    simco: 'SCTP' = 7626, 'simco', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: [SCTP] SCF nFAPI defining MAC/PHY split
    nfapi: 'SCTP' = 7701, 'nfapi', TransportProtocol.get('sctp')

    #: - [TCP] Open-Source Virtual Reality
    #: - [UDP] Open-Source Virtual Reality
    #: - [SCTP] Open-Source Virtual Reality
    osvr: 'SCTP' = 7728, 'osvr', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [SCTP] Reserved
    #: - [DCCP] Reserved
    reserved_8282: 'SCTP' = 8282, 'reserved', TransportProtocol.get('sctp') | TransportProtocol.get('dccp')

    #: - [TCP] PIM over Reliable Transport [:rfc:`6559`]
    #: - [SCTP] PIM over Reliable Transport [:rfc:`6559`]
    pim_port: 'SCTP' = 8471, 'pim-port', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: [SCTP] LCS Application Protocol
    lcs_ap: 'SCTP' = 9082, 'lcs-ap', TransportProtocol.get('sctp')

    #: - [TCP] IBM AURORA Performance Visualizer
    #: - [UDP] IBM AURORA Performance Visualizer
    #: - [SCTP] IBM AURORA Performance Visualizer
    aurora: 'SCTP' = 9084, 'aurora', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] IUA
    #: - [UDP] IUA
    #: - [SCTP] IUA
    iua: 'SCTP' = 9900, 'iua', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: [SCTP] enrp server channel [:rfc:`5353`]
    enrp_sctp: 'SCTP' = 9901, 'enrp-sctp', TransportProtocol.get('sctp')

    #: [SCTP] enrp/tls server channel [:rfc:`5353`]
    enrp_sctp_tls: 'SCTP' = 9902, 'enrp-sctp-tls', TransportProtocol.get('sctp')

    #: - [TCP] numerical systems messaging
    #: - [SCTP] numerical systems messaging
    xcompute: 'SCTP' = 11235, 'xcompute', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: [SCTP] WorldMailExpress
    wmereceiving: 'SCTP' = 11997, 'wmereceiving', TransportProtocol.get('sctp')

    #: [SCTP] WorldMailExpress
    wmedistribution: 'SCTP' = 11998, 'wmedistribution', TransportProtocol.get('sctp')

    #: [SCTP] WorldMailExpress
    wmereporting: 'SCTP' = 11999, 'wmereporting', TransportProtocol.get('sctp')

    #: - [TCP] SUA
    #: - [UDP] De-Registered
    #: - [SCTP] SUA
    sua: 'SCTP' = 14001, 'sua', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Distributed Network Protocol - Secure
    #: - [UDP] Distributed Network Protocol - Secure
    #: - [SCTP] Distributed Network Protocol - secured
    dnp_sec: 'SCTP' = 19999, 'dnp-sec', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] DNP
    #: - [UDP] DNP
    #: - [SCTP] Distributed Network Protocol
    dnp: 'SCTP' = 20000, 'dnp', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] Network File System (NFS) over RDMA [:rfc:`8267`]
    #: - [UDP] Network File System (NFS) over RDMA [:rfc:`8267`]
    #: - [SCTP] Network File System (NFS) over RDMA [:rfc:`8267`]
    nfsrdma: 'SCTP' = 20049, 'nfsrdma', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: [SCTP] RNSAP User Adaptation for Iurh
    rna: 'SCTP' = 25471, 'rna', TransportProtocol.get('sctp')

    #: [SCTP] SGsAP in 3GPP
    sgsap: 'SCTP' = 29118, 'sgsap', TransportProtocol.get('sctp')

    #: [SCTP] SBcAP in 3GPP
    sbcap: 'SCTP' = 29168, 'sbcap', TransportProtocol.get('sctp')

    #: [SCTP] HNBAP and RUA Common Association
    iuhsctpassoc: 'SCTP' = 29169, 'iuhsctpassoc', TransportProtocol.get('sctp')

    #: - [TCP] Remote Window Protocol
    #: - [SCTP] Remote Window Protocol
    rwp: 'SCTP' = 30100, 'rwp', TransportProtocol.get('tcp') | TransportProtocol.get('sctp')

    #: [SCTP] S1-Control Plane (3GPP)
    s1_control: 'SCTP' = 36412, 's1-control', TransportProtocol.get('sctp')

    #: [SCTP] X2-Control Plane (3GPP)
    x2_control: 'SCTP' = 36422, 'x2-control', TransportProtocol.get('sctp')

    #: [SCTP] SLm Interface Application Protocol
    slmap: 'SCTP' = 36423, 'slmap', TransportProtocol.get('sctp')

    #: [SCTP] Nq and Nq' Application Protocol
    nq_ap: 'SCTP' = 36424, 'nq-ap', TransportProtocol.get('sctp')

    #: [SCTP] M2 Application Part
    m2ap: 'SCTP' = 36443, 'm2ap', TransportProtocol.get('sctp')

    #: [SCTP] M3 Application Part
    m3ap: 'SCTP' = 36444, 'm3ap', TransportProtocol.get('sctp')

    #: [SCTP] Xw-Control Plane (3GPP)
    xw_control: 'SCTP' = 36462, 'xw-control', TransportProtocol.get('sctp')

    #: [SCTP] W1 signalling transport
    SCTP_3gpp_w1ap: 'SCTP' = 37472, '3gpp-w1ap', TransportProtocol.get('sctp')

    #: [SCTP] NG Control Plane (3GPP)
    ng_control: 'SCTP' = 38412, 'ng-control', TransportProtocol.get('sctp')

    #: [SCTP] Xn Control Plane (3GPP)
    xn_control: 'SCTP' = 38422, 'xn-control', TransportProtocol.get('sctp')

    #: [SCTP] E1 signalling transport (3GPP)
    e1_interface: 'SCTP' = 38462, 'e1-interface', TransportProtocol.get('sctp')

    #: [SCTP] F1 Control Plane (3GPP)
    f1_control: 'SCTP' = 38472, 'f1-control', TransportProtocol.get('sctp')

    #: - [TCP] http protocol over TLS/SSL [:rfc:`9110`]
    #: - [UDP] http protocol over TLS/SSL [:rfc:`9110`]
    #: - [SCTP] HTTPS [:rfc:`9260`]
    https_443: 'SCTP' = 443, 'https', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')

    #: - [TCP] The Secure Shell (SSH) Protocol [:rfc:`4251`]
    #: - [UDP] The Secure Shell (SSH) Protocol [:rfc:`4251`]
    #: - [SCTP] SSH [:rfc:`9260`]
    ssh_22: 'SCTP' = 22, 'ssh', TransportProtocol.get('tcp') | TransportProtocol.get('udp') | TransportProtocol.get('sctp')
