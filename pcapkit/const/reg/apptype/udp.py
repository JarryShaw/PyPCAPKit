# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Application Layer Protocol Numbers (UDP)
==============================================

.. module:: pcapkit.const.reg.apptype.udp

This module contains the constant enumeration for **Application Layer Protocol Numbers (UDP)**,
which is automatically generated from :class:`pcapkit.vendor.reg.apptype.udp.UDP`.

"""
from pcapkit.const.reg.apptype.apptype import AppType, TransportProtocol
from pcapkit.corekit.multidict import MultiDict

__all__ = ['UDP']


class UDP(AppType):
    """[UDP] Application Layer Protocol Numbers (UDP)

    Members carry the **whole** transport protocol set IANA assigned the service,
    not just ``udp``, so a service registered on several transports appears in
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
       * - ``7ksonar``
         - [TCP] Teledyne Marine 7k Sonar Protocol; [UDP] Teledyne Marine 7k
           Sonar Protocol
       * - ``ab-secure``
         - [TCP] AB Secure Protocol; [UDP] AB Secure Protocol
       * - ``acs-ctl-ds``
         - [TCP] Access Control Device; [UDP] Access Control Device
       * - ``acs-ctl-gw``
         - [TCP] Access Control Gateway; [UDP] Access Control Gateway
       * - ``adamhall``
         - [TCP] Adam Hall network control and monitoring; [UDP] Adam Hall
           network control and monitoring
       * - ``adaptive-rn``
         - [TCP] ARN (Adaptive Routing Notification) is a protocol designed to
           enable dynamic routing adjustments by sharing network status
           information between nodes in data center networks, improving
           efficiency and fault tolerance.; [UDP] ARN (Adaptive Routing
           Notification) is a protocol designed to enable dynamic routing
           adjustments by sharing network status information between nodes in
           data center networks, improving efficiency and fault tolerance.
       * - ``airmate``
         - [TCP] Airmate interworking protocol; [UDP] Airmate interworking
           protocol
       * - ``airplay``
         - [TCP] Protocol for streaming of audio/video content; [UDP] Protocol
           for streaming of audio/video content
       * - ``alpacadiscovery``
         - [UDP] ASCOM Alpaca Device Discovery
       * - ``amazon-expiscor``
         - [UDP] Device discovery for Amazon
       * - ``amba-cam``
         - [UDP] Ambarella Cameras
       * - ``apple-midi``
         - [UDP] Apple MIDI
       * - ``arcnet``
         - [UDP] Arcturus Networks Inc. Hardware Services
       * - ``asam-cmp``
         - [UDP] ASAM Capture Module Protocol
       * - ``astnotify``
         - [UDP] Asterisk Caller-ID Notification Service
       * - ``atnet``
         - [UDP] AT protocol over IP
       * - ``attero-ad``
         - [TCP] Attero Tech Audio Device; [UDP] Attero Tech Audio Device
       * - ``axis-nvr``
         - [TCP] Axis Network Video Recorders; [UDP] Axis Network Video
           Recorders
       * - ``autotunnel``
         - [UDP] IPSEC VPN tunnel over UDP [:rfc:`6281`]
       * - ``bhipc``
         - [TCP] Becker & Hickl Inter Process Communication; [UDP] Becker &
           Hickl Inter Process Communication
       * - ``biosonics``
         - [TCP] BioSonics Echosounders; [UDP] BioSonics Echosounders
       * - ``bluevertise``
         - [UDP] BlueVertise Network Protocol (BNP)
       * - ``bootstrap``
         - [TCP] Bootstrap service discovery; [UDP] Bootstrap service discovery
       * - ``boundaryscan``
         - [UDP] Proprietary
       * - ``boutfitness``
         - [TCP] Bout Fitness Synchronization Service; [UDP] Bout Fitness
           Synchronization Service
       * - ``bq-cromo``
         - [TCP] bq Cromo protocol; [UDP] bq Cromo protocol
       * - ``breas``
         - [TCP] Breas; [UDP] Breas
       * - ``clique``
         - [UDP] Clique Link-Local Multicast Chat Room
       * - ``collabio``
         - [TCP] Collabio; [UDP] Collabio
       * - ``compressnet``
         - [TCP] Management Utility/Compression Process; [UDP] Management
           Utility/Compression Process
       * - ``conecube``
         - [UDP] DNS SRV service for smarthome server
       * - ``core-rd``
         - [TCP] Resource Directory accessed using CoAP over TCP [:rfc:`9176`];
           [UDP] Resource Directory accessed using CoAP [:rfc:`9176`]
       * - ``core-rd-dtls``
         - [UDP] Resource Directory accessed using CoAP over DTLS [:rfc:`9176`]
       * - ``coviot``
         - [TCP] Service for coviot branded devices; [UDP] Service for coviot
           branded devices
       * - ``dbaudio``
         - [TCP] d&b audiotechnik remote network; [UDP] d&b audiotechnik remote
           network
       * - ``dell-soo-ds``
         - [TCP] Spotlight on Oracle Diagnostic Server; [UDP] Spotlight on
           Oracle Diagnostic Server
       * - ``demoncamremote``
         - [TCP] Peer-to-peer real-time video streaming; [UDP] Peer-to-peer
           real-time video streaming
       * - ``dhanda-g``
         - [TCP] DHANDAg is going for a site; [UDP] DHANDAg is going for a
           site; [SCTP] DHANDAg is going for a site
       * - ``dltimesync``
         - [UDP] Local Area Dynamic Time Synchronisation Protocol
       * - ``dns-update``
         - [TCP] DNS Dynamic Update Service; [UDP] DNS Dynamic Update Service
       * - ``dots-call-home``
         - [TCP] DOTS Signal Channel Call Home Protocol. The service name is
           used to construct the SRV service names "_dots-call-home._udp" and
           "_dots-call-home._tcp" for discovering Call Home DOTS clients used
           to establish DOTS signal channel call home. [:rfc:`8973`]; [UDP]
           DOTS Signal Channel Call Home Protocol. The service name is used to
           construct the SRV service names "_dots-call-home._udp" and "_dots-
           call-home._tcp" for discovering Call Home DOTS clients used to
           establish DOTS signal channel call home. [:rfc:`8973`]
       * - ``eb-sync``
         - [TCP] Easy Books App data sync helper for Mac OS X and iOS; [UDP]
           Easy Books App data sync helper for Mac OS X and iOS
       * - ``edcp``
         - [UDP] LaCie Ethernet Disk Configuration Protocol
       * - ``est-coaps``
         - [UDP] EST over secure CoAP (EST-coaps)
       * - ``fl-purr``
         - [UDP] FilmLight Cluster Power Control Service
       * - ``flightdmp``
         - [TCP] Flight Data Monitoring Protocol; [UDP] Flight Data Monitoring
           Protocol
       * - ``fv-cert``
         - [UDP] Fairview Certificate
       * - ``fv-key``
         - [UDP] Fairview Key
       * - ``fv-time``
         - [UDP] Fairview Time/Date
       * - ``googexpeditions``
         - [TCP] Service related to Google Expeditions which is a technology
           for enabling multi-participant virtual fieldtrip experiences over a
           local wireless network. See http://g.co/expeditions for more
           details; [UDP] Service related to Google Expeditions which is a
           technology for enabling multi-participant virtual fieldtrip
           experiences over a local wireless network. See
           http://g.co/expeditions for more details
       * - ``gopro-wake``
         - [UDP] GoPro proprietary protocol to wake devices
       * - ``gopro-web``
         - [UDP] GoPro proprietary protocol for devices
       * - ``honeywell-vid``
         - [UDP] Honeywell Video Systems
       * - ``htvncconf``
         - [UDP] HomeTouch Vnc Configuration
       * - ``im``
         - [TCP] Instant Messaging [:rfc:`3861`]; [UDP] Instant Messaging
           [:rfc:`3861`]
       * - ``iperfd``
         - [TCP] Network socket performance test; [UDP] Network socket
           performance test
       * - ``irobotmcs``
         - [TCP] iRobot Monitor and Control Service; [UDP] iRobot Monitor and
           Control Service
       * - ``knx``
         - [TCP] KNX Discovery Protocol; [UDP] Discovery in KNX IoT Point API
       * - ``labyrinth``
         - [UDP] Labyrinth local multiplayer protocol
       * - ``larvaio-control``
         - [TCP] Larva IP Controller; [UDP] Larva IP Controller
       * - ``logicnode``
         - [UDP] Logic Pro Distributed Audio
       * - ``m30s1pt``
         - [TCP] Moritz30-Project Standard protocol 1 Plain Text; [UDP]
           Moritz30-Project Standard protocol 1 Plain Text
       * - ``macfoh-audio``
         - [UDP] MacFOH audio stream
       * - ``macfoh-events``
         - [UDP] MacFOH show control events
       * - ``macfoh-data``
         - [UDP] MacFOH realtime data
       * - ``mas``
         - [TCP] Pravala Mobility and Aggregation Service; [UDP] Pravala
           Mobility and Aggregation Service
       * - ``matterc``
         - [TCP] Matter Commissionable Node Discovery; [UDP] Matter
           Commissionable Node Discovery
       * - ``matterd``
         - [TCP] Matter Commissioner Discovery; [UDP] Matter Commissioner
           Discovery
       * - ``mazepseudo-game``
         - [UDP] Peer to peer communication between instances of the Maze
           Pseudo game.
       * - ``meshcop``
         - [UDP] Thread Mesh Commissioning
       * - ``meshcop-e``
         - [UDP] Thread Mesh Commissioning Ephemeral-key
       * - ``midi2``
         - [UDP] MIDI 2.0 Device Discovery
       * - ``mn-passage``
         - [TCP] A Remote Control Application service used to control Computers
           on a Local Area Network; [UDP] A Remote Control Application service
           used to control Computers on a Local Area Network
       * - ``moncon``
         - [UDP] Sonnox MCON monitor controller protocol
       * - ``nasmon``
         - [TCP] Proprietary communication protocol for NAS Monitor; [UDP]
           Proprietary communication protocol for NAS Monitor
       * - ``ndi``
         - [TCP] IP based video discovery and usage; [UDP] IP based video
           discovery and usage
       * - ``neoriders``
         - [UDP] NeoRiders Client Discovery Protocol
       * - ``nextcap``
         - [TCP] Proprietary communication protocol for NextCap capture
           solution; [UDP] Proprietary communication protocol for NextCap
           capture solution
       * - ``ni-ftp``
         - [TCP] NI FTP; [UDP] NI FTP
       * - ``ni-mail``
         - [TCP] NI MAIL; [UDP] NI MAIL
       * - ``ntx``
         - [UDP] Tenasys
       * - ``oak``
         - [TCP] Oak Device Services; [UDP] Oak Device Services
       * - ``oca``
         - [TCP] Insecure OCP.1 protocol, which is the insecure TCP/IP
           implementation of the Object Control Architecture; [UDP] Insecure
           OCP.1 protocol, which is the insecure TCP/IP implementation of the
           Object Control Architecture
       * - ``ocasec``
         - [TCP] Secure OCP.1 protocol, which is the secure TCP/IP
           implementation of the Object Control Architecture; [UDP] Secure
           OCP.1 protocol, which is the secure TCP/IP implementation of the
           Object Control Architecture
       * - ``olpc-activity1``
         - [UDP] One Laptop per Child activity
       * - ``onenet-pgn``
         - [UDP] OneNet PGN Transport Service
       * - ``opencu``
         - [UDP] Conferencing Protocol
       * - ``oscit``
         - [UDP] Open Sound Control Interface Transfer
       * - ``p2pchat``
         - [UDP] Peer-to-Peer Chat (Sample Java Bonjour application)
       * - ``parity``
         - [TCP] PA-R-I-Ty (Public Address - Radio - Intercom - Telefony);
           [UDP] PA-R-I-Ty (Public Address - Radio - Intercom - Telefony)
       * - ``payload-app``
         - [TCP] Local and remote file transfers; [UDP] Local and remote file
           transfers
       * - ``pres``
         - [TCP] Presence [:rfc:`3861`]; [UDP] Presence [:rfc:`3861`]
       * - ``psap``
         - [UDP] Progal Service Advertising Protocol
       * - ``radioport``
         - [TCP] RadioPort Message Service; [UDP] RadioPort Message Service
       * - ``radiusdtls``
         - [UDP] Authentication, Accounting, and Dynamic Authorization via the
           RADIUS protocol. This service name is used to construct the SRV
           service label "_radiusdtls" for discovery of RADIUS/DTLS servers.
           [:rfc:`7585`]
       * - ``recolive-cc``
         - [TCP] Remote Camera Control; [UDP] Remote Camera Control
       * - ``scoop-sftp``
         - [TCP] The service name is used by the SFTP protocol to upload log
           files from vehicles to road side units in a securely way in a
           cooperative intelligent transportation system.; [UDP] The service
           name is used by the SFTP protocol to upload log files from vehicles
           to road side units in a securely way in a cooperative intelligent
           transportation system.
       * - ``shots-sync``
         - [UDP] The protocol is used to sync database among iOS devices and
           Mac OS X computers.
       * - ``skillscapture``
         - [TCP] The protocol is used to transfer database records between an
           iOS device to a Mac OS X computer; [UDP] The protocol is used to
           transfer database records between an iOS device to a Mac OS X
           computer
       * - ``sleep-proxy``
         - [UDP] Sleep Proxy Server
       * - ``slpda``
         - [TCP] Remote Service Discovery in the Service Location
           [:rfc:`3832`]; [UDP] Remote Service Discovery in the Service
           Location [:rfc:`3832`]
       * - ``ss-sign-disc``
         - [UDP] Samsung Smart Interaction for Group Network Discovery
       * - ``sugarlock-rcp``
         - [TCP] Remote control protocol for Sugarlock consumer electronics
           devices; [UDP] Remote control protocol for Sugarlock consumer
           electronics devices
       * - ``ted``
         - [UDP] Teddington Controls
       * - ``teleport``
         - [UDP] teleport
       * - ``thing``
         - [TCP] Internet of things service discovery; [UDP] Internet of things
           service discovery
       * - ``tmsensor``
         - [TCP] Teledyne Marine Sensor; [UDP] Teledyne Marine Sensor
       * - ``tokenlens``
         - [TCP] AI token usage and billing metering; [UDP] AI token usage and
           billing metering
       * - ``trel``
         - [UDP] Thread Radio Encapsulation Link
       * - ``ucdynamics-tuc``
         - [UDP] Tactical Unified Communicator
       * - ``usp-agt-coap``
         - [UDP] USP discovery [http://www.broadband-forum.org/assignments]
       * - ``usp-ctr-coap``
         - [UDP] USP discovery [http://www.broadband-forum.org/assignments]
       * - ``wchr``
         - [UDP] Powered wheelchair command protocol
       * - ``webex``
         - [TCP] Cisco WebEx serials products will release Bonjour based
           service; [UDP] Cisco WebEx serials products will release Bonjour
           based service
       * - ``wicop``
         - [UDP] WiFi Control Platform
       * - ``wot``
         - [TCP] W3C WoT Thing Description or Directory; [UDP] W3C WoT Thing
           Description or Directory
       * - ``x-plane9``
         - [UDP] x-plane9
       * - ``yakumo``
         - [UDP] Yakumo iPhone OS Device Control Protocol
       * - ``z-wave``
         - [TCP] Z-Wave Service Discovery; [UDP] Z-Wave Service Discovery
       * - ``zeromq``
         - [TCP] High performance brokerless messaging; [UDP] High performance
           brokerless messaging
       * - ``zigbee-bridge``
         - [TCP] ZigBee Bridge device; [UDP] ZigBee Bridge device
       * - ``zigbee-gateway``
         - [TCP] ZigBee IP Gateway; [UDP] ZigBee IP Gateway

    """

    #: Transport protocol whose assignments this registry holds.
    __transport__: 'TransportProtocol' = TransportProtocol.udp

    #: Members of this registry, keyed on port number. Declared per registry
    #: rather than inherited, since one mapping shared by all four would put
    #: every transport's ports in the same key space.
    __registry__: 'MultiDict[int, UDP]' = MultiDict()

    #: The canonical service for each port IANA assigns more than one to, i.e.
    #: what :meth:`~pcapkit.const.reg.apptype.apptype.AppType.get` answers with.
    #: Taken from :file:`/etc/services`, which is what
    #: :func:`socket.getservbyport` reads -- IANA names no precedence among the
    #: services it registers on one port, and registry row order does not supply
    #: one either. The rest stay reachable through
    #: :meth:`~pcapkit.const.reg.apptype.apptype.AppType.get_all`.
    __canonical__: 'dict[int, str]' = {
        42: 'nameserver',
        63: 'whois++',
        80: 'http',
        105: 'csnet-ns',
        351: 'matip-type-b',
        352: 'dtag-ste-sb',
        512: 'biff',
        666: 'mdqs',
        750: 'kerberos-iv',
        999: 'applix',
        1525: 'prospero-np',
        1701: 'l2tp',
        1989: 'tr-rsrb-p3',
        1992: 'stun-p3',
        2049: 'nfs',
        3000: 'hbci',
        3002: 'exlm-agent',
        3478: 'stun',
        4444: 'krb524',
        5349: 'stuns',
        9100: 'hp-pdl-datastr',
    }

    #: - [TCP] Reserved [:rfc:`6335`]
    #: - [UDP] Reserved [:rfc:`6335`]
    reserved_0 = 0, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TCP Port Service Multiplexer
    #: - [UDP] TCP Port Service Multiplexer
    tcpmux = 1, 'tcpmux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_2 = 2, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_3 = 3, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_4 = 4, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Job Entry
    #: - [UDP] Remote Job Entry
    rje = 5, 'rje', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_6 = 6, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Echo
    #: - [UDP] Echo
    echo = 7, 'echo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_8 = 8, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Discard
    #: - [UDP] Discard
    #: - [SCTP] Discard [:rfc:`9260`]
    #: - [DCCP] Discard [:rfc:`4340`]
    discard = 9, 'discard', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp | TransportProtocol.dccp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_10 = 10, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Active Users
    #: - [UDP] Active Users
    systat = 11, 'systat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_12 = 12, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Daytime [:rfc:`867`]
    #: - [UDP] Daytime [:rfc:`867`]
    daytime = 13, 'daytime', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_14 = 14, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Unassigned
    unassigned_15 = 15, 'unassigned', TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_16 = 16, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quote of the Day
    #: - [UDP] Quote of the Day
    qotd = 17, 'qotd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Character Generator
    #: - [UDP] Character Generator
    chargen = 19, 'chargen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] File Transfer [Default Data]
    #: - [UDP] File Transfer [Default Data]
    #: - [SCTP] FTP [:rfc:`9260`]
    ftp_data = 20, 'ftp-data', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] File Transfer Protocol [Control] [:rfc:`959`]
    #: - [UDP] File Transfer Protocol [Control] [:rfc:`959`]
    #: - [SCTP] FTP [:rfc:`9260`]
    ftp = 21, 'ftp', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Telnet [:rfc:`854`]
    #: - [UDP] Telnet [:rfc:`854`]
    telnet = 23, 'telnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] any private mail system
    #: - [UDP] any private mail system
    any_private_mail_system = 24, 'any_private_mail_system', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Mail Transfer [RFC-ietf-emailcore-rfc5321bis-43]
    #: - [UDP] Simple Mail Transfer [RFC-ietf-emailcore-rfc5321bis-43]
    smtp = 25, 'smtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_26 = 26, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NSW User System FE
    #: - [UDP] NSW User System FE
    nsw_fe = 27, 'nsw-fe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_28 = 28, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSG ICP
    #: - [UDP] MSG ICP
    msg_icp = 29, 'msg-icp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_30 = 30, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSG Authentication
    #: - [UDP] MSG Authentication
    msg_auth = 31, 'msg-auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_32 = 32, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Display Support Protocol
    #: - [UDP] Display Support Protocol
    dsp = 33, 'dsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_34 = 34, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] any private printer server
    #: - [UDP] any private printer server
    any_private_printer_server = 35, 'any_private_printer_server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_36 = 36, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Time
    #: - [UDP] Time
    time = 37, 'time', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Resource Location Protocol
    #: - [UDP] Resource Location Protocol
    rlp = 39, 'rlp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_40 = 40, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Graphics
    #: - [UDP] Graphics
    graphics = 41, 'graphics', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Host Name Server
    #: - [UDP] Host Name Server
    name = 42, 'name', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Host Name Server
    #: - [UDP] Host Name Server
    nameserver = 42, 'nameserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Who Is
    #: - [UDP] Who Is
    nicname = 43, 'nicname', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MPM FLAGS Protocol
    #: - [UDP] MPM FLAGS Protocol
    mpm_flags = 44, 'mpm-flags', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message Processing Module [recv]
    #: - [UDP] Message Processing Module [recv]
    mpm = 45, 'mpm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MPM [default send]
    #: - [UDP] MPM [default send]
    mpm_snd = 46, 'mpm-snd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_47 = 47, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Digital Audit Daemon
    #: - [UDP] Digital Audit Daemon
    auditd = 48, 'auditd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Login Host Protocol (TACACS)
    #: - [UDP] Login Host Protocol (TACACS)
    tacacs = 49, 'tacacs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Mail Checking Protocol
    #: - [UDP] Remote Mail Checking Protocol
    re_mail_ck = 50, 're-mail-ck', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XNS Time Protocol
    #: - [UDP] XNS Time Protocol
    xns_time = 52, 'xns-time', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Domain Name Server
    #: - [UDP] Domain Name Server
    domain = 53, 'domain', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XNS Clearinghouse
    #: - [UDP] XNS Clearinghouse
    xns_ch = 54, 'xns-ch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISI Graphics Language
    #: - [UDP] ISI Graphics Language
    isi_gl = 55, 'isi-gl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XNS Authentication
    #: - [UDP] XNS Authentication
    xns_auth = 56, 'xns-auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] any private terminal access
    #: - [UDP] any private terminal access
    any_private_terminal_access = 57, 'any_private_terminal_access', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XNS Mail
    #: - [UDP] XNS Mail
    xns_mail = 58, 'xns-mail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] any private file service
    #: - [UDP] any private file service
    any_private_file_service = 59, 'any_private_file_service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_60 = 60, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_61 = 61, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACA Services
    #: - [UDP] ACA Services
    acas = 62, 'acas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] whois++ IANA assigned this well-formed service name as a replacement
    #:   for "whois++".
    #: - [UDP] whois++ IANA assigned this well-formed service name as a replacement
    #:   for "whois++".
    whoispp = 63, 'whoispp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] whois++
    #: - [UDP] whois++
    whois = 63, 'whois++', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Communications Integrator (CI)
    #: - [UDP] Communications Integrator (CI)
    covia = 64, 'covia', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TACACS-Database Service
    #: - [UDP] TACACS-Database Service
    tacacs_ds = 65, 'tacacs-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bootstrap Protocol Server [:rfc:`951`]
    #: - [UDP] Bootstrap Protocol Server
    bootps = 67, 'bootps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bootstrap Protocol Client
    #: - [UDP] Bootstrap Protocol Client
    bootpc = 68, 'bootpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trivial File Transfer
    #: - [UDP] Trivial File Transfer
    tftp = 69, 'tftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gopher
    #: - [UDP] Gopher
    gopher = 70, 'gopher', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Job Service
    #: - [UDP] Remote Job Service
    netrjs_1 = 71, 'netrjs-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Job Service
    #: - [UDP] Remote Job Service
    netrjs_2 = 72, 'netrjs-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Job Service
    #: - [UDP] Remote Job Service
    netrjs_3 = 73, 'netrjs-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Job Service
    #: - [UDP] Remote Job Service
    netrjs_4 = 74, 'netrjs-4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] any private dial out service
    #: - [UDP] any private dial out service
    any_private_dial_out_service = 75, 'any_private_dial_out_service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Distributed External Object Store
    #: - [UDP] Distributed External Object Store
    deos = 76, 'deos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] any private RJE service
    #: - [UDP] any private RJE service
    any_private_rje_service = 77, 'any_private_rje_service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vettcp
    #: - [UDP] vettcp
    vettcp = 78, 'vettcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Finger
    #: - [UDP] Finger
    finger = 79, 'finger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] World Wide Web HTTP [:rfc:`9110`]
    #: - [UDP] World Wide Web HTTP [:rfc:`9110`]
    #: - [SCTP] HTTP [:rfc:`9260`]
    http = 80, 'http', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] World Wide Web HTTP [:rfc:`9110`]
    #: - [UDP] World Wide Web HTTP [:rfc:`9110`]
    www = 80, 'www', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] World Wide Web HTTP
    #: - [UDP] World Wide Web HTTP
    www_http = 80, 'www-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XFER Utility
    #: - [UDP] XFER Utility
    xfer = 82, 'xfer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Common Trace Facility
    #: - [UDP] Common Trace Facility
    ctf = 84, 'ctf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MIT ML Device
    #: - [UDP] MIT ML Device
    mit_ml_dev_83 = 83, 'mit-ml-dev', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MIT ML Device
    #: - [UDP] MIT ML Device
    mit_ml_dev_85 = 85, 'mit-ml-dev', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Micro Focus Cobol
    #: - [UDP] Micro Focus Cobol
    mfcobol = 86, 'mfcobol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] any private terminal link
    #: - [UDP] any private terminal link
    any_private_terminal_link = 87, 'any_private_terminal_link', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kerberos [:rfc:`4120`]
    #: - [UDP] Kerberos [:rfc:`4120`]
    kerberos = 88, 'kerberos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SU/MIT Telnet Gateway
    #: - [UDP] SU/MIT Telnet Gateway
    su_mit_tg = 89, 'su-mit-tg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNSIX Securit Attribute Token Map
    #: - [UDP] DNSIX Securit Attribute Token Map
    dnsix = 90, 'dnsix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MIT Dover Spooler
    #: - [UDP] MIT Dover Spooler
    mit_dov = 91, 'mit-dov', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Device Control Protocol
    #: - [UDP] Device Control Protocol
    dcp = 93, 'dcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tivoli Object Dispatcher
    #: - [UDP] Tivoli Object Dispatcher
    objcall = 94, 'objcall', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SUPDUP
    #: - [UDP] SUPDUP
    supdup = 95, 'supdup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DIXIE Protocol Specification
    #: - [UDP] DIXIE Protocol Specification
    dixie = 96, 'dixie', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Swift Remote Virtural File Protocol
    #: - [UDP] Swift Remote Virtural File Protocol
    swift_rvf = 97, 'swift-rvf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TAC News
    #: - [UDP] TAC News
    tacnews = 98, 'tacnews', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Metagram Relay
    #: - [UDP] Metagram Relay
    metagram = 99, 'metagram', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NIC Host Name Server
    #: - [UDP] NIC Host Name Server
    hostname = 101, 'hostname', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISO-TSAP Class 0
    #: - [UDP] ISO-TSAP Class 0
    iso_tsap = 102, 'iso-tsap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Genesis Point-to-Point Trans Net
    #: - [UDP] Genesis Point-to-Point Trans Net
    gppitnp = 103, 'gppitnp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACR-NEMA Digital Imag. & Comm. 300
    #: - [UDP] ACR-NEMA Digital Imag. & Comm. 300
    acr_nema = 104, 'acr-nema', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CCSO name server protocol
    #: - [UDP] CCSO name server protocol
    cso = 105, 'cso', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mailbox Name Nameserver
    #: - [UDP] Mailbox Name Nameserver
    csnet_ns = 105, 'csnet-ns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3COM-TSMUX
    #: - [UDP] 3COM-TSMUX
    UDP_3com_tsmux = 106, '3com-tsmux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Telnet Service
    #: - [UDP] Remote Telnet Service
    rtelnet = 107, 'rtelnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNA Gateway Access Server
    #: - [UDP] SNA Gateway Access Server
    snagas = 108, 'snagas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Post Office Protocol - Version 2
    #: - [UDP] Post Office Protocol - Version 2
    pop2 = 109, 'pop2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Post Office Protocol - Version 3
    #: - [UDP] Post Office Protocol - Version 3
    pop3 = 110, 'pop3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SUN Remote Procedure Call
    #: - [UDP] SUN Remote Procedure Call
    sunrpc = 111, 'sunrpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] McIDAS Data Transmission Protocol
    #: - [UDP] McIDAS Data Transmission Protocol
    mcidas = 112, 'mcidas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Authentication Service
    #: - [UDP] Authentication Service
    auth = 113, 'auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple File Transfer Protocol
    #: - [UDP] Simple File Transfer Protocol
    sftp = 115, 'sftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ANSA REX Notify
    #: - [UDP] ANSA REX Notify
    ansanotify = 116, 'ansanotify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UUCP Path Service
    #: - [UDP] UUCP Path Service
    uucp_path = 117, 'uucp-path', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SQL Services
    #: - [UDP] SQL Services
    sqlserv = 118, 'sqlserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network News Transfer Protocol [:rfc:`3977`]
    #: - [UDP] Network News Transfer Protocol [:rfc:`3977`]
    nntp = 119, 'nntp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CFDPTKT
    #: - [UDP] CFDPTKT
    cfdptkt = 120, 'cfdptkt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Encore Expedited Remote Pro.Call
    #: - [UDP] Encore Expedited Remote Pro.Call
    erpc = 121, 'erpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMAKYNET
    #: - [UDP] SMAKYNET
    smakynet = 122, 'smakynet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Time Protocol [:rfc:`5905`]
    #: - [UDP] Network Time Protocol [:rfc:`5905`]
    ntp = 123, 'ntp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ANSA REX Trader
    #: - [UDP] ANSA REX Trader
    ansatrader = 124, 'ansatrader', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Locus PC-Interface Net Map Ser
    #: - [UDP] Locus PC-Interface Net Map Ser
    locus_map = 125, 'locus-map', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NXEdit
    #: - [UDP] NXEdit
    nxedit = 126, 'nxedit', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Locus PC-Interface Conn Server
    #: - [UDP] Locus PC-Interface Conn Server
    locus_con = 127, 'locus-con', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GSS X License Verification
    #: - [UDP] GSS X License Verification
    gss_xlicen = 128, 'gss-xlicen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Password Generator Protocol
    #: - [UDP] Password Generator Protocol
    pwdgen = 129, 'pwdgen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco FNATIVE
    #: - [UDP] cisco FNATIVE
    cisco_fna = 130, 'cisco-fna', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco TNATIVE
    #: - [UDP] cisco TNATIVE
    cisco_tna = 131, 'cisco-tna', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco SYSMAINT
    #: - [UDP] cisco SYSMAINT
    cisco_sys = 132, 'cisco-sys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Statistics Service
    #: - [UDP] Statistics Service
    statsrv = 133, 'statsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INGRES-NET Service
    #: - [UDP] INGRES-NET Service
    ingres_net = 134, 'ingres-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DCE endpoint resolution
    #: - [UDP] DCE endpoint resolution
    epmap = 135, 'epmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PROFILE Naming System
    #: - [UDP] PROFILE Naming System
    profile = 136, 'profile', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETBIOS Name Service
    #: - [UDP] NETBIOS Name Service
    netbios_ns = 137, 'netbios-ns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETBIOS Datagram Service
    #: - [UDP] NETBIOS Datagram Service
    netbios_dgm = 138, 'netbios-dgm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETBIOS Session Service
    #: - [UDP] NETBIOS Session Service
    netbios_ssn = 139, 'netbios-ssn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMFIS Data Service
    #: - [UDP] EMFIS Data Service
    emfis_data = 140, 'emfis-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMFIS Control Service
    #: - [UDP] EMFIS Control Service
    emfis_cntl = 141, 'emfis-cntl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Britton-Lee IDM
    #: - [UDP] Britton-Lee IDM
    bl_idm = 142, 'bl-idm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved [:rfc:`9051`]
    reserved_143 = 143, 'reserved', TransportProtocol.udp

    #: - [TCP] UAAC Protocol
    #: - [UDP] UAAC Protocol
    uaac = 145, 'uaac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISO-IP0
    #: - [UDP] ISO-IP0
    iso_tp0 = 146, 'iso-tp0', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISO-IP
    #: - [UDP] ISO-IP
    iso_ip = 147, 'iso-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jargon
    #: - [UDP] Jargon
    jargon = 148, 'jargon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AED 512 Emulation Service
    #: - [UDP] AED 512 Emulation Service
    aed_512 = 149, 'aed-512', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle SQL*NET IANA assigned this well-formed service name as a
    #:   replacement for "sql*net".
    #: - [TCP] Oracle SQL*NET
    #: - [UDP] Oracle SQL*NET IANA assigned this well-formed service name as a
    #:   replacement for "sql*net".
    #: - [UDP] Oracle SQL*NET
    sql_net_66 = 66, 'sql-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SQL-NET
    #: - [UDP] SQL-NET
    sql_net_150 = 150, 'sql-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HEMS
    #: - [UDP] HEMS
    hems = 151, 'hems', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Background File Transfer Program
    #: - [UDP] Background File Transfer Program
    bftp = 152, 'bftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SGMP
    #: - [UDP] SGMP
    sgmp = 153, 'sgmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETSC
    #: - [UDP] NETSC
    netsc_prod = 154, 'netsc-prod', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETSC
    #: - [UDP] NETSC
    netsc_dev = 155, 'netsc-dev', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SQL Service
    #: - [UDP] SQL Service
    sqlsrv = 156, 'sqlsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KNET/VM Command/Message Protocol
    #: - [UDP] KNET/VM Command/Message Protocol
    knet_cmp = 157, 'knet-cmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCMail Server
    #: - [UDP] PCMail Server
    pcmail_srv = 158, 'pcmail-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NSS-Routing
    #: - [UDP] NSS-Routing
    nss_routing = 159, 'nss-routing', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SGMP-TRAPS
    #: - [UDP] SGMP-TRAPS
    sgmp_traps = 160, 'sgmp-traps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNMP
    #: - [UDP] SNMP
    snmp = 161, 'snmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNMPTRAP
    #: - [UDP] SNMPTRAP
    snmptrap = 162, 'snmptrap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CMIP/TCP Manager
    #: - [UDP] CMIP/TCP Manager
    cmip_man = 163, 'cmip-man', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CMIP/TCP Agent
    #: - [UDP] CMIP/TCP Agent
    cmip_agent = 164, 'cmip-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xerox
    #: - [UDP] Xerox
    xns_courier = 165, 'xns-courier', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sirius Systems
    #: - [UDP] Sirius Systems
    s_net = 166, 's-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NAMP
    #: - [UDP] NAMP
    namp = 167, 'namp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSVD
    #: - [UDP] RSVD
    rsvd = 168, 'rsvd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SEND
    #: - [UDP] SEND
    send = 169, 'send', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network PostScript
    #: - [UDP] Network PostScript
    print_srv = 170, 'print-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Innovations Multiplex
    #: - [UDP] Network Innovations Multiplex
    multiplex = 171, 'multiplex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Innovations CL/1 IANA assigned this well-formed service name
    #:   as a replacement for "cl/1".
    #: - [TCP] Network Innovations CL/1
    #: - [UDP] Network Innovations CL/1 IANA assigned this well-formed service name
    #:   as a replacement for "cl/1".
    #: - [UDP] Network Innovations CL/1
    cl_1 = 172, 'cl-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xyplex
    #: - [UDP] Xyplex
    xyplex_mux = 173, 'xyplex-mux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MAILQ
    #: - [UDP] MAILQ
    mailq = 174, 'mailq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VMNET
    #: - [UDP] VMNET
    vmnet = 175, 'vmnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GENRAD-MUX
    #: - [UDP] GENRAD-MUX
    genrad_mux = 176, 'genrad-mux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] X Display Manager Control Protocol
    #: - [UDP] X Display Manager Control Protocol
    xdmcp = 177, 'xdmcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NextStep Window Server
    #: - [UDP] NextStep Window Server
    nextstep = 178, 'nextstep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Border Gateway Protocol
    #: - [UDP] Border Gateway Protocol
    #: - [SCTP] BGP [:rfc:`9260`]
    bgp = 179, 'bgp', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Intergraph
    #: - [UDP] Intergraph
    ris = 180, 'ris', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unify
    #: - [UDP] Unify
    unify = 181, 'unify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unisys Audit SITP
    #: - [UDP] Unisys Audit SITP
    audit = 182, 'audit', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OCBinder
    #: - [UDP] OCBinder
    ocbinder = 183, 'ocbinder', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OCServer
    #: - [UDP] OCServer
    ocserver = 184, 'ocserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote-KIS
    #: - [UDP] Remote-KIS
    remote_kis = 185, 'remote-kis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KIS Protocol
    #: - [UDP] KIS Protocol
    kis = 186, 'kis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Application Communication Interface
    #: - [UDP] Application Communication Interface
    aci = 187, 'aci', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Plus Five's MUMPS
    #: - [UDP] Plus Five's MUMPS
    mumps = 188, 'mumps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Queued File Transport
    #: - [UDP] Queued File Transport
    qft = 189, 'qft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gateway Access Control Protocol
    #: - [UDP] Gateway Access Control Protocol
    gacp = 190, 'gacp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prospero Directory Service
    #: - [UDP] Prospero Directory Service
    prospero = 191, 'prospero', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OSU Network Monitoring System
    #: - [UDP] OSU Network Monitoring System
    osu_nms = 192, 'osu-nms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Spider Remote Monitoring Protocol
    #: - [UDP] Spider Remote Monitoring Protocol
    srmp = 193, 'srmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Internet Relay Chat Protocol
    #: - [UDP] Internet Relay Chat Protocol
    irc = 194, 'irc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNSIX Network Level Module Audit
    #: - [UDP] DNSIX Network Level Module Audit
    dn6_nlm_aud = 195, 'dn6-nlm-aud', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNSIX Session Mgt Module Audit Redir
    #: - [UDP] DNSIX Session Mgt Module Audit Redir
    dn6_smm_red = 196, 'dn6-smm-red', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Directory Location Service Monitor
    #: - [UDP] Directory Location Service Monitor
    dls_mon = 198, 'dls-mon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMUX
    #: - [UDP] SMUX
    smux = 199, 'smux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM System Resource Controller
    #: - [UDP] IBM System Resource Controller
    src = 200, 'src', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleTalk Routing Maintenance
    #: - [UDP] AppleTalk Routing Maintenance
    at_rtmp = 201, 'at-rtmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleTalk Name Binding
    #: - [UDP] AppleTalk Name Binding
    at_nbp = 202, 'at-nbp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleTalk Unused
    #: - [UDP] AppleTalk Unused
    at_3 = 203, 'at-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleTalk Echo
    #: - [UDP] AppleTalk Echo
    at_echo = 204, 'at-echo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleTalk Unused
    #: - [UDP] AppleTalk Unused
    at_5 = 205, 'at-5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleTalk Zone Information
    #: - [UDP] AppleTalk Zone Information
    at_zis = 206, 'at-zis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleTalk Unused
    #: - [UDP] AppleTalk Unused
    at_7 = 207, 'at-7', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleTalk Unused
    #: - [UDP] AppleTalk Unused
    at_8 = 208, 'at-8', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] The Quick Mail Transfer Protocol
    #: - [UDP] The Quick Mail Transfer Protocol
    qmtp = 209, 'qmtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ANSI Z39.50 IANA assigned this well-formed service name as a
    #:   replacement for "z39.50".
    #: - [TCP] ANSI Z39.50
    #: - [UDP] ANSI Z39.50 IANA assigned this well-formed service name as a
    #:   replacement for "z39.50".
    #: - [UDP] ANSI Z39.50
    z39_50 = 210, 'z39-50', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Texas Instruments 914C/G Terminal IANA assigned this well-formed
    #:   service name as a replacement for "914c/g".
    #: - [TCP] Texas Instruments 914C/G Terminal
    #: - [UDP] Texas Instruments 914C/G Terminal IANA assigned this well-formed
    #:   service name as a replacement for "914c/g".
    #: - [UDP] Texas Instruments 914C/G Terminal
    UDP_914c_g = 211, '914c-g', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ATEXSSTR
    #: - [UDP] ATEXSSTR
    anet = 212, 'anet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPX
    #: - [UDP] IPX
    ipx = 213, 'ipx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VM PWSCS
    #: - [UDP] VM PWSCS
    vmpwscs = 214, 'vmpwscs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Insignia Solutions
    #: - [UDP] Insignia Solutions
    softpc = 215, 'softpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Computer Associates Int'l License Server
    #: - [UDP] Computer Associates Int'l License Server
    cailic = 216, 'cailic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dBASE Unix
    #: - [UDP] dBASE Unix
    dbase = 217, 'dbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netix Message Posting Protocol
    #: - [UDP] Netix Message Posting Protocol
    mpp = 218, 'mpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unisys ARPs
    #: - [UDP] Unisys ARPs
    uarps = 219, 'uarps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Interactive Mail Access Protocol v3
    #: - [UDP] Interactive Mail Access Protocol v3
    imap3 = 220, 'imap3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Berkeley rlogind with SPX auth
    #: - [UDP] Berkeley rlogind with SPX auth
    fln_spx = 221, 'fln-spx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Berkeley rshd with SPX auth
    #: - [UDP] Berkeley rshd with SPX auth
    rsh_spx = 222, 'rsh-spx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Certificate Distribution Center
    #: - [UDP] Certificate Distribution Center
    cdc = 223, 'cdc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] masqdialer
    #: - [UDP] masqdialer
    masqdialer = 224, 'masqdialer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Direct
    #: - [UDP] Direct
    direct = 242, 'direct', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Survey Measurement
    #: - [UDP] Survey Measurement
    sur_meas = 243, 'sur-meas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] inbusiness
    #: - [UDP] inbusiness
    inbusiness = 244, 'inbusiness', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LINK
    #: - [UDP] LINK
    link = 245, 'link', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Display Systems Protocol
    #: - [UDP] Display Systems Protocol
    dsp3270 = 246, 'dsp3270', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SUBNTBCST_TFTP IANA assigned this well-formed service name as a
    #:   replacement for "subntbcst_tftp".
    #: - [TCP] SUBNTBCST_TFTP
    #: - [UDP] SUBNTBCST_TFTP IANA assigned this well-formed service name as a
    #:   replacement for "subntbcst_tftp".
    #: - [UDP] SUBNTBCST_TFTP
    subntbcst_tftp = 247, 'subntbcst-tftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bhfhs
    #: - [UDP] bhfhs
    bhfhs = 248, 'bhfhs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Route Access Protocol
    #: - [UDP] Route Access Protocol
    rap_38 = 38, 'rap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RAP
    #: - [UDP] RAP
    rap_256 = 256, 'rap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Electronic Transaction
    #: - [UDP] Secure Electronic Transaction
    set = 257, 'set', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Efficient Short Remote Operations
    #: - [UDP] Efficient Short Remote Operations
    esro_gen = 259, 'esro-gen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Openport
    #: - [UDP] Openport
    openport = 260, 'openport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IIOP Name Service over TLS/SSL
    #: - [UDP] IIOP Name Service over TLS/SSL
    nsiiops = 261, 'nsiiops', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Arcisdms
    #: - [UDP] Arcisdms
    arcisdms = 262, 'arcisdms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HDAP
    #: - [UDP] HDAP
    hdap = 263, 'hdap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BGMP
    #: - [UDP] BGMP
    bgmp = 264, 'bgmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] X-Bone CTL
    #: - [UDP] X-Bone CTL
    x_bone_ctl = 265, 'x-bone-ctl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCSI on ST
    #: - [UDP] SCSI on ST
    sst = 266, 'sst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tobit David Service Layer
    #: - [UDP] Tobit David Service Layer
    td_service = 267, 'td-service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tobit David Replica
    #: - [UDP] Tobit David Replica
    td_replica = 268, 'td-replica', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MANET Protocols [:rfc:`5498`]
    #: - [UDP] MANET Protocols [:rfc:`5498`]
    manet = 269, 'manet', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Q-mode encapsulation for GIST messages [:rfc:`5971`]
    gist = 270, 'gist', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_271 = 271, 'reserved', TransportProtocol.udp

    #: - [TCP] http-mgmt
    #: - [UDP] http-mgmt
    http_mgmt = 280, 'http-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Personal Link
    #: - [UDP] Personal Link
    personal_link = 281, 'personal-link', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cable Port A/X
    #: - [UDP] Cable Port A/X
    cableport_ax = 282, 'cableport-ax', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rescap
    #: - [UDP] rescap
    rescap = 283, 'rescap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] corerjd
    #: - [UDP] corerjd
    corerjd = 284, 'corerjd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] K-BLOCK
    #: - [UDP] K-BLOCK
    k_block = 287, 'k-block', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_300 = 300, 'reserved', TransportProtocol.udp

    #: - [TCP] Novastor Backup
    #: - [UDP] Novastor Backup
    novastorbakcup = 308, 'novastorbakcup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EntrustTime
    #: - [UDP] EntrustTime
    entrusttime = 309, 'entrusttime', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bhmds
    #: - [UDP] bhmds
    bhmds = 310, 'bhmds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppleShare IP WebAdmin
    #: - [UDP] AppleShare IP WebAdmin
    asip_webadmin = 311, 'asip-webadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSLMP
    #: - [UDP] VSLMP
    vslmp = 312, 'vslmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Magenta Logic
    #: - [UDP] Magenta Logic
    magenta_logic = 313, 'magenta-logic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Opalis Robot
    #: - [UDP] Opalis Robot
    opalis_robot = 314, 'opalis-robot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DPSI
    #: - [UDP] DPSI
    dpsi = 315, 'dpsi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] decAuth
    #: - [UDP] decAuth
    decauth = 316, 'decauth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zannet
    #: - [UDP] Zannet
    zannet = 317, 'zannet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PKIX TimeStamp
    #: - [UDP] PKIX TimeStamp
    pkix_timestamp = 318, 'pkix-timestamp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PTP Event
    #: - [UDP] PTP Event
    ptp_event = 319, 'ptp-event', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PTP General
    #: - [UDP] PTP General
    ptp_general = 320, 'ptp-general', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RTSPS
    #: - [UDP] RTSPS
    rtsps = 322, 'rtsps', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_323 = 323, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_324 = 324, 'reserved', TransportProtocol.udp

    #: - [TCP] Texar Security Port
    #: - [UDP] Texar Security Port
    texar = 333, 'texar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prospero Data Access Protocol
    #: - [UDP] Prospero Data Access Protocol
    pdap = 344, 'pdap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Perf Analysis Workbench
    #: - [UDP] Perf Analysis Workbench
    pawserv = 345, 'pawserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zebra server
    #: - [UDP] Zebra server
    zserv = 346, 'zserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fatmen Server
    #: - [UDP] Fatmen Server
    fatserv = 347, 'fatserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cabletron Management Protocol
    #: - [UDP] Cabletron Management Protocol
    csi_sgwp = 348, 'csi-sgwp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MATIP Type A [:rfc:`2351`]
    #: - [UDP] MATIP Type A [:rfc:`2351`]
    matip_type_a = 350, 'matip-type-a', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MATIP Type B [:rfc:`2351`]
    #: - [UDP] MATIP Type B [:rfc:`2351`]
    matip_type_b = 351, 'matip-type-b', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bhoetty
    #: - [UDP] bhoetty
    bhoetty = 351, 'bhoetty', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DTAG
    #: - [UDP] DTAG
    dtag_ste_sb = 352, 'dtag-ste-sb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bhoedap4
    #: - [UDP] bhoedap4
    bhoedap4 = 352, 'bhoedap4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NDSAUTH
    #: - [UDP] NDSAUTH
    ndsauth = 353, 'ndsauth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bh611
    #: - [UDP] bh611
    bh611 = 354, 'bh611', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DATEX-ASN
    #: - [UDP] DATEX-ASN
    datex_asn = 355, 'datex-asn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cloanto Net 1
    #: - [UDP] Cloanto Net 1
    cloanto_net_1 = 356, 'cloanto-net-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bhevent
    #: - [UDP] bhevent
    bhevent = 357, 'bhevent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Shrinkwrap
    #: - [UDP] Shrinkwrap
    shrinkwrap = 358, 'shrinkwrap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_359 = 359, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] scoi2odialog
    #: - [UDP] scoi2odialog
    scoi2odialog = 360, 'scoi2odialog', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Semantix
    #: - [UDP] Semantix
    semantix = 361, 'semantix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SRS Send
    #: - [UDP] SRS Send
    srssend = 362, 'srssend', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSVP Tunnel IANA assigned this well-formed service name as a
    #:   replacement for "rsvp_tunnel".
    #: - [TCP] RSVP Tunnel
    #: - [UDP] RSVP Tunnel IANA assigned this well-formed service name as a
    #:   replacement for "rsvp_tunnel".
    #: - [UDP] RSVP Tunnel
    rsvp_tunnel = 363, 'rsvp-tunnel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aurora CMGR
    #: - [UDP] Aurora CMGR
    aurora_cmgr = 364, 'aurora-cmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DTK
    #: - [UDP] DTK
    dtk = 365, 'dtk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ODMR
    #: - [UDP] ODMR
    odmr = 366, 'odmr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MortgageWare
    #: - [UDP] MortgageWare
    mortgageware = 367, 'mortgageware', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QbikGDP
    #: - [UDP] QbikGDP
    qbikgdp = 368, 'qbikgdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rpc2portmap
    #: - [UDP] rpc2portmap
    rpc2portmap = 369, 'rpc2portmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] codaauth2
    #: - [UDP] codaauth2
    codaauth2 = 370, 'codaauth2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Clearcase
    #: - [UDP] Clearcase
    clearcase = 371, 'clearcase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ListProcessor
    #: - [UDP] ListProcessor
    ulistproc = 372, 'ulistproc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Legent Corporation
    #: - [UDP] Legent Corporation
    legent_1 = 373, 'legent-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Legent Corporation
    #: - [UDP] Legent Corporation
    legent_2 = 374, 'legent-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hassle
    #: - [UDP] Hassle
    hassle = 375, 'hassle', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Amiga Envoy Network Inquiry Protocol
    #: - [UDP] Amiga Envoy Network Inquiry Protocol
    nip = 376, 'nip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NEC Corporation
    #: - [UDP] NEC Corporation
    tnetos = 377, 'tnetos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NEC Corporation
    #: - [UDP] NEC Corporation
    dsetos = 378, 'dsetos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TIA/EIA/IS-99 modem client
    #: - [UDP] TIA/EIA/IS-99 modem client
    is99c = 379, 'is99c', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TIA/EIA/IS-99 modem server
    #: - [UDP] TIA/EIA/IS-99 modem server
    is99s = 380, 'is99s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp performance data collector
    #: - [UDP] hp performance data collector
    hp_collector = 381, 'hp-collector', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp performance data managed node
    #: - [UDP] hp performance data managed node
    hp_managed_node = 382, 'hp-managed-node', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp performance data alarm manager
    #: - [UDP] hp performance data alarm manager
    hp_alarm_mgr = 383, 'hp-alarm-mgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A Remote Network Server System
    #: - [UDP] A Remote Network Server System
    arns = 384, 'arns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Application
    #: - [UDP] IBM Application
    ibm_app = 385, 'ibm-app', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASA Message Router Object Def.
    #: - [UDP] ASA Message Router Object Def.
    asa = 386, 'asa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Appletalk Update-Based Routing Pro.
    #: - [UDP] Appletalk Update-Based Routing Pro.
    aurp = 387, 'aurp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unidata LDM
    #: - [UDP] Unidata LDM
    unidata_ldm = 388, 'unidata-ldm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lightweight Directory Access Protocol
    #: - [UDP] Lightweight Directory Access Protocol
    ldap = 389, 'ldap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UIS
    #: - [UDP] UIS
    uis = 390, 'uis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SynOptics SNMP Relay Port
    #: - [UDP] SynOptics SNMP Relay Port
    synotics_relay = 391, 'synotics-relay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SynOptics Port Broker Port
    #: - [UDP] SynOptics Port Broker Port
    synotics_broker = 392, 'synotics-broker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Meta5
    #: - [UDP] Meta5
    meta5 = 393, 'meta5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMBL Nucleic Data Transfer
    #: - [UDP] EMBL Nucleic Data Transfer
    embl_ndt = 394, 'embl-ndt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetScout Control Protocol
    #: - [UDP] NetScout Control Protocol
    netcp = 395, 'netcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novell Netware over IP
    #: - [UDP] Novell Netware over IP
    netware_ip = 396, 'netware-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multi Protocol Trans. Net.
    #: - [UDP] Multi Protocol Trans. Net.
    mptn = 397, 'mptn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kryptolan
    #: - [UDP] Kryptolan
    kryptolan = 398, 'kryptolan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISO Transport Class 2 Non-Control over TCP
    #: - [UDP] ISO Transport Class 2 Non-Control over UDP
    iso_tsap_c2 = 399, 'iso-tsap-c2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle Secure Backup
    #: - [UDP] Oracle Secure Backup
    osb_sd = 400, 'osb-sd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Uninterruptible Power Supply
    #: - [UDP] Uninterruptible Power Supply
    ups = 401, 'ups', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Genie Protocol
    #: - [UDP] Genie Protocol
    genie = 402, 'genie', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] decap
    #: - [UDP] decap
    decap = 403, 'decap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nced
    #: - [UDP] nced
    nced = 404, 'nced', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ncld
    #: - [UDP] ncld
    ncld = 405, 'ncld', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Interactive Mail Support Protocol
    #: - [UDP] Interactive Mail Support Protocol
    imsp = 406, 'imsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Timbuktu
    #: - [UDP] Timbuktu
    timbuktu = 407, 'timbuktu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prospero Resource Manager Sys. Man.
    #: - [UDP] Prospero Resource Manager Sys. Man.
    prm_sm = 408, 'prm-sm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prospero Resource Manager Node Man.
    #: - [UDP] Prospero Resource Manager Node Man.
    prm_nm = 409, 'prm-nm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DECLadebug Remote Debug Protocol
    #: - [UDP] DECLadebug Remote Debug Protocol
    decladebug = 410, 'decladebug', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote MT Protocol
    #: - [UDP] Remote MT Protocol
    rmt = 411, 'rmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trap Convention Port
    #: - [UDP] Trap Convention Port
    synoptics_trap = 412, 'synoptics-trap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Storage Management Services Protocol
    #: - [UDP] Storage Management Services Protocol
    smsp = 413, 'smsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] InfoSeek
    #: - [UDP] InfoSeek
    infoseek = 414, 'infoseek', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BNet
    #: - [UDP] BNet
    bnet = 415, 'bnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Silverplatter
    #: - [UDP] Silverplatter
    silverplatter = 416, 'silverplatter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Onmux
    #: - [UDP] Onmux
    onmux = 417, 'onmux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hyper-G
    #: - [UDP] Hyper-G
    hyper_g = 418, 'hyper-g', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ariel 1
    #: - [UDP] Ariel 1
    ariel1 = 419, 'ariel1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMPTE
    #: - [UDP] SMPTE
    smpte = 420, 'smpte', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ariel 2
    #: - [UDP] Ariel 2
    ariel2 = 421, 'ariel2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ariel 3
    #: - [UDP] Ariel 3
    ariel3 = 422, 'ariel3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Operations Planning and Control Start
    #: - [UDP] IBM Operations Planning and Control Start
    opc_job_start = 423, 'opc-job-start', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Operations Planning and Control Track
    #: - [UDP] IBM Operations Planning and Control Track
    opc_job_track = 424, 'opc-job-track', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICAD
    #: - [UDP] ICAD
    icad_el = 425, 'icad-el', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] smartsdp
    #: - [UDP] smartsdp
    smartsdp = 426, 'smartsdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Server Location
    #: - [UDP] Server Location
    svrloc = 427, 'svrloc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OCS_CMU IANA assigned this well-formed service name as a replacement
    #:   for "ocs_cmu".
    #: - [TCP] OCS_CMU
    #: - [UDP] OCS_CMU IANA assigned this well-formed service name as a replacement
    #:   for "ocs_cmu".
    #: - [UDP] OCS_CMU
    ocs_cmu = 428, 'ocs-cmu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OCS_AMU IANA assigned this well-formed service name as a replacement
    #:   for "ocs_amu".
    #: - [TCP] OCS_AMU
    #: - [UDP] OCS_AMU IANA assigned this well-formed service name as a replacement
    #:   for "ocs_amu".
    #: - [UDP] OCS_AMU
    ocs_amu = 429, 'ocs-amu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UTMPSD
    #: - [UDP] UTMPSD
    utmpsd = 430, 'utmpsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UTMPCD
    #: - [UDP] UTMPCD
    utmpcd = 431, 'utmpcd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IASD
    #: - [UDP] IASD
    iasd = 432, 'iasd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NNTP for transit servers (NNSP) [:rfc:`3977`]
    #: - [UDP] NNTP for transit servers (NNSP) [:rfc:`3977`]
    nnsp = 433, 'nnsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MobileIP-Agent
    #: - [UDP] MobileIP-Agent
    mobileip_agent = 434, 'mobileip-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MobilIP-MN
    #: - [UDP] MobilIP-MN
    mobilip_mn = 435, 'mobilip-mn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNA-CML
    #: - [UDP] DNA-CML
    dna_cml = 436, 'dna-cml', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] comscm
    #: - [UDP] comscm
    comscm = 437, 'comscm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dsfgw
    #: - [UDP] dsfgw
    dsfgw = 438, 'dsfgw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dasp
    #: - [UDP] dasp
    dasp = 439, 'dasp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sgcp
    #: - [UDP] sgcp
    sgcp = 440, 'sgcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] decvms-sysmgt
    #: - [UDP] decvms-sysmgt
    decvms_sysmgt = 441, 'decvms-sysmgt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cvc_hostd IANA assigned this well-formed service name as a replacement
    #:   for "cvc_hostd".
    #: - [TCP] cvc_hostd
    #: - [UDP] cvc_hostd IANA assigned this well-formed service name as a replacement
    #:   for "cvc_hostd".
    #: - [UDP] cvc_hostd
    cvc_hostd = 442, 'cvc-hostd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Network Paging Protocol [:rfc:`1568`]
    #: - [UDP] Simple Network Paging Protocol [:rfc:`1568`]
    snpp = 444, 'snpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft-DS
    #: - [UDP] Microsoft-DS
    microsoft_ds = 445, 'microsoft-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DDM-Remote Relational Database Access
    #: - [UDP] DDM-Remote Relational Database Access
    ddm_rdb = 446, 'ddm-rdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DDM-Distributed File Management
    #: - [UDP] DDM-Distributed File Management
    ddm_dfm = 447, 'ddm-dfm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DDM-Remote DB Access Using Secure Sockets
    #: - [UDP] DDM-Remote DB Access Using Secure Sockets
    ddm_ssl = 448, 'ddm-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AS Server Mapper
    #: - [UDP] AS Server Mapper
    as_servermap = 449, 'as-servermap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Computer Supported Telecomunication Applications
    #: - [UDP] Computer Supported Telecomunication Applications
    tserver = 450, 'tserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cray Network Semaphore server
    #: - [UDP] Cray Network Semaphore server
    sfs_smp_net = 451, 'sfs-smp-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cray SFS config server
    #: - [UDP] Cray SFS config server
    sfs_config = 452, 'sfs-config', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] macon-udp
    macon_udp = 456, 'macon-udp', TransportProtocol.udp

    #: - [TCP] scohelp
    #: - [UDP] scohelp
    scohelp = 457, 'scohelp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] apple quick time
    #: - [UDP] apple quick time
    appleqtc = 458, 'appleqtc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ampr-rcmd
    #: - [UDP] ampr-rcmd
    ampr_rcmd = 459, 'ampr-rcmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] skronk
    #: - [UDP] skronk
    skronk = 460, 'skronk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DataRampSrv
    #: - [UDP] DataRampSrv
    datasurfsrv = 461, 'datasurfsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DataRampSrvSec
    #: - [UDP] DataRampSrvSec
    datasurfsrvsec = 462, 'datasurfsrvsec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] alpes
    #: - [UDP] alpes
    alpes = 463, 'alpes', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] kpasswd
    #: - [UDP] kpasswd
    kpasswd = 464, 'kpasswd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] IGMP over UDP for SSM
    igmpv3lite = 465, 'igmpv3lite', TransportProtocol.udp

    #: - [TCP] digital-vrc
    #: - [UDP] digital-vrc
    digital_vrc = 466, 'digital-vrc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mylex-mapd
    #: - [UDP] mylex-mapd
    mylex_mapd = 467, 'mylex-mapd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] proturis
    #: - [UDP] proturis
    photuris = 468, 'photuris', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Radio Control Protocol
    #: - [UDP] Radio Control Protocol
    rcp = 469, 'rcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] scx-proxy
    #: - [UDP] scx-proxy
    scx_proxy = 470, 'scx-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mondex
    #: - [UDP] Mondex
    mondex = 471, 'mondex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ljk-login
    #: - [UDP] ljk-login
    ljk_login = 472, 'ljk-login', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hybrid-pop
    #: - [UDP] hybrid-pop
    hybrid_pop = 473, 'hybrid-pop', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] tn-tl-w2
    tn_tl_w2 = 474, 'tn-tl-w2', TransportProtocol.udp

    #: - [TCP] tcpnethaspsrv
    #: - [UDP] tcpnethaspsrv
    tcpnethaspsrv = 475, 'tcpnethaspsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tn-tl-fd1
    #: - [UDP] tn-tl-fd1
    tn_tl_fd1 = 476, 'tn-tl-fd1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ss7ns
    #: - [UDP] ss7ns
    ss7ns = 477, 'ss7ns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] spsc
    #: - [UDP] spsc
    spsc = 478, 'spsc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iafserver
    #: - [UDP] iafserver
    iafserver = 479, 'iafserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iafdbase
    #: - [UDP] iafdbase
    iafdbase = 480, 'iafdbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ph service
    #: - [UDP] Ph service
    ph = 481, 'ph', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bgs-nsi
    #: - [UDP] bgs-nsi
    bgs_nsi = 482, 'bgs-nsi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ulpnet
    #: - [UDP] ulpnet
    ulpnet = 483, 'ulpnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Integra Software Management Environment
    #: - [UDP] Integra Software Management Environment
    integra_sme = 484, 'integra-sme', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Air Soft Power Burst
    #: - [UDP] Air Soft Power Burst
    powerburst = 485, 'powerburst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] avian
    #: - [UDP] avian
    avian = 486, 'avian', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] saft Simple Asynchronous File Transfer
    #: - [UDP] saft Simple Asynchronous File Transfer
    saft = 487, 'saft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gss-http
    #: - [UDP] gss-http
    gss_http = 488, 'gss-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nest-protocol
    #: - [UDP] nest-protocol
    nest_protocol = 489, 'nest-protocol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] micom-pfs
    #: - [UDP] micom-pfs
    micom_pfs = 490, 'micom-pfs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] go-login
    #: - [UDP] go-login
    go_login = 491, 'go-login', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Transport Independent Convergence for FNA
    #: - [UDP] Transport Independent Convergence for FNA
    ticf_1 = 492, 'ticf-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Transport Independent Convergence for FNA
    #: - [UDP] Transport Independent Convergence for FNA
    ticf_2 = 493, 'ticf-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] POV-Ray
    #: - [UDP] POV-Ray
    pov_ray = 494, 'pov-ray', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] intecourier
    #: - [UDP] intecourier
    intecourier = 495, 'intecourier', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PIM-RP-DISC
    #: - [UDP] PIM-RP-DISC
    pim_rp_disc = 496, 'pim-rp-disc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] siam
    #: - [UDP] siam
    siam = 498, 'siam', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISO ILL Protocol
    #: - [UDP] ISO ILL Protocol
    iso_ill = 499, 'iso-ill', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isakmp
    #: - [UDP] isakmp
    isakmp = 500, 'isakmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STMF
    #: - [UDP] STMF
    stmf = 501, 'stmf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Modbus Application Protocol
    #: - [UDP] Modbus Application Protocol
    mbap = 502, 'mbap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intrinsa
    #: - [UDP] Intrinsa
    intrinsa = 503, 'intrinsa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] citadel
    #: - [UDP] citadel
    citadel = 504, 'citadel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mailbox-lm
    #: - [UDP] mailbox-lm
    mailbox_lm = 505, 'mailbox-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ohimsrv
    #: - [UDP] ohimsrv
    ohimsrv = 506, 'ohimsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] crs
    #: - [UDP] crs
    crs = 507, 'crs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xvttp
    #: - [UDP] xvttp
    xvttp = 508, 'xvttp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] snare
    #: - [UDP] snare
    snare = 509, 'snare', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FirstClass Protocol
    #: - [UDP] FirstClass Protocol
    fcp = 510, 'fcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PassGo
    #: - [UDP] PassGo
    passgo = 511, 'passgo', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP]
    comsat = 512, 'comsat', TransportProtocol.udp

    #: [UDP] used by mail system to notify users of new mail received; currently
    #: receives messages only from processes on the same machine
    biff = 512, 'biff', TransportProtocol.udp

    #: [UDP] maintains data bases showing who's logged in to machines on a local
    #: net and the load average of the machine
    who = 513, 'who', TransportProtocol.udp

    #: [UDP] [:rfc:`5426`]
    syslog = 514, 'syslog', TransportProtocol.udp

    #: - [TCP] spooler
    #: - [UDP] spooler
    printer = 515, 'printer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] videotex
    #: - [UDP] videotex
    videotex = 516, 'videotex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] like tenex link, but across machine - unfortunately, doesn't use link
    #:   protocol (this is actually just a rendezvous port from which a tcp
    #:   connection is established)
    #: - [UDP] like tenex link, but across machine - unfortunately, doesn't use link
    #:   protocol (this is actually just a rendezvous port from which a tcp
    #:   connection is established)
    talk = 517, 'talk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    ntalk = 518, 'ntalk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] unixtime
    #: - [UDP] unixtime
    utime = 519, 'utime', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] local routing process (on site); uses variant of Xerox NS routing
    #: information protocol - RIP
    router = 520, 'router', TransportProtocol.udp

    #: - [TCP] ripng
    #: - [UDP] ripng
    ripng = 521, 'ripng', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ULP
    #: - [UDP] ULP
    ulp = 522, 'ulp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM-DB2
    #: - [UDP] IBM-DB2
    ibm_db2 = 523, 'ibm-db2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NCP
    #: - [UDP] NCP
    ncp = 524, 'ncp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] timeserver
    #: - [UDP] timeserver
    timed = 525, 'timed', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] newdate
    #: - [UDP] newdate
    tempo = 526, 'tempo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Stock IXChange
    #: - [UDP] Stock IXChange
    stx = 527, 'stx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Customer IXChange
    #: - [UDP] Customer IXChange
    custix = 528, 'custix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IRC-SERV
    #: - [UDP] IRC-SERV
    irc_serv = 529, 'irc-serv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rpc
    #: - [UDP] rpc
    courier = 530, 'courier', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] chat
    #: - [UDP] chat
    conference = 531, 'conference', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] readnews
    #: - [UDP] readnews
    netnews = 532, 'netnews', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] for emergency broadcasts
    #: - [UDP] for emergency broadcasts
    netwall = 533, 'netwall', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] windream Admin
    #: - [UDP] windream Admin
    windream = 534, 'windream', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iiop
    #: - [UDP] iiop
    iiop = 535, 'iiop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] opalis-rdv
    #: - [UDP] opalis-rdv
    opalis_rdv = 536, 'opalis-rdv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gdomap
    #: - [UDP] gdomap
    gdomap = 538, 'gdomap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apertus Technologies Load Determination
    #: - [UDP] Apertus Technologies Load Determination
    apertus_ldp = 539, 'apertus-ldp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] uucpd
    #: - [UDP] uucpd
    uucp = 540, 'uucp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] uucp-rlogin
    #: - [UDP] uucp-rlogin
    uucp_rlogin = 541, 'uucp-rlogin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] commerce
    #: - [UDP] commerce
    commerce = 542, 'commerce', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    klogin = 543, 'klogin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] krcmd
    #: - [UDP] krcmd
    kshell = 544, 'kshell', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] appleqtcsrvr
    #: - [UDP] appleqtcsrvr
    appleqtcsrvr = 545, 'appleqtcsrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DHCPv6 Client
    #: - [UDP] DHCPv6 Client [:rfc:`9915`]
    dhcpv6_client = 546, 'dhcpv6-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DHCPv6 Server [:rfc:`5460`]
    #: - [UDP] DHCPv6 Server [:rfc:`9915`]
    dhcpv6_server = 547, 'dhcpv6-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AFP over TCP
    #: - [UDP] AFP over TCP
    afpovertcp = 548, 'afpovertcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IDFP
    #: - [UDP] IDFP
    idfp = 549, 'idfp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] new-who [n/a]
    #: - [UDP] new-who [n/a]
    new_rwho = 550, 'new-rwho', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cybercash [:rfc:`1898`]
    #: - [UDP] cybercash [:rfc:`1898`]
    cybercash = 551, 'cybercash', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DeviceShare
    #: - [UDP] DeviceShare
    devshr_nts = 552, 'devshr-nts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pirp
    #: - [UDP] pirp
    pirp = 553, 'pirp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Real Time Streaming Protocol (RTSP)
    #: - [UDP] Real Time Streaming Protocol (RTSP)
    rtsp = 554, 'rtsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    dsf = 555, 'dsf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rfs server
    #: - [UDP] rfs server
    remotefs = 556, 'remotefs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] openvms-sysipc
    #: - [UDP] openvms-sysipc
    openvms_sysipc = 557, 'openvms-sysipc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SDNSKMP
    #: - [UDP] SDNSKMP
    sdnskmp = 558, 'sdnskmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TEEDTAP
    #: - [UDP] TEEDTAP
    teedtap = 559, 'teedtap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rmonitord
    #: - [UDP] rmonitord
    rmonitor = 560, 'rmonitor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    monitor = 561, 'monitor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] chcmd
    #: - [UDP] chcmd
    chshell = 562, 'chshell', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nntp protocol over TLS/SSL (was snntp) [:rfc:`4642`]
    #: - [UDP] nntp protocol over TLS/SSL (was snntp) [:rfc:`4642`]
    nntps = 563, 'nntps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] plan 9 file service
    #: - [UDP] plan 9 file service
    UDP_9pfs = 564, '9pfs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] whoami
    #: - [UDP] whoami
    whoami = 565, 'whoami', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] streettalk
    #: - [UDP] streettalk
    streettalk = 566, 'streettalk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] banyan-rpc
    #: - [UDP] banyan-rpc
    banyan_rpc = 567, 'banyan-rpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] microsoft shuttle
    #: - [UDP] microsoft shuttle
    ms_shuttle = 568, 'ms-shuttle', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] microsoft rome
    #: - [UDP] microsoft rome
    ms_rome = 569, 'ms-rome', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] demon
    #: - [UDP] demon
    meter_570 = 570, 'meter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] udemon
    #: - [UDP] udemon
    meter_571 = 571, 'meter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sonar
    #: - [UDP] sonar
    sonar = 572, 'sonar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] banyan-vip
    #: - [UDP] banyan-vip
    banyan_vip = 573, 'banyan-vip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FTP Software Agent System
    #: - [UDP] FTP Software Agent System
    ftp_agent = 574, 'ftp-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VEMMI
    #: - [UDP] VEMMI
    vemmi = 575, 'vemmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ipcd
    #: - [UDP] ipcd
    ipcd = 576, 'ipcd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vnas
    #: - [UDP] vnas
    vnas = 577, 'vnas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ipdd
    #: - [UDP] ipdd
    ipdd = 578, 'ipdd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] decbsrv
    #: - [UDP] decbsrv
    decbsrv = 579, 'decbsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNTP HEARTBEAT
    #: - [UDP] SNTP HEARTBEAT
    sntp_heartbeat = 580, 'sntp-heartbeat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bundle Discovery Protocol
    #: - [UDP] Bundle Discovery Protocol
    bdp = 581, 'bdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCC Security
    #: - [UDP] SCC Security
    scc_security = 582, 'scc-security', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Philips Video-Conferencing
    #: - [UDP] Philips Video-Conferencing
    philips_vc = 583, 'philips-vc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Key Server
    #: - [UDP] Key Server
    keyserver = 584, 'keyserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Password Change
    #: - [UDP] Password Change
    password_chg = 586, 'password-chg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message Submission [:rfc:`6409`]
    #: - [UDP] Message Submission [:rfc:`6409`]
    submission = 587, 'submission', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CAL
    #: - [UDP] CAL
    cal = 588, 'cal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EyeLink
    #: - [UDP] EyeLink
    eyelink = 589, 'eyelink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TNS CML
    #: - [UDP] TNS CML
    tns_cml = 590, 'tns-cml', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Eudora Set
    #: - [UDP] Eudora Set
    eudora_set = 592, 'eudora-set', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HTTP RPC Ep Map
    #: - [UDP] HTTP RPC Ep Map
    http_rpc_epmap = 593, 'http-rpc-epmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TPIP
    #: - [UDP] TPIP
    tpip = 594, 'tpip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CAB Protocol
    #: - [UDP] CAB Protocol
    cab_protocol = 595, 'cab-protocol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMSD
    #: - [UDP] SMSD
    smsd = 596, 'smsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PTC Name Service
    #: - [UDP] PTC Name Service
    ptcnameservice = 597, 'ptcnameservice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCO Web Server Manager 3
    #: - [UDP] SCO Web Server Manager 3
    sco_websrvrmg3 = 598, 'sco-websrvrmg3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aeolon Core Protocol
    #: - [UDP] Aeolon Core Protocol
    acp = 599, 'acp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun IPC server
    #: - [UDP] Sun IPC server
    ipcserver = 600, 'ipcserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reliable Syslog Service [:rfc:`3195`]
    #: - [UDP] Reliable Syslog Service [:rfc:`3195`]
    syslog_conn = 601, 'syslog-conn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XML-RPC over BEEP [:rfc:`3529`]
    #: - [UDP] XML-RPC over BEEP [:rfc:`3529`]
    xmlrpc_beep = 602, 'xmlrpc-beep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IDXP [:rfc:`4767`]
    #: - [UDP] IDXP [:rfc:`4767`]
    idxp = 603, 'idxp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TUNNEL [:rfc:`3620`]
    #: - [UDP] TUNNEL [:rfc:`3620`]
    tunnel = 604, 'tunnel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SOAP over BEEP [:rfc:`4227`]
    #: - [UDP] SOAP over BEEP [:rfc:`4227`]
    soap_beep = 605, 'soap-beep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cray Unified Resource Manager
    #: - [UDP] Cray Unified Resource Manager
    urm = 606, 'urm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nqs
    #: - [UDP] nqs
    nqs = 607, 'nqs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sender-Initiated/Unsolicited File Transfer
    #: - [UDP] Sender-Initiated/Unsolicited File Transfer
    sift_uft = 608, 'sift-uft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] npmp-trap
    #: - [UDP] npmp-trap
    npmp_trap = 609, 'npmp-trap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] npmp-local
    #: - [UDP] npmp-local
    npmp_local = 610, 'npmp-local', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] npmp-gui
    #: - [UDP] npmp-gui
    npmp_gui = 611, 'npmp-gui', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HMMP Indication
    #: - [UDP] HMMP Indication
    hmmp_ind = 612, 'hmmp-ind', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HMMP Operation
    #: - [UDP] HMMP Operation
    hmmp_op = 613, 'hmmp-op', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSLshell
    #: - [UDP] SSLshell
    sshell = 614, 'sshell', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Internet Configuration Manager
    #: - [UDP] Internet Configuration Manager
    sco_inetmgr = 615, 'sco-inetmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCO System Administration Server
    #: - [UDP] SCO System Administration Server
    sco_sysmgr = 616, 'sco-sysmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCO Desktop Administration Server
    #: - [UDP] SCO Desktop Administration Server
    sco_dtmgr = 617, 'sco-dtmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DEI-ICDA
    #: - [UDP] DEI-ICDA
    dei_icda = 618, 'dei-icda', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compaq EVM
    #: - [UDP] Compaq EVM
    compaq_evm = 619, 'compaq-evm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCO WebServer Manager
    #: - [UDP] SCO WebServer Manager
    sco_websrvrmgr = 620, 'sco-websrvrmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESCP
    #: - [UDP] ESCP
    escp_ip = 621, 'escp-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Collaborator
    #: - [UDP] Collaborator
    collaborator = 622, 'collaborator', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] ASF Remote Management and Control Protocol
    asf_rmcp = 623, 'asf-rmcp', TransportProtocol.udp

    #: - [TCP] Crypto Admin
    #: - [UDP] Crypto Admin
    cryptoadmin = 624, 'cryptoadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DEC DLM IANA assigned this well-formed service name as a replacement
    #:   for "dec_dlm".
    #: - [TCP] DEC DLM
    #: - [UDP] DEC DLM IANA assigned this well-formed service name as a replacement
    #:   for "dec_dlm".
    #: - [UDP] DEC DLM
    dec_dlm = 625, 'dec-dlm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASIA
    #: - [UDP] ASIA
    asia = 626, 'asia', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PassGo Tivoli
    #: - [UDP] PassGo Tivoli
    passgo_tivoli = 627, 'passgo-tivoli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QMQP
    #: - [UDP] QMQP
    qmqp = 628, 'qmqp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3Com AMP3
    #: - [UDP] 3Com AMP3
    UDP_3com_amp3 = 629, '3com-amp3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPP (Internet Printing Protocol) [:rfc:`8011`]
    #: - [UDP] IPP (Internet Printing Protocol) [:rfc:`8011`]
    ipp = 631, 'ipp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bmpp
    #: - [UDP] bmpp
    bmpp = 632, 'bmpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Status update (Sterling Software)
    #: - [UDP] Service Status update (Sterling Software)
    servstat = 633, 'servstat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ginad
    #: - [UDP] ginad
    ginad = 634, 'ginad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RLZ DBase
    #: - [UDP] RLZ DBase
    rlzdbase = 635, 'rlzdbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ldap protocol over TLS/SSL (was sldap)
    #: - [UDP] ldap protocol over TLS/SSL (was sldap)
    ldaps = 636, 'ldaps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] lanserver
    #: - [UDP] lanserver
    lanserver = 637, 'lanserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mcns-sec
    #: - [UDP] mcns-sec
    mcns_sec = 638, 'mcns-sec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSDP
    #: - [UDP] MSDP
    msdp = 639, 'msdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] entrust-sps
    #: - [UDP] entrust-sps
    entrust_sps = 640, 'entrust-sps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] repcmd
    #: - [UDP] repcmd
    repcmd = 641, 'repcmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESRO-EMSDP V1.3
    #: - [UDP] ESRO-EMSDP V1.3
    esro_emsdp = 642, 'esro-emsdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SANity
    #: - [UDP] SANity
    sanity = 643, 'sanity', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dwr
    #: - [UDP] dwr
    dwr = 644, 'dwr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PSSC
    #: - [UDP] PSSC
    pssc = 645, 'pssc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LDP
    #: - [UDP] LDP
    ldp = 646, 'ldp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DHCP Failover [:rfc:`8156`]
    #: - [UDP] DHCP Failover
    dhcp_failover = 647, 'dhcp-failover', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Registry Registrar Protocol (RRP)
    #: - [UDP] Registry Registrar Protocol (RRP)
    rrp = 648, 'rrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cadview-3d - streaming 3d models over the internet
    #: - [UDP] Cadview-3d - streaming 3d models over the internet
    cadview_3d = 649, 'cadview-3d', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OBEX
    #: - [UDP] OBEX
    obex = 650, 'obex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IEEE MMS
    #: - [UDP] IEEE MMS
    ieee_mms = 651, 'ieee-mms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HELLO_PORT
    #: - [UDP] HELLO_PORT
    hello_port = 652, 'hello-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RepCmd
    #: - [UDP] RepCmd
    repscmd = 653, 'repscmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AODV
    #: - [UDP] AODV
    aodv = 654, 'aodv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TINC
    #: - [UDP] TINC
    tinc = 655, 'tinc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPMP
    #: - [UDP] SPMP
    spmp = 656, 'spmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RMC
    #: - [UDP] RMC
    rmc = 657, 'rmc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TenFold
    #: - [UDP] TenFold
    tenfold = 658, 'tenfold', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MacOS Server Admin
    #: - [UDP] MacOS Server Admin
    mac_srvr_admin = 660, 'mac-srvr-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HAP
    #: - [UDP] HAP
    hap = 661, 'hap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PFTP
    #: - [UDP] PFTP
    pftp = 662, 'pftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PureNoise
    #: - [UDP] PureNoise
    purenoise = 663, 'purenoise', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] ASF Secure Remote Management and Control Protocol
    asf_secure_rmcp = 664, 'asf-secure-rmcp', TransportProtocol.udp

    #: - [TCP] Sun DR
    #: - [UDP] Sun DR
    sun_dr = 665, 'sun-dr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    mdqs = 666, 'mdqs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] doom Id Software
    #: - [UDP] doom Id Software
    doom = 666, 'doom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] campaign contribution disclosures - SDR Technologies
    #: - [UDP] campaign contribution disclosures - SDR Technologies
    disclose = 667, 'disclose', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MeComm
    #: - [UDP] MeComm
    mecomm = 668, 'mecomm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MeRegister
    #: - [UDP] MeRegister
    meregister = 669, 'meregister', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VACDSM-SWS
    #: - [UDP] VACDSM-SWS
    vacdsm_sws = 670, 'vacdsm-sws', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VACDSM-APP
    #: - [UDP] VACDSM-APP
    vacdsm_app = 671, 'vacdsm-app', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VPPS-QUA
    #: - [UDP] VPPS-QUA
    vpps_qua = 672, 'vpps-qua', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CIMPLEX
    #: - [UDP] CIMPLEX
    cimplex = 673, 'cimplex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACAP
    #: - [UDP] ACAP
    acap = 674, 'acap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DCTP
    #: - [UDP] DCTP
    dctp = 675, 'dctp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VPPS Via
    #: - [UDP] VPPS Via
    vpps_via = 676, 'vpps-via', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Presence Protocol
    #: - [UDP] Virtual Presence Protocol
    vpp = 677, 'vpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GNU Generation Foundation NCP
    #: - [UDP] GNU Generation Foundation NCP
    ggf_ncp = 678, 'ggf-ncp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MRM
    #: - [UDP] MRM
    mrm = 679, 'mrm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] entrust-aaas
    #: - [UDP] entrust-aaas
    entrust_aaas = 680, 'entrust-aaas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] entrust-aams
    #: - [UDP] entrust-aams
    entrust_aams = 681, 'entrust-aams', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XFR
    #: - [UDP] XFR
    xfr = 682, 'xfr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CORBA IIOP
    #: - [UDP] CORBA IIOP
    corba_iiop = 683, 'corba-iiop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CORBA IIOP SSL
    #: - [UDP] CORBA IIOP SSL
    corba_iiop_ssl = 684, 'corba-iiop-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MDC Port Mapper
    #: - [UDP] MDC Port Mapper
    mdc_portmapper = 685, 'mdc-portmapper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hardware Control Protocol Wismar
    #: - [UDP] Hardware Control Protocol Wismar
    hcp_wismar = 686, 'hcp-wismar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] asipregistry
    #: - [UDP] asipregistry
    asipregistry = 687, 'asipregistry', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ApplianceWare managment protocol
    #: - [UDP] ApplianceWare managment protocol
    realm_rusd = 688, 'realm-rusd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NMAP
    #: - [UDP] NMAP
    nmap = 689, 'nmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Velneo Application Transfer Protocol
    #: - [UDP] Velneo Application Transfer Protocol
    vatp = 690, 'vatp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS Exchange Routing
    #: - [UDP] MS Exchange Routing
    msexch_routing = 691, 'msexch-routing', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hyperwave-ISP
    #: - [UDP] Hyperwave-ISP
    hyperwave_isp = 692, 'hyperwave-isp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] almanid Connection Endpoint
    #: - [UDP] almanid Connection Endpoint
    connendp = 693, 'connendp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ha-cluster
    #: - [UDP] ha-cluster
    ha_cluster = 694, 'ha-cluster', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IEEE-MMS-SSL
    #: - [UDP] IEEE-MMS-SSL
    ieee_mms_ssl = 695, 'ieee-mms-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RUSHD
    #: - [UDP] RUSHD
    rushd = 696, 'rushd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UUIDGEN
    #: - [UDP] UUIDGEN
    uuidgen = 697, 'uuidgen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OLSR
    #: - [UDP] OLSR
    olsr = 698, 'olsr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Access Network
    #: - [UDP] Access Network
    accessnetwork = 699, 'accessnetwork', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Link Management Protocol (LMP) [:rfc:`4204`]
    #: - [UDP] Link Management Protocol (LMP) [:rfc:`4204`]
    lmp = 701, 'lmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IRIS over BEEP [:rfc:`3983`]
    #: - [UDP] IRIS over BEEP [:rfc:`3983`]
    iris_beep = 702, 'iris-beep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] errlog copy/server daemon
    #: - [UDP] errlog copy/server daemon
    elcsd = 704, 'elcsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AgentX
    #: - [UDP] AgentX
    agentx = 705, 'agentx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SILC
    #: - [UDP] SILC
    silc = 706, 'silc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Borland DSJ
    #: - [UDP] Borland DSJ
    borland_dsj = 707, 'borland-dsj', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Entrust Key Management Service Handler
    #: - [UDP] Entrust Key Management Service Handler
    entrust_kmsh = 709, 'entrust-kmsh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Entrust Administration Service Handler
    #: - [UDP] Entrust Administration Service Handler
    entrust_ash = 710, 'entrust-ash', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cisco TDP
    #: - [UDP] Cisco TDP
    cisco_tdp = 711, 'cisco-tdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TBRPF [:rfc:`3684`]
    #: - [UDP] TBRPF [:rfc:`3684`]
    tbrpf = 712, 'tbrpf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IRIS over XPC
    #: - [UDP] IRIS over XPC
    iris_xpc = 713, 'iris-xpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IRIS over XPCS [:rfc:`4992`]
    #: - [UDP] IRIS over XPCS [:rfc:`4992`]
    iris_xpcs = 714, 'iris-xpcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IRIS-LWZ [:rfc:`4993`]
    #: - [UDP] IRIS-LWZ [:rfc:`4993`]
    iris_lwz = 715, 'iris-lwz', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] PANA Messages [:rfc:`5191`]
    pana = 716, 'pana', TransportProtocol.udp

    #: - [TCP] IBM NetView DM/6000 Server/Client
    #: - [UDP] IBM NetView DM/6000 Server/Client
    netviewdm1 = 729, 'netviewdm1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM NetView DM/6000 send/tcp
    #: - [UDP] IBM NetView DM/6000 send/tcp
    netviewdm2 = 730, 'netviewdm2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM NetView DM/6000 receive/tcp
    #: - [UDP] IBM NetView DM/6000 receive/tcp
    netviewdm3 = 731, 'netviewdm3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netGW
    #: - [UDP] netGW
    netgw = 741, 'netgw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network based Rev. Cont. Sys.
    #: - [UDP] Network based Rev. Cont. Sys.
    netrcs = 742, 'netrcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Flexible License Manager
    #: - [UDP] Flexible License Manager
    flexlm = 744, 'flexlm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Device Control
    #: - [UDP] Fujitsu Device Control
    fujitsu_dev = 747, 'fujitsu-dev', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Russell Info Sci Calendar Manager
    #: - [UDP] Russell Info Sci Calendar Manager
    ris_cm = 748, 'ris-cm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] kerberos administration
    #: - [UDP] kerberos administration
    kerberos_adm = 749, 'kerberos-adm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP]
    loadav = 750, 'loadav', TransportProtocol.udp

    #: [UDP] kerberos version iv
    kerberos_iv = 750, 'kerberos-iv', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    pump = 751, 'pump', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    qrh = 752, 'qrh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    rrh = 753, 'rrh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] send
    #: - [UDP] send
    tell = 754, 'tell', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    nlogin = 758, 'nlogin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    con = 759, 'con', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    ns = 760, 'ns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    rxe = 761, 'rxe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    quotad = 762, 'quotad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    cycleserv = 763, 'cycleserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    omserv = 764, 'omserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    webster = 765, 'webster', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] phone
    #: - [UDP] phone
    phonebook = 767, 'phonebook', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    vid = 769, 'vid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    cadlock = 770, 'cadlock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    rtip = 771, 'rtip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    cycleserv2 = 772, 'cycleserv2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP]
    notify = 773, 'notify', TransportProtocol.udp

    #: - [UDP] IANA assigned this well-formed service name as a replacement for
    #:   "acmaint_dbd".
    #: - [UDP]
    acmaint_dbd = 774, 'acmaint-dbd', TransportProtocol.udp

    #: - [UDP] IANA assigned this well-formed service name as a replacement for
    #:   "acmaint_transd".
    #: - [UDP]
    acmaint_transd = 775, 'acmaint-transd', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    wpages = 776, 'wpages', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multiling HTTP
    #: - [UDP] Multiling HTTP
    multiling_http = 777, 'multiling-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    wpgs = 780, 'wpgs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IANA assigned this well-formed service name as a replacement for
    #:   "mdbs_daemon".
    #: - [TCP]
    #: - [UDP] IANA assigned this well-formed service name as a replacement for
    #:   "mdbs_daemon".
    #: - [UDP]
    mdbs_daemon = 800, 'mdbs-daemon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    device = 801, 'device', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Modbus Application Protocol Secure
    #: - [UDP] Modbus Application Protocol Secure
    mbap_s = 802, 'mbap-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FCP
    #: - [UDP] FCP Datagram
    fcp_udp = 810, 'fcp-udp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] itm-mcell-s
    #: - [UDP] itm-mcell-s
    itm_mcell_s = 828, 'itm-mcell-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PKIX-3 CA/RA
    #: - [UDP] PKIX-3 CA/RA
    pkix_3_ca_ra = 829, 'pkix-3-ca-ra', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETCONF over SSH [:rfc:`6242`]
    #: - [UDP] NETCONF over SSH [:rfc:`6242`]
    netconf_ssh = 830, 'netconf-ssh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_831 = 831, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_832 = 832, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_833 = 833, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dhcp-failover 2
    #: - [UDP] dhcp-failover 2
    dhcp_failover2 = 847, 'dhcp-failover2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GDOI [:rfc:`3547`]
    #: - [UDP] GDOI [:rfc:`3547`]
    gdoi = 848, 'gdoi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNS query-response protocol run over TLS [:rfc:`7858`]
    #: - [UDP] DNS query-response protocol run over DTLS or QUIC
    #:   [:rfc:`7858`][:rfc:`8094`][:rfc:`9250`]
    domain_s = 853, 'domain-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dynamic Link Exchange Protocol (DLEP) [:rfc:`8175`]
    #: - [UDP] Dynamic Link Exchange Protocol (DLEP) [:rfc:`8175`]
    dlep = 854, 'dlep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iSCSI [:rfc:`7143`]
    #: - [UDP] iSCSI [:rfc:`7143`]
    iscsi = 860, 'iscsi', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] OWAMP-Test [:rfc:`8545`]
    owamp_test = 861, 'owamp-test', TransportProtocol.udp

    #: [UDP] TWAMP-Test Receiver Port [:rfc:`8545`]
    twamp_test = 862, 'twamp-test', TransportProtocol.udp

    #: - [TCP] rsync
    #: - [UDP] rsync
    rsync = 873, 'rsync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICL coNETion locate server
    #: - [UDP] ICL coNETion locate server
    iclcnet_locate = 886, 'iclcnet-locate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICL coNETion server info IANA assigned this well-formed service name
    #:   as a replacement for "iclcnet_svinfo".
    #: - [TCP] ICL coNETion server info
    #: - [UDP] ICL coNETion server info IANA assigned this well-formed service name
    #:   as a replacement for "iclcnet_svinfo".
    #: - [UDP] ICL coNETion server info
    iclcnet_svinfo = 887, 'iclcnet-svinfo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AccessBuilder
    #: - [UDP] AccessBuilder
    accessbuilder = 888, 'accessbuilder', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMG Initial Refs
    #: - [UDP] OMG Initial Refs
    omginitialrefs = 900, 'omginitialrefs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMPNAMERES
    #: - [UDP] SMPNAMERES
    smpnameres = 901, 'smpnameres', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] self documenting Telnet Door
    #: - [UDP] self documenting Door: send 0x00 for info
    ideafarm_door = 902, 'ideafarm-door', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] self documenting Telnet Panic Door
    #: - [UDP] self documenting Panic Door: send 0x00 for info
    ideafarm_panic = 903, 'ideafarm-panic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kerberized Internet Negotiation of Keys (KINK) [:rfc:`4430`]
    #: - [UDP] Kerberized Internet Negotiation of Keys (KINK) [:rfc:`4430`]
    kink = 910, 'kink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xact-backup
    #: - [UDP] xact-backup
    xact_backup = 911, 'xact-backup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APEX relay-relay service
    #: - [UDP] APEX relay-relay service
    apex_mesh = 912, 'apex-mesh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APEX endpoint-relay service [:rfc:`3340`]
    #: - [UDP] APEX endpoint-relay service [:rfc:`3340`]
    apex_edge = 913, 'apex-edge', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Routing in Fat Trees Link Information Element [:rfc:`9692`]
    rift_lies = 914, 'rift-lies', TransportProtocol.udp

    #: [UDP] Routing in Fat Trees Topology Information Element [:rfc:`9692`]
    rift_ties = 915, 'rift-ties', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_953 = 953, 'reserved', TransportProtocol.udp

    #: - [TCP] ftp protocol, data, over TLS/SSL
    #: - [UDP] ftp protocol, data, over TLS/SSL
    ftps_data = 989, 'ftps-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ftp protocol, control, over TLS/SSL
    #: - [UDP] ftp protocol, control, over TLS/SSL
    ftps = 990, 'ftps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netnews Administration System [:rfc:`4707`]
    #: - [UDP] Netnews Administration System [:rfc:`4707`]
    nas = 991, 'nas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] telnet protocol over TLS/SSL
    #: - [UDP] telnet protocol over TLS/SSL
    telnets = 992, 'telnets', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved [:rfc:`9051`]
    reserved_993 = 993, 'reserved', TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_994 = 994, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] POP3 over TLS protocol [:rfc:`8314`]
    #: - [UDP] pop3 protocol over TLS/SSL (was spop3)
    pop3s = 995, 'pop3s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vsinet
    #: - [UDP] vsinet
    vsinet = 996, 'vsinet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    maitrd = 997, 'maitrd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP]
    puparp = 998, 'puparp', TransportProtocol.udp

    #: [UDP] Applix ac
    applix = 999, 'applix', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    puprouter = 999, 'puprouter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    cadlock2 = 1000, 'cadlock2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_1001 = 1001, 'reserved', TransportProtocol.udp

    #: [UDP] Possibly used by Sun Solaris????
    possibly_used_by_sun_solaris = 1008, 'possibly_used_by_sun_solaris', TransportProtocol.udp

    #: - [TCP] surf
    #: - [UDP] surf
    surf = 1010, 'surf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [UDP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [SCTP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [DCCP] RFC3692-style Experiment 1 [1][:rfc:`4727`][:rfc:`6335`]
    exp1 = 1021, 'exp1', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp | TransportProtocol.dccp

    #: - [TCP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [UDP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [SCTP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    #: - [DCCP] RFC3692-style Experiment 2 [1][:rfc:`4727`][:rfc:`6335`]
    exp2 = 1022, 'exp2', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp | TransportProtocol.dccp

    #: - [TCP] Reserved [:rfc:`6335`]
    #: - [UDP] Reserved [:rfc:`6335`]
    reserved_1023 = 1023, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved [:rfc:`6335`]
    #: - [UDP] Reserved [:rfc:`6335`]
    reserved_1024 = 1024, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] network blackjack
    #: - [UDP] network blackjack
    blackjack = 1025, 'blackjack', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Calendar Access Protocol
    #: - [UDP] Calendar Access Protocol
    cap = 1026, 'cap', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] IPv6 Behind NAT44 CPEs [:rfc:`6751`]
    UDP_6a44 = 1027, '6a44', TransportProtocol.udp

    #: - [TCP] Solid Mux Server
    #: - [UDP] Solid Mux Server
    solid_mux = 1029, 'solid-mux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] local netinfo port
    #: - [UDP] local netinfo port
    netinfo_local = 1033, 'netinfo-local', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ActiveSync Notifications
    #: - [UDP] ActiveSync Notifications
    activesync = 1034, 'activesync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MX-XR RPC
    #: - [UDP] MX-XR RPC
    mxxrlogin = 1035, 'mxxrlogin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nebula Secure Segment Transfer Protocol
    #: - [UDP] Nebula Secure Segment Transfer Protocol
    nsstp = 1036, 'nsstp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMS
    #: - [UDP] AMS
    ams = 1037, 'ams', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message Tracking Query Protocol [:rfc:`3887`]
    #: - [UDP] Message Tracking Query Protocol [:rfc:`3887`]
    mtqp = 1038, 'mtqp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Streamlined Blackhole
    #: - [UDP] Streamlined Blackhole
    sbl = 1039, 'sbl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netarx Netcare
    #: - [UDP] Netarx Netcare
    netarx = 1040, 'netarx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AK2 Product
    #: - [UDP] AK2 Product
    danf_ak2 = 1041, 'danf-ak2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Subnet Roaming
    #: - [UDP] Subnet Roaming
    afrog = 1042, 'afrog', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BOINC Client Control
    #: - [UDP] BOINC Client Control
    boinc_client = 1043, 'boinc-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dev Consortium Utility
    #: - [UDP] Dev Consortium Utility
    dcutility = 1044, 'dcutility', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fingerprint Image Transfer Protocol
    #: - [UDP] Fingerprint Image Transfer Protocol
    fpitp = 1045, 'fpitp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WebFilter Remote Monitor
    #: - [UDP] WebFilter Remote Monitor
    wfremotertm = 1046, 'wfremotertm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun's NEO Object Request Broker
    #: - [UDP] Sun's NEO Object Request Broker
    neod1 = 1047, 'neod1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun's NEO Object Request Broker
    #: - [UDP] Sun's NEO Object Request Broker
    neod2 = 1048, 'neod2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tobit David Postman VPMN
    #: - [UDP] Tobit David Postman VPMN
    td_postman = 1049, 'td-postman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CORBA Management Agent
    #: - [UDP] CORBA Management Agent
    cma = 1050, 'cma', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Optima VNET
    #: - [UDP] Optima VNET
    optima_vnet = 1051, 'optima-vnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dynamic DNS Tools
    #: - [UDP] Dynamic DNS Tools
    ddt = 1052, 'ddt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Assistant (RA)
    #: - [UDP] Remote Assistant (RA)
    remote_as = 1053, 'remote-as', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BRVREAD
    #: - [UDP] BRVREAD
    brvread = 1054, 'brvread', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ANSYS - License Manager
    #: - [UDP] ANSYS - License Manager
    ansyslmd = 1055, 'ansyslmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VFO
    #: - [UDP] VFO
    vfo = 1056, 'vfo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STARTRON
    #: - [UDP] STARTRON
    startron = 1057, 'startron', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nim
    #: - [UDP] nim
    nim = 1058, 'nim', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nimreg
    #: - [UDP] nimreg
    nimreg = 1059, 'nimreg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] POLESTAR
    #: - [UDP] POLESTAR
    polestar = 1060, 'polestar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KIOSK
    #: - [UDP] KIOSK
    kiosk = 1061, 'kiosk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Veracity
    #: - [UDP] Veracity
    veracity = 1062, 'veracity', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KyoceraNetDev
    #: - [UDP] KyoceraNetDev
    kyoceranetdev = 1063, 'kyoceranetdev', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JSTEL
    #: - [UDP] JSTEL
    jstel = 1064, 'jstel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SYSCOMLAN
    #: - [UDP] SYSCOMLAN
    syscomlan = 1065, 'syscomlan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FPO-FNS
    #: - [UDP] FPO-FNS
    fpo_fns = 1066, 'fpo-fns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Installation Bootstrap Proto. Serv. IANA assigned this well-formed
    #:   service name as a replacement for "instl_boots".
    #: - [TCP] Installation Bootstrap Proto. Serv.
    #: - [UDP] Installation Bootstrap Proto. Serv. IANA assigned this well-formed
    #:   service name as a replacement for "instl_boots".
    #: - [UDP] Installation Bootstrap Proto. Serv.
    instl_boots = 1067, 'instl-boots', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Installation Bootstrap Proto. Cli. IANA assigned this well-formed
    #:   service name as a replacement for "instl_bootc".
    #: - [TCP] Installation Bootstrap Proto. Cli.
    #: - [UDP] Installation Bootstrap Proto. Cli. IANA assigned this well-formed
    #:   service name as a replacement for "instl_bootc".
    #: - [UDP] Installation Bootstrap Proto. Cli.
    instl_bootc = 1068, 'instl-bootc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] COGNEX-INSIGHT
    #: - [UDP] COGNEX-INSIGHT
    cognex_insight = 1069, 'cognex-insight', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GMRUpdateSERV
    #: - [UDP] GMRUpdateSERV
    gmrupdateserv = 1070, 'gmrupdateserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BSQUARE-VOIP
    #: - [UDP] BSQUARE-VOIP
    bsquare_voip = 1071, 'bsquare-voip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CARDAX
    #: - [UDP] CARDAX
    cardax = 1072, 'cardax', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bridge Control
    #: - [UDP] Bridge Control
    bridgecontrol = 1073, 'bridgecontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Warmspot Management Protocol
    #: - [UDP] Warmspot Management Protocol
    warmspotmgmt = 1074, 'warmspotmgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RDRMSHC
    #: - [UDP] RDRMSHC
    rdrmshc = 1075, 'rdrmshc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DAB STI-C
    #: - [UDP] DAB STI-C
    dab_sti_c = 1076, 'dab-sti-c', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IMGames
    #: - [UDP] IMGames
    imgames = 1077, 'imgames', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avocent Proxy Protocol
    #: - [UDP] Avocent Proxy Protocol
    avocent_proxy = 1078, 'avocent-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASPROVATalk
    #: - [UDP] ASPROVATalk
    asprovatalk = 1079, 'asprovatalk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Socks
    #: - [UDP] Socks
    socks = 1080, 'socks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PVUNIWIEN
    #: - [UDP] PVUNIWIEN
    pvuniwien = 1081, 'pvuniwien', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMT-ESD-PROT
    #: - [UDP] AMT-ESD-PROT
    amt_esd_prot = 1082, 'amt-esd-prot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Anasoft License Manager
    #: - [UDP] Anasoft License Manager
    ansoft_lm_1 = 1083, 'ansoft-lm-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Anasoft License Manager
    #: - [UDP] Anasoft License Manager
    ansoft_lm_2 = 1084, 'ansoft-lm-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Web Objects
    #: - [UDP] Web Objects
    webobjects = 1085, 'webobjects', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CPL Scrambler Logging
    #: - [UDP] CPL Scrambler Logging
    cplscrambler_lg = 1086, 'cplscrambler-lg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CPL Scrambler Internal
    #: - [UDP] CPL Scrambler Internal
    cplscrambler_in = 1087, 'cplscrambler-in', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CPL Scrambler Alarm Log
    #: - [UDP] CPL Scrambler Alarm Log
    cplscrambler_al = 1088, 'cplscrambler-al', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FF Annunciation
    #: - [UDP] FF Annunciation
    ff_annunc = 1089, 'ff-annunc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FF Fieldbus Message Specification
    #: - [UDP] FF Fieldbus Message Specification
    ff_fms = 1090, 'ff-fms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FF System Management
    #: - [UDP] FF System Management
    ff_sm = 1091, 'ff-sm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Open Business Reporting Protocol
    #: - [UDP] Open Business Reporting Protocol
    obrpd = 1092, 'obrpd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PROOFD
    #: - [UDP] PROOFD
    proofd = 1093, 'proofd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ROOTD
    #: - [UDP] ROOTD
    rootd = 1094, 'rootd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NICELink
    #: - [UDP] NICELink
    nicelink = 1095, 'nicelink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Common Name Resolution Protocol
    #: - [UDP] Common Name Resolution Protocol
    cnrprotocol = 1096, 'cnrprotocol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun Cluster Manager
    #: - [UDP] Sun Cluster Manager
    sunclustermgr = 1097, 'sunclustermgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RMI Activation
    #: - [UDP] RMI Activation
    rmiactivation = 1098, 'rmiactivation', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RMI Registry
    #: - [UDP] RMI Registry
    rmiregistry = 1099, 'rmiregistry', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCTP
    #: - [UDP] MCTP
    mctp = 1100, 'mctp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PT2-DISCOVER
    #: - [UDP] PT2-DISCOVER
    pt2_discover = 1101, 'pt2-discover', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ADOBE SERVER 1
    #: - [UDP] ADOBE SERVER 1
    adobeserver_1 = 1102, 'adobeserver-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ADOBE SERVER 2
    #: - [UDP] ADOBE SERVER 2
    adobeserver_2 = 1103, 'adobeserver-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XRL
    #: - [UDP] XRL
    xrl = 1104, 'xrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FTRANHC
    #: - [UDP] FTRANHC
    ftranhc = 1105, 'ftranhc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISOIPSIGPORT-1
    #: - [UDP] ISOIPSIGPORT-1
    isoipsigport_1 = 1106, 'isoipsigport-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISOIPSIGPORT-2
    #: - [UDP] ISOIPSIGPORT-2
    isoipsigport_2 = 1107, 'isoipsigport-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ratio-adp
    #: - [UDP] ratio-adp
    ratio_adp = 1108, 'ratio-adp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Client status info
    nfsd_keepalive = 1110, 'nfsd-keepalive', TransportProtocol.udp

    #: - [TCP] LM Social Server
    #: - [UDP] LM Social Server
    lmsocialserver = 1111, 'lmsocialserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intelligent Communication Protocol
    #: - [UDP] Intelligent Communication Protocol
    icp = 1112, 'icp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Licklider Transmission Protocol [:rfc:`5326`]
    #: - [UDP] Licklider Transmission Protocol [:rfc:`5326`][:rfc:`7122`]
    #: - [DCCP] Licklider Transmission Protocol [:rfc:`7122`]
    ltp_deepspace = 1113, 'ltp-deepspace', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [TCP] Mini SQL
    #: - [UDP] Mini SQL
    mini_sql = 1114, 'mini-sql', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARDUS Transfer
    #: - [UDP] ARDUS Transfer
    ardus_trns = 1115, 'ardus-trns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARDUS Control
    #: - [UDP] ARDUS Control
    ardus_cntl = 1116, 'ardus-cntl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARDUS Multicast Transfer
    #: - [UDP] ARDUS Multicast Transfer
    ardus_mtrns = 1117, 'ardus-mtrns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SACRED [:rfc:`3767`]
    #: - [UDP] SACRED [:rfc:`3767`]
    sacred = 1118, 'sacred', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Battle.net Chat/Game Protocol
    #: - [UDP] Battle.net Chat/Game Protocol
    bnetgame = 1119, 'bnetgame', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Battle.net File Transfer Protocol
    #: - [UDP] Battle.net File Transfer Protocol
    bnetfile = 1120, 'bnetfile', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Datalode RMPP
    #: - [UDP] Datalode RMPP
    rmpp = 1121, 'rmpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] availant-mgr
    #: - [UDP] availant-mgr
    availant_mgr = 1122, 'availant-mgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Murray
    #: - [UDP] Murray
    murray = 1123, 'murray', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP VMM Control
    #: - [UDP] HP VMM Control
    hpvmmcontrol = 1124, 'hpvmmcontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP VMM Agent
    #: - [UDP] HP VMM Agent
    hpvmmagent = 1125, 'hpvmmagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP VMM Agent
    #: - [UDP] HP VMM Agent
    hpvmmdata = 1126, 'hpvmmdata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KWDB Remote Communication
    #: - [UDP] KWDB Remote Communication
    kwdb_commn = 1127, 'kwdb-commn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SAPHostControl over SOAP/HTTP
    #: - [UDP] SAPHostControl over SOAP/HTTP
    saphostctrl = 1128, 'saphostctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SAPHostControl over SOAP/HTTPS
    #: - [UDP] SAPHostControl over SOAP/HTTPS
    saphostctrls = 1129, 'saphostctrls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CAC App Service Protocol
    #: - [UDP] CAC App Service Protocol
    casp = 1130, 'casp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CAC App Service Protocol Encripted
    #: - [UDP] CAC App Service Protocol Encripted
    caspssl = 1131, 'caspssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KVM-via-IP Management Service
    #: - [UDP] KVM-via-IP Management Service
    kvm_via_ip = 1132, 'kvm-via-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Flow Network
    #: - [UDP] Data Flow Network
    dfn = 1133, 'dfn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MicroAPL APLX
    #: - [UDP] MicroAPL APLX
    aplx = 1134, 'aplx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OmniVision Communication Service
    #: - [UDP] OmniVision Communication Service
    omnivision = 1135, 'omnivision', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HHB Gateway Control
    #: - [UDP] HHB Gateway Control
    hhb_gateway = 1136, 'hhb-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRIM Workgroup Service
    #: - [UDP] TRIM Workgroup Service
    trim = 1137, 'trim', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] encrypted admin requests IANA assigned this well-formed service name
    #:   as a replacement for "encrypted_admin".
    #: - [TCP] encrypted admin requests
    #: - [UDP] encrypted admin requests IANA assigned this well-formed service name
    #:   as a replacement for "encrypted_admin".
    #: - [UDP] encrypted admin requests
    encrypted_admin = 1138, 'encrypted-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Enterprise Virtual Manager
    #: - [UDP] Enterprise Virtual Manager
    evm = 1139, 'evm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AutoNOC Network Operations Protocol
    #: - [UDP] AutoNOC Network Operations Protocol
    autonoc = 1140, 'autonoc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] User Message Service
    #: - [UDP] User Message Service
    mxomss = 1141, 'mxomss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] User Discovery Service
    #: - [UDP] User Discovery Service
    edtools = 1142, 'edtools', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Infomatryx Exchange
    #: - [UDP] Infomatryx Exchange
    imyx = 1143, 'imyx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fusion Script
    #: - [UDP] Fusion Script
    fuscript = 1144, 'fuscript', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] X9 iCue Show Control
    #: - [UDP] X9 iCue Show Control
    x9_icue = 1145, 'x9-icue', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] audit transfer
    #: - [UDP] audit transfer
    audit_transfer = 1146, 'audit-transfer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CAPIoverLAN
    #: - [UDP] CAPIoverLAN
    capioverlan = 1147, 'capioverlan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Elfiq Replication Service
    #: - [UDP] Elfiq Replication Service
    elfiq_repl = 1148, 'elfiq-repl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BlueView Sonar Service
    #: - [UDP] BlueView Sonar Service
    bvtsonar = 1149, 'bvtsonar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Blaze File Server
    #: - [UDP] Blaze File Server
    blaze = 1150, 'blaze', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unizensus Login Server
    #: - [UDP] Unizensus Login Server
    unizensus = 1151, 'unizensus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Winpopup LAN Messenger
    #: - [UDP] Winpopup LAN Messenger
    winpoplanmess = 1152, 'winpoplanmess', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ANSI C12.22 Port [:rfc:`6142`]
    #: - [UDP] ANSI C12.22 Port [:rfc:`6142`]
    c1222_acse = 1153, 'c1222-acse', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Community Service
    #: - [UDP] Community Service
    resacommunity = 1154, 'resacommunity', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network File Access
    #: - [UDP] Network File Access
    nfa = 1155, 'nfa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iasControl OMS
    #: - [UDP] iasControl OMS
    iascontrol_oms = 1156, 'iascontrol-oms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle iASControl
    #: - [UDP] Oracle iASControl
    iascontrol = 1157, 'iascontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dbControl OMS
    #: - [UDP] dbControl OMS
    dbcontrol_oms = 1158, 'dbcontrol-oms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle OMS
    #: - [UDP] Oracle OMS
    oracle_oms = 1159, 'oracle-oms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DB Lite Mult-User Server
    #: - [UDP] DB Lite Mult-User Server
    olsv = 1160, 'olsv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Health Polling
    #: - [UDP] Health Polling
    health_polling = 1161, 'health-polling', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Health Trap
    #: - [UDP] Health Trap
    health_trap = 1162, 'health-trap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SmartDialer Data Protocol
    #: - [UDP] SmartDialer Data Protocol
    sddp = 1163, 'sddp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSM Proxy Service
    #: - [UDP] QSM Proxy Service
    qsm_proxy = 1164, 'qsm-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSM GUI Service
    #: - [UDP] QSM GUI Service
    qsm_gui = 1165, 'qsm-gui', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSM RemoteExec
    #: - [UDP] QSM RemoteExec
    qsm_remote = 1166, 'qsm-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cisco IP SLAs Control Protocol
    #: - [UDP] Cisco IP SLAs Control Protocol
    #: - [SCTP] Cisco IP SLAs Control Protocol
    cisco_ipsla = 1167, 'cisco-ipsla', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] VChat Conference Service
    #: - [UDP] VChat Conference Service
    vchat = 1168, 'vchat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRIPWIRE
    #: - [UDP] TRIPWIRE
    tripwire = 1169, 'tripwire', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AT+C License Manager
    #: - [UDP] AT+C License Manager
    atc_lm = 1170, 'atc-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AT+C FmiApplicationServer
    #: - [UDP] AT+C FmiApplicationServer
    atc_appserver = 1171, 'atc-appserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNA Protocol
    #: - [UDP] DNA Protocol
    dnap = 1172, 'dnap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D-Cinema Request-Response
    #: - [UDP] D-Cinema Request-Response
    d_cinema_rrp = 1173, 'd-cinema-rrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FlashNet Remote Admin
    #: - [UDP] FlashNet Remote Admin
    fnet_remote_ui = 1174, 'fnet-remote-ui', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dossier Server
    #: - [UDP] Dossier Server
    dossier = 1175, 'dossier', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Indigo Home Server
    #: - [UDP] Indigo Home Server
    indigo_server = 1176, 'indigo-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DKMessenger Protocol
    #: - [UDP] DKMessenger Protocol
    dkmessenger = 1177, 'dkmessenger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SGI Storage Manager
    #: - [UDP] SGI Storage Manager
    sgi_storman = 1178, 'sgi-storman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Backup To Neighbor
    #: - [UDP] Backup To Neighbor
    b2n = 1179, 'b2n', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Millicent Client Proxy
    #: - [UDP] Millicent Client Proxy
    mc_client = 1180, 'mc-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3Com Net Management
    #: - [UDP] 3Com Net Management
    UDP_3comnetman = 1181, '3comnetman', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] AcceleNet Data
    accelenet_data = 1182, 'accelenet-data', TransportProtocol.udp

    #: - [TCP] LL Surfup HTTP
    #: - [UDP] LL Surfup HTTP
    llsurfup_http = 1183, 'llsurfup-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LL Surfup HTTPS
    #: - [UDP] LL Surfup HTTPS
    llsurfup_https = 1184, 'llsurfup-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Catchpole port
    #: - [UDP] Catchpole port
    catchpole = 1185, 'catchpole', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MySQL Cluster Manager
    #: - [UDP] MySQL Cluster Manager
    mysql_cluster = 1186, 'mysql-cluster', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alias Service
    #: - [UDP] Alias Service
    alias = 1187, 'alias', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP Web Admin
    #: - [UDP] HP Web Admin
    hp_webadmin = 1188, 'hp-webadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unet Connection
    #: - [UDP] Unet Connection
    unet = 1189, 'unet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CommLinx GPS / AVL System
    #: - [UDP] CommLinx GPS / AVL System
    commlinx_avl = 1190, 'commlinx-avl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] General Parallel File System
    #: - [UDP] General Parallel File System
    gpfs = 1191, 'gpfs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] caids sensors channel
    #: - [UDP] caids sensors channel
    caids_sensor = 1192, 'caids-sensor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Five Across Server
    #: - [UDP] Five Across Server
    fiveacross = 1193, 'fiveacross', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenVPN
    #: - [UDP] OpenVPN
    openvpn = 1194, 'openvpn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSF-1 clustering
    #: - [UDP] RSF-1 clustering
    rsf_1 = 1195, 'rsf-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Magic
    #: - [UDP] Network Magic
    netmagic = 1196, 'netmagic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Carrius Remote Access
    #: - [UDP] Carrius Remote Access
    carrius_rshell = 1197, 'carrius-rshell', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cajo reference discovery
    #: - [UDP] cajo reference discovery
    cajo_discovery = 1198, 'cajo-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DMIDI
    #: - [UDP] DMIDI
    dmidi = 1199, 'dmidi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCOL
    #: - [UDP] SCOL
    scol = 1200, 'scol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nucleus Sand Database Server
    #: - [UDP] Nucleus Sand Database Server
    nucleus_sand = 1201, 'nucleus-sand', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] caiccipc
    #: - [UDP] caiccipc
    caiccipc = 1202, 'caiccipc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] License Validation
    #: - [UDP] License Validation
    ssslic_mgr = 1203, 'ssslic-mgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Log Request Listener
    #: - [UDP] Log Request Listener
    ssslog_mgr = 1204, 'ssslog-mgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Accord-MGC
    #: - [UDP] Accord-MGC
    accord_mgc = 1205, 'accord-mgc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Anthony Data
    #: - [UDP] Anthony Data
    anthony_data = 1206, 'anthony-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MetaSage
    #: - [UDP] MetaSage
    metasage = 1207, 'metasage', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SEAGULL AIS
    #: - [UDP] SEAGULL AIS
    seagull_ais = 1208, 'seagull-ais', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPCD3
    #: - [UDP] IPCD3
    ipcd3 = 1209, 'ipcd3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EOSS
    #: - [UDP] EOSS
    eoss = 1210, 'eoss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Groove DPP
    #: - [UDP] Groove DPP
    groove_dpp = 1211, 'groove-dpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] lupa
    #: - [UDP] lupa
    lupa = 1212, 'lupa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Medtronic/Physio-Control LIFENET
    #: - [UDP] Medtronic/Physio-Control LIFENET
    mpc_lifenet = 1213, 'mpc-lifenet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KAZAA
    #: - [UDP] KAZAA
    kazaa = 1214, 'kazaa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] scanSTAT 1.0
    #: - [UDP] scanSTAT 1.0
    scanstat_1 = 1215, 'scanstat-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ETEBAC 5
    #: - [UDP] ETEBAC 5
    etebac5 = 1216, 'etebac5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HPSS NonDCE Gateway
    #: - [UDP] HPSS NonDCE Gateway
    hpss_ndapi = 1217, 'hpss-ndapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AeroFlight-ADs
    #: - [UDP] AeroFlight-ADs
    aeroflight_ads = 1218, 'aeroflight-ads', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AeroFlight-Ret
    #: - [UDP] AeroFlight-Ret
    aeroflight_ret = 1219, 'aeroflight-ret', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QT SERVER ADMIN
    #: - [UDP] QT SERVER ADMIN
    qt_serveradmin = 1220, 'qt-serveradmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SweetWARE Apps
    #: - [UDP] SweetWARE Apps
    sweetware_apps = 1221, 'sweetware-apps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNI R&D network
    #: - [UDP] SNI R&D network
    nerv = 1222, 'nerv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TrulyGlobal Protocol
    #: - [UDP] TrulyGlobal Protocol
    tgp = 1223, 'tgp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VPNz
    #: - [UDP] VPNz
    vpnz = 1224, 'vpnz', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SLINKYSEARCH
    #: - [UDP] SLINKYSEARCH
    slinkysearch = 1225, 'slinkysearch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STGXFWS
    #: - [UDP] STGXFWS
    stgxfws = 1226, 'stgxfws', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNS2Go
    #: - [UDP] DNS2Go
    dns2go = 1227, 'dns2go', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FLORENCE
    #: - [UDP] FLORENCE
    florence = 1228, 'florence', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ZENworks Tiered Electronic Distribution
    #: - [UDP] ZENworks Tiered Electronic Distribution
    zented = 1229, 'zented', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Periscope
    #: - [UDP] Periscope
    periscope = 1230, 'periscope', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] menandmice-lpm
    #: - [UDP] menandmice-lpm
    menandmice_lpm = 1231, 'menandmice-lpm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote systems monitoring
    #: - [UDP] Remote systems monitoring
    first_defense = 1232, 'first-defense', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Universal App Server
    #: - [UDP] Universal App Server
    univ_appserver = 1233, 'univ-appserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Infoseek Search Agent
    #: - [UDP] Infoseek Search Agent
    search_agent = 1234, 'search-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mosaicsyssvc1
    #: - [UDP] mosaicsyssvc1
    mosaicsyssvc1 = 1235, 'mosaicsyssvc1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bvcontrol
    #: - [UDP] bvcontrol
    bvcontrol = 1236, 'bvcontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tsdos390
    #: - [UDP] tsdos390
    tsdos390 = 1237, 'tsdos390', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hacl-qs
    #: - [UDP] hacl-qs
    hacl_qs = 1238, 'hacl-qs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NMSD
    #: - [UDP] NMSD
    nmsd = 1239, 'nmsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Instantia
    #: - [UDP] Instantia
    instantia = 1240, 'instantia', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nessus
    #: - [UDP] nessus
    nessus = 1241, 'nessus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NMAS over IP
    #: - [UDP] NMAS over IP
    nmasoverip = 1242, 'nmasoverip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SerialGateway
    #: - [UDP] SerialGateway
    serialgateway = 1243, 'serialgateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isbconference1
    #: - [UDP] isbconference1
    isbconference1 = 1244, 'isbconference1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isbconference2
    #: - [UDP] isbconference2
    isbconference2 = 1245, 'isbconference2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] payrouter
    #: - [UDP] payrouter
    payrouter = 1246, 'payrouter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VisionPyramid
    #: - [UDP] VisionPyramid
    visionpyramid = 1247, 'visionpyramid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hermes
    #: - [UDP] hermes
    hermes = 1248, 'hermes', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mesa Vista Co
    #: - [UDP] Mesa Vista Co
    mesavistaco = 1249, 'mesavistaco', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] swldy-sias
    #: - [UDP] swldy-sias
    swldy_sias = 1250, 'swldy-sias', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] servergraph
    #: - [UDP] servergraph
    servergraph = 1251, 'servergraph', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bspne-pcc
    #: - [UDP] bspne-pcc
    bspne_pcc = 1252, 'bspne-pcc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] q55-pcc
    #: - [UDP] q55-pcc
    q55_pcc = 1253, 'q55-pcc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] de-noc
    #: - [UDP] de-noc
    de_noc = 1254, 'de-noc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] de-cache-query
    #: - [UDP] de-cache-query
    de_cache_query = 1255, 'de-cache-query', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] de-server
    #: - [UDP] de-server
    de_server = 1256, 'de-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Shockwave 2
    #: - [UDP] Shockwave 2
    shockwave2 = 1257, 'shockwave2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Open Network Library
    #: - [UDP] Open Network Library
    opennl = 1258, 'opennl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Open Network Library Voice
    #: - [UDP] Open Network Library Voice
    opennl_voice = 1259, 'opennl-voice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ibm-ssd
    #: - [UDP] ibm-ssd
    ibm_ssd = 1260, 'ibm-ssd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mpshrsv
    #: - [UDP] mpshrsv
    mpshrsv = 1261, 'mpshrsv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QNTS-ORB
    #: - [UDP] QNTS-ORB
    qnts_orb = 1262, 'qnts-orb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dka
    #: - [UDP] dka
    dka = 1263, 'dka', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PRAT
    #: - [UDP] PRAT
    prat = 1264, 'prat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DSSIAPI
    #: - [UDP] DSSIAPI
    dssiapi = 1265, 'dssiapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DELLPWRAPPKS
    #: - [UDP] DELLPWRAPPKS
    dellpwrappks = 1266, 'dellpwrappks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eTrust Policy Compliance
    #: - [UDP] eTrust Policy Compliance
    epc = 1267, 'epc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PROPEL-MSGSYS
    #: - [UDP] PROPEL-MSGSYS
    propel_msgsys = 1268, 'propel-msgsys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WATiLaPP
    #: - [UDP] WATiLaPP
    watilapp = 1269, 'watilapp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Operations Manager
    #: - [UDP] Microsoft Operations Manager
    opsmgr = 1270, 'opsmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eXcW
    #: - [UDP] eXcW
    excw = 1271, 'excw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSPMLockMgr
    #: - [UDP] CSPMLockMgr
    cspmlockmgr = 1272, 'cspmlockmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMC-Gateway
    #: - [UDP] EMC-Gateway
    emc_gateway = 1273, 'emc-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] t1distproc
    #: - [UDP] t1distproc
    t1distproc = 1274, 't1distproc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ivcollector
    #: - [UDP] ivcollector
    ivcollector = 1275, 'ivcollector', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_1276 = 1276, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mqs
    #: - [UDP] mqs
    miva_mqs = 1277, 'miva-mqs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dell Web Admin 1
    #: - [UDP] Dell Web Admin 1
    dellwebadmin_1 = 1278, 'dellwebadmin-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dell Web Admin 2
    #: - [UDP] Dell Web Admin 2
    dellwebadmin_2 = 1279, 'dellwebadmin-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pictrography
    #: - [UDP] Pictrography
    pictrography = 1280, 'pictrography', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] healthd
    #: - [UDP] healthd
    healthd = 1281, 'healthd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Emperion
    #: - [UDP] Emperion
    emperion = 1282, 'emperion', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Product Information
    #: - [UDP] Product Information
    productinfo = 1283, 'productinfo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IEE-QFX
    #: - [UDP] IEE-QFX
    iee_qfx = 1284, 'iee-qfx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] neoiface
    #: - [UDP] neoiface
    neoiface = 1285, 'neoiface', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netuitive
    #: - [UDP] netuitive
    netuitive = 1286, 'netuitive', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RouteMatch Com
    #: - [UDP] RouteMatch Com
    routematch = 1287, 'routematch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NavBuddy
    #: - [UDP] NavBuddy
    navbuddy = 1288, 'navbuddy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JWalkServer
    #: - [UDP] JWalkServer
    jwalkserver = 1289, 'jwalkserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WinJaServer
    #: - [UDP] WinJaServer
    winjaserver = 1290, 'winjaserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SEAGULLLMS
    #: - [UDP] SEAGULLLMS
    seagulllms = 1291, 'seagulllms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dsdn
    #: - [UDP] dsdn
    dsdn = 1292, 'dsdn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PKT-KRB-IPSec
    #: - [UDP] PKT-KRB-IPSec
    pkt_krb_ipsec = 1293, 'pkt-krb-ipsec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CMMdriver
    #: - [UDP] CMMdriver
    cmmdriver = 1294, 'cmmdriver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] End-by-Hop Transmission Protocol
    #: - [UDP] End-by-Hop Transmission Protocol
    ehtp = 1295, 'ehtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dproxy
    #: - [UDP] dproxy
    dproxy = 1296, 'dproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sdproxy
    #: - [UDP] sdproxy
    sdproxy = 1297, 'sdproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] lpcp
    #: - [UDP] lpcp
    lpcp = 1298, 'lpcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp-sci
    #: - [UDP] hp-sci
    hp_sci = 1299, 'hp-sci', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] H.323 Secure Call Control Signalling
    #: - [UDP] H.323 Secure Call Control Signalling
    h323hostcallsc = 1300, 'h323hostcallsc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_1301 = 1301, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_1302 = 1302, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sftsrv
    #: - [UDP] sftsrv
    sftsrv = 1303, 'sftsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Boomerang
    #: - [UDP] Boomerang
    boomerang = 1304, 'boomerang', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pe-mike
    #: - [UDP] pe-mike
    pe_mike = 1305, 'pe-mike', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RE-Conn-Proto
    #: - [UDP] RE-Conn-Proto
    re_conn_proto = 1306, 're-conn-proto', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pacmand
    #: - [UDP] Pacmand
    pacmand = 1307, 'pacmand', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Optical Domain Service Interconnect (ODSI)
    #: - [UDP] Optical Domain Service Interconnect (ODSI)
    odsi = 1308, 'odsi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JTAG server
    #: - [UDP] JTAG server
    jtag_server = 1309, 'jtag-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Husky
    #: - [UDP] Husky
    husky = 1310, 'husky', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RxMon
    #: - [UDP] RxMon
    rxmon = 1311, 'rxmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STI Envision
    #: - [UDP] STI Envision
    sti_envision = 1312, 'sti-envision', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC_PATROLDB IANA assigned this well-formed service name as a
    #:   replacement for "bmc_patroldb".
    #: - [TCP] BMC_PATROLDB
    #: - [UDP] BMC_PATROLDB IANA assigned this well-formed service name as a
    #:   replacement for "bmc_patroldb".
    #: - [UDP] BMC_PATROLDB
    bmc_patroldb = 1313, 'bmc-patroldb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Photoscript Distributed Printing System
    #: - [UDP] Photoscript Distributed Printing System
    pdps = 1314, 'pdps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] E.L.S., Event Listener Service
    #: - [UDP] E.L.S., Event Listener Service
    els = 1315, 'els', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Exbit-ESCP
    #: - [UDP] Exbit-ESCP
    exbit_escp = 1316, 'exbit-escp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vrts-ipcserver
    #: - [UDP] vrts-ipcserver
    vrts_ipcserver = 1317, 'vrts-ipcserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] krb5gatekeeper
    #: - [UDP] krb5gatekeeper
    krb5gatekeeper = 1318, 'krb5gatekeeper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMX-ICSP
    #: - [UDP] AMX-ICSP
    amx_icsp = 1319, 'amx-icsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMX-AXBNET
    #: - [UDP] AMX-AXBNET
    amx_axbnet = 1320, 'amx-axbnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PIP
    #: - [UDP] PIP
    pip_321 = 321, 'pip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PIP
    #: - [UDP] PIP
    pip_1321 = 1321, 'pip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novation
    #: - [UDP] Novation
    novation = 1322, 'novation', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] brcd
    #: - [UDP] brcd
    brcd = 1323, 'brcd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] delta-mcp
    #: - [UDP] delta-mcp
    delta_mcp = 1324, 'delta-mcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Thermo Fisher Scientific Instrumentation (Formally Dionex)
    #: - [UDP] Thermo Fisher Scientific Instrumentation (Formally Dionex)
    dx_instrument = 1325, 'dx-instrument', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WIMSIC
    #: - [UDP] WIMSIC
    wimsic = 1326, 'wimsic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ultrex
    #: - [UDP] Ultrex
    ultrex = 1327, 'ultrex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EWALL
    #: - [UDP] EWALL
    ewall = 1328, 'ewall', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netdb-export
    #: - [UDP] netdb-export
    netdb_export = 1329, 'netdb-export', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] StreetPerfect
    #: - [UDP] StreetPerfect
    streetperfect = 1330, 'streetperfect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] intersan
    #: - [UDP] intersan
    intersan = 1331, 'intersan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCIA RXP-B
    #: - [UDP] PCIA RXP-B
    pcia_rxp_b = 1332, 'pcia-rxp-b', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Password Policy
    #: - [UDP] Password Policy
    passwrd_policy = 1333, 'passwrd-policy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] writesrv
    #: - [UDP] writesrv
    writesrv = 1334, 'writesrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Digital Notary Protocol
    #: - [UDP] Digital Notary Protocol
    digital_notary = 1335, 'digital-notary', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Instant Service Chat
    #: - [UDP] Instant Service Chat
    ischat = 1336, 'ischat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] menandmice DNS
    #: - [UDP] menandmice DNS
    menandmice_dns = 1337, 'menandmice-dns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WMC-log-svr
    #: - [UDP] WMC-log-svr
    wmc_log_svc = 1338, 'wmc-log-svc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] kjtsiteserver
    #: - [UDP] kjtsiteserver
    kjtsiteserver = 1339, 'kjtsiteserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NAAP
    #: - [UDP] NAAP
    naap = 1340, 'naap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QuBES
    #: - [UDP] QuBES
    qubes = 1341, 'qubes', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESBroker
    #: - [UDP] ESBroker
    esbroker = 1342, 'esbroker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] re101
    #: - [UDP] re101
    re101 = 1343, 're101', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICAP
    #: - [UDP] ICAP
    icap = 1344, 'icap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VPJP
    #: - [UDP] VPJP
    vpjp = 1345, 'vpjp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alta Analytics License Manager
    #: - [UDP] Alta Analytics License Manager
    alta_ana_lm = 1346, 'alta-ana-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] multi media conferencing
    #: - [UDP] multi media conferencing
    bbn_mmc = 1347, 'bbn-mmc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] multi media conferencing
    #: - [UDP] multi media conferencing
    bbn_mmx = 1348, 'bbn-mmx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Registration Network Protocol
    #: - [UDP] Registration Network Protocol
    sbook = 1349, 'sbook', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Registration Network Protocol
    #: - [UDP] Registration Network Protocol
    editbench = 1350, 'editbench', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Digital Tool Works (MIT)
    #: - [UDP] Digital Tool Works (MIT)
    equationbuilder = 1351, 'equationbuilder', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lotus Note
    #: - [UDP] Lotus Note
    lotusnote = 1352, 'lotusnote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Relief Consulting
    #: - [UDP] Relief Consulting
    relief = 1353, 'relief', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Five Across XSIP Network
    #: - [UDP] Five Across XSIP Network
    xsip_network = 1354, 'xsip-network', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intuitive Edge
    #: - [UDP] Intuitive Edge
    intuitive_edge = 1355, 'intuitive-edge', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CuillaMartin Company
    #: - [UDP] CuillaMartin Company
    cuillamartin = 1356, 'cuillamartin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Electronic PegBoard
    #: - [UDP] Electronic PegBoard
    pegboard = 1357, 'pegboard', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CONNLCLI
    #: - [UDP] CONNLCLI
    connlcli = 1358, 'connlcli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FTSRV
    #: - [UDP] FTSRV
    ftsrv = 1359, 'ftsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MIMER
    #: - [UDP] MIMER
    mimer = 1360, 'mimer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LinX
    #: - [UDP] LinX
    linx = 1361, 'linx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TimeFlies
    #: - [UDP] TimeFlies
    timeflies = 1362, 'timeflies', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network DataMover Requester
    #: - [UDP] Network DataMover Requester
    ndm_requester = 1363, 'ndm-requester', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network DataMover Server
    #: - [UDP] Network DataMover Server
    ndm_server = 1364, 'ndm-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Software Associates
    #: - [UDP] Network Software Associates
    adapt_sna = 1365, 'adapt-sna', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novell NetWare Comm Service Platform
    #: - [UDP] Novell NetWare Comm Service Platform
    netware_csp = 1366, 'netware-csp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DCS
    #: - [UDP] DCS
    dcs = 1367, 'dcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ScreenCast
    #: - [UDP] ScreenCast
    screencast = 1368, 'screencast', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GlobalView to Unix Shell
    #: - [UDP] GlobalView to Unix Shell
    gv_us = 1369, 'gv-us', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unix Shell to GlobalView
    #: - [UDP] Unix Shell to GlobalView
    us_gv = 1370, 'us-gv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Config Protocol
    #: - [UDP] Fujitsu Config Protocol
    fc_cli = 1371, 'fc-cli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Config Protocol
    #: - [UDP] Fujitsu Config Protocol
    fc_ser = 1372, 'fc-ser', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Chromagrafx
    #: - [UDP] Chromagrafx
    chromagrafx = 1373, 'chromagrafx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPI Software Systems
    #: - [UDP] EPI Software Systems
    molly = 1374, 'molly', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bytex
    #: - [UDP] Bytex
    bytex = 1375, 'bytex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Person to Person Software
    #: - [UDP] IBM Person to Person Software
    ibm_pps = 1376, 'ibm-pps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cichlid License Manager
    #: - [UDP] Cichlid License Manager
    cichlid = 1377, 'cichlid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Elan License Manager
    #: - [UDP] Elan License Manager
    elan = 1378, 'elan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Integrity Solutions
    #: - [UDP] Integrity Solutions
    dbreporter = 1379, 'dbreporter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Telesis Network License Manager
    #: - [UDP] Telesis Network License Manager
    telesis_licman = 1380, 'telesis-licman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apple Network License Manager
    #: - [UDP] Apple Network License Manager
    apple_licman = 1381, 'apple-licman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GW Hannaway Network License Manager
    #: - [UDP] GW Hannaway Network License Manager
    gwha = 1383, 'gwha', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Objective Solutions License Manager
    #: - [UDP] Objective Solutions License Manager
    os_licman = 1384, 'os-licman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Atex Publishing License Manager IANA assigned this well-formed service
    #:   name as a replacement for "atex_elmd".
    #: - [TCP] Atex Publishing License Manager
    #: - [UDP] Atex Publishing License Manager IANA assigned this well-formed service
    #:   name as a replacement for "atex_elmd".
    #: - [UDP] Atex Publishing License Manager
    atex_elmd = 1385, 'atex-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CheckSum License Manager
    #: - [UDP] CheckSum License Manager
    checksum = 1386, 'checksum', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Computer Aided Design Software Inc LM
    #: - [UDP] Computer Aided Design Software Inc LM
    cadsi_lm = 1387, 'cadsi-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Objective Solutions DataBase Cache
    #: - [UDP] Objective Solutions DataBase Cache
    objective_dbc = 1388, 'objective-dbc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Document Manager
    #: - [UDP] Document Manager
    iclpv_dm = 1389, 'iclpv-dm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Storage Controller
    #: - [UDP] Storage Controller
    iclpv_sc = 1390, 'iclpv-sc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Storage Access Server
    #: - [UDP] Storage Access Server
    iclpv_sas = 1391, 'iclpv-sas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Print Manager
    #: - [UDP] Print Manager
    iclpv_pm = 1392, 'iclpv-pm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Log Server
    #: - [UDP] Network Log Server
    iclpv_nls = 1393, 'iclpv-nls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Log Client
    #: - [UDP] Network Log Client
    iclpv_nlc = 1394, 'iclpv-nlc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PC Workstation Manager software
    #: - [UDP] PC Workstation Manager software
    iclpv_wsm = 1395, 'iclpv-wsm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DVL Active Mail
    #: - [UDP] DVL Active Mail
    dvl_activemail = 1396, 'dvl-activemail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Audio Active Mail
    #: - [UDP] Audio Active Mail
    audio_activmail = 1397, 'audio-activmail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Video Active Mail
    #: - [UDP] Video Active Mail
    video_activmail = 1398, 'video-activmail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cadkey License Manager
    #: - [UDP] Cadkey License Manager
    cadkey_licman = 1399, 'cadkey-licman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cadkey Tablet Daemon
    #: - [UDP] Cadkey Tablet Daemon
    cadkey_tablet = 1400, 'cadkey-tablet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Goldleaf License Manager
    #: - [UDP] Goldleaf License Manager
    goldleaf_licman = 1401, 'goldleaf-licman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prospero Resource Manager
    #: - [UDP] Prospero Resource Manager
    prm_sm_np = 1402, 'prm-sm-np', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prospero Resource Manager
    #: - [UDP] Prospero Resource Manager
    prm_nm_np = 1403, 'prm-nm-np', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Infinite Graphics License Manager
    #: - [UDP] Infinite Graphics License Manager
    igi_lm = 1404, 'igi-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Remote Execution Starter
    #: - [UDP] IBM Remote Execution Starter
    ibm_res = 1405, 'ibm-res', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetLabs License Manager
    #: - [UDP] NetLabs License Manager
    netlabs_lm = 1406, 'netlabs-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_1407 = 1407, 'reserved', TransportProtocol.udp

    #: - [TCP] Sophia License Manager
    #: - [UDP] Sophia License Manager
    sophia_lm = 1408, 'sophia-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Here License Manager
    #: - [UDP] Here License Manager
    here_lm = 1409, 'here-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HiQ License Manager
    #: - [UDP] HiQ License Manager
    hiq = 1410, 'hiq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AudioFile
    #: - [UDP] AudioFile
    af = 1411, 'af', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] InnoSys
    #: - [UDP] InnoSys
    innosys = 1412, 'innosys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Innosys-ACL
    #: - [UDP] Innosys-ACL
    innosys_acl = 1413, 'innosys-acl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM MQSeries
    #: - [UDP] IBM MQSeries
    ibm_mqseries = 1414, 'ibm-mqseries', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DBStar
    #: - [UDP] DBStar
    dbstar = 1415, 'dbstar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novell LU6.2 IANA assigned this well-formed service name as a
    #:   replacement for "novell-lu6.2".
    #: - [TCP] Novell LU6.2
    #: - [UDP] Novell LU6.2 IANA assigned this well-formed service name as a
    #:   replacement for "novell-lu6.2".
    #: - [UDP] Novell LU6.2
    novell_lu6_2 = 1416, 'novell-lu6-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Timbuktu Service 1 Port
    #: - [UDP] Timbuktu Service 1 Port
    timbuktu_srv1 = 1417, 'timbuktu-srv1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Timbuktu Service 2 Port
    #: - [UDP] Timbuktu Service 2 Port
    timbuktu_srv2 = 1418, 'timbuktu-srv2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Timbuktu Service 3 Port
    #: - [UDP] Timbuktu Service 3 Port
    timbuktu_srv3 = 1419, 'timbuktu-srv3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Timbuktu Service 4 Port
    #: - [UDP] Timbuktu Service 4 Port
    timbuktu_srv4 = 1420, 'timbuktu-srv4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gandalf License Manager
    #: - [UDP] Gandalf License Manager
    gandalf_lm = 1421, 'gandalf-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Autodesk License Manager
    #: - [UDP] Autodesk License Manager
    autodesk_lm = 1422, 'autodesk-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Essbase Arbor Software
    #: - [UDP] Essbase Arbor Software
    essbase = 1423, 'essbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hybrid Encryption Protocol
    #: - [UDP] Hybrid Encryption Protocol
    hybrid = 1424, 'hybrid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zion Software License Manager
    #: - [UDP] Zion Software License Manager
    zion_lm = 1425, 'zion-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Satellite-data Acquisition System 1
    #: - [UDP] Satellite-data Acquisition System 1
    sais = 1426, 'sais', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mloadd monitoring tool
    #: - [UDP] mloadd monitoring tool
    mloadd = 1427, 'mloadd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Informatik License Manager
    #: - [UDP] Informatik License Manager
    informatik_lm = 1428, 'informatik-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hypercom NMS
    #: - [UDP] Hypercom NMS
    nms = 1429, 'nms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hypercom TPDU
    #: - [UDP] Hypercom TPDU
    tpdu = 1430, 'tpdu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reverse Gossip Transport
    #: - [UDP] Reverse Gossip Transport
    rgtp = 1431, 'rgtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Blueberry Software License Manager
    #: - [UDP] Blueberry Software License Manager
    blueberry_lm = 1432, 'blueberry-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft-SQL-Server
    #: - [UDP] Microsoft-SQL-Server
    ms_sql_s = 1433, 'ms-sql-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft-SQL-Monitor
    #: - [UDP] Microsoft-SQL-Monitor
    ms_sql_m = 1434, 'ms-sql-m', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM CICS
    #: - [UDP] IBM CICS
    ibm_cics = 1435, 'ibm-cics', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Satellite-data Acquisition System 2
    #: - [UDP] Satellite-data Acquisition System 2
    saism = 1436, 'saism', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tabula
    #: - [UDP] Tabula
    tabula = 1437, 'tabula', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Eicon Security Agent/Server
    #: - [UDP] Eicon Security Agent/Server
    eicon_server = 1438, 'eicon-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Eicon X25/SNA Gateway
    #: - [UDP] Eicon X25/SNA Gateway
    eicon_x25 = 1439, 'eicon-x25', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Eicon Service Location Protocol
    #: - [UDP] Eicon Service Location Protocol
    eicon_slp = 1440, 'eicon-slp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cadis License Management
    #: - [UDP] Cadis License Management
    cadis_1 = 1441, 'cadis-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cadis License Management
    #: - [UDP] Cadis License Management
    cadis_2 = 1442, 'cadis-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Integrated Engineering Software
    #: - [UDP] Integrated Engineering Software
    ies_lm = 1443, 'ies-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Marcam License Management
    #: - [UDP] Marcam License Management
    marcam_lm = 1444, 'marcam-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Proxima License Manager
    #: - [UDP] Proxima License Manager
    proxima_lm = 1445, 'proxima-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Optical Research Associates License Manager
    #: - [UDP] Optical Research Associates License Manager
    ora_lm = 1446, 'ora-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Applied Parallel Research LM
    #: - [UDP] Applied Parallel Research LM
    apri_lm = 1447, 'apri-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenConnect License Manager
    #: - [UDP] OpenConnect License Manager
    oc_lm = 1448, 'oc-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PEport
    #: - [UDP] PEport
    peport = 1449, 'peport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tandem Distributed Workbench Facility
    #: - [UDP] Tandem Distributed Workbench Facility
    dwf = 1450, 'dwf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Information Management
    #: - [UDP] IBM Information Management
    infoman = 1451, 'infoman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GTE Government Systems License Man
    #: - [UDP] GTE Government Systems License Man
    gtegsc_lm = 1452, 'gtegsc-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Genie License Manager
    #: - [UDP] Genie License Manager
    genie_lm = 1453, 'genie-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] interHDL License Manager IANA assigned this well-formed service name
    #:   as a replacement for "interhdl_elmd".
    #: - [TCP] interHDL License Manager
    #: - [UDP] interHDL License Manager IANA assigned this well-formed service name
    #:   as a replacement for "interhdl_elmd".
    #: - [UDP] interHDL License Manager
    interhdl_elmd = 1454, 'interhdl-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESL License Manager
    #: - [UDP] ESL License Manager
    esl_lm = 1455, 'esl-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DCA
    #: - [UDP] DCA
    dca = 1456, 'dca', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Valisys License Manager
    #: - [UDP] Valisys License Manager
    valisys_lm = 1457, 'valisys-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nichols Research Corp.
    #: - [UDP] Nichols Research Corp.
    nrcabq_lm = 1458, 'nrcabq-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Proshare Notebook Application
    #: - [UDP] Proshare Notebook Application
    proshare1 = 1459, 'proshare1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Proshare Notebook Application
    #: - [UDP] Proshare Notebook Application
    proshare2 = 1460, 'proshare2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Wireless LAN IANA assigned this well-formed service name as a
    #:   replacement for "ibm_wrless_lan".
    #: - [TCP] IBM Wireless LAN
    #: - [UDP] IBM Wireless LAN IANA assigned this well-formed service name as a
    #:   replacement for "ibm_wrless_lan".
    #: - [UDP] IBM Wireless LAN
    ibm_wrless_lan = 1461, 'ibm-wrless-lan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] World License Manager
    #: - [UDP] World License Manager
    world_lm = 1462, 'world-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nucleus
    #: - [UDP] Nucleus
    nucleus = 1463, 'nucleus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSL License Manager IANA assigned this well-formed service name as a
    #:   replacement for "msl_lmd".
    #: - [TCP] MSL License Manager
    #: - [UDP] MSL License Manager IANA assigned this well-formed service name as a
    #:   replacement for "msl_lmd".
    #: - [UDP] MSL License Manager
    msl_lmd = 1464, 'msl-lmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pipes Platform
    #: - [UDP] Pipes Platform
    pipes = 1465, 'pipes', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ocean Software License Manager
    #: - [UDP] Ocean Software License Manager
    oceansoft_lm = 1466, 'oceansoft-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Active Analysis Limited License Manager
    #: - [UDP] Active Analysis Limited License Manager
    aal_lm = 1469, 'aal-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Universal Analytics
    #: - [UDP] Universal Analytics
    uaiact = 1470, 'uaiact', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSDMBASE
    #: - [UDP] CSDMBASE
    csdmbase_1467 = 1467, 'csdmbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] csdmbase
    #: - [UDP] csdmbase
    csdmbase_1471 = 1471, 'csdmbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSDM
    #: - [UDP] CSDM
    csdm_1468 = 1468, 'csdm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] csdm
    #: - [UDP] csdm
    csdm_1472 = 1472, 'csdm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenMath
    #: - [UDP] OpenMath
    openmath = 1473, 'openmath', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Telefinder
    #: - [UDP] Telefinder
    telefinder = 1474, 'telefinder', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Taligent License Manager
    #: - [UDP] Taligent License Manager
    taligent_lm = 1475, 'taligent-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] clvm-cfg
    #: - [UDP] clvm-cfg
    clvm_cfg = 1476, 'clvm-cfg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ms-sna-server
    #: - [UDP] ms-sna-server
    ms_sna_server = 1477, 'ms-sna-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ms-sna-base
    #: - [UDP] ms-sna-base
    ms_sna_base = 1478, 'ms-sna-base', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dberegister
    #: - [UDP] dberegister
    dberegister = 1479, 'dberegister', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PacerForum
    #: - [UDP] PacerForum
    pacerforum = 1480, 'pacerforum', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AIRS
    #: - [UDP] AIRS
    airs = 1481, 'airs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Miteksys License Manager
    #: - [UDP] Miteksys License Manager
    miteksys_lm = 1482, 'miteksys-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AFS License Manager
    #: - [UDP] AFS License Manager
    afs = 1483, 'afs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Confluent License Manager
    #: - [UDP] Confluent License Manager
    confluent = 1484, 'confluent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LANSource
    #: - [UDP] LANSource
    lansource = 1485, 'lansource', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nms_topo_serv IANA assigned this well-formed service name as a
    #:   replacement for "nms_topo_serv".
    #: - [TCP] nms_topo_serv
    #: - [UDP] nms_topo_serv IANA assigned this well-formed service name as a
    #:   replacement for "nms_topo_serv".
    #: - [UDP] nms_topo_serv
    nms_topo_serv = 1486, 'nms-topo-serv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LocalInfoSrvr
    #: - [UDP] LocalInfoSrvr
    localinfosrvr = 1487, 'localinfosrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DocStor
    #: - [UDP] DocStor
    docstor = 1488, 'docstor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dmdocbroker
    #: - [UDP] dmdocbroker
    dmdocbroker = 1489, 'dmdocbroker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] insitu-conf
    #: - [UDP] insitu-conf
    insitu_conf = 1490, 'insitu-conf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] stone-design-1
    #: - [UDP] stone-design-1
    stone_design_1 = 1492, 'stone-design-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netmap_lm IANA assigned this well-formed service name as a replacement
    #:   for "netmap_lm".
    #: - [TCP] netmap_lm
    #: - [UDP] netmap_lm IANA assigned this well-formed service name as a replacement
    #:   for "netmap_lm".
    #: - [UDP] netmap_lm
    netmap_lm = 1493, 'netmap-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ica
    #: - [UDP] ica
    ica = 1494, 'ica', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cvc
    #: - [UDP] cvc
    cvc = 1495, 'cvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] liberty-lm
    #: - [UDP] liberty-lm
    liberty_lm = 1496, 'liberty-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rfx-lm
    #: - [UDP] rfx-lm
    rfx_lm = 1497, 'rfx-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sybase SQL Any
    #: - [UDP] Sybase SQL Any
    sybase_sqlany = 1498, 'sybase-sqlany', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Federico Heinz Consultora
    #: - [UDP] Federico Heinz Consultora
    fhc = 1499, 'fhc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VLSI License Manager
    #: - [UDP] VLSI License Manager
    vlsi_lm = 1500, 'vlsi-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Satellite-data Acquisition System 3
    #: - [UDP] Satellite-data Acquisition System 3
    saiscm = 1501, 'saiscm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Shiva
    #: - [UDP] Shiva
    shivadiscovery = 1502, 'shivadiscovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Databeam
    #: - [UDP] Databeam
    imtc_mcs = 1503, 'imtc-mcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EVB Software Engineering License Manager
    #: - [UDP] EVB Software Engineering License Manager
    evb_elm = 1504, 'evb-elm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Funk Software, Inc.
    #: - [UDP] Funk Software, Inc.
    funkproxy = 1505, 'funkproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Universal Time daemon (utcd)
    #: - [UDP] Universal Time daemon (utcd)
    utcd = 1506, 'utcd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] symplex
    #: - [UDP] symplex
    symplex = 1507, 'symplex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] diagmond
    #: - [UDP] diagmond
    diagmond = 1508, 'diagmond', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Robcad, Ltd. License Manager
    #: - [UDP] Robcad, Ltd. License Manager
    robcad_lm = 1509, 'robcad-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Midland Valley Exploration Ltd. Lic. Man.
    #: - [UDP] Midland Valley Exploration Ltd. Lic. Man.
    mvx_lm = 1510, 'mvx-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3l-l1
    #: - [UDP] 3l-l1
    UDP_3l_l1 = 1511, '3l-l1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft's Windows Internet Name Service
    #: - [UDP] Microsoft's Windows Internet Name Service
    wins = 1512, 'wins', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Systems Business of America, Inc
    #: - [UDP] Fujitsu Systems Business of America, Inc
    fujitsu_dtc = 1513, 'fujitsu-dtc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Systems Business of America, Inc
    #: - [UDP] Fujitsu Systems Business of America, Inc
    fujitsu_dtcns = 1514, 'fujitsu-dtcns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ifor-protocol
    #: - [UDP] ifor-protocol
    ifor_protocol = 1515, 'ifor-protocol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Places Audio data
    #: - [UDP] Virtual Places Audio data
    vpad = 1516, 'vpad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Places Audio control
    #: - [UDP] Virtual Places Audio control
    vpac = 1517, 'vpac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Places Video data
    #: - [UDP] Virtual Places Video data
    vpvd = 1518, 'vpvd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Places Video control
    #: - [UDP] Virtual Places Video control
    vpvc = 1519, 'vpvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] atm zip office
    #: - [UDP] atm zip office
    atm_zip_office = 1520, 'atm-zip-office', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nCube License Manager
    #: - [UDP] nCube License Manager
    ncube_lm = 1521, 'ncube-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cichild
    #: - [UDP] cichild
    cichild_lm = 1523, 'cichild-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ingres
    #: - [UDP] ingres
    ingreslock = 1524, 'ingreslock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] oracle
    #: - [UDP] oracle
    orasrv = 1525, 'orasrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prospero Directory Service non-priv
    #: - [UDP] Prospero Directory Service non-priv
    prospero_np = 1525, 'prospero-np', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prospero Data Access Prot non-priv
    #: - [UDP] Prospero Data Access Prot non-priv
    pdap_np = 1526, 'pdap-np', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] oracle
    #: - [UDP] oracle
    tlisrv = 1527, 'tlisrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Not Only a Routeing Protocol
    #: - [UDP] Not Only a Routeing Protocol
    #: - [SCTP] Not Only a Routeing Protocol
    norp = 1528, 'norp', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] oracle
    #: - [UDP] oracle
    coauthor = 1529, 'coauthor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rap-service
    #: - [UDP] rap-service
    rap_service = 1530, 'rap-service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rap-listen
    #: - [UDP] rap-listen
    rap_listen = 1531, 'rap-listen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] miroconnect
    #: - [UDP] miroconnect
    miroconnect = 1532, 'miroconnect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Places Software
    #: - [UDP] Virtual Places Software
    virtual_places = 1533, 'virtual-places', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] micromuse-lm
    #: - [UDP] micromuse-lm
    micromuse_lm = 1534, 'micromuse-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ampr-info
    #: - [UDP] ampr-info
    ampr_info = 1535, 'ampr-info', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ampr-inter
    #: - [UDP] ampr-inter
    ampr_inter = 1536, 'ampr-inter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isi-lm
    #: - [UDP] isi-lm
    sdsc_lm = 1537, 'sdsc-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3ds-lm
    #: - [UDP] 3ds-lm
    UDP_3ds_lm = 1538, '3ds-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intellistor License Manager
    #: - [UDP] Intellistor License Manager
    intellistor_lm = 1539, 'intellistor-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rds
    #: - [UDP] rds
    rds = 1540, 'rds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rds2
    #: - [UDP] rds2
    rds2 = 1541, 'rds2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gridgen-elmd
    #: - [UDP] gridgen-elmd
    gridgen_elmd = 1542, 'gridgen-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] simba-cs
    #: - [UDP] simba-cs
    simba_cs = 1543, 'simba-cs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] aspeclmd
    #: - [UDP] aspeclmd
    aspeclmd = 1544, 'aspeclmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vistium-share
    #: - [UDP] vistium-share
    vistium_share = 1545, 'vistium-share', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] abbaccuray
    #: - [UDP] abbaccuray
    abbaccuray = 1546, 'abbaccuray', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] laplink
    #: - [UDP] laplink
    laplink = 1547, 'laplink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Axon License Manager
    #: - [UDP] Axon License Manager
    axon_lm = 1548, 'axon-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Shiva Sound
    shivasound = 1549, 'shivasound', TransportProtocol.udp

    #: - [TCP] Image Storage license manager 3M Company
    #: - [UDP] Image Storage license manager 3M Company
    UDP_3m_image_lm = 1550, '3m-image-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HECMTL-DB
    #: - [UDP] HECMTL-DB
    hecmtl_db = 1551, 'hecmtl-db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pciarray
    #: - [UDP] pciarray
    pciarray = 1552, 'pciarray', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sna-cs
    #: - [UDP] sna-cs
    sna_cs = 1553, 'sna-cs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CACI Products Company License Manager
    #: - [UDP] CACI Products Company License Manager
    caci_lm = 1554, 'caci-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] livelan
    #: - [UDP] livelan
    livelan = 1555, 'livelan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS Private Branch Exchange IANA assigned this well-formed service
    #:   name as a replacement for "veritas_pbx".
    #: - [TCP] VERITAS Private Branch Exchange
    #: - [UDP] VERITAS Private Branch Exchange IANA assigned this well-formed service
    #:   name as a replacement for "veritas_pbx".
    #: - [UDP] VERITAS Private Branch Exchange
    veritas_pbx = 1556, 'veritas-pbx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ArborText License Manager
    #: - [UDP] ArborText License Manager
    arbortext_lm = 1557, 'arbortext-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xingmpeg
    #: - [UDP] xingmpeg
    xingmpeg = 1558, 'xingmpeg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] web2host
    #: - [UDP] web2host
    web2host = 1559, 'web2host', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASCI-RemoteSHADOW
    #: - [UDP] ASCI-RemoteSHADOW
    asci_val = 1560, 'asci-val', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] facilityview
    #: - [UDP] facilityview
    facilityview = 1561, 'facilityview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pconnectmgr
    #: - [UDP] pconnectmgr
    pconnectmgr = 1562, 'pconnectmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cadabra License Manager
    #: - [UDP] Cadabra License Manager
    cadabra_lm = 1563, 'cadabra-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pay-Per-View
    #: - [UDP] Pay-Per-View
    pay_per_view = 1564, 'pay-per-view', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WinDD
    #: - [UDP] WinDD
    winddlb = 1565, 'winddlb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CORELVIDEO
    #: - [UDP] CORELVIDEO
    corelvideo = 1566, 'corelvideo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] jlicelmd
    #: - [UDP] jlicelmd
    jlicelmd = 1567, 'jlicelmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tsspmap
    #: - [UDP] tsspmap
    tsspmap = 1568, 'tsspmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ets
    #: - [UDP] ets
    ets = 1569, 'ets', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] orbixd
    #: - [UDP] orbixd
    orbixd = 1570, 'orbixd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle Remote Data Base
    #: - [UDP] Oracle Remote Data Base
    rdb_dbs_disp = 1571, 'rdb-dbs-disp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Chipcom License Manager
    #: - [UDP] Chipcom License Manager
    chip_lm = 1572, 'chip-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] itscomm-ns
    #: - [UDP] itscomm-ns
    itscomm_ns = 1573, 'itscomm-ns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mvel-lm
    #: - [UDP] mvel-lm
    mvel_lm = 1574, 'mvel-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] oraclenames
    #: - [UDP] oraclenames
    oraclenames = 1575, 'oraclenames', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Moldflow License Manager
    #: - [UDP] Moldflow License Manager
    moldflow_lm = 1576, 'moldflow-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hypercube-lm
    #: - [UDP] hypercube-lm
    hypercube_lm = 1577, 'hypercube-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jacobus License Manager
    #: - [UDP] Jacobus License Manager
    jacobus_lm = 1578, 'jacobus-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ioc-sea-lm
    #: - [UDP] ioc-sea-lm
    ioc_sea_lm = 1579, 'ioc-sea-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] tn-tl-r2
    tn_tl_r2 = 1580, 'tn-tl-r2', TransportProtocol.udp

    #: - [TCP] MIL-2045-47001
    #: - [UDP] MIL-2045-47001
    mil_2045_47001 = 1581, 'mil-2045-47001', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSIMS
    #: - [UDP] MSIMS
    msims = 1582, 'msims', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] simbaexpress
    #: - [UDP] simbaexpress
    simbaexpress = 1583, 'simbaexpress', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tn-tl-fd2
    #: - [UDP] tn-tl-fd2
    tn_tl_fd2 = 1584, 'tn-tl-fd2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] intv
    #: - [UDP] intv
    intv = 1585, 'intv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ibm-abtact
    #: - [UDP] ibm-abtact
    ibm_abtact = 1586, 'ibm-abtact', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pra_elmd IANA assigned this well-formed service name as a replacement
    #:   for "pra_elmd".
    #: - [TCP] pra_elmd
    #: - [UDP] pra_elmd IANA assigned this well-formed service name as a replacement
    #:   for "pra_elmd".
    #: - [UDP] pra_elmd
    pra_elmd = 1587, 'pra-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] triquest-lm
    #: - [UDP] triquest-lm
    triquest_lm = 1588, 'triquest-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VQP
    #: - [UDP] VQP
    vqp = 1589, 'vqp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gemini-lm
    #: - [UDP] gemini-lm
    gemini_lm = 1590, 'gemini-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ncpm-pm
    #: - [UDP] ncpm-pm
    ncpm_pm = 1591, 'ncpm-pm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] commonspace
    #: - [UDP] commonspace
    commonspace = 1592, 'commonspace', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mainsoft-lm
    #: - [UDP] mainsoft-lm
    mainsoft_lm = 1593, 'mainsoft-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sixtrak
    #: - [UDP] sixtrak
    sixtrak = 1594, 'sixtrak', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] radio
    #: - [UDP] radio
    radio = 1595, 'radio', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] radio-bc
    radio_bc = 1596, 'radio-bc', TransportProtocol.udp

    #: - [TCP] orbplus-iiop
    #: - [UDP] orbplus-iiop
    orbplus_iiop = 1597, 'orbplus-iiop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] picknfs
    #: - [UDP] picknfs
    picknfs = 1598, 'picknfs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] simbaservices
    #: - [UDP] simbaservices
    simbaservices = 1599, 'simbaservices', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] issd
    #: - [UDP] issd
    issd = 1600, 'issd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] aas
    #: - [UDP] aas
    aas = 1601, 'aas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] inspect
    #: - [UDP] inspect
    inspect = 1602, 'inspect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pickodbc
    #: - [UDP] pickodbc
    picodbc = 1603, 'picodbc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icabrowser
    #: - [UDP] icabrowser
    icabrowser = 1604, 'icabrowser', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Salutation Manager (Salutation Protocol)
    #: - [UDP] Salutation Manager (Salutation Protocol)
    slp = 1605, 'slp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Salutation Manager (SLM-API)
    #: - [UDP] Salutation Manager (SLM-API)
    slm_api = 1606, 'slm-api', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] stt
    #: - [UDP] stt
    stt = 1607, 'stt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Smart Corp. License Manager
    #: - [UDP] Smart Corp. License Manager
    smart_lm = 1608, 'smart-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isysg-lm
    #: - [UDP] isysg-lm
    isysg_lm = 1609, 'isysg-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] taurus-wh
    #: - [UDP] taurus-wh
    taurus_wh = 1610, 'taurus-wh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inter Library Loan
    #: - [UDP] Inter Library Loan
    ill = 1611, 'ill', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetBill Transaction Server
    #: - [UDP] NetBill Transaction Server
    netbill_trans = 1612, 'netbill-trans', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetBill Key Repository
    #: - [UDP] NetBill Key Repository
    netbill_keyrep = 1613, 'netbill-keyrep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetBill Credential Server
    #: - [UDP] NetBill Credential Server
    netbill_cred = 1614, 'netbill-cred', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetBill Authorization Server
    #: - [UDP] NetBill Authorization Server
    netbill_auth = 1615, 'netbill-auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetBill Product Server
    #: - [UDP] NetBill Product Server
    netbill_prod = 1616, 'netbill-prod', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nimrod Inter-Agent Communication
    #: - [UDP] Nimrod Inter-Agent Communication
    nimrod_agent = 1617, 'nimrod-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] skytelnet
    #: - [UDP] skytelnet
    skytelnet = 1618, 'skytelnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xs-openstorage
    #: - [UDP] xs-openstorage
    xs_openstorage = 1619, 'xs-openstorage', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] faxportwinport
    #: - [UDP] faxportwinport
    faxportwinport = 1620, 'faxportwinport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] softdataphone
    #: - [UDP] softdataphone
    softdataphone = 1621, 'softdataphone', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ontime
    #: - [UDP] ontime
    ontime = 1622, 'ontime', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] jaleosnd
    #: - [UDP] jaleosnd
    jaleosnd = 1623, 'jaleosnd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] udp-sr-port
    #: - [UDP] udp-sr-port
    udp_sr_port = 1624, 'udp-sr-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] svs-omagent
    #: - [UDP] svs-omagent
    svs_omagent = 1625, 'svs-omagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Shockwave
    #: - [UDP] Shockwave
    shockwave = 1626, 'shockwave', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] T.128 Gateway
    #: - [UDP] T.128 Gateway
    t128_gateway = 1627, 't128-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LonTalk normal
    #: - [UDP] LonTalk normal
    lontalk_norm = 1628, 'lontalk-norm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LonTalk urgent
    #: - [UDP] LonTalk urgent
    lontalk_urgnt = 1629, 'lontalk-urgnt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle Net8 Cman
    #: - [UDP] Oracle Net8 Cman
    oraclenet8cman = 1630, 'oraclenet8cman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Visit view
    #: - [UDP] Visit view
    visitview = 1631, 'visitview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PAMMRATC
    #: - [UDP] PAMMRATC
    pammratc = 1632, 'pammratc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PAMMRPC
    #: - [UDP] PAMMRPC
    pammrpc = 1633, 'pammrpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Log On America Probe
    #: - [UDP] Log On America Probe
    loaprobe = 1634, 'loaprobe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EDB Server 1
    #: - [UDP] EDB Server 1
    edb_server1 = 1635, 'edb-server1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISP shared public data control
    #: - [UDP] ISP shared public data control
    isdc = 1636, 'isdc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISP shared local data control
    #: - [UDP] ISP shared local data control
    islc = 1637, 'islc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISP shared management control
    #: - [UDP] ISP shared management control
    ismc = 1638, 'ismc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cert-initiator
    #: - [UDP] cert-initiator
    cert_initiator = 1639, 'cert-initiator', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cert-responder
    #: - [UDP] cert-responder
    cert_responder = 1640, 'cert-responder', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] InVision
    #: - [UDP] InVision
    invision = 1641, 'invision', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isis-am
    #: - [UDP] isis-am
    isis_am = 1642, 'isis-am', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isis-ambc
    #: - [UDP] isis-ambc
    isis_ambc = 1643, 'isis-ambc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Satellite-data Acquisition System 4
    #: - [UDP] Satellite-data Acquisition System 4
    saiseh = 1644, 'saiseh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SightLine
    #: - [UDP] SightLine
    sightline = 1645, 'sightline', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sa-msg-port
    #: - [UDP] sa-msg-port
    sa_msg_port = 1646, 'sa-msg-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rsap
    #: - [UDP] rsap
    rsap = 1647, 'rsap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] concurrent-lm
    #: - [UDP] concurrent-lm
    concurrent_lm = 1648, 'concurrent-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] kermit
    #: - [UDP] kermit
    kermit = 1649, 'kermit', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nkdn
    #: - [UDP] nkd
    nkd = 1650, 'nkd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] shiva_confsrvr IANA assigned this well-formed service name as a
    #:   replacement for "shiva_confsrvr".
    #: - [TCP] shiva_confsrvr
    #: - [UDP] shiva_confsrvr IANA assigned this well-formed service name as a
    #:   replacement for "shiva_confsrvr".
    #: - [UDP] shiva_confsrvr
    shiva_confsrvr = 1651, 'shiva-confsrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xnmp
    #: - [UDP] xnmp
    xnmp = 1652, 'xnmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] alphatech-lm
    #: - [UDP] alphatech-lm
    alphatech_lm = 1653, 'alphatech-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] stargatealerts
    #: - [UDP] stargatealerts
    stargatealerts = 1654, 'stargatealerts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dec-mbadmin
    #: - [UDP] dec-mbadmin
    dec_mbadmin = 1655, 'dec-mbadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dec-mbadmin-h
    #: - [UDP] dec-mbadmin-h
    dec_mbadmin_h = 1656, 'dec-mbadmin-h', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fujitsu-mmpdc
    #: - [UDP] fujitsu-mmpdc
    fujitsu_mmpdc = 1657, 'fujitsu-mmpdc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sixnetudr
    #: - [UDP] sixnetudr
    sixnetudr = 1658, 'sixnetudr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Silicon Grail License Manager
    #: - [UDP] Silicon Grail License Manager
    sg_lm = 1659, 'sg-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] skip-mc-gikreq
    #: - [UDP] skip-mc-gikreq
    skip_mc_gikreq = 1660, 'skip-mc-gikreq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-1
    #: - [UDP] netview-aix-1
    netview_aix_1 = 1661, 'netview-aix-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-2
    #: - [UDP] netview-aix-2
    netview_aix_2 = 1662, 'netview-aix-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-3
    #: - [UDP] netview-aix-3
    netview_aix_3 = 1663, 'netview-aix-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-4
    #: - [UDP] netview-aix-4
    netview_aix_4 = 1664, 'netview-aix-4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-5
    #: - [UDP] netview-aix-5
    netview_aix_5 = 1665, 'netview-aix-5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-6
    #: - [UDP] netview-aix-6
    netview_aix_6 = 1666, 'netview-aix-6', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-7
    #: - [UDP] netview-aix-7
    netview_aix_7 = 1667, 'netview-aix-7', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-8
    #: - [UDP] netview-aix-8
    netview_aix_8 = 1668, 'netview-aix-8', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-9
    #: - [UDP] netview-aix-9
    netview_aix_9 = 1669, 'netview-aix-9', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-10
    #: - [UDP] netview-aix-10
    netview_aix_10 = 1670, 'netview-aix-10', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-11
    #: - [UDP] netview-aix-11
    netview_aix_11 = 1671, 'netview-aix-11', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netview-aix-12
    #: - [UDP] netview-aix-12
    netview_aix_12 = 1672, 'netview-aix-12', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intel Proshare Multicast
    #: - [UDP] Intel Proshare Multicast
    proshare_mc_1 = 1673, 'proshare-mc-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intel Proshare Multicast
    #: - [UDP] Intel Proshare Multicast
    proshare_mc_2 = 1674, 'proshare-mc-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pacific Data Products
    #: - [UDP] Pacific Data Products
    pdp = 1675, 'pdp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] netcomm2
    netcomm2 = 1676, 'netcomm2', TransportProtocol.udp

    #: - [TCP] groupwise
    #: - [UDP] groupwise
    groupwise = 1677, 'groupwise', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] prolink
    #: - [UDP] prolink
    prolink = 1678, 'prolink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] darcorp-lm
    #: - [UDP] darcorp-lm
    darcorp_lm = 1679, 'darcorp-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] microcom-sbp
    #: - [UDP] microcom-sbp
    microcom_sbp = 1680, 'microcom-sbp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sd-elmd
    #: - [UDP] sd-elmd
    sd_elmd = 1681, 'sd-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] lanyon-lantern
    #: - [UDP] lanyon-lantern
    lanyon_lantern = 1682, 'lanyon-lantern', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ncpm-hip
    #: - [UDP] ncpm-hip
    ncpm_hip = 1683, 'ncpm-hip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SnareSecure
    #: - [UDP] SnareSecure
    snaresecure = 1684, 'snaresecure', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] n2nremote
    #: - [UDP] n2nremote
    n2nremote = 1685, 'n2nremote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cvmon
    #: - [UDP] cvmon
    cvmon = 1686, 'cvmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nsjtp-ctrl
    #: - [UDP] nsjtp-ctrl
    nsjtp_ctrl = 1687, 'nsjtp-ctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nsjtp-data
    #: - [UDP] nsjtp-data
    nsjtp_data = 1688, 'nsjtp-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] firefox
    #: - [UDP] firefox
    firefox = 1689, 'firefox', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ng-umds
    #: - [UDP] ng-umds
    ng_umds = 1690, 'ng-umds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] empire-empuma
    #: - [UDP] empire-empuma
    empire_empuma = 1691, 'empire-empuma', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sstsys-lm
    #: - [UDP] sstsys-lm
    sstsys_lm = 1692, 'sstsys-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rrirtr
    #: - [UDP] rrirtr
    rrirtr = 1693, 'rrirtr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rrimwm
    #: - [UDP] rrimwm
    rrimwm = 1694, 'rrimwm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rrilwm
    #: - [UDP] rrilwm
    rrilwm = 1695, 'rrilwm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rrifmm
    #: - [UDP] rrifmm
    rrifmm = 1696, 'rrifmm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rrisat
    #: - [UDP] rrisat
    rrisat = 1697, 'rrisat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSVP-ENCAPSULATION-1
    #: - [UDP] RSVP-ENCAPSULATION-1
    rsvp_encap_1 = 1698, 'rsvp-encap-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSVP-ENCAPSULATION-2
    #: - [UDP] RSVP-ENCAPSULATION-2
    rsvp_encap_2 = 1699, 'rsvp-encap-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mps-raft
    #: - [UDP] mps-raft
    mps_raft = 1700, 'mps-raft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] l2f
    #: - [UDP] l2f
    l2f = 1701, 'l2f', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] l2tp
    #: - [UDP] l2tp
    l2tp = 1701, 'l2tp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] deskshare
    #: - [UDP] deskshare
    deskshare = 1702, 'deskshare', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hb-engine
    #: - [UDP] hb-engine
    hb_engine = 1703, 'hb-engine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bcs-broker
    #: - [UDP] bcs-broker
    bcs_broker = 1704, 'bcs-broker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] slingshot
    #: - [UDP] slingshot
    slingshot = 1705, 'slingshot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] jetform
    #: - [UDP] jetform
    jetform = 1706, 'jetform', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vdmplay
    #: - [UDP] vdmplay
    vdmplay = 1707, 'vdmplay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gat-lmd
    #: - [UDP] gat-lmd
    gat_lmd = 1708, 'gat-lmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] centra
    #: - [UDP] centra
    centra = 1709, 'centra', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] impera
    #: - [UDP] impera
    impera = 1710, 'impera', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pptconference
    #: - [UDP] pptconference
    pptconference = 1711, 'pptconference', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] resource monitoring service
    #: - [UDP] resource monitoring service
    registrar = 1712, 'registrar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ConferenceTalk
    #: - [UDP] ConferenceTalk
    conferencetalk = 1713, 'conferencetalk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sesi-lm
    #: - [UDP] sesi-lm
    sesi_lm = 1714, 'sesi-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] houdini-lm
    #: - [UDP] houdini-lm
    houdini_lm = 1715, 'houdini-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xmsg
    #: - [UDP] xmsg
    xmsg = 1716, 'xmsg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fj-hdnet
    #: - [UDP] fj-hdnet
    fj_hdnet = 1717, 'fj-hdnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] H.323 Multicast Gatekeeper Discover
    #: - [UDP] H.323 Multicast Gatekeeper Discover
    h323gatedisc = 1718, 'h323gatedisc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] H.323 Unicast Gatekeeper Signaling
    #: - [UDP] H.323 Unicast Gatekeeper Signaling
    h323gatestat = 1719, 'h323gatestat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] H.323 Call Control Signalling
    #: - [UDP] H.323 Call Control Signalling
    #: - [SCTP] H.323 Call Control
    h323hostcall = 1720, 'h323hostcall', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] caicci
    #: - [UDP] caicci
    caicci = 1721, 'caicci', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HKS License Manager
    #: - [UDP] HKS License Manager
    hks_lm = 1722, 'hks-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pptp [:rfc:`2637`]
    #: - [UDP] pptp [:rfc:`2637`]
    pptp = 1723, 'pptp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] csbphonemaster
    #: - [UDP] csbphonemaster
    csbphonemaster = 1724, 'csbphonemaster', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iden-ralp
    #: - [UDP] iden-ralp
    iden_ralp = 1725, 'iden-ralp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBERIAGAMES
    #: - [UDP] IBERIAGAMES
    iberiagames = 1726, 'iberiagames', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] winddx
    #: - [UDP] winddx
    winddx = 1727, 'winddx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TELINDUS
    #: - [UDP] TELINDUS
    telindus = 1728, 'telindus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CityNL License Management
    #: - [UDP] CityNL License Management
    citynl = 1729, 'citynl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] roketz
    #: - [UDP] roketz
    roketz = 1730, 'roketz', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSICCP
    #: - [UDP] MSICCP
    msiccp = 1731, 'msiccp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] proxim
    #: - [UDP] proxim
    proxim = 1732, 'proxim', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SIMS - SIIPAT Protocol for Alarm Transmission
    #: - [UDP] SIMS - SIIPAT Protocol for Alarm Transmission
    siipat = 1733, 'siipat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Camber Corporation License Management
    #: - [UDP] Camber Corporation License Management
    cambertx_lm = 1734, 'cambertx-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PrivateChat
    #: - [UDP] PrivateChat
    privatechat = 1735, 'privatechat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] street-stream
    #: - [UDP] street-stream
    street_stream = 1736, 'street-stream', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ultimad
    #: - [UDP] ultimad
    ultimad = 1737, 'ultimad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GameGen1
    #: - [UDP] GameGen1
    gamegen1 = 1738, 'gamegen1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] webaccess
    #: - [UDP] webaccess
    webaccess = 1739, 'webaccess', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] encore
    #: - [UDP] encore
    encore = 1740, 'encore', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco-net-mgmt
    #: - [UDP] cisco-net-mgmt
    cisco_net_mgmt = 1741, 'cisco-net-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3Com-nsd
    #: - [UDP] 3Com-nsd
    UDP_3com_nsd = 1742, '3com-nsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cinema Graphics License Manager
    #: - [UDP] Cinema Graphics License Manager
    cinegrfx_lm = 1743, 'cinegrfx-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ncpm-ft
    #: - [UDP] ncpm-ft
    ncpm_ft = 1744, 'ncpm-ft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] remote-winsock
    #: - [UDP] remote-winsock
    remote_winsock = 1745, 'remote-winsock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ftrapid-1
    #: - [UDP] ftrapid-1
    ftrapid_1 = 1746, 'ftrapid-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ftrapid-2
    #: - [UDP] ftrapid-2
    ftrapid_2 = 1747, 'ftrapid-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] oracle-em1
    #: - [UDP] oracle-em1
    oracle_em1 = 1748, 'oracle-em1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] aspen-services
    #: - [UDP] aspen-services
    aspen_services = 1749, 'aspen-services', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Socket Library's PortMaster
    #: - [UDP] Simple Socket Library's PortMaster
    sslp = 1750, 'sslp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SwiftNet
    #: - [UDP] SwiftNet
    swiftnet = 1751, 'swiftnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Leap of Faith Research License Manager
    #: - [UDP] Leap of Faith Research License Manager
    lofr_lm = 1752, 'lofr-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_1753 = 1753, 'reserved', TransportProtocol.udp

    #: - [TCP] oracle-em2
    #: - [UDP] oracle-em2
    oracle_em2 = 1754, 'oracle-em2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ms-streaming
    #: - [UDP] ms-streaming
    ms_streaming = 1755, 'ms-streaming', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] capfast-lmd
    #: - [UDP] capfast-lmd
    capfast_lmd = 1756, 'capfast-lmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cnhrp
    #: - [UDP] cnhrp
    cnhrp = 1757, 'cnhrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tftp-mcast
    #: - [UDP] tftp-mcast
    tftp_mcast = 1758, 'tftp-mcast', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPSS License Manager
    #: - [UDP] SPSS License Manager
    spss_lm = 1759, 'spss-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] www-ldap-gw
    #: - [UDP] www-ldap-gw
    www_ldap_gw = 1760, 'www-ldap-gw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cft-0
    #: - [UDP] cft-0
    cft_0 = 1761, 'cft-0', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cft-1
    #: - [UDP] cft-1
    cft_1 = 1762, 'cft-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cft-2
    #: - [UDP] cft-2
    cft_2 = 1763, 'cft-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cft-3
    #: - [UDP] cft-3
    cft_3 = 1764, 'cft-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cft-4
    #: - [UDP] cft-4
    cft_4 = 1765, 'cft-4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cft-5
    #: - [UDP] cft-5
    cft_5 = 1766, 'cft-5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cft-6
    #: - [UDP] cft-6
    cft_6 = 1767, 'cft-6', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cft-7
    #: - [UDP] cft-7
    cft_7 = 1768, 'cft-7', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bmc-net-adm
    #: - [UDP] bmc-net-adm
    bmc_net_adm = 1769, 'bmc-net-adm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bmc-net-svc
    #: - [UDP] bmc-net-svc
    bmc_net_svc = 1770, 'bmc-net-svc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vaultbase
    #: - [UDP] vaultbase
    vaultbase = 1771, 'vaultbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EssWeb Gateway
    #: - [UDP] EssWeb Gateway
    essweb_gw = 1772, 'essweb-gw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KMSControl
    #: - [UDP] KMSControl
    kmscontrol = 1773, 'kmscontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] global-dtserv
    #: - [UDP] global-dtserv
    global_dtserv = 1774, 'global-dtserv', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_1775 = 1775, 'reserved', TransportProtocol.udp

    #: - [TCP] Federal Emergency Management Information System
    #: - [UDP] Federal Emergency Management Information System
    femis = 1776, 'femis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] powerguardian
    #: - [UDP] powerguardian
    powerguardian = 1777, 'powerguardian', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] prodigy-internet
    #: - [UDP] prodigy-internet
    prodigy_intrnet = 1778, 'prodigy-intrnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pharmasoft
    #: - [UDP] pharmasoft
    pharmasoft = 1779, 'pharmasoft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dpkeyserv
    #: - [UDP] dpkeyserv
    dpkeyserv = 1780, 'dpkeyserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] answersoft-lm
    #: - [UDP] answersoft-lm
    answersoft_lm = 1781, 'answersoft-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp-hcip
    #: - [UDP] hp-hcip
    hp_hcip = 1782, 'hp-hcip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Finle License Manager
    #: - [UDP] Finle License Manager
    finle_lm = 1784, 'finle-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wind River Systems License Manager
    #: - [UDP] Wind River Systems License Manager
    windlm = 1785, 'windlm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] funk-logger
    #: - [UDP] funk-logger
    funk_logger = 1786, 'funk-logger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] funk-license
    #: - [UDP] funk-license
    funk_license = 1787, 'funk-license', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] psmond
    #: - [UDP] psmond
    psmond = 1788, 'psmond', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hello
    #: - [UDP] hello
    hello = 1789, 'hello', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Networked Media Streaming Protocol
    #: - [UDP] Networked Media Streaming Protocol
    nmsp_537 = 537, 'nmsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Narrative Media Streaming Protocol
    #: - [UDP] Narrative Media Streaming Protocol
    nmsp_1790 = 1790, 'nmsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EA1
    #: - [UDP] EA1
    ea1 = 1791, 'ea1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ibm-dt-2
    #: - [UDP] ibm-dt-2
    ibm_dt_2 = 1792, 'ibm-dt-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rsc-robot
    #: - [UDP] rsc-robot
    rsc_robot = 1793, 'rsc-robot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cera-bcm
    #: - [UDP] cera-bcm
    cera_bcm = 1794, 'cera-bcm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dpi-proxy
    #: - [UDP] dpi-proxy
    dpi_proxy = 1795, 'dpi-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vocaltec Server Administration
    #: - [UDP] Vocaltec Server Administration
    vocaltec_admin = 1796, 'vocaltec-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Universal Management Architecture
    #: - [UDP] Universal Management Architecture
    uma_144 = 144, 'uma', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UMA
    #: - [UDP] UMA
    uma_1797 = 1797, 'uma', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Event Transfer Protocol
    #: - [UDP] Event Transfer Protocol
    etp = 1798, 'etp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETRISK
    #: - [UDP] NETRISK
    netrisk = 1799, 'netrisk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ANSYS-License manager
    #: - [UDP] ANSYS-License manager
    ansys_lm = 1800, 'ansys-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Message Que
    #: - [UDP] Microsoft Message Que
    msmq = 1801, 'msmq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ConComp1
    #: - [UDP] ConComp1
    concomp1 = 1802, 'concomp1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP-HCIP-GWY
    #: - [UDP] HP-HCIP-GWY
    hp_hcip_gwy = 1803, 'hp-hcip-gwy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ENL
    #: - [UDP] ENL
    enl = 1804, 'enl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ENL-Name
    #: - [UDP] ENL-Name
    enl_name = 1805, 'enl-name', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Musiconline
    #: - [UDP] Musiconline
    musiconline = 1806, 'musiconline', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Hot Standby Protocol
    #: - [UDP] Fujitsu Hot Standby Protocol
    fhsp = 1807, 'fhsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle-VP2
    #: - [UDP] Oracle-VP2
    oracle_vp2 = 1808, 'oracle-vp2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle-VP1
    #: - [UDP] Oracle-VP1
    oracle_vp1 = 1809, 'oracle-vp1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jerand License Manager
    #: - [UDP] Jerand License Manager
    jerand_lm = 1810, 'jerand-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Scientia-SDB
    #: - [UDP] Scientia-SDB
    scientia_sdb = 1811, 'scientia-sdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RADIUS [:rfc:`2865`]
    #: - [UDP] RADIUS [:rfc:`2865`]
    radius = 1812, 'radius', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RADIUS Accounting [:rfc:`2866`]
    #: - [UDP] RADIUS Accounting [:rfc:`2866`]
    radius_acct = 1813, 'radius-acct', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TDP Suite
    #: - [UDP] TDP Suite
    tdp_suite = 1814, 'tdp-suite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Manufacturing messaging protocol for factory transmission
    #: - [UDP] Manufacturing messaging protocol for factory transmission
    mmpft = 1815, 'mmpft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HARP
    #: - [UDP] HARP
    harp = 1816, 'harp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RKB-OSCS
    #: - [UDP] RKB-OSCS
    rkb_oscs = 1817, 'rkb-oscs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Enhanced Trivial File Transfer Protocol
    #: - [UDP] Enhanced Trivial File Transfer Protocol
    etftp = 1818, 'etftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Plato License Manager
    #: - [UDP] Plato License Manager
    plato_lm = 1819, 'plato-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mcagent
    #: - [UDP] mcagent
    mcagent = 1820, 'mcagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] donnyworld
    #: - [UDP] donnyworld
    donnyworld = 1821, 'donnyworld', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] es-elmd
    #: - [UDP] es-elmd
    es_elmd = 1822, 'es-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unisys Natural Language License Manager
    #: - [UDP] Unisys Natural Language License Manager
    unisys_lm = 1823, 'unisys-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] metrics-pas
    #: - [UDP] metrics-pas
    metrics_pas = 1824, 'metrics-pas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DirecPC Video
    #: - [UDP] DirecPC Video
    direcpc_video = 1825, 'direcpc-video', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARDT
    #: - [UDP] ARDT
    ardt = 1826, 'ardt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASI
    #: - [UDP] ASI
    asi = 1827, 'asi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] itm-mcell-u
    #: - [UDP] itm-mcell-u
    itm_mcell_u = 1828, 'itm-mcell-u', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Optika eMedia
    #: - [UDP] Optika eMedia
    optika_emedia = 1829, 'optika-emedia', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle Net8 CMan Admin
    #: - [UDP] Oracle Net8 CMan Admin
    net8_cman = 1830, 'net8-cman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Myrtle
    #: - [UDP] Myrtle
    myrtle = 1831, 'myrtle', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ThoughtTreasure
    #: - [UDP] ThoughtTreasure
    tht_treasure = 1832, 'tht-treasure', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] udpradio
    #: - [UDP] udpradio
    udpradio = 1833, 'udpradio', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARDUS Unicast
    #: - [UDP] ARDUS Unicast
    ardusuni = 1834, 'ardusuni', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARDUS Multicast
    #: - [UDP] ARDUS Multicast
    ardusmul = 1835, 'ardusmul', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ste-smsc
    #: - [UDP] ste-smsc
    ste_smsc = 1836, 'ste-smsc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] csoft1
    #: - [UDP] csoft1
    csoft1 = 1837, 'csoft1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TALNET
    #: - [UDP] TALNET
    talnet = 1838, 'talnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netopia-vo1
    #: - [UDP] netopia-vo1
    netopia_vo1 = 1839, 'netopia-vo1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netopia-vo2
    #: - [UDP] netopia-vo2
    netopia_vo2 = 1840, 'netopia-vo2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netopia-vo3
    #: - [UDP] netopia-vo3
    netopia_vo3 = 1841, 'netopia-vo3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netopia-vo4
    #: - [UDP] netopia-vo4
    netopia_vo4 = 1842, 'netopia-vo4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netopia-vo5
    #: - [UDP] netopia-vo5
    netopia_vo5 = 1843, 'netopia-vo5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DirecPC-DLL
    #: - [UDP] DirecPC-DLL
    direcpc_dll = 1844, 'direcpc-dll', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] altalink
    #: - [UDP] altalink
    altalink = 1845, 'altalink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tunstall PNC
    #: - [UDP] Tunstall PNC
    tunstall_pnc = 1846, 'tunstall-pnc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SLP Notification [:rfc:`3082`]
    #: - [UDP] SLP Notification [:rfc:`3082`]
    slp_notify = 1847, 'slp-notify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fjdocdist
    #: - [UDP] fjdocdist
    fjdocdist = 1848, 'fjdocdist', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ALPHA-SMS
    #: - [UDP] ALPHA-SMS
    alpha_sms = 1849, 'alpha-sms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GSI
    #: - [UDP] GSI
    gsi = 1850, 'gsi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ctcd
    #: - [UDP] ctcd
    ctcd = 1851, 'ctcd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Time
    #: - [UDP] Virtual Time
    virtual_time = 1852, 'virtual-time', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VIDS-AVTP
    #: - [UDP] VIDS-AVTP
    vids_avtp = 1853, 'vids-avtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Buddy Draw
    #: - [UDP] Buddy Draw
    buddy_draw = 1854, 'buddy-draw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fiorano RtrSvc
    #: - [UDP] Fiorano RtrSvc
    fiorano_rtrsvc = 1855, 'fiorano-rtrsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fiorano MsgSvc
    #: - [UDP] Fiorano MsgSvc
    fiorano_msgsvc = 1856, 'fiorano-msgsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DataCaptor
    #: - [UDP] DataCaptor
    datacaptor = 1857, 'datacaptor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PrivateArk
    #: - [UDP] PrivateArk
    privateark = 1858, 'privateark', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gamma Fetcher Server
    #: - [UDP] Gamma Fetcher Server
    gammafetchsvr = 1859, 'gammafetchsvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SunSCALAR Services
    #: - [UDP] SunSCALAR Services
    sunscalar_svc = 1860, 'sunscalar-svc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LeCroy VICP
    #: - [UDP] LeCroy VICP
    lecroy_vicp = 1861, 'lecroy-vicp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MySQL Cluster Manager Agent
    #: - [UDP] MySQL Cluster Manager Agent
    mysql_cm_agent = 1862, 'mysql-cm-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSNP
    #: - [UDP] MSNP
    msnp = 1863, 'msnp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Paradym 31 Port
    #: - [UDP] Paradym 31 Port
    paradym_31port = 1864, 'paradym-31port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ENTP
    #: - [UDP] ENTP
    entp = 1865, 'entp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] swrmi
    #: - [UDP] swrmi
    swrmi = 1866, 'swrmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UDRIVE
    #: - [UDP] UDRIVE
    udrive = 1867, 'udrive', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VizibleBrowser
    #: - [UDP] VizibleBrowser
    viziblebrowser = 1868, 'viziblebrowser', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TransAct
    #: - [UDP] TransAct
    transact = 1869, 'transact', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SunSCALAR DNS Service
    #: - [UDP] SunSCALAR DNS Service
    sunscalar_dns = 1870, 'sunscalar-dns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cano Central 0
    #: - [UDP] Cano Central 0
    canocentral0 = 1871, 'canocentral0', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cano Central 1
    #: - [UDP] Cano Central 1
    canocentral1 = 1872, 'canocentral1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fjmpjps
    #: - [UDP] Fjmpjps
    fjmpjps = 1873, 'fjmpjps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fjswapsnp
    #: - [UDP] Fjswapsnp
    fjswapsnp = 1874, 'fjswapsnp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] westell stats
    #: - [UDP] westell stats
    westell_stats = 1875, 'westell-stats', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ewcappsrv
    #: - [UDP] ewcappsrv
    ewcappsrv = 1876, 'ewcappsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp-webqosdb
    #: - [UDP] hp-webqosdb
    hp_webqosdb = 1877, 'hp-webqosdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] drmsmc
    #: - [UDP] drmsmc
    drmsmc = 1878, 'drmsmc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NettGain NMS
    #: - [UDP] NettGain NMS
    nettgain_nms = 1879, 'nettgain-nms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gilat VSAT Control
    #: - [UDP] Gilat VSAT Control
    vsat_control = 1880, 'vsat-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM WebSphere MQ Everyplace
    #: - [UDP] IBM WebSphere MQ Everyplace
    ibm_mqseries2 = 1881, 'ibm-mqseries2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA eTrust Common Services
    #: - [UDP] CA eTrust Common Services
    ecsqdmn = 1882, 'ecsqdmn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Internet Distance Map Svc
    #: - [UDP] Internet Distance Map Svc
    idmaps = 1884, 'idmaps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Veritas Trap Server
    #: - [UDP] Veritas Trap Server
    vrtstrapserver = 1885, 'vrtstrapserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Leonardo over IP
    #: - [UDP] Leonardo over IP
    leoip = 1886, 'leoip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileX Listening Port
    #: - [UDP] FileX Listening Port
    filex_lport = 1887, 'filex-lport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NC Config Port
    #: - [UDP] NC Config Port
    ncconfig = 1888, 'ncconfig', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unify Web Adapter Service
    #: - [UDP] Unify Web Adapter Service
    unify_adapter = 1889, 'unify-adapter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] wilkenListener
    #: - [UDP] wilkenListener
    wilkenlistener = 1890, 'wilkenlistener', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ChildKey Notification
    #: - [UDP] ChildKey Notification
    childkey_notif = 1891, 'childkey-notif', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ChildKey Control
    #: - [UDP] ChildKey Control
    childkey_ctrl = 1892, 'childkey-ctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ELAD Protocol
    #: - [UDP] ELAD Protocol
    elad = 1893, 'elad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] O2Server Port
    #: - [UDP] O2Server Port
    o2server_port = 1894, 'o2server-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] unassigned
    #: - [UDP] unassigned
    unassigned_1895 = 1895, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] b-novative license server
    #: - [UDP] b-novative license server
    b_novative_ls = 1896, 'b-novative-ls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MetaAgent
    #: - [UDP] MetaAgent
    metaagent = 1897, 'metaagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cymtec secure management
    #: - [UDP] Cymtec secure management
    cymtec_port = 1898, 'cymtec-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MC2Studios
    #: - [UDP] MC2Studios
    mc2studios = 1899, 'mc2studios', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSDP
    #: - [UDP] SSDP
    ssdp = 1900, 'ssdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu ICL Terminal Emulator Program A
    #: - [UDP] Fujitsu ICL Terminal Emulator Program A
    fjicl_tep_a = 1901, 'fjicl-tep-a', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu ICL Terminal Emulator Program B
    #: - [UDP] Fujitsu ICL Terminal Emulator Program B
    fjicl_tep_b = 1902, 'fjicl-tep-b', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Local Link Name Resolution
    #: - [UDP] Local Link Name Resolution
    linkname = 1903, 'linkname', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu ICL Terminal Emulator Program C
    #: - [UDP] Fujitsu ICL Terminal Emulator Program C
    fjicl_tep_c = 1904, 'fjicl-tep-c', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure UP.Link Gateway Protocol
    #: - [UDP] Secure UP.Link Gateway Protocol
    sugp = 1905, 'sugp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TPortMapperReq
    #: - [UDP] TPortMapperReq
    tpmd = 1906, 'tpmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IntraSTAR
    #: - [UDP] IntraSTAR
    intrastar = 1907, 'intrastar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dawn
    #: - [UDP] Dawn
    dawn = 1908, 'dawn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Global World Link
    #: - [UDP] Global World Link
    global_wlink = 1909, 'global-wlink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UltraBac Software communications port
    #: - [UDP] UltraBac Software communications port
    ultrabac = 1910, 'ultrabac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Starlight Networks Multimedia Transport Protocol
    #: - [UDP] Starlight Networks Multimedia Transport Protocol
    mtp = 1911, 'mtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rhp-iibp
    #: - [UDP] rhp-iibp
    rhp_iibp = 1912, 'rhp-iibp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] armadp
    #: - [UDP] armadp
    armadp = 1913, 'armadp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Elm-Momentum
    #: - [UDP] Elm-Momentum
    elm_momentum = 1914, 'elm-momentum', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FACELINK
    #: - [UDP] FACELINK
    facelink = 1915, 'facelink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Persoft Persona
    #: - [UDP] Persoft Persona
    persona = 1916, 'persona', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nOAgent
    #: - [UDP] nOAgent
    noagent = 1917, 'noagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Tivole Directory Service - NDS
    #: - [UDP] IBM Tivole Directory Service - NDS
    can_nds = 1918, 'can-nds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Tivoli Directory Service - DCH
    #: - [UDP] IBM Tivoli Directory Service - DCH
    can_dch = 1919, 'can-dch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Tivoli Directory Service - FERRET
    #: - [UDP] IBM Tivoli Directory Service - FERRET
    can_ferret = 1920, 'can-ferret', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NoAdmin
    #: - [UDP] NoAdmin
    noadmin = 1921, 'noadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tapestry
    #: - [UDP] Tapestry
    tapestry = 1922, 'tapestry', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPICE
    #: - [UDP] SPICE
    spice = 1923, 'spice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XIIP
    #: - [UDP] XIIP
    xiip = 1924, 'xiip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Surrogate Discovery Port
    #: - [UDP] Surrogate Discovery Port
    discovery_port = 1925, 'discovery-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Evolution Game Server
    #: - [UDP] Evolution Game Server
    egs = 1926, 'egs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Videte CIPC Port
    #: - [UDP] Videte CIPC Port
    videte_cipc = 1927, 'videte-cipc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Expnd Maui Srvr Dscovr
    #: - [UDP] Expnd Maui Srvr Dscovr
    emsd_port = 1928, 'emsd-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bandwiz System - Server
    #: - [UDP] Bandwiz System - Server
    bandwiz_system = 1929, 'bandwiz-system', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Drive AppServer
    #: - [UDP] Drive AppServer
    driveappserver = 1930, 'driveappserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMD SCHED
    #: - [UDP] AMD SCHED
    amdsched = 1931, 'amdsched', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CTT Broker
    #: - [UDP] CTT Broker
    ctt_broker = 1932, 'ctt-broker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM LM MT Agent
    #: - [UDP] IBM LM MT Agent
    xmapi = 1933, 'xmapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM LM Appl Agent
    #: - [UDP] IBM LM Appl Agent
    xaapi = 1934, 'xaapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Macromedia Flash Communications Server MX
    #: - [UDP] Macromedia Flash Communications server MX
    macromedia_fcs = 1935, 'macromedia-fcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JetCmeServer Server Port
    #: - [UDP] JetCmeServer Server Port
    jetcmeserver = 1936, 'jetcmeserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JetVWay Server Port
    #: - [UDP] JetVWay Server Port
    jwserver = 1937, 'jwserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JetVWay Client Port
    #: - [UDP] JetVWay Client Port
    jwclient = 1938, 'jwclient', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JetVision Server Port
    #: - [UDP] JetVision Server Port
    jvserver = 1939, 'jvserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JetVision Client Port
    #: - [UDP] JetVision Client Port
    jvclient = 1940, 'jvclient', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DIC-Aida
    #: - [UDP] DIC-Aida
    dic_aida = 1941, 'dic-aida', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Real Enterprise Service
    #: - [UDP] Real Enterprise Service
    res = 1942, 'res', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Beeyond Media
    #: - [UDP] Beeyond Media
    beeyond_media = 1943, 'beeyond-media', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] close-combat
    #: - [UDP] close-combat
    close_combat = 1944, 'close-combat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dialogic-elmd
    #: - [UDP] dialogic-elmd
    dialogic_elmd = 1945, 'dialogic-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tekpls
    #: - [UDP] tekpls
    tekpls = 1946, 'tekpls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SentinelSRM
    #: - [UDP] SentinelSRM
    sentinelsrm = 1947, 'sentinelsrm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eye2eye
    #: - [UDP] eye2eye
    eye2eye = 1948, 'eye2eye', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISMA Easdaq Live
    #: - [UDP] ISMA Easdaq Live
    ismaeasdaqlive = 1949, 'ismaeasdaqlive', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISMA Easdaq Test
    #: - [UDP] ISMA Easdaq Test
    ismaeasdaqtest = 1950, 'ismaeasdaqtest', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bcs-lmserver
    #: - [UDP] bcs-lmserver
    bcs_lmserver = 1951, 'bcs-lmserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mpnjsc
    #: - [UDP] mpnjsc
    mpnjsc = 1952, 'mpnjsc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rapid Base
    #: - [UDP] Rapid Base
    rapidbase = 1953, 'rapidbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ABR-API (diskbridge)
    #: - [UDP] ABR-API (diskbridge)
    abr_api = 1954, 'abr-api', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ABR-Secure Data (diskbridge)
    #: - [UDP] ABR-Secure Data (diskbridge)
    abr_secure = 1955, 'abr-secure', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vertel VMF DS
    #: - [UDP] Vertel VMF DS
    vrtl_vmf_ds = 1956, 'vrtl-vmf-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] unix-status
    #: - [UDP] unix-status
    unix_status = 1957, 'unix-status', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA Administration Daemon
    #: - [UDP] CA Administration Daemon
    dxadmind = 1958, 'dxadmind', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SIMP Channel
    #: - [UDP] SIMP Channel
    simp_all = 1959, 'simp-all', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Merit DAC NASmanager
    #: - [UDP] Merit DAC NASmanager
    nasmanager = 1960, 'nasmanager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BTS APPSERVER
    #: - [UDP] BTS APPSERVER
    bts_appserver = 1961, 'bts-appserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BIAP-MP
    #: - [UDP] BIAP-MP
    biap_mp = 1962, 'biap-mp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WebMachine
    #: - [UDP] WebMachine
    webmachine = 1963, 'webmachine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SOLID E ENGINE
    #: - [UDP] SOLID E ENGINE
    solid_e_engine = 1964, 'solid-e-engine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tivoli NPM
    #: - [UDP] Tivoli NPM
    tivoli_npm = 1965, 'tivoli-npm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Slush
    #: - [UDP] Slush
    slush = 1966, 'slush', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNS Quote
    #: - [UDP] SNS Quote
    sns_quote = 1967, 'sns-quote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LIPSinc
    #: - [UDP] LIPSinc
    lipsinc = 1968, 'lipsinc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LIPSinc 1
    #: - [UDP] LIPSinc 1
    lipsinc1 = 1969, 'lipsinc1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetOp Remote Control
    #: - [UDP] NetOp Remote Control
    netop_rc = 1970, 'netop-rc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetOp School
    #: - [UDP] NetOp School
    netop_school = 1971, 'netop-school', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cache
    #: - [UDP] Cache
    intersys_cache = 1972, 'intersys-cache', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Link Switching Remote Access Protocol
    #: - [UDP] Data Link Switching Remote Access Protocol
    dlsrap = 1973, 'dlsrap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DRP
    #: - [UDP] DRP
    drp = 1974, 'drp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TCO Flash Agent
    #: - [UDP] TCO Flash Agent
    tcoflashagent = 1975, 'tcoflashagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TCO Reg Agent
    #: - [UDP] TCO Reg Agent
    tcoregagent = 1976, 'tcoregagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TCO Address Book
    #: - [UDP] TCO Address Book
    tcoaddressbook = 1977, 'tcoaddressbook', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UniSQL
    #: - [UDP] UniSQL
    unisql = 1978, 'unisql', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UniSQL Java
    #: - [UDP] UniSQL Java
    unisql_java = 1979, 'unisql-java', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PanQuest XACT
    #: - [UDP] PanQuest XACT
    panquest_xact = 1980, 'panquest-xact', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] p2pQ
    #: - [UDP] p2pQ
    p2pq = 1981, 'p2pq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Evidentiary Timestamp
    #: - [UDP] Evidentiary Timestamp
    estamp = 1982, 'estamp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Loophole Test Protocol
    #: - [UDP] Loophole Test Protocol
    lhtp = 1983, 'lhtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BB
    #: - [UDP] BB
    bb = 1984, 'bb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hot Standby Router Protocol [:rfc:`2281`]
    #: - [UDP] Hot Standby Router Protocol [:rfc:`2281`]
    hsrp = 1985, 'hsrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco license management
    #: - [UDP] cisco license management
    licensedaemon = 1986, 'licensedaemon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco RSRB Priority 1 port
    #: - [UDP] cisco RSRB Priority 1 port
    tr_rsrb_p1 = 1987, 'tr-rsrb-p1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco RSRB Priority 2 port
    #: - [UDP] cisco RSRB Priority 2 port
    tr_rsrb_p2 = 1988, 'tr-rsrb-p2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco RSRB Priority 3 port
    #: - [UDP] cisco RSRB Priority 3 port
    tr_rsrb_p3 = 1989, 'tr-rsrb-p3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MHSnet system
    #: - [UDP] MHSnet system
    mshnet = 1989, 'mshnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco STUN Priority 1 port
    #: - [UDP] cisco STUN Priority 1 port
    stun_p1 = 1990, 'stun-p1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco STUN Priority 2 port
    #: - [UDP] cisco STUN Priority 2 port
    stun_p2 = 1991, 'stun-p2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco STUN Priority 3 port
    #: - [UDP] cisco STUN Priority 3 port
    stun_p3 = 1992, 'stun-p3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPsendmsg
    #: - [UDP] IPsendmsg
    ipsendmsg = 1992, 'ipsendmsg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco SNMP TCP port
    #: - [UDP] cisco SNMP TCP port
    snmp_tcp_port = 1993, 'snmp-tcp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco serial tunnel port
    #: - [UDP] cisco serial tunnel port
    stun_port = 1994, 'stun-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco perf port
    #: - [UDP] cisco perf port
    perf_port = 1995, 'perf-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco Remote SRB port
    #: - [UDP] cisco Remote SRB port
    tr_rsrb_port = 1996, 'tr-rsrb-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco Gateway Discovery Protocol
    #: - [UDP] cisco Gateway Discovery Protocol
    gdp_port = 1997, 'gdp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco X.25 service (XOT)
    #: - [UDP] cisco X.25 service (XOT)
    x25_svc_port = 1998, 'x25-svc-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cisco identification port
    #: - [UDP] cisco identification port
    tcp_id_port = 1999, 'tcp-id-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cisco SCCP
    #: - [UDP] Cisco SCCp
    cisco_sccp = 2000, 'cisco-sccp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] curry
    wizard = 2001, 'wizard', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    globe = 2002, 'globe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Brutus Server
    #: - [UDP] Brutus Server
    brutus = 2003, 'brutus', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] CCWS mm conf
    emce = 2004, 'emce', TransportProtocol.udp

    #: [UDP]
    oracle = 2005, 'oracle', TransportProtocol.udp

    #: - [UDP] IANA assigned this well-formed service name as a replacement for
    #:   "pipe_server".
    #: - [UDP]
    pipe_server = 2010, 'pipe-server', TransportProtocol.udp

    #: [UDP]
    servserv = 2011, 'servserv', TransportProtocol.udp

    #: [UDP]
    raid_ac = 2012, 'raid-ac', TransportProtocol.udp

    #: [UDP]
    raid_am_2007 = 2007, 'raid-am', TransportProtocol.udp

    #: [UDP] raid
    raid_cd_2006 = 2006, 'raid-cd', TransportProtocol.udp

    #: [UDP]
    raid_cd_2013 = 2013, 'raid-cd', TransportProtocol.udp

    #: [UDP]
    raid_sf = 2014, 'raid-sf', TransportProtocol.udp

    #: [UDP]
    raid_cs = 2015, 'raid-cs', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    bootserver = 2016, 'bootserver', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP]
    bootclient = 2017, 'bootclient', TransportProtocol.udp

    #: [UDP]
    terminaldb_2008 = 2008, 'terminaldb', TransportProtocol.udp

    #: [UDP]
    rellpack = 2018, 'rellpack', TransportProtocol.udp

    #: [UDP]
    whosockami_2009 = 2009, 'whosockami', TransportProtocol.udp

    #: [UDP]
    about = 2019, 'about', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    xinupageserver = 2020, 'xinupageserver', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP]
    xinuexpansion1 = 2021, 'xinuexpansion1', TransportProtocol.udp

    #: [UDP]
    xinuexpansion2 = 2022, 'xinuexpansion2', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    xinuexpansion3 = 2023, 'xinuexpansion3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    xinuexpansion4 = 2024, 'xinuexpansion4', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP]
    xribs = 2025, 'xribs', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    scrabble = 2026, 'scrabble', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    shadowserver = 2027, 'shadowserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    submitserver = 2028, 'submitserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hot Standby Router Protocol IPv6
    #: - [UDP] Hot Standby Router Protocol IPv6
    hsrpv6 = 2029, 'hsrpv6', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    device2 = 2030, 'device2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mobrien-chat
    #: - [UDP] mobrien-chat
    mobrien_chat = 2031, 'mobrien-chat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    blackboard = 2032, 'blackboard', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    glogger = 2033, 'glogger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    scoremgr = 2034, 'scoremgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    imsldoc = 2035, 'imsldoc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ethernet WS DP network
    #: - [UDP] Ethernet WS DP network
    e_dpnet = 2036, 'e-dpnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APplus Application Server
    #: - [UDP] APplus Application Server
    applus = 2037, 'applus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    objectmanager = 2038, 'objectmanager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prizma Monitoring Service
    #: - [UDP] Prizma Monitoring Service
    prizma = 2039, 'prizma', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    lam = 2040, 'lam', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    interbase = 2041, 'interbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isis
    #: - [UDP] isis
    isis = 2042, 'isis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isis-bcast
    #: - [UDP] isis-bcast
    isis_bcast = 2043, 'isis-bcast', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    rimsl = 2044, 'rimsl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    cdfunc = 2045, 'cdfunc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    sdfunc = 2046, 'sdfunc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Directory Location Service
    #: - [UDP] Directory Location Service
    dls_197 = 197, 'dls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    dls_2047 = 2047, 'dls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    dls_monitor = 2048, 'dls-monitor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    shilp = 2049, 'shilp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network File System - Sun Microsystems
    #: - [UDP] Network File System - Sun Microsystems
    #: - [SCTP] Network File System [:rfc:`5665`]
    nfs = 2049, 'nfs', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Avaya EMB Config Port
    #: - [UDP] Avaya EMB Config Port
    av_emb_config = 2050, 'av-emb-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPNSDP
    #: - [UDP] EPNSDP
    epnsdp = 2051, 'epnsdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] clearVisn Services Port
    #: - [UDP] clearVisn Services Port
    clearvisn = 2052, 'clearvisn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lot105 DSuper Updates
    #: - [UDP] Lot105 DSuper Updates
    lot105_ds_upd = 2053, 'lot105-ds-upd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Weblogin Port
    #: - [UDP] Weblogin Port
    weblogin = 2054, 'weblogin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Iliad-Odyssey Protocol
    #: - [UDP] Iliad-Odyssey Protocol
    iop = 2055, 'iop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OmniSky Port
    #: - [UDP] OmniSky Port
    omnisky = 2056, 'omnisky', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rich Content Protocol
    #: - [UDP] Rich Content Protocol
    rich_cp = 2057, 'rich-cp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NewWaveSearchables RMI
    #: - [UDP] NewWaveSearchables RMI
    newwavesearch = 2058, 'newwavesearch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC Messaging Service
    #: - [UDP] BMC Messaging Service
    bmc_messaging = 2059, 'bmc-messaging', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Telenium Daemon IF
    #: - [UDP] Telenium Daemon IF
    teleniumdaemon = 2060, 'teleniumdaemon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetMount
    #: - [UDP] NetMount
    netmount = 2061, 'netmount', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICG SWP Port
    #: - [UDP] ICG SWP Port
    icg_swp = 2062, 'icg-swp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICG Bridge Port
    #: - [UDP] ICG Bridge Port
    icg_bridge = 2063, 'icg-bridge', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICG IP Relay Port
    #: - [UDP] ICG IP Relay Port
    icg_iprelay = 2064, 'icg-iprelay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Link Switch Read Port Number
    #: - [UDP] Data Link Switch Read Port Number
    dlsrpn = 2065, 'dlsrpn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AVM USB Remote Architecture
    #: - [UDP] AVM USB Remote Architecture
    aura = 2066, 'aura', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Link Switch Write Port Number
    #: - [UDP] Data Link Switch Write Port Number
    dlswpn = 2067, 'dlswpn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avocent AuthSrv Protocol
    #: - [UDP] Avocent AuthSrv Protocol
    avauthsrvprtcl = 2068, 'avauthsrvprtcl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HTTP Event Port
    #: - [UDP] HTTP Event Port
    event_port = 2069, 'event-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AH and ESP Encapsulated in UDP packet
    #: - [UDP] AH and ESP Encapsulated in UDP packet
    ah_esp_encap = 2070, 'ah-esp-encap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Axon Control Protocol
    #: - [UDP] Axon Control Protocol
    acp_port = 2071, 'acp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GlobeCast mSync
    #: - [UDP] GlobeCast mSync
    msync = 2072, 'msync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DataReel Database Socket
    #: - [UDP] DataReel Database Socket
    gxs_data_port = 2073, 'gxs-data-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vertel VMF SA
    #: - [UDP] Vertel VMF SA
    vrtl_vmf_sa = 2074, 'vrtl-vmf-sa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Newlix ServerWare Engine
    #: - [UDP] Newlix ServerWare Engine
    newlixengine = 2075, 'newlixengine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Newlix JSPConfig
    #: - [UDP] Newlix JSPConfig
    newlixconfig = 2076, 'newlixconfig', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Old Tivoli Storage Manager
    #: - [UDP] Old Tivoli Storage Manager
    tsrmagt = 2077, 'tsrmagt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Total Productivity Center Server
    #: - [UDP] IBM Total Productivity Center Server
    tpcsrvr = 2078, 'tpcsrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IDWARE Router Port
    #: - [UDP] IDWARE Router Port
    idware_router = 2079, 'idware-router', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Autodesk NLM (FLEXlm)
    #: - [UDP] Autodesk NLM (FLEXlm)
    autodesk_nlm = 2080, 'autodesk-nlm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KME PRINTER TRAP PORT
    #: - [UDP] KME PRINTER TRAP PORT
    kme_trap_port = 2081, 'kme-trap-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Infowave Mobility Server
    #: - [UDP] Infowave Mobility Server
    infowave = 2082, 'infowave', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Radius Service [:rfc:`6614`]
    #: - [UDP] Secure Radius Service [:rfc:`7360`]
    radsec = 2083, 'radsec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SunCluster Geographic
    #: - [UDP] SunCluster Geographic
    sunclustergeo = 2084, 'sunclustergeo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ADA Control
    #: - [UDP] ADA Control
    ada_cip = 2085, 'ada-cip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GNUnet
    #: - [UDP] GNUnet
    gnunet = 2086, 'gnunet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ELI - Event Logging Integration
    #: - [UDP] ELI - Event Logging Integration
    eli = 2087, 'eli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IP Busy Lamp Field
    #: - [UDP] IP Busy Lamp Field
    ip_blf = 2088, 'ip-blf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Security Encapsulation Protocol - SEP
    #: - [UDP] Security Encapsulation Protocol - SEP
    sep = 2089, 'sep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Load Report Protocol
    #: - [UDP] Load Report Protocol
    lrp = 2090, 'lrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PRP
    #: - [UDP] PRP
    prp = 2091, 'prp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Descent 3
    #: - [UDP] Descent 3
    descent3 = 2092, 'descent3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NBX CC
    #: - [UDP] NBX CC
    nbx_cc = 2093, 'nbx-cc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NBX AU
    #: - [UDP] NBX AU
    nbx_au = 2094, 'nbx-au', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NBX SER
    #: - [UDP] NBX SER
    nbx_ser = 2095, 'nbx-ser', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NBX DIR
    #: - [UDP] NBX DIR
    nbx_dir = 2096, 'nbx-dir', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jet Form Preview
    #: - [UDP] Jet Form Preview
    jetformpreview = 2097, 'jetformpreview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dialog Port
    #: - [UDP] Dialog Port
    dialog_port = 2098, 'dialog-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] H.225.0 Annex G Signalling
    #: - [UDP] H.225.0 Annex G Signalling
    h2250_annex_g = 2099, 'h2250-annex-g', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Amiga Network Filesystem
    #: - [UDP] Amiga Network Filesystem
    amiganetfs = 2100, 'amiganetfs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rtcm-sc104
    #: - [UDP] rtcm-sc104
    rtcm_sc104 = 2101, 'rtcm-sc104', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zephyr server
    #: - [UDP] Zephyr server
    zephyr_srv = 2102, 'zephyr-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zephyr serv-hm connection
    #: - [UDP] Zephyr serv-hm connection
    zephyr_clt = 2103, 'zephyr-clt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zephyr hostmanager
    #: - [UDP] Zephyr hostmanager
    zephyr_hm = 2104, 'zephyr-hm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MiniPay
    #: - [UDP] MiniPay
    minipay = 2105, 'minipay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MZAP
    #: - [UDP] MZAP
    mzap = 2106, 'mzap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BinTec Admin
    #: - [UDP] BinTec Admin
    bintec_admin = 2107, 'bintec-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Comcam
    #: - [UDP] Comcam
    comcam = 2108, 'comcam', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ergolight
    #: - [UDP] Ergolight
    ergolight = 2109, 'ergolight', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UMSP
    #: - [UDP] UMSP
    umsp = 2110, 'umsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPNET Dynamic Sampling Agent Transaction Protocol
    #: - [UDP] OPNET Dynamic Sampling Agent Transaction Protocol
    dsatp = 2111, 'dsatp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Idonix MetaNet
    #: - [UDP] Idonix MetaNet
    idonix_metanet = 2112, 'idonix-metanet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HSL StoRM
    #: - [UDP] HSL StoRM
    hsl_storm = 2113, 'hsl-storm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Classical Music Meta-Data Access and Enhancement
    #: - [UDP] Classical Music Meta-Data Access and Enhancement
    ariascribe = 2114, 'ariascribe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Key Distribution Manager
    #: - [UDP] Key Distribution Manager
    kdm = 2115, 'kdm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CCOWCMR
    #: - [UDP] CCOWCMR
    ccowcmr = 2116, 'ccowcmr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MENTACLIENT
    #: - [UDP] MENTACLIENT
    mentaclient = 2117, 'mentaclient', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MENTASERVER
    #: - [UDP] MENTASERVER
    mentaserver = 2118, 'mentaserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GSIGATEKEEPER
    #: - [UDP] GSIGATEKEEPER
    gsigatekeeper = 2119, 'gsigatekeeper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quick Eagle Networks CP
    #: - [UDP] Quick Eagle Networks CP
    qencp = 2120, 'qencp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCIENTIA-SSDB
    #: - [UDP] SCIENTIA-SSDB
    scientia_ssdb = 2121, 'scientia-ssdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CauPC Remote Control
    #: - [UDP] CauPC Remote Control
    caupc_remote = 2122, 'caupc-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GTP-Control Plane (3GPP)
    #: - [UDP] GTP-Control Plane (3GPP)
    gtp_control = 2123, 'gtp-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ELATELINK
    #: - [UDP] ELATELINK
    elatelink = 2124, 'elatelink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LOCKSTEP
    #: - [UDP] LOCKSTEP
    lockstep = 2125, 'lockstep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PktCable-COPS
    #: - [UDP] PktCable-COPS
    pktcable_cops = 2126, 'pktcable-cops', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INDEX-PC-WB
    #: - [UDP] INDEX-PC-WB
    index_pc_wb = 2127, 'index-pc-wb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net Steward Control
    #: - [UDP] Net Steward Control
    net_steward = 2128, 'net-steward', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cs-live.com
    #: - [UDP] cs-live.com
    cs_live = 2129, 'cs-live', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XDS
    #: - [UDP] XDS
    xds = 2130, 'xds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avantageb2b
    #: - [UDP] Avantageb2b
    avantageb2b = 2131, 'avantageb2b', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SoleraTec End Point Map
    #: - [UDP] SoleraTec End Point Map
    solera_epmap = 2132, 'solera-epmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ZYMED-ZPP
    #: - [UDP] ZYMED-ZPP
    zymed_zpp = 2133, 'zymed-zpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AVENUE
    #: - [UDP] AVENUE
    avenue = 2134, 'avenue', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Grid Resource Information Server
    #: - [UDP] Grid Resource Information Server
    gris = 2135, 'gris', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APPWORXSRV
    #: - [UDP] APPWORXSRV
    appworxsrv = 2136, 'appworxsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CONNECT
    #: - [UDP] CONNECT
    connect = 2137, 'connect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UNBIND-CLUSTER
    #: - [UDP] UNBIND-CLUSTER
    unbind_cluster = 2138, 'unbind-cluster', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IAS-AUTH
    #: - [UDP] IAS-AUTH
    ias_auth = 2139, 'ias-auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IAS-REG
    #: - [UDP] IAS-REG
    ias_reg = 2140, 'ias-reg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IAS-ADMIND
    #: - [UDP] IAS-ADMIND
    ias_admind = 2141, 'ias-admind', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TDM OVER IP [:rfc:`5087`]
    #: - [UDP] TDM OVER IP [:rfc:`5087`]
    tdmoip = 2142, 'tdmoip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Live Vault Job Control
    #: - [UDP] Live Vault Job Control
    lv_jc = 2143, 'lv-jc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Live Vault Fast Object Transfer
    #: - [UDP] Live Vault Fast Object Transfer
    lv_ffx = 2144, 'lv-ffx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Live Vault Remote Diagnostic Console Support
    #: - [UDP] Live Vault Remote Diagnostic Console Support
    lv_pici = 2145, 'lv-pici', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Live Vault Admin Event Notification
    #: - [UDP] Live Vault Admin Event Notification
    lv_not = 2146, 'lv-not', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Live Vault Authentication
    #: - [UDP] Live Vault Authentication
    lv_auth = 2147, 'lv-auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS UNIVERSAL COMMUNICATION LAYER
    #: - [UDP] VERITAS UNIVERSAL COMMUNICATION LAYER
    veritas_ucl = 2148, 'veritas-ucl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACPTSYS
    #: - [UDP] ACPTSYS
    acptsys = 2149, 'acptsys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DYNAMIC3D
    #: - [UDP] DYNAMIC3D
    dynamic3d = 2150, 'dynamic3d', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DOCENT
    #: - [UDP] DOCENT
    docent = 2151, 'docent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GTP-User Plane (3GPP)
    #: - [UDP] GTP-User Plane (3GPP)
    gtp_user = 2152, 'gtp-user', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Control Protocol
    #: - [UDP] Control Protocol
    ctlptc = 2153, 'ctlptc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Standard Protocol
    #: - [UDP] Standard Protocol
    stdptc = 2154, 'stdptc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bridge Protocol
    #: - [UDP] Bridge Protocol
    brdptc = 2155, 'brdptc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talari Reliable Protocol
    #: - [UDP] Talari Reliable Protocol
    trp = 2156, 'trp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xerox Network Document Scan Protocol
    #: - [UDP] Xerox Network Document Scan Protocol
    xnds = 2157, 'xnds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TouchNetPlus Service
    #: - [UDP] TouchNetPlus Service
    touchnetplus = 2158, 'touchnetplus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GDB Remote Debug Port
    #: - [UDP] GDB Remote Debug Port
    gdbremote = 2159, 'gdbremote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 2160
    #: - [UDP] APC 2160
    apc_2160 = 2160, 'apc-2160', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 2161
    #: - [UDP] APC 2161
    apc_2161 = 2161, 'apc-2161', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Navisphere
    #: - [UDP] Navisphere
    navisphere = 2162, 'navisphere', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Navisphere Secure
    #: - [UDP] Navisphere Secure
    navisphere_sec = 2163, 'navisphere-sec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dynamic DNS Version 3
    #: - [UDP] Dynamic DNS Version 3
    ddns_v3 = 2164, 'ddns-v3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] X-Bone API
    #: - [UDP] X-Bone API
    x_bone_api = 2165, 'x-bone-api', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iwserver
    #: - [UDP] iwserver
    iwserver = 2166, 'iwserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Raw Async Serial Link
    #: - [UDP] Raw Async Serial Link
    raw_serial = 2167, 'raw-serial', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] easy-soft Multiplexer
    #: - [UDP] easy-soft Multiplexer
    easy_soft_mux = 2168, 'easy-soft-mux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Backbone for Academic Information Notification (BRAIN)
    #: - [UDP] Backbone for Academic Information Notification (BRAIN)
    brain = 2169, 'brain', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EyeTV Server Port
    #: - [UDP] EyeTV Server Port
    eyetv = 2170, 'eyetv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS Firewall Storage
    #: - [UDP] MS Firewall Storage
    msfw_storage = 2171, 'msfw-storage', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS Firewall SecureStorage
    #: - [UDP] MS Firewall SecureStorage
    msfw_s_storage = 2172, 'msfw-s-storage', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS Firewall Replication
    #: - [UDP] MS Firewall Replication
    msfw_replica = 2173, 'msfw-replica', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS Firewall Intra Array
    #: - [UDP] MS Firewall Intra Array
    msfw_array = 2174, 'msfw-array', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Desktop AirSync Protocol
    #: - [UDP] Microsoft Desktop AirSync Protocol
    airsync = 2175, 'airsync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft ActiveSync Remote API
    #: - [UDP] Microsoft ActiveSync Remote API
    rapi = 2176, 'rapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qWAVE Bandwidth Estimate
    #: - [UDP] qWAVE Bandwidth Estimate
    qwave = 2177, 'qwave', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Peer Services for BITS
    #: - [UDP] Peer Services for BITS
    bitspeer = 2178, 'bitspeer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft RDP for virtual machines
    #: - [UDP] Microsoft RDP for virtual machines
    vmrdp = 2179, 'vmrdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Millicent Vendor Gateway Server
    #: - [UDP] Millicent Vendor Gateway Server
    mc_gt_srv = 2180, 'mc-gt-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eforward
    #: - [UDP] eforward
    eforward = 2181, 'eforward', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CGN status
    #: - [UDP] CGN status
    cgn_stat = 2182, 'cgn-stat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Code Green configuration
    #: - [UDP] Code Green configuration
    cgn_config = 2183, 'cgn-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OnBase Distributed Disk Services
    #: - [UDP] OnBase Distributed Disk Services
    onbase_dds = 2185, 'onbase-dds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Guy-Tek Automated Update Applications
    #: - [UDP] Guy-Tek Automated Update Applications
    gtaua = 2186, 'gtaua', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Sepehr System Management Data
    ssmd = 2187, 'ssmd', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2188 = 2188, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2189 = 2189, 'reserved', TransportProtocol.udp

    #: - [TCP] TiVoConnect Beacon
    #: - [UDP] TiVoConnect Beacon
    tivoconnect = 2190, 'tivoconnect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TvBus Messaging
    #: - [UDP] TvBus Messaging
    tvbus = 2191, 'tvbus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASDIS software management
    #: - [UDP] ASDIS software management
    asdis = 2192, 'asdis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dr.Web Enterprise Management Service
    #: - [UDP] Dr.Web Enterprise Management Service
    drwcs = 2193, 'drwcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MNP data exchange
    #: - [UDP] MNP data exchange
    mnp_exchange = 2197, 'mnp-exchange', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OneHome Remote Access
    #: - [UDP] OneHome Remote Access
    onehome_remote = 2198, 'onehome-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OneHome Service Port
    #: - [UDP] OneHome Service Port
    onehome_help = 2199, 'onehome-help', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_2200 = 2200, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Advanced Training System Program
    #: - [UDP] Advanced Training System Program
    ats = 2201, 'ats', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Int. Multimedia Teleconferencing Cosortium
    #: - [UDP] Int. Multimedia Teleconferencing Cosortium
    imtc_map = 2202, 'imtc-map', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] b2 Runtime Protocol
    #: - [UDP] b2 Runtime Protocol
    b2_runtime = 2203, 'b2-runtime', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] b2 License Server
    #: - [UDP] b2 License Server
    b2_license = 2204, 'b2-license', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Java Presentation Server
    #: - [UDP] Java Presentation Server
    jps = 2205, 'jps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP OpenCall bus
    #: - [UDP] HP OpenCall bus
    hpocbus = 2206, 'hpocbus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP Status and Services
    #: - [UDP] HP Status and Services
    hpssd = 2207, 'hpssd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP I/O Backend
    #: - [UDP] HP I/O Backend
    hpiod = 2208, 'hpiod', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP RIM for Files Portal Service
    #: - [UDP] HP RIM for Files Portal Service
    rimf_ps = 2209, 'rimf-ps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NOAAPORT Broadcast Network
    #: - [UDP] NOAAPORT Broadcast Network
    noaaport = 2210, 'noaaport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMWIN
    #: - [UDP] EMWIN
    emwin = 2211, 'emwin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LeeCO POS Server Service
    #: - [UDP] LeeCO POS Server Service
    leecoposserver = 2212, 'leecoposserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kali
    #: - [UDP] Kali
    kali = 2213, 'kali', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RDQ Protocol Interface
    #: - [UDP] RDQ Protocol Interface
    rpi = 2214, 'rpi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPCore.co.za GPRS
    #: - [UDP] IPCore.co.za GPRS
    ipcore = 2215, 'ipcore', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VTU data service
    #: - [UDP] VTU data service
    vtu_comms = 2216, 'vtu-comms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GoToDevice Device Management
    #: - [UDP] GoToDevice Device Management
    gotodevice = 2217, 'gotodevice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bounzza IRC Proxy
    #: - [UDP] Bounzza IRC Proxy
    bounzza = 2218, 'bounzza', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetIQ NCAP Protocol
    #: - [UDP] NetIQ NCAP Protocol
    netiq_ncap = 2219, 'netiq-ncap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetIQ End2End
    #: - [UDP] NetIQ End2End
    netiq = 2220, 'netiq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EtherNet/IP over TLS
    #: - [UDP] EtherNet/IP over DTLS
    ethernet_ip_s = 2221, 'ethernet-ip-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EtherNet/IP I/O IANA assigned this well-formed service name as a
    #:   replacement for "EtherNet/IP-1".
    #: - [TCP] EtherNet/IP I/O
    #: - [UDP] EtherNet/IP I/O IANA assigned this well-formed service name as a
    #:   replacement for "EtherNet/IP-1".
    #: - [UDP] EtherNet/IP I/O
    ethernet_ip_1 = 2222, 'ethernet-ip-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rockwell CSP2
    #: - [UDP] Rockwell CSP2
    rockwell_csp2 = 2223, 'rockwell-csp2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Easy Flexible Internet/Multiplayer Games
    #: - [UDP] Easy Flexible Internet/Multiplayer Games
    efi_mg = 2224, 'efi-mg', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2225 = 2225, 'reserved', TransportProtocol.udp

    #: - [TCP] Digital Instinct DRM
    #: - [UDP] Digital Instinct DRM
    di_drm = 2226, 'di-drm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DI Messaging Service
    #: - [UDP] DI Messaging Service
    di_msg = 2227, 'di-msg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eHome Message Server
    #: - [UDP] eHome Message Server
    ehome_ms = 2228, 'ehome-ms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DataLens Service
    #: - [UDP] DataLens Service
    datalens = 2229, 'datalens', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MetaSoft Job Queue Administration Service
    #: - [UDP] MetaSoft Job Queue Administration Service
    queueadm = 2230, 'queueadm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WiMAX ASN Control Plane Protocol
    #: - [UDP] WiMAX ASN Control Plane Protocol
    wimaxasncp = 2231, 'wimaxasncp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IVS Video default
    #: - [UDP] IVS Video default
    ivs_video = 2232, 'ivs-video', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INFOCRYPT
    #: - [UDP] INFOCRYPT
    infocrypt = 2233, 'infocrypt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DirectPlay
    #: - [UDP] DirectPlay
    directplay = 2234, 'directplay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sercomm-WLink
    #: - [UDP] Sercomm-WLink
    sercomm_wlink = 2235, 'sercomm-wlink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nani
    #: - [UDP] Nani
    nani = 2236, 'nani', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Optech Port1 License Manager
    #: - [UDP] Optech Port1 License Manager
    optech_port1_lm = 2237, 'optech-port1-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AVIVA SNA SERVER
    #: - [UDP] AVIVA SNA SERVER
    aviva_sna = 2238, 'aviva-sna', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Image Query
    #: - [UDP] Image Query
    imagequery = 2239, 'imagequery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RECIPe
    #: - [UDP] RECIPe
    recipe = 2240, 'recipe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IVS Daemon
    #: - [UDP] IVS Daemon
    ivsd = 2241, 'ivsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Folio Remote Server
    #: - [UDP] Folio Remote Server
    foliocorp = 2242, 'foliocorp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Magicom Protocol
    #: - [UDP] Magicom Protocol
    magicom = 2243, 'magicom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NMS Server
    #: - [UDP] NMS Server
    nmsserver = 2244, 'nmsserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HaO
    #: - [UDP] HaO
    hao = 2245, 'hao', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PacketCable MTA Addr Map
    #: - [UDP] PacketCable MTA Addr Map
    pc_mta_addrmap = 2246, 'pc-mta-addrmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Antidote Deployment Manager Service
    #: - [UDP] Antidote Deployment Manager Service
    antidotemgrsvr = 2247, 'antidotemgrsvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] User Management Service
    #: - [UDP] User Management Service
    ums = 2248, 'ums', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RISO File Manager Protocol
    #: - [UDP] RISO File Manager Protocol
    rfmp = 2249, 'rfmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] remote-collab
    #: - [UDP] remote-collab
    remote_collab = 2250, 'remote-collab', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Distributed Framework Port
    #: - [UDP] Distributed Framework Port
    dif_port = 2251, 'dif-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NJENET using SSL
    #: - [UDP] NJENET using SSL
    njenet_ssl = 2252, 'njenet-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DTV Channel Request
    #: - [UDP] DTV Channel Request
    dtv_chan_req = 2253, 'dtv-chan-req', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Seismic P.O.C. Port
    #: - [UDP] Seismic P.O.C. Port
    seispoc = 2254, 'seispoc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VRTP - ViRtue Transfer Protocol
    #: - [UDP] VRTP - ViRtue Transfer Protocol
    vrtp = 2255, 'vrtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCC MFP
    #: - [UDP] PCC MFP
    pcc_mfp = 2256, 'pcc-mfp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] simple text/file transfer
    #: - [UDP] simple text/file transfer
    simple_tx_rx = 2257, 'simple-tx-rx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rotorcraft Communications Test System
    #: - [UDP] Rotorcraft Communications Test System
    rcts = 2258, 'rcts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BIF identifiers resolution service
    #: - [UDP] BIF identifiers resolution service
    bid_serv = 2259, 'bid-serv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 2260
    #: - [UDP] APC 2260
    apc_2260 = 2260, 'apc-2260', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CoMotion Master Server
    #: - [UDP] CoMotion Master Server
    comotionmaster = 2261, 'comotionmaster', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CoMotion Backup Server
    #: - [UDP] CoMotion Backup Server
    comotionback = 2262, 'comotionback', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ECweb Configuration Service
    #: - [UDP] ECweb Configuration Service
    ecwcfg = 2263, 'ecwcfg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Audio Precision Apx500 API Port 1
    #: - [UDP] Audio Precision Apx500 API Port 1
    apx500api_1 = 2264, 'apx500api-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Audio Precision Apx500 API Port 2
    #: - [UDP] Audio Precision Apx500 API Port 2
    apx500api_2 = 2265, 'apx500api-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] M-Files Server
    #: - [UDP] M-files Server
    mfserver = 2266, 'mfserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OntoBroker
    #: - [UDP] OntoBroker
    ontobroker = 2267, 'ontobroker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMT [:rfc:`7450`]
    #: - [UDP] AMT [:rfc:`7450`]
    amt = 2268, 'amt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MIKEY
    #: - [UDP] MIKEY
    mikey = 2269, 'mikey', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] starSchool
    #: - [UDP] starSchool
    starschool = 2270, 'starschool', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Meeting Maker Scheduling
    #: - [UDP] Secure Meeting Maker Scheduling
    mmcals = 2271, 'mmcals', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Meeting Maker Scheduling
    #: - [UDP] Meeting Maker Scheduling
    mmcal = 2272, 'mmcal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MySQL Instance Manager
    #: - [UDP] MySQL Instance Manager
    mysql_im = 2273, 'mysql-im', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCTTunneller
    #: - [UDP] PCTTunneller
    pcttunnell = 2274, 'pcttunnell', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iBridge Conferencing
    #: - [UDP] iBridge Conferencing
    ibridge_data = 2275, 'ibridge-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iBridge Management
    #: - [UDP] iBridge Management
    ibridge_mgmt = 2276, 'ibridge-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bt device control proxy
    #: - [UDP] Bt device control proxy
    bluectrlproxy = 2277, 'bluectrlproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Stacked Sequences Database
    #: - [UDP] Simple Stacked Sequences Database
    s3db = 2278, 's3db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xmquery
    #: - [UDP] xmquery
    xmquery = 2279, 'xmquery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LNVPOLLER
    #: - [UDP] LNVPOLLER
    lnvpoller = 2280, 'lnvpoller', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LNVCONSOLE
    #: - [UDP] LNVCONSOLE
    lnvconsole = 2281, 'lnvconsole', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LNVALARM
    #: - [UDP] LNVALARM
    lnvalarm = 2282, 'lnvalarm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LNVSTATUS
    #: - [UDP] LNVSTATUS
    lnvstatus = 2283, 'lnvstatus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LNVMAPS
    #: - [UDP] LNVMAPS
    lnvmaps = 2284, 'lnvmaps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LNVMAILMON
    #: - [UDP] LNVMAILMON
    lnvmailmon = 2285, 'lnvmailmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NAS-Metering
    #: - [UDP] NAS-Metering
    nas_metering = 2286, 'nas-metering', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNA
    #: - [UDP] DNA
    dna = 2287, 'dna', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETML
    #: - [UDP] NETML
    netml = 2288, 'netml', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lookup dict server
    #: - [UDP] Lookup dict server
    dict_lookup = 2289, 'dict-lookup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sonus Logging Services
    #: - [UDP] Sonus Logging Services
    sonus_logging = 2290, 'sonus-logging', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPSON Advanced Printer Share Protocol
    #: - [UDP] EPSON Advanced Printer Share Protocol
    eapsp = 2291, 'eapsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sonus Element Management Services
    #: - [UDP] Sonus Element Management Services
    mib_streaming = 2292, 'mib-streaming', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Platform Debug Manager
    #: - [UDP] Network Platform Debug Manager
    npdbgmngr = 2293, 'npdbgmngr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Konshus License Manager (FLEX)
    #: - [UDP] Konshus License Manager (FLEX)
    konshus_lm = 2294, 'konshus-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Advant License Manager
    #: - [UDP] Advant License Manager
    advant_lm = 2295, 'advant-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Theta License Manager (Rainbow)
    #: - [UDP] Theta License Manager (Rainbow)
    theta_lm = 2296, 'theta-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D2K DataMover 1
    #: - [UDP] D2K DataMover 1
    d2k_datamover1 = 2297, 'd2k-datamover1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D2K DataMover 2
    #: - [UDP] D2K DataMover 2
    d2k_datamover2 = 2298, 'd2k-datamover2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PC Telecommute
    #: - [UDP] PC Telecommute
    pc_telecommute = 2299, 'pc-telecommute', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CVMMON
    #: - [UDP] CVMMON
    cvmmon = 2300, 'cvmmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compaq HTTP
    #: - [UDP] Compaq HTTP
    cpq_wbem = 2301, 'cpq-wbem', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bindery Support
    #: - [UDP] Bindery Support
    binderysupport = 2302, 'binderysupport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Proxy Gateway
    #: - [UDP] Proxy Gateway
    proxy_gateway = 2303, 'proxy-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Attachmate UTS
    #: - [UDP] Attachmate UTS
    attachmate_uts = 2304, 'attachmate-uts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MT ScaleServer
    #: - [UDP] MT ScaleServer
    mt_scaleserver = 2305, 'mt-scaleserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TAPPI BoxNet
    #: - [UDP] TAPPI BoxNet
    tappi_boxnet = 2306, 'tappi-boxnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pehelp
    #: - [UDP] pehelp
    pehelp = 2307, 'pehelp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sdhelp
    #: - [UDP] sdhelp
    sdhelp = 2308, 'sdhelp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SD Server
    #: - [UDP] SD Server
    sdserver = 2309, 'sdserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SD Client
    #: - [UDP] SD Client
    sdclient = 2310, 'sdclient', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message Service
    #: - [UDP] Message Service
    messageservice = 2311, 'messageservice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WANScaler Communication Service
    #: - [UDP] WANScaler Communication Service
    wanscaler = 2312, 'wanscaler', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IAPP (Inter Access Point Protocol)
    #: - [UDP] IAPP (Inter Access Point Protocol)
    iapp = 2313, 'iapp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CR WebSystems
    #: - [UDP] CR WebSystems
    cr_websystems = 2314, 'cr-websystems', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Precise Sft.
    #: - [UDP] Precise Sft.
    precise_sft = 2315, 'precise-sft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SENT License Manager
    #: - [UDP] SENT License Manager
    sent_lm = 2316, 'sent-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Attachmate G32
    #: - [UDP] Attachmate G32
    attachmate_g32 = 2317, 'attachmate-g32', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cadence Control
    #: - [UDP] Cadence Control
    cadencecontrol = 2318, 'cadencecontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] InfoLibria
    #: - [UDP] InfoLibria
    infolibria = 2319, 'infolibria', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Siebel NS
    #: - [UDP] Siebel NS
    siebel_ns = 2320, 'siebel-ns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RDLAP
    #: - [UDP] RDLAP
    rdlap = 2321, 'rdlap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ofsd
    #: - [UDP] ofsd
    ofsd = 2322, 'ofsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3d-nfsd
    #: - [UDP] 3d-nfsd
    UDP_3d_nfsd = 2323, '3d-nfsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cosmocall
    #: - [UDP] Cosmocall
    cosmocall = 2324, 'cosmocall', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ANSYS Licensing Interconnect
    #: - [UDP] ANSYS Licensing Interconnect
    ansysli = 2325, 'ansysli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IDCP
    #: - [UDP] IDCP
    idcp = 2326, 'idcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xingcsm
    #: - [UDP] xingcsm
    xingcsm = 2327, 'xingcsm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netrix SFTM
    #: - [UDP] Netrix SFTM
    netrix_sftm = 2328, 'netrix-sftm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NVD User
    #: - [UDP] NVD User
    nvd_2184 = 2184, 'nvd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NVD
    #: - [UDP] NVD
    nvd_2329 = 2329, 'nvd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TSCCHAT
    #: - [UDP] TSCCHAT
    tscchat = 2330, 'tscchat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AGENTVIEW
    #: - [UDP] AGENTVIEW
    agentview = 2331, 'agentview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RCC Host
    #: - [UDP] RCC Host
    rcc_host = 2332, 'rcc-host', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNAPP
    #: - [UDP] SNAPP
    snapp = 2333, 'snapp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACE Client Auth
    #: - [UDP] ACE Client Auth
    ace_client = 2334, 'ace-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACE Proxy
    #: - [UDP] ACE Proxy
    ace_proxy = 2335, 'ace-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apple UG Control
    #: - [UDP] Apple UG Control
    appleugcontrol = 2336, 'appleugcontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ideesrv
    #: - [UDP] ideesrv
    ideesrv = 2337, 'ideesrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Norton Lambert
    #: - [UDP] Norton Lambert
    norton_lambert = 2338, 'norton-lambert', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3Com WebView
    #: - [UDP] 3Com WebView
    UDP_3com_webview = 2339, '3com-webview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WRS Registry IANA assigned this well-formed service name as a
    #:   replacement for "wrs_registry".
    #: - [TCP] WRS Registry
    #: - [UDP] WRS Registry IANA assigned this well-formed service name as a
    #:   replacement for "wrs_registry".
    #: - [UDP] WRS Registry
    wrs_registry = 2340, 'wrs-registry', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XIO Status
    #: - [UDP] XIO Status
    xiostatus = 2341, 'xiostatus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Seagate Manage Exec
    #: - [UDP] Seagate Manage Exec
    manage_exec = 2342, 'manage-exec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nati logos
    #: - [UDP] nati logos
    nati_logos = 2343, 'nati-logos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fcmsys
    #: - [UDP] fcmsys
    fcmsys = 2344, 'fcmsys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dbm
    #: - [UDP] dbm
    dbm = 2345, 'dbm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Game Connection Port IANA assigned this well-formed service name as a
    #:   replacement for "redstorm_join".
    #: - [TCP] Game Connection Port
    #: - [UDP] Game Connection Port IANA assigned this well-formed service name as a
    #:   replacement for "redstorm_join".
    #: - [UDP] Game Connection Port
    redstorm_join = 2346, 'redstorm-join', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Game Announcement and Location IANA assigned this well-formed service
    #:   name as a replacement for "redstorm_find".
    #: - [TCP] Game Announcement and Location
    #: - [UDP] Game Announcement and Location IANA assigned this well-formed service
    #:   name as a replacement for "redstorm_find".
    #: - [UDP] Game Announcement and Location
    redstorm_find = 2347, 'redstorm-find', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Information to query for game status IANA assigned this well-formed
    #:   service name as a replacement for "redstorm_info".
    #: - [TCP] Information to query for game status
    #: - [UDP] Information to query for game status IANA assigned this well-formed
    #:   service name as a replacement for "redstorm_info".
    #: - [UDP] Information to query for game status
    redstorm_info = 2348, 'redstorm-info', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Diagnostics Port IANA assigned this well-formed service name as a
    #:   replacement for "redstorm_diag".
    #: - [TCP] Diagnostics Port
    #: - [UDP] Diagnostics Port IANA assigned this well-formed service name as a
    #:   replacement for "redstorm_diag".
    #: - [UDP] Diagnostics Port
    redstorm_diag = 2349, 'redstorm-diag', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pharos Booking Server
    #: - [UDP] Pharos Booking Server
    psbserver = 2350, 'psbserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] psrserver
    #: - [UDP] psrserver
    psrserver = 2351, 'psrserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pslserver
    #: - [UDP] pslserver
    pslserver = 2352, 'pslserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pspserver
    #: - [UDP] pspserver
    pspserver = 2353, 'pspserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] psprserver
    #: - [UDP] psprserver
    psprserver = 2354, 'psprserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] psdbserver
    #: - [UDP] psdbserver
    psdbserver = 2355, 'psdbserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GXT License Managemant
    #: - [UDP] GXT License Managemant
    gxtelmd = 2356, 'gxtelmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UniHub Server
    #: - [UDP] UniHub Server
    unihub_server = 2357, 'unihub-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Futrix
    #: - [UDP] Futrix
    futrix = 2358, 'futrix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FlukeServer
    #: - [UDP] FlukeServer
    flukeserver = 2359, 'flukeserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NexstorIndLtd
    #: - [UDP] NexstorIndLtd
    nexstorindltd = 2360, 'nexstorindltd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TL1
    #: - [UDP] TL1
    tl1 = 2361, 'tl1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] digiman
    #: - [UDP] digiman
    digiman = 2362, 'digiman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Media Central NFSD
    #: - [UDP] Media Central NFSD
    mediacntrlnfsd = 2363, 'mediacntrlnfsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OI-2000
    #: - [UDP] OI-2000
    oi_2000 = 2364, 'oi-2000', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dbref
    #: - [UDP] dbref
    dbref = 2365, 'dbref', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qip-login
    #: - [UDP] qip-login
    qip_login = 2366, 'qip-login', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Control
    #: - [UDP] Service Control
    service_ctrl = 2367, 'service-ctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenTable
    #: - [UDP] OpenTable
    opentable = 2368, 'opentable', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Blockchain Identifier InFrastructure P2P
    #: - [UDP] Blockchain Identifier InFrastructure P2P
    bif_p2p = 2369, 'bif-p2p', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] L3-HBMon
    #: - [UDP] L3-HBMon
    l3_hbmon = 2370, 'l3-hbmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RDA
    #: - [UDP] RDA
    rda_630 = 630, 'rda', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2371 = 2371, 'reserved', TransportProtocol.udp

    #: - [TCP] LanMessenger
    #: - [UDP] LanMessenger
    lanmessenger = 2372, 'lanmessenger', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2373 = 2373, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2374 = 2374, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2375 = 2375, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2377 = 2377, 'reserved', TransportProtocol.udp

    #: [UDP] DALI lighting control
    dali = 2378, 'dali', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2379 = 2379, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2380 = 2380, 'reserved', TransportProtocol.udp

    #: - [TCP] Compaq HTTPS
    #: - [UDP] Compaq HTTPS
    compaq_https = 2381, 'compaq-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft OLAP
    #: - [UDP] Microsoft OLAP
    ms_olap3 = 2382, 'ms-olap3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft OLAP
    #: - [UDP] Microsoft OLAP
    ms_olap4 = 2383, 'ms-olap4', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] SD-CAPACITY
    sd_capacity = 2384, 'sd-capacity', TransportProtocol.udp

    #: - [TCP] SD-DATA
    #: - [UDP] SD-DATA
    sd_data = 2385, 'sd-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Tape
    #: - [UDP] Virtual Tape
    virtualtape = 2386, 'virtualtape', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSAM Redirector
    #: - [UDP] VSAM Redirector
    vsamredirector = 2387, 'vsamredirector', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MYNAH AutoStart
    #: - [UDP] MYNAH AutoStart
    mynahautostart = 2388, 'mynahautostart', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView Session Mgr
    #: - [UDP] OpenView Session Mgr
    ovsessionmgr = 2389, 'ovsessionmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSMTP
    #: - [UDP] RSMTP
    rsmtp = 2390, 'rsmtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3COM Net Management
    #: - [UDP] 3COM Net Management
    UDP_3com_net_mgmt = 2391, '3com-net-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tactical Auth
    #: - [UDP] Tactical Auth
    tacticalauth = 2392, 'tacticalauth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS OLAP 1
    #: - [UDP] MS OLAP 1
    ms_olap1 = 2393, 'ms-olap1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS OLAP 2
    #: - [UDP] MS OLAP 2
    ms_olap2 = 2394, 'ms-olap2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LAN900 Remote IANA assigned this well-formed service name as a
    #:   replacement for "lan900_remote".
    #: - [TCP] LAN900 Remote
    #: - [UDP] LAN900 Remote IANA assigned this well-formed service name as a
    #:   replacement for "lan900_remote".
    #: - [UDP] LAN900 Remote
    lan900_remote = 2395, 'lan900-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wusage
    #: - [UDP] Wusage
    wusage = 2396, 'wusage', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NCL
    #: - [UDP] NCL
    ncl = 2397, 'ncl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Orbiter
    #: - [UDP] Orbiter
    orbiter = 2398, 'orbiter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileMaker, Inc. - Data Access Layer
    #: - [UDP] FileMaker, Inc. - Data Access Layer
    fmpro_fdal = 2399, 'fmpro-fdal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpEquus Server
    #: - [UDP] OpEquus Server
    opequus_server = 2400, 'opequus-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cvspserver
    #: - [UDP] cvspserver
    cvspserver = 2401, 'cvspserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TaskMaster 2000 Server
    #: - [UDP] TaskMaster 2000 Server
    taskmaster2000_2402 = 2402, 'taskmaster2000', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TaskMaster 2000 Web
    #: - [UDP] TaskMaster 2000 Web
    taskmaster2000_2403 = 2403, 'taskmaster2000', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IEC 60870-5-104 process control over IP
    #: - [UDP] IEC 60870-5-104 process control over IP
    iec_104 = 2404, 'iec-104', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRC Netpoll
    #: - [UDP] TRC Netpoll
    trc_netpoll = 2405, 'trc-netpoll', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JediServer
    #: - [UDP] JediServer
    jediserver = 2406, 'jediserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Orion
    #: - [UDP] Orion
    orion = 2407, 'orion', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2408 = 2408, 'reserved', TransportProtocol.udp

    #: - [TCP] SNS Protocol
    #: - [UDP] SNS Protocol
    sns_protocol = 2409, 'sns-protocol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VRTS Registry
    #: - [UDP] VRTS Registry
    vrts_registry = 2410, 'vrts-registry', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netwave AP Management
    #: - [UDP] Netwave AP Management
    netwave_ap_mgmt = 2411, 'netwave-ap-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CDN
    #: - [UDP] CDN
    cdn = 2412, 'cdn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] orion-rmi-reg
    #: - [UDP] orion-rmi-reg
    orion_rmi_reg = 2413, 'orion-rmi-reg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Beeyond
    #: - [UDP] Beeyond
    beeyond = 2414, 'beeyond', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Codima Remote Transaction Protocol
    #: - [UDP] Codima Remote Transaction Protocol
    codima_rtp = 2415, 'codima-rtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RMT Server
    #: - [UDP] RMT Server
    rmtserver = 2416, 'rmtserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Composit Server
    #: - [UDP] Composit Server
    composit_server = 2417, 'composit-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cas
    #: - [UDP] cas
    cas = 2418, 'cas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Attachmate S2S
    #: - [UDP] Attachmate S2S
    attachmate_s2s = 2419, 'attachmate-s2s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DSL Remote Management
    #: - [UDP] DSL Remote Management
    dslremote_mgmt = 2420, 'dslremote-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] G-Talk
    #: - [UDP] G-Talk
    g_talk = 2421, 'g-talk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CRMSBITS
    #: - [UDP] CRMSBITS
    crmsbits = 2422, 'crmsbits', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RNRP
    #: - [UDP] RNRP
    rnrp = 2423, 'rnrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KOFAX-SVR
    #: - [UDP] KOFAX-SVR
    kofax_svr = 2424, 'kofax-svr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu App Manager
    #: - [UDP] Fujitsu App Manager
    fjitsuappmgr = 2425, 'fjitsuappmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VeloCloud MultiPath Protocol
    #: - [UDP] VeloCloud MultiPath Protocol
    vcmp = 2426, 'vcmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Media Gateway Control Protocol Gateway
    #: - [UDP] Media Gateway Control Protocol Gateway
    mgcp_gateway = 2427, 'mgcp-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] One Way Trip Time
    #: - [UDP] One Way Trip Time
    ott = 2428, 'ott', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FT-ROLE
    #: - [UDP] FT-ROLE
    ft_role = 2429, 'ft-role', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] venus
    #: - [UDP] venus
    venus = 2430, 'venus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] venus-se
    #: - [UDP] venus-se
    venus_se = 2431, 'venus-se', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] codasrv
    #: - [UDP] codasrv
    codasrv = 2432, 'codasrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] codasrv-se
    #: - [UDP] codasrv-se
    codasrv_se = 2433, 'codasrv-se', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pxc-epmap
    #: - [UDP] pxc-epmap
    pxc_epmap = 2434, 'pxc-epmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OptiLogic
    #: - [UDP] OptiLogic
    optilogic = 2435, 'optilogic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TOP/X
    #: - [UDP] TOP/X
    topx = 2436, 'topx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message Send Protocol (historic)
    #: - [UDP] Message Send Protocol (historic)
    msp_18 = 18, 'msp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSP
    #: - [UDP] MSP
    msp_2438 = 2438, 'msp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SybaseDBSynch
    #: - [UDP] SybaseDBSynch
    sybasedbsynch = 2439, 'sybasedbsynch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Spearway Lockers
    #: - [UDP] Spearway Lockers
    spearway = 2440, 'spearway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pervasive I*net Data Server
    #: - [UDP] Pervasive I*net Data Server
    pvsw_inet = 2441, 'pvsw-inet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netangel
    #: - [UDP] Netangel
    netangel = 2442, 'netangel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PowerClient Central Storage Facility
    #: - [UDP] PowerClient Central Storage Facility
    powerclientcsf = 2443, 'powerclientcsf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BT PP2 Sectrans
    #: - [UDP] BT PP2 Sectrans
    btpp2sectrans = 2444, 'btpp2sectrans', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DTN1
    #: - [UDP] DTN1
    dtn1 = 2445, 'dtn1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bues_service IANA assigned this well-formed service name as a
    #:   replacement for "bues_service".
    #: - [TCP] bues_service
    #: - [UDP] bues_service IANA assigned this well-formed service name as a
    #:   replacement for "bues_service".
    #: - [UDP] bues_service
    bues_service = 2446, 'bues-service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView NNM daemon
    #: - [UDP] OpenView NNM daemon
    ovwdb = 2447, 'ovwdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hpppsvr
    #: - [UDP] hpppsvr
    hpppssvr = 2448, 'hpppssvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RATL
    #: - [UDP] RATL
    ratl = 2449, 'ratl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netadmin
    #: - [UDP] netadmin
    netadmin = 2450, 'netadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netchat
    #: - [UDP] netchat
    netchat = 2451, 'netchat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SnifferClient
    #: - [UDP] SnifferClient
    snifferclient = 2452, 'snifferclient', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] madge ltd
    #: - [UDP] madge ltd
    madge_ltd = 2453, 'madge-ltd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IndX-DDS
    #: - [UDP] IndX-DDS
    indx_dds = 2454, 'indx-dds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAGO-IO-SYSTEM
    #: - [UDP] WAGO-IO-SYSTEM
    wago_io_system = 2455, 'wago-io-system', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] altav-remmgt
    #: - [UDP] altav-remmgt
    altav_remmgt = 2456, 'altav-remmgt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rapido_IP
    #: - [UDP] Rapido_IP
    rapido_ip = 2457, 'rapido-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] griffin
    #: - [UDP] griffin
    griffin = 2458, 'griffin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Community
    #: - [UDP] Community
    xrpl = 2459, 'xrpl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ms-theater
    #: - [UDP] ms-theater
    ms_theater = 2460, 'ms-theater', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qadmifoper
    #: - [UDP] qadmifoper
    qadmifoper = 2461, 'qadmifoper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qadmifevent
    #: - [UDP] qadmifevent
    qadmifevent = 2462, 'qadmifevent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LSI RAID Management
    #: - [UDP] LSI RAID Management
    lsi_raid_mgmt = 2463, 'lsi-raid-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DirecPC SI
    #: - [UDP] DirecPC SI
    direcpc_si = 2464, 'direcpc-si', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Load Balance Management
    #: - [UDP] Load Balance Management
    lbm = 2465, 'lbm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Load Balance Forwarding
    #: - [UDP] Load Balance Forwarding
    lbf = 2466, 'lbf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] High Criteria
    #: - [UDP] High Criteria
    high_criteria = 2467, 'high-criteria', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qip_msgd
    #: - [UDP] qip_msgd
    qip_msgd = 2468, 'qip-msgd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MTI-TCS-COMM
    #: - [UDP] MTI-TCS-COMM
    mti_tcs_comm = 2469, 'mti-tcs-comm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] taskman port
    #: - [UDP] taskman port
    taskman_port = 2470, 'taskman-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SeaODBC
    #: - [UDP] SeaODBC
    seaodbc = 2471, 'seaodbc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] C3
    #: - [UDP] C3
    c3 = 2472, 'c3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aker-cdp
    #: - [UDP] Aker-cdp
    aker_cdp = 2473, 'aker-cdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vital Analysis
    #: - [UDP] Vital Analysis
    vitalanalysis = 2474, 'vitalanalysis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACE Server
    #: - [UDP] ACE Server
    ace_server = 2475, 'ace-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACE Server Propagation
    #: - [UDP] ACE Server Propagation
    ace_svr_prop = 2476, 'ace-svr-prop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SecurSight Certificate Valifation Service
    #: - [UDP] SecurSight Certificate Valifation Service
    ssm_cvs = 2477, 'ssm-cvs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SecurSight Authentication Server (SSL)
    #: - [UDP] SecurSight Authentication Server (SSL)
    ssm_cssps = 2478, 'ssm-cssps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SecurSight Event Logging Server (SSL)
    #: - [UDP] SecurSight Event Logging Server (SSL)
    ssm_els = 2479, 'ssm-els', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Informatica PowerExchange Listener
    #: - [UDP] Informatica PowerExchange Listener
    powerexchange = 2480, 'powerexchange', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle GIOP
    #: - [UDP] Oracle GIOP
    giop = 2481, 'giop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle GIOP SSL
    #: - [UDP] Oracle GIOP SSL
    giop_ssl = 2482, 'giop-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle TTC
    #: - [UDP] Oracle TTC
    ttc = 2483, 'ttc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle TTC SSL
    #: - [UDP] Oracle TTC SSL
    ttc_ssl = 2484, 'ttc-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net Objects1
    #: - [UDP] Net Objects1
    netobjects1 = 2485, 'netobjects1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net Objects2
    #: - [UDP] Net Objects2
    netobjects2 = 2486, 'netobjects2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Policy Notice Service
    #: - [UDP] Policy Notice Service
    pns = 2487, 'pns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Moy Corporation
    #: - [UDP] Moy Corporation
    moy_corp = 2488, 'moy-corp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TSILB
    #: - [UDP] TSILB
    tsilb = 2489, 'tsilb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qip_qdhcp
    #: - [UDP] qip_qdhcp
    qip_qdhcp = 2490, 'qip-qdhcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Conclave CPP
    #: - [UDP] Conclave CPP
    conclave_cpp = 2491, 'conclave-cpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GROOVE
    #: - [UDP] GROOVE
    groove = 2492, 'groove', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talarian MQS
    #: - [UDP] Talarian MQS
    talarian_mqs = 2493, 'talarian-mqs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC AR
    #: - [UDP] BMC AR
    bmc_ar = 2494, 'bmc-ar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fast Remote Services
    #: - [UDP] Fast Remote Services
    fast_rem_serv = 2495, 'fast-rem-serv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DIRGIS
    #: - [UDP] DIRGIS
    dirgis = 2496, 'dirgis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quad DB
    #: - [UDP] Quad DB
    quaddb = 2497, 'quaddb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ODN-CasTraq
    #: - [UDP] ODN-CasTraq
    odn_castraq = 2498, 'odn-castraq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UniControl
    #: - [UDP] UniControl
    unicontrol_2437 = 2437, 'unicontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UniControl
    #: - [UDP] UniControl
    unicontrol_2499 = 2499, 'unicontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Resource Tracking system server
    #: - [UDP] Resource Tracking system server
    rtsserv = 2500, 'rtsserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Resource Tracking system client
    #: - [UDP] Resource Tracking system client
    rtsclient = 2501, 'rtsclient', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kentrox Protocol
    #: - [UDP] Kentrox Protocol
    kentrox_prot = 2502, 'kentrox-prot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NMS-DPNSS
    #: - [UDP] NMS-DPNSS
    nms_dpnss = 2503, 'nms-dpnss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WLBS
    #: - [UDP] WLBS
    wlbs = 2504, 'wlbs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PowerPlay Control
    #: - [UDP] PowerPlay Control
    ppcontrol = 2505, 'ppcontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] jbroker
    #: - [UDP] jbroker
    jbroker = 2506, 'jbroker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] spock
    #: - [UDP] spock
    spock = 2507, 'spock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JDataStore
    #: - [UDP] JDataStore
    jdatastore = 2508, 'jdatastore', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fjmpss
    #: - [UDP] fjmpss
    fjmpss = 2509, 'fjmpss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fjappmgrbulk
    #: - [UDP] fjappmgrbulk
    fjappmgrbulk = 2510, 'fjappmgrbulk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Metastorm
    #: - [UDP] Metastorm
    metastorm = 2511, 'metastorm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Citrix IMA
    #: - [UDP] Citrix IMA
    citrixima = 2512, 'citrixima', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Citrix ADMIN
    #: - [UDP] Citrix ADMIN
    citrixadmin = 2513, 'citrixadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Facsys NTP
    #: - [UDP] Facsys NTP
    facsys_ntp = 2514, 'facsys-ntp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Facsys Router
    #: - [UDP] Facsys Router
    facsys_router = 2515, 'facsys-router', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Main Control
    #: - [UDP] Main Control
    maincontrol = 2516, 'maincontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] H.323 Annex E Call Control Signalling Transport
    #: - [UDP] H.323 Annex E Call Control Signalling Transport
    call_sig_trans = 2517, 'call-sig-trans', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Willy
    #: - [UDP] Willy
    willy = 2518, 'willy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] globmsgsvc
    #: - [UDP] globmsgsvc
    globmsgsvc = 2519, 'globmsgsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pervasive Listener
    #: - [UDP] Pervasive Listener
    pvsw = 2520, 'pvsw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Adaptec Manager
    #: - [UDP] Adaptec Manager
    adaptecmgr = 2521, 'adaptecmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WinDb
    #: - [UDP] WinDb
    windb = 2522, 'windb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Qke LLC V.3
    #: - [UDP] Qke LLC V.3
    qke_llc_v3 = 2523, 'qke-llc-v3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Optiwave License Management
    #: - [UDP] Optiwave License Management
    optiwave_lm = 2524, 'optiwave-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS V-Worlds
    #: - [UDP] MS V-Worlds
    ms_v_worlds = 2525, 'ms-v-worlds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMA License Manager
    #: - [UDP] EMA License Manager
    ema_sent_lm = 2526, 'ema-sent-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IQ Server
    #: - [UDP] IQ Server
    iqserver = 2527, 'iqserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NCR CCL IANA assigned this well-formed service name as a replacement
    #:   for "ncr_ccl".
    #: - [TCP] NCR CCL
    #: - [UDP] NCR CCL IANA assigned this well-formed service name as a replacement
    #:   for "ncr_ccl".
    #: - [UDP] NCR CCL
    ncr_ccl = 2528, 'ncr-ccl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UTS FTP
    #: - [UDP] UTS FTP
    utsftp = 2529, 'utsftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VR Commerce
    #: - [UDP] VR Commerce
    vrcommerce = 2530, 'vrcommerce', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITO-E GUI
    #: - [UDP] ITO-E GUI
    ito_e_gui = 2531, 'ito-e-gui', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OVTOPMD
    #: - [UDP] OVTOPMD
    ovtopmd = 2532, 'ovtopmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SnifferServer
    #: - [UDP] SnifferServer
    snifferserver = 2533, 'snifferserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Combox Web Access
    #: - [UDP] Combox Web Access
    combox_web_acc = 2534, 'combox-web-acc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MADCAP
    #: - [UDP] MADCAP
    madcap = 2535, 'madcap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] btpp2audctr1
    #: - [UDP] btpp2audctr1
    btpp2audctr1 = 2536, 'btpp2audctr1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Upgrade Protocol
    #: - [UDP] Upgrade Protocol
    upgrade = 2537, 'upgrade', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vnwk-prapi
    #: - [UDP] vnwk-prapi
    vnwk_prapi = 2538, 'vnwk-prapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSI Admin
    #: - [UDP] VSI Admin
    vsiadmin = 2539, 'vsiadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LonWorks2
    #: - [UDP] LonWorks2
    lonworks2 = 2541, 'lonworks2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] uDraw(Graph)
    #: - [UDP] uDraw(Graph)
    udrawgraph = 2542, 'udrawgraph', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] REFTEK
    #: - [UDP] REFTEK
    reftek = 2543, 'reftek', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Management Daemon Refresh
    #: - [UDP] Management Daemon Refresh
    novell_zen = 2544, 'novell-zen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sis-emt
    #: - [UDP] sis-emt
    sis_emt = 2545, 'sis-emt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vytalvaultbrtp
    #: - [UDP] vytalvaultbrtp
    vytalvaultbrtp = 2546, 'vytalvaultbrtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vytalvaultvsmp
    #: - [UDP] vytalvaultvsmp
    vytalvaultvsmp = 2547, 'vytalvaultvsmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vytalvaultpipe
    #: - [UDP] vytalvaultpipe
    vytalvaultpipe = 2548, 'vytalvaultpipe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPASS
    #: - [UDP] IPASS
    ipass = 2549, 'ipass', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ADS
    #: - [UDP] ADS
    ads = 2550, 'ads', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISG UDA Server
    #: - [UDP] ISG UDA Server
    isg_uda_server = 2551, 'isg-uda-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Call Logging
    #: - [UDP] Call Logging
    call_logging = 2552, 'call-logging', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] efidiningport
    #: - [UDP] efidiningport
    efidiningport = 2553, 'efidiningport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VCnet-Link v10
    #: - [UDP] VCnet-Link v10
    vcnet_link_v10 = 2554, 'vcnet-link-v10', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compaq WCP
    #: - [UDP] Compaq WCP
    compaq_wcp = 2555, 'compaq-wcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nicetec-nmsvc
    #: - [UDP] nicetec-nmsvc
    nicetec_nmsvc = 2556, 'nicetec-nmsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nicetec-mgmt
    #: - [UDP] nicetec-mgmt
    nicetec_mgmt = 2557, 'nicetec-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCLE Multi Media
    #: - [UDP] PCLE Multi Media
    pclemultimedia = 2558, 'pclemultimedia', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LSTP
    #: - [UDP] LSTP
    lstp = 2559, 'lstp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] labrat
    #: - [UDP] labrat
    labrat = 2560, 'labrat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MosaixCC
    #: - [UDP] MosaixCC
    mosaixcc = 2561, 'mosaixcc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Delibo
    #: - [UDP] Delibo
    delibo = 2562, 'delibo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CTI Redwood
    #: - [UDP] CTI Redwood
    cti_redwood = 2563, 'cti-redwood', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP 3000 NS/VT block mode telnet
    #: - [UDP] HP 3000 NS/VT block mode telnet
    hp_3000_telnet = 2564, 'hp-3000-telnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Coordinator Server
    #: - [UDP] Coordinator Server
    coord_svr = 2565, 'coord-svr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pcs-pcw
    #: - [UDP] pcs-pcw
    pcs_pcw = 2566, 'pcs-pcw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cisco Line Protocol
    #: - [UDP] Cisco Line Protocol
    clp = 2567, 'clp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPAM TRAP
    #: - [UDP] SPAM TRAP
    spamtrap = 2568, 'spamtrap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sonus Call Signal
    #: - [UDP] Sonus Call Signal
    sonuscallsig = 2569, 'sonuscallsig', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HS Port
    #: - [UDP] HS Port
    hs_port = 2570, 'hs-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CECSVC
    #: - [UDP] CECSVC
    cecsvc = 2571, 'cecsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBP
    #: - [UDP] IBP
    ibp = 2572, 'ibp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trust Establish
    #: - [UDP] Trust Establish
    trustestablish = 2573, 'trustestablish', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Blockade BPSP
    #: - [UDP] Blockade BPSP
    blockade_bpsp = 2574, 'blockade-bpsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HL7
    #: - [UDP] HL7
    hl7 = 2575, 'hl7', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TCL Pro Debugger
    #: - [UDP] TCL Pro Debugger
    tclprodebugger = 2576, 'tclprodebugger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Scriptics Lsrvr
    #: - [UDP] Scriptics Lsrvr
    scipticslsrvr = 2577, 'scipticslsrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RVS ISDN DCP
    #: - [UDP] RVS ISDN DCP
    rvs_isdn_dcp = 2578, 'rvs-isdn-dcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mpfoncl
    #: - [UDP] mpfoncl
    mpfoncl = 2579, 'mpfoncl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tributary
    #: - [UDP] Tributary
    tributary = 2580, 'tributary', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARGIS TE
    #: - [UDP] ARGIS TE
    argis_te = 2581, 'argis-te', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARGIS DS
    #: - [UDP] ARGIS DS
    argis_ds = 2582, 'argis-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cyaserv
    #: - [UDP] cyaserv
    cyaserv = 2584, 'cyaserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETX Server
    #: - [UDP] NETX Server
    netx_server = 2585, 'netx-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETX Agent
    #: - [UDP] NETX Agent
    netx_agent = 2586, 'netx-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MASC
    #: - [UDP] MASC
    masc = 2587, 'masc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Privilege
    #: - [UDP] Privilege
    privilege = 2588, 'privilege', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] quartus tcl
    #: - [UDP] quartus tcl
    quartus_tcl = 2589, 'quartus-tcl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] idotdist
    #: - [UDP] idotdist
    idotdist = 2590, 'idotdist', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Maytag Shuffle
    #: - [UDP] Maytag Shuffle
    maytagshuffle = 2591, 'maytagshuffle', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netrek
    #: - [UDP] netrek
    netrek = 2592, 'netrek', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MNS Mail Notice Service
    #: - [UDP] MNS Mail Notice Service
    mns_mail = 2593, 'mns-mail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Base Server
    #: - [UDP] Data Base Server
    dts = 2594, 'dts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] World Fusion 1
    #: - [UDP] World Fusion 1
    worldfusion1 = 2595, 'worldfusion1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] World Fusion 2
    #: - [UDP] World Fusion 2
    worldfusion2 = 2596, 'worldfusion2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Homestead Glory
    #: - [UDP] Homestead Glory
    homesteadglory = 2597, 'homesteadglory', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Citrix MA Client
    #: - [UDP] Citrix MA Client
    citriximaclient = 2598, 'citriximaclient', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Snap Discovery
    #: - [UDP] Snap Discovery
    snapd = 2599, 'snapd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HPSTGMGR
    #: - [UDP] HPSTGMGR
    hpstgmgr = 2600, 'hpstgmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] discp client
    #: - [UDP] discp client
    discp_client = 2601, 'discp-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] discp server
    #: - [UDP] discp server
    discp_server = 2602, 'discp-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Meter
    #: - [UDP] Service Meter
    servicemeter = 2603, 'servicemeter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NSC CCS
    #: - [UDP] NSC CCS
    nsc_ccs = 2604, 'nsc-ccs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NSC POSA
    #: - [UDP] NSC POSA
    nsc_posa = 2605, 'nsc-posa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dell Netmon
    #: - [UDP] Dell Netmon
    netmon = 2606, 'netmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dell Connection
    #: - [UDP] Dell Connection
    connection = 2607, 'connection', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wag Service
    #: - [UDP] Wag Service
    wag_service = 2608, 'wag-service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] System Monitor
    #: - [UDP] System Monitor
    system_monitor = 2609, 'system-monitor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VersaTek
    #: - [UDP] VersaTek
    versa_tek = 2610, 'versa-tek', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LIONHEAD
    #: - [UDP] LIONHEAD
    lionhead = 2611, 'lionhead', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Qpasa Agent
    #: - [UDP] Qpasa Agent
    qpasa_agent = 2612, 'qpasa-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMNTUBootstrap
    #: - [UDP] SMNTUBootstrap
    smntubootstrap = 2613, 'smntubootstrap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Never Offline
    #: - [UDP] Never Offline
    neveroffline = 2614, 'neveroffline', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] firepower
    #: - [UDP] firepower
    firepower = 2615, 'firepower', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] appswitch-emp
    #: - [UDP] appswitch-emp
    appswitch_emp = 2616, 'appswitch-emp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Clinical Context Managers
    #: - [UDP] Clinical Context Managers
    cmadmin = 2617, 'cmadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Priority E-Com
    #: - [UDP] Priority E-Com
    priority_e_com = 2618, 'priority-e-com', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bruce
    #: - [UDP] bruce
    bruce = 2619, 'bruce', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LPSRecommender
    #: - [UDP] LPSRecommender
    lpsrecommender = 2620, 'lpsrecommender', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Miles Apart Jukebox Server
    #: - [UDP] Miles Apart Jukebox Server
    miles_apart = 2621, 'miles-apart', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MetricaDBC
    #: - [UDP] MetricaDBC
    metricadbc = 2622, 'metricadbc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LMDP
    #: - [UDP] LMDP
    lmdp = 2623, 'lmdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aria
    #: - [UDP] Aria
    aria = 2624, 'aria', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Blwnkl Port
    #: - [UDP] Blwnkl Port
    blwnkl_port = 2625, 'blwnkl-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gbjd816
    #: - [UDP] gbjd816
    gbjd816 = 2626, 'gbjd816', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Moshe Beeri
    #: - [UDP] Moshe Beeri
    moshebeeri = 2627, 'moshebeeri', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DICT
    #: - [UDP] DICT
    dict = 2628, 'dict', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sitara Server
    #: - [UDP] Sitara Server
    sitaraserver = 2629, 'sitaraserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sitara Management
    #: - [UDP] Sitara Management
    sitaramgmt = 2630, 'sitaramgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sitara Dir
    #: - [UDP] Sitara Dir
    sitaradir = 2631, 'sitaradir', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IRdg Post
    #: - [UDP] IRdg Post
    irdg_post = 2632, 'irdg-post', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] InterIntelli
    #: - [UDP] InterIntelli
    interintelli = 2633, 'interintelli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PK Electronics
    #: - [UDP] PK Electronics
    pk_electronics = 2634, 'pk-electronics', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Back Burner
    #: - [UDP] Back Burner
    backburner = 2635, 'backburner', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Solve
    #: - [UDP] Solve
    solve = 2636, 'solve', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Import Document Service
    #: - [UDP] Import Document Service
    imdocsvc = 2637, 'imdocsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sybase Anywhere
    #: - [UDP] Sybase Anywhere
    sybaseanywhere = 2638, 'sybaseanywhere', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMInet
    #: - [UDP] AMInet
    aminet = 2639, 'aminet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alcorn McBride Inc protocol used for device control
    #: - [UDP] Alcorn McBride Inc protocol used for device control
    ami_control = 2640, 'ami-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HDL Server
    #: - [UDP] HDL Server
    hdl_srv = 2641, 'hdl-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tragic
    #: - [UDP] Tragic
    tragic = 2642, 'tragic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GTE-SAMP
    #: - [UDP] GTE-SAMP
    gte_samp = 2643, 'gte-samp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Travsoft IPX Tunnel
    #: - [UDP] Travsoft IPX Tunnel
    travsoft_ipx_t = 2644, 'travsoft-ipx-t', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novell IPX CMD
    #: - [UDP] Novell IPX CMD
    novell_ipx_cmd = 2645, 'novell-ipx-cmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AND License Manager
    #: - [UDP] AND License Manager
    and_lm = 2646, 'and-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SyncServer
    #: - [UDP] SyncServer
    syncserver = 2647, 'syncserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Upsnotifyprot
    #: - [UDP] Upsnotifyprot
    upsnotifyprot = 2648, 'upsnotifyprot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VPSIPPORT
    #: - [UDP] VPSIPPORT
    vpsipport = 2649, 'vpsipport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eristwoguns
    #: - [UDP] eristwoguns
    eristwoguns = 2650, 'eristwoguns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EBInSite
    #: - [UDP] EBInSite
    ebinsite = 2651, 'ebinsite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] InterPathPanel
    #: - [UDP] InterPathPanel
    interpathpanel = 2652, 'interpathpanel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sonus
    #: - [UDP] Sonus
    sonus = 2653, 'sonus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Corel VNC Admin IANA assigned this well-formed service name as a
    #:   replacement for "corel_vncadmin".
    #: - [TCP] Corel VNC Admin
    #: - [UDP] Corel VNC Admin IANA assigned this well-formed service name as a
    #:   replacement for "corel_vncadmin".
    #: - [UDP] Corel VNC Admin
    corel_vncadmin = 2654, 'corel-vncadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UNIX Nt Glue
    #: - [UDP] UNIX Nt Glue
    unglue = 2655, 'unglue', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kana
    #: - [UDP] Kana
    kana = 2656, 'kana', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNS Dispatcher
    #: - [UDP] SNS Dispatcher
    sns_dispatcher = 2657, 'sns-dispatcher', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNS Admin
    #: - [UDP] SNS Admin
    sns_admin = 2658, 'sns-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNS Query
    #: - [UDP] SNS Query
    sns_query = 2659, 'sns-query', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GC Monitor
    #: - [UDP] GC Monitor
    gcmonitor = 2660, 'gcmonitor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OLHOST
    #: - [UDP] OLHOST
    olhost = 2661, 'olhost', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BinTec-CAPI
    #: - [UDP] BinTec-CAPI
    bintec_capi = 2662, 'bintec-capi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BinTec-TAPI
    #: - [UDP] BinTec-TAPI
    bintec_tapi = 2663, 'bintec-tapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Patrol for MQ GM
    #: - [UDP] Patrol for MQ GM
    patrol_mq_gm = 2664, 'patrol-mq-gm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Patrol for MQ NM
    #: - [UDP] Patrol for MQ NM
    patrol_mq_nm = 2665, 'patrol-mq-nm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] extensis
    #: - [UDP] extensis
    extensis = 2666, 'extensis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alarm Clock Server
    #: - [UDP] Alarm Clock Server
    alarm_clock_s = 2667, 'alarm-clock-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alarm Clock Client
    #: - [UDP] Alarm Clock Client
    alarm_clock_c = 2668, 'alarm-clock-c', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TOAD
    #: - [UDP] TOAD
    toad = 2669, 'toad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TVE Announce
    #: - [UDP] TVE Announce
    tve_announce = 2670, 'tve-announce', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] newlixreg
    #: - [UDP] newlixreg
    newlixreg = 2671, 'newlixreg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nhserver
    #: - [UDP] nhserver
    nhserver = 2672, 'nhserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] First Call 42
    #: - [UDP] First Call 42
    firstcall42 = 2673, 'firstcall42', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ewnn
    #: - [UDP] ewnn
    ewnn = 2674, 'ewnn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TTC ETAP
    #: - [UDP] TTC ETAP
    ttc_etap = 2675, 'ttc-etap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SIMSLink
    #: - [UDP] SIMSLink
    simslink = 2676, 'simslink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gadget Gate 1 Way
    #: - [UDP] Gadget Gate 1 Way
    gadgetgate1way = 2677, 'gadgetgate1way', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gadget Gate 2 Way
    #: - [UDP] Gadget Gate 2 Way
    gadgetgate2way = 2678, 'gadgetgate2way', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sync Server SSL
    #: - [UDP] Sync Server SSL
    syncserverssl = 2679, 'syncserverssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pxc-sapxom
    #: - [UDP] pxc-sapxom
    pxc_sapxom = 2680, 'pxc-sapxom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mpnjsomb
    #: - [UDP] mpnjsomb
    mpnjsomb = 2681, 'mpnjsomb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NCDLoadBalance
    #: - [UDP] NCDLoadBalance
    ncdloadbalance = 2683, 'ncdloadbalance', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mpnjsosv
    #: - [UDP] mpnjsosv
    mpnjsosv = 2684, 'mpnjsosv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mpnjsocl
    #: - [UDP] mpnjsocl
    mpnjsocl = 2685, 'mpnjsocl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mpnjsomg
    #: - [UDP] mpnjsomg
    mpnjsomg = 2686, 'mpnjsomg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pq-lic-mgmt
    #: - [UDP] pq-lic-mgmt
    pq_lic_mgmt = 2687, 'pq-lic-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] md-cf-http
    #: - [UDP] md-cf-http
    md_cg_http = 2688, 'md-cg-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FastLynx
    #: - [UDP] FastLynx
    fastlynx = 2689, 'fastlynx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP NNM Embedded Database
    #: - [UDP] HP NNM Embedded Database
    hp_nnm_data = 2690, 'hp-nnm-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITInternet ISM Server
    #: - [UDP] ITInternet ISM Server
    itinternet = 2691, 'itinternet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Admins LMS
    #: - [UDP] Admins LMS
    admins_lms = 2692, 'admins-lms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unassigned
    #: - [UDP] Unassigned
    unassigned_2693 = 2693, 'unassigned', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pwrsevent
    #: - [UDP] pwrsevent
    pwrsevent = 2694, 'pwrsevent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSPREAD
    #: - [UDP] VSPREAD
    vspread = 2695, 'vspread', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unify Admin
    #: - [UDP] Unify Admin
    unifyadmin = 2696, 'unifyadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oce SNMP Trap Port
    #: - [UDP] Oce SNMP Trap Port
    oce_snmp_trap = 2697, 'oce-snmp-trap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCK-IVPIP
    #: - [UDP] MCK-IVPIP
    mck_ivpip = 2698, 'mck-ivpip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Csoft Plus Client
    #: - [UDP] Csoft Plus Client
    csoft_plusclnt = 2699, 'csoft-plusclnt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tqdata
    #: - [UDP] tqdata
    tqdata = 2700, 'tqdata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMS RCINFO
    #: - [UDP] SMS RCINFO
    sms_rcinfo = 2701, 'sms-rcinfo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMS XFER
    #: - [UDP] SMS XFER
    sms_xfer = 2702, 'sms-xfer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMS CHAT
    #: - [UDP] SMS CHAT
    sms_chat = 2703, 'sms-chat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMS REMCTRL
    #: - [UDP] SMS REMCTRL
    sms_remctrl = 2704, 'sms-remctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SDS Admin
    #: - [UDP] SDS Admin
    sds_admin = 2705, 'sds-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NCD Mirroring
    #: - [UDP] NCD Mirroring
    ncdmirroring = 2706, 'ncdmirroring', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMCSYMAPIPORT
    #: - [UDP] EMCSYMAPIPORT
    emcsymapiport = 2707, 'emcsymapiport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Banyan-Net
    #: - [UDP] Banyan-Net
    banyan_net = 2708, 'banyan-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Supermon
    #: - [UDP] Supermon
    supermon = 2709, 'supermon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSO Service
    #: - [UDP] SSO Service
    sso_service = 2710, 'sso-service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSO Control
    #: - [UDP] SSO Control
    sso_control = 2711, 'sso-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Axapta Object Communication Protocol
    #: - [UDP] Axapta Object Communication Protocol
    aocp = 2712, 'aocp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Raven Trinity Broker Service
    #: - [UDP] Raven Trinity Broker Service
    raventbs = 2713, 'raventbs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Raven Trinity Data Mover
    #: - [UDP] Raven Trinity Data Mover
    raventdm = 2714, 'raventdm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HPSTGMGR2
    #: - [UDP] HPSTGMGR2
    hpstgmgr2 = 2715, 'hpstgmgr2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inova IP Disco
    #: - [UDP] Inova IP Disco
    inova_ip_disco = 2716, 'inova-ip-disco', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PN REQUESTER
    #: - [UDP] PN REQUESTER
    pn_requester = 2717, 'pn-requester', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PN REQUESTER 2
    #: - [UDP] PN REQUESTER 2
    pn_requester2 = 2718, 'pn-requester2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Scan & Change
    #: - [UDP] Scan & Change
    scan_change = 2719, 'scan-change', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] wkars
    #: - [UDP] wkars
    wkars = 2720, 'wkars', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Smart Diagnose
    #: - [UDP] Smart Diagnose
    smart_diagnose = 2721, 'smart-diagnose', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Proactive Server
    #: - [UDP] Proactive Server
    proactivesrvr = 2722, 'proactivesrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WatchDog NT Protocol
    #: - [UDP] WatchDog NT Protocol
    watchdog_nt = 2723, 'watchdog-nt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qotps
    #: - [UDP] qotps
    qotps = 2724, 'qotps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSOLAP PTP2
    #: - [UDP] MSOLAP PTP2
    msolap_ptp2 = 2725, 'msolap-ptp2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TAMS
    #: - [UDP] TAMS
    tams = 2726, 'tams', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Media Gateway Control Protocol Call Agent
    #: - [UDP] Media Gateway Control Protocol Call Agent
    mgcp_callagent = 2727, 'mgcp-callagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SQDR
    #: - [UDP] SQDR
    sqdr = 2728, 'sqdr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TCIM Control
    #: - [UDP] TCIM Control
    tcim_control = 2729, 'tcim-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NEC RaidPlus
    #: - [UDP] NEC RaidPlus
    nec_raidplus = 2730, 'nec-raidplus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fyre Messanger
    #: - [UDP] Fyre Messanger
    fyre_messanger = 2731, 'fyre-messanger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] G5M
    #: - [UDP] G5M
    g5m = 2732, 'g5m', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Signet CTF
    #: - [UDP] Signet CTF
    signet_ctf = 2733, 'signet-ctf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CCS Software
    #: - [UDP] CCS Software
    ccs_software = 2734, 'ccs-software', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetIQ Monitor Console
    #: - [UDP] NetIQ Monitor Console
    netiq_mc = 2735, 'netiq-mc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RADWIZ NMS SRV
    #: - [UDP] RADWIZ NMS SRV
    radwiz_nms_srv = 2736, 'radwiz-nms-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SRP Feedback
    #: - [UDP] SRP Feedback
    srp_feedback = 2737, 'srp-feedback', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NDL TCP-OSI Gateway
    #: - [UDP] NDL TCP-OSI Gateway
    ndl_tcp_ois_gw = 2738, 'ndl-tcp-ois-gw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TN Timing
    #: - [UDP] TN Timing
    tn_timing = 2739, 'tn-timing', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alarm
    #: - [UDP] Alarm
    alarm = 2740, 'alarm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TSB
    #: - [UDP] TSB
    tsb = 2741, 'tsb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TSB2
    #: - [UDP] TSB2
    tsb2 = 2742, 'tsb2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] murx
    #: - [UDP] murx
    murx = 2743, 'murx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] honyaku
    #: - [UDP] honyaku
    honyaku = 2744, 'honyaku', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] URBISNET
    #: - [UDP] URBISNET
    urbisnet = 2745, 'urbisnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CPUDPENCAP
    #: - [UDP] CPUDPENCAP
    cpudpencap = 2746, 'cpudpencap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    fjippol_swrly = 2747, 'fjippol-swrly', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    fjippol_polsvr = 2748, 'fjippol-polsvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    fjippol_cnsl = 2749, 'fjippol-cnsl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    fjippol_port1 = 2750, 'fjippol-port1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    fjippol_port2 = 2751, 'fjippol-port2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSISYS ACCESS
    #: - [UDP] RSISYS ACCESS
    rsisysaccess = 2752, 'rsisysaccess', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] de-spot
    #: - [UDP] de-spot
    de_spot = 2753, 'de-spot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APOLLO CC
    #: - [UDP] APOLLO CC
    apollo_cc = 2754, 'apollo-cc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Express Pay
    #: - [UDP] Express Pay
    expresspay = 2755, 'expresspay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] simplement-tie
    #: - [UDP] simplement-tie
    simplement_tie = 2756, 'simplement-tie', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CNRP
    #: - [UDP] CNRP
    cnrp = 2757, 'cnrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APOLLO Status
    #: - [UDP] APOLLO Status
    apollo_status = 2758, 'apollo-status', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APOLLO GMS
    #: - [UDP] APOLLO GMS
    apollo_gms = 2759, 'apollo-gms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Saba MS
    #: - [UDP] Saba MS
    sabams = 2760, 'sabams', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DICOM ISCL
    #: - [UDP] DICOM ISCL
    dicom_iscl = 2761, 'dicom-iscl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DICOM TLS
    #: - [UDP] DICOM TLS
    dicom_tls = 2762, 'dicom-tls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Desktop DNA
    #: - [UDP] Desktop DNA
    desktop_dna = 2763, 'desktop-dna', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Insurance
    #: - [UDP] Data Insurance
    data_insurance = 2764, 'data-insurance', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qip-audup
    #: - [UDP] qip-audup
    qip_audup = 2765, 'qip-audup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compaq SCP
    #: - [UDP] Compaq SCP
    compaq_scp = 2766, 'compaq-scp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UADTC
    #: - [UDP] UADTC
    uadtc = 2767, 'uadtc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UACS
    #: - [UDP] UACS
    uacs = 2768, 'uacs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eXcE
    #: - [UDP] eXcE
    exce = 2769, 'exce', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Veronica
    #: - [UDP] Veronica
    veronica = 2770, 'veronica', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vergence CM
    #: - [UDP] Vergence CM
    vergencecm = 2771, 'vergencecm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] auris
    #: - [UDP] auris
    auris = 2772, 'auris', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RBackup Remote Backup
    #: - [UDP] RBackup Remote Backup
    rbakcup1 = 2773, 'rbakcup1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RBackup Remote Backup
    #: - [UDP] RBackup Remote Backup
    rbakcup2 = 2774, 'rbakcup2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMPP
    #: - [UDP] SMPP
    smpp = 2775, 'smpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ridgeway Systems & Software
    #: - [UDP] Ridgeway Systems & Software
    ridgeway1 = 2776, 'ridgeway1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ridgeway Systems & Software
    #: - [UDP] Ridgeway Systems & Software
    ridgeway2 = 2777, 'ridgeway2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gwen-Sonya
    #: - [UDP] Gwen-Sonya
    gwen_sonya = 2778, 'gwen-sonya', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LBC Sync
    #: - [UDP] LBC Sync
    lbc_sync = 2779, 'lbc-sync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LBC Control
    #: - [UDP] LBC Control
    lbc_control = 2780, 'lbc-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] whosells
    #: - [UDP] whosells
    whosells = 2781, 'whosells', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] everydayrc
    #: - [UDP] everydayrc
    everydayrc = 2782, 'everydayrc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AISES
    #: - [UDP] AISES
    aises = 2783, 'aises', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] world wide web - development
    #: - [UDP] world wide web - development
    www_dev = 2784, 'www-dev', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] aic-np
    #: - [UDP] aic-np
    aic_np = 2785, 'aic-np', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] aic-oncrpc - Destiny MCD database
    #: - [UDP] aic-oncrpc - Destiny MCD database
    aic_oncrpc = 2786, 'aic-oncrpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] piccolo - Cornerstone Software
    #: - [UDP] piccolo - Cornerstone Software
    piccolo = 2787, 'piccolo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetWare Loadable Module - Seagate Software
    #: - [UDP] NetWare Loadable Module - Seagate Software
    fryeserv = 2788, 'fryeserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Media Agent
    #: - [UDP] Media Agent
    media_agent = 2789, 'media-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PLG Proxy
    #: - [UDP] PLG Proxy
    plgproxy = 2790, 'plgproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MT Port Registrator
    #: - [UDP] MT Port Registrator
    mtport_regist = 2791, 'mtport-regist', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] f5-globalsite
    #: - [UDP] f5-globalsite
    f5_globalsite = 2792, 'f5-globalsite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] initlsmsad
    #: - [UDP] initlsmsad
    initlsmsad = 2793, 'initlsmsad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Uniform Resource Platform
    #: - [UDP] Uniform Resource Platform
    urp = 2794, 'urp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LiveStats
    #: - [UDP] LiveStats
    livestats = 2795, 'livestats', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ac-tech
    #: - [UDP] ac-tech
    ac_tech = 2796, 'ac-tech', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] esp-encap
    #: - [UDP] esp-encap
    esp_encap = 2797, 'esp-encap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TMESIS-UPShot
    #: - [UDP] TMESIS-UPShot
    tmesis_upshot = 2798, 'tmesis-upshot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICON Discover
    #: - [UDP] ICON Discover
    icon_discover = 2799, 'icon-discover', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACC RAID
    #: - [UDP] ACC RAID
    acc_raid = 2800, 'acc-raid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IGCP
    #: - [UDP] IGCP
    igcp = 2801, 'igcp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Veritas UDP1
    veritas_udp1 = 2802, 'veritas-udp1', TransportProtocol.udp

    #: - [TCP] btprjctrl
    #: - [UDP] btprjctrl
    btprjctrl = 2803, 'btprjctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] March Networks Digital Video Recorders and Enterprise Service Manager
    #:   products
    #: - [UDP] March Networks Digital Video Recorders and Enterprise Service Manager
    #:   products
    dvr_esm = 2804, 'dvr-esm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WTA WSP-S
    #: - [UDP] WTA WSP-S
    wta_wsp_s = 2805, 'wta-wsp-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cspuni
    #: - [UDP] cspuni
    cspuni = 2806, 'cspuni', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cspmulti
    #: - [UDP] cspmulti
    cspmulti = 2807, 'cspmulti', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] J-LAN-P
    #: - [UDP] J-LAN-P
    j_lan_p = 2808, 'j-lan-p', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CORBA LOC
    #: - [UDP] CORBA LOC
    corbaloc = 2809, 'corbaloc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Active Net Steward
    #: - [UDP] Active Net Steward
    netsteward = 2810, 'netsteward', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GSI FTP
    #: - [UDP] GSI FTP
    gsiftp = 2811, 'gsiftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] atmtcp
    #: - [UDP] atmtcp
    atmtcp = 2812, 'atmtcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] llm-pass
    #: - [UDP] llm-pass
    llm_pass = 2813, 'llm-pass', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] llm-csv
    #: - [UDP] llm-csv
    llm_csv = 2814, 'llm-csv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LBC Measurement
    #: - [UDP] LBC Measurement
    lbc_measure = 2815, 'lbc-measure', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LBC Watchdog
    #: - [UDP] LBC Watchdog
    lbc_watchdog = 2816, 'lbc-watchdog', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rmlnk
    #: - [UDP] rmlnk
    rmlnk = 2818, 'rmlnk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FC Fault Notification
    #: - [UDP] FC Fault Notification
    fc_faultnotify = 2819, 'fc-faultnotify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UniVision
    #: - [UDP] UniVision
    univision = 2820, 'univision', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS Authentication Service
    #: - [UDP] VERITAS Authentication Service
    vrts_at_port = 2821, 'vrts-at-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ka0wuc
    #: - [UDP] ka0wuc
    ka0wuc = 2822, 'ka0wuc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CQG Net/LAN
    #: - [UDP] CQG Net/LAN
    cqg_netlan = 2823, 'cqg-netlan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CQG Net/LAN 1
    #: - [UDP] CQG Net/Lan 1
    cqg_netlan_1 = 2824, 'cqg-netlan-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] slc systemlog
    #: - [UDP] slc systemlog
    slc_systemlog = 2826, 'slc-systemlog', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] slc ctrlrloops
    #: - [UDP] slc ctrlrloops
    slc_ctrlrloops = 2827, 'slc-ctrlrloops', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITM License Manager
    #: - [UDP] ITM License Manager
    itm_lm = 2828, 'itm-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] silkp1
    #: - [UDP] silkp1
    silkp1 = 2829, 'silkp1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] silkp2
    #: - [UDP] silkp2
    silkp2 = 2830, 'silkp2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] silkp3
    #: - [UDP] silkp3
    silkp3 = 2831, 'silkp3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] silkp4
    #: - [UDP] silkp4
    silkp4 = 2832, 'silkp4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] glishd
    #: - [UDP] glishd
    glishd = 2833, 'glishd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EVTP
    #: - [UDP] EVTP
    evtp = 2834, 'evtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EVTP-DATA
    #: - [UDP] EVTP-DATA
    evtp_data = 2835, 'evtp-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] catalyst
    #: - [UDP] catalyst
    catalyst = 2836, 'catalyst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Repliweb
    #: - [UDP] Repliweb
    repliweb = 2837, 'repliweb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Starbot
    #: - [UDP] Starbot
    starbot = 2838, 'starbot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NMSig Port
    #: - [UDP] NMSig Port
    nmsigport_2817 = 2817, 'nmsigport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NMSigPort
    #: - [UDP] NMSigPort
    nmsigport_2839 = 2839, 'nmsigport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] l3-exprt
    #: - [UDP] l3-exprt
    l3_exprt = 2840, 'l3-exprt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] l3-ranger
    #: - [UDP] l3-ranger
    l3_ranger = 2841, 'l3-ranger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] l3-hawk
    #: - [UDP] l3-hawk
    l3_hawk = 2842, 'l3-hawk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PDnet
    #: - [UDP] PDnet
    pdnet = 2843, 'pdnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BPCP POLL
    #: - [UDP] BPCP POLL
    bpcp_poll = 2844, 'bpcp-poll', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BPCP TRAP
    #: - [UDP] BPCP TRAP
    bpcp_trap = 2845, 'bpcp-trap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AIMPP Hello
    #: - [UDP] AIMPP Hello
    aimpp_hello = 2846, 'aimpp-hello', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AIMPP Port Req
    #: - [UDP] AIMPP Port Req
    aimpp_port_req = 2847, 'aimpp-port-req', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMT-BLC-PORT
    #: - [UDP] AMT-BLC-PORT
    amt_blc_port = 2848, 'amt-blc-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FXP Communication
    #: - [UDP] FXP Communication
    fxp_286 = 286, 'fxp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FXP
    #: - [UDP] FXP
    fxp_2849 = 2849, 'fxp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MetaConsole
    #: - [UDP] MetaConsole
    metaconsole = 2850, 'metaconsole', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] webemshttp
    #: - [UDP] webemshttp
    webemshttp = 2851, 'webemshttp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bears-01
    #: - [UDP] bears-01
    bears_01 = 2852, 'bears-01', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISPipes
    #: - [UDP] ISPipes
    ispipes = 2853, 'ispipes', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] InfoMover
    #: - [UDP] InfoMover
    infomover = 2854, 'infomover', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_2855 = 2855, 'reserved', TransportProtocol.udp

    #: - [TCP] cesdinv
    #: - [UDP] cesdinv
    cesdinv = 2856, 'cesdinv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SimCtIP
    #: - [UDP] SimCtIP
    simctlp = 2857, 'simctlp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ECNP
    #: - [UDP] ECNP
    ecnp = 2858, 'ecnp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Active Memory
    #: - [UDP] Active Memory
    activememory = 2859, 'activememory', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dialpad Voice 1
    #: - [UDP] Dialpad Voice 1
    dialpad_voice1 = 2860, 'dialpad-voice1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dialpad Voice 2
    #: - [UDP] Dialpad Voice 2
    dialpad_voice2 = 2861, 'dialpad-voice2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TTG Protocol
    #: - [UDP] TTG Protocol
    ttg_protocol = 2862, 'ttg-protocol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sonar Data
    #: - [UDP] Sonar Data
    sonardata = 2863, 'sonardata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] main 5001 cmd
    #: - [UDP] main 5001 cmd
    astronova_main = 2864, 'astronova-main', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pit-vpn
    #: - [UDP] pit-vpn
    pit_vpn = 2865, 'pit-vpn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iwlistener
    #: - [UDP] iwlistener
    iwlistener = 2866, 'iwlistener', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] esps-portal
    #: - [UDP] esps-portal
    esps_portal = 2867, 'esps-portal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Norman Proprietaqry Events Protocol
    #: - [UDP] Norman Proprietaqry Events Protocol
    npep_messaging = 2868, 'npep-messaging', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICSLAP
    #: - [UDP] ICSLAP
    icslap = 2869, 'icslap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] daishi
    #: - [UDP] daishi
    daishi = 2870, 'daishi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSI Select Play
    #: - [UDP] MSI Select Play
    msi_selectplay = 2871, 'msi-selectplay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RADIX
    #: - [UDP] RADIX
    radix = 2872, 'radix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PubSub Realtime Telemetry Protocol
    #: - [UDP] PubSub Realtime Telemetry Protocol
    psrt = 2873, 'psrt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DX Message Base Transport Protocol
    #: - [UDP] DX Message Base Transport Protocol
    dxmessagebase1 = 2874, 'dxmessagebase1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DX Message Base Transport Protocol
    #: - [UDP] DX Message Base Transport Protocol
    dxmessagebase2 = 2875, 'dxmessagebase2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPS Tunnel
    #: - [UDP] SPS Tunnel
    sps_tunnel = 2876, 'sps-tunnel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BLUELANCE
    #: - [UDP] BLUELANCE
    bluelance = 2877, 'bluelance', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AAP
    #: - [UDP] AAP
    aap = 2878, 'aap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ucentric-ds
    #: - [UDP] ucentric-ds
    ucentric_ds = 2879, 'ucentric-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Synapse Transport
    #: - [UDP] Synapse Transport
    synapse = 2880, 'synapse', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NDSP
    #: - [UDP] NDSP
    ndsp = 2881, 'ndsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NDTP
    #: - [UDP] NDTP
    ndtp = 2882, 'ndtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NDNP
    #: - [UDP] NDNP
    ndnp = 2883, 'ndnp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Flash Msg
    #: - [UDP] Flash Msg
    flashmsg = 2884, 'flashmsg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TopFlow
    #: - [UDP] TopFlow
    topflow = 2885, 'topflow', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RESPONSELOGIC
    #: - [UDP] RESPONSELOGIC
    responselogic = 2886, 'responselogic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] aironet
    #: - [UDP] aironet
    aironetddp = 2887, 'aironetddp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPCSDLOBBY
    #: - [UDP] SPCSDLOBBY
    spcsdlobby = 2888, 'spcsdlobby', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSOM
    #: - [UDP] RSOM
    rsom = 2889, 'rsom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSPCLMULTI
    #: - [UDP] CSPCLMULTI
    cspclmulti = 2890, 'cspclmulti', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CINEGRFX-ELMD License Manager
    #: - [UDP] CINEGRFX-ELMD License Manager
    cinegrfx_elmd = 2891, 'cinegrfx-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNIFFERDATA
    #: - [UDP] SNIFFERDATA
    snifferdata = 2892, 'snifferdata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSECONNECTOR
    #: - [UDP] VSECONNECTOR
    vseconnector = 2893, 'vseconnector', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ABACUS-REMOTE
    #: - [UDP] ABACUS-REMOTE
    abacus_remote = 2894, 'abacus-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NATUS LINK
    #: - [UDP] NATUS LINK
    natuslink = 2895, 'natuslink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ECOVISIONG6-1
    #: - [UDP] ECOVISIONG6-1
    ecovisiong6_1 = 2896, 'ecovisiong6-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Citrix RTMP
    #: - [UDP] Citrix RTMP
    citrix_rtmp = 2897, 'citrix-rtmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APPLIANCE-CFG
    #: - [UDP] APPLIANCE-CFG
    appliance_cfg = 2898, 'appliance-cfg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] POWERGEMPLUS
    #: - [UDP] POWERGEMPLUS
    powergemplus = 2899, 'powergemplus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QUICKSUITE
    #: - [UDP] QUICKSUITE
    quicksuite = 2900, 'quicksuite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ALLSTORCNS
    #: - [UDP] ALLSTORCNS
    allstorcns = 2901, 'allstorcns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NET ASPI
    #: - [UDP] NET ASPI
    netaspi = 2902, 'netaspi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SUITCASE
    #: - [UDP] SUITCASE
    suitcase = 2903, 'suitcase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] M2UA
    #: - [UDP] M2UA
    #: - [SCTP] M2UA
    m2ua = 2904, 'm2ua', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: [UDP] De-registered
    de_registered_2905 = 2905, 'de_registered', TransportProtocol.udp

    #: - [TCP] CALLER9
    #: - [UDP] CALLER9
    caller9 = 2906, 'caller9', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WEBMETHODS B2B
    #: - [UDP] WEBMETHODS B2B
    webmethods_b2b = 2907, 'webmethods-b2b', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mao
    #: - [UDP] mao
    mao = 2908, 'mao', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Funk Dialout
    #: - [UDP] Funk Dialout
    funk_dialout = 2909, 'funk-dialout', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TDAccess
    #: - [UDP] TDAccess
    tdaccess = 2910, 'tdaccess', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Blockade
    #: - [UDP] Blockade
    blockade = 2911, 'blockade', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Epicon
    #: - [UDP] Epicon
    epicon = 2912, 'epicon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Booster Ware
    #: - [UDP] Booster Ware
    boosterware = 2913, 'boosterware', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Game Lobby
    #: - [UDP] Game Lobby
    gamelobby = 2914, 'gamelobby', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TK Socket
    #: - [UDP] TK Socket
    tksocket = 2915, 'tksocket', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Elvin Server IANA assigned this well-formed service name as a
    #:   replacement for "elvin_server".
    #: - [TCP] Elvin Server
    #: - [UDP] Elvin Server IANA assigned this well-formed service name as a
    #:   replacement for "elvin_server".
    #: - [UDP] Elvin Server
    elvin_server = 2916, 'elvin-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Elvin Client IANA assigned this well-formed service name as a
    #:   replacement for "elvin_client".
    #: - [TCP] Elvin Client
    #: - [UDP] Elvin Client IANA assigned this well-formed service name as a
    #:   replacement for "elvin_client".
    #: - [UDP] Elvin Client
    elvin_client = 2917, 'elvin-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kasten Chase Pad
    #: - [UDP] Kasten Chase Pad
    kastenchasepad = 2918, 'kastenchasepad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] roboER
    #: - [UDP] roboER
    roboer = 2919, 'roboer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] roboEDA
    #: - [UDP] roboEDA
    roboeda = 2920, 'roboeda', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CESD Contents Delivery Management
    #: - [UDP] CESD Contents Delivery Management
    cesdcdman = 2921, 'cesdcdman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CESD Contents Delivery Data Transfer
    #: - [UDP] CESD Contents Delivery Data Transfer
    cesdcdtrn = 2922, 'cesdcdtrn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WTA-WSP-WTP-S
    #: - [UDP] WTA-WSP-WTP-S
    wta_wsp_wtp_s = 2923, 'wta-wsp-wtp-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PRECISE-VIP
    #: - [UDP] PRECISE-VIP
    precise_vip = 2924, 'precise-vip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MOBILE-FILE-DL
    #: - [UDP] MOBILE-FILE-DL
    mobile_file_dl = 2926, 'mobile-file-dl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UNIMOBILECTRL
    #: - [UDP] UNIMOBILECTRL
    unimobilectrl = 2927, 'unimobilectrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] REDSTONE-CPSS
    #: - [UDP] REDSTONE-CPSS
    redstone_cpss = 2928, 'redstone-cpss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMX-WEBADMIN
    #: - [UDP] AMX-WEBADMIN
    amx_webadmin = 2929, 'amx-webadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMX-WEBLINX
    #: - [UDP] AMX-WEBLINX
    amx_weblinx = 2930, 'amx-weblinx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Circle-X
    #: - [UDP] Circle-X
    circle_x = 2931, 'circle-x', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INCP
    #: - [UDP] INCP
    incp = 2932, 'incp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 4-TIER OPM GW
    #: - [UDP] 4-TIER OPM GW
    UDP_4_tieropmgw = 2933, '4-tieropmgw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 4-TIER OPM CLI
    #: - [UDP] 4-TIER OPM CLI
    UDP_4_tieropmcli = 2934, '4-tieropmcli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QTP
    #: - [UDP] QTP
    qtp = 2935, 'qtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OTPatch
    #: - [UDP] OTPatch
    otpatch = 2936, 'otpatch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PNACONSULT-LM
    #: - [UDP] PNACONSULT-LM
    pnaconsult_lm = 2937, 'pnaconsult-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SM-PAS-1
    #: - [UDP] SM-PAS-1
    sm_pas_1 = 2938, 'sm-pas-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SM-PAS-2
    #: - [UDP] SM-PAS-2
    sm_pas_2 = 2939, 'sm-pas-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SM-PAS-3
    #: - [UDP] SM-PAS-3
    sm_pas_3 = 2940, 'sm-pas-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SM-PAS-4
    #: - [UDP] SM-PAS-4
    sm_pas_4 = 2941, 'sm-pas-4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SM-PAS-5
    #: - [UDP] SM-PAS-5
    sm_pas_5 = 2942, 'sm-pas-5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TTNRepository
    #: - [UDP] TTNRepository
    ttnrepository = 2943, 'ttnrepository', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Megaco H-248
    #: - [UDP] Megaco H-248
    #: - [SCTP] Megaco-H.248 text
    megaco_h248 = 2944, 'megaco-h248', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] H248 Binary
    #: - [UDP] H248 Binary
    #: - [SCTP] Megaco/H.248 binary
    h248_binary = 2945, 'h248-binary', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] FJSVmpor
    #: - [UDP] FJSVmpor
    fjsvmpor = 2946, 'fjsvmpor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GPS Daemon request/response protocol
    #: - [UDP] GPS Daemon request/response protocol
    gpsd = 2947, 'gpsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP PUSH
    #: - [UDP] WAP PUSH
    wap_push = 2948, 'wap-push', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP PUSH SECURE
    #: - [UDP] WAP PUSH SECURE
    wap_pushsecure = 2949, 'wap-pushsecure', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESIP
    #: - [UDP] ESIP
    esip = 2950, 'esip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OTTP
    #: - [UDP] OTTP
    ottp = 2951, 'ottp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MPFWSAS
    #: - [UDP] MPFWSAS
    mpfwsas = 2952, 'mpfwsas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OVALARMSRV
    #: - [UDP] OVALARMSRV
    ovalarmsrv = 2953, 'ovalarmsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OVALARMSRV-CMD
    #: - [UDP] OVALARMSRV-CMD
    ovalarmsrv_cmd = 2954, 'ovalarmsrv-cmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSNOTIFY
    #: - [UDP] CSNOTIFY
    csnotify = 2955, 'csnotify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OVRIMOSDBMAN
    #: - [UDP] OVRIMOSDBMAN
    ovrimosdbman = 2956, 'ovrimosdbman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JAMCT5
    #: - [UDP] JAMCT5
    jmact5 = 2957, 'jmact5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JAMCT6
    #: - [UDP] JAMCT6
    jmact6 = 2958, 'jmact6', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RMOPAGT
    #: - [UDP] RMOPAGT
    rmopagt = 2959, 'rmopagt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DFOXSERVER
    #: - [UDP] DFOXSERVER
    dfoxserver = 2960, 'dfoxserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BOLDSOFT-LM
    #: - [UDP] BOLDSOFT-LM
    boldsoft_lm = 2961, 'boldsoft-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPH-POLICY-CLI
    #: - [UDP] IPH-POLICY-CLI
    iph_policy_cli = 2962, 'iph-policy-cli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPH-POLICY-ADM
    #: - [UDP] IPH-POLICY-ADM
    iph_policy_adm = 2963, 'iph-policy-adm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BULLANT SRAP
    #: - [UDP] BULLANT SRAP
    bullant_srap = 2964, 'bullant-srap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BULLANT RAP
    #: - [UDP] BULLANT RAP
    bullant_rap = 2965, 'bullant-rap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IDP-INFOTRIEVE
    #: - [UDP] IDP-INFOTRIEVE
    idp_infotrieve = 2966, 'idp-infotrieve', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSC-AGENT
    #: - [UDP] SSC-AGENT
    ssc_agent = 2967, 'ssc-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ENPP
    #: - [UDP] ENPP
    enpp = 2968, 'enpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESSP
    #: - [UDP] ESSP
    essp = 2969, 'essp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INDEX-NET
    #: - [UDP] INDEX-NET
    index_net = 2970, 'index-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetClip clipboard daemon
    #: - [UDP] NetClip clipboard daemon
    netclip = 2971, 'netclip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PMSM Webrctl
    #: - [UDP] PMSM Webrctl
    pmsm_webrctl = 2972, 'pmsm-webrctl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SV Networks
    #: - [UDP] SV Networks
    svnetworks = 2973, 'svnetworks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Signal
    #: - [UDP] Signal
    signal = 2974, 'signal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Configuration Management Service
    #: - [UDP] Fujitsu Configuration Management Service
    fjmpcm = 2975, 'fjmpcm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CNS Server Port
    #: - [UDP] CNS Server Port
    cns_srv_port = 2976, 'cns-srv-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TTCs Enterprise Test Access Protocol - NS
    #: - [UDP] TTCs Enterprise Test Access Protocol - NS
    ttc_etap_ns = 2977, 'ttc-etap-ns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TTCs Enterprise Test Access Protocol - DS
    #: - [UDP] TTCs Enterprise Test Access Protocol - DS
    ttc_etap_ds = 2978, 'ttc-etap-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] H.263 Video Streaming
    #: - [UDP] H.263 Video Streaming
    h263_video = 2979, 'h263-video', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Instant Messaging Service
    #: - [UDP] Instant Messaging Service
    wimd = 2980, 'wimd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MYLXAMPORT
    #: - [UDP] MYLXAMPORT
    mylxamport = 2981, 'mylxamport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IWB-WHITEBOARD
    #: - [UDP] IWB-WHITEBOARD
    iwb_whiteboard = 2982, 'iwb-whiteboard', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETPLAN
    #: - [UDP] NETPLAN
    netplan = 2983, 'netplan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HPIDSADMIN
    #: - [UDP] HPIDSADMIN
    hpidsadmin = 2984, 'hpidsadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HPIDSAGENT
    #: - [UDP] HPIDSAGENT
    hpidsagent = 2985, 'hpidsagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STONEFALLS
    #: - [UDP] STONEFALLS
    stonefalls = 2986, 'stonefalls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] identify
    #: - [UDP] identify
    identify = 2987, 'identify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HIPPA Reporting Protocol
    #: - [UDP] HIPPA Reporting Protocol
    hippad = 2988, 'hippad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ZARKOV Intelligent Agent Communication
    #: - [UDP] ZARKOV Intelligent Agent Communication
    zarkov = 2989, 'zarkov', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BOSCAP
    #: - [UDP] BOSCAP
    boscap = 2990, 'boscap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WKSTN-MON
    #: - [UDP] WKSTN-MON
    wkstn_mon = 2991, 'wkstn-mon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avenyo Server
    #: - [UDP] Avenyo Server
    avenyo = 2992, 'avenyo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS VIS1
    #: - [UDP] VERITAS VIS1
    veritas_vis1 = 2993, 'veritas-vis1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS VIS2
    #: - [UDP] VERITAS VIS2
    veritas_vis2 = 2994, 'veritas-vis2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IDRS
    #: - [UDP] IDRS
    idrs = 2995, 'idrs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vsixml
    #: - [UDP] vsixml
    vsixml = 2996, 'vsixml', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] REBOL
    #: - [UDP] REBOL
    rebol = 2997, 'rebol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Real Secure
    #: - [UDP] Real Secure
    realsecure = 2998, 'realsecure', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RemoteWare Unassigned
    #: - [UDP] RemoteWare Unassigned
    remoteware_un = 2999, 'remoteware-un', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HBCI
    #: - [UDP] HBCI
    hbci = 3000, 'hbci', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RemoteWare Client
    #: - [UDP] RemoteWare Client
    remoteware_cl = 3000, 'remoteware-cl', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3001 = 3001, 'reserved', TransportProtocol.udp

    #: - [TCP] EXLM Agent
    #: - [UDP] EXLM Agent
    exlm_agent = 3002, 'exlm-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RemoteWare Server
    #: - [UDP] RemoteWare Server
    remoteware_srv = 3002, 'remoteware-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CGMS
    #: - [UDP] CGMS
    cgms = 3003, 'cgms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Csoft Agent
    #: - [UDP] Csoft Agent
    csoftragent = 3004, 'csoftragent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Genius License Manager
    #: - [UDP] Genius License Manager
    geniuslm = 3005, 'geniuslm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Instant Internet Admin
    #: - [UDP] Instant Internet Admin
    ii_admin = 3006, 'ii-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lotus Mail Tracking Agent Protocol
    #: - [UDP] Lotus Mail Tracking Agent Protocol
    lotusmtap = 3007, 'lotusmtap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Midnight Technologies
    #: - [UDP] Midnight Technologies
    midnight_tech = 3008, 'midnight-tech', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PXC-NTFY
    #: - [UDP] PXC-NTFY
    pxc_ntfy = 3009, 'pxc-ntfy', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Telerate Workstation
    ping_pong = 3010, 'ping-pong', TransportProtocol.udp

    #: - [TCP] Trusted Web
    #: - [UDP] Trusted Web
    trusted_web = 3011, 'trusted-web', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trusted Web Client
    #: - [UDP] Trusted Web Client
    twsdss = 3012, 'twsdss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gilat Sky Surfer
    #: - [UDP] Gilat Sky Surfer
    gilatskysurfer = 3013, 'gilatskysurfer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Broker Service IANA assigned this well-formed service name as a
    #:   replacement for "broker_service".
    #: - [TCP] Broker Service
    #: - [UDP] Broker Service IANA assigned this well-formed service name as a
    #:   replacement for "broker_service".
    #: - [UDP] Broker Service
    broker_service = 3014, 'broker-service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NATI DSTP
    #: - [UDP] NATI DSTP
    nati_dstp = 3015, 'nati-dstp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Notify Server IANA assigned this well-formed service name as a
    #:   replacement for "notify_srvr".
    #: - [TCP] Notify Server
    #: - [UDP] Notify Server IANA assigned this well-formed service name as a
    #:   replacement for "notify_srvr".
    #: - [UDP] Notify Server
    notify_srvr = 3016, 'notify-srvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Event Listener IANA assigned this well-formed service name as a
    #:   replacement for "event_listener".
    #: - [TCP] Event Listener
    #: - [UDP] Event Listener IANA assigned this well-formed service name as a
    #:   replacement for "event_listener".
    #: - [UDP] Event Listener
    event_listener = 3017, 'event-listener', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Registry IANA assigned this well-formed service name as a
    #:   replacement for "srvc_registry".
    #: - [TCP] Service Registry
    #: - [UDP] Service Registry IANA assigned this well-formed service name as a
    #:   replacement for "srvc_registry".
    #: - [UDP] Service Registry
    srvc_registry = 3018, 'srvc-registry', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Resource Manager IANA assigned this well-formed service name as a
    #:   replacement for "resource_mgr".
    #: - [TCP] Resource Manager
    #: - [UDP] Resource Manager IANA assigned this well-formed service name as a
    #:   replacement for "resource_mgr".
    #: - [UDP] Resource Manager
    resource_mgr = 3019, 'resource-mgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CIFS
    #: - [UDP] CIFS
    cifs = 3020, 'cifs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AGRI Server
    #: - [UDP] AGRI Server
    agriserver = 3021, 'agriserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSREGAGENT
    #: - [UDP] CSREGAGENT
    csregagent = 3022, 'csregagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] magicnotes
    #: - [UDP] magicnotes
    magicnotes = 3023, 'magicnotes', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NDS_SSO IANA assigned this well-formed service name as a replacement
    #:   for "nds_sso".
    #: - [TCP] NDS_SSO
    #: - [UDP] NDS_SSO IANA assigned this well-formed service name as a replacement
    #:   for "nds_sso".
    #: - [UDP] NDS_SSO
    nds_sso = 3024, 'nds-sso', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Arepa Raft
    #: - [UDP] Arepa Raft
    arepa_raft = 3025, 'arepa-raft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AGRI Gateway
    #: - [UDP] AGRI Gateway
    agri_gateway = 3026, 'agri-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LiebDevMgmt_C IANA assigned this well-formed service name as a
    #:   replacement for "LiebDevMgmt_C".
    #: - [TCP] LiebDevMgmt_C
    #: - [UDP] LiebDevMgmt_C IANA assigned this well-formed service name as a
    #:   replacement for "LiebDevMgmt_C".
    #: - [UDP] LiebDevMgmt_C
    liebdevmgmt_c = 3027, 'liebdevmgmt-c', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LiebDevMgmt_DM IANA assigned this well-formed service name as a
    #:   replacement for "LiebDevMgmt_DM".
    #: - [TCP] LiebDevMgmt_DM
    #: - [UDP] LiebDevMgmt_DM IANA assigned this well-formed service name as a
    #:   replacement for "LiebDevMgmt_DM".
    #: - [UDP] LiebDevMgmt_DM
    liebdevmgmt_dm = 3028, 'liebdevmgmt-dm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LiebDevMgmt_A IANA assigned this well-formed service name as a
    #:   replacement for "LiebDevMgmt_A".
    #: - [TCP] LiebDevMgmt_A
    #: - [UDP] LiebDevMgmt_A IANA assigned this well-formed service name as a
    #:   replacement for "LiebDevMgmt_A".
    #: - [UDP] LiebDevMgmt_A
    liebdevmgmt_a = 3029, 'liebdevmgmt-a', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Arepa Cas
    #: - [UDP] Arepa Cas
    arepa_cas = 3030, 'arepa-cas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote AppleEvents/PPC Toolbox
    #: - [UDP] Remote AppleEvents/PPC Toolbox
    eppc = 3031, 'eppc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Redwood Chat
    #: - [UDP] Redwood Chat
    redwood_chat = 3032, 'redwood-chat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PDB
    #: - [UDP] PDB
    pdb = 3033, 'pdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Osmosis / Helix (R) AEEA Port
    #: - [UDP] Osmosis / Helix (R) AEEA Port
    osmosis_aeea = 3034, 'osmosis-aeea', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FJSV gssagt
    #: - [UDP] FJSV gssagt
    fjsv_gssagt = 3035, 'fjsv-gssagt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hagel DUMP
    #: - [UDP] Hagel DUMP
    hagel_dump = 3036, 'hagel-dump', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP SAN Mgmt
    #: - [UDP] HP SAN Mgmt
    hp_san_mgmt = 3037, 'hp-san-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Santak UPS
    #: - [UDP] Santak UPS
    santak_ups = 3038, 'santak-ups', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cogitate, Inc.
    #: - [UDP] Cogitate, Inc.
    cogitate = 3039, 'cogitate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tomato Springs
    #: - [UDP] Tomato Springs
    tomato_springs = 3040, 'tomato-springs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] di-traceware
    #: - [UDP] di-traceware
    di_traceware = 3041, 'di-traceware', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] journee
    #: - [UDP] journee
    journee = 3042, 'journee', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Broadcast Routing Protocol
    #: - [UDP] Broadcast Routing Protocol
    brp = 3043, 'brp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Extensible Provisioning Protocol [:rfc:`5734`]
    #: - [UDP] EPP running over QUIC [:rfc:`5734`][RFC-ietf-regext-epp-quic-12]
    epp_700 = 700, 'epp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EndPoint Protocol
    #: - [UDP] EndPoint Protocol
    epp_3044 = 3044, 'epp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ResponseNet
    #: - [UDP] ResponseNet
    responsenet = 3045, 'responsenet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] di-ase
    #: - [UDP] di-ase
    di_ase = 3046, 'di-ase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fast Security HL Server
    #: - [UDP] Fast Security HL Server
    hlserver = 3047, 'hlserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sierra Net PC Trader
    #: - [UDP] Sierra Net PC Trader
    pctrader = 3048, 'pctrader', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NSWS
    #: - [UDP] NSWS
    nsws = 3049, 'nsws', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gds_db IANA assigned this well-formed service name as a replacement
    #:   for "gds_db".
    #: - [TCP] gds_db
    #: - [UDP] gds_db IANA assigned this well-formed service name as a replacement
    #:   for "gds_db".
    #: - [UDP] gds_db
    gds_db = 3050, 'gds-db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Galaxy Server
    #: - [UDP] Galaxy Server
    galaxy_server = 3051, 'galaxy-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 3052
    #: - [UDP] APC 3052
    apc_3052 = 3052, 'apc-3052', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dsom-server
    #: - [UDP] dsom-server
    dsom_server = 3053, 'dsom-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMT CNF PROT
    #: - [UDP] AMT CNF PROT
    amt_cnf_prot = 3054, 'amt-cnf-prot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Policy Server
    #: - [UDP] Policy Server
    policyserver = 3055, 'policyserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CDL Server
    #: - [UDP] CDL Server
    cdl_server = 3056, 'cdl-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GoAhead FldUp
    #: - [UDP] GoAhead FldUp
    goahead_fldup = 3057, 'goahead-fldup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] videobeans
    #: - [UDP] videobeans
    videobeans = 3058, 'videobeans', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qsoft
    #: - [UDP] qsoft
    qsoft = 3059, 'qsoft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] interserver
    #: - [UDP] interserver
    interserver = 3060, 'interserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cautcpd
    #: - [UDP] cautcpd
    cautcpd = 3061, 'cautcpd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ncacn-ip-tcp
    #: - [UDP] ncacn-ip-tcp
    ncacn_ip_tcp = 3062, 'ncacn-ip-tcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ncadg-ip-udp
    #: - [UDP] ncadg-ip-udp
    ncadg_ip_udp = 3063, 'ncadg-ip-udp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Port Redirector
    #: - [UDP] Remote Port Redirector
    rprt = 3064, 'rprt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] slinterbase
    #: - [UDP] slinterbase
    slinterbase = 3065, 'slinterbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETATTACHSDMP
    #: - [UDP] NETATTACHSDMP
    netattachsdmp = 3066, 'netattachsdmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FJHPJP
    #: - [UDP] FJHPJP
    fjhpjp = 3067, 'fjhpjp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ls3 Broadcast
    #: - [UDP] ls3 Broadcast
    ls3bcast = 3068, 'ls3bcast', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ls3
    #: - [UDP] ls3
    ls3 = 3069, 'ls3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MGXSWITCH
    #: - [UDP] MGXSWITCH
    mgxswitch = 3070, 'mgxswitch', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3071 = 3071, 'reserved', TransportProtocol.udp

    #: - [TCP] ContinuStor Monitor Port
    #: - [UDP] ContinuStor Monitor Port
    csd_monitor = 3072, 'csd-monitor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Very simple chatroom prot
    #: - [UDP] Very simple chatroom prot
    vcrp = 3073, 'vcrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xbox game port
    #: - [UDP] Xbox game port
    xbox = 3074, 'xbox', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Orbix 2000 Locator
    #: - [UDP] Orbix 2000 Locator
    orbix_locator = 3075, 'orbix-locator', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Orbix 2000 Config
    #: - [UDP] Orbix 2000 Config
    orbix_config = 3076, 'orbix-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Orbix 2000 Locator SSL
    #: - [UDP] Orbix 2000 Locator SSL
    orbix_loc_ssl = 3077, 'orbix-loc-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Orbix 2000 Locator SSL
    #: - [UDP] Orbix 2000 Locator SSL
    orbix_cfg_ssl = 3078, 'orbix-cfg-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LV Front Panel
    #: - [UDP] LV Front Panel
    lv_frontpanel = 3079, 'lv-frontpanel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] stm_pproc IANA assigned this well-formed service name as a replacement
    #:   for "stm_pproc".
    #: - [TCP] stm_pproc
    #: - [UDP] stm_pproc IANA assigned this well-formed service name as a replacement
    #:   for "stm_pproc".
    #: - [UDP] stm_pproc
    stm_pproc = 3080, 'stm-pproc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TL1-LV
    #: - [UDP] TL1-LV
    tl1_lv = 3081, 'tl1-lv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TL1-RAW
    #: - [UDP] TL1-RAW
    tl1_raw = 3082, 'tl1-raw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TL1-TELNET
    #: - [UDP] TL1-TELNET
    tl1_telnet = 3083, 'tl1-telnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITM-MCCS
    #: - [UDP] ITM-MCCS
    itm_mccs = 3084, 'itm-mccs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCIHReq
    #: - [UDP] PCIHReq
    pcihreq = 3085, 'pcihreq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JDL-DBKitchen
    #: - [UDP] JDL-DBKitchen
    jdl_dbkitchen = 3086, 'jdl-dbkitchen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Asoki SMA
    #: - [UDP] Asoki SMA
    asoki_sma = 3087, 'asoki-sma', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eXtensible Data Transfer Protocol
    #: - [UDP] eXtensible Data Transfer Protocol
    xdtp = 3088, 'xdtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ParaTek Agent Linking
    #: - [UDP] ParaTek Agent Linking
    ptk_alink = 3089, 'ptk-alink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Senforce Session Services
    #: - [UDP] Senforce Session Services
    stss = 3090, 'stss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 1Ci Server Management
    #: - [UDP] 1Ci Server Management
    UDP_1ci_smcs = 3091, '1ci-smcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jiiva RapidMQ Center
    #: - [UDP] Jiiva RapidMQ Center
    rapidmq_center = 3093, 'rapidmq-center', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jiiva RapidMQ Registry
    #: - [UDP] Jiiva RapidMQ Registry
    rapidmq_reg = 3094, 'rapidmq-reg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Panasas rendezvous port
    #: - [UDP] Panasas rendezvous port
    panasas = 3095, 'panasas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Active Print Server Port
    #: - [UDP] Active Print Server Port
    ndl_aps = 3096, 'ndl-aps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_3097 = 3097, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Universal Message Manager
    #: - [UDP] Universal Message Manager
    umm_port = 3098, 'umm-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CHIPSY Machine Daemon
    #: - [UDP] CHIPSY Machine Daemon
    chmd = 3099, 'chmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpCon/xps
    #: - [UDP] OpCon/xps
    opcon_xps = 3100, 'opcon-xps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP PolicyXpert PIB Server
    #: - [UDP] HP PolicyXpert PIB Server
    hp_pxpib = 3101, 'hp-pxpib', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SoftlinK Slave Mon Port
    #: - [UDP] SoftlinK Slave Mon Port
    slslavemon = 3102, 'slslavemon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Autocue SMI Protocol
    #: - [UDP] Autocue SMI Protocol
    autocuesmi = 3103, 'autocuesmi', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Autocue Time Service
    autocuetime = 3104, 'autocuetime', TransportProtocol.udp

    #: - [TCP] Cardbox
    #: - [UDP] Cardbox
    cardbox = 3105, 'cardbox', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cardbox HTTP
    #: - [UDP] Cardbox HTTP
    cardbox_http = 3106, 'cardbox-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Business protocol
    #: - [UDP] Business protocol
    business = 3107, 'business', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Geolocate protocol
    #: - [UDP] Geolocate protocol
    geolocate = 3108, 'geolocate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Personnel protocol
    #: - [UDP] Personnel protocol
    personnel = 3109, 'personnel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] simulator control port
    #: - [UDP] simulator control port
    sim_control = 3110, 'sim-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Web Synchronous Services
    #: - [UDP] Web Synchronous Services
    wsynch = 3111, 'wsynch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KDE System Guard
    #: - [UDP] KDE System Guard
    ksysguard = 3112, 'ksysguard', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CS-Authenticate Svr Port
    #: - [UDP] CS-Authenticate Svr Port
    cs_auth_svr = 3113, 'cs-auth-svr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CCM AutoDiscover
    #: - [UDP] CCM AutoDiscover
    ccmad = 3114, 'ccmad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCTET Master
    #: - [UDP] MCTET Master
    mctet_master = 3115, 'mctet-master', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCTET Gateway
    #: - [UDP] MCTET Gateway
    mctet_gateway = 3116, 'mctet-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCTET Jserv
    #: - [UDP] MCTET Jserv
    mctet_jserv = 3117, 'mctet-jserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PKAgent
    #: - [UDP] PKAgent
    pkagent = 3118, 'pkagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D2000 Kernel Port
    #: - [UDP] D2000 Kernel Port
    d2000kernel = 3119, 'd2000kernel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D2000 Webserver Port
    #: - [UDP] D2000 Webserver Port
    d2000webserver = 3120, 'd2000webserver', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3121 = 3121, 'reserved', TransportProtocol.udp

    #: - [TCP] MTI VTR Emulator port
    #: - [UDP] MTI VTR Emulator port
    vtr_emulator = 3122, 'vtr-emulator', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EDI Translation Protocol
    #: - [UDP] EDI Translation Protocol
    edix = 3123, 'edix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Beacon Port
    #: - [UDP] Beacon Port
    beacon_port = 3124, 'beacon-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A13-AN Interface
    #: - [UDP] A13-AN Interface
    a13_an = 3125, 'a13-an', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CTX Bridge Port
    #: - [UDP] CTX Bridge Port
    ctx_bridge = 3127, 'ctx-bridge', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Active API Server Port
    #: - [UDP] Active API Server Port
    ndl_aas = 3128, 'ndl-aas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetPort Discovery Port
    #: - [UDP] NetPort Discovery Port
    netport_id = 3129, 'netport-id', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICPv2
    #: - [UDP] ICPv2
    icpv2 = 3130, 'icpv2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net Book Mark
    #: - [UDP] Net Book Mark
    netbookmark = 3131, 'netbookmark', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Business Rule Engine Update Service
    #: - [UDP] Microsoft Business Rule Engine Update Service
    ms_rule_engine = 3132, 'ms-rule-engine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prism Deploy User Port
    #: - [UDP] Prism Deploy User Port
    prism_deploy = 3133, 'prism-deploy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Extensible Code Protocol
    #: - [UDP] Extensible Code Protocol
    ecp = 3134, 'ecp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PeerBook Port
    #: - [UDP] PeerBook Port
    peerbook_port = 3135, 'peerbook-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Grub Server Port
    #: - [UDP] Grub Server Port
    grubd = 3136, 'grubd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rtnt-1 data packets
    #: - [UDP] rtnt-1 data packets
    rtnt_1 = 3137, 'rtnt-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rtnt-2 data packets
    #: - [UDP] rtnt-2 data packets
    rtnt_2 = 3138, 'rtnt-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Incognito Rendez-Vous
    #: - [UDP] Incognito Rendez-Vous
    incognitorv = 3139, 'incognitorv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Arilia Multiplexor
    #: - [UDP] Arilia Multiplexor
    ariliamulti = 3140, 'ariliamulti', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VMODEM
    #: - [UDP] VMODEM
    vmodem = 3141, 'vmodem', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RDC WH EOS
    #: - [UDP] RDC WH EOS
    rdc_wh_eos = 3142, 'rdc-wh-eos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sea View
    #: - [UDP] Sea View
    seaview = 3143, 'seaview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tarantella
    #: - [UDP] Tarantella
    tarantella = 3144, 'tarantella', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSI-LFAP
    #: - [UDP] CSI-LFAP
    csi_lfap = 3145, 'csi-lfap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bears-02
    #: - [UDP] bears-02
    bears_02 = 3146, 'bears-02', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RFIO
    #: - [UDP] RFIO
    rfio = 3147, 'rfio', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetMike Game Administrator
    #: - [UDP] NetMike Game Administrator
    nm_game_admin = 3148, 'nm-game-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetMike Game Server
    #: - [UDP] NetMike Game Server
    nm_game_server = 3149, 'nm-game-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetMike Assessor Administrator
    #: - [UDP] NetMike Assessor Administrator
    nm_asses_admin = 3150, 'nm-asses-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetMike Assessor
    #: - [UDP] NetMike Assessor
    nm_assessor = 3151, 'nm-assessor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FeiTian Port
    #: - [UDP] FeiTian Port
    feitianrockey = 3152, 'feitianrockey', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] S8Cargo Client Port
    #: - [UDP] S8Cargo Client Port
    s8_client_port = 3153, 's8-client-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ON RMI Registry
    #: - [UDP] ON RMI Registry
    ccmrmi = 3154, 'ccmrmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JpegMpeg Port
    #: - [UDP] JpegMpeg Port
    jpegmpeg = 3155, 'jpegmpeg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Indura Collector
    #: - [UDP] Indura Collector
    indura = 3156, 'indura', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LSA Communicator
    #: - [UDP] LSA Communicator
    lsa_comm = 3157, 'lsa-comm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SmashTV Protocol
    #: - [UDP] SmashTV Protocol
    stvp = 3158, 'stvp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NavegaWeb Tarification
    #: - [UDP] NavegaWeb Tarification
    navegaweb_port = 3159, 'navegaweb-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TIP Application Server
    #: - [UDP] TIP Application Server
    tip_app_server = 3160, 'tip-app-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DOC1 License Manager
    #: - [UDP] DOC1 License Manager
    doc1lm = 3161, 'doc1lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SFLM
    #: - [UDP] SFLM
    sflm = 3162, 'sflm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RES-SAP
    #: - [UDP] RES-SAP
    res_sap = 3163, 'res-sap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IMPRS
    #: - [UDP] IMPRS
    imprs = 3164, 'imprs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Newgenpay Engine Service
    #: - [UDP] Newgenpay Engine Service
    newgenpay = 3165, 'newgenpay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quest Spotlight Out-Of-Process Collector
    #: - [UDP] Quest Spotlight Out-Of-Process Collector
    sossecollector = 3166, 'sossecollector', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Now Contact Public Server
    #: - [UDP] Now Contact Public Server
    nowcontact = 3167, 'nowcontact', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Now Up-to-Date Public Server
    #: - [UDP] Now Up-to-Date Public Server
    poweronnud = 3168, 'poweronnud', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SERVERVIEW-AS
    #: - [UDP] SERVERVIEW-AS
    serverview_as = 3169, 'serverview-as', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SERVERVIEW-ASN
    #: - [UDP] SERVERVIEW-ASN
    serverview_asn = 3170, 'serverview-asn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SERVERVIEW-GF
    #: - [UDP] SERVERVIEW-GF
    serverview_gf = 3171, 'serverview-gf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SERVERVIEW-RM
    #: - [UDP] SERVERVIEW-RM
    serverview_rm = 3172, 'serverview-rm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SERVERVIEW-ICC
    #: - [UDP] SERVERVIEW-ICC
    serverview_icc = 3173, 'serverview-icc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARMI Server
    #: - [UDP] ARMI Server
    armi_server = 3174, 'armi-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] T1_E1_Over_IP
    #: - [UDP] T1_E1_Over_IP
    t1_e1_over_ip = 3175, 't1-e1-over-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARS Master
    #: - [UDP] ARS Master
    ars_master = 3176, 'ars-master', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Phonex Protocol
    #: - [UDP] Phonex Protocol
    phonex_port = 3177, 'phonex-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Radiance UltraEdge Port
    #: - [UDP] Radiance UltraEdge Port
    radclientport = 3178, 'radclientport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] H2GF W.2m Handover prot.
    #: - [UDP] H2GF W.2m Handover prot.
    h2gf_w_2m = 3179, 'h2gf-w-2m', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Millicent Broker Server
    #: - [UDP] Millicent Broker Server
    mc_brk_srv = 3180, 'mc-brk-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC Patrol Agent
    #: - [UDP] BMC Patrol Agent
    bmcpatrolagent = 3181, 'bmcpatrolagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC Patrol Rendezvous
    #: - [UDP] BMC Patrol Rendezvous
    bmcpatrolrnvu = 3182, 'bmcpatrolrnvu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] COPS/TLS
    #: - [UDP] COPS/TLS
    cops_tls = 3183, 'cops-tls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ApogeeX Port
    #: - [UDP] ApogeeX Port
    apogeex_port = 3184, 'apogeex-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SuSE Meta PPPD
    #: - [UDP] SuSE Meta PPPD
    smpppd = 3185, 'smpppd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IIW Monitor User Port
    #: - [UDP] IIW Monitor User Port
    iiw_port = 3186, 'iiw-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Open Design Listen Port
    #: - [UDP] Open Design Listen Port
    odi_port = 3187, 'odi-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Broadcom Port
    #: - [UDP] Broadcom Port
    brcm_comm_port = 3188, 'brcm-comm-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pinnacle Sys InfEx Port
    #: - [UDP] Pinnacle Sys InfEx Port
    pcle_infex = 3189, 'pcle-infex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ConServR Proxy
    #: - [UDP] ConServR Proxy
    csvr_proxy = 3190, 'csvr-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ConServR SSL Proxy
    #: - [UDP] ConServR SSL Proxy
    csvr_sslproxy = 3191, 'csvr-sslproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FireMon Revision Control
    #: - [UDP] FireMon Revision Control
    firemonrcc = 3192, 'firemonrcc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SpanDataPort
    #: - [UDP] SpanDataPort
    spandataport = 3193, 'spandataport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rockstorm MAG protocol
    #: - [UDP] Rockstorm MAG protocol
    magbind = 3194, 'magbind', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Control Unit
    #: - [UDP] Network Control Unit
    ncu_1 = 3195, 'ncu-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Control Unit
    #: - [UDP] Network Control Unit
    ncu_2 = 3196, 'ncu-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Embrace Device Protocol Server
    #: - [UDP] Embrace Device Protocol Server
    embrace_dp_s = 3197, 'embrace-dp-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Embrace Device Protocol Client
    #: - [UDP] Embrace Device Protocol Client
    embrace_dp_c = 3198, 'embrace-dp-c', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DMOD WorkSpace
    #: - [UDP] DMOD WorkSpace
    dmod_workspace = 3199, 'dmod-workspace', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Press-sense Tick Port
    #: - [UDP] Press-sense Tick Port
    tick_port = 3200, 'tick-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CPQ-TaskSmart
    #: - [UDP] CPQ-TaskSmart
    cpq_tasksmart = 3201, 'cpq-tasksmart', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IntraIntra
    #: - [UDP] IntraIntra
    intraintra = 3202, 'intraintra', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Watcher Monitor
    #: - [UDP] Network Watcher Monitor
    netwatcher_mon = 3203, 'netwatcher-mon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Watcher DB Access
    #: - [UDP] Network Watcher DB Access
    netwatcher_db = 3204, 'netwatcher-db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iSNS Server Port [:rfc:`4171`]
    #: - [UDP] iSNS Server Port [:rfc:`4171`]
    isns = 3205, 'isns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IronMail POP Proxy
    #: - [UDP] IronMail POP Proxy
    ironmail = 3206, 'ironmail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Veritas Authentication Port
    #: - [UDP] Veritas Authentication Port
    vx_auth_port = 3207, 'vx-auth-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PFU PR Callback
    #: - [UDP] PFU PR Callback
    pfu_prcallback = 3208, 'pfu-prcallback', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP OpenView Network Path Engine Server
    #: - [UDP] HP OpenView Network Path Engine Server
    netwkpathengine = 3209, 'netwkpathengine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Flamenco Networks Proxy
    #: - [UDP] Flamenco Networks Proxy
    flamenco_proxy = 3210, 'flamenco-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avocent Secure Management
    #: - [UDP] Avocent Secure Management
    avsecuremgmt = 3211, 'avsecuremgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Survey Instrument
    #: - [UDP] Survey Instrument
    surveyinst = 3212, 'surveyinst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NEON 24X7 Mission Control
    #: - [UDP] NEON 24X7 Mission Control
    neon24x7 = 3213, 'neon24x7', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JMQ Daemon Port 1
    #: - [UDP] JMQ Daemon Port 1
    jmq_daemon_1 = 3214, 'jmq-daemon-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JMQ Daemon Port 2
    #: - [UDP] JMQ Daemon Port 2
    jmq_daemon_2 = 3215, 'jmq-daemon-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ferrari electronic FOAM
    #: - [UDP] Ferrari electronic FOAM
    ferrari_foam = 3216, 'ferrari-foam', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unified IP & Telecom Environment
    #: - [UDP] Unified IP & Telecom Environment
    unite = 3217, 'unite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMC SmartPackets
    #: - [UDP] EMC SmartPackets
    smartpackets = 3218, 'smartpackets', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WMS Messenger
    #: - [UDP] WMS Messenger
    wms_messenger = 3219, 'wms-messenger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XML NM over SSL
    #: - [UDP] XML NM over SSL
    xnm_ssl = 3220, 'xnm-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XML NM over TCP
    #: - [UDP] XML NM over TCP
    xnm_clear_text = 3221, 'xnm-clear-text', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Gateway Load Balancing Pr
    #: - [UDP] Gateway Load Balancing Pr
    glbp = 3222, 'glbp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DIGIVOTE (R) Vote-Server
    #: - [UDP] DIGIVOTE (R) Vote-Server
    digivote = 3223, 'digivote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AES Discovery Port
    #: - [UDP] AES Discovery Port
    aes_discovery = 3224, 'aes-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FCIP [:rfc:`3821`]
    #: - [UDP] FCIP [:rfc:`3821`]
    fcip_port = 3225, 'fcip-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISI Industry Software IRP
    #: - [UDP] ISI Industry Software IRP
    isi_irp = 3226, 'isi-irp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DiamondWave NMS Server
    #: - [UDP] DiamondWave NMS Server
    dwnmshttp = 3227, 'dwnmshttp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DiamondWave MSG Server
    #: - [UDP] DiamondWave MSG Server
    dwmsgserver = 3228, 'dwmsgserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Global CD Port
    #: - [UDP] Global CD Port
    global_cd_port = 3229, 'global-cd-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Software Distributor Port
    #: - [UDP] Software Distributor Port
    sftdst_port = 3230, 'sftdst-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VidiGo communication (previous was: Delta Solutions Direct)
    #: - [UDP] VidiGo communication (previous was: Delta Solutions Direct)
    vidigo = 3231, 'vidigo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MDT port [:rfc:`6513`]
    #: - [UDP] MDT port [:rfc:`6513`]
    mdtp = 3232, 'mdtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WhiskerControl main port
    #: - [UDP] WhiskerControl main port
    whisker = 3233, 'whisker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alchemy Server
    #: - [UDP] Alchemy Server
    alchemy = 3234, 'alchemy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MDAP port
    #: - [UDP] MDAP Port
    mdap_port = 3235, 'mdap-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] appareNet Test Server
    #: - [UDP] appareNet Test Server
    apparenet_ts = 3236, 'apparenet-ts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] appareNet Test Packet Sequencer
    #: - [UDP] appareNet Test Packet Sequencer
    apparenet_tps = 3237, 'apparenet-tps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] appareNet Analysis Server
    #: - [UDP] appareNet Analysis Server
    apparenet_as = 3238, 'apparenet-as', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] appareNet User Interface
    #: - [UDP] appareNet User Interface
    apparenet_ui = 3239, 'apparenet-ui', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trio Motion Control Port
    #: - [UDP] Trio Motion Control Port
    triomotion = 3240, 'triomotion', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SysOrb Monitoring Server
    #: - [UDP] SysOrb Monitoring Server
    sysorb = 3241, 'sysorb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Session Description ID
    #: - [UDP] Session Description ID
    sdp_id_port = 3242, 'sdp-id-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Timelot Port
    #: - [UDP] Timelot Port
    timelot = 3243, 'timelot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OneSAF
    #: - [UDP] OneSAF
    onesaf = 3244, 'onesaf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VIEO Fabric Executive
    #: - [UDP] VIEO Fabric Executive
    vieo_fe = 3245, 'vieo-fe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DVT SYSTEM PORT
    #: - [UDP] DVT SYSTEM PORT
    dvt_system = 3246, 'dvt-system', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DVT DATA LINK
    #: - [UDP] DVT DATA LINK
    dvt_data = 3247, 'dvt-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PROCOS LM
    #: - [UDP] PROCOS LM
    procos_lm = 3248, 'procos-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] State Sync Protocol
    #: - [UDP] State Sync Protocol
    ssp = 3249, 'ssp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HMS hicp port
    #: - [UDP] HMS hicp port
    hicp = 3250, 'hicp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sys Scanner
    #: - [UDP] Sys Scanner
    sysscanner = 3251, 'sysscanner', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DHE port
    #: - [UDP] DHE port
    dhe = 3252, 'dhe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PDA Data
    #: - [UDP] PDA Data
    pda_data = 3253, 'pda-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PDA System
    #: - [UDP] PDA System
    pda_sys = 3254, 'pda-sys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Semaphore Connection Port
    #: - [UDP] Semaphore Connection Port
    semaphore = 3255, 'semaphore', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compaq RPM Agent Port
    #: - [UDP] Compaq RPM Agent Port
    cpqrpm_agent = 3256, 'cpqrpm-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compaq RPM Server Port
    #: - [UDP] Compaq RPM Server Port
    cpqrpm_server = 3257, 'cpqrpm-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ivecon Server Port
    #: - [UDP] Ivecon Server Port
    ivecon_port = 3258, 'ivecon-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Epson Network Common Devi
    #: - [UDP] Epson Network Common Devi
    epncdp2 = 3259, 'epncdp2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iSCSI port [:rfc:`7143`]
    #: - [UDP] iSCSI port [:rfc:`7143`]
    iscsi_target = 3260, 'iscsi-target', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] winShadow
    #: - [UDP] winShadow
    winshadow = 3261, 'winshadow', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NECP
    #: - [UDP] NECP
    necp = 3262, 'necp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] E-Color Enterprise Imager
    #: - [UDP] E-Color Enterprise Imager
    ecolor_imager = 3263, 'ecolor-imager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cc:mail/lotus
    #: - [UDP] cc:mail/lotus
    ccmail = 3264, 'ccmail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Altav Tunnel
    #: - [UDP] Altav Tunnel
    altav_tunnel = 3265, 'altav-tunnel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NS CFG Server
    #: - [UDP] NS CFG Server
    ns_cfg_server = 3266, 'ns-cfg-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Dial Out
    #: - [UDP] IBM Dial Out
    ibm_dial_out = 3267, 'ibm-dial-out', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Global Catalog
    #: - [UDP] Microsoft Global Catalog
    msft_gc = 3268, 'msft-gc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Global Catalog with LDAP/SSL
    #: - [UDP] Microsoft Global Catalog with LDAP/SSL
    msft_gc_ssl = 3269, 'msft-gc-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Verismart
    #: - [UDP] Verismart
    verismart = 3270, 'verismart', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSoft Prev Port
    #: - [UDP] CSoft Prev Port
    csoft_prev = 3271, 'csoft-prev', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu User Manager
    #: - [UDP] Fujitsu User Manager
    user_manager = 3272, 'user-manager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Extensible Multiplexed Protocol
    #: - [UDP] Simple Extensible Multiplexed Protocol
    sxmp = 3273, 'sxmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ordinox Server
    #: - [UDP] Ordinox Server
    ordinox_server = 3274, 'ordinox-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SAMD
    #: - [UDP] SAMD
    samd = 3275, 'samd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Maxim ASICs
    #: - [UDP] Maxim ASICs
    maxim_asics = 3276, 'maxim-asics', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AWG Proxy
    #: - [UDP] AWG Proxy
    awg_proxy = 3277, 'awg-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LKCM Server
    #: - [UDP] LKCM Server
    lkcmserver = 3278, 'lkcmserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VS Server
    #: - [UDP] VS Server
    vs_server = 3280, 'vs-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SYSOPT
    #: - [UDP] SYSOPT
    sysopt = 3281, 'sysopt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Datusorb
    #: - [UDP] Datusorb
    datusorb = 3282, 'datusorb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net Assistant
    #: - [UDP] Net Assistant
    net_assistant = 3283, 'net-assistant', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 4Talk
    #: - [UDP] 4Talk
    UDP_4talk = 3284, '4talk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Plato
    #: - [UDP] Plato
    plato = 3285, 'plato', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] E-Net
    #: - [UDP] E-Net
    e_net = 3286, 'e-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DIRECTVDATA
    #: - [UDP] DIRECTVDATA
    directvdata = 3287, 'directvdata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] COPS
    #: - [UDP] COPS
    cops = 3288, 'cops', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ENPC
    #: - [UDP] ENPC
    enpc = 3289, 'enpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CAPS LOGISTICS TOOLKIT - LM
    #: - [UDP] CAPS LOGISTICS TOOLKIT - LM
    caps_lm = 3290, 'caps-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] S A Holditch & Associates - LM
    #: - [UDP] S A Holditch & Associates - LM
    sah_lm = 3291, 'sah-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cart O Rama
    #: - [UDP] Cart O Rama
    cart_o_rama = 3292, 'cart-o-rama', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fg-fps
    #: - [UDP] fg-fps
    fg_fps = 3293, 'fg-fps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fg-gip
    #: - [UDP] fg-gip
    fg_gip = 3294, 'fg-gip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dynamic IP Lookup
    #: - [UDP] Dynamic IP Lookup
    dyniplookup = 3295, 'dyniplookup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rib License Manager
    #: - [UDP] Rib License Manager
    rib_slm = 3296, 'rib-slm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cytel License Manager
    #: - [UDP] Cytel License Manager
    cytel_lm = 3297, 'cytel-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DeskView
    #: - [UDP] DeskView
    deskview = 3298, 'deskview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pdrncs
    #: - [UDP] pdrncs
    pdrncs = 3299, 'pdrncs', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3300 = 3300, 'reserved', TransportProtocol.udp

    #: - [TCP] Tarantool in-memory computing platform
    #: - [UDP] Tarantool in-memory computing platform
    tarantool = 3301, 'tarantool', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCS Fastmail
    #: - [UDP] MCS Fastmail
    mcs_fastmail = 3302, 'mcs-fastmail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OP Session Client
    #: - [UDP] OP Session Client
    opsession_clnt = 3303, 'opsession-clnt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OP Session Server
    #: - [UDP] OP Session Server
    opsession_srvr = 3304, 'opsession-srvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ODETTE-FTP [:rfc:`5024`]
    #: - [UDP] ODETTE-FTP [:rfc:`5024`]
    odette_ftp = 3305, 'odette-ftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MySQL
    #: - [UDP] MySQL
    mysql = 3306, 'mysql', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OP Session Proxy
    #: - [UDP] OP Session Proxy
    opsession_prxy = 3307, 'opsession-prxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TNS Server
    #: - [UDP] TNS Server
    tns_server = 3308, 'tns-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TNS ADV
    #: - [UDP] TNS ADV
    tns_adv = 3309, 'tns-adv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dyna Access
    #: - [UDP] Dyna Access
    dyna_access = 3310, 'dyna-access', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCNS Tel Ret
    #: - [UDP] MCNS Tel Ret
    mcns_tel_ret = 3311, 'mcns-tel-ret', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Application Management Server
    #: - [UDP] Application Management Server
    appman_server = 3312, 'appman-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unify Object Broker
    #: - [UDP] Unify Object Broker
    uorb = 3313, 'uorb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unify Object Host
    #: - [UDP] Unify Object Host
    uohost = 3314, 'uohost', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CDID
    #: - [UDP] CDID
    cdid = 3315, 'cdid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AICC/CMI
    #: - [UDP] AICC/CMI
    aicc_cmi = 3316, 'aicc-cmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSAI PORT
    #: - [UDP] VSAI PORT
    vsaiport = 3317, 'vsaiport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Swith to Swith Routing Information Protocol
    #: - [UDP] Swith to Swith Routing Information Protocol
    ssrip = 3318, 'ssrip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SDT License Manager
    #: - [UDP] SDT License Manager
    sdt_lmd = 3319, 'sdt-lmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Office Link 2000
    #: - [UDP] Office Link 2000
    officelink2000 = 3320, 'officelink2000', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VNSSTR
    #: - [UDP] VNSSTR
    vnsstr = 3321, 'vnsstr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SFTU
    #: - [UDP] SFTU
    sftu = 3326, 'sftu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BBARS
    #: - [UDP] BBARS
    bbars = 3327, 'bbars', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Eaglepoint License Manager
    #: - [UDP] Eaglepoint License Manager
    egptlm = 3328, 'egptlm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP Device Disc
    #: - [UDP] HP Device Disc
    hp_device_disc = 3329, 'hp-device-disc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCS Calypso ICF
    #: - [UDP] MCS Calypso ICF
    mcs_calypsoicf = 3330, 'mcs-calypsoicf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCS Messaging
    #: - [UDP] MCS Messaging
    mcs_messaging = 3331, 'mcs-messaging', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCS Mail Server
    #: - [UDP] MCS Mail Server
    mcs_mailsvr = 3332, 'mcs-mailsvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DEC Notes
    #: - [UDP] DEC Notes
    dec_notes = 3333, 'dec-notes', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Direct TV Webcasting
    #: - [UDP] Direct TV Webcasting
    directv_web = 3334, 'directv-web', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Direct TV Software Updates
    #: - [UDP] Direct TV Software Updates
    directv_soft = 3335, 'directv-soft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Direct TV Tickers
    #: - [UDP] Direct TV Tickers
    directv_tick = 3336, 'directv-tick', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Direct TV Data Catalog
    #: - [UDP] Direct TV Data Catalog
    directv_catlg = 3337, 'directv-catlg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMF data b
    #: - [UDP] OMF data b
    anet_b = 3338, 'anet-b', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMF data l
    #: - [UDP] OMF data l
    anet_l = 3339, 'anet-l', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMF data m
    #: - [UDP] OMF data m
    anet_m = 3340, 'anet-m', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMF data h
    #: - [UDP] OMF data h
    anet_h = 3341, 'anet-h', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WebTIE
    #: - [UDP] WebTIE
    webtie = 3342, 'webtie', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS Cluster Net
    #: - [UDP] MS Cluster Net
    ms_cluster_net = 3343, 'ms-cluster-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BNT Manager
    #: - [UDP] BNT Manager
    bnt_manager = 3344, 'bnt-manager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Influence
    #: - [UDP] Influence
    influence = 3345, 'influence', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trnsprnt Proxy
    #: - [UDP] Trnsprnt Proxy
    trnsprntproxy = 3346, 'trnsprntproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Phoenix RPC
    #: - [UDP] Phoenix RPC
    phoenix_rpc = 3347, 'phoenix-rpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pangolin Laser
    #: - [UDP] Pangolin Laser
    pangolin_laser = 3348, 'pangolin-laser', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Chevin Services
    #: - [UDP] Chevin Services
    chevinservices = 3349, 'chevinservices', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FINDVIATV
    #: - [UDP] FINDVIATV
    findviatv = 3350, 'findviatv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Btrieve port
    #: - [UDP] Btrieve port
    btrieve = 3351, 'btrieve', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Scalable SQL
    #: - [UDP] Scalable SQL
    ssql = 3352, 'ssql', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FATPIPE
    #: - [UDP] FATPIPE
    fatpipe = 3353, 'fatpipe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SUITJD
    #: - [UDP] SUITJD
    suitjd = 3354, 'suitjd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ordinox Dbase
    #: - [UDP] Ordinox Dbase
    ordinox_dbase = 3355, 'ordinox-dbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UPNOTIFYPS
    #: - [UDP] UPNOTIFYPS
    upnotifyps = 3356, 'upnotifyps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Adtech Test IP
    #: - [UDP] Adtech Test IP
    adtech_test = 3357, 'adtech-test', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mp Sys Rmsvr
    #: - [UDP] Mp Sys Rmsvr
    mpsysrmsvr = 3358, 'mpsysrmsvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WG NetForce
    #: - [UDP] WG NetForce
    wg_netforce = 3359, 'wg-netforce', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KV Server
    #: - [UDP] KV Server
    kv_server = 3360, 'kv-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KV Agent
    #: - [UDP] KV Agent
    kv_agent = 3361, 'kv-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DJ ILM
    #: - [UDP] DJ ILM
    dj_ilm = 3362, 'dj-ilm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NATI Vi Server
    #: - [UDP] NATI Vi Server
    nati_vi_server = 3363, 'nati-vi-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CreativeServer
    #: - [UDP] CreativeServer
    creativeserver_453 = 453, 'creativeserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Creative Server
    #: - [UDP] Creative Server
    creativeserver_3364 = 3364, 'creativeserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ContentServer
    #: - [UDP] ContentServer
    contentserver_454 = 454, 'contentserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Content Server
    #: - [UDP] Content Server
    contentserver_3365 = 3365, 'contentserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CreativePartnr
    #: - [UDP] CreativePartnr
    creativepartnr_455 = 455, 'creativepartnr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Creative Partner
    #: - [UDP] Creative Partner
    creativepartnr_3366 = 3366, 'creativepartnr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TIP 2
    #: - [UDP] TIP 2
    tip2 = 3372, 'tip2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lavenir License Manager
    #: - [UDP] Lavenir License Manager
    lavenir_lm = 3373, 'lavenir-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cluster Disc
    #: - [UDP] Cluster Disc
    cluster_disc = 3374, 'cluster-disc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSNM Agent
    #: - [UDP] VSNM Agent
    vsnm_agent = 3375, 'vsnm-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CD Broker
    #: - [UDP] CD Broker
    cdbroker = 3376, 'cdbroker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cogsys Network License Manager
    #: - [UDP] Cogsys Network License Manager
    cogsys_lm = 3377, 'cogsys-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WSICOPY
    #: - [UDP] WSICOPY
    wsicopy = 3378, 'wsicopy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SOCORFS
    #: - [UDP] SOCORFS
    socorfs = 3379, 'socorfs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNS Channels
    #: - [UDP] SNS Channels
    sns_channels = 3380, 'sns-channels', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Geneous
    #: - [UDP] Geneous
    geneous = 3381, 'geneous', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Network Enhanced Antitheft function
    #: - [UDP] Fujitsu Network Enhanced Antitheft function
    fujitsu_neat = 3382, 'fujitsu-neat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Enterprise Software Products License Manager
    #: - [UDP] Enterprise Software Products License Manager
    esp_lm = 3383, 'esp-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cluster Management Services
    #: - [UDP] Hardware Management
    hp_clic = 3384, 'hp-clic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qnxnetman
    #: - [UDP] qnxnetman
    qnxnetman = 3385, 'qnxnetman', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] GPRS SIG
    gprs_sig = 3386, 'gprs-sig', TransportProtocol.udp

    #: - [TCP] Back Room Net
    #: - [UDP] Back Room Net
    backroomnet = 3387, 'backroomnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CB Server
    #: - [UDP] CB Server
    cbserver = 3388, 'cbserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS WBT Server
    #: - [UDP] MS WBT Server
    ms_wbt_server = 3389, 'ms-wbt-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Distributed Service Coordinator
    #: - [UDP] Distributed Service Coordinator
    dsc = 3390, 'dsc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SAVANT
    #: - [UDP] SAVANT
    savant = 3391, 'savant', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EFI License Management
    #: - [UDP] EFI License Management
    efi_lm = 3392, 'efi-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D2K Tapestry Client to Server
    #: - [UDP] D2K Tapestry Client to Server
    d2k_tapestry1 = 3393, 'd2k-tapestry1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D2K Tapestry Server to Server
    #: - [UDP] D2K Tapestry Server to Server
    d2k_tapestry2 = 3394, 'd2k-tapestry2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dyna License Manager (Elam)
    #: - [UDP] Dyna License Manager (Elam)
    dyna_lm = 3395, 'dyna-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Printer Agent IANA assigned this well-formed service name as a
    #:   replacement for "printer_agent".
    #: - [TCP] Printer Agent
    #: - [UDP] Printer Agent IANA assigned this well-formed service name as a
    #:   replacement for "printer_agent".
    #: - [UDP] Printer Agent
    printer_agent = 3396, 'printer-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cloanto License Manager
    #: - [UDP] Cloanto License Manager
    cloanto_lm = 3397, 'cloanto-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mercantile
    #: - [UDP] Mercantile
    mercantile = 3398, 'mercantile', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSMS
    #: - [UDP] CSMS
    csms = 3399, 'csms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSMS2
    #: - [UDP] CSMS2
    csms2 = 3400, 'csms2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] filecast
    #: - [UDP] filecast
    filecast = 3401, 'filecast', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FXa Engine Network Port
    #: - [UDP] FXa Engine Network Port
    fxaengine_net = 3402, 'fxaengine-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nokia Announcement ch 1
    #: - [UDP] Nokia Announcement ch 1
    nokia_ann_ch1 = 3405, 'nokia-ann-ch1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nokia Announcement ch 2
    #: - [UDP] Nokia Announcement ch 2
    nokia_ann_ch2 = 3406, 'nokia-ann-ch2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LDAP admin server port
    #: - [UDP] LDAP admin server port
    ldap_admin = 3407, 'ldap-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BES Api Port
    #: - [UDP] BES Api Port
    besapi = 3408, 'besapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetworkLens Event Port
    #: - [UDP] NetworkLens Event Port
    networklens = 3409, 'networklens', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetworkLens SSL Event
    #: - [UDP] NetworkLens SSL Event
    networklenss = 3410, 'networklenss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BioLink Authenteon server
    #: - [UDP] BioLink Authenteon server
    biolink_auth = 3411, 'biolink-auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xmlBlaster
    #: - [UDP] xmlBlaster
    xmlblaster = 3412, 'xmlblaster', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SpecView Networking
    #: - [UDP] SpecView Networking
    svnet = 3413, 'svnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BroadCloud WIP Port
    #: - [UDP] BroadCloud WIP Port
    wip_port = 3414, 'wip-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BCI Name Service
    #: - [UDP] BCI Name Service
    bcinameservice = 3415, 'bcinameservice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AirMobile IS Command Port
    #: - [UDP] AirMobile IS Command Port
    commandport = 3416, 'commandport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ConServR file translation
    #: - [UDP] ConServR file translation
    csvr = 3417, 'csvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote nmap
    #: - [UDP] Remote nmap
    rnmap = 3418, 'rnmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Isogon SoftAudit
    #: - [UDP] ISogon SoftAudit
    softaudit = 3419, 'softaudit', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iFCP User Port [:rfc:`4172`]
    #: - [UDP] iFCP User Port [:rfc:`4172`]
    ifcp_port = 3420, 'ifcp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bull Apprise portmapper
    #: - [UDP] Bull Apprise portmapper
    bmap = 3421, 'bmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote USB System Port
    #: - [UDP] Remote USB System Port
    rusb_sys_port = 3422, 'rusb-sys-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xTrade Reliable Messaging
    #: - [UDP] xTrade Reliable Messaging
    xtrm = 3423, 'xtrm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xTrade over TLS/SSL
    #: - [UDP] xTrade over TLS/SSL
    xtrms = 3424, 'xtrms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AGPS Access Port
    #: - [UDP] AGPS Access Port
    agps_port = 3425, 'agps-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Arkivio Storage Protocol
    #: - [UDP] Arkivio Storage Protocol
    arkivio = 3426, 'arkivio', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WebSphere SNMP
    #: - [UDP] WebSphere SNMP
    websphere_snmp = 3427, 'websphere-snmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 2Wire CSS
    #: - [UDP] 2Wire CSS
    twcss = 3428, 'twcss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GCSP user port
    #: - [UDP] GCSP user port
    gcsp = 3429, 'gcsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Scott Studios Dispatch
    #: - [UDP] Scott Studios Dispatch
    ssdispatch = 3430, 'ssdispatch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Active License Server Port
    #: - [UDP] Active License Server Port
    ndl_als = 3431, 'ndl-als', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Device Protocol
    #: - [UDP] Secure Device Protocol
    osdcp = 3432, 'osdcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPNET Service Management Platform
    #: - [UDP] OPNET Service Management Platform
    opnet_smp = 3433, 'opnet-smp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenCM Server
    #: - [UDP] OpenCM Server
    opencm = 3434, 'opencm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pacom Security User Port
    #: - [UDP] Pacom Security User Port
    pacom = 3435, 'pacom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GuardControl Exchange Protocol
    #: - [UDP] GuardControl Exchange Protocol
    gc_config = 3436, 'gc-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Autocue Directory Service
    #: - [UDP] Autocue Directory Service
    autocueds = 3437, 'autocueds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Spiralcraft Admin
    #: - [UDP] Spiralcraft Admin
    spiral_admin = 3438, 'spiral-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HRI Interface Port
    #: - [UDP] HRI Interface Port
    hri_port = 3439, 'hri-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net Steward Mgmt Console
    #: - [UDP] Net Steward Mgmt Console
    ans_console = 3440, 'ans-console', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OC Connect Client
    #: - [UDP] OC Connect Client
    connect_client = 3441, 'connect-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OC Connect Server
    #: - [UDP] OC Connect Server
    connect_server = 3442, 'connect-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView Network Node Manager WEB Server
    #: - [UDP] OpenView Network Node Manager WEB Server
    ov_nnm_websrv = 3443, 'ov-nnm-websrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Denali Server
    #: - [UDP] Denali Server
    denali_server = 3444, 'denali-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Media Object Network Protocol
    #: - [UDP] Media Object Network Protocol
    monp = 3445, 'monp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3Com FAX RPC port
    #: - [UDP] 3Com FAX RPC port
    UDP_3comfaxrpc = 3446, '3comfaxrpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DirectNet IM System
    #: - [UDP] DirectNet IM System
    directnet = 3447, 'directnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Discovery and Net Config
    #: - [UDP] Discovery and Net Config
    dnc_port = 3448, 'dnc-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HotU Chat
    #: - [UDP] HotU Chat
    hotu_chat = 3449, 'hotu-chat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CAStorProxy
    #: - [UDP] CAStorProxy
    castorproxy = 3450, 'castorproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASAM Services
    #: - [UDP] ASAM Services
    asam = 3451, 'asam', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SABP-Signalling Protocol
    #: - [UDP] SABP-Signalling Protocol
    sabp_signal = 3452, 'sabp-signal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PSC Update
    #: - [UDP] PSC Update
    pscupd = 3453, 'pscupd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apple Remote Access Protocol
    #: - [UDP] Apple Remote Access Protocol
    mira = 3454, 'mira', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSVP Port
    #: - [UDP] RSVP Port
    prsvp = 3455, 'prsvp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VAT default data
    #: - [UDP] VAT default data
    vat = 3456, 'vat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VAT default control
    #: - [UDP] VAT default control
    vat_control = 3457, 'vat-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D3WinOSFI
    #: - [UDP] D3WinOSFI
    d3winosfi = 3458, 'd3winosfi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TIP Integral
    #: - [UDP] TIP Integral
    integral = 3459, 'integral', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EDM Manger
    #: - [UDP] EDM Manger
    edm_manager = 3460, 'edm-manager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EDM Stager
    #: - [UDP] EDM Stager
    edm_stager = 3461, 'edm-stager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EDM STD Notify
    #: - [UDP] EDM STD Notify
    edm_std_notify = 3462, 'edm-std-notify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EDM ADM Notify
    #: - [UDP] EDM ADM Notify
    edm_adm_notify = 3463, 'edm-adm-notify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EDM MGR Sync
    #: - [UDP] EDM MGR Sync
    edm_mgr_sync = 3464, 'edm-mgr-sync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EDM MGR Cntrl
    #: - [UDP] EDM MGR Cntrl
    edm_mgr_cntrl = 3465, 'edm-mgr-cntrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WORKFLOW
    #: - [UDP] WORKFLOW
    workflow = 3466, 'workflow', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RCST
    #: - [UDP] RCST
    rcst = 3467, 'rcst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TTCM Remote Controll
    #: - [UDP] TTCM Remote Controll
    ttcmremotectrl = 3468, 'ttcmremotectrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pluribus
    #: - [UDP] Pluribus
    pluribus = 3469, 'pluribus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] jt400
    #: - [UDP] jt400
    jt400 = 3470, 'jt400', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] jt400-ssl
    #: - [UDP] jt400-ssl
    jt400_ssl = 3471, 'jt400-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JAUGS N-G Remotec 1
    #: - [UDP] JAUGS N-G Remotec 1
    jaugsremotec_1 = 3472, 'jaugsremotec-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JAUGS N-G Remotec 2
    #: - [UDP] JAUGS N-G Remotec 2
    jaugsremotec_2 = 3473, 'jaugsremotec-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TSP Automation
    #: - [UDP] TSP Automation
    ttntspauto = 3474, 'ttntspauto', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Genisar Comm Port
    #: - [UDP] Genisar Comm Port
    genisar_port = 3475, 'genisar-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NVIDIA Mgmt Protocol
    #: - [UDP] NVIDIA Mgmt Protocol
    nppmp = 3476, 'nppmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eComm link port
    #: - [UDP] eComm link port
    ecomm = 3477, 'ecomm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Session Traversal Utilities for NAT (STUN) port [:rfc:`8489`]
    #: - [UDP] Session Traversal Utilities for NAT (STUN) port [:rfc:`8489`]
    stun = 3478, 'stun', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TURN over TCP [:rfc:`8656`]
    #: - [UDP] TURN over UDP [:rfc:`8656`]
    turn = 3478, 'turn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STUN Behavior Discovery over TCP [:rfc:`5780`]
    #: - [UDP] STUN Behavior Discovery over UDP [:rfc:`5780`]
    stun_behavior = 3478, 'stun-behavior', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 2Wire RPC
    #: - [UDP] 2Wire RPC
    twrpc = 3479, 'twrpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Virtual Workspace
    #: - [UDP] Secure Virtual Workspace
    plethora = 3480, 'plethora', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CleanerLive remote ctrl
    #: - [UDP] CleanerLive remote ctrl
    cleanerliverc = 3481, 'cleanerliverc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vulture Monitoring System
    #: - [UDP] Vulture Monitoring System
    vulture = 3482, 'vulture', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Slim Devices Protocol
    #: - [UDP] Slim Devices Protocol
    slim_devices = 3483, 'slim-devices', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GBS SnapTalk Protocol
    #: - [UDP] GBS SnapTalk Protocol
    gbs_stp = 3484, 'gbs-stp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CelaTalk
    #: - [UDP] CelaTalk
    celatalk = 3485, 'celatalk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IFSF Heartbeat Port
    #: - [UDP] IFSF Heartbeat Port
    ifsf_hb_port = 3486, 'ifsf-hb-port', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] LISA UDP Transfer Channel
    ltcudp = 3487, 'ltcudp', TransportProtocol.udp

    #: - [TCP] FS Remote Host Server
    #: - [UDP] FS Remote Host Server
    fs_rh_srv = 3488, 'fs-rh-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DTP/DIA
    #: - [UDP] DTP/DIA
    dtp_dia = 3489, 'dtp-dia', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Colubris Management Port
    #: - [UDP] Colubris Management Port
    colubris = 3490, 'colubris', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SWR Port
    #: - [UDP] SWR Port
    swr_port = 3491, 'swr-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TVDUM Tray Port
    #: - [UDP] TVDUM Tray Port
    tvdumtray_port = 3492, 'tvdumtray-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network UPS Tools [:rfc:`9271`]
    #: - [UDP] Network UPS Tools
    nut = 3493, 'nut', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM 3494
    #: - [UDP] IBM 3494
    ibm3494 = 3494, 'ibm3494', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] securitylayer over tcp
    #: - [UDP] securitylayer over tcp
    seclayer_tcp = 3495, 'seclayer-tcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] securitylayer over tls
    #: - [UDP] securitylayer over tls
    seclayer_tls = 3496, 'seclayer-tls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ipEther232Port
    #: - [UDP] ipEther232Port
    ipether232port = 3497, 'ipether232port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DASHPAS user port
    #: - [UDP] DASHPAS user port
    dashpas_port = 3498, 'dashpas-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SccIP Media
    #: - [UDP] SccIP Media
    sccip_media = 3499, 'sccip-media', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RTMP Port
    #: - [UDP] RTMP Port
    rtmp_port = 3500, 'rtmp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iSoft-P2P
    #: - [UDP] iSoft-P2P
    isoft_p2p = 3501, 'isoft-p2p', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avocent Install Discovery
    #: - [UDP] Avocent Install Discovery
    avinstalldisc = 3502, 'avinstalldisc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MPLS LSP-echo Port [:rfc:`8029`]
    #: - [UDP] MPLS LSP-echo Port [:rfc:`8029`]
    lsp_ping = 3503, 'lsp-ping', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IronStorm game server
    #: - [UDP] IronStorm game server
    ironstorm = 3504, 'ironstorm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CCM communications port
    #: - [UDP] CCM communications port
    ccmcomm = 3505, 'ccmcomm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 3506
    #: - [UDP] APC 3506
    apc_3506 = 3506, 'apc-3506', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nesh Broker Port
    #: - [UDP] Nesh Broker Port
    nesh_broker = 3507, 'nesh-broker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Interaction Web
    #: - [UDP] Interaction Web
    interactionweb = 3508, 'interactionweb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Token SSL Port
    #: - [UDP] Virtual Token SSL Port
    vt_ssl = 3509, 'vt-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XSS Port
    #: - [UDP] XSS Port
    xss_port = 3510, 'xss-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WebMail/2
    #: - [UDP] WebMail/2
    webmail_2 = 3511, 'webmail-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aztec Distribution Port
    #: - [UDP] Aztec Distribution Port
    aztec = 3512, 'aztec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Adaptec Remote Protocol
    #: - [UDP] Adaptec Remote Protocol
    arcpd = 3513, 'arcpd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MUST Peer to Peer
    #: - [UDP] MUST Peer to Peer
    must_p2p = 3514, 'must-p2p', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MUST Backplane
    #: - [UDP] MUST Backplane
    must_backplane = 3515, 'must-backplane', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Smartcard Port
    #: - [UDP] Smartcard Port
    smartcard_port = 3516, 'smartcard-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IEEE 802.11 WLANs WG IAPP
    #: - [UDP] IEEE 802.11 WLANs WG IAPP
    UDP_802_11_iapp = 3517, '802-11-iapp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Artifact Message Server
    #: - [UDP] Artifact Message Server
    artifact_msg = 3518, 'artifact-msg', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Netvion Galileo Port
    galileo = 3519, 'galileo', TransportProtocol.udp

    #: - [TCP] Netvion Galileo Log Port
    #: - [UDP] Netvion Galileo Log Port
    galileolog = 3520, 'galileolog', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Telequip Labs MC3SS
    #: - [UDP] Telequip Labs MC3SS
    mc3ss = 3521, 'mc3ss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DO over NSSocketPort
    #: - [UDP] DO over NSSocketPort
    nssocketport = 3522, 'nssocketport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Odeum Serverlink
    #: - [UDP] Odeum Serverlink
    odeumservlink = 3523, 'odeumservlink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ECM Server port
    #: - [UDP] ECM Server port
    ecmport = 3524, 'ecmport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EIS Server port
    #: - [UDP] EIS Server port
    eisport = 3525, 'eisport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] starQuiz Port
    #: - [UDP] starQuiz Port
    starquiz_port = 3526, 'starquiz-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS Backup Exec Server
    #: - [UDP] VERITAS Backup Exec Server
    beserver_msg_q = 3527, 'beserver-msg-q', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JBoss IIOP
    #: - [UDP] JBoss IIOP
    jboss_iiop = 3528, 'jboss-iiop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JBoss IIOP/SSL
    #: - [UDP] JBoss IIOP/SSL
    jboss_iiop_ssl = 3529, 'jboss-iiop-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Grid Friendly
    #: - [UDP] Grid Friendly
    gf = 3530, 'gf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Joltid
    #: - [UDP] Joltid
    joltid = 3531, 'joltid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Raven Remote Management Control
    #: - [UDP] Raven Remote Management Control
    raven_rmp = 3532, 'raven-rmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Raven Remote Management Data
    #: - [UDP] Raven Remote Management Data
    raven_rdp = 3533, 'raven-rdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] URL Daemon Port
    #: - [UDP] URL Daemon Port
    urld_port = 3534, 'urld-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS-LA
    #: - [UDP] MS-LA
    ms_la = 3535, 'ms-la', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNAC
    #: - [UDP] SNAC
    snac = 3536, 'snac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote NI-VISA port
    #: - [UDP] Remote NI-VISA port
    ni_visa_remote = 3537, 'ni-visa-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Directory Server
    #: - [UDP] IBM Directory Server
    ibm_diradm = 3538, 'ibm-diradm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Directory Server SSL
    #: - [UDP] IBM Directory Server SSL
    ibm_diradm_ssl = 3539, 'ibm-diradm-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PNRP User Port
    #: - [UDP] PNRP User Port
    pnrp_port = 3540, 'pnrp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VoiSpeed Port
    #: - [UDP] VoiSpeed Port
    voispeed_port = 3541, 'voispeed-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HA cluster monitor
    #: - [UDP] HA cluster monitor
    hacl_monitor = 3542, 'hacl-monitor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] qftest Lookup Port
    #: - [UDP] qftest Lookup Port
    qftest_lookup = 3543, 'qftest-lookup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Teredo Port [:rfc:`4380`]
    #: - [UDP] Teredo Port [:rfc:`4380`]
    teredo = 3544, 'teredo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CAMAC equipment
    #: - [UDP] CAMAC equipment
    camac = 3545, 'camac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Symantec SIM
    #: - [UDP] Symantec SIM
    symantec_sim = 3547, 'symantec-sim', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Interworld
    #: - [UDP] Interworld
    interworld = 3548, 'interworld', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tellumat MDR NMS
    #: - [UDP] Tellumat MDR NMS
    tellumat_nms = 3549, 'tellumat-nms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure SMPP
    #: - [UDP] Secure SMPP
    ssmpp = 3550, 'ssmpp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apcupsd Information Port
    #: - [UDP] Apcupsd Information Port
    apcupsd = 3551, 'apcupsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TeamAgenda Server Port
    #: - [UDP] TeamAgenda Server Port
    taserver = 3552, 'taserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Red Box Recorder ADP
    #: - [UDP] Red Box Recorder ADP
    rbr_discovery = 3553, 'rbr-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quest Notification Server
    #: - [UDP] Quest Notification Server
    questnotify = 3554, 'questnotify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vipul's Razor
    #: - [UDP] Vipul's Razor
    razor = 3555, 'razor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sky Transport Protocol
    #: - [UDP] Sky Transport Protocol
    sky_transport = 3556, 'sky-transport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PersonalOS Comm Port
    #: - [UDP] PersonalOS Comm Port
    personalos_001 = 3557, 'personalos-001', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCP user port
    #: - [UDP] MCP user port
    mcp_port = 3558, 'mcp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CCTV control port
    #: - [UDP] CCTV control port
    cctv_port = 3559, 'cctv-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INIServe port
    #: - [UDP] INIServe port
    iniserve_port = 3560, 'iniserve-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC-OneKey
    #: - [UDP] BMC-OneKey
    bmc_onekey = 3561, 'bmc-onekey', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SDBProxy
    #: - [UDP] SDBProxy
    sdbproxy = 3562, 'sdbproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Watcom Debug
    #: - [UDP] Watcom Debug
    watcomdebug = 3563, 'watcomdebug', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Electromed SIM port
    #: - [UDP] Electromed SIM port
    esimport = 3564, 'esimport', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3565 = 3565, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3566 = 3566, 'reserved', TransportProtocol.udp

    #: - [TCP] DOF Protocol Stack
    #: - [UDP] DOF Protocol Stack
    dof_eps = 3567, 'dof-eps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DOF Secure Tunnel
    #: - [UDP] DOF Secure Tunnel
    dof_tunnel_sec = 3568, 'dof-tunnel-sec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Meinberg Control Service
    #: - [UDP] Meinberg Control Service
    mbg_ctrl = 3569, 'mbg-ctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCC Web Server Port
    #: - [UDP] MCC Web Server Port
    mccwebsvr_port = 3570, 'mccwebsvr-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MegaRAID Server Port
    #: - [UDP] MegaRAID Server Port
    megardsvr_port = 3571, 'megardsvr-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Registration Server Port
    #: - [UDP] Registration Server Port
    megaregsvrport = 3572, 'megaregsvrport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Advantage Group UPS Suite
    #: - [UDP] Advantage Group UPS Suite
    tag_ups_1 = 3573, 'tag-ups-1', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] DMAF Caster
    dmaf_caster = 3574, 'dmaf-caster', TransportProtocol.udp

    #: - [TCP] Coalsere CCM Port
    #: - [UDP] Coalsere CCM Port
    ccm_port = 3575, 'ccm-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Coalsere CMC Port
    #: - [UDP] Coalsere CMC Port
    cmc_port = 3576, 'cmc-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Configuration Port
    #: - [UDP] Configuration Port
    config_port = 3577, 'config-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Port
    #: - [UDP] Data Port
    data_port = 3578, 'data-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tarantella Load Balancing
    #: - [UDP] Tarantella Load Balancing
    ttat3lb = 3579, 'ttat3lb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NATI-ServiceLocator
    #: - [UDP] NATI-ServiceLocator
    nati_svrloc = 3580, 'nati-svrloc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ascent Capture Licensing
    #: - [UDP] Ascent Capture Licensing
    kfxaclicensing = 3581, 'kfxaclicensing', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PEG PRESS Server
    #: - [UDP] PEG PRESS Server
    press = 3582, 'press', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CANEX Watch System
    #: - [UDP] CANEX Watch System
    canex_watch = 3583, 'canex-watch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] U-DBase Access Protocol
    #: - [UDP] U-DBase Access Protocol
    u_dbap = 3584, 'u-dbap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Emprise License Server
    #: - [UDP] Emprise License Server
    emprise_lls = 3585, 'emprise-lls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] License Server Console
    #: - [UDP] License Server Console
    emprise_lsc = 3586, 'emprise-lsc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Peer to Peer Grouping
    #: - [UDP] Peer to Peer Grouping
    p2pgroup = 3587, 'p2pgroup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sentinel Server
    #: - [UDP] Sentinel Server
    sentinel = 3588, 'sentinel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] isomair
    #: - [UDP] isomair
    isomair = 3589, 'isomair', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WV CSP SMS Binding
    #: - [UDP] WV CSP SMS Binding
    wv_csp_sms = 3590, 'wv-csp-sms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LOCANIS G-TRACK Server
    #: - [UDP] LOCANIS G-TRACK Server
    gtrack_server = 3591, 'gtrack-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LOCANIS G-TRACK NE Port
    #: - [UDP] LOCANIS G-TRACK NE Port
    gtrack_ne = 3592, 'gtrack-ne', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BP Model Debugger
    #: - [UDP] BP Model Debugger
    bpmd = 3593, 'bpmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MediaSpace
    #: - [UDP] MediaSpace
    mediaspace = 3594, 'mediaspace', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ShareApp
    #: - [UDP] ShareApp
    shareapp = 3595, 'shareapp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Illusion Wireless MMOG
    #: - [UDP] Illusion Wireless MMOG
    iw_mmogame = 3596, 'iw-mmogame', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A14 (AN-to-SC/MM)
    #: - [UDP] A14 (AN-to-SC/MM)
    a14 = 3597, 'a14', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A15 (AN-to-AN)
    #: - [UDP] A15 (AN-to-AN)
    a15 = 3598, 'a15', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quasar Accounting Server
    #: - [UDP] Quasar Accounting Server
    quasar_server = 3599, 'quasar-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] text relay-answer
    #: - [UDP] text relay-answer
    trap_daemon = 3600, 'trap-daemon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Visinet Gui
    #: - [UDP] Visinet Gui
    visinet_gui = 3601, 'visinet-gui', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] InfiniSwitch Mgr Client
    #: - [UDP] InfiniSwitch Mgr Client
    infiniswitchcl = 3602, 'infiniswitchcl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Integrated Rcvr Control
    #: - [UDP] Integrated Rcvr Control
    int_rcv_cntrl = 3603, 'int-rcv-cntrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC JMX Port
    #: - [UDP] BMC JMX Port
    bmc_jmx_port = 3604, 'bmc-jmx-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ComCam IO Port
    #: - [UDP] ComCam IO Port
    comcam_io = 3605, 'comcam-io', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Splitlock Server
    #: - [UDP] Splitlock Server
    splitlock = 3606, 'splitlock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Precise I3
    #: - [UDP] Precise I3
    precise_i3 = 3607, 'precise-i3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trendchip control protocol
    #: - [UDP] Trendchip control protocol
    trendchip_dcp = 3608, 'trendchip-dcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CPDI PIDAS Connection Mon
    #: - [UDP] CPDI PIDAS Connection Mon
    cpdi_pidas_cm = 3609, 'cpdi-pidas-cm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ECHONET
    #: - [UDP] ECHONET
    echonet = 3610, 'echonet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Six Degrees Port
    #: - [UDP] Six Degrees Port
    six_degrees = 3611, 'six-degrees', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Micro Focus Data Protector
    #: - [UDP] Micro Focus Data Protector
    dataprotector = 3612, 'dataprotector', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alaris Device Discovery
    #: - [UDP] Alaris Device Discovery
    alaris_disc = 3613, 'alaris-disc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Satchwell Sigma
    #: - [UDP] Satchwell Sigma
    sigma_port = 3614, 'sigma-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Start Messaging Network
    #: - [UDP] Start Messaging Network
    start_network = 3615, 'start-network', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] cd3o Control Protocol
    #: - [UDP] cd3o Control Protocol
    cd3o_protocol = 3616, 'cd3o-protocol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ATI SHARP Logic Engine
    #: - [UDP] ATI SHARP Logic Engine
    sharp_server = 3617, 'sharp-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AAIR-Network 1
    #: - [UDP] AAIR-Network 1
    aairnet_1 = 3618, 'aairnet-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AAIR-Network 2
    #: - [UDP] AAIR-Network 2
    aairnet_2 = 3619, 'aairnet-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPSON Projector Control Port
    #: - [UDP] EPSON Projector Control Port
    ep_pcp = 3620, 'ep-pcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPSON Network Screen Port
    #: - [UDP] EPSON Network Screen Port
    ep_nsp = 3621, 'ep-nsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FF LAN Redundancy Port
    #: - [UDP] FF LAN Redundancy Port
    ff_lr_port = 3622, 'ff-lr-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HAIPIS Dynamic Discovery
    #: - [UDP] HAIPIS Dynamic Discovery
    haipe_discover = 3623, 'haipe-discover', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Distributed Upgrade Port
    #: - [UDP] Distributed Upgrade Port
    dist_upgrade = 3624, 'dist-upgrade', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Volley
    #: - [UDP] Volley
    volley = 3625, 'volley', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bvControl Daemon
    #: - [UDP] bvControl Daemon
    bvcdaemon_port = 3626, 'bvcdaemon-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jam Server Port
    #: - [UDP] Jam Server Port
    jamserverport = 3627, 'jamserverport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPT Machine Interface
    #: - [UDP] EPT Machine Interface
    ept_machine = 3628, 'ept-machine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESC/VP.net
    #: - [UDP] ESC/VP.net
    escvpnet = 3629, 'escvpnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] C&S Remote Database Port
    #: - [UDP] C&S Remote Database Port
    cs_remote_db = 3630, 'cs-remote-db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] C&S Web Services Port
    #: - [UDP] C&S Web Services Port
    cs_services = 3631, 'cs-services', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] distributed compiler
    #: - [UDP] distributed compiler
    distcc = 3632, 'distcc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wyrnix AIS port
    #: - [UDP] Wyrnix AIS port
    wacp = 3633, 'wacp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hNTSP Library Manager
    #: - [UDP] hNTSP Library Manager
    hlibmgr = 3634, 'hlibmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Distributed Objects
    #: - [UDP] Simple Distributed Objects
    sdo = 3635, 'sdo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SerVistaITSM
    #: - [UDP] SerVistaITSM
    servistaitsm = 3636, 'servistaitsm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Customer Service Port
    #: - [UDP] Customer Service Port
    scservp = 3637, 'scservp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EHP Backup Protocol
    #: - [UDP] EHP Backup Protocol
    ehp_backup = 3638, 'ehp-backup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Extensible Automation
    #: - [UDP] Extensible Automation
    xap_ha = 3639, 'xap-ha', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netplay Port 1
    #: - [UDP] Netplay Port 1
    netplay_port1 = 3640, 'netplay-port1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netplay Port 2
    #: - [UDP] Netplay Port 2
    netplay_port2 = 3641, 'netplay-port2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Juxml Replication port
    #: - [UDP] Juxml Replication port
    juxml_port = 3642, 'juxml-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AudioJuggler
    #: - [UDP] AudioJuggler
    audiojuggler = 3643, 'audiojuggler', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ssowatch
    #: - [UDP] ssowatch
    ssowatch = 3644, 'ssowatch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cyc
    #: - [UDP] Cyc
    cyc = 3645, 'cyc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XSS Server Port
    #: - [UDP] XSS Server Port
    xss_srv_port = 3646, 'xss-srv-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Splitlock Gateway
    #: - [UDP] Splitlock Gateway
    splitlock_gw = 3647, 'splitlock-gw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fujitsu Cooperation Port
    #: - [UDP] Fujitsu Cooperation Port
    fjcp = 3648, 'fjcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nishioka Miyuki Msg Protocol
    #: - [UDP] Nishioka Miyuki Msg Protocol
    nmmp = 3649, 'nmmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PRISMIQ VOD plug-in
    #: - [UDP] PRISMIQ VOD plug-in
    prismiq_plugin = 3650, 'prismiq-plugin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XRPC Registry
    #: - [UDP] XRPC Registry
    xrpc_registry = 3651, 'xrpc-registry', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VxCR NBU Default Port
    #: - [UDP] VxCR NBU Default Port
    vxcrnbuport = 3652, 'vxcrnbuport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tunnel Setup Protocol [:rfc:`5572`]
    #: - [UDP] Tunnel Setup Protocol [:rfc:`5572`]
    tsp = 3653, 'tsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VAP RealTime Messenger
    #: - [UDP] VAP RealTime Messenger
    vaprtm = 3654, 'vaprtm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ActiveBatch Exec Agent
    #: - [UDP] ActiveBatch Exec Agent
    abatemgr = 3655, 'abatemgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ActiveBatch Job Scheduler
    #: - [UDP] ActiveBatch Job Scheduler
    abatjss = 3656, 'abatjss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ImmediaNet Beacon
    #: - [UDP] ImmediaNet Beacon
    immedianet_bcn = 3657, 'immedianet-bcn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PlayStation AMS (Secure)
    #: - [UDP] PlayStation AMS (Secure)
    ps_ams = 3658, 'ps-ams', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apple SASL
    #: - [UDP] Apple SASL
    apple_sasl = 3659, 'apple-sasl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Tivoli Directory Service using SSL
    #: - [UDP] IBM Tivoli Directory Service using SSL
    can_nds_ssl = 3660, 'can-nds-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Tivoli Directory Service using SSL
    #: - [UDP] IBM Tivoli Directory Service using SSL
    can_ferret_ssl = 3661, 'can-ferret-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pserver
    #: - [UDP] pserver
    pserver = 3662, 'pserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DIRECWAY Tunnel Protocol
    #: - [UDP] DIRECWAY Tunnel Protocol
    dtp = 3663, 'dtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UPS Engine Port
    #: - [UDP] UPS Engine Port
    ups_engine = 3664, 'ups-engine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Enterprise Engine Port
    #: - [UDP] Enterprise Engine Port
    ent_engine = 3665, 'ent-engine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM eServer PAP
    #: - [UDP] IBM EServer PAP
    eserver_pap = 3666, 'eserver-pap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Information Exchange
    #: - [UDP] IBM Information Exchange
    infoexch = 3667, 'infoexch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dell Remote Management
    #: - [UDP] Dell Remote Management
    dell_rm_port = 3668, 'dell-rm-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA SAN Switch Management
    #: - [UDP] CA SAN Switch Management
    casanswmgmt = 3669, 'casanswmgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMILE TCP/UDP Interface
    #: - [UDP] SMILE TCP/UDP Interface
    smile = 3670, 'smile', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] e Field Control (EIBnet)
    #: - [UDP] e Field Control (EIBnet)
    efcp = 3671, 'efcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LispWorks ORB
    #: - [UDP] LispWorks ORB
    lispworks_orb = 3672, 'lispworks-orb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Openview Media Vault GUI
    #: - [UDP] Openview Media Vault GUI
    mediavault_gui = 3673, 'mediavault-gui', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WinINSTALL IPC Port
    #: - [UDP] WinINSTALL IPC Port
    wininstall_ipc = 3674, 'wininstall-ipc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CallTrax Data Port
    #: - [UDP] CallTrax Data Port
    calltrax = 3675, 'calltrax', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VisualAge Pacbase server
    #: - [UDP] VisualAge Pacbase server
    va_pacbase = 3676, 'va-pacbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RoverLog IPC
    #: - [UDP] RoverLog IPC
    roverlog = 3677, 'roverlog', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DataGuardianLT
    #: - [UDP] DataGuardianLT
    ipr_dglt = 3678, 'ipr-dglt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Newton Dock
    #: - [UDP] Newton Dock
    newton_dock = 3679, 'newton-dock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NPDS Tracker
    #: - [UDP] NPDS Tracker
    npds_tracker = 3680, 'npds-tracker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BTS X73 Port
    #: - [UDP] BTS X73 Port
    bts_x73 = 3681, 'bts-x73', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMC SmartPackets-MAPI
    #: - [UDP] EMC SmartPackets-MAPI
    cas_mapi = 3682, 'cas-mapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC EDV/EA
    #: - [UDP] BMC EDV/EA
    bmc_ea = 3683, 'bmc-ea', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FAXstfX
    #: - [UDP] FAXstfX
    faxstfx_port = 3684, 'faxstfx-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DS Expert Agent
    #: - [UDP] DS Expert Agent
    dsx_agent = 3685, 'dsx-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trivial Network Management
    #: - [UDP] Trivial Network Management
    tnmpv2 = 3686, 'tnmpv2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] simple-push
    #: - [UDP] simple-push
    simple_push = 3687, 'simple-push', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] simple-push Secure
    #: - [UDP] simple-push Secure
    simple_push_s = 3688, 'simple-push-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Digital Audio Access Protocol (iTunes)
    #: - [UDP] Digital Audio Access Protocol (iTunes)
    daap = 3689, 'daap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Magaya Network Port
    #: - [UDP] Magaya Network Port
    magaya_network = 3691, 'magaya-network', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Brimstone IntelSync
    #: - [UDP] Brimstone IntelSync
    intelsync = 3692, 'intelsync', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3693 = 3693, 'reserved', TransportProtocol.udp

    #: - [TCP] BMC Data Collection
    #: - [UDP] BMC Data Collection
    bmc_data_coll = 3695, 'bmc-data-coll', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Telnet Com Port Control
    #: - [UDP] Telnet Com Port Control
    telnetcpcd = 3696, 'telnetcpcd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NavisWorks License System
    #: - [UDP] NavisWorks License System
    nw_license = 3697, 'nw-license', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SAGECTLPANEL
    #: - [UDP] SAGECTLPANEL
    sagectlpanel = 3698, 'sagectlpanel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Internet Call Waiting
    #: - [UDP] Internet Call Waiting
    kpn_icw = 3699, 'kpn-icw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LRS NetPage
    #: - [UDP] LRS NetPage
    lrs_paging = 3700, 'lrs-paging', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetCelera
    #: - [UDP] NetCelera
    netcelera = 3701, 'netcelera', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Web Service Discovery
    #: - [UDP] Web Service Discovery
    ws_discovery = 3702, 'ws-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Adobe Server 3
    #: - [UDP] Adobe Server 3
    adobeserver_3 = 3703, 'adobeserver-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Adobe Server 4
    #: - [UDP] Adobe Server 4
    adobeserver_4 = 3704, 'adobeserver-4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Adobe Server 5
    #: - [UDP] Adobe Server 5
    adobeserver_5 = 3705, 'adobeserver-5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Real-Time Event Port
    #: - [UDP] Real-Time Event Port
    rt_event = 3706, 'rt-event', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Real-Time Event Secure Port
    #: - [UDP] Real-Time Event Secure Port
    rt_event_s = 3707, 'rt-event-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun App Svr - Naming
    #: - [UDP] Sun App Svr - Naming
    sun_as_iiops = 3708, 'sun-as-iiops', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA-IDMS Server
    #: - [UDP] CA-IDMS Server
    ca_idms = 3709, 'ca-idms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PortGate Authentication
    #: - [UDP] PortGate Authentication
    portgate_auth = 3710, 'portgate-auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EBD Server 2
    #: - [UDP] EBD Server 2
    edb_server2 = 3711, 'edb-server2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sentinel Enterprise
    #: - [UDP] Sentinel Enterprise
    sentinel_ent = 3712, 'sentinel-ent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TFTP over TLS
    #: - [UDP] TFTP over TLS
    tftps = 3713, 'tftps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DELOS Direct Messaging
    #: - [UDP] DELOS Direct Messaging
    delos_dms = 3714, 'delos-dms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Anoto Rendezvous Port
    #: - [UDP] Anoto Rendezvous Port
    anoto_rendezv = 3715, 'anoto-rendezv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WV CSP SMS CIR Channel
    #: - [UDP] WV CSP SMS CIR Channel
    wv_csp_sms_cir = 3716, 'wv-csp-sms-cir', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WV CSP UDP/IP CIR Channel
    #: - [UDP] WV CSP UDP/IP CIR Channel
    wv_csp_udp_cir = 3717, 'wv-csp-udp-cir', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPUS Server Port
    #: - [UDP] OPUS Server Port
    opus_services = 3718, 'opus-services', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iTel Server Port
    #: - [UDP] iTel Server Port
    itelserverport = 3719, 'itelserverport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UF Astro. Instr. Services
    #: - [UDP] UF Astro. Instr. Services
    ufastro_instr = 3720, 'ufastro-instr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xsync
    #: - [UDP] Xsync
    xsync = 3721, 'xsync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xserve RAID
    #: - [UDP] Xserve RAID
    xserveraid = 3722, 'xserveraid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sychron Service Daemon
    #: - [UDP] Sychron Service Daemon
    sychrond = 3723, 'sychrond', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] World of Warcraft
    #: - [UDP] World of Warcraft
    blizwow = 3724, 'blizwow', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netia NA-ER Port
    #: - [UDP] Netia NA-ER Port
    na_er_tip = 3725, 'na-er-tip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xyratex Array Manager
    #: - [UDP] Xyratex Array Manager
    array_manager = 3726, 'array-manager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ericsson Mobile Data Unit
    #: - [UDP] Ericsson Mobile Data Unit
    e_mdu = 3727, 'e-mdu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ericsson Web on Air
    #: - [UDP] Ericsson Web on Air
    e_woa = 3728, 'e-woa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fireking Audit Port
    #: - [UDP] Fireking Audit Port
    fksp_audit = 3729, 'fksp-audit', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Client Control
    #: - [UDP] Client Control
    client_ctrl = 3730, 'client-ctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Manager
    #: - [UDP] Service Manager
    smap = 3731, 'smap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mobile Wnn
    #: - [UDP] Mobile Wnn
    m_wnn = 3732, 'm-wnn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multipuesto Msg Port
    #: - [UDP] Multipuesto Msg Port
    multip_msg = 3733, 'multip-msg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Synel Data Collection Port
    #: - [UDP] Synel Data Collection Port
    synel_data = 3734, 'synel-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Password Distribution
    #: - [UDP] Password Distribution
    pwdis = 3735, 'pwdis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RealSpace RMI
    #: - [UDP] RealSpace RMI
    rs_rmi = 3736, 'rs-rmi', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3737 = 3737, 'reserved', TransportProtocol.udp

    #: - [TCP] versaTalk Server Port
    #: - [UDP] versaTalk Server Port
    versatalk = 3738, 'versatalk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Launchbird LicenseManager
    #: - [UDP] Launchbird LicenseManager
    launchbird_lm = 3739, 'launchbird-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Heartbeat Protocol
    #: - [UDP] Heartbeat Protocol
    heartbeat = 3740, 'heartbeat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WysDM Agent
    #: - [UDP] WysDM Agent
    wysdma = 3741, 'wysdma', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CST - Configuration & Service Tracker
    #: - [UDP] CST - Configuration & Service Tracker
    cst_port = 3742, 'cst-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IP Control Systems Ltd.
    #: - [UDP] IP Control Systems Ltd.
    ipcs_command = 3743, 'ipcs-command', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SASG
    #: - [UDP] SASG
    sasg = 3744, 'sasg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GWRTC Call Port
    #: - [UDP] GWRTC Call Port
    gw_call_port = 3745, 'gw-call-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LXPRO.COM LinkTest
    #: - [UDP] LXPRO.COM LinkTest
    linktest = 3746, 'linktest', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LXPRO.COM LinkTest SSL
    #: - [UDP] LXPRO.COM LinkTest SSL
    linktest_s = 3747, 'linktest-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] webData
    #: - [UDP] webData
    webdata = 3748, 'webdata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CimTrak
    #: - [UDP] CimTrak
    cimtrak = 3749, 'cimtrak', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CBOS/IP ncapsalation port
    #: - [UDP] CBOS/IP ncapsalation port
    cbos_ip_port = 3750, 'cbos-ip-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CommLinx GPRS Cube
    #: - [UDP] CommLinx GPRS Cube
    gprs_cube = 3751, 'gprs-cube', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vigil-IP RemoteAgent
    #: - [UDP] Vigil-IP RemoteAgent
    vipremoteagent = 3752, 'vipremoteagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NattyServer Port
    #: - [UDP] NattyServer Port
    nattyserver = 3753, 'nattyserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TimesTen Broker Port
    #: - [UDP] TimesTen Broker Port
    timestenbroker = 3754, 'timestenbroker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SAS Remote Help Server
    #: - [UDP] SAS Remote Help Server
    sas_remote_hlp = 3755, 'sas-remote-hlp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Canon CAPT Port
    #: - [UDP] Canon CAPT Port
    canon_capt = 3756, 'canon-capt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GRF Server Port
    #: - [UDP] GRF Server Port
    grf_port = 3757, 'grf-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] apw RMI registry
    #: - [UDP] apw RMI registry
    apw_registry = 3758, 'apw-registry', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Exapt License Manager
    #: - [UDP] Exapt License Manager
    exapt_lmgr = 3759, 'exapt-lmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] adTempus Client
    #: - [UDP] adTEmpus Client
    adtempusclient = 3760, 'adtempusclient', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gsakmp port [:rfc:`4535`]
    #: - [UDP] gsakmp port [:rfc:`4535`]
    gsakmp = 3761, 'gsakmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GBS SnapMail Protocol
    #: - [UDP] GBS SnapMail Protocol
    gbs_smp = 3762, 'gbs-smp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XO Wave Control Port
    #: - [UDP] XO Wave Control Port
    xo_wave = 3763, 'xo-wave', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MNI Protected Routing
    #: - [UDP] MNI Protected Routing
    mni_prot_rout = 3764, 'mni-prot-rout', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Traceroute
    #: - [UDP] Remote Traceroute
    rtraceroute = 3765, 'rtraceroute', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3766 = 3766, 'reserved', TransportProtocol.udp

    #: - [TCP] ListMGR Port
    #: - [UDP] ListMGR Port
    listmgr_port = 3767, 'listmgr-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rblcheckd server daemon
    #: - [UDP] rblcheckd server daemon
    rblcheckd = 3768, 'rblcheckd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HAIPE Network Keying
    #: - [UDP] HAIPE Network Keying
    haipe_otnk = 3769, 'haipe-otnk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cinderella Collaboration
    #: - [UDP] Cinderella Collaboration
    cindycollab = 3770, 'cindycollab', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RTP Paging Port
    #: - [UDP] RTP Paging Port
    paging_port = 3771, 'paging-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Chantry Tunnel Protocol
    #: - [UDP] Chantry Tunnel Protocol
    ctp = 3772, 'ctp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ctdhercules
    #: - [UDP] ctdhercules
    ctdhercules = 3773, 'ctdhercules', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ZICOM
    #: - [UDP] ZICOM
    zicom = 3774, 'zicom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISPM Manager Port
    #: - [UDP] ISPM Manager Port
    ispmmgr = 3775, 'ispmmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Device Provisioning Port
    #: - [UDP] Device Provisioning Port
    dvcprov_port = 3776, 'dvcprov-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jibe EdgeBurst
    #: - [UDP] Jibe EdgeBurst
    jibe_eb = 3777, 'jibe-eb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cutler-Hammer IT Port
    #: - [UDP] Cutler-Hammer IT Port
    c_h_it_port = 3778, 'c-h-it-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cognima Replication
    #: - [UDP] Cognima Replication
    cognima = 3779, 'cognima', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nuzzler Network Protocol
    #: - [UDP] Nuzzler Network Protocol
    nnp = 3780, 'nnp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ABCvoice server port
    #: - [UDP] ABCvoice server port
    abcvoice_port = 3781, 'abcvoice-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure ISO TP0 port
    #: - [UDP] Secure ISO TP0 port
    iso_tp0s = 3782, 'iso-tp0s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Impact Mgr./PEM Gateway
    #: - [UDP] Impact Mgr./PEM Gateway
    bim_pem = 3783, 'bim-pem', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BFD Control Protocol [:rfc:`5881`]
    #: - [UDP] BFD Control Protocol [:rfc:`5881`]
    bfd_control = 3784, 'bfd-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BFD Echo Protocol [:rfc:`5881`]
    #: - [UDP] BFD Echo Protocol [:rfc:`5881`]
    bfd_echo = 3785, 'bfd-echo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSW Upstrigger port
    #: - [UDP] VSW Upstrigger port
    upstriggervsw = 3786, 'upstriggervsw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fintrx
    #: - [UDP] Fintrx
    fintrx = 3787, 'fintrx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPACEWAY Routing port
    #: - [UDP] SPACEWAY Routing port
    isrp_port = 3788, 'isrp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RemoteDeploy Administration Port [July 2003]
    #: - [UDP] RemoteDeploy Administration Port [July 2003]
    remotedeploy = 3789, 'remotedeploy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QuickBooks RDS
    #: - [UDP] QuickBooks RDS
    quickbooksrds = 3790, 'quickbooksrds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TV NetworkVideo Data port
    #: - [UDP] TV NetworkVideo Data port
    tvnetworkvideo = 3791, 'tvnetworkvideo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] e-Watch Corporation SiteWatch
    #: - [UDP] e-Watch Corporation SiteWatch
    sitewatch = 3792, 'sitewatch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DataCore Software
    #: - [UDP] DataCore Software
    dcsoftware = 3793, 'dcsoftware', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JAUS Robots
    #: - [UDP] JAUS Robots
    jaus = 3794, 'jaus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] myBLAST Mekentosj port
    #: - [UDP] myBLAST Mekentosj port
    myblast = 3795, 'myblast', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Spaceway Dialer
    #: - [UDP] Spaceway Dialer
    spw_dialer = 3796, 'spw-dialer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] idps
    #: - [UDP] idps
    idps = 3797, 'idps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Minilock
    #: - [UDP] Minilock
    minilock = 3798, 'minilock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RADIUS Dynamic Authorization [:rfc:`3576`]
    #: - [UDP] RADIUS Dynamic Authorization [:rfc:`3576`]
    radius_dynauth = 3799, 'radius-dynauth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Print Services Interface
    #: - [UDP] Print Services Interface
    pwgpsi = 3800, 'pwgpsi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ibm manager service
    #: - [UDP] ibm manager service
    ibm_mgr = 3801, 'ibm-mgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VHD
    #: - [UDP] VHD
    vhd = 3802, 'vhd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SoniqSync
    #: - [UDP] SoniqSync
    soniqsync = 3803, 'soniqsync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Harman IQNet Port
    #: - [UDP] Harman IQNet Port
    iqnet_port = 3804, 'iqnet-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ThorGuard Server Port
    #: - [UDP] ThorGuard Server Port
    tcpdataserver = 3805, 'tcpdataserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote System Manager
    #: - [UDP] Remote System Manager
    wsmlb = 3806, 'wsmlb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SpuGNA Communication Port
    #: - [UDP] SpuGNA Communication Port
    spugna = 3807, 'spugna', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun App Svr-IIOPClntAuth
    #: - [UDP] Sun App Svr-IIOPClntAuth
    sun_as_iiops_ca = 3808, 'sun-as-iiops-ca', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Java Desktop System Configuration Agent
    #: - [UDP] Java Desktop System Configuration Agent
    apocd = 3809, 'apocd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WLAN AS server
    #: - [UDP] WLAN AS server
    wlanauth = 3810, 'wlanauth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMP
    #: - [UDP] AMP
    amp = 3811, 'amp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netO WOL Server
    #: - [UDP] netO WOL Server
    neto_wol_server = 3812, 'neto-wol-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rhapsody Interface Protocol
    #: - [UDP] Rhapsody Interface Protocol
    rap_ip = 3813, 'rap-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] netO DCS
    #: - [UDP] netO DCS
    neto_dcs = 3814, 'neto-dcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LANsurveyor XML
    #: - [UDP] LANsurveyor XML
    lansurveyorxml = 3815, 'lansurveyorxml', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun Local Patch Server
    #: - [UDP] Sun Local Patch Server
    sunlps_http = 3816, 'sunlps-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Yosemite Tech Tapeware
    #: - [UDP] Yosemite Tech Tapeware
    tapeware = 3817, 'tapeware', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Crinis Heartbeat
    #: - [UDP] Crinis Heartbeat
    crinis_hb = 3818, 'crinis-hb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPL Sequ Layer Protocol
    #: - [UDP] EPL Sequ Layer Protocol
    epl_slp = 3819, 'epl-slp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Siemens AuD SCP
    #: - [UDP] Siemens AuD SCP
    scp = 3820, 'scp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ATSC PMCP Standard
    #: - [UDP] ATSC PMCP Standard
    pmcp = 3821, 'pmcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compute Pool Discovery
    #: - [UDP] Compute Pool Discovery
    acp_discovery = 3822, 'acp-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compute Pool Conduit
    #: - [UDP] Compute Pool Conduit
    acp_conduit = 3823, 'acp-conduit', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Compute Pool Policy
    #: - [UDP] Compute Pool Policy
    acp_policy = 3824, 'acp-policy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Antera FlowFusion Process Simulation
    #: - [UDP] Antera FlowFusion Process Simulation
    ffserver = 3825, 'ffserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WarMUX game server
    #: - [UDP] WarMUX game server
    warmux = 3826, 'warmux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netadmin Systems MPI service
    #: - [UDP] Netadmin Systems MPI service
    netmpi = 3827, 'netmpi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netadmin Systems Event Handler
    #: - [UDP] Netadmin Systems Event Handler
    neteh = 3828, 'neteh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netadmin Systems Event Handler External
    #: - [UDP] Netadmin Systems Event Handler External
    neteh_ext = 3829, 'neteh-ext', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cerner System Management Agent
    #: - [UDP] Cerner System Management Agent
    cernsysmgmtagt = 3830, 'cernsysmgmtagt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Docsvault Application Service
    #: - [UDP] Docsvault Application Service
    dvapps = 3831, 'dvapps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xxNETserver
    #: - [UDP] xxNETserver
    xxnetserver = 3832, 'xxnetserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AIPN LS Authentication
    #: - [UDP] AIPN LS Authentication
    aipn_auth = 3833, 'aipn-auth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Spectar Data Stream Service
    #: - [UDP] Spectar Data Stream Service
    spectardata = 3834, 'spectardata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Spectar Database Rights Service
    #: - [UDP] Spectar Database Rights Service
    spectardb = 3835, 'spectardb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MARKEM NEXTGEN DCP
    #: - [UDP] MARKEM NEXTGEN DCP
    markem_dcp = 3836, 'markem-dcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MARKEM Auto-Discovery
    #: - [UDP] MARKEM Auto-Discovery
    mkm_discovery = 3837, 'mkm-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Scito Object Server
    #: - [UDP] Scito Object Server
    sos = 3838, 'sos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMX Resource Management Suite
    #: - [UDP] AMX Resource Management Suite
    amx_rms = 3839, 'amx-rms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] www.FlirtMitMir.de
    #: - [UDP] www.FlirtMitMir.de
    flirtmitmir = 3840, 'flirtmitmir', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3841 = 3841, 'reserved', TransportProtocol.udp

    #: - [TCP] NHCI status port
    #: - [UDP] NHCI status port
    nhci = 3842, 'nhci', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quest Common Agent
    #: - [UDP] Quest Common Agent
    quest_agent = 3843, 'quest-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RNM
    #: - [UDP] RNM
    rnm = 3844, 'rnm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] V-ONE Single Port Proxy
    #: - [UDP] V-ONE Single Port Proxy
    v_one_spp = 3845, 'v-one-spp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Astare Network PCP
    #: - [UDP] Astare Network PCP
    an_pcp = 3846, 'an-pcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS Firewall Control
    #: - [UDP] MS Firewall Control
    msfw_control = 3847, 'msfw-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IT Environmental Monitor
    #: - [UDP] IT Environmental Monitor
    item = 3848, 'item', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPACEWAY DNS Preload
    #: - [UDP] SPACEWAY DNS Preload
    spw_dnspreload = 3849, 'spw-dnspreload', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QTMS Bootstrap Protocol
    #: - [UDP] QTMS Bootstrap Protocol
    qtms_bootstrap = 3850, 'qtms-bootstrap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SpectraTalk Port
    #: - [UDP] SpectraTalk Port
    spectraport = 3851, 'spectraport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSE App Configuration
    #: - [UDP] SSE App Configuration
    sse_app_config = 3852, 'sse-app-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SONY scanning protocol
    #: - [UDP] SONY scanning protocol
    sscan = 3853, 'sscan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Stryker Comm Port
    #: - [UDP] Stryker Comm Port
    stryker_com = 3854, 'stryker-com', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenTRAC
    #: - [UDP] OpenTRAC
    opentrac = 3855, 'opentrac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INFORMER
    #: - [UDP] INFORMER
    informer = 3856, 'informer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trap Port
    #: - [UDP] Trap Port
    trap_port = 3857, 'trap-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trap Port MOM
    #: - [UDP] Trap Port MOM
    trap_port_mom = 3858, 'trap-port-mom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Navini Port
    #: - [UDP] Navini Port
    nav_port = 3859, 'nav-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Server/Application State Protocol (SASP)
    #: - [UDP] Server/Application State Protocol (SASP)
    sasp = 3860, 'sasp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] winShadow Host Discovery
    #: - [UDP] winShadow Host Discovery
    winshadow_hd = 3861, 'winshadow-hd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GIGA-POCKET
    #: - [UDP] GIGA-POCKET
    giga_pocket = 3862, 'giga-pocket', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] asap udp port [:rfc:`5352`]
    asap_udp = 3863, 'asap-udp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3864 = 3864, 'reserved', TransportProtocol.udp

    #: - [TCP] xpl automation protocol
    #: - [UDP] xpl automation protocol
    xpl = 3865, 'xpl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun SDViz DZDAEMON Port
    #: - [UDP] Sun SDViz DZDAEMON Port
    dzdaemon = 3866, 'dzdaemon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun SDViz DZOGLSERVER Port
    #: - [UDP] Sun SDViz DZOGLSERVER Port
    dzoglserver = 3867, 'dzoglserver', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_3868 = 3868, 'reserved', TransportProtocol.udp

    #: - [TCP] hp OVSAM MgmtServer Disco
    #: - [UDP] hp OVSAM MgmtServer Disco
    ovsam_mgmt = 3869, 'ovsam-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp OVSAM HostAgent Disco
    #: - [UDP] hp OVSAM HostAgent Disco
    ovsam_d_agent = 3870, 'ovsam-d-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avocent DS Authorization
    #: - [UDP] Avocent DS Authorization
    avocent_adsap = 3871, 'avocent-adsap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OEM Agent
    #: - [UDP] OEM Agent
    oem_agent = 3872, 'oem-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fagordnc
    #: - [UDP] fagordnc
    fagordnc = 3873, 'fagordnc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SixXS Configuration
    #: - [UDP] SixXS Configuration
    sixxsconfig = 3874, 'sixxsconfig', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PNBSCADA
    #: - [UDP] PNBSCADA
    pnbscada = 3875, 'pnbscada', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DirectoryLockdown Agent IANA assigned this well-formed service name as
    #:   a replacement for "dl_agent".
    #: - [TCP] DirectoryLockdown Agent
    #: - [UDP] DirectoryLockdown Agent IANA assigned this well-formed service name as
    #:   a replacement for "dl_agent".
    #: - [UDP] DirectoryLockdown Agent
    dl_agent = 3876, 'dl-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XMPCR Interface Port
    #: - [UDP] XMPCR Interface Port
    xmpcr_interface = 3877, 'xmpcr-interface', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FotoG CAD interface
    #: - [UDP] FotoG CAD interface
    fotogcad = 3878, 'fotogcad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] appss license manager
    #: - [UDP] appss license manager
    appss_lm = 3879, 'appss-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IGRS
    #: - [UDP] IGRS
    igrs = 3880, 'igrs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Acquisition and Control
    #: - [UDP] Data Acquisition and Control
    idac = 3881, 'idac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DTS Service Port
    #: - [UDP] DTS Service Port
    msdts1 = 3882, 'msdts1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VR Peripheral Network
    #: - [UDP] VR Peripheral Network
    vrpn = 3883, 'vrpn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SofTrack Metering
    #: - [UDP] SofTrack Metering
    softrack_meter = 3884, 'softrack-meter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TopFlow SSL
    #: - [UDP] TopFlow SSL
    topflow_ssl = 3885, 'topflow-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NEI management port
    #: - [UDP] NEI management port
    nei_management = 3886, 'nei-management', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ciphire Data Transport
    #: - [UDP] Ciphire Data Transport
    ciphire_data = 3887, 'ciphire-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ciphire Services
    #: - [UDP] Ciphire Services
    ciphire_serv = 3888, 'ciphire-serv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D and V Tester Control Port
    #: - [UDP] D and V Tester Control Port
    dandv_tester = 3889, 'dandv-tester', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Niche Data Server Connect
    #: - [UDP] Niche Data Server Connect
    ndsconnect = 3890, 'ndsconnect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle RTC-PM port
    #: - [UDP] Oracle RTC-PM port
    rtc_pm_port = 3891, 'rtc-pm-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCC-image-port
    #: - [UDP] PCC-image-port
    pcc_image_port = 3892, 'pcc-image-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CGI StarAPI Server
    #: - [UDP] CGI StarAPI Server
    cgi_starapi = 3893, 'cgi-starapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SyAM Agent Port
    #: - [UDP] SyAM Agent Port
    syam_agent = 3894, 'syam-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SyAm SMC Service Port
    #: - [UDP] SyAm SMC Service Port
    syam_smc = 3895, 'syam-smc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Distributed Objects over TLS
    #: - [UDP] Simple Distributed Objects over TLS
    sdo_tls = 3896, 'sdo-tls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Distributed Objects over SSH
    #: - [UDP] Simple Distributed Objects over SSH
    sdo_ssh = 3897, 'sdo-ssh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IAS, Inc. SmartEye NET Internet Protocol
    #: - [UDP] IAS, Inc. SmartEye NET Internet Protocol
    senip = 3898, 'senip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITV Port
    #: - [UDP] ITV Port
    itv_control = 3899, 'itv-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] udt_os IANA assigned this well-formed service name as a replacement
    #:   for "udt_os".
    #: - [TCP] udt_os
    #: - [UDP] udt_os IANA assigned this well-formed service name as a replacement
    #:   for "udt_os".
    #: - [UDP] udt_os
    udt_os_1382 = 1382, 'udt-os', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unidata UDT OS IANA assigned this well-formed service name as a
    #:   replacement for "udt_os".
    #: - [TCP] Unidata UDT OS
    #: - [UDP] Unidata UDT OS IANA assigned this well-formed service name as a
    #:   replacement for "udt_os".
    #: - [UDP] Unidata UDT OS
    udt_os_3900 = 3900, 'udt-os', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NIM Service Handler
    #: - [UDP] NIM Service Handler
    nimsh = 3901, 'nimsh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NIMsh Auxiliary Port
    #: - [UDP] NIMsh Auxiliary Port
    nimaux = 3902, 'nimaux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CharsetMGR
    #: - [UDP] CharsetMGR
    charsetmgr = 3903, 'charsetmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Arnet Omnilink Port
    #: - [UDP] Arnet Omnilink Port
    omnilink_port = 3904, 'omnilink-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mailbox Update (MUPDATE) protocol [:rfc:`3656`]
    #: - [UDP] Mailbox Update (MUPDATE) protocol [:rfc:`3656`]
    mupdate = 3905, 'mupdate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TopoVista elevation data
    #: - [UDP] TopoVista elevation data
    topovista_data = 3906, 'topovista-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Imoguia Port
    #: - [UDP] Imoguia Port
    imoguia_port = 3907, 'imoguia-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP Procurve NetManagement
    #: - [UDP] HP Procurve NetManagement
    hppronetman = 3908, 'hppronetman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SurfControl CPA
    #: - [UDP] SurfControl CPA
    surfcontrolcpa = 3909, 'surfcontrolcpa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Printer Request Port
    #: - [UDP] Printer Request Port
    prnrequest = 3910, 'prnrequest', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Printer Status Port
    #: - [UDP] Printer Status Port
    prnstatus = 3911, 'prnstatus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Global Maintech Stars
    #: - [UDP] Global Maintech Stars
    gbmt_stars = 3912, 'gbmt-stars', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ListCREATOR Port
    #: - [UDP] ListCREATOR Port
    listcrt_port = 3913, 'listcrt-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ListCREATOR Port 2
    #: - [UDP] ListCREATOR Port 2
    listcrt_port_2 = 3914, 'listcrt-port-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Auto-Graphics Cataloging
    #: - [UDP] Auto-Graphics Cataloging
    agcat = 3915, 'agcat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WysDM Controller
    #: - [UDP] WysDM Controller
    wysdmc = 3916, 'wysdmc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AFT multiplex port
    #: - [UDP] AFT multiplex port
    aftmux = 3917, 'aftmux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PacketCableMultimediaCOPS
    #: - [UDP] PacketCableMultimediaCOPS
    pktcablemmcops = 3918, 'pktcablemmcops', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HyperIP
    #: - [UDP] HyperIP
    hyperip = 3919, 'hyperip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Exasoft IP Port
    #: - [UDP] Exasoft IP Port
    exasoftport1 = 3920, 'exasoftport1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Herodotus Net
    #: - [UDP] Herodotus Net
    herodotus_net = 3921, 'herodotus-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Soronti Update Port
    #: - [UDP] Soronti Update Port
    sor_update = 3922, 'sor-update', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Symbian Service Broker
    #: - [UDP] Symbian Service Broker
    symb_sb_port = 3923, 'symb-sb-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MPL_GPRS_PORT
    #: - [UDP] MPL_GPRS_Port
    mpl_gprs_port = 3924, 'mpl-gprs-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zoran Media Port
    #: - [UDP] Zoran Media Port
    zmp = 3925, 'zmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WINPort
    #: - [UDP] WINPort
    winport = 3926, 'winport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ScsTsr
    #: - [UDP] ScsTsr
    natdataservice = 3927, 'natdataservice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PXE NetBoot Manager
    #: - [UDP] PXE NetBoot Manager
    netboot_pxe = 3928, 'netboot-pxe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMS Port
    #: - [UDP] AMS Port
    smauth_port = 3929, 'smauth-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Syam Web Server Port
    #: - [UDP] Syam Web Server Port
    syam_webserver = 3930, 'syam-webserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MSR Plugin Port
    #: - [UDP] MSR Plugin Port
    msr_plugin_port = 3931, 'msr-plugin-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dynamic Site System
    #: - [UDP] Dynamic Site System
    dyn_site = 3932, 'dyn-site', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PL/B App Server User Port
    #: - [UDP] PL/B App Server User Port
    plbserve_port = 3933, 'plbserve-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PL/B File Manager Port
    #: - [UDP] PL/B File Manager Port
    sunfm_port = 3934, 'sunfm-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SDP Port Mapper Protocol
    #: - [UDP] SDP Port Mapper Protocol
    sdp_portmapper = 3935, 'sdp-portmapper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mailprox
    #: - [UDP] Mailprox
    mailprox = 3936, 'mailprox', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DVB Service Discovery
    #: - [UDP] DVB Service Discovery
    dvbservdsc = 3937, 'dvbservdsc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle dbControl Agent po IANA assigned this well-formed service name
    #:   as a replacement for "dbcontrol_agent".
    #: - [TCP] Oracle dbControl Agent po
    #: - [UDP] Oracle dbControl Agent po IANA assigned this well-formed service name
    #:   as a replacement for "dbcontrol_agent".
    #: - [UDP] Oracle dbControl Agent po
    dbcontrol_agent = 3938, 'dbcontrol-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Anti-virus Application Management Port
    #: - [UDP] Anti-virus Application Management Port
    aamp = 3939, 'aamp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XeCP Node Service
    #: - [UDP] XeCP Node Service
    xecp_node = 3940, 'xecp-node', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Home Portal Web Server
    #: - [UDP] Home Portal Web Server
    homeportal_web = 3941, 'homeportal-web', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] satellite distribution
    #: - [UDP] satellite distribution
    srdp = 3942, 'srdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TetraNode Ip Gateway
    #: - [UDP] TetraNode Ip Gateway
    tig = 3943, 'tig', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] S-Ops Management
    #: - [UDP] S-Ops Management
    sops = 3944, 'sops', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMCADS Server Port
    #: - [UDP] EMCADS Server Port
    emcads = 3945, 'emcads', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BackupEDGE Server
    #: - [UDP] BackupEDGE Server
    backupedge = 3946, 'backupedge', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Connect and Control Protocol for Consumer, Commercial, and Industrial
    #:   Electronic Devices
    #: - [UDP] Connect and Control Protocol for Consumer, Commercial, and Industrial
    #:   Electronic Devices
    ccp = 3947, 'ccp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Anton Paar Device Administration Protocol
    #: - [UDP] Anton Paar Device Administration Protocol
    apdap = 3948, 'apdap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dynamic Routing Information Protocol
    #: - [UDP] Dynamic Routing Information Protocol
    drip = 3949, 'drip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Name Munging
    #: - [UDP] Name Munging
    namemunge = 3950, 'namemunge', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PWG IPP Facsimile
    #: - [UDP] PWG IPP Facsimile
    pwgippfax = 3951, 'pwgippfax', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] I3 Session Manager
    #: - [UDP] I3 Session Manager
    i3_sessionmgr = 3952, 'i3-sessionmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Eydeas XMLink Connect
    #: - [UDP] Eydeas XMLink Connect
    xmlink_connect = 3953, 'xmlink-connect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AD Replication RPC
    #: - [UDP] AD Replication RPC
    adrep = 3954, 'adrep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] p2pCommunity
    #: - [UDP] p2pCommunity
    p2pcommunity = 3955, 'p2pcommunity', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GigE Vision Control
    #: - [UDP] GigE Vision Control
    gvcp = 3956, 'gvcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MQEnterprise Broker
    #: - [UDP] MQEnterprise Broker
    mqe_broker = 3957, 'mqe-broker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MQEnterprise Agent
    #: - [UDP] MQEnterprise Agent
    mqe_agent = 3958, 'mqe-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tree Hopper Networking
    #: - [UDP] Tree Hopper Networking
    treehopper = 3959, 'treehopper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bess Peer Assessment
    #: - [UDP] Bess Peer Assessment
    bess = 3960, 'bess', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ProAxess Server
    #: - [UDP] ProAxess Server
    proaxess = 3961, 'proaxess', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SBI Agent Protocol
    #: - [UDP] SBI Agent Protocol
    sbi_agent = 3962, 'sbi-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Teran Hybrid Routing Protocol
    #: - [UDP] Teran Hybrid Routing Protocol
    thrp = 3963, 'thrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SASG GPRS
    #: - [UDP] SASG GPRS
    sasggprs = 3964, 'sasggprs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avanti IP to NCPE API
    #: - [UDP] Avanti IP to NCPE API
    ati_ip_to_ncpe = 3965, 'ati-ip-to-ncpe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BuildForge Lock Manager
    #: - [UDP] BuildForge Lock Manager
    bflckmgr = 3966, 'bflckmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PPS Message Service
    #: - [UDP] PPS Message Service
    ppsms = 3967, 'ppsms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iAnywhere DBNS
    #: - [UDP] iAnywhere DBNS
    ianywhere_dbns = 3968, 'ianywhere-dbns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Landmark Messages
    #: - [UDP] Landmark Messages
    landmarks = 3969, 'landmarks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LANrev Agent
    #: - [UDP] LANrev Agent
    lanrevagent = 3970, 'lanrevagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LANrev Server
    #: - [UDP] LANrev Server
    lanrevserver = 3971, 'lanrevserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ict-control Protocol
    #: - [UDP] ict-control Protocol
    iconp = 3972, 'iconp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ConnectShip Progistics
    #: - [UDP] ConnectShip Progistics
    progistics = 3973, 'progistics', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Applicant Tracking Service
    #: - [UDP] Remote Applicant Tracking Service
    xk22 = 3974, 'xk22', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Air Shot
    #: - [UDP] Air Shot
    airshot = 3975, 'airshot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Server Automation Agent
    #: - [UDP] Server Automation Agent
    opswagent = 3976, 'opswagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Opsware Manager
    #: - [UDP] Opsware Manager
    opswmanager = 3977, 'opswmanager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secured Configuration Server
    #: - [UDP] Secured Configuration Server
    secure_cfg_svr = 3978, 'secure-cfg-svr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Smith Micro Wide Area Network Service
    #: - [UDP] Smith Micro Wide Area Network Service
    smwan = 3979, 'smwan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_3980 = 3980, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Starfish System Admin
    #: - [UDP] Starfish System Admin
    starfish = 3981, 'starfish', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESRI Image Server
    #: - [UDP] ESRI Image Server
    eis = 3982, 'eis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESRI Image Service
    #: - [UDP] ESRI Image Service
    eisp = 3983, 'eisp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MAPPER network node manager
    #: - [UDP] MAPPER network node manager
    mapper_nodemgr = 3984, 'mapper-nodemgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MAPPER TCP/IP server
    #: - [UDP] MAPPER TCP/IP server
    mapper_mapethd = 3985, 'mapper-mapethd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MAPPER workstation server IANA assigned this well-formed service name
    #:   as a replacement for "mapper-ws_ethd".
    #: - [TCP] MAPPER workstation server
    #: - [UDP] MAPPER workstation server IANA assigned this well-formed service name
    #:   as a replacement for "mapper-ws_ethd".
    #: - [UDP] MAPPER workstation server
    mapper_ws_ethd = 3986, 'mapper-ws-ethd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Centerline
    #: - [UDP] Centerline
    centerline = 3987, 'centerline', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DCS Configuration Port
    #: - [UDP] DCS Configuration Port
    dcs_config = 3988, 'dcs-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BindView-Query Engine
    #: - [UDP] BindView-Query Engine
    bv_queryengine = 3989, 'bv-queryengine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BindView-IS
    #: - [UDP] BindView-IS
    bv_is = 3990, 'bv-is', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BindView-SMCServer
    #: - [UDP] BindView-SMCServer
    bv_smcsrv = 3991, 'bv-smcsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BindView-DirectoryServer
    #: - [UDP] BindView-DirectoryServer
    bv_ds = 3992, 'bv-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BindView-Agent
    #: - [UDP] BindView-Agent
    bv_agent = 3993, 'bv-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISS Management Svcs SSL
    #: - [UDP] ISS Management Svcs SSL
    iss_mgmt_ssl = 3995, 'iss-mgmt-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] abcsoftware-01
    #: - [UDP] abcsoftware-01
    abcsoftware = 3996, 'abcsoftware', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] aes_db
    #: - [UDP] aes_db
    agentsease_db = 3997, 'agentsease-db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Distributed Nagios Executor Service
    #: - [UDP] Distributed Nagios Executor Service
    dnx = 3998, 'dnx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Norman distributes scanning service
    #: - [UDP] Norman distributes scanning service
    nvcnet = 3999, 'nvcnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Terabase
    #: - [UDP] Terabase
    terabase = 4000, 'terabase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NewOak
    #: - [UDP] NewOak
    newoak = 4001, 'newoak', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pxc-spvr-ft
    #: - [UDP] pxc-spvr-ft
    pxc_spvr_ft = 4002, 'pxc-spvr-ft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pxc-splr-ft
    #: - [UDP] pxc-splr-ft
    pxc_splr_ft = 4003, 'pxc-splr-ft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pxc-roid
    #: - [UDP] pxc-roid
    pxc_roid = 4004, 'pxc-roid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pxc-pin
    #: - [UDP] pxc-pin
    pxc_pin = 4005, 'pxc-pin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pxc-spvr
    #: - [UDP] pxc-spvr
    pxc_spvr = 4006, 'pxc-spvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pxc-splr
    #: - [UDP] pxc-splr
    pxc_splr = 4007, 'pxc-splr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetCheque accounting
    #: - [UDP] NetCheque accounting
    netcheque = 4008, 'netcheque', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Chimera HWM
    #: - [UDP] Chimera HWM
    chimera_hwm = 4009, 'chimera-hwm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Samsung Unidex
    #: - [UDP] Samsung Unidex
    samsung_unidex = 4010, 'samsung-unidex', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alternate Service Boot
    #: - [UDP] Alternate Service Boot
    altserviceboot = 4011, 'altserviceboot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PDA Gate
    #: - [UDP] PDA Gate
    pda_gate = 4012, 'pda-gate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACL Manager
    #: - [UDP] ACL Manager
    acl_manager = 4013, 'acl-manager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TAICLOCK
    #: - [UDP] TAICLOCK
    taiclock = 4014, 'taiclock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talarian Mcast
    #: - [UDP] Talarian Mcast
    talarian_mcast1 = 4015, 'talarian-mcast1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talarian Mcast
    #: - [UDP] Talarian Mcast
    talarian_mcast2 = 4016, 'talarian-mcast2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talarian Mcast
    #: - [UDP] Talarian Mcast
    talarian_mcast3 = 4017, 'talarian-mcast3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talarian Mcast
    #: - [UDP] Talarian Mcast
    talarian_mcast4 = 4018, 'talarian-mcast4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talarian Mcast
    #: - [UDP] Talarian Mcast
    talarian_mcast5 = 4019, 'talarian-mcast5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRAP Port
    #: - [UDP] TRAP Port
    trap = 4020, 'trap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nexus Portal
    #: - [UDP] Nexus Portal
    nexus_portal = 4021, 'nexus-portal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DNOX
    #: - [UDP] DNOX
    dnox = 4022, 'dnox', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESNM Zoning Port
    #: - [UDP] ESNM Zoning Port
    esnm_zoning = 4023, 'esnm-zoning', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TNP1 User Port
    #: - [UDP] TNP1 User Port
    tnp1_port = 4024, 'tnp1-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Partition Image Port
    #: - [UDP] Partition Image Port
    partimage = 4025, 'partimage', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Graphical Debug Server
    #: - [UDP] Graphical Debug Server
    as_debug = 4026, 'as-debug', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bitxpress
    #: - [UDP] bitxpress
    bxp = 4027, 'bxp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DTServer Port
    #: - [UDP] DTServer Port
    dtserver_port = 4028, 'dtserver-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IP Q signaling protocol
    #: - [UDP] IP Q signaling protocol
    ip_qsig = 4029, 'ip-qsig', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Accell/JSP Daemon Port
    #: - [UDP] Accell/JSP Daemon Port
    jdmn_port = 4030, 'jdmn-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UUCP over SSL
    #: - [UDP] UUCP over SSL
    suucp = 4031, 'suucp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS Authorization Service
    #: - [UDP] VERITAS Authorization Service
    vrts_auth_port = 4032, 'vrts-auth-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SANavigator Peer Port
    #: - [UDP] SANavigator Peer Port
    sanavigator = 4033, 'sanavigator', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ubiquinox Daemon
    #: - [UDP] Ubiquinox Daemon
    ubxd = 4034, 'ubxd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP Push OTA-HTTP port
    #: - [UDP] WAP Push OTA-HTTP port
    wap_push_http = 4035, 'wap-push-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP Push OTA-HTTP secure
    #: - [UDP] WAP Push OTA-HTTP secure
    wap_push_https = 4036, 'wap-push-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RaveHD network control
    #: - [UDP] RaveHD network control
    ravehd = 4037, 'ravehd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fazzt Point-To-Point
    #: - [UDP] Fazzt Point-To-Point
    fazzt_ptp = 4038, 'fazzt-ptp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fazzt Administration
    #: - [UDP] Fazzt Administration
    fazzt_admin = 4039, 'fazzt-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Yo.net main service
    #: - [UDP] Yo.net main service
    yo_main = 4040, 'yo-main', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rocketeer-Houston
    #: - [UDP] Rocketeer-Houston
    houston = 4041, 'houston', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LDXP
    #: - [UDP] LDXP
    ldxp = 4042, 'ldxp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Neighbour Identity Resolution
    #: - [UDP] Neighbour Identity Resolution
    nirp = 4043, 'nirp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Location Tracking Protocol
    #: - [UDP] Location Tracking Protocol
    ltp = 4044, 'ltp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Printing Protocol
    #: - [UDP] Network Printing Protocol
    npp_92 = 92, 'npp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Paging Protocol
    #: - [UDP] Network Paging Protocol
    npp_4045 = 4045, 'npp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Accounting Protocol
    #: - [UDP] Accounting Protocol
    acp_proto = 4046, 'acp-proto', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Context Transfer Protocol
    #: - [UDP] Context Transfer Protocol
    ctp_state = 4047, 'ctp-state', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wide Area File Services
    #: - [UDP] Wide Area File Services
    wafs = 4049, 'wafs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wide Area File Services
    #: - [UDP] Wide Area File Services
    cisco_wafs = 4050, 'cisco-wafs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cisco Peer to Peer Distribution Protocol
    #: - [UDP] Cisco Peer to Peer Distribution Protocol
    cppdp = 4051, 'cppdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VoiceConnect Interact
    #: - [UDP] VoiceConnect Interact
    interact = 4052, 'interact', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CosmoCall Universe Communications Port 1
    #: - [UDP] CosmoCall Universe Communications Port 1
    ccu_comm_1 = 4053, 'ccu-comm-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CosmoCall Universe Communications Port 2
    #: - [UDP] CosmoCall Universe Communications Port 2
    ccu_comm_2 = 4054, 'ccu-comm-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CosmoCall Universe Communications Port 3
    #: - [UDP] CosmoCall Universe Communications Port 3
    ccu_comm_3 = 4055, 'ccu-comm-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Location Message Service
    #: - [UDP] Location Message Service
    lms = 4056, 'lms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Servigistics WFM server
    #: - [UDP] Servigistics WFM server
    wfm = 4057, 'wfm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kingfisher protocol
    #: - [UDP] Kingfisher protocol
    kingfisher = 4058, 'kingfisher', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DLMS/COSEM
    #: - [UDP] DLMS/COSEM
    dlms_cosem = 4059, 'dlms-cosem', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DSMETER Inter-Agent Transfer Channel IANA assigned this well-formed
    #:   service name as a replacement for "dsmeter_iatc".
    #: - [TCP] DSMETER Inter-Agent Transfer Channel
    #: - [UDP] DSMETER Inter-Agent Transfer Channel IANA assigned this well-formed
    #:   service name as a replacement for "dsmeter_iatc".
    #: - [UDP] DSMETER Inter-Agent Transfer Channel
    dsmeter_iatc = 4060, 'dsmeter-iatc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ice Location Service (TCP)
    #: - [UDP] Ice Location Service (TCP)
    ice_location = 4061, 'ice-location', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ice Location Service (SSL)
    #: - [UDP] Ice Location Service (SSL)
    ice_slocation = 4062, 'ice-slocation', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ice Firewall Traversal Service (TCP)
    #: - [UDP] Ice Firewall Traversal Service (TCP)
    ice_router = 4063, 'ice-router', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ice Firewall Traversal Service (SSL)
    #: - [UDP] Ice Firewall Traversal Service (SSL)
    ice_srouter = 4064, 'ice-srouter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Avanti Common Data IANA assigned this well-formed service name as a
    #:   replacement for "avanti_cdp".
    #: - [TCP] Avanti Common Data
    #: - [UDP] Avanti Common Data IANA assigned this well-formed service name as a
    #:   replacement for "avanti_cdp".
    #: - [UDP] Avanti Common Data
    avanti_cdp = 4065, 'avanti-cdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Performance Measurement and Analysis
    #: - [UDP] Performance Measurement and Analysis
    pmas = 4066, 'pmas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Information Distribution Protocol
    #: - [UDP] Information Distribution Protocol
    idp = 4067, 'idp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IP Fleet Broadcast
    #: - [UDP] IP Fleet Broadcast
    ipfltbcst = 4068, 'ipfltbcst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Minger Email Address Validation Service
    #: - [UDP] Minger Email Address Validation Service
    minger = 4069, 'minger', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trivial IP Encryption (TrIPE)
    #: - [UDP] Trivial IP Encryption (TrIPE)
    tripe = 4070, 'tripe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Automatically Incremental Backup
    #: - [UDP] Automatically Incremental Backup
    aibkup = 4071, 'aibkup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zieto Socket Communications
    #: - [UDP] Zieto Socket Communications
    zieto_sock = 4072, 'zieto-sock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Interactive Remote Application Pairing Protocol
    #: - [UDP] Interactive Remote Application Pairing Protocol
    irapp = 4073, 'irapp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cequint City ID UI trigger
    #: - [UDP] Cequint City ID UI trigger
    cequint_cityid = 4074, 'cequint-cityid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ISC Alarm Message Service
    #: - [UDP] ISC Alarm Message Service
    perimlan = 4075, 'perimlan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Seraph DCS
    #: - [UDP] Seraph DCS
    seraph = 4076, 'seraph', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Ascom IP Alarming
    ascomalarm = 4077, 'ascomalarm', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4078 = 4078, 'reserved', TransportProtocol.udp

    #: - [TCP] SANtools Diagnostic Server
    #: - [UDP] SANtools Diagnostic Server
    santools = 4079, 'santools', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lorica inside facing
    #: - [UDP] Lorica inside facing
    lorica_in = 4080, 'lorica-in', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lorica inside facing (SSL)
    #: - [UDP] Lorica inside facing (SSL)
    lorica_in_sec = 4081, 'lorica-in-sec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lorica outside facing
    #: - [UDP] Lorica outside facing
    lorica_out = 4082, 'lorica-out', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lorica outside facing (SSL)
    #: - [UDP] Lorica outside facing (SSL)
    lorica_out_sec = 4083, 'lorica-out-sec', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Fortisphere VM Service
    fortisphere_vm = 4084, 'fortisphere-vm', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4085 = 4085, 'reserved', TransportProtocol.udp

    #: [UDP] Firewall/NAT state table synchronization
    ftsync = 4086, 'ftsync', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4087 = 4087, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4088 = 4088, 'reserved', TransportProtocol.udp

    #: - [TCP] OpenCORE Remote Control Service
    #: - [UDP] OpenCORE Remote Control Service
    opencore = 4089, 'opencore', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA BCAST Service Guide
    #: - [UDP] OMA BCAST Service Guide
    omasgport = 4090, 'omasgport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EminentWare Installer
    #: - [UDP] EminentWare Installer
    ewinstaller = 4091, 'ewinstaller', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EminentWare DGS
    #: - [UDP] EminentWare DGS
    ewdgs = 4092, 'ewdgs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pvx Plus CS Host
    #: - [UDP] Pvx Plus CS Host
    pvxpluscs = 4093, 'pvxpluscs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sysrq daemon
    #: - [UDP] sysrq daemon
    sysrqd = 4094, 'sysrqd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xtgui information service
    #: - [UDP] xtgui information service
    xtgui = 4095, 'xtgui', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BRE (Bridge Relay Element)
    #: - [UDP] BRE (Bridge Relay Element)
    bre = 4096, 'bre', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Patrol View
    #: - [UDP] Patrol View
    patrolview = 4097, 'patrolview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] drmsfsd
    #: - [UDP] drmsfsd
    drmsfsd = 4098, 'drmsfsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DPCP
    #: - [UDP] DPCP
    dpcp = 4099, 'dpcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IGo Incognito Data Port
    #: - [UDP] IGo Incognito Data Port
    igo_incognito = 4100, 'igo-incognito', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Braille protocol
    #: - [UDP] Braille protocol
    brlp_0 = 4101, 'brlp-0', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Braille protocol
    #: - [UDP] Braille protocol
    brlp_1 = 4102, 'brlp-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Braille protocol
    #: - [UDP] Braille protocol
    brlp_2 = 4103, 'brlp-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Braille protocol
    #: - [UDP] Braille protocol
    brlp_3 = 4104, 'brlp-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Shofar
    #: - [UDP] Shofar
    shofar = 4105, 'shofar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Synchronite
    #: - [UDP] Synchronite
    synchronite = 4106, 'synchronite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JDL Accounting LAN Service
    #: - [UDP] JDL Accounting LAN Service
    j_ac = 4107, 'j-ac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACCEL
    #: - [UDP] ACCEL
    accel = 4108, 'accel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Instantiated Zero-control Messaging
    #: - [UDP] Instantiated Zero-control Messaging
    izm = 4109, 'izm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] G2 RFID Tag Telemetry Data
    #: - [UDP] G2 RFID Tag Telemetry Data
    g2tag = 4110, 'g2tag', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xgrid
    #: - [UDP] Xgrid
    xgrid = 4111, 'xgrid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apple VPN Server Reporting Protocol
    #: - [UDP] Apple VPN Server Reporting Protocol
    apple_vpns_rp = 4112, 'apple-vpns-rp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AIPN LS Registration
    #: - [UDP] AIPN LS Registration
    aipn_reg = 4113, 'aipn-reg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JomaMQMonitor
    #: - [UDP] JomaMQMonitor
    jomamqmonitor = 4114, 'jomamqmonitor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CDS Transfer Agent
    #: - [UDP] CDS Transfer Agent
    cds = 4115, 'cds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] smartcard-TLS
    #: - [UDP] smartcard-TLS
    smartcard_tls = 4116, 'smartcard-tls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hillr Connection Manager
    #: - [UDP] Hillr Connection Manager
    hillrserv = 4117, 'hillrserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netadmin Systems NETscript service
    #: - [UDP] Netadmin Systems NETscript service
    netscript = 4118, 'netscript', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Assuria Log Manager
    #: - [UDP] Assuria Log Manager
    assuria_slm = 4119, 'assuria-slm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4120 = 4120, 'reserved', TransportProtocol.udp

    #: - [TCP] e-Builder Application Communication
    #: - [UDP] e-Builder Application Communication
    e_builder = 4121, 'e-builder', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fiber Patrol Alarm Service
    #: - [UDP] Fiber Patrol Alarm Service
    fprams = 4122, 'fprams', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rohill TetraNode Ip Gateway v2
    #: - [UDP] Rohill TetraNode Ip Gateway v2
    tigv2 = 4124, 'tigv2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Opsview Envoy
    #: - [UDP] Opsview Envoy
    opsview_envoy = 4125, 'opsview-envoy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Data Domain Replication Service
    #: - [UDP] Data Domain Replication Service
    ddrepl = 4126, 'ddrepl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetUniKeyServer
    #: - [UDP] NetUniKeyServer
    unikeypro = 4127, 'unikeypro', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NuFW decision delegation protocol
    #: - [UDP] NuFW decision delegation protocol
    nufw = 4128, 'nufw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NuFW authentication protocol
    #: - [UDP] NuFW authentication protocol
    nuauth = 4129, 'nuauth', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FRONET message protocol
    #: - [UDP] FRONET message protocol
    fronet = 4130, 'fronet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Global Maintech Stars
    #: - [UDP] Global Maintech Stars
    stars = 4131, 'stars', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NUTS Daemon IANA assigned this well-formed service name as a
    #:   replacement for "nuts_dem".
    #: - [TCP] NUTS Daemon
    #: - [UDP] NUTS Daemon IANA assigned this well-formed service name as a
    #:   replacement for "nuts_dem".
    #: - [UDP] NUTS Daemon
    nuts_dem = 4132, 'nuts-dem', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NUTS Bootp Server IANA assigned this well-formed service name as a
    #:   replacement for "nuts_bootp".
    #: - [TCP] NUTS Bootp Server
    #: - [UDP] NUTS Bootp Server IANA assigned this well-formed service name as a
    #:   replacement for "nuts_bootp".
    #: - [UDP] NUTS Bootp Server
    nuts_bootp = 4133, 'nuts-bootp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NIFTY-Serve HMI protocol
    #: - [UDP] NIFTY-Serve HMI protocol
    nifty_hmi = 4134, 'nifty-hmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Classic Line Database Server Attach
    #: - [UDP] Classic Line Database Server Attach
    cl_db_attach = 4135, 'cl-db-attach', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Classic Line Database Server Request
    #: - [UDP] Classic Line Database Server Request
    cl_db_request = 4136, 'cl-db-request', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Classic Line Database Server Remote
    #: - [UDP] Classic Line Database Server Remote
    cl_db_remote = 4137, 'cl-db-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nettest
    #: - [UDP] nettest
    nettest = 4138, 'nettest', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Imperfect Networks Server
    #: - [UDP] Imperfect Networks Server
    thrtx = 4139, 'thrtx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cedros Fraud Detection System IANA assigned this well-formed service
    #:   name as a replacement for "cedros_fds".
    #: - [TCP] Cedros Fraud Detection System
    #: - [UDP] Cedros Fraud Detection System IANA assigned this well-formed service
    #:   name as a replacement for "cedros_fds".
    #: - [UDP] Cedros Fraud Detection System
    cedros_fds = 4140, 'cedros-fds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Workflow Server
    #: - [UDP] Workflow Server
    oirtgsvc = 4141, 'oirtgsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Document Server
    #: - [UDP] Document Server
    oidocsvc = 4142, 'oidocsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Document Replication
    #: - [UDP] Document Replication
    oidsr = 4143, 'oidsr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VVR Control
    #: - [UDP] VVR Control
    vvr_control = 4145, 'vvr-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TGCConnect Beacon
    #: - [UDP] TGCConnect Beacon
    tgcconnect = 4146, 'tgcconnect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multum Service Manager
    #: - [UDP] Multum Service Manager
    vrxpservman = 4147, 'vrxpservman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HHB Handheld Client
    #: - [UDP] HHB Handheld Client
    hhb_handheld = 4148, 'hhb-handheld', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A10 GSLB Service
    #: - [UDP] A10 GSLB Service
    agslb = 4149, 'agslb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PowerAlert Network Shutdown Agent
    #: - [UDP] PowerAlert Network Shutdown Agent
    poweralert_nsa = 4150, 'poweralert-nsa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Men & Mice Remote Control IANA assigned this well-formed service name
    #:   as a replacement for "menandmice_noh".
    #: - [TCP] Men & Mice Remote Control
    #: - [UDP] Men & Mice Remote Control IANA assigned this well-formed service name
    #:   as a replacement for "menandmice_noh".
    #: - [UDP] Men & Mice Remote Control
    menandmice_noh = 4151, 'menandmice-noh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iDigTech Multiplex IANA assigned this well-formed service name as a
    #:   replacement for "idig_mux".
    #: - [TCP] iDigTech Multiplex
    #: - [UDP] iDigTech Multiplex IANA assigned this well-formed service name as a
    #:   replacement for "idig_mux".
    #: - [UDP] iDigTech Multiplex
    idig_mux = 4152, 'idig-mux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MBL Remote Battery Monitoring
    #: - [UDP] MBL Remote Battery Monitoring
    mbl_battd = 4153, 'mbl-battd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] atlinks device discovery
    #: - [UDP] atlinks device discovery
    atlinks = 4154, 'atlinks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bazaar version control system
    #: - [UDP] Bazaar version control system
    bzr = 4155, 'bzr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STAT Results
    #: - [UDP] STAT Results
    stat_results = 4156, 'stat-results', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STAT Scanner Control
    #: - [UDP] STAT Scanner Control
    stat_scanner = 4157, 'stat-scanner', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STAT Command Center
    #: - [UDP] STAT Command Center
    stat_cc = 4158, 'stat-cc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Security Service
    #: - [UDP] Network Security Service
    nss = 4159, 'nss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jini Discovery
    #: - [UDP] Jini Discovery
    jini_discovery = 4160, 'jini-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMS Contact
    #: - [UDP] OMS Contact
    omscontact = 4161, 'omscontact', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMS Topology
    #: - [UDP] OMS Topology
    omstopology = 4162, 'omstopology', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Silver Peak Peer Protocol
    #: - [UDP] Silver Peak Peer Protocol
    silverpeakpeer = 4163, 'silverpeakpeer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Silver Peak Communication Protocol
    #: - [UDP] Silver Peak Communication Protocol
    silverpeakcomm = 4164, 'silverpeakcomm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ArcLink over Ethernet
    #: - [UDP] ArcLink over Ethernet
    altcp = 4165, 'altcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Joost Peer to Peer Protocol
    #: - [UDP] Joost Peer to Peer Protocol
    joost = 4166, 'joost', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DeskDirect Global Network
    #: - [UDP] DeskDirect Global Network
    ddgn = 4167, 'ddgn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PrintSoft License Server
    #: - [UDP] PrintSoft License Server
    pslicser = 4168, 'pslicser', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Internet ADT Discovery Protocol
    iadt_disc = 4169, 'iadt-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4170 = 4170, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4171 = 4171, 'reserved', TransportProtocol.udp

    #: - [TCP] PC over IP
    #: - [UDP] PC over IP
    pcoip = 4172, 'pcoip', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] MMA Device Discovery
    mma_discovery = 4173, 'mma-discovery', TransportProtocol.udp

    #: [UDP] StorMagic Discovery
    sm_disc = 4174, 'sm-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4175 = 4175, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4176 = 4176, 'reserved', TransportProtocol.udp

    #: - [TCP] Wello P2P pubsub service
    #: - [UDP] Wello P2P pubsub service
    wello = 4177, 'wello', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] StorMan
    #: - [UDP] StorMan
    storman = 4178, 'storman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Maxum Services
    #: - [UDP] Maxum Services
    maxumsp = 4179, 'maxumsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HTTPX
    #: - [UDP] HTTPX
    httpx = 4180, 'httpx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MacBak
    #: - [UDP] MacBak
    macbak = 4181, 'macbak', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Production Company Pro TCP Service
    #: - [UDP] Production Company Pro TCP Service
    pcptcpservice = 4182, 'pcptcpservice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CyborgNet communications protocol
    #: - [UDP] CyborgNet communications protocol
    cyborgnet = 4183, 'cyborgnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UNIVERSE SUITE MESSAGE SERVICE IANA assigned this well-formed service
    #:   name as a replacement for "universe_suite".
    #: - [TCP] UNIVERSE SUITE MESSAGE SERVICE
    #: - [UDP] UNIVERSE SUITE MESSAGE SERVICE IANA assigned this well-formed service
    #:   name as a replacement for "universe_suite".
    #: - [UDP] UNIVERSE SUITE MESSAGE SERVICE
    universe_suite = 4184, 'universe-suite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Woven Control Plane Protocol
    #: - [UDP] Woven Control Plane Protocol
    wcpp = 4185, 'wcpp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4186 = 4186, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4187 = 4187, 'reserved', TransportProtocol.udp

    #: - [TCP] Vatata Peer to Peer Protocol
    #: - [UDP] Vatata Peer to Peer Protocol
    vatata = 4188, 'vatata', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved [:rfc:`5440`]
    reserved_4189 = 4189, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved [:rfc:`5804`]
    reserved_4190 = 4190, 'reserved', TransportProtocol.udp

    #: [UDP] Dual Stack MIPv6 NAT Traversal [:rfc:`5555`]
    dsmipv6 = 4191, 'dsmipv6', TransportProtocol.udp

    #: [UDP] azeti blinddate
    azeti_bd = 4192, 'azeti-bd', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4193 = 4193, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4194 = 4194, 'reserved', TransportProtocol.udp

    #: - [TCP] AWS protocol for cloud remoting solution
    #: - [UDP] AWS protocol for cloud remoting solution
    #: - [SCTP] AWS protocol for cloud remoting solution
    #: - [DCCP] AWS protocol for cloud remoting solution
    aws_wsp = 4195, 'aws-wsp', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp | TransportProtocol.dccp

    #: - [TCP] Harman HControl Protocol
    #: - [UDP] Harman HControl Protocol
    hctl = 4197, 'hctl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EIMS ADMIN
    #: - [UDP] EIMS ADMIN
    eims_admin = 4199, 'eims-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Corel CCam
    #: - [UDP] Corel CCam
    corelccam = 4300, 'corelccam', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Diagnostic Data
    #: - [UDP] Diagnostic Data
    d_data = 4301, 'd-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Diagnostic Data Control
    #: - [UDP] Diagnostic Data Control
    d_data_control = 4302, 'd-data-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Railroad Command Protocol
    #: - [UDP] Simple Railroad Command Protocol
    srcp = 4303, 'srcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] One-Wire Filesystem Server
    #: - [UDP] One-Wire Filesystem Server
    owserver = 4304, 'owserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] better approach to mobile ad-hoc networking
    #: - [UDP] better approach to mobile ad-hoc networking
    batman = 4305, 'batman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hellgate London
    #: - [UDP] Hellgate London
    pinghgl = 4306, 'pinghgl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TrueConf Videoconference Service
    #: - [UDP] TrueConf Videoconference Service
    trueconf = 4307, 'trueconf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CompX-LockView
    #: - [UDP] CompX-LockView
    compx_lockview = 4308, 'compx-lockview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Exsequi Appliance Discovery
    #: - [UDP] Exsequi Appliance Discovery
    dserver = 4309, 'dserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mir-RT exchange service
    #: - [UDP] Mir-RT exchange service
    mirrtex = 4310, 'mirrtex', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4311 = 4311, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4312 = 4312, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4313 = 4313, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4314 = 4314, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4316 = 4316, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4317 = 4317, 'reserved', TransportProtocol.udp

    #: - [TCP] Sentyron SkyTale encrypted communication
    #: - [UDP] Sentyron SkyTale encrypted communication
    skytale = 4319, 'skytale', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FDT Remote Categorization Protocol
    #: - [UDP] FDT Remote Categorization Protocol
    fdt_rcatp = 4320, 'fdt-rcatp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Who Is [:rfc:`2167`]
    #: - [UDP] Remote Who Is [:rfc:`2167`]
    rwhois = 4321, 'rwhois', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRIM Event Service
    #: - [UDP] TRIM Event Service
    trim_event = 4322, 'trim-event', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRIM ICE Service
    #: - [UDP] TRIM ICE Service
    trim_ice = 4323, 'trim-ice', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Cadcorp GeognoSIS Administrator
    geognosisman = 4325, 'geognosisman', TransportProtocol.udp

    #: - [TCP] Cadcorp GeognoSIS
    #: - [UDP] Cadcorp GeognoSIS
    geognosis = 4326, 'geognosis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jaxer Web Protocol
    #: - [UDP] Jaxer Web Protocol
    jaxer_web = 4327, 'jaxer-web', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Jaxer Manager Command Protocol
    #: - [UDP] Jaxer Manager Command Protocol
    jaxer_manager = 4328, 'jaxer-manager', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4329 = 4329, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4330 = 4330, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4331 = 4331, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4332 = 4332, 'reserved', TransportProtocol.udp

    #: - [TCP] ArrowHead Service Protocol (AHSP)
    #: - [UDP] ArrowHead Service Protocol (AHSP)
    #: - [SCTP] ArrowHead Service Protocol (AHSP)
    ahsp = 4333, 'ahsp', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: [UDP] Reserved
    reserved_4334 = 4334, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4335 = 4335, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4336 = 4336, 'reserved', TransportProtocol.udp

    #: - [TCP] Gaia Connector Protocol
    #: - [UDP] Gaia Connector Protocol
    gaia = 4340, 'gaia', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] LISP Data Packets [:rfc:`9300`]
    lisp_data = 4341, 'lisp-data', TransportProtocol.udp

    #: [UDP] LISP Control Packets [:rfc:`9301`]
    lisp_control = 4342, 'lisp-control', TransportProtocol.udp

    #: - [TCP] UNICALL
    #: - [UDP] UNICALL
    unicall = 4343, 'unicall', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VinaInstall
    #: - [UDP] VinaInstall
    vinainstall = 4344, 'vinainstall', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Macro 4 Network AS
    #: - [UDP] Macro 4 Network AS
    m4_network_as = 4345, 'm4-network-as', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ELAN LM
    #: - [UDP] ELAN LM
    elanlm = 4346, 'elanlm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LAN Surveyor
    #: - [UDP] LAN Surveyor
    lansurveyor = 4347, 'lansurveyor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITOSE
    #: - [UDP] ITOSE
    itose = 4348, 'itose', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] File System Port Map
    #: - [UDP] File System Port Map
    fsportmap = 4349, 'fsportmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net Device
    #: - [UDP] Net Device
    net_device = 4350, 'net-device', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PLCY Net Services
    #: - [UDP] PLCY Net Services
    plcy_net_svcs = 4351, 'plcy-net-svcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Projector Link
    #: - [UDP] Projector Link
    pjlink = 4352, 'pjlink', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] F5 iQuery
    #: - [UDP] F5 iQuery
    f5_iquery = 4353, 'f5-iquery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSNet Transmitter
    #: - [UDP] QSNet Transmitter
    qsnet_trans = 4354, 'qsnet-trans', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSNet Workstation
    #: - [UDP] QSNet Workstation
    qsnet_workst = 4355, 'qsnet-workst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSNet Assistant
    #: - [UDP] QSNet Assistant
    qsnet_assist = 4356, 'qsnet-assist', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSNet Conductor
    #: - [UDP] QSNet Conductor
    qsnet_cond = 4357, 'qsnet-cond', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSNet Nucleus
    #: - [UDP] QSNet Nucleus
    qsnet_nucl = 4358, 'qsnet-nucl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA BCAST Long-Term Key Messages
    #: - [UDP] OMA BCAST Long-Term Key Messages
    omabcastltkm = 4359, 'omabcastltkm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4360 = 4360, 'reserved', TransportProtocol.udp

    #: [UDP] NavCom Discovery and Control Port
    nacnl = 4361, 'nacnl', TransportProtocol.udp

    #: [UDP] AFORE vNode Discovery protocol
    afore_vdp_disc = 4362, 'afore-vdp-disc', TransportProtocol.udp

    #: [UDP] ShadowStream System
    shadowstream = 4366, 'shadowstream', TransportProtocol.udp

    #: - [TCP] WeatherBrief Direct
    #: - [UDP] WeatherBrief Direct
    wxbrief = 4368, 'wxbrief', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Erlang Port Mapper Daemon
    #: - [UDP] Erlang Port Mapper Daemon
    epmd = 4369, 'epmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ELPRO V2 Protocol Tunnel IANA assigned this well-formed service name
    #:   as a replacement for "elpro_tunnel".
    #: - [TCP] ELPRO V2 Protocol Tunnel
    #: - [UDP] ELPRO V2 Protocol Tunnel IANA assigned this well-formed service name
    #:   as a replacement for "elpro_tunnel".
    #: - [UDP] ELPRO V2 Protocol Tunnel
    elpro_tunnel = 4370, 'elpro-tunnel', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] LAN2CAN Discovery
    l2c_disc = 4371, 'l2c-disc', TransportProtocol.udp

    #: - [TCP] LAN2CAN Data
    #: - [UDP] LAN2CAN Data
    l2c_data = 4372, 'l2c-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Authenticated Command Service
    #: - [UDP] Remote Authenticated Command Service
    remctl = 4373, 'remctl', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4374 = 4374, 'reserved', TransportProtocol.udp

    #: - [TCP] Toltec EasyShare
    #: - [UDP] Toltec EasyShare
    tolteces = 4375, 'tolteces', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BioAPI Interworking
    #: - [UDP] BioAPI Interworking
    bip = 4376, 'bip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cambridge Pixel SPx Server
    #: - [UDP] Cambridge Pixel SPx Server
    cp_spxsvr = 4377, 'cp-spxsvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cambridge Pixel SPx Display
    #: - [UDP] Cambridge Pixel SPx Display
    cp_spxdpy = 4378, 'cp-spxdpy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CTDB
    #: - [UDP] CTDB
    ctdb = 4379, 'ctdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xandros Community Management Service
    #: - [UDP] Xandros Community Management Service
    xandros_cms = 4389, 'xandros-cms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Physical Access Control
    #: - [UDP] Physical Access Control
    wiegand = 4390, 'wiegand', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4391 = 4391, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4392 = 4392, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4393 = 4393, 'reserved', TransportProtocol.udp

    #: [UDP] American Printware Discovery
    apwi_disc = 4394, 'apwi-disc', TransportProtocol.udp

    #: - [TCP] OmniVision communication for Virtual environments
    #: - [UDP] OmniVision communication for Virtual environments
    omnivisionesx = 4395, 'omnivisionesx', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4396 = 4396, 'reserved', TransportProtocol.udp

    #: - [TCP] ASIGRA Services
    #: - [UDP] ASIGRA Services
    ds_srv = 4400, 'ds-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASIGRA Televaulting DS-System Service
    #: - [UDP] ASIGRA Televaulting DS-System Service
    ds_srvr = 4401, 'ds-srvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASIGRA Televaulting DS-Client Service
    #: - [UDP] ASIGRA Televaulting DS-Client Service
    ds_clnt = 4402, 'ds-clnt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASIGRA Televaulting DS-Client Monitoring/Management
    #: - [UDP] ASIGRA Televaulting DS-Client Monitoring/Management
    ds_user = 4403, 'ds-user', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASIGRA Televaulting DS-System Monitoring/Management
    #: - [UDP] ASIGRA Televaulting DS-System Monitoring/Management
    ds_admin = 4404, 'ds-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASIGRA Televaulting Message Level Restore service
    #: - [UDP] ASIGRA Televaulting Message Level Restore service
    ds_mail = 4405, 'ds-mail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASIGRA Televaulting DS-Sleeper Service
    #: - [UDP] ASIGRA Televaulting DS-Sleeper Service
    ds_slp = 4406, 'ds-slp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4407 = 4407, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4408 = 4408, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4409 = 4409, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4410 = 4410, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4411 = 4411, 'reserved', TransportProtocol.udp

    #: [UDP] SmallChat
    smallchat = 4412, 'smallchat', TransportProtocol.udp

    #: [UDP] FORTÉ Vision Monitoring platform
    vision_mon_disc = 4413, 'vision-mon-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4414 = 4414, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4415 = 4415, 'reserved', TransportProtocol.udp

    #: [UDP] PJJ Media Player discovery
    pjj_player_disc = 4416, 'pjj-player-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4417 = 4417, 'reserved', TransportProtocol.udp

    #: [UDP] AXYS communication protocol
    axysbridge = 4418, 'axysbridge', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4419 = 4419, 'reserved', TransportProtocol.udp

    #: - [TCP] NVM Express over Fabrics storage access
    #: - [UDP] NVM Express over Fabrics storage access
    nvme = 4420, 'nvme', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4421 = 4421, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4422 = 4422, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4423 = 4423, 'reserved', TransportProtocol.udp

    #: - [TCP] NetROCKEY6 SMART Plus Service
    #: - [UDP] NetROCKEY6 SMART Plus Service
    netrockey6 = 4425, 'netrockey6', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMARTS Beacon Port
    #: - [UDP] SMARTS Beacon Port
    beacon_port_2 = 4426, 'beacon-port-2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4427 = 4427, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4428 = 4428, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4429 = 4429, 'reserved', TransportProtocol.udp

    #: - [TCP] REAL SQL Server
    #: - [UDP] REAL SQL Server
    rsqlserver = 4430, 'rsqlserver', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4431 = 4431, 'reserved', TransportProtocol.udp

    #: - [TCP] L-ACOUSTICS management
    #: - [UDP] L-ACOUSTICS management
    l_acoustics = 4432, 'l-acoustics', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4433 = 4433, 'reserved', TransportProtocol.udp

    #: [UDP] Netblox Protocol
    netblox = 4441, 'netblox', TransportProtocol.udp

    #: - [TCP] Saris
    #: - [UDP] Saris
    saris = 4442, 'saris', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pharos
    #: - [UDP] Pharos
    pharos = 4443, 'pharos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] KRB524
    #: - [UDP] KRB524
    krb524 = 4444, 'krb524', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NV Video default
    #: - [UDP] NV Video default
    nv_video = 4444, 'nv-video', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UPNOTIFYP
    #: - [UDP] UPNOTIFYP
    upnotifyp = 4445, 'upnotifyp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] N1-FWP
    #: - [UDP] N1-FWP
    n1_fwp = 4446, 'n1-fwp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] N1-RMGMT
    #: - [UDP] N1-RMGMT
    n1_rmgmt = 4447, 'n1-rmgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ASC Licence Manager
    #: - [UDP] ASC Licence Manager
    asc_slmd = 4448, 'asc-slmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PrivateWire
    #: - [UDP] PrivateWire
    privatewire = 4449, 'privatewire', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Common ASCII Messaging Protocol
    #: - [UDP] Common ASCII Messaging Protocol
    camp = 4450, 'camp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CTI System Msg
    #: - [UDP] CTI System Msg
    ctisystemmsg = 4451, 'ctisystemmsg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CTI Program Load
    #: - [UDP] CTI Program Load
    ctiprogramload = 4452, 'ctiprogramload', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NSS Alert Manager
    #: - [UDP] NSS Alert Manager
    nssalertmgr = 4453, 'nssalertmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NSS Agent Manager
    #: - [UDP] NSS Agent Manager
    nssagentmgr = 4454, 'nssagentmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PR Chat User
    #: - [UDP] PR Chat User
    prchat_user = 4455, 'prchat-user', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PR Chat Server
    #: - [UDP] PR Chat Server
    prchat_server = 4456, 'prchat-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PR Register
    #: - [UDP] PR Register
    prregister = 4457, 'prregister', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Matrix Configuration Protocol
    #: - [UDP] Matrix Configuration Protocol
    mcp = 4458, 'mcp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4460 = 4460, 'reserved', TransportProtocol.udp

    #: [UDP] Agent Transfer Protocol over QUIC
    agtp_quic = 4480, 'agtp-quic', TransportProtocol.udp

    #: - [TCP] hpssmgmt service
    #: - [UDP] hpssmgmt service
    hpssmgmt = 4484, 'hpssmgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4485 = 4485, 'reserved', TransportProtocol.udp

    #: - [TCP] Integrated Client Message Service
    #: - [UDP] Integrated Client Message Service
    icms = 4486, 'icms', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4487 = 4487, 'reserved', TransportProtocol.udp

    #: - [TCP] Apple Wide Area Connectivity Service ICE Bootstrap
    #: - [UDP] Apple Wide Area Connectivity Service ICE Bootstrap
    awacs_ice = 4488, 'awacs-ice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPsec NAT-Traversal [:rfc:`9329`]
    #: - [UDP] IPsec NAT-Traversal [:rfc:`3948`][:rfc:`7296`]
    ipsec_nat_t = 4500, 'ipsec-nat-t', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] M-Bus-OMS over UDP
    m_bus_oms = 4503, 'm-bus-oms', TransportProtocol.udp

    #: [UDP] Armagetron Advanced Game Server
    armagetronad = 4534, 'armagetronad', TransportProtocol.udp

    #: - [TCP] Event Heap Server
    #: - [UDP] Event Heap Server
    ehs = 4535, 'ehs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Event Heap Server SSL
    #: - [UDP] Event Heap Server SSL
    ehs_ssl = 4536, 'ehs-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WSS Security Service
    #: - [UDP] WSS Security Service
    wssauthsvc = 4537, 'wssauthsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Software Data Exchange Gateway
    #: - [UDP] Software Data Exchange Gateway
    swx_gate = 4538, 'swx-gate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WorldScores
    #: - [UDP] WorldScores
    worldscores = 4545, 'worldscores', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SF License Manager (Sentinel)
    #: - [UDP] SF License Manager (Sentinel)
    sf_lm = 4546, 'sf-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lanner License Manager
    #: - [UDP] Lanner License Manager
    lanner_lm = 4547, 'lanner-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Synchromesh
    #: - [UDP] Synchromesh
    synchromesh = 4548, 'synchromesh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aegate PMR Service
    #: - [UDP] Aegate PMR Service
    aegate = 4549, 'aegate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Perman I Interbase Server
    #: - [UDP] Perman I Interbase Server
    gds_adppiw_db = 4550, 'gds-adppiw-db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MIH Services [:rfc:`5677`]
    #: - [UDP] MIH Services [:rfc:`5677`]
    ieee_mih = 4551, 'ieee-mih', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Men and Mice Monitoring
    #: - [UDP] Men and Mice Monitoring
    menandmice_mon = 4552, 'menandmice-mon', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4553 = 4553, 'reserved', TransportProtocol.udp

    #: - [TCP] MS FRS Replication
    #: - [UDP] MS FRS Replication
    msfrs = 4554, 'msfrs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RSIP Port [:rfc:`3103`]
    #: - [UDP] RSIP Port [:rfc:`3103`]
    rsip = 4555, 'rsip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DTN Bundle TCP CL Protocol [:rfc:`9174`]
    #: - [UDP] DTN Bundle UDP CL Protocol [:rfc:`7122`]
    #: - [DCCP] DTN Bundle DCCP CL Protocol [:rfc:`7122`]
    dtn_bundle = 4556, 'dtn-bundle', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: [UDP] Marathon everRun Quorum Service Server
    mtcevrunqss = 4557, 'mtcevrunqss', TransportProtocol.udp

    #: [UDP] Marathon everRun Quorum Service Manager
    mtcevrunqman = 4558, 'mtcevrunqman', TransportProtocol.udp

    #: - [TCP] HylaFAX
    #: - [UDP] HylaFAX
    hylafax = 4559, 'hylafax', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4563 = 4563, 'reserved', TransportProtocol.udp

    #: - [TCP] Kids Watch Time Control Service
    #: - [UDP] Kids Watch Time Control Service
    kwtc = 4566, 'kwtc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRAM
    #: - [UDP] TRAM
    tram = 4567, 'tram', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC Reporting
    #: - [UDP] BMC Reporting
    bmc_reporting = 4568, 'bmc-reporting', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inter-Asterisk eXchange [:rfc:`5456`]
    #: - [UDP] Inter-Asterisk eXchange [:rfc:`5456`]
    iax = 4569, 'iax', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4570 = 4570, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4573 = 4573, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4590 = 4590, 'reserved', TransportProtocol.udp

    #: - [TCP] HRPD L3T (AT-AN)
    #: - [UDP] HRPD L3T (AT-AN)
    l3t_at_an = 4591, 'l3t-at-an', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] HRPD-ITH (AT-AN)
    hrpd_ith_at_an = 4592, 'hrpd-ith-at-an', TransportProtocol.udp

    #: - [TCP] IPT (ANRI-ANRI)
    #: - [UDP] IPT (ANRI-ANRI)
    ipt_anri_anri = 4593, 'ipt-anri-anri', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IAS-Session (ANRI-ANRI)
    #: - [UDP] IAS-Session (ANRI-ANRI)
    ias_session = 4594, 'ias-session', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IAS-Paging (ANRI-ANRI)
    #: - [UDP] IAS-Paging (ANRI-ANRI)
    ias_paging = 4595, 'ias-paging', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IAS-Neighbor (ANRI-ANRI)
    #: - [UDP] IAS-Neighbor (ANRI-ANRI)
    ias_neighbor = 4596, 'ias-neighbor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A21 (AN-1xBS)
    #: - [UDP] A21 (AN-1xBS)
    a21_an_1xbs = 4597, 'a21-an-1xbs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A16 (AN-AN)
    #: - [UDP] A16 (AN-AN)
    a16_an_an = 4598, 'a16-an-an', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A17 (AN-AN)
    #: - [UDP] A17 (AN-AN)
    a17_an_an = 4599, 'a17-an-an', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Piranha1
    #: - [UDP] Piranha1
    piranha1 = 4600, 'piranha1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Piranha2
    #: - [UDP] Piranha2
    piranha2 = 4601, 'piranha2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4602 = 4602, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4603 = 4603, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4604 = 4604, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4605 = 4605, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4606 = 4606, 'reserved', TransportProtocol.udp

    #: [UDP] Bidirectional single port remote radio VOIP and Control stream
    ventoso = 4621, 'ventoso', TransportProtocol.udp

    #: - [TCP] Distributed Denial-of-Service Open Threat Signaling (DOTS) Signal
    #:   Channel Protocol. The service name is used to construct the SRV service
    #:   names "_dots-signal._udp" and "_dots-signal._tcp" for discovering DOTS
    #:   servers used to establish DOTS signal channel. [:rfc:`8973`][:rfc:`9132`]
    #: - [UDP] Distributed Denial-of-Service Open Threat Signaling (DOTS) Signal
    #:   Channel Protocol. The service name is used to construct the SRV service
    #:   names "_dots-signal._udp" and "_dots-signal._tcp" for discovering DOTS
    #:   servers used to establish DOTS signal channel. [:rfc:`8973`][:rfc:`9132`]
    dots_signal = 4646, 'dots-signal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PlayStation2 App Port
    #: - [UDP] PlayStation2 App Port
    playsta2_app = 4658, 'playsta2-app', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PlayStation2 Lobby Port
    #: - [UDP] PlayStation2 Lobby Port
    playsta2_lob = 4659, 'playsta2-lob', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] smaclmgr
    #: - [UDP] smaclmgr
    smaclmgr = 4660, 'smaclmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kar2ouche Peer location service
    #: - [UDP] Kar2ouche Peer location service
    kar2ouche = 4661, 'kar2ouche', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OrbitNet Message Service
    #: - [UDP] OrbitNet Message Service
    oms = 4662, 'oms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Note It! Message Service
    #: - [UDP] Note It! Message Service
    noteit = 4663, 'noteit', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Rimage Messaging Server
    #: - [UDP] Rimage Messaging Server
    ems = 4664, 'ems', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Container Client Message Service
    #: - [UDP] Container Client Message Service
    contclientms = 4665, 'contclientms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] E-Port Message Service
    #: - [UDP] E-Port Message Service
    eportcomm = 4666, 'eportcomm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MMA Comm Services
    #: - [UDP] MMA Comm Services
    mmacomm = 4667, 'mmacomm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MMA EDS Service
    #: - [UDP] MMA EDS Service
    mmaeds = 4668, 'mmaeds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] E-Port Data Service
    #: - [UDP] E-Port Data Service
    eportcommdata = 4669, 'eportcommdata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Light packets transfer protocol
    #: - [UDP] Light packets transfer protocol
    light = 4670, 'light', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bull RSF action server
    #: - [UDP] Bull RSF action server
    acter = 4671, 'acter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] remote file access server
    #: - [UDP] remote file access server
    rfa = 4672, 'rfa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CXWS Operations
    #: - [UDP] CXWS Operations
    cxws = 4673, 'cxws', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppIQ Agent Management
    #: - [UDP] AppIQ Agent Management
    appiq_mgmt = 4674, 'appiq-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BIAP Device Status
    #: - [UDP] BIAP Device Status
    dhct_status = 4675, 'dhct-status', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BIAP Generic Alert
    #: - [UDP] BIAP Generic Alert
    dhct_alerts = 4676, 'dhct-alerts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Business Continuity Servi
    #: - [UDP] Business Continuity Servi
    bcs = 4677, 'bcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] boundary traversal
    #: - [UDP] boundary traversal
    traversal = 4678, 'traversal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MGE UPS Supervision
    #: - [UDP] MGE UPS Supervision
    mgesupervision = 4679, 'mgesupervision', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MGE UPS Management
    #: - [UDP] MGE UPS Management
    mgemanagement = 4680, 'mgemanagement', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Parliant Telephony System
    #: - [UDP] Parliant Telephony System
    parliant = 4681, 'parliant', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] finisar
    #: - [UDP] finisar
    finisar = 4682, 'finisar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Spike Clipboard Service
    #: - [UDP] Spike Clipboard Service
    spike = 4683, 'spike', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RFID Reader Protocol 1.0
    #: - [UDP] RFID Reader Protocol 1.0
    rfid_rp1 = 4684, 'rfid-rp1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Autopac Protocol
    #: - [UDP] Autopac Protocol
    autopac = 4685, 'autopac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Manina Service Protocol
    #: - [UDP] Manina Service Protocol
    msp_os = 4686, 'msp-os', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Scanner Tool FTP
    #: - [UDP] Network Scanner Tool FTP
    nst = 4687, 'nst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mobile P2P Service
    #: - [UDP] Mobile P2P Service
    mobile_p2p = 4688, 'mobile-p2p', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Altova DatabaseCentral
    #: - [UDP] Altova DatabaseCentral
    altovacentral = 4689, 'altovacentral', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prelude IDS message proto
    #: - [UDP] Prelude IDS message proto
    prelude = 4690, 'prelude', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] monotone Netsync Protocol
    #: - [UDP] monotone Netsync Protocol
    mtn = 4691, 'mtn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Conspiracy messaging
    #: - [UDP] Conspiracy messaging
    conspiracy = 4692, 'conspiracy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetXMS Agent
    #: - [UDP] NetXMS Agent
    netxms_agent = 4700, 'netxms-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetXMS Management
    #: - [UDP] NetXMS Management
    netxms_mgmt = 4701, 'netxms-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetXMS Server Synchronization
    #: - [UDP] NetXMS Server Synchronization
    netxms_sync = 4702, 'netxms-sync', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4703 = 4703, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4704 = 4704, 'reserved', TransportProtocol.udp

    #: - [TCP] Trinity Trust Network Node Communication
    #: - [UDP] Trinity Trust Network Node Communication
    #: - [SCTP] Trinity Trust Network Node Communication
    trinity_dist = 4711, 'trinity-dist', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] TruckStar Service
    #: - [UDP] TruckStar Service
    truckstar = 4725, 'truckstar', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] A26 (FAP-FGW)
    a26_fap_fgw = 4726, 'a26-fap-fgw', TransportProtocol.udp

    #: [UDP] F-Link Client Information Service Discovery
    fcis_disc = 4727, 'fcis-disc', TransportProtocol.udp

    #: - [TCP] CA Port Multiplexer
    #: - [UDP] CA Port Multiplexer
    capmux = 4728, 'capmux', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] GSM Interface Tap
    gsmtap = 4729, 'gsmtap', TransportProtocol.udp

    #: - [TCP] Gearman Job Queue System
    #: - [UDP] Gearman Job Queue System
    gearman = 4730, 'gearman', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4731 = 4731, 'reserved', TransportProtocol.udp

    #: [UDP] OHM server trigger
    ohmtrigger = 4732, 'ohmtrigger', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4733 = 4733, 'reserved', TransportProtocol.udp

    #: - [TCP] IPDR/SP
    #: - [UDP] IPDR/SP
    ipdr_sp = 4737, 'ipdr-sp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SoleraTec Locator
    #: - [UDP] SoleraTec Locator
    solera_lpn = 4738, 'solera-lpn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IP Flow Info Export
    #: - [UDP] IP Flow Info Export
    #: - [SCTP] IP Flow Info Export
    ipfix = 4739, 'ipfix', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] ipfix protocol over TLS
    #: - [SCTP] ipfix protocol over DTLS
    #: - [UDP] ipfix protocol over DTLS
    ipfixs = 4740, 'ipfixs', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Luminizer Manager
    #: - [UDP] Luminizer Manager
    lumimgrd = 4741, 'lumimgrd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] SICCT Service Discovery Protocol
    sicct_sdp = 4742, 'sicct-sdp', TransportProtocol.udp

    #: - [TCP] openhpi HPI service
    #: - [UDP] openhpi HPI service
    openhpid = 4743, 'openhpid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Internet File Synchronization Protocol
    #: - [UDP] Internet File Synchronization Protocol
    ifsp = 4744, 'ifsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Funambol Mobile Push
    #: - [UDP] Funambol Mobile Push
    fmp = 4745, 'fmp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] IntelliAdmin Discovery
    intelliadm_disc = 4746, 'intelliadm-disc', TransportProtocol.udp

    #: [UDP] peer-to-peer file exchange protocol
    buschtrommel = 4747, 'buschtrommel', TransportProtocol.udp

    #: - [TCP] Simple Service Auto Discovery
    #: - [UDP] Simple Service Auto Discovery
    ssad = 4750, 'ssad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Policy Control Protocol
    #: - [UDP] Simple Policy Control Protocol
    spocp = 4751, 'spocp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Network Audio Protocol
    #: - [UDP] Simple Network Audio Protocol
    snap = 4752, 'snap', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Simple Invocation of Methods Over Network (SIMON) Discovery
    simon_disc = 4753, 'simon-disc', TransportProtocol.udp

    #: [UDP] GRE-in-UDP Encapsulation [:rfc:`8086`]
    gre_in_udp = 4754, 'gre-in-udp', TransportProtocol.udp

    #: [UDP] GRE-in-UDP Encapsulation with DTLS [:rfc:`8086`]
    gre_udp_dtls = 4755, 'gre-udp-dtls', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4756 = 4756, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4774 = 4774, 'reserved', TransportProtocol.udp

    #: - [TCP] BFD Multihop Control
    #: - [UDP] BFD Multihop Control
    bfd_multi_ctl = 4784, 'bfd-multi-ctl', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Cisco Nexus Control Protocol
    cncp = 4785, 'cncp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4786 = 4786, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4787 = 4787, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4788 = 4788, 'reserved', TransportProtocol.udp

    #: [UDP] Virtual eXtensible Local Area Network (VXLAN) [:rfc:`7348`]
    vxlan = 4789, 'vxlan', TransportProtocol.udp

    #: [UDP] Generic Protocol Extension for Virtual eXtensible Local Area Network
    #: (VXLAN)
    vxlan_gpe = 4790, 'vxlan-gpe', TransportProtocol.udp

    #: [UDP] IP Routable RocE
    roce = 4791, 'roce', TransportProtocol.udp

    #: - [TCP] IP Routable Unified Bus
    #: - [UDP] IP Routable Unified Bus
    unified_bus = 4792, 'unified-bus', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Ultra Ethernet Transport
    uet = 4793, 'uet', TransportProtocol.udp

    #: [UDP] veRoCE Transport Protocol
    veroce = 4794, 'veroce', TransportProtocol.udp

    #: - [TCP] Icona Instant Messenging System
    #: - [UDP] Icona Instant Messenging System
    iims = 4800, 'iims', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Icona Web Embedded Chat
    #: - [UDP] Icona Web Embedded Chat
    iwec = 4801, 'iwec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Icona License System Server
    #: - [UDP] Icona License System Server
    ilss = 4802, 'ilss', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Notateit Messaging Discovery
    notateit_disc = 4803, 'notateit-disc', TransportProtocol.udp

    #: [UDP] AJA ntv4 Video System Discovery
    aja_ntv4_disc = 4804, 'aja-ntv4-disc', TransportProtocol.udp

    #: - [TCP] HTCP
    #: - [UDP] HTCP
    htcp = 4827, 'htcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Varadero-0
    #: - [UDP] Varadero-0
    varadero_0 = 4837, 'varadero-0', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Varadero-1
    #: - [UDP] Varadero-1
    varadero_1 = 4838, 'varadero-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Varadero-2
    #: - [UDP] Varadero-2
    varadero_2 = 4839, 'varadero-2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] OPC UA Multicast Datagram Protocol
    opcua_udp = 4840, 'opcua-udp', TransportProtocol.udp

    #: - [TCP] QUOSA Virtual Library Service
    #: - [UDP] QUOSA Virtual Library Service
    quosa = 4841, 'quosa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nCode ICE-flow Library AppServer
    #: - [UDP] nCode ICE-flow Library AppServer
    gw_asv = 4842, 'gw-asv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPC UA TCP Protocol over TLS/SSL
    #: - [UDP] OPC UA TCP Protocol over TLS/SSL
    opcua_tls = 4843, 'opcua-tls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nCode ICE-flow Library LogServer
    #: - [UDP] nCode ICE-flow Library LogServer
    gw_log = 4844, 'gw-log', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WordCruncher Remote Library Service
    #: - [UDP] WordCruncher Remote Library Service
    wcr_remlib = 4845, 'wcr-remlib', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Contamac ICM Service IANA assigned this well-formed service name as a
    #:   replacement for "contamac_icm".
    #: - [TCP] Contamac ICM Service
    #: - [UDP] Contamac ICM Service IANA assigned this well-formed service name as a
    #:   replacement for "contamac_icm".
    #: - [UDP] Contamac ICM Service
    contamac_icm = 4846, 'contamac-icm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Web Fresh Communication
    #: - [UDP] Web Fresh Communication
    wfc = 4847, 'wfc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] App Server - Admin HTTP
    #: - [UDP] App Server - Admin HTTP
    appserv_http = 4848, 'appserv-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] App Server - Admin HTTPS
    #: - [UDP] App Server - Admin HTTPS
    appserv_https = 4849, 'appserv-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun App Server - NA
    #: - [UDP] Sun App Server - NA
    sun_as_nodeagt = 4850, 'sun-as-nodeagt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apache Derby Replication
    #: - [UDP] Apache Derby Replication
    derby_repli = 4851, 'derby-repli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unify Debugger
    #: - [UDP] Unify Debugger
    unify_debug = 4867, 'unify-debug', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Photon Relay
    #: - [UDP] Photon Relay
    phrelay = 4868, 'phrelay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Photon Relay Debug
    #: - [UDP] Photon Relay Debug
    phrelaydbg = 4869, 'phrelaydbg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Citcom Tracking Service
    #: - [UDP] Citcom Tracking Service
    cc_tracking = 4870, 'cc-tracking', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wired
    #: - [UDP] Wired
    wired = 4871, 'wired', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tritium CAN Bus Bridge Service
    #: - [UDP] Tritium CAN Bus Bridge Service
    tritium_can = 4876, 'tritium-can', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lighting Management Control System
    #: - [UDP] Lighting Management Control System
    lmcs = 4877, 'lmcs', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Agilent Instrument Discovery
    inst_discovery = 4878, 'inst-discovery', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4879 = 4879, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4880 = 4880, 'reserved', TransportProtocol.udp

    #: [UDP] SOCP Time Synchronization Protocol
    socp_t = 4881, 'socp-t', TransportProtocol.udp

    #: [UDP] SOCP Control Protocol
    socp_c = 4882, 'socp-c', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4883 = 4883, 'reserved', TransportProtocol.udp

    #: - [TCP] HiveStor Distributed File System
    #: - [UDP] HiveStor Distributed File System
    hivestor = 4884, 'hivestor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ABBS
    #: - [UDP] ABBS
    abbs = 4885, 'abbs', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4888 = 4888, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4889 = 4889, 'reserved', TransportProtocol.udp

    #: - [TCP] LysKOM Protocol A
    #: - [UDP] LysKOM Protocol A
    lyskom = 4894, 'lyskom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RAdmin Port
    #: - [UDP] RAdmin Port
    radmin_port = 4899, 'radmin-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HFSQL Client/Server Database Engine
    #: - [UDP] HFSQL Client/Server Database Engine
    hfcs = 4900, 'hfcs', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4901 = 4901, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4902 = 4902, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4912 = 4912, 'reserved', TransportProtocol.udp

    #: - [TCP] Bones Remote Control
    #: - [UDP] Bones Remote Control
    bones = 4914, 'bones', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4915 = 4915, 'reserved', TransportProtocol.udp

    #: [UDP] Signal protocol port for autonomic networking
    an_signaling = 4936, 'an-signaling', TransportProtocol.udp

    #: [UDP] ATSC-M/H Service Signaling Channel
    atsc_mh_ssc = 4937, 'atsc-mh-ssc', TransportProtocol.udp

    #: - [TCP] Equitrac Office
    #: - [UDP] Equitrac Office
    eq_office_4940 = 4940, 'eq-office-4940', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Equitrac Office
    #: - [UDP] Equitrac Office
    eq_office_4941 = 4941, 'eq-office-4941', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Equitrac Office
    #: - [UDP] Equitrac Office
    eq_office_4942 = 4942, 'eq-office-4942', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Munin Graphing Framework
    #: - [UDP] Munin Graphing Framework
    munin = 4949, 'munin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sybase Server Monitor
    #: - [UDP] Sybase Server Monitor
    sybasesrvmon = 4950, 'sybasesrvmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PWG WIMS
    #: - [UDP] PWG WIMS
    pwgwims = 4951, 'pwgwims', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SAG Directory Server
    #: - [UDP] SAG Directory Server
    sagxtsds = 4952, 'sagxtsds', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4953 = 4953, 'reserved', TransportProtocol.udp

    #: - [TCP] CCSS QMessageMonitor
    #: - [UDP] CCSS QMessageMonitor
    ccss_qmm = 4969, 'ccss-qmm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CCSS QSystemMonitor
    #: - [UDP] CCSS QSystemMonitor
    ccss_qsm = 4970, 'ccss-qsm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4971 = 4971, 'reserved', TransportProtocol.udp

    #: [UDP] Citrix Virtual Path
    ctxs_vpp = 4980, 'ctxs-vpp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4984 = 4984, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_4985 = 4985, 'reserved', TransportProtocol.udp

    #: - [TCP] Model Railway Interface Program
    #: - [UDP] Model Railway Interface Program
    mrip = 4986, 'mrip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMAR Ethernet Port 1
    #: - [UDP] SMAR Ethernet Port 1
    smar_se_port1 = 4987, 'smar-se-port1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMAR Ethernet Port 2
    #: - [UDP] SMAR Ethernet Port 2
    smar_se_port2 = 4988, 'smar-se-port2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Parallel for GAUSS (tm)
    #: - [UDP] Parallel for GAUSS (tm)
    parallel = 4989, 'parallel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BusySync Calendar Synch. Protocol
    #: - [UDP] BusySync Calendar Synch. Protocol
    busycal = 4990, 'busycal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VITA Radio Transport
    #: - [UDP] VITA Radio Transport
    vrt = 4991, 'vrt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HFSQL Client/Server Database Engine Manager
    #: - [UDP] HFSQL Client/Server Database Engine Manager
    hfcs_manager = 4999, 'hfcs-manager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    commplex_main = 5000, 'commplex-main', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    commplex_link = 5001, 'commplex-link', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] radio free ethernet
    #: - [UDP] radio free ethernet
    rfe = 5002, 'rfe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileMaker, Inc. - Proprietary transport
    #: - [UDP] FileMaker, Inc. - Proprietary name binding
    fmpro_internal = 5003, 'fmpro-internal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RTP media data [:rfc:`3551`][:rfc:`4571`]
    #: - [UDP] RTP media data [:rfc:`3551`]
    #: - [DCCP] RTP media data [:rfc:`3551`][:rfc:`5762`]
    avt_profile_1 = 5004, 'avt-profile-1', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [TCP] RTP control protocol [:rfc:`3551`][:rfc:`4571`]
    #: - [UDP] RTP control protocol [:rfc:`3551`]
    #: - [DCCP] RTP control protocol [:rfc:`3551`][:rfc:`5762`]
    avt_profile_2 = 5005, 'avt-profile-2', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [TCP] wsm server
    #: - [UDP] wsm server
    wsm_server = 5006, 'wsm-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] wsm server ssl
    #: - [UDP] wsm server ssl
    wsm_server_ssl = 5007, 'wsm-server-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Synapsis EDGE
    #: - [UDP] Synapsis EDGE
    synapsis_edge = 5008, 'synapsis-edge', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Windows Filesystem
    #: - [UDP] Microsoft Windows Filesystem
    winfs = 5009, 'winfs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TelepathStart
    #: - [UDP] TelepathStart
    telelpathstart = 5010, 'telelpathstart', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TelepathAttack
    #: - [UDP] TelepathAttack
    telelpathattack = 5011, 'telelpathattack', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetOnTap Service
    #: - [UDP] NetOnTap Service
    nsp = 5012, 'nsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileMaker, Inc. - Proprietary transport
    #: - [UDP] FileMaker, Inc. - Proprietary transport
    fmpro_v6 = 5013, 'fmpro-v6', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Overlay Network Protocol
    onpsocket = 5014, 'onpsocket', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5015 = 5015, 'reserved', TransportProtocol.udp

    #: - [TCP] zenginkyo-1
    #: - [UDP] zenginkyo-1
    zenginkyo_1 = 5020, 'zenginkyo-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] zenginkyo-2
    #: - [UDP] zenginkyo-2
    zenginkyo_2 = 5021, 'zenginkyo-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mice server
    #: - [UDP] mice server
    mice = 5022, 'mice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Htuil Server for PLD2
    #: - [UDP] Htuil Server for PLD2
    htuilsrv = 5023, 'htuilsrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Storix I/O daemon (data)
    #: - [UDP] Storix I/O daemon (data)
    strexec_d = 5026, 'strexec-d', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Storix I/O daemon (stat)
    #: - [UDP] Storix I/O daemon (stat)
    strexec_s = 5027, 'strexec-s', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5028 = 5028, 'reserved', TransportProtocol.udp

    #: - [TCP] Infobright Database Server
    #: - [UDP] Infobright Database Server
    infobright = 5029, 'infobright', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_5030 = 5030, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Direct Message Protocol
    dmp = 5031, 'dmp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5032 = 5032, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5033 = 5033, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5034 = 5034, 'reserved', TransportProtocol.udp

    #: - [TCP] asnaacceler8db
    #: - [UDP] asnaacceler8db
    asnaacceler8db = 5042, 'asnaacceler8db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ShopWorX Administration
    #: - [UDP] ShopWorX Administration
    swxadmin = 5043, 'swxadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LXI Event Service
    #: - [UDP] LXI Event Service
    lxi_evntsvc = 5044, 'lxi-evntsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5045 = 5045, 'reserved', TransportProtocol.udp

    #: [UDP] Vishay PM UDP Service
    vpm_udp = 5046, 'vpm-udp', TransportProtocol.udp

    #: [UDP] iSCAPE Data Broadcasting
    iscape = 5047, 'iscape', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5048 = 5048, 'reserved', TransportProtocol.udp

    #: - [TCP] iVocalize Web Conference
    #: - [UDP] iVocalize Web Conference
    ivocalize = 5049, 'ivocalize', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] multimedia conference control tool
    #: - [UDP] multimedia conference control tool
    mmcc = 5050, 'mmcc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITA Agent
    #: - [UDP] ITA Agent
    ita_agent = 5051, 'ita-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITA Manager
    #: - [UDP] ITA Manager
    ita_manager = 5052, 'ita-manager', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] RLM Discovery Server
    rlm_disc = 5053, 'rlm-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5054 = 5054, 'reserved', TransportProtocol.udp

    #: - [TCP] UNOT
    #: - [UDP] UNOT
    unot = 5055, 'unot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intecom Pointspan 1
    #: - [UDP] Intecom Pointspan 1
    intecom_ps1 = 5056, 'intecom-ps1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intecom Pointspan 2
    #: - [UDP] Intecom Pointspan 2
    intecom_ps2 = 5057, 'intecom-ps2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Locus Discovery
    locus_disc = 5058, 'locus-disc', TransportProtocol.udp

    #: - [TCP] SIP Directory Services
    #: - [UDP] SIP Directory Services
    sds = 5059, 'sds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SIP [:rfc:`3263`]
    #: - [UDP] SIP [:rfc:`3263`]
    #: - [SCTP] SIP [:rfc:`4168`]
    sip = 5060, 'sip', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] SIP-TLS [:rfc:`3263`]
    #: - [UDP] SIP-TLS [:rfc:`3263`]
    #: - [SCTP] SIP-TLS [:rfc:`4168`]
    sips = 5061, 'sips', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Localisation access
    #: - [UDP] Localisation access
    na_localise = 5062, 'na-localise', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5063 = 5063, 'reserved', TransportProtocol.udp

    #: - [TCP] Channel Access 1
    #: - [UDP] Channel Access 1
    ca_1 = 5064, 'ca-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Channel Access 2
    #: - [UDP] Channel Access 2
    ca_2 = 5065, 'ca-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STANAG-5066-SUBNET-INTF
    #: - [UDP] STANAG-5066-SUBNET-INTF
    stanag_5066 = 5066, 'stanag-5066', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Authentx Service
    #: - [UDP] Authentx Service
    authentx = 5067, 'authentx', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5068 = 5068, 'reserved', TransportProtocol.udp

    #: - [TCP] I/Net 2000-NPR
    #: - [UDP] I/Net 2000-NPR
    i_net_2000_npr = 5069, 'i-net-2000-npr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VersaTrans Server Agent Service
    #: - [UDP] VersaTrans Server Agent Service
    vtsas = 5070, 'vtsas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PowerSchool
    #: - [UDP] PowerSchool
    powerschool = 5071, 'powerschool', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Anything In Anything
    #: - [UDP] Anything In Anything
    ayiya = 5072, 'ayiya', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Advantage Group Port Mgr
    #: - [UDP] Advantage Group Port Mgr
    tag_pm = 5073, 'tag-pm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ALES Query
    #: - [UDP] ALES Query
    alesquery = 5074, 'alesquery', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5075 = 5075, 'reserved', TransportProtocol.udp

    #: [UDP] PixelPusher pixel data
    pixelpusher = 5078, 'pixelpusher', TransportProtocol.udp

    #: [UDP] Cambridge Pixel SPx Reports
    cp_spxrpts = 5079, 'cp-spxrpts', TransportProtocol.udp

    #: - [TCP] OnScreen Data Collection Service
    #: - [UDP] OnScreen Data Collection Service
    onscreen = 5080, 'onscreen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SDL - Ent Trans Server
    #: - [UDP] SDL - Ent Trans Server
    sdl_ets = 5081, 'sdl-ets', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Qpur Communication Protocol
    #: - [UDP] Qpur Communication Protocol
    qcp = 5082, 'qcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Qpur File Protocol
    #: - [UDP] Qpur File Protocol
    qfp = 5083, 'qfp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPCglobal Low-Level Reader Protocol
    #: - [UDP] EPCglobal Low-Level Reader Protocol
    llrp = 5084, 'llrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EPCglobal Encrypted LLRP
    #: - [UDP] EPCglobal Encrypted LLRP
    encrypted_llrp = 5085, 'encrypted-llrp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5086 = 5086, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5087 = 5087, 'reserved', TransportProtocol.udp

    #: [UDP] Magpie Binary
    magpie = 5092, 'magpie', TransportProtocol.udp

    #: - [TCP] Sentinel LM
    #: - [UDP] Sentinel LM
    sentinel_lm = 5093, 'sentinel-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HART-IP
    #: - [UDP] HART-IP
    hart_ip = 5094, 'hart-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SentLM Srv2Srv
    #: - [UDP] SentLM Srv2Srv
    sentlm_srv2srv = 5099, 'sentlm-srv2srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Socalia service mux
    #: - [UDP] Socalia service mux
    socalia = 5100, 'socalia', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Talarian_UDP
    talarian_udp = 5101, 'talarian-udp', TransportProtocol.udp

    #: - [TCP] Oracle OMS non-secure
    #: - [UDP] Oracle OMS non-secure
    oms_nonsecure = 5102, 'oms-nonsecure', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5103 = 5103, 'reserved', TransportProtocol.udp

    #: [UDP] TinyMessage
    tinymessage = 5104, 'tinymessage', TransportProtocol.udp

    #: [UDP] Hughes Association Protocol
    hughes_ap = 5105, 'hughes-ap', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5106 = 5106, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5107 = 5107, 'reserved', TransportProtocol.udp

    #: - [TCP] TAEP AS service
    #: - [UDP] TAEP AS service
    taep_as_svc = 5111, 'taep-as-svc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PeerMe Msg Cmd Service
    #: - [UDP] PeerMe Msg Cmd Service
    pm_cmdsvr = 5112, 'pm-cmdsvr', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5114 = 5114, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5115 = 5115, 'reserved', TransportProtocol.udp

    #: [UDP] EPSON Projecter Image Transfer
    emb_proj_cmd = 5116, 'emb-proj-cmd', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5117 = 5117, 'reserved', TransportProtocol.udp

    #: - [TCP] Barracuda Backup Protocol
    #: - [UDP] Barracuda Backup Protocol
    barracuda_bbs = 5120, 'barracuda-bbs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Policy Commander
    #: - [UDP] Policy Commander
    nbt_pc = 5133, 'nbt-pc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5134 = 5134, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5135 = 5135, 'reserved', TransportProtocol.udp

    #: [UDP] Minotaur SA
    minotaur_sa = 5136, 'minotaur-sa', TransportProtocol.udp

    #: - [TCP] MyCTS server port
    #: - [UDP] MyCTS server port
    ctsd = 5137, 'ctsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RMONITOR SECURE IANA assigned this well-formed service name as a
    #:   replacement for "rmonitor_secure".
    #: - [TCP] RMONITOR SECURE
    #: - [UDP] RMONITOR SECURE IANA assigned this well-formed service name as a
    #:   replacement for "rmonitor_secure".
    #: - [UDP] RMONITOR SECURE
    rmonitor_secure = 5145, 'rmonitor-secure', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5146 = 5146, 'reserved', TransportProtocol.udp

    #: - [TCP] Ascend Tunnel Management Protocol
    #: - [UDP] Ascend Tunnel Management Protocol
    atmp = 5150, 'atmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESRI SDE Instance IANA assigned this well-formed service name as a
    #:   replacement for "esri_sde".
    #: - [TCP] ESRI SDE Instance
    #: - [UDP] ESRI SDE Remote Start IANA assigned this well-formed service name as a
    #:   replacement for "esri_sde".
    #: - [UDP] ESRI SDE Remote Start
    esri_sde = 5151, 'esri-sde', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ESRI SDE Instance Discovery
    #: - [UDP] ESRI SDE Instance Discovery
    sde_discovery = 5152, 'sde-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_5153 = 5153, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BZFlag game server
    #: - [UDP] BZFlag game server
    bzflag = 5154, 'bzflag', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle asControl Agent
    #: - [UDP] Oracle asControl Agent
    asctrl_agent = 5155, 'asctrl-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5156 = 5156, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5157 = 5157, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5161 = 5161, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5162 = 5162, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5163 = 5163, 'reserved', TransportProtocol.udp

    #: [UDP] Virtual Protocol Adapter Discovery
    vpa_disc = 5164, 'vpa-disc', TransportProtocol.udp

    #: - [TCP] ife_1corp IANA assigned this well-formed service name as a replacement
    #:   for "ife_icorp".
    #: - [TCP] ife_1corp
    #: - [UDP] ife_1corp IANA assigned this well-formed service name as a replacement
    #:   for "ife_icorp".
    #: - [UDP] ife_1corp
    ife_icorp = 5165, 'ife-icorp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WinPCS Service Connection
    #: - [UDP] WinPCS Service Connection
    winpcs = 5166, 'winpcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCTE104 Connection
    #: - [UDP] SCTE104 Connection
    scte104 = 5167, 'scte104', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCTE30 Connection
    #: - [UDP] SCTE30 Connection
    scte30 = 5168, 'scte30', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5172 = 5172, 'reserved', TransportProtocol.udp

    #: - [TCP] America-Online
    #: - [UDP] America-Online
    aol = 5190, 'aol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AmericaOnline1
    #: - [UDP] AmericaOnline1
    aol_1 = 5191, 'aol-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AmericaOnline2
    #: - [UDP] AmericaOnline2
    aol_2 = 5192, 'aol-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AmericaOnline3
    #: - [UDP] AmericaOnline3
    aol_3 = 5193, 'aol-3', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5194 = 5194, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5195 = 5195, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5196 = 5196, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5197 = 5197, 'reserved', TransportProtocol.udp

    #: - [TCP] TARGUS GetData
    #: - [UDP] TARGUS GetData
    targus_getdata = 5200, 'targus-getdata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TARGUS GetData 1
    #: - [UDP] TARGUS GetData 1
    targus_getdata1 = 5201, 'targus-getdata1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TARGUS GetData 2
    #: - [UDP] TARGUS GetData 2
    targus_getdata2 = 5202, 'targus-getdata2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TARGUS GetData 3
    #: - [UDP] TARGUS GetData 3
    targus_getdata3 = 5203, 'targus-getdata3', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5209 = 5209, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5215 = 5215, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5221 = 5221, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5222 = 5222, 'reserved', TransportProtocol.udp

    #: - [TCP] HP Virtual Machine Group Management
    #: - [UDP] HP Virtual Machine Group Management
    hpvirtgrp = 5223, 'hpvirtgrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP Virtual Machine Console Operations
    #: - [UDP] HP Virtual Machine Console Operations
    hpvirtctrl = 5224, 'hpvirtctrl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP Server
    #: - [UDP] HP Server
    hp_server = 5225, 'hp-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP Status
    #: - [UDP] HP Status
    hp_status = 5226, 'hp-status', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP System Performance Metric Service
    #: - [UDP] HP System Performance Metric Service
    perfd = 5227, 'perfd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5228 = 5228, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5229 = 5229, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5230 = 5230, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5231 = 5231, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5232 = 5232, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5233 = 5233, 'reserved', TransportProtocol.udp

    #: - [TCP] EEnet communications
    #: - [UDP] EEnet communications
    eenet = 5234, 'eenet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Galaxy Network Service
    #: - [UDP] Galaxy Network Service
    galaxy_network = 5235, 'galaxy-network', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    padl2sim = 5236, 'padl2sim', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] m-net discovery
    #: - [UDP] m-net discovery
    mnet_discovery = 5237, 'mnet-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5242 = 5242, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5243 = 5243, 'reserved', TransportProtocol.udp

    #: [UDP] DownTools Discovery Protocol
    downtools_disc = 5245, 'downtools-disc', TransportProtocol.udp

    #: [UDP] CAPWAP Control Protocol [:rfc:`5415`]
    capwap_control = 5246, 'capwap-control', TransportProtocol.udp

    #: [UDP] CAPWAP Data Protocol [:rfc:`5415`]
    capwap_data = 5247, 'capwap-data', TransportProtocol.udp

    #: - [TCP] CA Access Control Web Service
    #: - [UDP] CA Access Control Web Service
    caacws = 5248, 'caacws', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA AC Lang Service
    #: - [UDP] CA AC Lang Service
    caaclang2 = 5249, 'caaclang2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] soaGateway
    #: - [UDP] soaGateway
    soagateway = 5250, 'soagateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA eTrust VM Service
    #: - [UDP] CA eTrust VM Service
    caevms = 5251, 'caevms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Movaz SSC
    #: - [UDP] Movaz SSC
    movaz_ssc = 5252, 'movaz-ssc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5253 = 5253, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5254 = 5254, 'reserved', TransportProtocol.udp

    #: - [TCP] 3Com Network Jack Port 1
    #: - [UDP] 3Com Network Jack Port 1
    UDP_3com_njack_1 = 5264, '3com-njack-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3Com Network Jack Port 2
    #: - [UDP] 3Com Network Jack Port 2
    UDP_3com_njack_2 = 5265, '3com-njack-2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5269 = 5269, 'reserved', TransportProtocol.udp

    #: - [TCP] Cartographer XMP
    #: - [UDP] Cartographer XMP
    cartographerxmp = 5270, 'cartographerxmp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] StageSoft CueLink discovery
    cuelink_disc = 5271, 'cuelink-disc', TransportProtocol.udp

    #: - [TCP] PK
    #: - [UDP] PK
    pk = 5272, 'pk', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5280 = 5280, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5281 = 5281, 'reserved', TransportProtocol.udp

    #: - [TCP] Marimba Transmitter Port
    #: - [UDP] Marimba Transmitter Port
    transmit_port = 5282, 'transmit-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NLG Data Service
    #: - [UDP] NLG Data Service
    nlg_data = 5299, 'nlg-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HA cluster heartbeat
    #: - [UDP] HA cluster heartbeat
    hacl_hb = 5300, 'hacl-hb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HA cluster general services
    #: - [UDP] HA cluster general services
    hacl_gs = 5301, 'hacl-gs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HA cluster configuration
    #: - [UDP] HA cluster configuration
    hacl_cfg = 5302, 'hacl-cfg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HA cluster probing
    #: - [UDP] HA cluster probing
    hacl_probe = 5303, 'hacl-probe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HA Cluster Commands
    #: - [UDP] HA Cluster Commands
    hacl_local = 5304, 'hacl-local', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HA Cluster Test
    #: - [UDP] HA Cluster Test
    hacl_test = 5305, 'hacl-test', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun MC Group
    #: - [UDP] Sun MC Group
    sun_mc_grp = 5306, 'sun-mc-grp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCO AIP
    #: - [UDP] SCO AIP
    sco_aip = 5307, 'sco-aip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CFengine
    #: - [UDP] CFengine
    cfengine = 5308, 'cfengine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] J Printer
    #: - [UDP] J Printer
    jprinter = 5309, 'jprinter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Outlaws
    #: - [UDP] Outlaws
    outlaws = 5310, 'outlaws', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Permabit Client-Server
    #: - [UDP] Permabit Client-Server
    permabit_cs = 5312, 'permabit-cs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Real-time & Reliable Data
    #: - [UDP] Real-time & Reliable Data
    rrdp = 5313, 'rrdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] opalis-rbt-ipc
    #: - [UDP] opalis-rbt-ipc
    opalis_rbt_ipc = 5314, 'opalis-rbt-ipc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HA Cluster UDP Polling
    #: - [UDP] HA Cluster UDP Polling
    hacl_poll = 5315, 'hacl-poll', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Unassigned
    unassigned_5316 = 5316, 'unassigned', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5317 = 5317, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5318 = 5318, 'reserved', TransportProtocol.udp

    #: - [TCP] Roughtime time synchronization [RFC-ietf-ntp-roughtime-19]
    #: - [UDP] Roughtime time synchronization [RFC-ietf-ntp-roughtime-19]
    roughtime = 5319, 'roughtime', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5320 = 5320, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5321 = 5321, 'reserved', TransportProtocol.udp

    #: - [TCP] Sculptor Database Server
    #: - [UDP] Sculptor Database Server
    kfserver = 5343, 'kfserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xkoto DRCP
    #: - [UDP] xkoto DRCP
    xkotodrcp = 5344, 'xkotodrcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Session Traversal Utilities for NAT (STUN) port [:rfc:`8489`]
    #: - [UDP] STUN over DTLS [:rfc:`7350`]
    stuns = 5349, 'stuns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TURN over TLS [:rfc:`8656`]
    #: - [UDP] TURN over DTLS [:rfc:`7350`]
    turns = 5349, 'turns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] STUN Behavior Discovery over TLS [:rfc:`5780`]
    #: - [UDP] Reserved for a future enhancement of STUN-BEHAVIOR [:rfc:`5780`]
    stun_behaviors = 5349, 'stun-behaviors', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Port Control Protocol Multicast [:rfc:`6887`]
    pcp_multicast = 5350, 'pcp-multicast', TransportProtocol.udp

    #: [UDP] Port Control Protocol [:rfc:`6887`]
    pcp = 5351, 'pcp', TransportProtocol.udp

    #: - [TCP] DNS Long-Lived Queries [:rfc:`8764`]
    #: - [UDP] DNS Long-Lived Queries [:rfc:`8764`]
    dns_llq = 5352, 'dns-llq', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multicast DNS [:rfc:`6762`]
    #: - [UDP] Multicast DNS [:rfc:`6762`]
    mdns = 5353, 'mdns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multicast DNS Responder IPC
    #: - [UDP] Multicast DNS Responder IPC
    mdnsresponder = 5354, 'mdnsresponder', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LLMNR
    #: - [UDP] LLMNR
    llmnr = 5355, 'llmnr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Small Business
    #: - [UDP] Microsoft Small Business
    ms_smlbiz = 5356, 'ms-smlbiz', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Web Services for Devices
    #: - [UDP] Web Services for Devices
    wsdapi = 5357, 'wsdapi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WS for Devices Secured
    #: - [UDP] WS for Devices Secured
    wsdapi_s = 5358, 'wsdapi-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Alerter
    #: - [UDP] Microsoft Alerter
    ms_alerter = 5359, 'ms-alerter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Protocol for Windows SideShow
    #: - [UDP] Protocol for Windows SideShow
    ms_sideshow = 5360, 'ms-sideshow', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Protocol for Windows SideShow
    #: - [UDP] Secure Protocol for Windows SideShow
    ms_s_sideshow = 5361, 'ms-s-sideshow', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Windows Server WSD2 Service
    #: - [UDP] Microsoft Windows Server WSD2 Service
    serverwsd2 = 5362, 'serverwsd2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Windows Network Projection
    #: - [UDP] Windows Network Projection
    net_projection = 5363, 'net-projection', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Microsoft Kernel Debugger
    kdnet = 5364, 'kdnet', TransportProtocol.udp

    #: - [TCP] StressTester(tm) Injector
    #: - [UDP] StressTester(tm) Injector
    stresstester = 5397, 'stresstester', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Elektron Administration
    #: - [UDP] Elektron Administration
    elektron_admin = 5398, 'elektron-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SecurityChase
    #: - [UDP] SecurityChase
    securitychase = 5399, 'securitychase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Excerpt Search
    #: - [UDP] Excerpt Search
    excerpt = 5400, 'excerpt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Excerpt Search Secure
    #: - [UDP] Excerpt Search Secure
    excerpts = 5401, 'excerpts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mftp
    #: - [UDP] mftp
    mftp_349 = 349, 'mftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OmniCast MFTP
    #: - [UDP] OmniCast MFTP
    mftp_5402 = 5402, 'mftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HPOMS-CI-LSTN
    #: - [UDP] HPOMS-CI-LSTN
    hpoms_ci_lstn = 5403, 'hpoms-ci-lstn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HPOMS-DPS-LSTN
    #: - [UDP] HPOMS-DPS-LSTN
    hpoms_dps_lstn = 5404, 'hpoms-dps-lstn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetSupport
    #: - [UDP] NetSupport
    netsupport = 5405, 'netsupport', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Systemics Sox
    #: - [UDP] Systemics Sox
    systemics_sox = 5406, 'systemics-sox', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Foresyte-Clear
    #: - [UDP] Foresyte-Clear
    foresyte_clear = 5407, 'foresyte-clear', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Foresyte-Sec
    #: - [UDP] Foresyte-Sec
    foresyte_sec = 5408, 'foresyte-sec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Salient Data Server
    #: - [UDP] Salient Data Server
    salient_dtasrv = 5409, 'salient-dtasrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Salient User Manager
    #: - [UDP] Salient User Manager
    salient_usrmgr = 5410, 'salient-usrmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ActNet
    #: - [UDP] ActNet
    actnet = 5411, 'actnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Continuus
    #: - [UDP] Continuus
    continuus = 5412, 'continuus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WWIOTALK
    #: - [UDP] WWIOTALK
    wwiotalk = 5413, 'wwiotalk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] StatusD
    #: - [UDP] StatusD
    statusd = 5414, 'statusd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NS Server
    #: - [UDP] NS Server
    ns_server = 5415, 'ns-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNS Gateway
    #: - [UDP] SNS Gateway
    sns_gateway = 5416, 'sns-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNS Agent
    #: - [UDP] SNS Agent
    sns_agent = 5417, 'sns-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCNTP
    #: - [UDP] MCNTP
    mcntp = 5418, 'mcntp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DJ-ICE
    #: - [UDP] DJ-ICE
    dj_ice = 5419, 'dj-ice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cylink-C
    #: - [UDP] Cylink-C
    cylink_c = 5420, 'cylink-c', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net Support 2
    #: - [UDP] Net Support 2
    netsupport2 = 5421, 'netsupport2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Salient MUX
    #: - [UDP] Salient MUX
    salient_mux = 5422, 'salient-mux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VIRTUALUSER
    #: - [UDP] VIRTUALUSER
    virtualuser = 5423, 'virtualuser', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Beyond Remote
    #: - [UDP] Beyond Remote
    beyond_remote = 5424, 'beyond-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Beyond Remote Command Channel
    #: - [UDP] Beyond Remote Command Channel
    br_channel = 5425, 'br-channel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DEVBASIC
    #: - [UDP] DEVBASIC
    devbasic = 5426, 'devbasic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCO-PEER-TTA
    #: - [UDP] SCO-PEER-TTA
    sco_peer_tta = 5427, 'sco-peer-tta', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TELACONSOLE
    #: - [UDP] TELACONSOLE
    telaconsole = 5428, 'telaconsole', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Billing and Accounting System Exchange
    #: - [UDP] Billing and Accounting System Exchange
    base = 5429, 'base', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RADEC CORP
    #: - [UDP] RADEC CORP
    radec_corp = 5430, 'radec-corp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PARK AGENT
    #: - [UDP] PARK AGENT
    park_agent = 5431, 'park-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PostgreSQL Database
    #: - [UDP] PostgreSQL Database
    postgresql = 5432, 'postgresql', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pyrrho DBMS
    #: - [UDP] Pyrrho DBMS
    pyrrho = 5433, 'pyrrho', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SGI Array Services Daemon
    #: - [UDP] SGI Array Services Daemon
    sgi_arrayd = 5434, 'sgi-arrayd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCEANICS situation and action notification
    #: - [UDP] SCEANICS situation and action notification
    sceanics = 5435, 'sceanics', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] pmip6-cntl [:rfc:`5844`]
    pmip6_cntl = 5436, 'pmip6-cntl', TransportProtocol.udp

    #: [UDP] pmip6-data [:rfc:`5844`]
    pmip6_data = 5437, 'pmip6-data', TransportProtocol.udp

    #: - [TCP] Pearson HTTPS
    #: - [UDP] Pearson HTTPS
    spss = 5443, 'spss', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5445 = 5445, 'reserved', TransportProtocol.udp

    #: [UDP] TiePie engineering data acquisition (discovery)
    tiepie_disc = 5450, 'tiepie-disc', TransportProtocol.udp

    #: - [TCP] SureBox
    #: - [UDP] SureBox
    surebox = 5453, 'surebox', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 5454
    #: - [UDP] APC 5454
    apc_5454 = 5454, 'apc-5454', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 5455
    #: - [UDP] APC 5455
    apc_5455 = 5455, 'apc-5455', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 5456
    #: - [UDP] APC 5456
    apc_5456 = 5456, 'apc-5456', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SILKMETER
    #: - [UDP] SILKMETER
    silkmeter = 5461, 'silkmeter', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TTL Publisher
    #: - [UDP] TTL Publisher
    ttl_publisher = 5462, 'ttl-publisher', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TTL Price Proxy
    #: - [UDP] TTL Price Proxy
    ttlpriceproxy = 5463, 'ttlpriceproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quail Networks Object Broker
    #: - [UDP] Quail Networks Object Broker
    quailnet = 5464, 'quailnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NETOPS-BROKER
    #: - [UDP] NETOPS-BROKER
    netops_broker = 5465, 'netops-broker', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5470 = 5470, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5471 = 5471, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5472 = 5472, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5473 = 5473, 'reserved', TransportProtocol.udp

    #: [UDP] The Apsolab company's status query protocol
    apsolab_rpc = 5474, 'apsolab-rpc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5475 = 5475, 'reserved', TransportProtocol.udp

    #: - [TCP] fcp-addr-srvr1
    #: - [UDP] fcp-addr-srvr1
    fcp_addr_srvr1 = 5500, 'fcp-addr-srvr1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fcp-addr-srvr2
    #: - [UDP] fcp-addr-srvr2
    fcp_addr_srvr2 = 5501, 'fcp-addr-srvr2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fcp-srvr-inst1
    #: - [UDP] fcp-srvr-inst1
    fcp_srvr_inst1 = 5502, 'fcp-srvr-inst1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fcp-srvr-inst2
    #: - [UDP] fcp-srvr-inst2
    fcp_srvr_inst2 = 5503, 'fcp-srvr-inst2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fcp-cics-gw1
    #: - [UDP] fcp-cics-gw1
    fcp_cics_gw1 = 5504, 'fcp-cics-gw1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Checkout Database
    #: - [UDP] Checkout Database
    checkoutdb = 5505, 'checkoutdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Amcom Mobile Connect
    #: - [UDP] Amcom Mobile Connect
    amc = 5506, 'amc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5507 = 5507, 'reserved', TransportProtocol.udp

    #: - [TCP] Matter Operational Discovery and Communi
    #: - [UDP] Matter Operational Discovery and Communi
    matter = 5540, 'matter', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5543 = 5543, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5550 = 5550, 'reserved', TransportProtocol.udp

    #: - [TCP] SGI Eventmond Port
    #: - [UDP] SGI Eventmond Port
    sgi_eventmond = 5553, 'sgi-eventmond', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SGI ESP HTTP
    #: - [UDP] SGI ESP HTTP
    sgi_esphttp = 5554, 'sgi-esphttp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Personal Agent
    #: - [UDP] Personal Agent
    personal_agent = 5555, 'personal-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Freeciv gameplay
    #: - [UDP] Freeciv gameplay
    freeciv = 5556, 'freeciv', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5557 = 5557, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5565 = 5565, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5566 = 5566, 'reserved', TransportProtocol.udp

    #: - [TCP] DOF Protocol Stack Multicast/Secure Transport
    #: - [UDP] DOF Protocol Stack Multicast/Secure Transport
    dof_dps_mc_sec = 5567, 'dof-dps-mc-sec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Session Data Transport Multicast
    #: - [UDP] Session Data Transport Multicast
    sdt = 5568, 'sdt', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] PLASA E1.33, Remote Device Management (RDM) messages
    rdmnet_device = 5569, 'rdmnet-device', TransportProtocol.udp

    #: - [TCP] SAS Domain Management Messaging Protocol
    #: - [UDP] SAS Domain Management Messaging Protocol
    sdmmp = 5573, 'sdmmp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5574 = 5574, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5575 = 5575, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5579 = 5579, 'reserved', TransportProtocol.udp

    #: - [TCP] T-Mobile SMS Protocol Message 0
    #: - [UDP] T-Mobile SMS Protocol Message 0
    tmosms0 = 5580, 'tmosms0', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] T-Mobile SMS Protocol Message 1
    #: - [UDP] T-Mobile SMS Protocol Message 1
    tmosms1 = 5581, 'tmosms1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] T-Mobile SMS Protocol Message 3
    #: - [UDP] T-Mobile SMS Protocol Message 3
    fac_restore = 5582, 'fac-restore', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] T-Mobile SMS Protocol Message 2
    #: - [UDP] T-Mobile SMS Protocol Message 2
    tmo_icon_sync = 5583, 'tmo-icon-sync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BeInSync-Web
    #: - [UDP] BeInSync-Web
    bis_web = 5584, 'bis-web', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BeInSync-sync
    #: - [UDP] BeInSync-sync
    bis_sync = 5585, 'bis-sync', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5586 = 5586, 'reserved', TransportProtocol.udp

    #: - [TCP] inin secure messaging
    #: - [UDP] inin secure messaging
    ininmessaging = 5597, 'ininmessaging', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCT Market Data Feed
    #: - [UDP] MCT Market Data Feed
    mctfeed = 5598, 'mctfeed', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Enterprise Security Remote Install
    #: - [UDP] Enterprise Security Remote Install
    esinstall = 5599, 'esinstall', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Enterprise Security Manager
    #: - [UDP] Enterprise Security Manager
    esmmanager = 5600, 'esmmanager', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Enterprise Security Agent
    #: - [UDP] Enterprise Security Agent
    esmagent = 5601, 'esmagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A1-MSC
    #: - [UDP] A1-MSC
    a1_msc = 5602, 'a1-msc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A1-BS
    #: - [UDP] A1-BS
    a1_bs = 5603, 'a1-bs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A3-SDUNode
    #: - [UDP] A3-SDUNode
    a3_sdunode = 5604, 'a3-sdunode', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] A4-SDUNode
    #: - [UDP] A4-SDUNode
    a4_sdunode = 5605, 'a4-sdunode', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5618 = 5618, 'reserved', TransportProtocol.udp

    #: - [TCP] Node Initiated Network Association Forma
    #: - [UDP] Node Initiated Network Association Forma
    ninaf = 5627, 'ninaf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HTrust API
    #: - [UDP] HTrust API
    htrust = 5628, 'htrust', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Symantec Storage Foundation for Database
    #: - [UDP] Symantec Storage Foundation for Database
    symantec_sfdb = 5629, 'symantec-sfdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PreciseCommunication
    #: - [UDP] PreciseCommunication
    precise_comm = 5630, 'precise-comm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pcANYWHEREdata
    #: - [UDP] pcANYWHEREdata
    pcanywheredata = 5631, 'pcanywheredata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pcANYWHEREstat
    #: - [UDP] pcANYWHEREstat
    pcanywherestat = 5632, 'pcanywherestat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BE Operations Request Listener
    #: - [UDP] BE Operations Request Listener
    beorl = 5633, 'beorl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SF Message Service
    #: - [UDP] SF Message Service
    xprtld = 5634, 'xprtld', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5635 = 5635, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5636 = 5636, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5637 = 5637, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5638 = 5638, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5639 = 5639, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5646 = 5646, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5666 = 5666, 'reserved', TransportProtocol.udp

    #: [UDP] Local area discovery and messaging over ZeroMQ
    zre_disc = 5670, 'zre-disc', TransportProtocol.udp

    #: - [TCP] amqp protocol over TLS/SSL
    #: - [UDP] amqp protocol over TLS/SSL
    amqps = 5671, 'amqps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AMQP
    #: - [UDP] AMQP
    #: - [SCTP] AMQP
    amqp = 5672, 'amqp', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] JACL Message Server
    #: - [UDP] JACL Message Server
    jms = 5673, 'jms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HyperSCSI Port
    #: - [UDP] HyperSCSI Port
    hyperscsi_port = 5674, 'hyperscsi-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] V5UA application port [:rfc:`3807`]
    #: - [UDP] V5UA application port [:rfc:`3807`]
    #: - [SCTP] V5UA application port [:rfc:`3807`]
    v5ua = 5675, 'v5ua', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] RA Administration
    #: - [UDP] RA Administration
    raadmin = 5676, 'raadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quest Central DB2 Launchr
    #: - [UDP] Quest Central DB2 Launchr
    questdb2_lnchr = 5677, 'questdb2-lnchr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Remote Replication Agent Connection
    #: - [UDP] Remote Replication Agent Connection
    rrac = 5678, 'rrac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Direct Cable Connect Manager
    #: - [UDP] Direct Cable Connect Manager
    dccm = 5679, 'dccm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Auriga Router Service
    #: - [UDP] Auriga Router Service
    auriga_router = 5680, 'auriga-router', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Net-coneX Control Protocol
    #: - [UDP] Net-coneX Control Protocol
    ncxcp = 5681, 'ncxcp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] BrightCore control & data transfer exchange
    brightcore = 5682, 'brightcore', TransportProtocol.udp

    #: - [TCP] Constrained Application Protocol (CoAP) [:rfc:`8323`]
    #: - [UDP] Constrained Application Protocol [:rfc:`7252`]
    coap = 5683, 'coap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Constrained Application Protocol (CoAP) [:rfc:`7301`][:rfc:`8323`]
    #: - [UDP] DTLS-secured CoAP [:rfc:`7252`]
    coaps = 5684, 'coaps', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] GOG multiplayer game protocol
    gog_multiplayer = 5687, 'gog-multiplayer', TransportProtocol.udp

    #: - [TCP] GGZ Gaming Zone
    #: - [UDP] GGZ Gaming Zone
    ggz = 5688, 'ggz', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QM video network management protocol
    #: - [UDP] QM video network management protocol
    qmvideo = 5689, 'qmvideo', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5693 = 5693, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5696 = 5696, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5700 = 5700, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5705 = 5705, 'reserved', TransportProtocol.udp

    #: - [TCP] proshare conf audio
    #: - [UDP] proshare conf audio
    proshareaudio = 5713, 'proshareaudio', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] proshare conf video
    #: - [UDP] proshare conf video
    prosharevideo = 5714, 'prosharevideo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] proshare conf data
    #: - [UDP] proshare conf data
    prosharedata = 5715, 'prosharedata', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] proshare conf request
    #: - [UDP] proshare conf request
    prosharerequest = 5716, 'prosharerequest', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] proshare conf notify
    #: - [UDP] proshare conf notify
    prosharenotify = 5717, 'prosharenotify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DPM Communication Server
    #: - [UDP] DPM Communication Server
    dpm = 5718, 'dpm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DPM Agent Coordinator
    #: - [UDP] DPM Agent Coordinator
    dpm_agent = 5719, 'dpm-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MS-Licensing
    #: - [UDP] MS-Licensing
    ms_licensing = 5720, 'ms-licensing', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Desktop Passthru Service
    #: - [UDP] Desktop Passthru Service
    dtpt = 5721, 'dtpt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft DFS Replication Service
    #: - [UDP] Microsoft DFS Replication Service
    msdfsr = 5722, 'msdfsr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Operations Manager - Health Service
    #: - [UDP] Operations Manager - Health Service
    omhs = 5723, 'omhs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Operations Manager - SDK Service
    #: - [UDP] Operations Manager - SDK Service
    omsdk = 5724, 'omsdk', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5725 = 5725, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5726 = 5726, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5727 = 5727, 'reserved', TransportProtocol.udp

    #: [UDP] Dist. I/O Comm. Service Group Membership
    io_dist_group = 5728, 'io-dist-group', TransportProtocol.udp

    #: - [TCP] Openmail User Agent Layer
    #: - [UDP] Openmail User Agent Layer
    openmail = 5729, 'openmail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Steltor's calendar access
    #: - [UDP] Steltor's calendar access
    unieng = 5730, 'unieng', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IDA Discover Port 1
    #: - [UDP] IDA Discover Port 1
    ida_discover1 = 5741, 'ida-discover1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IDA Discover Port 2
    #: - [UDP] IDA Discover Port 2
    ida_discover2 = 5742, 'ida-discover2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Watchdoc NetPOD Protocol
    #: - [UDP] Watchdoc NetPOD Protocol
    watchdoc_pod = 5743, 'watchdoc-pod', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Watchdoc Server
    #: - [UDP] Watchdoc Server
    watchdoc = 5744, 'watchdoc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fcopy-server
    #: - [UDP] fcopy-server
    fcopy_server = 5745, 'fcopy-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fcopys-server
    #: - [UDP] fcopys-server
    fcopys_server = 5746, 'fcopys-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wildbits Tunatic
    #: - [UDP] Wildbits Tunatic
    tunatic = 5747, 'tunatic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wildbits Tunalyzer
    #: - [UDP] Wildbits Tunalyzer
    tunalyzer = 5748, 'tunalyzer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bladelogic Agent Service
    #: - [UDP] Bladelogic Agent Service
    rscd = 5750, 'rscd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenMail Desk Gateway server
    #: - [UDP] OpenMail Desk Gateway server
    openmailg = 5755, 'openmailg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenMail X.500 Directory Server
    #: - [UDP] OpenMail X.500 Directory Server
    x500ms = 5757, 'x500ms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenMail NewMail Server
    #: - [UDP] OpenMail NewMail Server
    openmailns = 5766, 'openmailns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenMail Suer Agent Layer (Secure)
    #: - [UDP] OpenMail Suer Agent Layer (Secure)
    s_openmail = 5767, 's-openmail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenMail CMTS Server
    #: - [UDP] OpenMail CMTS Server
    openmailpxy = 5768, 'openmailpxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] x509solutions Internal CA
    #: - [UDP] x509solutions Internal CA
    spramsca = 5769, 'spramsca', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] x509solutions Secure Data
    #: - [UDP] x509solutions Secure Data
    spramsd = 5770, 'spramsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetAgent
    #: - [UDP] NetAgent
    netagent = 5771, 'netagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Control commands and responses
    #: - [UDP] Control commands and responses
    starfield_io = 5777, 'starfield-io', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5780 = 5780, 'reserved', TransportProtocol.udp

    #: - [TCP] 3PAR Event Reporting Service
    #: - [UDP] 3PAR Event Reporting Service
    UDP_3par_evts = 5781, '3par-evts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3PAR Management Service
    #: - [UDP] 3PAR Management Service
    UDP_3par_mgmt = 5782, '3par-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3PAR Management Service with SSL
    #: - [UDP] 3PAR Management Service with SSL
    UDP_3par_mgmt_ssl = 5783, '3par-mgmt-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Cisco Interbox Application Redundancy
    ibar = 5784, 'ibar', TransportProtocol.udp

    #: - [TCP] 3PAR Inform Remote Copy
    #: - [UDP] 3PAR Inform Remote Copy
    UDP_3par_rcopy = 5785, '3par-rcopy', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] redundancy notification
    cisco_redu = 5786, 'cisco-redu', TransportProtocol.udp

    #: [UDP] Cisco WAAS Cluster Protocol
    waascluster = 5787, 'waascluster', TransportProtocol.udp

    #: - [TCP] XtreamX Supervised Peer message
    #: - [UDP] XtreamX Supervised Peer message
    xtreamx = 5793, 'xtreamx', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Simple Peered Discovery Protocol
    spdp = 5794, 'spdp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5798 = 5798, 'reserved', TransportProtocol.udp

    #: - [TCP] ICMPD
    #: - [UDP] ICMPD
    icmpd = 5813, 'icmpd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Support Automation
    #: - [UDP] Support Automation
    spt_automation = 5814, 'spt-automation', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5820 = 5820, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5841 = 5841, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5842 = 5842, 'reserved', TransportProtocol.udp

    #: - [TCP] WHEREHOO
    #: - [UDP] WHEREHOO
    wherehoo = 5859, 'wherehoo', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PlanetPress Suite Messeng
    #: - [UDP] PlanetPress Suite Messeng
    ppsuitemsg = 5863, 'ppsuitemsg', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5868 = 5868, 'reserved', TransportProtocol.udp

    #: - [TCP] Remote Framebuffer [:rfc:`6143`]
    #: - [UDP] Remote Framebuffer [:rfc:`6143`]
    rfb = 5900, 'rfb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Flight & Flow Info for Collaborative Env
    #: - [UDP] Flight & Flow Info for Collaborative Env
    #: - [SCTP] Flight & Flow Info for Collaborative Env
    ff_ice = 5903, 'ff-ice', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Air-Ground SWIM
    #: - [UDP] Air-Ground SWIM
    #: - [SCTP] Air-Ground SWIM
    ag_swim = 5904, 'ag-swim', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Adv Surface Mvmnt and Guidance Cont Sys
    #: - [UDP] Adv Surface Mvmnt and Guidance Cont Sys
    #: - [SCTP] Adv Surface Mvmnt and Guidance Cont Sys
    asmgcs = 5905, 'asmgcs', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Remotely Piloted Vehicle C&C
    #: - [UDP] Remotely Piloted Vehicle C&C
    #: - [SCTP] Remotely Piloted Vehicle C&C
    rpas_c2 = 5906, 'rpas-c2', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Distress and Safety Data App
    #: - [UDP] Distress and Safety Data App
    #: - [SCTP] Distress and Safety Data App
    dsd = 5907, 'dsd', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] IPS Management Application
    #: - [UDP] IPS Management Application
    #: - [SCTP] IPS Management Application
    ipsma = 5908, 'ipsma', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Air-ground media advisory
    #: - [UDP] Air-ground media advisory
    #: - [SCTP] Air-ground media advisory
    agma = 5909, 'agma', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Air Traffic Services applications using ATN
    #: - [UDP] Air Traffic Services applications using ATN
    ats_atn = 5910, 'ats-atn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Air Traffic Services applications using ACARS
    #: - [UDP] Air Traffic Services applications using ACARS
    ats_acars = 5911, 'ats-acars', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aeronautical Information Service/Meteorological applications using
    #:   ACARS
    #: - [UDP] Aeronautical Information Service/Meteorological applications using
    #:   ACARS
    ais_met = 5912, 'ais-met', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Airline operational communications applications using ACARS
    #: - [UDP] Airline operational communications applications using ACARS
    aoc_acars = 5913, 'aoc-acars', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Security for Internet Protocol Suite
    #: - [UDP] Security for Internet Protocol Suite
    #: - [SCTP] Security for Internet Protocol Suite
    ipsdtls = 5914, 'ipsdtls', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Indy Application Server
    #: - [UDP] Indy Application Server
    indy = 5963, 'indy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mppolicy-v5
    #: - [UDP] mppolicy-v5
    mppolicy_v5 = 5968, 'mppolicy-v5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mppolicy-mgr
    #: - [UDP] mppolicy-mgr
    mppolicy_mgr = 5969, 'mppolicy-mgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CouchDB
    #: - [UDP] CouchDB
    couchdb = 5984, 'couchdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WBEM WS-Management HTTP
    #: - [UDP] WBEM WS-Management HTTP
    wsman = 5985, 'wsman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WBEM WS-Management HTTP over TLS/SSL
    #: - [UDP] WBEM WS-Management HTTP over TLS/SSL
    wsmans = 5986, 'wsmans', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WBEM RMI
    #: - [UDP] WBEM RMI
    wbem_rmi = 5987, 'wbem-rmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WBEM CIM-XML (HTTP)
    #: - [UDP] WBEM CIM-XML (HTTP)
    wbem_http = 5988, 'wbem-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WBEM CIM-XML (HTTPS)
    #: - [UDP] WBEM CIM-XML (HTTPS)
    wbem_https = 5989, 'wbem-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WBEM Export HTTPS
    #: - [UDP] WBEM Export HTTPS
    wbem_exp_https = 5990, 'wbem-exp-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NUXSL
    #: - [UDP] NUXSL
    nuxsl = 5991, 'nuxsl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Consul InSight Security
    #: - [UDP] Consul InSight Security
    consul_insight = 5992, 'consul-insight', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5993 = 5993, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_5994 = 5994, 'reserved', TransportProtocol.udp

    #: - [TCP] CVSup
    #: - [UDP] CVSup
    cvsup = 5999, 'cvsup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NDL-AHP-SVC
    #: - [UDP] NDL-AHP-SVC
    ndl_ahp_svc = 6064, 'ndl-ahp-svc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WinPharaoh
    #: - [UDP] WinPharaoh
    winpharaoh = 6065, 'winpharaoh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EWCTSP
    #: - [UDP] EWCTSP
    ewctsp = 6066, 'ewctsp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6068 = 6068, 'reserved', TransportProtocol.udp

    #: - [TCP] TRIP
    #: - [UDP] TRIP
    trip = 6069, 'trip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Messageasap
    #: - [UDP] Messageasap
    messageasap = 6070, 'messageasap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSDTP
    #: - [UDP] SSDTP
    ssdtp = 6071, 'ssdtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DIAGNOSE-PROC
    #: - [UDP] DIAGNOSE-PROC
    diagnose_proc = 6072, 'diagnose-proc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DirectPlay8
    #: - [UDP] DirectPlay8
    directplay8 = 6073, 'directplay8', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Max
    #: - [UDP] Microsoft Max
    max = 6074, 'max', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6075 = 6075, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6076 = 6076, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6077 = 6077, 'reserved', TransportProtocol.udp

    #: [UDP] Generic UDP Encapsulation [draft-herbert-gue-02]
    gue = 6080, 'gue', TransportProtocol.udp

    #: [UDP] Generic Network Virtualization Encapsulation (Geneve) [:rfc:`8926`]
    geneve = 6081, 'geneve', TransportProtocol.udp

    #: [UDP] APCO Project 25 Common Air Interface - UDP encapsulation
    p25cai = 6082, 'p25cai', TransportProtocol.udp

    #: [UDP] telecomsoftware miami broadcast
    miami_bcast = 6083, 'miami-bcast', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6084 = 6084, 'reserved', TransportProtocol.udp

    #: - [TCP] konspire2b p2p network
    #: - [UDP] konspire2b p2p network
    konspire2b = 6085, 'konspire2b', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PDTP P2P
    #: - [UDP] PDTP P2P
    pdtp = 6086, 'pdtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Local Download Sharing Service
    #: - [UDP] Local Download Sharing Service
    ldss = 6087, 'ldss', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] SuperDog License Manager Notifier
    doglms_notify = 6088, 'doglms-notify', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6099 = 6099, 'reserved', TransportProtocol.udp

    #: - [TCP] SynchroNet-db
    #: - [UDP] SynchroNet-db
    synchronet_db = 6100, 'synchronet-db', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SynchroNet-rtc
    #: - [UDP] SynchroNet-rtc
    synchronet_rtc = 6101, 'synchronet-rtc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SynchroNet-upd
    #: - [UDP] SynchroNet-upd
    synchronet_upd = 6102, 'synchronet-upd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RETS
    #: - [UDP] RETS
    rets = 6103, 'rets', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DBDB
    #: - [UDP] DBDB
    dbdb = 6104, 'dbdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Prima Server
    #: - [UDP] Prima Server
    primaserver = 6105, 'primaserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MPS Server
    #: - [UDP] MPS Server
    mpsserver = 6106, 'mpsserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ETC Control
    #: - [UDP] ETC Control
    etc_control = 6107, 'etc-control', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sercomm-SCAdmin
    #: - [UDP] Sercomm-SCAdmin
    sercomm_scadmin = 6108, 'sercomm-scadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GLOBECAST-ID
    #: - [UDP] GLOBECAST-ID
    globecast_id = 6109, 'globecast-id', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP SoftBench CM
    #: - [UDP] HP SoftBench CM
    softcm = 6110, 'softcm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP SoftBench Sub-Process Control
    #: - [UDP] HP SoftBench Sub-Process Control
    spc = 6111, 'spc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Desk-Top Sub-Process Control Daemon
    #: - [UDP] Desk-Top Sub-Process Control Daemon
    dtspcd = 6112, 'dtspcd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6113 = 6113, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6114 = 6114, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6115 = 6115, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6116 = 6116, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6117 = 6117, 'reserved', TransportProtocol.udp

    #: [UDP] Transparent Inter Process Communication
    tipc = 6118, 'tipc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6121 = 6121, 'reserved', TransportProtocol.udp

    #: - [TCP] Backup Express Web Server
    #: - [UDP] Backup Express Web Server
    bex_webadmin = 6122, 'bex-webadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Backup Express
    #: - [UDP] Backup Express
    backup_express = 6123, 'backup-express', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Phlexible Network Backup Service
    #: - [UDP] Phlexible Network Backup Service
    pnbs = 6124, 'pnbs', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6130 = 6130, 'reserved', TransportProtocol.udp

    #: - [TCP] New Boundary Tech WOL
    #: - [UDP] New Boundary Tech WOL
    nbt_wol = 6133, 'nbt-wol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pulsonix Network License Service
    #: - [UDP] Pulsonix Network License Service
    pulsonixnls = 6140, 'pulsonixnls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Meta Corporation License Manager
    #: - [UDP] Meta Corporation License Manager
    meta_corp = 6141, 'meta-corp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aspen Technology License Manager
    #: - [UDP] Aspen Technology License Manager
    aspentec_lm = 6142, 'aspentec-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Watershed License Manager
    #: - [UDP] Watershed License Manager
    watershed_lm = 6143, 'watershed-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] StatSci License Manager - 1
    #: - [UDP] StatSci License Manager - 1
    statsci1_lm = 6144, 'statsci1-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] StatSci License Manager - 2
    #: - [UDP] StatSci License Manager - 2
    statsci2_lm = 6145, 'statsci2-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Lone Wolf Systems License Manager
    #: - [UDP] Lone Wolf Systems License Manager
    lonewolf_lm = 6146, 'lonewolf-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Montage License Manager
    #: - [UDP] Montage License Manager
    montage_lm = 6147, 'montage-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ricardo North America License Manager
    #: - [UDP] Ricardo North America License Manager
    ricardo_lm_1522 = 1522, 'ricardo-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ricardo North America License Manager
    #: - [UDP] Ricardo North America License Manager
    ricardo_lm_6148 = 6148, 'ricardo-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tal-pod
    #: - [UDP] tal-pod
    tal_pod = 6149, 'tal-pod', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6159 = 6159, 'reserved', TransportProtocol.udp

    #: [UDP] Emerson Extensible Control and Management Protocol Data
    ecmp_data = 6160, 'ecmp-data', TransportProtocol.udp

    #: - [TCP] PATROL Internet Srv Mgr
    #: - [UDP] PATROL Internet Srv Mgr
    patrol_ism = 6161, 'patrol-ism', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PATROL Collector
    #: - [UDP] PATROL Collector
    patrol_coll = 6162, 'patrol-coll', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Precision Scribe Cnx Port
    #: - [UDP] Precision Scribe Cnx Port
    pscribe = 6163, 'pscribe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LM-X License Manager by X-Formation
    #: - [UDP] LM-X License Manager by X-Formation
    lm_x = 6200, 'lm-x', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Management of service nodes in a processing grid for thermodynamic
    #: calculations
    thermo_calc = 6201, 'thermo-calc', TransportProtocol.udp

    #: - [TCP] QMTP over TLS
    #: - [UDP] QMTP over TLS
    qmtps = 6209, 'qmtps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Radmind Access Protocol
    #: - [UDP] Radmind Access Protocol
    radmind = 6222, 'radmind', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] JEOL Network Services Dynamic Discovery Protocol 1
    jeol_nsddp_1 = 6241, 'jeol-nsddp-1', TransportProtocol.udp

    #: [UDP] JEOL Network Services Dynamic Discovery Protocol 2
    jeol_nsddp_2 = 6242, 'jeol-nsddp-2', TransportProtocol.udp

    #: [UDP] JEOL Network Services Dynamic Discovery Protocol 3
    jeol_nsddp_3 = 6243, 'jeol-nsddp-3', TransportProtocol.udp

    #: [UDP] JEOL Network Services Dynamic Discovery Protocol 4
    jeol_nsddp_4 = 6244, 'jeol-nsddp-4', TransportProtocol.udp

    #: - [TCP] TL1 Raw Over SSL/TLS
    #: - [UDP] TL1 Raw Over SSL/TLS
    tl1_raw_ssl = 6251, 'tl1-raw-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TL1 over SSH
    #: - [UDP] TL1 over SSH
    tl1_ssh = 6252, 'tl1-ssh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CRIP
    #: - [UDP] CRIP
    crip = 6253, 'crip', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6267 = 6267, 'reserved', TransportProtocol.udp

    #: - [TCP] Grid Authentication
    #: - [UDP] Grid Authentication
    grid = 6268, 'grid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Grid Authentication Alt
    #: - [UDP] Grid Authentication Alt
    grid_alt = 6269, 'grid-alt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC GRX
    #: - [UDP] BMC GRX
    bmc_grx = 6300, 'bmc-grx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC CONTROL-D LDAP SERVER IANA assigned this well-formed service name
    #:   as a replacement for "bmc_ctd_ldap".
    #: - [TCP] BMC CONTROL-D LDAP SERVER
    #: - [UDP] BMC CONTROL-D LDAP SERVER IANA assigned this well-formed service name
    #:   as a replacement for "bmc_ctd_ldap".
    #: - [UDP] BMC CONTROL-D LDAP SERVER
    bmc_ctd_ldap = 6301, 'bmc-ctd-ldap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Unified Fabric Management Protocol
    #: - [UDP] Unified Fabric Management Protocol
    ufmp = 6306, 'ufmp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Sensor Control Unit Protocol Discovery Protocol
    scup_disc = 6315, 'scup-disc', TransportProtocol.udp

    #: - [TCP] Ethernet Sensor Communications Protocol
    #: - [UDP] Ethernet Sensor Communications Protocol
    abb_escp = 6316, 'abb-escp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Navtech Radar Sensor Data
    nav_data = 6317, 'nav-data', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6318 = 6318, 'reserved', TransportProtocol.udp

    #: - [TCP] Double-Take Replication Service
    #: - [UDP] Double-Take Replication Service
    repsvc = 6320, 'repsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Empress Software Connectivity Server 1
    #: - [UDP] Empress Software Connectivity Server 1
    emp_server1 = 6321, 'emp-server1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Empress Software Connectivity Server 2
    #: - [UDP] Empress Software Connectivity Server 2
    emp_server2 = 6322, 'emp-server2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] HR Device Network service
    hrd_ns_disc = 6324, 'hrd-ns-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6325 = 6325, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6326 = 6326, 'reserved', TransportProtocol.udp

    #: - [TCP] sFlow traffic monitoring
    #: - [UDP] sFlow traffic monitoring
    sflow = 6343, 'sflow', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6344 = 6344, 'reserved', TransportProtocol.udp

    #: - [TCP] gnutella-svc
    #: - [UDP] gnutella-svc
    gnutella_svc = 6346, 'gnutella-svc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] gnutella-rtr
    #: - [UDP] gnutella-rtr
    gnutella_rtr = 6347, 'gnutella-rtr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] App Discovery and Access Protocol
    #: - [UDP] App Discovery and Access Protocol
    adap = 6350, 'adap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PMCS applications
    #: - [UDP] PMCS applications
    pmcs = 6355, 'pmcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MetaEdit+ Multi-User
    #: - [UDP] MetaEdit+ Multi-User
    metaedit_mu = 6360, 'metaedit-mu', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Named Data Networking
    ndn = 6363, 'ndn', TransportProtocol.udp

    #: - [TCP] MetaEdit+ Server Administration
    #: - [UDP] MetaEdit+ Server Administration
    metaedit_se = 6370, 'metaedit-se', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6379 = 6379, 'reserved', TransportProtocol.udp

    #: - [TCP] Metatude Dialogue Server
    #: - [UDP] Metatude Dialogue Server
    metatude_mds = 6382, 'metatude-mds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] clariion-evr01
    #: - [UDP] clariion-evr01
    clariion_evr01 = 6389, 'clariion-evr01', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MetaEdit+ WebService API
    #: - [UDP] MetaEdit+ WebService API
    metaedit_ws = 6390, 'metaedit-ws', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Faxcom Message Service
    #: - [UDP] Faxcom Message Service
    faxcomservice = 6417, 'faxcomservice', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6418 = 6418, 'reserved', TransportProtocol.udp

    #: [UDP] Simple VDR Protocol Discovery
    svdrp_disc = 6419, 'svdrp-disc', TransportProtocol.udp

    #: - [TCP] NIM_VDRShell
    #: - [UDP] NIM_VDRShell
    nim_vdrshell = 6420, 'nim-vdrshell', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NIM_WAN
    #: - [UDP] NIM_WAN
    nim_wan = 6421, 'nim-wan', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6432 = 6432, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6440 = 6440, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6442 = 6442, 'reserved', TransportProtocol.udp

    #: - [TCP] Service Registry Default HTTPS Domain
    #: - [UDP] Service Registry Default HTTPS Domain
    sun_sr_https = 6443, 'sun-sr-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Grid Engine Execution Service IANA assigned this well-formed service
    #:   name as a replacement for "sge_execd".
    #: - [TCP] Grid Engine Execution Service
    #: - [UDP] Grid Engine Execution Service IANA assigned this well-formed service
    #:   name as a replacement for "sge_execd".
    #: - [UDP] Grid Engine Execution Service
    sge_execd = 6445, 'sge-execd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MySQL Proxy
    #: - [UDP] MySQL Proxy
    mysql_proxy = 6446, 'mysql-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SKIP Certificate Receive
    #: - [UDP] SKIP Certificate Receive
    skip_cert_recv = 6455, 'skip-cert-recv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SKIP Certificate Send
    #: - [UDP] SKIP Certificate Send
    skip_cert_send = 6456, 'skip-cert-send', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Port assignment for medical device communication in accordance to IEEE
    #:   11073-20701
    #: - [UDP] Port assignment for medical device communication in accordance to IEEE
    #:   11073-20701
    ieee11073_20701 = 6464, 'ieee11073-20701', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LVision License Manager
    #: - [UDP] LVision License Manager
    lvision_lm = 6471, 'lvision-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Registry Default HTTP Domain
    #: - [UDP] Service Registry Default HTTP Domain
    sun_sr_http = 6480, 'sun-sr-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Tags
    #: - [UDP] Service Tags
    servicetags = 6481, 'servicetags', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Logical Domains Management Interface
    #: - [UDP] Logical Domains Management Interface
    ldoms_mgmt = 6482, 'ldoms-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SunVTS RMI
    #: - [UDP] SunVTS RMI
    sunvts_rmi = 6483, 'sunvts-rmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Registry Default JMS Domain
    #: - [UDP] Service Registry Default JMS Domain
    sun_sr_jms = 6484, 'sun-sr-jms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Registry Default IIOP Domain
    #: - [UDP] Service Registry Default IIOP Domain
    sun_sr_iiop = 6485, 'sun-sr-iiop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Registry Default IIOPS Domain
    #: - [UDP] Service Registry Default IIOPS Domain
    sun_sr_iiops = 6486, 'sun-sr-iiops', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Registry Default IIOPAuth Domain
    #: - [UDP] Service Registry Default IIOPAuth Domain
    sun_sr_iiop_aut = 6487, 'sun-sr-iiop-aut', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Registry Default JMX Domain
    #: - [UDP] Service Registry Default JMX Domain
    sun_sr_jmx = 6488, 'sun-sr-jmx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Service Registry Default Admin Domain
    #: - [UDP] Service Registry Default Admin Domain
    sun_sr_admin = 6489, 'sun-sr-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BoKS Master
    #: - [UDP] BoKS Master
    boks = 6500, 'boks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BoKS Servc IANA assigned this well-formed service name as a
    #:   replacement for "boks_servc".
    #: - [TCP] BoKS Servc
    #: - [UDP] BoKS Servc IANA assigned this well-formed service name as a
    #:   replacement for "boks_servc".
    #: - [UDP] BoKS Servc
    boks_servc = 6501, 'boks-servc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BoKS Servm IANA assigned this well-formed service name as a
    #:   replacement for "boks_servm".
    #: - [TCP] BoKS Servm
    #: - [UDP] BoKS Servm IANA assigned this well-formed service name as a
    #:   replacement for "boks_servm".
    #: - [UDP] BoKS Servm
    boks_servm = 6502, 'boks-servm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BoKS Clntd IANA assigned this well-formed service name as a
    #:   replacement for "boks_clntd".
    #: - [TCP] BoKS Clntd
    #: - [UDP] BoKS Clntd IANA assigned this well-formed service name as a
    #:   replacement for "boks_clntd".
    #: - [UDP] BoKS Clntd
    boks_clntd = 6503, 'boks-clntd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BoKS Admin Private Port IANA assigned this well-formed service name as
    #:   a replacement for "badm_priv".
    #: - [TCP] BoKS Admin Private Port
    #: - [UDP] BoKS Admin Private Port IANA assigned this well-formed service name as
    #:   a replacement for "badm_priv".
    #: - [UDP] BoKS Admin Private Port
    badm_priv = 6505, 'badm-priv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BoKS Admin Public Port IANA assigned this well-formed service name as
    #:   a replacement for "badm_pub".
    #: - [TCP] BoKS Admin Public Port
    #: - [UDP] BoKS Admin Public Port IANA assigned this well-formed service name as
    #:   a replacement for "badm_pub".
    #: - [UDP] BoKS Admin Public Port
    badm_pub = 6506, 'badm-pub', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BoKS Dir Server, Private Port IANA assigned this well-formed service
    #:   name as a replacement for "bdir_priv".
    #: - [TCP] BoKS Dir Server, Private Port
    #: - [UDP] BoKS Dir Server, Private Port IANA assigned this well-formed service
    #:   name as a replacement for "bdir_priv".
    #: - [UDP] BoKS Dir Server, Private Port
    bdir_priv = 6507, 'bdir-priv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BoKS Dir Server, Public Port IANA assigned this well-formed service
    #:   name as a replacement for "bdir_pub".
    #: - [TCP] BoKS Dir Server, Public Port
    #: - [UDP] BoKS Dir Server, Public Port IANA assigned this well-formed service
    #:   name as a replacement for "bdir_pub".
    #: - [UDP] BoKS Dir Server, Public Port
    bdir_pub = 6508, 'bdir-pub', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MGCS-MFP Port
    #: - [UDP] MGCS-MFP Port
    mgcs_mfp_port = 6509, 'mgcs-mfp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MCER Port
    #: - [UDP] MCER Port
    mcer_port = 6510, 'mcer-port', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Datagram Congestion Control Protocol Encapsulation for NAT Traversal
    #: [:rfc:`6773`]
    dccp_udp = 6511, 'dccp-udp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6513 = 6513, 'reserved', TransportProtocol.udp

    #: - [TCP] Syslog over TLS [:rfc:`5425`]
    #: - [UDP] syslog over DTLS [:rfc:`6012`]
    #: - [DCCP] syslog over DTLS [:rfc:`6012`]
    syslog_tls = 6514, 'syslog-tls', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [TCP] Elipse RPC Protocol
    #: - [UDP] Elipse RPC Protocol
    elipse_rec = 6515, 'elipse-rec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] lds_distrib
    #: - [UDP] lds_distrib
    lds_distrib = 6543, 'lds-distrib', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LDS Dump Service
    #: - [UDP] LDS Dump Service
    lds_dump = 6544, 'lds-dump', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 6547
    #: - [UDP] APC 6547
    apc_6547 = 6547, 'apc-6547', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 6548
    #: - [UDP] APC 6548
    apc_6548 = 6548, 'apc-6548', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 6549
    #: - [UDP] APC 6549
    apc_6549 = 6549, 'apc-6549', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fg-sysupdate
    #: - [UDP] fg-sysupdate
    fg_sysupdate = 6550, 'fg-sysupdate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Software Update Manager
    #: - [UDP] Software Update Manager
    sum = 6551, 'sum', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6556 = 6556, 'reserved', TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    xdsxdm = 6558, 'xdsxdm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SANE Control Port
    #: - [UDP] SANE Control Port
    sane_port = 6566, 'sane-port', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Roaring Penguin IP Address Reputation Collection
    rp_reputation = 6568, 'rp-reputation', TransportProtocol.udp

    #: - [TCP] Affiliate
    #: - [UDP] Affiliate
    affiliate = 6579, 'affiliate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Parsec Masterserver
    #: - [UDP] Parsec Masterserver
    parsec_master = 6580, 'parsec-master', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Parsec Peer-to-Peer
    #: - [UDP] Parsec Peer-to-Peer
    parsec_peer = 6581, 'parsec-peer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Parsec Gameserver
    #: - [UDP] Parsec Gameserver
    parsec_game = 6582, 'parsec-game', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JOA Jewel Suite
    #: - [UDP] JOA Jewel Suite
    joajewelsuite = 6583, 'joajewelsuite', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6600 = 6600, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6601 = 6601, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6602 = 6602, 'reserved', TransportProtocol.udp

    #: - [TCP] Bencher API
    #: - [UDP] Bencher API
    bencher = 6610, 'bencher', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ODETTE-FTP over TLS/SSL [:rfc:`5024`]
    #: - [UDP] ODETTE-FTP over TLS/SSL [:rfc:`5024`]
    odette_ftps = 6619, 'odette-ftps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kerberos V5 FTP Data
    #: - [UDP] Kerberos V5 FTP Data
    kftp_data = 6620, 'kftp-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kerberos V5 FTP Control
    #: - [UDP] Kerberos V5 FTP Control
    kftp = 6621, 'kftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multicast FTP
    #: - [UDP] Multicast FTP
    mcftp = 6622, 'mcftp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kerberos V5 Telnet
    #: - [UDP] Kerberos V5 Telnet
    ktelnet = 6623, 'ktelnet', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6624 = 6624, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6625 = 6625, 'reserved', TransportProtocol.udp

    #: - [TCP] WAGO Service and Update
    #: - [UDP] WAGO Service and Update
    wago_service = 6626, 'wago-service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Allied Electronics NeXGen
    #: - [UDP] Allied Electronics NeXGen
    nexgen = 6627, 'nexgen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AFE Stock Channel M/C
    #: - [UDP] AFE Stock Channel M/C
    afesc_mc = 6628, 'afesc-mc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secondary, (non ANDI) multi-protocol multi-function interface to the
    #:   Allied ANDI-based family of forecourt controllers
    #: - [UDP] Secondary, (non ANDI) multi-protocol multi-function interface to the
    #:   Allied ANDI-based family of forecourt controllers
    nexgen_aux = 6629, 'nexgen-aux', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6632 = 6632, 'reserved', TransportProtocol.udp

    #: [UDP] Cisco vPath Services Overlay
    cisco_vpath_tun = 6633, 'cisco-vpath-tun', TransportProtocol.udp

    #: [UDP] MPLS Performance Measurement out-of-band response
    mpls_pm = 6634, 'mpls-pm', TransportProtocol.udp

    #: [UDP] Encapsulate MPLS packets in UDP tunnels. [:rfc:`7510`]
    mpls_udp = 6635, 'mpls-udp', TransportProtocol.udp

    #: [UDP] Encapsulate MPLS packets in UDP tunnels with DTLS. [:rfc:`7510`]
    mpls_udp_dtls = 6636, 'mpls-udp-dtls', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6640 = 6640, 'reserved', TransportProtocol.udp

    #: - [TCP] OpenFlow
    #: - [UDP] OpenFlow
    openflow = 6653, 'openflow', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6655 = 6655, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6656 = 6656, 'reserved', TransportProtocol.udp

    #: [UDP] PalCom Discovery
    palcom_disc = 6657, 'palcom-disc', TransportProtocol.udp

    #: - [TCP] Vocaltec Global Online Directory
    #: - [UDP] Vocaltec Global Online Directory
    vocaltec_gold = 6670, 'vocaltec-gold', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] P4P Portal Service
    #: - [UDP] P4P Portal Service
    p4p_portal = 6671, 'p4p-portal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vision_server IANA assigned this well-formed service name as a
    #:   replacement for "vision_server".
    #: - [TCP] vision_server
    #: - [UDP] vision_server IANA assigned this well-formed service name as a
    #:   replacement for "vision_server".
    #: - [UDP] vision_server
    vision_server = 6672, 'vision-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] vision_elmd IANA assigned this well-formed service name as a
    #:   replacement for "vision_elmd".
    #: - [TCP] vision_elmd
    #: - [UDP] vision_elmd IANA assigned this well-formed service name as a
    #:   replacement for "vision_elmd".
    #: - [UDP] vision_elmd
    vision_elmd = 6673, 'vision-elmd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Viscount Freedom Bridge Discovery
    vfbp_disc = 6678, 'vfbp-disc', TransportProtocol.udp

    #: - [TCP] Osorno Automation
    #: - [UDP] Osorno Automation
    osaut = 6679, 'osaut', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6687 = 6687, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6688 = 6688, 'reserved', TransportProtocol.udp

    #: - [TCP] Tofino Security Appliance
    #: - [UDP] Tofino Security Appliance
    tsa = 6689, 'tsa', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6690 = 6690, 'reserved', TransportProtocol.udp

    #: [UDP] Babel Routing Protocol [:rfc:`8966`]
    babel = 6696, 'babel', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6697 = 6697, 'reserved', TransportProtocol.udp

    #: [UDP] Babel Routing Protocol over DTLS [:rfc:`8968`]
    babel_dtls = 6699, 'babel-dtls', TransportProtocol.udp

    #: - [TCP] KTI/ICAD Nameserver
    #: - [UDP] KTI/ICAD Nameserver
    kti_icad_srvr = 6701, 'kti-icad-srvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] e-Design network
    #: - [UDP] e-Design network
    e_design_net = 6702, 'e-design-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] e-Design web
    #: - [UDP] e-Design web
    e_design_web = 6703, 'e-design-web', TransportProtocol.tcp | TransportProtocol.udp

    #: - [UDP] Reserved
    #: - [TCP] Reserved
    reserved_6704 = 6704, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [UDP] Reserved
    #: - [TCP] Reserved
    reserved_6705 = 6705, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [UDP] Reserved
    #: - [TCP] Reserved
    reserved_6706 = 6706, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Internet Backplane Protocol
    #: - [UDP] Internet Backplane Protocol
    ibprotocol = 6714, 'ibprotocol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fibotrader Communications
    #: - [UDP] Fibotrader Communications
    fibotrader_com = 6715, 'fibotrader-com', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6716 = 6716, 'reserved', TransportProtocol.udp

    #: - [TCP] BMC PERFORM AGENT
    #: - [UDP] BMC PERFORM AGENT
    bmc_perf_agent = 6767, 'bmc-perf-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BMC PERFORM MGRD
    #: - [UDP] BMC PERFORM MGRD
    bmc_perf_mgrd = 6768, 'bmc-perf-mgrd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ADInstruments GxP Server
    #: - [UDP] ADInstruments GxP Server
    adi_gxp_srvprt = 6769, 'adi-gxp-srvprt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PolyServe http
    #: - [UDP] PolyServe http
    plysrv_http = 6770, 'plysrv-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PolyServe https
    #: - [UDP] PolyServe https
    plysrv_https = 6771, 'plysrv-https', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6777 = 6777, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6778 = 6778, 'reserved', TransportProtocol.udp

    #: [UDP] Bidirectional Forwarding Detection (BFD) on Link Aggregation Group
    #: (LAG) Interfaces [:rfc:`7130`]
    bfd_lag = 6784, 'bfd-lag', TransportProtocol.udp

    #: - [TCP] DGPF Individual Exchange
    #: - [UDP] DGPF Individual Exchange
    dgpf_exchg = 6785, 'dgpf-exchg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun Java Web Console JMX
    #: - [UDP] Sun Java Web Console JMX
    smc_jmx = 6786, 'smc-jmx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun Web Console Admin
    #: - [UDP] Sun Web Console Admin
    smc_admin = 6787, 'smc-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SMC-HTTP
    #: - [UDP] SMC-HTTP
    smc_http = 6788, 'smc-http', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6789 = 6789, 'reserved', TransportProtocol.udp

    #: - [TCP] HNMP
    #: - [UDP] HNMP
    hnmp = 6790, 'hnmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Halcyon Network Manager
    #: - [UDP] Halcyon Network Manager
    hnm = 6791, 'hnm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ACNET Control System Protocol
    #: - [UDP] ACNET Control System Protocol
    acnet = 6801, 'acnet', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6817 = 6817, 'reserved', TransportProtocol.udp

    #: - [TCP] ambit-lm
    #: - [UDP] ambit-lm
    ambit_lm = 6831, 'ambit-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netmo Default
    #: - [UDP] Netmo Default
    netmo_default = 6841, 'netmo-default', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Netmo HTTP
    #: - [UDP] Netmo HTTP
    netmo_http = 6842, 'netmo-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ICCRUSHMORE
    #: - [UDP] ICCRUSHMORE
    iccrushmore = 6850, 'iccrushmore', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Acctopus Status
    acctopus_st = 6868, 'acctopus-st', TransportProtocol.udp

    #: - [TCP] MUSE
    #: - [UDP] MUSE
    muse = 6888, 'muse', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6900 = 6900, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6901 = 6901, 'reserved', TransportProtocol.udp

    #: - [TCP] Ping with RX/TX latency/loss split
    #: - [UDP] Ping with RX/TX latency/loss split
    split_ping = 6924, 'split-ping', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EthoScan Service
    #: - [UDP] EthoScan Service
    ethoscan = 6935, 'ethoscan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XenSource Management Service
    #: - [UDP] XenSource Management Service
    xsmsvc = 6936, 'xsmsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Biometrics Server
    #: - [UDP] Biometrics Server
    bioserver = 6946, 'bioserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OTLP
    #: - [UDP] OTLP
    otlp = 6951, 'otlp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JMACT3
    #: - [UDP] JMACT3
    jmact3 = 6961, 'jmact3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] jmevt2
    #: - [UDP] jmevt2
    jmevt2 = 6962, 'jmevt2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] swismgr1
    #: - [UDP] swismgr1
    swismgr1 = 6963, 'swismgr1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] swismgr2
    #: - [UDP] swismgr2
    swismgr2 = 6964, 'swismgr2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] swistrap
    #: - [UDP] swistrap
    swistrap = 6965, 'swistrap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] swispol
    #: - [UDP] swispol
    swispol = 6966, 'swispol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] acmsoda
    #: - [UDP] acmsoda
    acmsoda = 6969, 'acmsoda', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_6970 = 6970, 'reserved', TransportProtocol.udp

    #: [UDP] QoS-extended OLSR protocol
    qolyester = 6980, 'qolyester', TransportProtocol.udp

    #: - [TCP] Mobility XE Protocol
    #: - [UDP] Mobility XE Protocol
    mobilitysrv = 6997, 'mobilitysrv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IATP-highPri
    #: - [UDP] IATP-highPri
    iatp_highpri = 6998, 'iatp-highpri', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IATP-normalPri
    #: - [UDP] IATP-normalPri
    iatp_normalpri = 6999, 'iatp-normalpri', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] file server itself
    #: - [UDP] file server itself
    afs3_fileserver = 7000, 'afs3-fileserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] callbacks to cache managers
    #: - [UDP] callbacks to cache managers
    afs3_callback = 7001, 'afs3-callback', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] users & groups database
    #: - [UDP] users & groups database
    afs3_prserver = 7002, 'afs3-prserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] volume location database
    #: - [UDP] volume location database
    afs3_vlserver = 7003, 'afs3-vlserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AFS/Kerberos authentication service
    #: - [UDP] AFS/Kerberos authentication service
    afs3_kaserver = 7004, 'afs3-kaserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] volume managment server
    #: - [UDP] volume managment server
    afs3_volser = 7005, 'afs3-volser', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] error interpretation service
    #: - [UDP] error interpretation service
    afs3_errors = 7006, 'afs3-errors', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] basic overseer process
    #: - [UDP] basic overseer process
    afs3_bos = 7007, 'afs3-bos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] server-to-server updater
    #: - [UDP] server-to-server updater
    afs3_update = 7008, 'afs3-update', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] remote cache manager service
    #: - [UDP] remote cache manager service
    afs3_rmtsys = 7009, 'afs3-rmtsys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] onlinet uninterruptable power supplies
    #: - [UDP] onlinet uninterruptable power supplies
    ups_onlinet = 7010, 'ups-onlinet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talon Discovery Port
    #: - [UDP] Talon Discovery Port
    talon_disc = 7011, 'talon-disc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talon Engine
    #: - [UDP] Talon Engine
    talon_engine = 7012, 'talon-engine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microtalon Discovery
    #: - [UDP] Microtalon Discovery
    microtalon_dis = 7013, 'microtalon-dis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microtalon Communications
    #: - [UDP] Microtalon Communications
    microtalon_com = 7014, 'microtalon-com', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Talon Webserver
    #: - [UDP] Talon Webserver
    talon_webserver = 7015, 'talon-webserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SPG Controls Carrier
    #: - [UDP] SPG Controls Carrier
    spg = 7016, 'spg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] GeneRic Autonomic Signaling Protocol [:rfc:`8990`]
    #: - [UDP] GeneRic Autonomic Signaling Protocol [:rfc:`8990`]
    grasp = 7017, 'grasp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7018 = 7018, 'reserved', TransportProtocol.udp

    #: [UDP] doceri drawing service screen view
    doceri_view = 7019, 'doceri-view', TransportProtocol.udp

    #: - [TCP] DP Serve
    #: - [UDP] DP Serve
    dpserve = 7020, 'dpserve', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DP Serve Admin
    #: - [UDP] DP Serve Admin
    dpserveadmin = 7021, 'dpserveadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CT Discovery Protocol
    #: - [UDP] CT Discovery Protocol
    ctdp = 7022, 'ctdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Comtech T2 NMCS
    #: - [UDP] Comtech T2 NMCS
    ct2nmcs = 7023, 'ct2nmcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vormetric service
    #: - [UDP] Vormetric service
    vmsvc = 7024, 'vmsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vormetric Service II
    #: - [UDP] Vormetric Service II
    vmsvc_2 = 7025, 'vmsvc-2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7026 = 7026, 'reserved', TransportProtocol.udp

    #: - [TCP] ObjectPlanet probe
    #: - [UDP] ObjectPlanet probe
    op_probe = 7030, 'op-probe', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7031 = 7031, 'reserved', TransportProtocol.udp

    #: [UDP] Quest application level network service discovery
    quest_disc = 7040, 'quest-disc', TransportProtocol.udp

    #: - [TCP] ARCP
    #: - [UDP] ARCP
    arcp = 7070, 'arcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IWGADTS Aircraft Housekeeping Message
    #: - [UDP] IWGADTS Aircraft Housekeeping Message
    iwg1 = 7071, 'iwg1', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] iba Device Configuration Protocol
    iba_cfg_disc = 7072, 'iba-cfg-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7073 = 7073, 'reserved', TransportProtocol.udp

    #: - [TCP] EmpowerID Communication
    #: - [UDP] EmpowerID Communication
    empowerid = 7080, 'empowerid', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Zixi live video transport protocol
    zixi_transport = 7088, 'zixi-transport', TransportProtocol.udp

    #: [UDP] Java Discovery Protocol
    jdp_disc = 7095, 'jdp-disc', TransportProtocol.udp

    #: - [TCP] lazy-ptop
    #: - [UDP] lazy-ptop
    lazy_ptop = 7099, 'lazy-ptop', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] X Font Service
    #: - [UDP] X Font Service
    font_service = 7100, 'font-service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Embedded Light Control Network
    #: - [UDP] Embedded Light Control Network
    elcn = 7101, 'elcn', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] AES-X170
    aes_x170 = 7107, 'aes-x170', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7117 = 7117, 'reserved', TransportProtocol.udp

    #: - [TCP] Virtual Prototypes License Manager
    #: - [UDP] Virtual Prototypes License Manager
    virprot_lm = 7121, 'virprot-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNIF End-to-End TLS Relay Control Connection [draft-zubov-snif-05,
    #:   Section 4.3]
    #: - [UDP] SNIF End-to-End TLS Relay over QUIC [draft-zubov-snif-05, Section 4.4]
    snif = 7123, 'snif', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] intelligent data manager
    #: - [UDP] intelligent data manager
    scenidm = 7128, 'scenidm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Catalog Content Search
    #: - [UDP] Catalog Content Search
    scenccs = 7129, 'scenccs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA BSM Comm
    #: - [UDP] CA BSM Comm
    cabsm_comm = 7161, 'cabsm-comm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA Storage Manager
    #: - [UDP] CA Storage Manager
    caistoragemgr = 7162, 'caistoragemgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA Connection Broker
    #: - [UDP] CA Connection Broker
    cacsambroker = 7163, 'cacsambroker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] File System Repository Agent
    #: - [UDP] File System Repository Agent
    fsr = 7164, 'fsr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Document WCF Server
    #: - [UDP] Document WCF Server
    doc_server = 7165, 'doc-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aruba eDiscovery Server
    #: - [UDP] Aruba eDiscovery Server
    aruba_server = 7166, 'aruba-server', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7167 = 7167, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7168 = 7168, 'reserved', TransportProtocol.udp

    #: - [TCP] Consequor Consulting Process Integration Bridge
    #: - [UDP] Consequor Consulting Process Integration Bridge
    ccag_pib = 7169, 'ccag-pib', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Adaptive Name/Service Resolution
    #: - [UDP] Adaptive Name/Service Resolution
    nsrp = 7170, 'nsrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Discovery and Retention Mgt Production
    #: - [UDP] Discovery and Retention Mgt Production
    drm_production = 7171, 'drm-production', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7172 = 7172, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7173 = 7173, 'reserved', TransportProtocol.udp

    #: - [TCP] Clutild
    #: - [UDP] Clutild
    clutild = 7174, 'clutild', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Janus Guidewire Enterprise Discovery Service Bus
    janus_disc = 7181, 'janus-disc', TransportProtocol.udp

    #: - [TCP] FODMS FLIP
    #: - [UDP] FODMS FLIP
    fodms = 7200, 'fodms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DLIP
    #: - [UDP] DLIP
    dlip = 7201, 'dlip', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7202 = 7202, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7215 = 7215, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7216 = 7216, 'reserved', TransportProtocol.udp

    #: - [TCP] Registry A & M Protocol
    #: - [UDP] Registry A & M Protocol
    ramp = 7227, 'ramp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7228 = 7228, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7229 = 7229, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7234 = 7234, 'reserved', TransportProtocol.udp

    #: [UDP] ASP Coordination Protocol
    aspcoordination = 7235, 'aspcoordination', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7236 = 7236, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7237 = 7237, 'reserved', TransportProtocol.udp

    #: [UDP] FrontRow Calypso Human Interface Control Protocol
    frc_hicp_disc = 7244, 'frc-hicp-disc', TransportProtocol.udp

    #: - [TCP] Calypso Network Access Protocol
    #: - [UDP] Calypso Network Access Protocol
    cnap = 7262, 'cnap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WatchMe Monitoring 7272
    #: - [UDP] WatchMe Monitoring 7272
    watchme_7272 = 7272, 'watchme-7272', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA Roaming Location
    #: - [UDP] OMA Roaming Location
    oma_rlp = 7273, 'oma-rlp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA Roaming Location SEC
    #: - [UDP] OMA Roaming Location SEC
    oma_rlp_s = 7274, 'oma-rlp-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA UserPlane Location
    #: - [UDP] OMA UserPlane Location
    oma_ulp = 7275, 'oma-ulp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA Internal Location Protocol
    #: - [UDP] OMA Internal Location Protocol
    oma_ilp = 7276, 'oma-ilp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA Internal Location Secure Protocol
    #: - [UDP] OMA Internal Location Secure Protocol
    oma_ilp_s = 7277, 'oma-ilp-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA Dynamic Content Delivery over CBS
    #: - [UDP] OMA Dynamic Content Delivery over CBS
    oma_dcdocbs = 7278, 'oma-dcdocbs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Citrix Licensing
    #: - [UDP] Citrix Licensing
    ctxlic = 7279, 'ctxlic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITACTIONSERVER 1
    #: - [UDP] ITACTIONSERVER 1
    itactionserver1 = 7280, 'itactionserver1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ITACTIONSERVER 2
    #: - [UDP] ITACTIONSERVER 2
    itactionserver2 = 7281, 'itactionserver2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] eventACTION/ussACTION (MZCA) alert
    mzca_alert = 7282, 'mzca-alert', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7283 = 7283, 'reserved', TransportProtocol.udp

    #: - [TCP] LifeKeeper Communications
    #: - [UDP] LifeKeeper Communications
    lcm_server = 7365, 'lcm-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mind-file system server
    #: - [UDP] mind-file system server
    mindfilesys = 7391, 'mindfilesys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mrss-rendezvous server
    #: - [UDP] mrss-rendezvous server
    mrssrendezvous = 7392, 'mrssrendezvous', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] nFoldMan Remote Publish
    #: - [UDP] nFoldMan Remote Publish
    nfoldman = 7393, 'nfoldman', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] File system export of backup images
    #: - [UDP] File system export of backup images
    fse = 7394, 'fse', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] winqedit
    #: - [UDP] winqedit
    winqedit = 7395, 'winqedit', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hexarc Command Language
    #: - [UDP] Hexarc Command Language
    hexarc = 7397, 'hexarc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RTPS Discovery
    #: - [UDP] RTPS Discovery
    rtps_discovery = 7400, 'rtps-discovery', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RTPS Data-Distribution User-Traffic
    #: - [UDP] RTPS Data-Distribution User-Traffic
    rtps_dd_ut = 7401, 'rtps-dd-ut', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RTPS Data-Distribution Meta-Traffic
    #: - [UDP] RTPS Data-Distribution Meta-Traffic
    rtps_dd_mt = 7402, 'rtps-dd-mt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ionix Network Monitor
    #: - [UDP] Ionix Network Monitor
    ionixnetmon = 7410, 'ionixnetmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Streaming of measurement data
    #: - [UDP] Streaming of measurement data
    daqstream = 7411, 'daqstream', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Multichannel real-time lighting control
    ipluminary = 7420, 'ipluminary', TransportProtocol.udp

    #: - [TCP] Matisse Port Monitor
    #: - [UDP] Matisse Port Monitor
    mtportmon = 7421, 'mtportmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView DM Postmaster Manager
    #: - [UDP] OpenView DM Postmaster Manager
    pmdmgr = 7426, 'pmdmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView DM Event Agent Manager
    #: - [UDP] OpenView DM Event Agent Manager
    oveadmgr = 7427, 'oveadmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView DM Log Agent Manager
    #: - [UDP] OpenView DM Log Agent Manager
    ovladmgr = 7428, 'ovladmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView DM rqt communication
    #: - [UDP] OpenView DM rqt communication
    opi_sock = 7429, 'opi-sock', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView DM xmpv7 api pipe
    #: - [UDP] OpenView DM xmpv7 api pipe
    xmpv7 = 7430, 'xmpv7', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView DM ovc/xmpv3 api pipe
    #: - [UDP] OpenView DM ovc/xmpv3 api pipe
    pmd = 7431, 'pmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Faximum
    #: - [UDP] Faximum
    faximum = 7437, 'faximum', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Oracle Application Server HTTPS
    #: - [UDP] Oracle Application Server HTTPS
    oracleas_https = 7443, 'oracleas-https', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7471 = 7471, 'reserved', TransportProtocol.udp

    #: - [TCP] Rise: The Vieneo Province
    #: - [UDP] Rise: The Vieneo Province
    rise = 7473, 'rise', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7474 = 7474, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7478 = 7478, 'reserved', TransportProtocol.udp

    #: - [TCP] telops-lmd
    #: - [UDP] telops-lmd
    telops_lmd = 7491, 'telops-lmd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Silhouette User
    #: - [UDP] Silhouette User
    silhouette = 7500, 'silhouette', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP OpenView Bus Daemon
    #: - [UDP] HP OpenView Bus Daemon
    ovbus = 7501, 'ovbus', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7508 = 7508, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7509 = 7509, 'reserved', TransportProtocol.udp

    #: - [TCP] HP OpenView Application Server
    #: - [UDP] HP OpenView Application Server
    ovhpas = 7510, 'ovhpas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] pafec-lm
    #: - [UDP] pafec-lm
    pafec_lm = 7511, 'pafec-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Saratoga Transfer Protocol
    #: - [UDP] Saratoga Transfer Protocol
    saratoga = 7542, 'saratoga', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] atul server
    #: - [UDP] atul server
    atul = 7543, 'atul', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FlowAnalyzer DisplayServer
    #: - [UDP] FlowAnalyzer DisplayServer
    nta_ds = 7544, 'nta-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FlowAnalyzer UtilityServer
    #: - [UDP] FlowAnalyzer UtilityServer
    nta_us = 7545, 'nta-us', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cisco Fabric service
    #: - [UDP] Cisco Fabric service
    cfs = 7546, 'cfs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Broadband Forum CWMP
    #: - [UDP] Broadband Forum CWMP
    cwmp = 7547, 'cwmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Threat Information Distribution Protocol
    #: - [UDP] Threat Information Distribution Protocol
    tidp = 7548, 'tidp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Layer Signaling Transport Layer
    #: - [UDP] Network Layer Signaling Transport Layer
    nls_tl = 7549, 'nls-tl', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Cloud Signaling Service
    cloudsignaling = 7550, 'cloudsignaling', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7551 = 7551, 'reserved', TransportProtocol.udp

    #: - [TCP] Sniffer Command Protocol
    #: - [UDP] Sniffer Command Protocol
    sncp = 7560, 'sncp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7563 = 7563, 'reserved', TransportProtocol.udp

    #: - [TCP] VSI Omega
    #: - [UDP] VSI Omega
    vsi_omega = 7566, 'vsi-omega', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7569 = 7569, 'reserved', TransportProtocol.udp

    #: - [TCP] Aries Kfinder
    #: - [UDP] Aries Kfinder
    aries_kfinder = 7570, 'aries-kfinder', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Oracle Coherence Cluster discovery service
    coherence_disc = 7574, 'coherence-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7575 = 7575, 'reserved', TransportProtocol.udp

    #: - [TCP] Sun License Manager
    #: - [UDP] Sun License Manager
    sun_lm = 7588, 'sun-lm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MIPI Alliance Debug
    #: - [UDP] MIPI Alliance Debug
    mipi_debug = 7606, 'mipi-debug', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Instrument Neutral Distributed Interface
    #: - [UDP] Instrument Neutral Distributed Interface
    indi = 7624, 'indi', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] De-registered
    de_registered_7626 = 7626, 'de_registered', TransportProtocol.udp

    #: - [TCP] SOAP Service Port
    #: - [UDP] SOAP Service Port
    soap_http = 7627, 'soap-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Primary Agent Work Notification
    #: - [UDP] Primary Agent Work Notification
    zen_pawn = 7628, 'zen-pawn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenXDAS Wire Protocol
    #: - [UDP] OpenXDAS Wire Protocol
    xdas = 7629, 'xdas', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7630 = 7630, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7631 = 7631, 'reserved', TransportProtocol.udp

    #: - [TCP] PMDF Management
    #: - [UDP] PMDF Management
    pmdfmgt = 7633, 'pmdfmgt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] bonjour-cuseeme
    #: - [UDP] bonjour-cuseeme
    cuseeme = 7648, 'cuseeme', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Proprietary immutable distributed data storage
    #: - [UDP] Proprietary immutable distributed data storage
    rome = 7663, 'rome', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7668 = 7668, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7672 = 7672, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7673 = 7673, 'reserved', TransportProtocol.udp

    #: - [TCP] iMQ SSL tunnel
    #: - [UDP] iMQ SSL tunnel
    imqtunnels = 7674, 'imqtunnels', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iMQ Tunnel
    #: - [UDP] iMQ Tunnel
    imqtunnel = 7675, 'imqtunnel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iMQ Broker Rendezvous
    #: - [UDP] iMQ Broker Rendezvous
    imqbrokerd = 7676, 'imqbrokerd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun App Server - HTTPS
    #: - [UDP] Sun App Server - HTTPS
    sun_user_https = 7677, 'sun-user-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Microsoft Delivery Optimization Peer-to-Peer
    #: - [UDP] Microsoft Delivery Optimization Peer-to-Peer
    ms_do = 7680, 'ms-do', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7683 = 7683, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7687 = 7687, 'reserved', TransportProtocol.udp

    #: - [TCP] Collaber Network Service
    #: - [UDP] Collaber Network Service
    collaber = 7689, 'collaber', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7690 = 7690, 'reserved', TransportProtocol.udp

    #: - [TCP] KLIO communications
    #: - [UDP] KLIO communications
    klio = 7697, 'klio', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7700 = 7700, 'reserved', TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_7701 = 7701, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EM7 Dynamic Updates
    #: - [UDP] EM7 Dynamic Updates
    sync_em7 = 7707, 'sync-em7', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] scientia.net
    #: - [UDP] scientia.net
    scinet = 7708, 'scinet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MedImage Portal
    #: - [UDP] MedImage Portal
    medimageportal = 7720, 'medimageportal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novell Snap-in Deep Freeze Control
    #: - [UDP] Novell Snap-in Deep Freeze Control
    nsdeepfreezectl = 7724, 'nsdeepfreezectl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nitrogen Service
    #: - [UDP] Nitrogen Service
    nitrogen = 7725, 'nitrogen', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FreezeX Console Service
    #: - [UDP] FreezeX Console Service
    freezexservice = 7726, 'freezexservice', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trident Systems Data
    #: - [UDP] Trident Systems Data
    trident_data = 7727, 'trident-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Open-Source Virtual Reality
    #: - [UDP] Open-Source Virtual Reality
    #: - [SCTP] Open-Source Virtual Reality
    osvr = 7728, 'osvr', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Smith Protocol over IP
    #: - [UDP] Smith Protocol over IP
    smip = 7734, 'smip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP Enterprise Discovery Agent
    #: - [UDP] HP Enterprise Discovery Agent
    aiagent = 7738, 'aiagent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ScriptView Network
    #: - [UDP] ScriptView Network
    scriptview = 7741, 'scriptview', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7742 = 7742, 'reserved', TransportProtocol.udp

    #: - [TCP] Sakura Script Transfer Protocol
    #: - [UDP] Sakura Script Transfer Protocol
    sstp_1 = 7743, 'sstp-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RAQMON PDU [:rfc:`4712`]
    #: - [UDP] RAQMON PDU [:rfc:`4712`]
    raqmon_pdu = 7744, 'raqmon-pdu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Put/Run/Get Protocol
    #: - [UDP] Put/Run/Get Protocol
    prgp = 7747, 'prgp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7775 = 7775, 'reserved', TransportProtocol.udp

    #: - [TCP] cbt
    #: - [UDP] cbt
    cbt = 7777, 'cbt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Interwise
    #: - [UDP] Interwise
    interwise = 7778, 'interwise', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VSTAT
    #: - [UDP] VSTAT
    vstat = 7779, 'vstat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] accu-lmgr
    #: - [UDP] accu-lmgr
    accu_lmgr = 7781, 'accu-lmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Seamless Bidirectional Forwarding Detection (S-BFD) [:rfc:`7881`]
    s_bfd = 7784, 's-bfd', TransportProtocol.udp

    #: - [TCP] MINIVEND
    #: - [UDP] MINIVEND
    minivend = 7786, 'minivend', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Popup Reminders Receive
    #: - [UDP] Popup Reminders Receive
    popup_reminders = 7787, 'popup-reminders', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Office Tools Pro Receive
    #: - [UDP] Office Tools Pro Receive
    office_tools = 7789, 'office-tools', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Q3ADE Cluster Service
    #: - [UDP] Q3ADE Cluster Service
    q3ade = 7794, 'q3ade', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Propel Connector port
    #: - [UDP] Propel Connector port
    pnet_conn = 7797, 'pnet-conn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Propel Encoder port
    #: - [UDP] Propel Encoder port
    pnet_enc = 7798, 'pnet-enc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Alternate BSDP Service
    #: - [UDP] Alternate BSDP Service
    altbsdp = 7799, 'altbsdp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apple Software Restore
    #: - [UDP] Apple Software Restore
    asr = 7800, 'asr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Server Protocol - client
    #: - [UDP] Secure Server Protocol - client
    ssp_client = 7801, 'ssp-client', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Virtualized Network Services Tunnel Protocol
    vns_tp = 7802, 'vns-tp', TransportProtocol.udp

    #: - [TCP] Riverbed WAN Optimization Protocol
    #: - [UDP] Riverbed WAN Optimization Protocol
    rbt_wanopt = 7810, 'rbt-wanopt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 7845
    #: - [UDP] APC 7845
    apc_7845 = 7845, 'apc-7845', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 7846
    #: - [UDP] APC 7846
    apc_7846 = 7846, 'apc-7846', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7847 = 7847, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7869 = 7869, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7870 = 7870, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7871 = 7871, 'reserved', TransportProtocol.udp

    #: [UDP] TLS-based Mobile IPv6 Security [:rfc:`6618`]
    mipv6tls = 7872, 'mipv6tls', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7878 = 7878, 'reserved', TransportProtocol.udp

    #: - [TCP] Pearson
    #: - [UDP] Pearson
    pss = 7880, 'pss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Universal Broker
    #: - [UDP] Universal Broker
    ubroker = 7887, 'ubroker', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multicast Event
    #: - [UDP] Multicast Event
    mevent = 7900, 'mevent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TNOS Service Protocol
    #: - [UDP] TNOS Service Protocol
    tnos_sp = 7901, 'tnos-sp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TNOS shell Protocol
    #: - [UDP] TNOS shell Protocol
    tnos_dp = 7902, 'tnos-dp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TNOS Secure DiaguardProtocol
    #: - [UDP] TNOS Secure DiaguardProtocol
    tnos_dps = 7903, 'tnos-dps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QuickObjects secure port
    #: - [UDP] QuickObjects secure port
    qo_secure = 7913, 'qo-secure', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tier 2 Data Resource Manager
    #: - [UDP] Tier 2 Data Resource Manager
    t2_drm = 7932, 't2-drm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tier 2 Business Rules Manager
    #: - [UDP] Tier 2 Business Rules Manager
    t2_brm = 7933, 't2-brm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Encrypted, extendable, general-purpose synchronization protocol
    #: - [UDP] Encrypted, extendable, general-purpose synchronization protocol
    generalsync = 7962, 'generalsync', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Supercell
    #: - [UDP] Supercell
    supercell = 7967, 'supercell', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Micromuse-ncps
    #: - [UDP] Micromuse-ncps
    micromuse_ncps = 7979, 'micromuse-ncps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Quest Vista
    #: - [UDP] Quest Vista
    quest_vista = 7980, 'quest-vista', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7981 = 7981, 'reserved', TransportProtocol.udp

    #: [UDP] Spotlight on SQL Server Desktop Agent Discovery
    sossd_disc = 7982, 'sossd-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_7997 = 7997, 'reserved', TransportProtocol.udp

    #: [UDP] USI Content Push Service
    usicontentpush = 7998, 'usicontentpush', TransportProtocol.udp

    #: - [TCP] iRDMI2
    #: - [UDP] iRDMI2
    irdmi2 = 7999, 'irdmi2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iRDMI
    #: - [UDP] iRDMI
    irdmi = 8000, 'irdmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VCOM Tunnel
    #: - [UDP] VCOM Tunnel
    vcom_tunnel = 8001, 'vcom-tunnel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Teradata ORDBMS
    #: - [UDP] Teradata ORDBMS
    teradataordbms = 8002, 'teradataordbms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mulberry Connect Reporting Service
    #: - [UDP] Mulberry Connect Reporting Service
    mcreport = 8003, 'mcreport', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8004 = 8004, 'reserved', TransportProtocol.udp

    #: - [TCP] MXI Generation II for z/OS
    #: - [UDP] MXI Generation II for z/OS
    mxi = 8005, 'mxi', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] World Programming analytics discovery
    wpl_disc = 8006, 'wpl-disc', TransportProtocol.udp

    #: - [TCP] I/O oriented cluster computing software
    #: - [UDP] I/O oriented cluster computing software
    warppipe = 8007, 'warppipe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileMaker, Inc. - HTTP Alternate (see Port 80)
    #: - [UDP] FileMaker, Inc. - HTTP Alternate (see Port 80)
    http_alt_591 = 591, 'http-alt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HTTP Alternate
    #: - [UDP] HTTP Alternate
    http_alt_8008 = 8008, 'http-alt', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8009 = 8009, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8015 = 8015, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8016 = 8016, 'reserved', TransportProtocol.udp

    #: [UDP] Cisco Cloudsec Dataplane Port Number
    cisco_cloudsec = 8017, 'cisco-cloudsec', TransportProtocol.udp

    #: - [TCP] QB DB Dynamic Port
    #: - [UDP] QB DB Dynamic Port
    qbdb = 8019, 'qbdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intuit Entitlement Service and Discovery
    #: - [UDP] Intuit Entitlement Service and Discovery
    intu_ec_svcdisc = 8020, 'intu-ec-svcdisc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intuit Entitlement Client
    #: - [UDP] Intuit Entitlement Client
    intu_ec_client = 8021, 'intu-ec-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] oa-system
    #: - [UDP] oa-system
    oa_system = 8022, 'oa-system', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARCATrust vault API
    #: - [UDP] ARCATrust vault API
    arca_api = 8023, 'arca-api', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA Audit Distribution Agent
    #: - [UDP] CA Audit Distribution Agent
    ca_audit_da = 8025, 'ca-audit-da', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA Audit Distribution Server
    #: - [UDP] CA Audit Distribution Server
    ca_audit_ds = 8026, 'ca-audit-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] peer tracker and data relay service
    #: - [UDP] peer tracker and data relay service
    papachi_p2p_srv = 8027, 'papachi-p2p-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ProEd
    #: - [UDP] ProEd
    pro_ed = 8032, 'pro-ed', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MindPrint
    #: - [UDP] MindPrint
    mindprint = 8033, 'mindprint', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] .vantronix Management
    #: - [UDP] .vantronix Management
    vantronix_mgmt = 8034, 'vantronix-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ampify Messaging Protocol
    #: - [UDP] Ampify Messaging Protocol
    ampify = 8040, 'ampify', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xcorpeon ASIC Carrier Ethernet Transport
    #: - [UDP] Xcorpeon ASIC Carrier Ethernet Transport
    enguity_xccetp = 8041, 'enguity-xccetp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8042 = 8042, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8043 = 8043, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8044 = 8044, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8051 = 8051, 'reserved', TransportProtocol.udp

    #: - [TCP] Senomix Timesheets Server
    #: - [UDP] Senomix Timesheets Server
    senomix01 = 8052, 'senomix01', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Senomix Timesheets Client [1 year assignment]
    #: - [UDP] Senomix Timesheets Client [1 year assignment]
    senomix02 = 8053, 'senomix02', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Senomix Timesheets Server [1 year assignment]
    #: - [UDP] Senomix Timesheets Server [1 year assignment]
    senomix03 = 8054, 'senomix03', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Senomix Timesheets Server [1 year assignment]
    #: - [UDP] Senomix Timesheets Server [1 year assignment]
    senomix04 = 8055, 'senomix04', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Senomix Timesheets Server [1 year assignment]
    #: - [UDP] Senomix Timesheets Server [1 year assignment]
    senomix05 = 8056, 'senomix05', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Senomix Timesheets Client [1 year assignment]
    #: - [UDP] Senomix Timesheets Client [1 year assignment]
    senomix06 = 8057, 'senomix06', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Senomix Timesheets Client [1 year assignment]
    #: - [UDP] Senomix Timesheets Client [1 year assignment]
    senomix07 = 8058, 'senomix07', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Senomix Timesheets Client [1 year assignment]
    #: - [UDP] Senomix Timesheets Client [1 year assignment]
    senomix08 = 8059, 'senomix08', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Asymmetric Extended Route Optimization (AERO) [:rfc:`6706`]
    aero = 8060, 'aero', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8061 = 8061, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8066 = 8066, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8067 = 8067, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8070 = 8070, 'reserved', TransportProtocol.udp

    #: - [TCP] Gadu-Gadu
    #: - [UDP] Gadu-Gadu
    gadugadu = 8074, 'gadugadu', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_8077 = 8077, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HTTP Alternate (see port 80)
    #: - [UDP] HTTP Alternate (see port 80)
    http_alt = 8080, 'http-alt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun Proxy Admin Service
    #: - [UDP] Sun Proxy Admin Service
    sunproxyadmin = 8081, 'sunproxyadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Utilistor (Client)
    #: - [UDP] Utilistor (Client)
    us_cli = 8082, 'us-cli', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Utilistor (Server)
    #: - [UDP] Utilistor (Server)
    us_srv = 8083, 'us-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8084 = 8084, 'reserved', TransportProtocol.udp

    #: - [TCP] Distributed SCADA Networking Rendezvous Port
    #: - [UDP] Distributed SCADA Networking Rendezvous Port
    d_s_n = 8086, 'd-s-n', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simplify Media SPP Protocol
    #: - [UDP] Simplify Media SPP Protocol
    simplifymedia = 8087, 'simplifymedia', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Radan HTTP
    #: - [UDP] Radan HTTP
    radan_http = 8088, 'radan-http', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8090 = 8090, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8091 = 8091, 'reserved', TransportProtocol.udp

    #: - [TCP] SAC Port Id
    #: - [UDP] SAC Port Id
    sac = 8097, 'sac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xprint Server
    #: - [UDP] Xprint Server
    xprint_server = 8100, 'xprint-server', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8101 = 8101, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8102 = 8102, 'reserved', TransportProtocol.udp

    #: [UDP] Skynetflow network services
    skynetflow = 8111, 'skynetflow', TransportProtocol.udp

    #: - [TCP] MTL8000 Matrix
    #: - [UDP] MTL8000 Matrix
    mtl8000_matrix = 8115, 'mtl8000-matrix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Check Point Clustering
    #: - [UDP] Check Point Clustering
    cp_cluster = 8116, 'cp-cluster', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8117 = 8117, 'reserved', TransportProtocol.udp

    #: - [TCP] Privoxy HTTP proxy
    #: - [UDP] Privoxy HTTP proxy
    privoxy = 8118, 'privoxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apollo Data Port
    #: - [UDP] Apollo Data Port
    apollo_data = 8121, 'apollo-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Apollo Admin Port
    #: - [UDP] Apollo Admin Port
    apollo_admin = 8122, 'apollo-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PayCash Online Protocol
    #: - [UDP] PayCash Online Protocol
    paycash_online = 8128, 'paycash-online', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PayCash Wallet-Browser
    #: - [UDP] PayCash Wallet-Browser
    paycash_wbp = 8129, 'paycash-wbp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INDIGO-VRMI
    #: - [UDP] INDIGO-VRMI
    indigo_vrmi = 8130, 'indigo-vrmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INDIGO-VBCP
    #: - [UDP] INDIGO-VBCP
    indigo_vbcp = 8131, 'indigo-vbcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] dbabble
    #: - [UDP] dbabble
    dbabble = 8132, 'dbabble', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8140 = 8140, 'reserved', TransportProtocol.udp

    #: - [TCP] i-SDD file transfer
    #: - [UDP] i-SDD file transfer
    isdd = 8148, 'isdd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Edge of Reality game data
    eor_game = 8149, 'eor-game', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8153 = 8153, 'reserved', TransportProtocol.udp

    #: - [TCP] Patrol
    #: - [UDP] Patrol
    patrol = 8160, 'patrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Patrol SNMP
    #: - [UDP] Patrol SNMP
    patrol_snmp = 8161, 'patrol-snmp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8162 = 8162, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8181 = 8181, 'reserved', TransportProtocol.udp

    #: - [TCP] VMware Fault Domain Manager
    #: - [UDP] VMware Fault Domain Manager
    vmware_fdm = 8182, 'vmware-fdm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8183 = 8183, 'reserved', TransportProtocol.udp

    #: - [TCP] Remote iTach Connection
    #: - [UDP] Remote iTach Connection
    itach = 8184, 'itach', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8190 = 8190, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8191 = 8191, 'reserved', TransportProtocol.udp

    #: - [TCP] SpyTech Phone Service
    #: - [UDP] SpyTech Phone Service
    spytechphone = 8192, 'spytechphone', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bloomberg data API
    #: - [UDP] Bloomberg data API
    blp1 = 8194, 'blp1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bloomberg feed
    #: - [UDP] Bloomberg feed
    blp2 = 8195, 'blp2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VVR DATA
    #: - [UDP] VVR DATA
    vvr_data = 8199, 'vvr-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRIVNET
    #: - [UDP] TRIVNET
    trivnet1 = 8200, 'trivnet1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TRIVNET
    #: - [UDP] TRIVNET
    trivnet2 = 8201, 'trivnet2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Audio+Ethernet Standard Open Protocol
    aesop = 8202, 'aesop', TransportProtocol.udp

    #: - [TCP] LM Perfworks
    #: - [UDP] LM Perfworks
    lm_perfworks = 8204, 'lm-perfworks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LM Instmgr
    #: - [UDP] LM Instmgr
    lm_instmgr = 8205, 'lm-instmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LM Dta
    #: - [UDP] LM Dta
    lm_dta = 8206, 'lm-dta', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LM SServer
    #: - [UDP] LM SServer
    lm_sserver = 8207, 'lm-sserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LM Webwatcher
    #: - [UDP] LM Webwatcher
    lm_webwatcher = 8208, 'lm-webwatcher', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Aruba Networks AP management
    aruba_papi = 8211, 'aruba-papi', TransportProtocol.udp

    #: - [TCP] RexecJ Server
    #: - [UDP] RexecJ Server
    rexecj = 8230, 'rexecj', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] HNCP [:rfc:`7788`]
    hncp_udp_port = 8231, 'hncp-udp-port', TransportProtocol.udp

    #: [UDP] HNCP over DTLS [:rfc:`7788`]
    hncp_dtls_port = 8232, 'hncp-dtls-port', TransportProtocol.udp

    #: - [TCP] Synapse Non Blocking HTTPS
    #: - [UDP] Synapse Non Blocking HTTPS
    synapse_nhttps = 8243, 'synapse-nhttps', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] ESPeasy peer-2-peer communication
    espeasy_p2p = 8266, 'espeasy-p2p', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8270 = 8270, 'reserved', TransportProtocol.udp

    #: - [TCP] Microsoft Connected Cache
    #: - [UDP] Microsoft Connected Cache
    ms_mcc = 8276, 'ms-mcc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Synapse Non Blocking HTTP
    #: - [UDP] Synapse Non Blocking HTTP
    synapse_nhttp = 8280, 'synapse-nhttp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Libelle EnterpriseBus discovery
    libelle_disc = 8282, 'libelle-disc', TransportProtocol.udp

    #: - [TCP] Bloomberg professional
    #: - [UDP] Bloomberg professional
    blp3 = 8292, 'blp3', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8293 = 8293, 'reserved', TransportProtocol.udp

    #: - [TCP] Bloomberg intelligent client
    #: - [UDP] Bloomberg intelligent client
    blp4 = 8294, 'blp4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Transport Management Interface
    #: - [UDP] Transport Management Interface
    tmi = 8300, 'tmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Amberon PPC/PPS
    #: - [UDP] Amberon PPC/PPS
    amberon = 8301, 'amberon', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8313 = 8313, 'reserved', TransportProtocol.udp

    #: - [TCP] Thin(ium) Network Protocol
    #: - [UDP] Thin(ium) Network Protocol
    tnp_discover = 8320, 'tnp-discover', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Thin(ium) Network Protocol
    #: - [UDP] Thin(ium) Network Protocol
    tnp = 8321, 'tnp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Garmin Marine
    #: - [UDP] Garmin Marine
    garmin_marine = 8322, 'garmin-marine', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Server Find
    #: - [UDP] Server Find
    server_find = 8351, 'server-find', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cruise ENUM
    #: - [UDP] Cruise ENUM
    cruise_enum = 8376, 'cruise-enum', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cruise SWROUTE
    #: - [UDP] Cruise SWROUTE
    cruise_swroute = 8377, 'cruise-swroute', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cruise CONFIG
    #: - [UDP] Cruise CONFIG
    cruise_config = 8378, 'cruise-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cruise DIAGS
    #: - [UDP] Cruise DIAGS
    cruise_diags = 8379, 'cruise-diags', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cruise UPDATE
    #: - [UDP] Cruise UPDATE
    cruise_update = 8380, 'cruise-update', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] M2m Services
    #: - [UDP] M2m Services
    m2mservices = 8383, 'm2mservices', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Marathon Transport Protocol
    marathontp = 8384, 'marathontp', TransportProtocol.udp

    #: - [TCP] cvd
    #: - [UDP] cvd
    cvd = 8400, 'cvd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sabarsd
    #: - [UDP] sabarsd
    sabarsd = 8401, 'sabarsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] abarsd
    #: - [UDP] abarsd
    abarsd = 8402, 'abarsd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] admind
    #: - [UDP] admind
    admind_3279 = 3279, 'admind', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] admind
    #: - [UDP] admind
    admind_8403 = 8403, 'admind', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8404 = 8404, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8405 = 8405, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8415 = 8415, 'reserved', TransportProtocol.udp

    #: - [TCP] eSpeech Session Protocol
    #: - [UDP] eSpeech Session Protocol
    espeech = 8416, 'espeech', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eSpeech RTP Protocol
    #: - [UDP] eSpeech RTP Protocol
    espeech_rtp = 8417, 'espeech-rtp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8423 = 8423, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8432 = 8432, 'reserved', TransportProtocol.udp

    #: [UDP] Non Persistent Desktop and Application Streaming
    aws_as2 = 8433, 'aws-as2', TransportProtocol.udp

    #: - [TCP] CyBro A-bus Protocol
    #: - [UDP] CyBro A-bus Protocol
    cybro_a_bus = 8442, 'cybro-a-bus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCsync HTTPS
    #: - [UDP] PCsync HTTPS
    pcsync_https = 8443, 'pcsync-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCsync HTTP
    #: - [UDP] PCsync HTTP
    pcsync_http = 8444, 'pcsync-http', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Port for copy discovery
    copy_disc = 8445, 'copy-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8448 = 8448, 'reserved', TransportProtocol.udp

    #: - [TCP] npmp
    #: - [UDP] npmp
    npmp = 8450, 'npmp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8457 = 8457, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8470 = 8470, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8471 = 8471, 'reserved', TransportProtocol.udp

    #: - [TCP] Overlay Transport Virtualization (OTV)
    #: - [UDP] Overlay Transport Virtualization (OTV)
    otv = 8472, 'otv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Point to Point
    #: - [UDP] Virtual Point to Point
    vp2p = 8473, 'vp2p', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AquaMinds NoteShare
    #: - [UDP] AquaMinds NoteShare
    noteshare = 8474, 'noteshare', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Flight Message Transfer Protocol
    #: - [UDP] Flight Message Transfer Protocol
    fmtp = 8500, 'fmtp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] CYTEL Message Transfer Audio and Video
    cmtp_av = 8501, 'cmtp-av', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8502 = 8502, 'reserved', TransportProtocol.udp

    #: [UDP] MPLS LSP Self-Ping [:rfc:`7746`]
    lsp_self_ping = 8503, 'lsp-self-ping', TransportProtocol.udp

    #: - [TCP] RTSP Alternate (see port 554)
    #: - [UDP] RTSP Alternate (see port 554)
    rtsp_alt = 8554, 'rtsp-alt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SYMAX D-FENCE
    #: - [UDP] SYMAX D-FENCE
    d_fence = 8555, 'd-fence', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DOF Tunneling Protocol
    #: - [UDP] DOF Tunneling Protocol
    dof_tunnel = 8567, 'dof-tunnel', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Surveillance Data
    #: - [UDP] Surveillance Data
    asterix = 8600, 'asterix', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Canon Compact Printer Protocol Discovery
    canon_cpp_disc = 8609, 'canon-cpp-disc', TransportProtocol.udp

    #: - [TCP] Canon MFNP Service
    #: - [UDP] Canon MFNP Service
    canon_mfnp = 8610, 'canon-mfnp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Canon BJNP Port 1
    #: - [UDP] Canon BJNP Port 1
    canon_bjnp1 = 8611, 'canon-bjnp1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Canon BJNP Port 2
    #: - [UDP] Canon BJNP Port 2
    canon_bjnp2 = 8612, 'canon-bjnp2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Canon BJNP Port 3
    #: - [UDP] Canon BJNP Port 3
    canon_bjnp3 = 8613, 'canon-bjnp3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Canon BJNP Port 4
    #: - [UDP] Canon BJNP Port 4
    canon_bjnp4 = 8614, 'canon-bjnp4', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8615 = 8615, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8665 = 8665, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8666 = 8666, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8668 = 8668, 'reserved', TransportProtocol.udp

    #: [UDP] Motorola Solutions Customer Programming Software for Radio Management
    #: Discovery
    msi_cps_rm_disc = 8675, 'msi-cps-rm-disc', TransportProtocol.udp

    #: - [TCP] Sun App Server - JMX/RMI
    #: - [UDP] Sun App Server - JMX/RMI
    sun_as_jmxrmi = 8686, 'sun-as-jmxrmi', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8688 = 8688, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8699 = 8699, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8710 = 8710, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8711 = 8711, 'reserved', TransportProtocol.udp

    #: [UDP] DASGIP Net Services
    dtp_net = 8732, 'dtp-net', TransportProtocol.udp

    #: - [TCP] iBus
    #: - [UDP] iBus
    ibus = 8733, 'ibus', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8750 = 8750, 'reserved', TransportProtocol.udp

    #: - [TCP] MC-APPSERVER
    #: - [UDP] MC-APPSERVER
    mc_appserver = 8763, 'mc-appserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPENQUEUE
    #: - [UDP] OPENQUEUE
    openqueue = 8764, 'openqueue', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ultraseek HTTP
    #: - [UDP] Ultraseek HTTP
    ultraseek_http = 8765, 'ultraseek-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Agilent Connectivity Service
    #: - [UDP] Agilent Connectivity Service
    amcs = 8766, 'amcs', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8767 = 8767, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8768 = 8768, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8769 = 8769, 'reserved', TransportProtocol.udp

    #: - [TCP] Digital Photo Access Protocol (iPhoto)
    #: - [UDP] Digital Photo Access Protocol (iPhoto)
    dpap = 8770, 'dpap', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8778 = 8778, 'reserved', TransportProtocol.udp

    #: - [TCP] Message Client
    #: - [UDP] Message Client
    msgclnt = 8786, 'msgclnt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message Server
    #: - [UDP] Message Server
    msgsrvr = 8787, 'msgsrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Accedian Performance Measurement
    #: - [UDP] Accedian Performance Measurement
    acd_pm = 8793, 'acd-pm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun Web Server Admin Service
    #: - [UDP] Sun Web Server Admin Service
    sunwebadmin = 8800, 'sunwebadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] truecm
    #: - [UDP] truecm
    truecm = 8804, 'truecm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Destination Port number for PFCP
    pfcp = 8805, 'pfcp', TransportProtocol.udp

    #: [UDP] HES-CLIP Interoperability protocol
    hes_clip = 8807, 'hes-clip', TransportProtocol.udp

    #: [UDP] STATSports Broadcast Service
    ssports_bcast = 8808, 'ssports-bcast', TransportProtocol.udp

    #: [UDP] MCPTT Off-Network Protocol (MONP) [3GPP TS 24.379 v13.5.0s]
    UDP_3gpp_monp = 8809, '3gpp-monp', TransportProtocol.udp

    #: - [TCP] dxspider linking protocol
    #: - [UDP] dxspider linking protocol
    dxspider = 8873, 'dxspider', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CDDBP
    #: - [UDP] CDDBP
    cddbp_alt = 8880, 'cddbp-alt', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8881 = 8881, 'reserved', TransportProtocol.udp

    #: - [TCP] Secure MQTT
    #: - [UDP] Secure MQTT
    secure_mqtt = 8883, 'secure-mqtt', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] NewsEDGE server UDP (UDP 1)
    ddi_udp_1 = 8888, 'ddi-udp-1', TransportProtocol.udp

    #: [UDP] NewsEDGE server broadcast
    ddi_udp_2 = 8889, 'ddi-udp-2', TransportProtocol.udp

    #: [UDP] NewsEDGE client broadcast
    ddi_udp_3 = 8890, 'ddi-udp-3', TransportProtocol.udp

    #: [UDP] Desktop Data UDP 3: NESS application
    ddi_udp_4 = 8891, 'ddi-udp-4', TransportProtocol.udp

    #: [UDP] Desktop Data UDP 4: FARM product
    ddi_udp_5 = 8892, 'ddi-udp-5', TransportProtocol.udp

    #: [UDP] Desktop Data UDP 5: NewsEDGE/Web application
    ddi_udp_6 = 8893, 'ddi-udp-6', TransportProtocol.udp

    #: [UDP] Desktop Data UDP 6: COAL application
    ddi_udp_7 = 8894, 'ddi-udp-7', TransportProtocol.udp

    #: - [TCP] ospf-lite
    #: - [UDP] ospf-lite
    ospf_lite = 8899, 'ospf-lite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JMB-CDS 1
    #: - [UDP] JMB-CDS 1
    jmb_cds1 = 8900, 'jmb-cds1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JMB-CDS 2
    #: - [UDP] JMB-CDS 2
    jmb_cds2 = 8901, 'jmb-cds2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8908 = 8908, 'reserved', TransportProtocol.udp

    #: - [TCP] manyone-http
    #: - [UDP] manyone-http
    manyone_http = 8910, 'manyone-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] manyone-xml
    #: - [UDP] manyone-xml
    manyone_xml = 8911, 'manyone-xml', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Windows Client Backup
    #: - [UDP] Windows Client Backup
    wcbackup = 8912, 'wcbackup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Dragonfly System Service
    #: - [UDP] Dragonfly System Service
    dragonfly = 8913, 'dragonfly', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8937 = 8937, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8953 = 8953, 'reserved', TransportProtocol.udp

    #: - [TCP] Cumulus Admin Port
    #: - [UDP] Cumulus Admin Port
    cumulus_admin = 8954, 'cumulus-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network of Devices Provider
    #: - [UDP] Network of Devices Provider
    nod_provider = 8980, 'nod-provider', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Network of Devices Client
    nod_client = 8981, 'nod-client', TransportProtocol.udp

    #: - [TCP] Sun Web Server SSL Admin Service
    #: - [UDP] Sun Web Server SSL Admin Service
    sunwebadmins = 8989, 'sunwebadmins', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] webmail HTTP service
    #: - [UDP] webmail HTTP service
    http_wmap = 8990, 'http-wmap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] webmail HTTPS service
    #: - [UDP] webmail HTTPS service
    https_wmap = 8991, 'https-wmap', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8997 = 8997, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_8998 = 8998, 'reserved', TransportProtocol.udp

    #: - [TCP] Brodos Crypto Trade Protocol
    #: - [UDP] Brodos Crypto Trade Protocol
    bctp = 8999, 'bctp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSlistener
    #: - [UDP] CSlistener
    cslistener = 9000, 'cslistener', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ETL Service Manager
    #: - [UDP] ETL Service Manager
    etlservicemgr = 9001, 'etlservicemgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DynamID authentication
    #: - [UDP] DynamID authentication
    dynamid = 9002, 'dynamid', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9005 = 9005, 'reserved', TransportProtocol.udp

    #: [UDP] Open Grid Services Client
    ogs_client = 9007, 'ogs-client', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9008 = 9008, 'reserved', TransportProtocol.udp

    #: - [TCP] Pichat Server
    #: - [UDP] Pichat Server
    pichat = 9009, 'pichat', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9010 = 9010, 'reserved', TransportProtocol.udp

    #: [UDP] D-Star Routing digital voice+data for amateur radio
    d_star = 9011, 'd-star', TransportProtocol.udp

    #: - [TCP] TAMBORA
    #: - [UDP] TAMBORA
    tambora = 9020, 'tambora', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pangolin Identification
    #: - [UDP] Pangolin Identification
    panagolin_ident = 9021, 'panagolin-ident', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PrivateArk Remote Agent
    #: - [UDP] PrivateArk Remote Agent
    paragent = 9022, 'paragent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Web Access - 1
    #: - [UDP] Secure Web Access - 1
    swa_1 = 9023, 'swa-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Web Access - 2
    #: - [UDP] Secure Web Access - 2
    swa_2 = 9024, 'swa-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Web Access - 3
    #: - [UDP] Secure Web Access - 3
    swa_3 = 9025, 'swa-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Secure Web Access - 4
    #: - [UDP] Secure Web Access - 4
    swa_4 = 9026, 'swa-4', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9050 = 9050, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9051 = 9051, 'reserved', TransportProtocol.udp

    #: [UDP] CardWeb realtime device data
    cardweb_rt = 9060, 'cardweb-rt', TransportProtocol.udp

    #: - [TCP] Groove GLRPC
    #: - [UDP] Groove GLRPC
    glrpc = 9080, 'glrpc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Required for Adaptive Quality of Service
    cisco_aqos = 9081, 'cisco-aqos', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9083 = 9083, 'reserved', TransportProtocol.udp

    #: - [TCP] IBM AURORA Performance Visualizer
    #: - [UDP] IBM AURORA Performance Visualizer
    #: - [SCTP] IBM AURORA Performance Visualizer
    aurora = 9084, 'aurora', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] IBM Remote System Console
    #: - [UDP] IBM Remote System Console
    ibm_rsyscon = 9085, 'ibm-rsyscon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vesa Net2Display
    #: - [UDP] Vesa Net2Display
    net2display = 9086, 'net2display', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Classic Data Server
    #: - [UDP] Classic Data Server
    classic = 9087, 'classic', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Informix SQL Interface
    #: - [UDP] IBM Informix SQL Interface
    sqlexec = 9088, 'sqlexec', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Informix SQL Interface - Encrypted
    #: - [UDP] IBM Informix SQL Interface - Encrypted
    sqlexec_ssl = 9089, 'sqlexec-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WebSM
    #: - [UDP] WebSM
    websm = 9090, 'websm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] xmltec-xmlmail
    #: - [UDP] xmltec-xmlmail
    xmltec_xmlmail = 9091, 'xmltec-xmlmail', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xml-Ipc Server Reg
    #: - [UDP] Xml-Ipc Server Reg
    xmlipcregsvc = 9092, 'xmlipcregsvc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9093 = 9093, 'reserved', TransportProtocol.udp

    #: - [TCP] PDL Data Streaming Port
    #: - [UDP] PDL Data Streaming Port
    hp_pdl_datastr = 9100, 'hp-pdl-datastr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Printer PDL Data Stream
    #: - [UDP] Printer PDL Data Stream
    pdl_datastream = 9100, 'pdl-datastream', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bacula Director
    #: - [UDP] Bacula Director
    bacula_dir = 9101, 'bacula-dir', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bacula File Daemon
    #: - [UDP] Bacula File Daemon
    bacula_fd = 9102, 'bacula-fd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bacula Storage Daemon
    #: - [UDP] Bacula Storage Daemon
    bacula_sd = 9103, 'bacula-sd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PeerWire
    #: - [UDP] PeerWire
    peerwire = 9104, 'peerwire', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Xadmin Control Service [Ari√´n Huisken <xadmin&huisken-systems.nl> 15
    #:   June 2009]
    #: - [UDP] Xadmin Control Service [Ari√´n Huisken <xadmin&huisken-systems.nl> 15
    #:   June 2009]
    xadmin = 9105, 'xadmin', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Astergate Discovery Service
    astergate_disc = 9106, 'astergate-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9107 = 9107, 'reserved', TransportProtocol.udp

    #: - [TCP] Multiple Purpose, Distributed Message Bus
    #: - [UDP] Multiple Purpose, Distributed Message Bus
    hexxorecore = 9111, 'hexxorecore', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MXit Instant Messaging
    #: - [UDP] MXit Instant Messaging
    mxit = 9119, 'mxit', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9122 = 9122, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9123 = 9123, 'reserved', TransportProtocol.udp

    #: - [TCP] Dynamic Device Discovery
    #: - [UDP] Dynamic Device Discovery
    dddp = 9131, 'dddp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] apani1
    #: - [UDP] apani1
    apani1 = 9160, 'apani1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] apani2
    #: - [UDP] apani2
    apani2 = 9161, 'apani2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] apani3
    #: - [UDP] apani3
    apani3 = 9162, 'apani3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] apani4
    #: - [UDP] apani4
    apani4 = 9163, 'apani4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] apani5
    #: - [UDP] apani5
    apani5 = 9164, 'apani5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sirius Configuration Agent
    #: - [UDP] Sirius Configuration Agent
    sirius_agent = 9183, 'sirius-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sun AppSvr JPDA
    #: - [UDP] Sun AppSvr JPDA
    sun_as_jpda = 9191, 'sun-as-jpda', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP connectionless session service
    #: - [UDP] WAP connectionless session service
    wap_wsp = 9200, 'wap-wsp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP session service
    #: - [UDP] WAP session service
    wap_wsp_wtp = 9201, 'wap-wsp-wtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP secure connectionless session service
    #: - [UDP] WAP secure connectionless session service
    wap_wsp_s = 9202, 'wap-wsp-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP secure session service
    #: - [UDP] WAP secure session service
    wap_wsp_wtp_s = 9203, 'wap-wsp-wtp-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP vCard
    #: - [UDP] WAP vCard
    wap_vcard = 9204, 'wap-vcard', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP vCal
    #: - [UDP] WAP vCal
    wap_vcal = 9205, 'wap-vcal', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP vCard Secure
    #: - [UDP] WAP vCard Secure
    wap_vcard_s = 9206, 'wap-vcard-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WAP vCal Secure
    #: - [UDP] WAP vCal Secure
    wap_vcal_s = 9207, 'wap-vcal-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rjcdb vCard
    #: - [UDP] rjcdb vCard
    rjcdb_vcards = 9208, 'rjcdb-vcards', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ALMobile System Service
    #: - [UDP] ALMobile System Service
    almobile_system = 9209, 'almobile-system', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA Mobile Location Protocol
    #: - [UDP] OMA Mobile Location Protocol
    oma_mlp = 9210, 'oma-mlp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OMA Mobile Location Protocol Secure
    #: - [UDP] OMA Mobile Location Protocol Secure
    oma_mlp_s = 9211, 'oma-mlp-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Server View dbms access
    #: - [UDP] Server View dbms access
    serverviewdbms = 9212, 'serverviewdbms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ServerStart RemoteControl
    #: - [UDP] ServerStart RemoteControl
    serverstart = 9213, 'serverstart', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPDC ESG BootstrapService
    #: - [UDP] IPDC ESG BootstrapService
    ipdcesgbs = 9214, 'ipdcesgbs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Integrated Setup and Install Service
    #: - [UDP] Integrated Setup and Install Service
    insis = 9215, 'insis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Aionex Communication Management Engine
    #: - [UDP] Aionex Communication Management Engine
    acme = 9216, 'acme', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FSC Communication Port
    #: - [UDP] FSC Communication Port
    fsc_port = 9217, 'fsc-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] QSC Team Coherence
    #: - [UDP] QSC Team Coherence
    teamcoherence = 9222, 'teamcoherence', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MON
    #: - [UDP] MON
    mon_2583 = 2583, 'mon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Manager On Network
    #: - [UDP] Manager On Network
    mon_9255 = 9255, 'mon', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] GPS Data transmitted from train to ground network
    traingpsdata = 9277, 'traingpsdata', TransportProtocol.udp

    #: - [TCP] Pegasus GPS Platform
    #: - [UDP] Pegasus GPS Platform
    pegasus = 9278, 'pegasus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pegaus GPS System Control Interface
    #: - [UDP] Pegaus GPS System Control Interface
    pegasus_ctl = 9279, 'pegasus-ctl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Predicted GPS
    #: - [UDP] Predicted GPS
    pgps = 9280, 'pgps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SofaWare transport port 1
    #: - [UDP] SofaWare transport port 1
    swtp_port1 = 9281, 'swtp-port1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SofaWare transport port 2
    #: - [UDP] SofaWare transport port 2
    swtp_port2 = 9282, 'swtp-port2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CallWaveIAM
    #: - [UDP] CallWaveIAM
    callwaveiam = 9283, 'callwaveiam', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS Information Serve
    #: - [UDP] VERITAS Information Serve
    visd = 9284, 'visd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] N2H2 Filter Service Port
    #: - [UDP] N2H2 Filter Service Port
    n2h2server = 9285, 'n2h2server', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] n2 monitoring receiver
    n2receive = 9286, 'n2receive', TransportProtocol.udp

    #: - [TCP] Cumulus
    #: - [UDP] Cumulus
    cumulus = 9287, 'cumulus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ArmTech Daemon
    #: - [UDP] ArmTech Daemon
    armtechdaemon = 9292, 'armtechdaemon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] StorView Client
    #: - [UDP] StorView Client
    storview = 9293, 'storview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARMCenter http Service
    #: - [UDP] ARMCenter http Service
    armcenterhttp = 9294, 'armcenterhttp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARMCenter https Service
    #: - [UDP] ARMCenter https Service
    armcenterhttps = 9295, 'armcenterhttps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Virtual Racing Service
    #: - [UDP] Virtual Racing Service
    vrace = 9300, 'vrace', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9306 = 9306, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9310 = 9310, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9312 = 9312, 'reserved', TransportProtocol.udp

    #: - [TCP] PKIX TimeStamp over TLS
    #: - [UDP] PKIX TimeStamp over TLS
    secure_ts = 9318, 'secure-ts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] guibase
    #: - [UDP] guibase
    guibase = 9321, 'guibase', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9339 = 9339, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9340 = 9340, 'reserved', TransportProtocol.udp

    #: - [TCP] MpIdcMgr
    #: - [UDP] MpIdcMgr
    mpidcmgr = 9343, 'mpidcmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mphlpdmc
    #: - [UDP] Mphlpdmc
    mphlpdmc = 9344, 'mphlpdmc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9345 = 9345, 'reserved', TransportProtocol.udp

    #: - [TCP] C Tech Licensing
    #: - [UDP] C Tech Licensing
    ctechlicensing = 9346, 'ctechlicensing', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fjdmimgr
    #: - [UDP] fjdmimgr
    fjdmimgr = 9374, 'fjdmimgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Brivs! Open Extensible Protocol
    #: - [UDP] Brivs! Open Extensible Protocol
    boxp = 9380, 'boxp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9387 = 9387, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9388 = 9388, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9389 = 9389, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9390 = 9390, 'reserved', TransportProtocol.udp

    #: - [TCP] fjinvmgr
    #: - [UDP] fjinvmgr
    fjinvmgr = 9396, 'fjinvmgr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MpIdcAgt
    #: - [UDP] MpIdcAgt
    mpidcagt = 9397, 'mpidcagt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Samsung Twain for Network Server
    #: - [UDP] Samsung Twain for Network Server
    sec_t4net_srv = 9400, 'sec-t4net-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Samsung Twain for Network Client
    #: - [UDP] Samsung Twain for Network Client
    sec_t4net_clt = 9401, 'sec-t4net-clt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Samsung PC2FAX for Network Server
    #: - [UDP] Samsung PC2FAX for Network Server
    sec_pc2fax_srv = 9402, 'sec-pc2fax-srv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] git pack transfer service
    #: - [UDP] git pack transfer service
    git = 9418, 'git', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WSO2 Tungsten HTTPS
    #: - [UDP] WSO2 Tungsten HTTPS
    tungsten_https = 9443, 'tungsten-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WSO2 ESB Administration Console HTTPS
    #: - [UDP] WSO2 ESB Administration Console HTTPS
    wso2esb_console = 9444, 'wso2esb-console', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9445 = 9445, 'reserved', TransportProtocol.udp

    #: - [TCP] Sentinel Keys Server
    #: - [UDP] Sentinel Keys Server
    sntlkeyssrvr = 9450, 'sntlkeyssrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ismserver
    #: - [UDP] ismserver
    ismserver = 9500, 'ismserver', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] SMA Speedwire
    sma_spw = 9522, 'sma-spw', TransportProtocol.udp

    #: - [TCP] Management Suite Remote Control
    #: - [UDP] Management Suite Remote Control
    mngsuite = 9535, 'mngsuite', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Surveillance buffering function
    #: - [UDP] Surveillance buffering function
    laes_bf = 9536, 'laes-bf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Trispen Secure Remote Access
    #: - [UDP] Trispen Secure Remote Access
    trispen_sra = 9555, 'trispen-sra', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9559 = 9559, 'reserved', TransportProtocol.udp

    #: - [TCP] LANDesk Gateway
    #: - [UDP] LANDesk Gateway
    ldgateway = 9592, 'ldgateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LANDesk Management Agent (cba8)
    #: - [UDP] LANDesk Management Agent (cba8)
    cba8 = 9593, 'cba8', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message System
    #: - [UDP] Message System
    msgsys = 9594, 'msgsys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Ping Discovery Service
    #: - [UDP] Ping Discovery Service
    pds = 9595, 'pds', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Mercury Discovery
    #: - [UDP] Mercury Discovery
    mercury_disc = 9596, 'mercury-disc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PD Administration
    #: - [UDP] PD Administration
    pd_admin = 9597, 'pd-admin', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Very Simple Ctrl Protocol
    #: - [UDP] Very Simple Ctrl Protocol
    vscp = 9598, 'vscp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Robix
    #: - [UDP] Robix
    robix = 9599, 'robix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MICROMUSE-NCPW
    #: - [UDP] MICROMUSE-NCPW
    micromuse_ncpw = 9600, 'micromuse-ncpw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] StreamComm User Directory
    #: - [UDP] StreamComm User Directory
    streamcomm_ds = 9612, 'streamcomm-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9614 = 9614, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9616 = 9616, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9617 = 9617, 'reserved', TransportProtocol.udp

    #: - [TCP] Condor Collector Service
    #: - [UDP] Condor Collector Service
    condor = 9618, 'condor', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ODBC Pathway Service
    #: - [UDP] ODBC Pathway Service
    odbcpathway = 9628, 'odbcpathway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UniPort SSO Controller
    #: - [UDP] UniPort SSO Controller
    uniport = 9629, 'uniport', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9630 = 9630, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9631 = 9631, 'reserved', TransportProtocol.udp

    #: [UDP] Mobile-C Communications
    mc_comm = 9632, 'mc-comm', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9640 = 9640, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9666 = 9666, 'reserved', TransportProtocol.udp

    #: - [TCP] Cross-platform Music Multiplexing System
    #: - [UDP] Cross-platform Music Multiplexing System
    xmms2 = 9667, 'xmms2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] tec5 Spectral Device Control Protocol
    #: - [UDP] tec5 Spectral Device Control Protocol
    tec5_sdctp = 9668, 'tec5-sdctp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] T-Mobile Client Wakeup Message
    #: - [UDP] T-Mobile Client Wakeup Message
    client_wakeup = 9694, 'client-wakeup', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Content Centric Networking
    #: - [UDP] Content Centric Networking
    ccnx = 9695, 'ccnx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Board M.I.T. Service
    #: - [UDP] Board M.I.T. Service
    board_roar = 9700, 'board-roar', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] L5NAS Parallel Channel
    #: - [UDP] L5NAS Parallel Channel
    l5nas_parchan = 9747, 'l5nas-parchan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Board M.I.T. Synchronous Collaboration
    #: - [UDP] Board M.I.T. Synchronous Collaboration
    board_voip = 9750, 'board-voip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] rasadv
    #: - [UDP] rasadv
    rasadv = 9753, 'rasadv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WSO2 Tungsten HTTP
    #: - [UDP] WSO2 Tungsten HTTP
    tungsten_http = 9762, 'tungsten-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WebDav Source Port
    #: - [UDP] WebDav Source Port
    davsrc = 9800, 'davsrc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Sakura Script Transfer Protocol-2
    #: - [UDP] Sakura Script Transfer Protocol-2
    sstp_2 = 9801, 'sstp-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WebDAV Source TLS/SSL
    #: - [UDP] WebDAV Source TLS/SSL
    davsrcs = 9802, 'davsrcs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Session Announcement v1 [:rfc:`2974`]
    #: - [UDP] Session Announcement v1 [:rfc:`2974`]
    sapv1 = 9875, 'sapv1', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9877 = 9877, 'reserved', TransportProtocol.udp

    #: [UDP] The KX509 Kerberized Certificate Issuance Protocol in Use in 2012
    #: [:rfc:`6717`]
    kca_service = 9878, 'kca-service', TransportProtocol.udp

    #: - [TCP] CYBORG Systems
    #: - [UDP] CYBORG Systems
    cyborg_systems = 9888, 'cyborg-systems', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Port for Cable network related data proxy or repeater
    #: - [UDP] Port for Cable network related data proxy or repeater
    gt_proxy = 9889, 'gt-proxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MonkeyCom
    #: - [UDP] MonkeyCom
    monkeycom = 9898, 'monkeycom', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] SCTP TUNNELING [:rfc:`6951`]
    sctp_tunneling = 9899, 'sctp-tunneling', TransportProtocol.udp

    #: - [TCP] IUA
    #: - [UDP] IUA
    #: - [SCTP] IUA
    iua = 9900, 'iua', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: [UDP] enrp server channel
    enrp = 9901, 'enrp', TransportProtocol.udp

    #: [UDP] Multicast Ping Protocol [:rfc:`6450`]
    multicast_ping = 9903, 'multicast-ping', TransportProtocol.udp

    #: - [TCP] domaintime
    #: - [UDP] domaintime
    domaintime = 9909, 'domaintime', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SYPECom Transport Protocol
    #: - [UDP] SYPECom Transport Protocol
    sype_transport = 9911, 'sype-transport', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9925 = 9925, 'reserved', TransportProtocol.udp

    #: - [TCP] APC 9950
    #: - [UDP] APC 9950
    apc_9950 = 9950, 'apc-9950', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 9951
    #: - [UDP] APC 9951
    apc_9951 = 9951, 'apc-9951', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APC 9952
    #: - [UDP] APC 9952
    apc_9952 = 9952, 'apc-9952', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 9953
    #: - [UDP] 9953
    acis = 9953, 'acis', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9954 = 9954, 'reserved', TransportProtocol.udp

    #: [UDP] Contact Port for AllJoyn multiplexed constrained messaging
    alljoyn_mcm = 9955, 'alljoyn-mcm', TransportProtocol.udp

    #: [UDP] Alljoyn Name Service
    alljoyn = 9956, 'alljoyn', TransportProtocol.udp

    #: - [TCP] OKI Data Network Setting Protocol
    #: - [UDP] OKI Data Network Setting Protocol
    odnsp = 9966, 'odnsp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9978 = 9978, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9979 = 9979, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9981 = 9981, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9986 = 9986, 'reserved', TransportProtocol.udp

    #: - [TCP] DSM/SCM Target Interface
    #: - [UDP] DSM/SCM Target Interface
    dsm_scm_target = 9987, 'dsm-scm-target', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_9988 = 9988, 'reserved', TransportProtocol.udp

    #: - [TCP] OSM Applet Server
    #: - [UDP] OSM Applet Server
    osm_appsrvr = 9990, 'osm-appsrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OSM Event Server
    #: - [UDP] OSM Event Server
    osm_oev = 9991, 'osm-oev', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OnLive-1
    #: - [UDP] OnLive-1
    palace_1 = 9992, 'palace-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OnLive-2
    #: - [UDP] OnLive-2
    palace_2 = 9993, 'palace-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OnLive-3
    #: - [UDP] OnLive-3
    palace_3 = 9994, 'palace-3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Palace-4
    #: - [UDP] Palace-4
    palace_4 = 9995, 'palace-4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Palace-5
    #: - [UDP] Palace-5
    palace_5 = 9996, 'palace-5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Palace-6
    #: - [UDP] Palace-6
    palace_6 = 9997, 'palace-6', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Distinct32
    #: - [UDP] Distinct32
    distinct32 = 9998, 'distinct32', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] distinct
    #: - [UDP] distinct
    distinct = 9999, 'distinct', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Data Management Protocol
    #: - [UDP] Network Data Management Protocol
    ndmp = 10000, 'ndmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCP Configuration
    #: - [UDP] SCP Configuration
    scp_config = 10001, 'scp-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMC-Documentum Content Server Product
    #: - [UDP] EMC-Documentum Content Server Product
    documentum = 10002, 'documentum', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMC-Documentum Content Server Product IANA assigned this well-formed
    #:   service name as a replacement for "documentum_s".
    #: - [TCP] EMC-Documentum Content Server Product
    #: - [UDP] EMC-Documentum Content Server Product IANA assigned this well-formed
    #:   service name as a replacement for "documentum_s".
    #: - [UDP] EMC-Documentum Content Server Product
    documentum_s = 10003, 'documentum-s', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10004 = 10004, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10005 = 10005, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10006 = 10006, 'reserved', TransportProtocol.udp

    #: - [TCP] MVS Capacity
    #: - [UDP] MVS Capacity
    mvs_capacity = 10007, 'mvs-capacity', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Octopus Multiplexer
    #: - [UDP] Octopus Multiplexer
    octopus = 10008, 'octopus', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Systemwalker Desktop Patrol
    #: - [UDP] Systemwalker Desktop Patrol
    swdtp_sv = 10009, 'swdtp-sv', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10010 = 10010, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10020 = 10020, 'reserved', TransportProtocol.udp

    #: [UDP] Comtech EF-Data's Vipersat Management Protocol
    cefd_vmp = 10023, 'cefd-vmp', TransportProtocol.udp

    #: - [TCP] Zabbix Agent
    #: - [UDP] Zabbix Agent
    zabbix_agent = 10050, 'zabbix-agent', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Zabbix Trapper
    #: - [UDP] Zabbix Trapper
    zabbix_trapper = 10051, 'zabbix-trapper', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10055 = 10055, 'reserved', TransportProtocol.udp

    #: - [TCP] Amanda
    #: - [UDP] Amanda
    amanda = 10080, 'amanda', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FAM Archive Server
    #: - [UDP] FAM Archive Server
    famdc = 10081, 'famdc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS ITAP DDTP
    #: - [UDP] VERITAS ITAP DDTP
    itap_ddtp = 10100, 'itap-ddtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eZmeeting
    #: - [UDP] eZmeeting
    ezmeeting_2 = 10101, 'ezmeeting-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eZproxy
    #: - [UDP] eZproxy
    ezproxy_2 = 10102, 'ezproxy-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eZrelay
    #: - [UDP] eZrelay
    ezrelay = 10103, 'ezrelay', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Systemwalker Desktop Patrol
    #: - [UDP] Systemwalker Desktop Patrol
    swdtp = 10104, 'swdtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS BCTP, server
    #: - [UDP] VERITAS BCTP, server
    bctp_server = 10107, 'bctp-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NMEA-0183 Navigational Data
    #: - [UDP] NMEA-0183 Navigational Data
    nmea_0183 = 10110, 'nmea-0183', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] NMEA OneNet multicast messaging
    nmea_onenet = 10111, 'nmea-onenet', TransportProtocol.udp

    #: - [TCP] NetIQ Endpoint
    #: - [UDP] NetIQ Endpoint
    netiq_endpoint = 10113, 'netiq-endpoint', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetIQ Qcheck
    #: - [UDP] NetIQ Qcheck
    netiq_qcheck = 10114, 'netiq-qcheck', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetIQ Endpoint
    #: - [UDP] NetIQ Endpoint
    netiq_endpt = 10115, 'netiq-endpt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetIQ VoIP Assessor
    #: - [UDP] NetIQ VoIP Assessor
    netiq_voipa = 10116, 'netiq-voipa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetIQ IQCResource Managament Svc
    #: - [UDP] NetIQ IQCResource Managament Svc
    iqrm = 10117, 'iqrm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10125 = 10125, 'reserved', TransportProtocol.udp

    #: - [TCP] BMC-PERFORM-SERVICE DAEMON
    #: - [UDP] BMC-PERFORM-SERVICE DAEMON
    bmc_perf_sd = 10128, 'bmc-perf-sd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10129 = 10129, 'reserved', TransportProtocol.udp

    #: - [TCP] QB Database Server
    #: - [UDP] QB Database Server
    qb_db_server = 10160, 'qb-db-server', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] SNMP-DTLS [:rfc:`6353`]
    snmpdtls = 10161, 'snmpdtls', TransportProtocol.udp

    #: [UDP] SNMP-Trap-DTLS [:rfc:`6353`]
    snmpdtls_trap = 10162, 'snmpdtls-trap', TransportProtocol.udp

    #: - [TCP] Trigence AE Soap Service
    #: - [UDP] Trigence AE Soap Service
    trisoap = 10200, 'trisoap', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Remote Server Control and Test Service
    rscs = 10201, 'rscs', TransportProtocol.udp

    #: - [TCP] Apollo Relay Port
    #: - [UDP] Apollo Relay Port
    apollo_relay = 10252, 'apollo-relay', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Relay of EAPOL frames
    eapol_relay = 10253, 'eapol-relay', TransportProtocol.udp

    #: - [TCP] Axis WIMP Port
    #: - [UDP] Axis WIMP Port
    axis_wimp_port = 10260, 'axis-wimp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10261 = 10261, 'reserved', TransportProtocol.udp

    #: - [TCP] Blocks
    #: - [UDP] Blocks
    blocks = 10288, 'blocks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_10321 = 10321, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] BalanceNG session table synchronization protocol
    bngsync = 10439, 'bngsync', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10443 = 10443, 'reserved', TransportProtocol.udp

    #: [UDP] HIP NAT-Traversal [:rfc:`5770`][:rfc:`9028`]
    hip_nat_t = 10500, 'hip-nat-t', TransportProtocol.udp

    #: - [TCP] MOS Media Object Metadata Port
    #: - [UDP] MOS Media Object Metadata Port
    mos_lower = 10540, 'mos-lower', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MOS Running Order Port
    #: - [UDP] MOS Running Order Port
    mos_upper = 10541, 'mos-upper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MOS Low Priority Port
    #: - [UDP] MOS Low Priority Port
    mos_aux = 10542, 'mos-aux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MOS SOAP Default Port
    #: - [UDP] MOS SOAP Default Port
    mos_soap = 10543, 'mos-soap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] MOS SOAP Optional Port
    #: - [UDP] MOS SOAP Optional Port
    mos_soap_opt = 10544, 'mos-soap-opt', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10548 = 10548, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10631 = 10631, 'reserved', TransportProtocol.udp

    #: - [TCP] Gestor de Acaparamiento para Pocket PCs
    #: - [UDP] Gestor de Acaparamiento para Pocket PCs
    gap = 10800, 'gap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LUCIA Pareja Data Group
    #: - [UDP] LUCIA Pareja Data Group
    lpdg = 10805, 'lpdg', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10809 = 10809, 'reserved', TransportProtocol.udp

    #: [UDP] Nuance Mobile Care Discovery
    nmc_disc = 10810, 'nmc-disc', TransportProtocol.udp

    #: - [TCP] Helix Client/Server
    #: - [UDP] Helix Client/Server
    helix = 10860, 'helix', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BVEssentials HTTP API
    #: - [UDP] BVEssentials HTTP API
    bveapi = 10880, 'bveapi', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_10933 = 10933, 'reserved', TransportProtocol.udp

    #: - [TCP] Auxiliary RMI Port
    #: - [UDP] Auxiliary RMI Port
    rmiaux = 10990, 'rmiaux', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IRISA
    #: - [UDP] IRISA
    irisa = 11000, 'irisa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Metasys
    #: - [UDP] Metasys
    metasys = 11001, 'metasys', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nest device-to-device and device-to-service application protocol
    #: - [UDP] Nest device-to-device and device-to-service application protocol
    weave = 11095, 'weave', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11103 = 11103, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11104 = 11104, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11105 = 11105, 'reserved', TransportProtocol.udp

    #: - [TCP] SGI LK Licensing service
    #: - [UDP] SGI LK Licensing service
    sgi_lk = 11106, 'sgi-lk', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Hardware Terminals Discovery and Low-Level Communication Protocol
    myq_termlink = 11108, 'myq-termlink', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11109 = 11109, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11110 = 11110, 'reserved', TransportProtocol.udp

    #: - [TCP] Viral Computing Environment (VCE)
    #: - [UDP] Viral Computing Environment (VCE)
    vce = 11111, 'vce', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DICOM
    #: - [UDP] DICOM
    dicom = 11112, 'dicom', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sun cacao snmp access point
    #: - [UDP] sun cacao snmp access point
    suncacao_snmp = 11161, 'suncacao-snmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sun cacao JMX-remoting access point
    #: - [UDP] sun cacao JMX-remoting access point
    suncacao_jmxmp = 11162, 'suncacao-jmxmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sun cacao rmi registry access point
    #: - [UDP] sun cacao rmi registry access point
    suncacao_rmi = 11163, 'suncacao-rmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sun cacao command-streaming access point
    #: - [UDP] sun cacao command-streaming access point
    suncacao_csa = 11164, 'suncacao-csa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sun cacao web service access point
    #: - [UDP] sun cacao web service access point
    suncacao_websvc = 11165, 'suncacao-websvc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Surgical Notes Security Service Discovery (SNSS)
    snss = 11171, 'snss', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11172 = 11172, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11173 = 11173, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11174 = 11174, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11175 = 11175, 'reserved', TransportProtocol.udp

    #: - [TCP] smsqp
    #: - [UDP] smsqp
    smsqp = 11201, 'smsqp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11202 = 11202, 'reserved', TransportProtocol.udp

    #: - [TCP] WiFree Service
    #: - [UDP] WiFree Service
    wifree = 11208, 'wifree', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Memory cache service
    #: - [UDP] Memory cache service
    memcache = 11211, 'memcache', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11235 = 11235, 'reserved', TransportProtocol.udp

    #: - [TCP] IMIP
    #: - [UDP] IMIP
    imip = 11319, 'imip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IMIP Channels Port
    #: - [UDP] IMIP Channels Port
    imip_channels = 11320, 'imip-channels', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Arena Server Listen
    #: - [UDP] Arena Server Listen
    arena_server = 11321, 'arena-server', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ATM UHAS
    #: - [UDP] ATM UHAS
    atm_uhas = 11367, 'atm-uhas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenPGP HTTP Keyserver
    #: - [UDP] OpenPGP HTTP Keyserver
    hkp = 11371, 'hkp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Lenbrook Service Discovery Protocol
    lsdp = 11430, 'lsdp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11434 = 11434, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11489 = 11489, 'reserved', TransportProtocol.udp

    #: - [TCP] Tempest Protocol Port
    #: - [UDP] Tempest Protocol Port
    tempest_port = 11600, 'tempest-port', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11623 = 11623, 'reserved', TransportProtocol.udp

    #: - [TCP] H.323 Call Control Signalling Alternate
    #: - [UDP] H.323 Call Control Signalling Alternate
    h323callsigalt = 11720, 'h323callsigalt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EMC XtremSW distributed cache
    #: - [UDP] EMC XtremSW distributed cache
    emc_xsw_dcache = 11723, 'emc-xsw-dcache', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intrepid SSL
    #: - [UDP] Intrepid SSL
    intrepid_ssl = 11751, 'intrepid-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Lanschool Multipoint
    lanschool_mpt = 11796, 'lanschool-mpt', TransportProtocol.udp

    #: - [TCP] X2E Xoraya Multichannel protocol
    #: - [UDP] X2E Xoraya Multichannel protocol
    xoraya = 11876, 'xoraya', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] X2E service discovery protocol
    x2e_disc = 11877, 'x2e-disc', TransportProtocol.udp

    #: - [TCP] SysInfo Service Protocol
    #: - [UDP] SysInfo Service Protocol
    sysinfo_sp = 11967, 'sysinfo-sp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_11971 = 11971, 'reserved', TransportProtocol.udp

    #: - [TCP] IBM Enterprise Extender SNA XID Exchange
    #: - [UDP] IBM Enterprise Extender SNA XID Exchange
    entextxid = 12000, 'entextxid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Enterprise Extender SNA COS Network Priority
    #: - [UDP] IBM Enterprise Extender SNA COS Network Priority
    entextnetwk = 12001, 'entextnetwk', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Enterprise Extender SNA COS High Priority
    #: - [UDP] IBM Enterprise Extender SNA COS High Priority
    entexthigh = 12002, 'entexthigh', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Enterprise Extender SNA COS Medium Priority
    #: - [UDP] IBM Enterprise Extender SNA COS Medium Priority
    entextmed = 12003, 'entextmed', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IBM Enterprise Extender SNA COS Low Priority
    #: - [UDP] IBM Enterprise Extender SNA COS Low Priority
    entextlow = 12004, 'entextlow', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DBISAM Database Server - Regular
    #: - [UDP] DBISAM Database Server - Regular
    dbisamserver1 = 12005, 'dbisamserver1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DBISAM Database Server - Admin
    #: - [UDP] DBISAM Database Server - Admin
    dbisamserver2 = 12006, 'dbisamserver2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Accuracer Database System Server
    #: - [UDP] Accuracer Database System Server
    accuracer = 12007, 'accuracer', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Accuracer Database System Admin
    #: - [UDP] Accuracer Database System Admin
    accuracer_dbms = 12008, 'accuracer-dbms', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Green Hills VPN
    ghvpn = 12009, 'ghvpn', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_12010 = 12010, 'reserved', TransportProtocol.udp

    #: - [TCP] Vipera Messaging Service
    #: - [UDP] Vipera Messaging Service
    vipera = 12012, 'vipera', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vipera Messaging Service over SSL Communication
    #: - [UDP] Vipera Messaging Service over SSL Communication
    vipera_ssl = 12013, 'vipera-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] RETS over SSL
    #: - [UDP] RETS over SSL
    rets_ssl = 12109, 'rets-ssl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NuPaper Session Service
    #: - [UDP] NuPaper Session Service
    nupaper_ss = 12121, 'nupaper-ss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA Web Access Service
    #: - [UDP] CA Web Access Service
    cawas = 12168, 'cawas', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HiveP
    #: - [UDP] HiveP
    hivep = 12172, 'hivep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] LinoGrid Engine
    #: - [UDP] LinoGrid Engine
    linogridengine = 12300, 'linogridengine', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_12302 = 12302, 'reserved', TransportProtocol.udp

    #: - [TCP] Warehouse Monitoring Syst SSS
    #: - [UDP] Warehouse Monitoring Syst SSS
    warehouse_sss = 12321, 'warehouse-sss', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Warehouse Monitoring Syst
    #: - [UDP] Warehouse Monitoring Syst
    warehouse = 12322, 'warehouse', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Italk Chat System
    #: - [UDP] Italk Chat System
    italk = 12345, 'italk', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_12546 = 12546, 'reserved', TransportProtocol.udp

    #: - [TCP] tsaf port
    #: - [UDP] tsaf port
    tsaf = 12753, 'tsaf', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_12865 = 12865, 'reserved', TransportProtocol.udp

    #: - [TCP] I-ZIPQD
    #: - [UDP] I-ZIPQD
    i_zipqd = 13160, 'i-zipqd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Black Crow Software application logging
    #: - [UDP] Black Crow Software application logging
    bcslogc = 13216, 'bcslogc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] R&S Proxy Installation Assistant Service
    #: - [UDP] R&S Proxy Installation Assistant Service
    rs_pias = 13217, 'rs-pias', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] EMV Virtual CAS Service Discovery
    emc_vcas_udp = 13218, 'emc-vcas-udp', TransportProtocol.udp

    #: - [TCP] PowWow Client
    #: - [UDP] PowWow Client
    powwow_client = 13223, 'powwow-client', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PowWow Server
    #: - [UDP] PowWow Server
    powwow_server = 13224, 'powwow-server', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] DoIP Discovery
    doip_disc = 13400, 'doip-disc', TransportProtocol.udp

    #: - [TCP] BPRD Protocol (VERITAS NetBackup)
    #: - [UDP] BPRD Protocol (VERITAS NetBackup)
    bprd = 13720, 'bprd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BPDBM Protocol (VERITAS NetBackup)
    #: - [UDP] BPDBM Protocol (VERITAS NetBackup)
    bpdbm = 13721, 'bpdbm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BP Java MSVC Protocol
    #: - [UDP] BP Java MSVC Protocol
    bpjava_msvc = 13722, 'bpjava-msvc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Veritas Network Utility
    #: - [UDP] Veritas Network Utility
    vnetd = 13724, 'vnetd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VERITAS NetBackup
    #: - [UDP] VERITAS NetBackup
    bpcd = 13782, 'bpcd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VOPIED Protocol
    #: - [UDP] VOPIED Protocol
    vopied = 13783, 'vopied', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetBackup Database
    #: - [UDP] NetBackup Database
    nbdb = 13785, 'nbdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Veritas-nomdb
    #: - [UDP] Veritas-nomdb
    nomdb = 13786, 'nomdb', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DSMCC Config [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    #: - [UDP] DSMCC Config [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    dsmcc_config = 13818, 'dsmcc-config', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DSMCC Session Messages [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    #: - [UDP] DSMCC Session Messages [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    dsmcc_session = 13819, 'dsmcc-session', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DSMCC Pass-Thru Messages [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    #: - [UDP] DSMCC Pass-Thru Messages [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    dsmcc_passthru = 13820, 'dsmcc-passthru', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DSMCC Download Protocol [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    #: - [UDP] DSMCC Download Protocol [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    dsmcc_download = 13821, 'dsmcc-download', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DSMCC Channel Change Protocol [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    #: - [UDP] DSMCC Channel Change Protocol [ISO/IEC 13818-6 MPEG-2 DSM-CC]
    dsmcc_ccp = 13822, 'dsmcc-ccp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_13823 = 13823, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_13832 = 13832, 'reserved', TransportProtocol.udp

    #: - [TCP] Ultimate Control communication protocol
    #: - [UDP] Ultimate Control communication protocol
    ucontrol = 13894, 'ucontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] D-TA SYSTEMS
    #: - [UDP] D-TA SYSTEMS
    dta_systems = 13929, 'dta-systems', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_13930 = 13930, 'reserved', TransportProtocol.udp

    #: - [TCP] SCOTTY High-Speed Filetransfer
    #: - [UDP] SCOTTY High-Speed Filetransfer
    scotty_ft = 14000, 'scotty-ft', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SUA
    #: - [UDP] De-Registered
    #: - [SCTP] SUA
    sua = 14001, 'sua', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: [UDP] Discovery of a SCOTTY hardware codec board
    scotty_disc = 14002, 'scotty-disc', TransportProtocol.udp

    #: - [TCP] sage Best! Config Server 1
    #: - [UDP] sage Best! Config Server 1
    sage_best_com1 = 14033, 'sage-best-com1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] sage Best! Config Server 2
    #: - [UDP] sage Best! Config Server 2
    sage_best_com2 = 14034, 'sage-best-com2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VCS Application
    #: - [UDP] VCS Application
    vcs_app = 14141, 'vcs-app', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IceWall Cert Protocol
    #: - [UDP] IceWall Cert Protocol
    icpp = 14142, 'icpp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_14143 = 14143, 'reserved', TransportProtocol.udp

    #: - [TCP] GCM Application
    #: - [UDP] GCM Application
    gcm_app = 14145, 'gcm-app', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Veritas Traffic Director
    #: - [UDP] Veritas Traffic Director
    vrts_tdd = 14149, 'vrts-tdd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_14150 = 14150, 'reserved', TransportProtocol.udp

    #: - [TCP] Veritas Application Director
    #: - [UDP] Veritas Application Director
    vad = 14154, 'vad', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fencing Server
    #: - [UDP] Fencing Server
    cps = 14250, 'cps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA eTrust Web Update Service
    #: - [UDP] CA eTrust Web Update Service
    ca_web_update = 14414, 'ca-web-update', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_14500 = 14500, 'reserved', TransportProtocol.udp

    #: - [TCP] hde-lcesrvr-1
    #: - [UDP] hde-lcesrvr-1
    hde_lcesrvr_1 = 14936, 'hde-lcesrvr-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hde-lcesrvr-2
    #: - [UDP] hde-lcesrvr-2
    hde_lcesrvr_2 = 14937, 'hde-lcesrvr-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Hypack Data Aquisition
    #: - [UDP] Hypack Data Aquisition
    hydap = 15000, 'hydap', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_15002 = 15002, 'reserved', TransportProtocol.udp

    #: [UDP] v2g Supply Equipment Communication Controller Discovery Protocol
    v2g_secc = 15118, 'v2g-secc', TransportProtocol.udp

    #: - [TCP] XPilot Contact Port
    #: - [UDP] XPilot Contact Port
    xpilot = 15345, 'xpilot', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] 3Link Negotiation
    #: - [UDP] 3Link Negotiation
    UDP_3link = 15363, '3link', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Cisco Stateful NAT
    #: - [UDP] Cisco Stateful NAT
    cisco_snat = 15555, 'cisco-snat', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Backup Express Restore Server
    #: - [UDP] Backup Express Restore Server
    bex_xr = 15660, 'bex-xr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Picture Transfer Protocol
    #: - [UDP] Picture Transfer Protocol
    ptp = 15740, 'ptp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] 2ping Bi-Directional Ping Service
    UDP_2ping = 15998, '2ping', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_15999 = 15999, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16000 = 16000, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16001 = 16001, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16002 = 16002, 'reserved', TransportProtocol.udp

    #: [UDP] Automation and Control by REGULACE.ORG
    alfin = 16003, 'alfin', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16020 = 16020, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16021 = 16021, 'reserved', TransportProtocol.udp

    #: - [TCP] Solaris SEA Port
    #: - [UDP] Solaris SEA Port
    sun_sea_port = 16161, 'sun-sea-port', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16162 = 16162, 'reserved', TransportProtocol.udp

    #: - [TCP] etb4j
    #: - [UDP] etb4j
    etb4j = 16309, 'etb4j', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Policy Distribute, Update Notification
    #: - [UDP] Policy Distribute, Update Notification
    pduncs = 16310, 'pduncs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Policy definition and update management
    #: - [UDP] Policy definition and update management
    pdefmns = 16311, 'pdefmns', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Serial Extension Ports One
    #: - [UDP] Network Serial Extension Ports One
    netserialext1 = 16360, 'netserialext1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Serial Extension Ports Two
    #: - [UDP] Network Serial Extension Ports Two
    netserialext2 = 16361, 'netserialext2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Serial Extension Ports Three
    #: - [UDP] Network Serial Extension Ports Three
    netserialext3 = 16367, 'netserialext3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network Serial Extension Ports Four
    #: - [UDP] Network Serial Extension Ports Four
    netserialext4 = 16368, 'netserialext4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Connected Corp
    #: - [UDP] Connected Corp
    connected = 16384, 'connected', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16385 = 16385, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16619 = 16619, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16665 = 16665, 'reserved', TransportProtocol.udp

    #: [UDP] Vidder Tunnel Protocol
    vtp = 16666, 'vtp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_16789 = 16789, 'reserved', TransportProtocol.udp

    #: - [TCP] Newbay Mobile Client Update Service
    #: - [UDP] Newbay Mobile Client Update Service
    newbay_snc_mc = 16900, 'newbay-snc-mc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Simple Generic Client Interface Protocol
    #: - [UDP] Simple Generic Client Interface Protocol
    sgcip = 16950, 'sgcip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] INTEL-RCI-MP
    #: - [UDP] INTEL-RCI-MP
    intel_rci_mp = 16991, 'intel-rci-mp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intel(R) AMT SOAP/HTTP
    #: - [UDP] Intel(R) AMT SOAP/HTTP
    amt_soap_http = 16992, 'amt-soap-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intel(R) AMT SOAP/HTTPS
    #: - [UDP] Intel(R) AMT SOAP/HTTPS
    amt_soap_https = 16993, 'amt-soap-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intel(R) AMT Redirection/TCP
    #: - [UDP] Intel(R) AMT Redirection/TCP
    amt_redir_tcp = 16994, 'amt-redir-tcp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Intel(R) AMT Redirection/TLS
    #: - [UDP] Intel(R) AMT Redirection/TLS
    amt_redir_tls = 16995, 'amt-redir-tls', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP]
    #: - [UDP]
    isode_dua = 17007, 'isode-dua', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_17010 = 17010, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_17184 = 17184, 'reserved', TransportProtocol.udp

    #: - [TCP] Sounds Virtual
    #: - [UDP] Sounds Virtual
    soundsvirtual = 17185, 'soundsvirtual', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Chipper
    #: - [UDP] Chipper
    chipper = 17219, 'chipper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IEEE 1722 Transport Protocol for Time Sensitive Applications
    #: - [UDP] IEEE 1722 Transport Protocol for Time Sensitive Applications
    avtp = 17220, 'avtp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IEEE 1722.1 AVB Discovery, Enumeration, Connection management, and
    #:   Control
    #: - [UDP] IEEE 1722.1 AVB Discovery, Enumeration, Connection management, and
    #:   Control
    avdecc = 17221, 'avdecc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Control Plane Synchronization Protocol (SPSP)
    cpsp = 17222, 'cpsp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_17223 = 17223, 'reserved', TransportProtocol.udp

    #: [UDP] Train Realtime Data Protocol (TRDP) Process Data
    trdp_pd = 17224, 'trdp-pd', TransportProtocol.udp

    #: - [TCP] Train Realtime Data Protocol (TRDP) Message Data
    #: - [UDP] Train Realtime Data Protocol (TRDP) Message Data
    trdp_md = 17225, 'trdp-md', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Integrius Secure Tunnel Protocol
    #: - [UDP] Integrius Secure Tunnel Protocol
    integrius_stp = 17234, 'integrius-stp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSH Tectia Manager
    #: - [UDP] SSH Tectia Manager
    ssh_mgmt = 17235, 'ssh-mgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Dropbox LanSync Discovery
    db_lsp_disc = 17500, 'db-lsp-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_17555 = 17555, 'reserved', TransportProtocol.udp

    #: - [TCP] Eclipse Aviation
    #: - [UDP] Eclipse Aviation
    ea = 17729, 'ea', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Encap. ZigBee Packets
    #: - [UDP] Encap. ZigBee Packets
    zep = 17754, 'zep', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ZigBee IP Transport Service
    #: - [UDP] ZigBee IP Transport Service
    zigbee_ip = 17755, 'zigbee-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ZigBee IP Transport Secure Service
    #: - [UDP] ZigBee IP Transport Secure Service
    zigbee_ips = 17756, 'zigbee-ips', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_17777 = 17777, 'reserved', TransportProtocol.udp

    #: - [TCP] Beckman Instruments, Inc.
    #: - [UDP] Beckman Instruments, Inc.
    biimenu = 18000, 'biimenu', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_18104 = 18104, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_18136 = 18136, 'reserved', TransportProtocol.udp

    #: - [TCP] OPSEC CVP
    #: - [UDP] OPSEC CVP
    opsec_cvp = 18181, 'opsec-cvp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPSEC UFP
    #: - [UDP] OPSEC UFP
    opsec_ufp = 18182, 'opsec-ufp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPSEC SAM
    #: - [UDP] OPSEC SAM
    opsec_sam = 18183, 'opsec-sam', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPSEC LEA
    #: - [UDP] OPSEC LEA
    opsec_lea = 18184, 'opsec-lea', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPSEC OMI
    #: - [UDP] OPSEC OMI
    opsec_omi = 18185, 'opsec-omi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Occupational Health SC
    #: - [UDP] Occupational Health Sc
    ohsc = 18186, 'ohsc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OPSEC ELA
    #: - [UDP] OPSEC ELA
    opsec_ela = 18187, 'opsec-ela', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Check Point RTM
    #: - [UDP] Check Point RTM
    checkpoint_rtm = 18241, 'checkpoint-rtm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_18242 = 18242, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_18243 = 18243, 'reserved', TransportProtocol.udp

    #: - [TCP] GV NetConfig Service
    #: - [UDP] GV NetConfig Service
    gv_pf = 18262, 'gv-pf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AC Cluster
    #: - [UDP] AC Cluster
    ac_cluster = 18463, 'ac-cluster', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] HeyThings Device communicate service
    heythings = 18516, 'heythings', TransportProtocol.udp

    #: - [TCP] Reliable Datagram Service
    #: - [UDP] Reliable Datagram Service
    rds_ib = 18634, 'rds-ib', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reliable Datagram Service over IP
    #: - [UDP] Reliable Datagram Service over IP
    rds_ip = 18635, 'rds-ip', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Manufacturing Execution Systems Mesh Communication
    vdmmesh_disc = 18668, 'vdmmesh-disc', TransportProtocol.udp

    #: - [TCP] IQue Protocol
    #: - [UDP] IQue Protocol
    ique = 18769, 'ique', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Infotos
    #: - [UDP] Infotos
    infotos = 18881, 'infotos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] APCNECMP
    #: - [UDP] APCNECMP
    apc_necmp = 18888, 'apc-necmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iGrid Server
    #: - [UDP] iGrid Server
    igrid = 19000, 'igrid', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Scintilla protocol for device services
    #: - [UDP] Scintilla protocol for device services
    scintilla = 19007, 'scintilla', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_19020 = 19020, 'reserved', TransportProtocol.udp

    #: - [TCP] OPSEC UAA
    #: - [UDP] OPSEC UAA
    opsec_uaa = 19191, 'opsec-uaa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] UserAuthority SecureAgent
    #: - [UDP] UserAuthority SecureAgent
    ua_secureagent = 19194, 'ua-secureagent', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Discovery for Client Connection Management and Data Exchange Service
    cora_disc = 19220, 'cora-disc', TransportProtocol.udp

    #: - [TCP] Key Server for SASSAFRAS
    #: - [UDP] Key Server for SASSAFRAS
    keysrvr = 19283, 'keysrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Key Shadow for SASSAFRAS
    #: - [UDP] Key Shadow for SASSAFRAS
    keyshadow = 19315, 'keyshadow', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] mtrgtrans
    #: - [UDP] mtrgtrans
    mtrgtrans = 19398, 'mtrgtrans', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp-sco
    #: - [UDP] hp-sco
    hp_sco = 19410, 'hp-sco', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] hp-sca
    #: - [UDP] hp-sca
    hp_sca = 19411, 'hp-sca', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] HP-SESSMON
    #: - [UDP] HP-SESSMON
    hp_sessmon = 19412, 'hp-sessmon', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FXUPTP
    #: - [UDP] FXUPTP
    fxuptp = 19539, 'fxuptp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SXUPTP
    #: - [UDP] SXUPTP
    sxuptp = 19540, 'sxuptp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] JCP Client
    #: - [UDP] JCP Client
    jcp = 19541, 'jcp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Mesh Link Establishment
    mle = 19788, 'mle', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_19790 = 19790, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_19998 = 19998, 'reserved', TransportProtocol.udp

    #: - [TCP] Distributed Network Protocol - Secure
    #: - [UDP] Distributed Network Protocol - Secure
    #: - [SCTP] Distributed Network Protocol - secured
    dnp_sec = 19999, 'dnp-sec', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] DNP
    #: - [UDP] DNP
    #: - [SCTP] Distributed Network Protocol
    dnp = 20000, 'dnp', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] MicroSAN
    #: - [UDP] MicroSAN
    microsan = 20001, 'microsan', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Commtact HTTP
    #: - [UDP] Commtact HTTP
    commtact_http = 20002, 'commtact-http', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Commtact HTTPS
    #: - [UDP] Commtact HTTPS
    commtact_https = 20003, 'commtact-https', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenWebNet protocol for electric network
    #: - [UDP] OpenWebNet protocol for electric network
    openwebnet = 20005, 'openwebnet', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Samsung Interdevice Interaction discovery
    ss_idi_disc = 20012, 'ss-idi-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_20013 = 20013, 'reserved', TransportProtocol.udp

    #: - [TCP] OpenDeploy Listener
    #: - [UDP] OpenDeploy Listener
    opendeploy = 20014, 'opendeploy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetBurner ID Port IANA assigned this well-formed service name as a
    #:   replacement for "nburn_id".
    #: - [TCP] NetBurner ID Port
    #: - [UDP] NetBurner ID Port IANA assigned this well-formed service name as a
    #:   replacement for "nburn_id".
    #: - [UDP] NetBurner ID Port
    nburn_id = 20034, 'nburn-id', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TMOP HL7 Message Transfer Service
    #: - [UDP] TMOP HL7 Message Transfer Service
    tmophl7mts = 20046, 'tmophl7mts', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NFS mount protocol
    #: - [UDP] NFS mount protocol
    mountd = 20048, 'mountd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Network File System (NFS) over RDMA [:rfc:`8267`]
    #: - [UDP] Network File System (NFS) over RDMA [:rfc:`8267`]
    #: - [SCTP] Network File System (NFS) over RDMA [:rfc:`8267`]
    nfsrdma = 20049, 'nfsrdma', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: [UDP] Reserved
    reserved_20057 = 20057, 'reserved', TransportProtocol.udp

    #: - [TCP] TOLfab Data Change
    #: - [UDP] TOLfab Data Change
    tolfab = 20167, 'tolfab', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IPD Tunneling Port
    #: - [UDP] IPD Tunneling Port
    ipdtp_port = 20202, 'ipdtp-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iPulse-ICS
    #: - [UDP] iPulse-ICS
    ipulse_ics = 20222, 'ipulse-ics', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] emWave Message Service
    #: - [UDP] emWave Message Service
    emwavemsg = 20480, 'emwavemsg', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Track
    #: - [UDP] Track
    track = 20670, 'track', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_20810 = 20810, 'reserved', TransportProtocol.udp

    #: - [TCP] At Hand MMP
    #: - [UDP] AT Hand MMP
    athand_mmp = 20999, 'athand-mmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IRTrans Control
    #: - [UDP] IRTrans Control
    irtrans = 21000, 'irtrans', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_21010 = 21010, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_21212 = 21212, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_21213 = 21213, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_21221 = 21221, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_21337 = 21337, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_21553 = 21553, 'reserved', TransportProtocol.udp

    #: - [TCP] MineScape Design File Server
    #: - [UDP] MineScape Design File Server
    dfserver = 21554, 'dfserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] VoFR Gateway
    #: - [UDP] VoFR Gateway
    vofr_gateway = 21590, 'vofr-gateway', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TVNC Pro Multiplexing
    #: - [UDP] TVNC Pro Multiplexing
    tvpm = 21800, 'tvpm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] webphone
    #: - [UDP] webphone
    webphone = 21845, 'webphone', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetSpeak Corp. Directory Services
    #: - [UDP] NetSpeak Corp. Directory Services
    netspeak_is = 21846, 'netspeak-is', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetSpeak Corp. Connection Services
    #: - [UDP] NetSpeak Corp. Connection Services
    netspeak_cs = 21847, 'netspeak-cs', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetSpeak Corp. Automatic Call Distribution
    #: - [UDP] NetSpeak Corp. Automatic Call Distribution
    netspeak_acd = 21848, 'netspeak-acd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NetSpeak Corp. Credit Processing System
    #: - [UDP] NetSpeak Corp. Credit Processing System
    netspeak_cps = 21849, 'netspeak-cps', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SNAPenetIO
    #: - [UDP] SNAPenetIO
    snapenetio = 22000, 'snapenetio', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OptoControl
    #: - [UDP] OptoControl
    optocontrol = 22001, 'optocontrol', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Opto Host Port 2
    #: - [UDP] Opto Host Port 2
    optohost002 = 22002, 'optohost002', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Opto Host Port 3
    #: - [UDP] Opto Host Port 3
    optohost003 = 22003, 'optohost003', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Opto Host Port 4
    #: - [UDP] Opto Host Port 4
    optohost004_22004 = 22004, 'optohost004', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Opto Host Port 5
    #: - [UDP] Opto Host Port 5
    optohost004_22005 = 22005, 'optohost004', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_22125 = 22125, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_22128 = 22128, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_22222 = 22222, 'reserved', TransportProtocol.udp

    #: - [TCP] wnn6
    #: - [UDP] wnn6
    wnn6 = 22273, 'wnn6', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CompactIS Tunnel
    #: - [UDP] CompactIS Tunnel
    cis = 22305, 'cis', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ShowCockpit Networking
    #: - [UDP] ShowCockpit Networking
    showcockpit_net = 22333, 'showcockpit-net', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Initium Labs Security and Automation Streaming
    shrewd_stream = 22335, 'shrewd-stream', TransportProtocol.udp

    #: - [TCP] CompactIS Secure Tunnel
    #: - [UDP] CompactIS Secure Tunnel
    cis_secure = 22343, 'cis-secure', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] WibuKey Standard WkLan
    #: - [UDP] WibuKey Standard WkLan
    wibukey = 22347, 'wibukey', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CodeMeter Standard
    #: - [UDP] CodeMeter Standard
    codemeter = 22350, 'codemeter', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_22351 = 22351, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_22537 = 22537, 'reserved', TransportProtocol.udp

    #: [UDP] Vocaltec Internet Phone
    vocaltec_phone = 22555, 'vocaltec-phone', TransportProtocol.udp

    #: - [TCP] Talika Main Server
    #: - [UDP] Talika Main Server
    talikaserver = 22763, 'talikaserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Telerate Information Platform LAN
    #: - [UDP] Telerate Information Platform LAN
    aws_brf = 22800, 'aws-brf', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Telerate Information Platform WAN
    #: - [UDP] Telerate Information Platform WAN
    brf_gw = 22951, 'brf-gw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inova LightLink Server Type 1
    #: - [UDP] Inova LightLink Server Type 1
    inovaport1 = 23000, 'inovaport1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inova LightLink Server Type 2
    #: - [UDP] Inova LightLink Server Type 2
    inovaport2 = 23001, 'inovaport2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inova LightLink Server Type 3
    #: - [UDP] Inova LightLink Server Type 3
    inovaport3 = 23002, 'inovaport3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inova LightLink Server Type 4
    #: - [UDP] Inova LightLink Server Type 4
    inovaport4 = 23003, 'inovaport4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inova LightLink Server Type 5
    #: - [UDP] Inova LightLink Server Type 5
    inovaport5 = 23004, 'inovaport5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Inova LightLink Server Type 6
    #: - [UDP] Inova LightLink Server Type 6
    inovaport6 = 23005, 'inovaport6', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_23053 = 23053, 'reserved', TransportProtocol.udp

    #: [UDP] S102 application
    s102 = 23272, 's102', TransportProtocol.udp

    #: [UDP] 5AFE SDN Directory discovery
    UDP_5afe_disc = 23294, '5afe-disc', TransportProtocol.udp

    #: - [TCP] Emulex HBAnyware Remote Management
    #: - [UDP] Emulex HBAnyware Remote Management
    elxmgmt = 23333, 'elxmgmt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novar Data
    #: - [UDP] Novar Data
    novar_dbase = 23400, 'novar-dbase', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novar Alarm
    #: - [UDP] Novar Alarm
    novar_alarm = 23401, 'novar-alarm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Novar Global
    #: - [UDP] Novar Global
    novar_global = 23402, 'novar-global', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_23456 = 23456, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_23457 = 23457, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_23546 = 23546, 'reserved', TransportProtocol.udp

    #: - [TCP] med-ltp
    #: - [UDP] med-ltp
    med_ltp = 24000, 'med-ltp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] med-fsp-rx
    #: - [UDP] med-fsp-rx
    med_fsp_rx = 24001, 'med-fsp-rx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] med-fsp-tx
    #: - [UDP] med-fsp-tx
    med_fsp_tx = 24002, 'med-fsp-tx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] med-supp
    #: - [UDP] med-supp
    med_supp = 24003, 'med-supp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] med-ovw
    #: - [UDP] med-ovw
    med_ovw = 24004, 'med-ovw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] med-ci
    #: - [UDP] med-ci
    med_ci = 24005, 'med-ci', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] med-net-svc
    #: - [UDP] med-net-svc
    med_net_svc = 24006, 'med-net-svc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] fileSphere
    #: - [UDP] fileSphere
    filesphere = 24242, 'filesphere', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Vista 4GL
    #: - [UDP] Vista 4GL
    vista_4gl = 24249, 'vista-4gl', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Isolv Local Directory
    #: - [UDP] Isolv Local Directory
    ild = 24321, 'ild', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Transport of Human Interface Device data streams
    hid = 24322, 'hid', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_24323 = 24323, 'reserved', TransportProtocol.udp

    #: - [TCP] Intel RCI IANA assigned this well-formed service name as a replacement
    #:   for "intel_rci".
    #: - [TCP] Intel RCI
    #: - [UDP] Intel RCI IANA assigned this well-formed service name as a replacement
    #:   for "intel_rci".
    #: - [UDP] Intel RCI
    intel_rci = 24386, 'intel-rci', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Tonido Domain Server
    #: - [UDP] Tonido Domain Server
    tonidods = 24465, 'tonidods', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] BINKP
    #: - [UDP] BINKP
    binkp = 24554, 'binkp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] bilobit Service Update
    bilobit_update = 24577, 'bilobit-update', TransportProtocol.udp

    #: [UDP] UDP-based IP-Layer Capacity and Performance Measurement protocol
    #: [:rfc:`9946`]
    udpstp = 24601, 'udpstp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_24666 = 24666, 'reserved', TransportProtocol.udp

    #: - [TCP] Canditv Message Service
    #: - [UDP] Canditv Message Service
    canditv = 24676, 'canditv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FlashFiler
    #: - [UDP] FlashFiler
    flashfiler = 24677, 'flashfiler', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Turbopower Proactivate
    #: - [UDP] Turbopower Proactivate
    proactivate = 24678, 'proactivate', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TCC User HTTP Service
    #: - [UDP] TCC User HTTP Service
    tcc_http = 24680, 'tcc-http', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_24754 = 24754, 'reserved', TransportProtocol.udp

    #: [UDP] Device Association Discovery
    assoc_disc = 24850, 'assoc-disc', TransportProtocol.udp

    #: - [TCP] Find Identification of Network Devices
    #: - [UDP] Find Identification of Network Devices
    find = 24922, 'find', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase1
    #: - [UDP] icl-twobase1
    icl_twobase1 = 25000, 'icl-twobase1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase2
    #: - [UDP] icl-twobase2
    icl_twobase2 = 25001, 'icl-twobase2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase3
    #: - [UDP] icl-twobase3
    icl_twobase3 = 25002, 'icl-twobase3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase4
    #: - [UDP] icl-twobase4
    icl_twobase4 = 25003, 'icl-twobase4', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase5
    #: - [UDP] icl-twobase5
    icl_twobase5 = 25004, 'icl-twobase5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase6
    #: - [UDP] icl-twobase6
    icl_twobase6 = 25005, 'icl-twobase6', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase7
    #: - [UDP] icl-twobase7
    icl_twobase7 = 25006, 'icl-twobase7', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase8
    #: - [UDP] icl-twobase8
    icl_twobase8 = 25007, 'icl-twobase8', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase9
    #: - [UDP] icl-twobase9
    icl_twobase9 = 25008, 'icl-twobase9', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] icl-twobase10
    #: - [UDP] icl-twobase10
    icl_twobase10 = 25009, 'icl-twobase10', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_25100 = 25100, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_25576 = 25576, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_25604 = 25604, 'reserved', TransportProtocol.udp

    #: - [TCP] Vocaltec Address Server
    #: - [UDP] Vocaltec Address Server
    vocaltec_hos = 25793, 'vocaltec-hos', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TASP Network Comm
    #: - [UDP] TASP Network Comm
    tasp_net = 25900, 'tasp-net', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NIObserver
    #: - [UDP] NIObserver
    niobserver = 25901, 'niobserver', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NILinkAnalyst
    #: - [UDP] NILinkAnalyst
    nilinkanalyst = 25902, 'nilinkanalyst', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NIProbe
    #: - [UDP] NIProbe
    niprobe = 25903, 'niprobe', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Bitfighter game server
    bf_game = 25954, 'bf-game', TransportProtocol.udp

    #: [UDP] Bitfighter master server
    bf_master = 25955, 'bf-master', TransportProtocol.udp

    #: - [TCP] quake
    #: - [UDP] quake
    quake = 26000, 'quake', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Symbolic Computation Software Composability Protocol
    #: - [UDP] Symbolic Computation Software Composability Protocol
    scscp = 26133, 'scscp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] wnn6-ds
    #: - [UDP] wnn6-ds
    wnn6_ds = 26208, 'wnn6-ds', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_26257 = 26257, 'reserved', TransportProtocol.udp

    #: - [TCP] eZproxy
    #: - [UDP] eZproxy
    ezproxy = 26260, 'ezproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] eZmeeting
    #: - [UDP] eZmeeting
    ezmeeting = 26261, 'ezmeeting', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] K3 Software-Server
    #: - [UDP] K3 Software-Server
    k3software_svr = 26262, 'k3software-svr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] K3 Software-Client
    #: - [UDP] K3 Software-Client
    k3software_cli = 26263, 'k3software-cli', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] EXOline-UDP
    exoline_udp = 26486, 'exoline-udp', TransportProtocol.udp

    #: - [TCP] EXOconfig
    #: - [UDP] EXOconfig
    exoconfig = 26487, 'exoconfig', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] EXOnet
    #: - [UDP] EXOnet
    exonet = 26489, 'exonet', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_27010 = 27010, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_27016 = 27016, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_27017 = 27017, 'reserved', TransportProtocol.udp

    #: - [TCP] ImagePump
    #: - [UDP] ImagePump
    imagepump = 27345, 'imagepump', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Job controller service
    #: - [UDP] Job controller service
    jesmsjc = 27442, 'jesmsjc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Kopek HTTP Head Port
    #: - [UDP] Kopek HTTP Head Port
    kopek_httphead = 27504, 'kopek-httphead', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ARS VISTA Application
    #: - [UDP] ARS VISTA Application
    ars_vista = 27782, 'ars-vista', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_27876 = 27876, 'reserved', TransportProtocol.udp

    #: - [TCP] TW Authentication/Key Distribution and
    #: - [UDP] Attribute Certificate Services
    tw_auth_key = 27999, 'tw-auth-key', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NX License Manager
    #: - [UDP] NX License Manager
    nxlmd = 28000, 'nxlmd', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_28001 = 28001, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_28010 = 28010, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_28080 = 28080, 'reserved', TransportProtocol.udp

    #: [UDP] A27 cdma2000 RAN Management
    a27_ran_ran = 28119, 'a27-ran-ran', TransportProtocol.udp

    #: - [TCP] VoxelStorm game server
    #: - [UDP] VoxelStorm game server
    voxelstorm = 28200, 'voxelstorm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Siemens GSM
    #: - [UDP] Siemens GSM
    siemensgsm = 28240, 'siemensgsm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_28589 = 28589, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_29000 = 29000, 'reserved', TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_29118 = 29118, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ObTools Message Protocol
    #: - [UDP] ObTools Message Protocol
    otmp = 29167, 'otmp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_29168 = 29168, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_29999 = 29999, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_30000 = 30000, 'reserved', TransportProtocol.udp

    #: - [TCP] Pago Services 1
    #: - [UDP] Pago Services 1
    pago_services1 = 30001, 'pago-services1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Pago Services 2
    #: - [UDP] Pago Services 2
    pago_services2 = 30002, 'pago-services2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Amicon FPSU-IP Remote Administration
    #: - [UDP] Amicon FPSU-IP Remote Administration
    amicon_fpsu_ra = 30003, 'amicon-fpsu-ra', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Amicon FPSU-IP VPN
    amicon_fpsu_s = 30004, 'amicon-fpsu-s', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_30100 = 30100, 'reserved', TransportProtocol.udp

    #: - [TCP] Kingdoms Online (CraigAvenue)
    #: - [UDP] Kingdoms Online (CraigAvenue)
    kingdomsonline = 30260, 'kingdomsonline', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_30400 = 30400, 'reserved', TransportProtocol.udp

    #: [UDP] Samsung Convergence Discovery Protocol
    samsung_disc = 30832, 'samsung-disc', TransportProtocol.udp

    #: - [TCP] Persistent peer-to-peer connections for block propagation, transaction
    #:   relay, and BFT consensus message exchange.
    #: - [UDP] Kademlia DHT peer discovery and routing table maintenance.
    dilithium3 = 30939, 'dilithium3', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] OpenView Service Desk Client
    #: - [UDP] OpenView Service Desk Client
    ovobs = 30999, 'ovobs', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Kollective Agent Kollective Delivery Protocol
    ka_kdp = 31016, 'ka-kdp', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_31020 = 31020, 'reserved', TransportProtocol.udp

    #: [UDP] YaWN - Yet Another Windows Notifier
    yawn = 31029, 'yawn', TransportProtocol.udp

    #: - [TCP] eldim is a secure file upload proxy
    #: - [UDP] eldim is a secure file upload proxy
    eldim = 31337, 'eldim', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_31400 = 31400, 'reserved', TransportProtocol.udp

    #: - [TCP] XQoS network monitor
    #: - [UDP] XQoS network monitor
    xqosd = 31416, 'xqosd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] TetriNET Protocol
    #: - [UDP] TetriNET Protocol
    tetrinet = 31457, 'tetrinet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] lm mon
    #: - [UDP] lm mon
    lm_mon = 31620, 'lm-mon', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_31685 = 31685, 'reserved', TransportProtocol.udp

    #: - [TCP] GameSmith Port
    #: - [UDP] GameSmith Port
    gamesmith_port = 31765, 'gamesmith-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Embedded Device Configuration Protocol TX IANA assigned this well-
    #:   formed service name as a replacement for "iceedcp_tx".
    #: - [TCP] Embedded Device Configuration Protocol TX
    #: - [UDP] Embedded Device Configuration Protocol TX IANA assigned this well-
    #:   formed service name as a replacement for "iceedcp_tx".
    #: - [UDP] Embedded Device Configuration Protocol TX
    iceedcp_tx = 31948, 'iceedcp-tx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Embedded Device Configuration Protocol RX IANA assigned this well-
    #:   formed service name as a replacement for "iceedcp_rx".
    #: - [TCP] Embedded Device Configuration Protocol RX
    #: - [UDP] Embedded Device Configuration Protocol RX IANA assigned this well-
    #:   formed service name as a replacement for "iceedcp_rx".
    #: - [UDP] Embedded Device Configuration Protocol RX
    iceedcp_rx = 31949, 'iceedcp-rx', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iRacing helper service
    #: - [UDP] iRacing helper service
    iracinghelper = 32034, 'iracinghelper', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] T1 Distributed Processor
    #: - [UDP] T1 Distributed Processor
    t1distproc60 = 32249, 't1distproc60', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_32400 = 32400, 'reserved', TransportProtocol.udp

    #: - [TCP] Access Point Manager Link
    #: - [UDP] Access Point Manager Link
    apm_link = 32483, 'apm-link', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SecureNotebook-CLNT
    #: - [UDP] SecureNotebook-CLNT
    sec_ntb_clnt = 32635, 'sec-ntb-clnt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DMExpress
    #: - [UDP] DMExpress
    dmexpress = 32636, 'dmexpress', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileNet BPM WS-ReliableMessaging Client
    #: - [UDP] FileNet BPM WS-ReliableMessaging Client
    filenet_powsrm = 32767, 'filenet-powsrm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Filenet TMS
    #: - [UDP] Filenet TMS
    filenet_tms = 32768, 'filenet-tms', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Filenet RPC
    #: - [UDP] Filenet RPC
    filenet_rpc = 32769, 'filenet-rpc', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Filenet NCH
    #: - [UDP] Filenet NCH
    filenet_nch = 32770, 'filenet-nch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileNET RMI
    #: - [UDP] FileNet RMI
    filenet_rmi = 32771, 'filenet-rmi', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileNET Process Analyzer
    #: - [UDP] FileNET Process Analyzer
    filenet_pa = 32772, 'filenet-pa', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileNET Component Manager
    #: - [UDP] FileNET Component Manager
    filenet_cm = 32773, 'filenet-cm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileNET Rules Engine
    #: - [UDP] FileNET Rules Engine
    filenet_re = 32774, 'filenet-re', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Performance Clearinghouse
    #: - [UDP] Performance Clearinghouse
    filenet_pch = 32775, 'filenet-pch', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileNET BPM IOR
    #: - [UDP] FileNET BPM IOR
    filenet_peior = 32776, 'filenet-peior', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] FileNet BPM CORBA
    #: - [UDP] FileNet BPM CORBA
    filenet_obrok = 32777, 'filenet-obrok', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Multiple Listing Service Network
    #: - [UDP] Multiple Listing Service Network
    mlsn = 32801, 'mlsn', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_32811 = 32811, 'reserved', TransportProtocol.udp

    #: - [TCP] Attachmate ID Manager
    #: - [UDP] Attachmate ID Manager
    idmgratm = 32896, 'idmgratm', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_33000 = 33000, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_33060 = 33060, 'reserved', TransportProtocol.udp

    #: - [TCP] Aurora (Balaena Ltd)
    #: - [UDP] Aurora (Balaena Ltd)
    aurora_balaena = 33123, 'aurora-balaena', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] DiamondCentral Interface
    #: - [UDP] DiamondCentral Interface
    diamondport = 33331, 'diamondport', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_33333 = 33333, 'reserved', TransportProtocol.udp

    #: [UDP] SpeedTrace TraceAgent Discovery
    speedtrace_disc = 33334, 'speedtrace-disc', TransportProtocol.udp

    #: - [TCP] traceroute use
    #: - [UDP] traceroute use
    traceroute = 33434, 'traceroute', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] IP Multicast Traceroute [:rfc:`8487`]
    mtrace = 33435, 'mtrace', TransportProtocol.udp

    #: - [TCP] SNIP Slave
    #: - [UDP] SNIP Slave
    snip_slave = 33656, 'snip-slave', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_33890 = 33890, 'reserved', TransportProtocol.udp

    #: - [TCP] TurboNote Relay Server Default Port
    #: - [UDP] TurboNote Relay Server Default Port
    turbonote_2 = 34249, 'turbonote-2', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] P-Net on IP local
    #: - [UDP] P-Net on IP local
    p_net_local = 34378, 'p-net-local', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] P-Net on IP remote
    #: - [UDP] P-Net on IP remote
    p_net_remote = 34379, 'p-net-remote', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] dhanalakshmi.org EDI Service
    edi_service = 34567, 'edi_service', TransportProtocol.udp

    #: - [TCP] PROFInet RT Unicast
    #: - [UDP] PROFInet RT Unicast
    profinet_rt = 34962, 'profinet-rt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PROFInet RT Multicast
    #: - [UDP] PROFInet RT Multicast
    profinet_rtm = 34963, 'profinet-rtm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PROFInet Context Manager
    #: - [UDP] PROFInet Context Manager
    profinet_cm = 34964, 'profinet-cm', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PROFINET secure connection management and key provisioning
    #: - [UDP] PROFINET secure connection management and key provisioning
    profinet_cm_sec = 34965, 'profinet-cm-sec', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] PROFINET secure real-time data transfer over UDP (unicast and
    #: multicast)
    profinet_rt_sec = 34966, 'profinet-rt-sec', TransportProtocol.udp

    #: - [TCP] EtherCAT Port
    #: - [UDP] EtherCAT Port
    ethercat = 34980, 'ethercat', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_35000 = 35000, 'reserved', TransportProtocol.udp

    #: - [TCP] ReadyTech Viewer
    #: - [UDP] ReadyTech Viewer
    rt_viewer = 35001, 'rt-viewer', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_35002 = 35002, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_35003 = 35003, 'reserved', TransportProtocol.udp

    #: - [TCP] ReadyTech ClassManager
    #: - [UDP] ReadyTech ClassManager
    rt_classmanager = 35004, 'rt-classmanager', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_35005 = 35005, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_35006 = 35006, 'reserved', TransportProtocol.udp

    #: - [TCP] Axiomatic discovery protocol
    #: - [UDP] Axiomatic discovery protocol
    axio_disc = 35100, 'axio-disc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_35354 = 35354, 'reserved', TransportProtocol.udp

    #: [UDP] Altova License Management Discovery
    altova_lm_disc = 35355, 'altova-lm-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_35356 = 35356, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_35357 = 35357, 'reserved', TransportProtocol.udp

    #: - [TCP] AllPeers Network
    #: - [UDP] AllPeers Network
    allpeers = 36001, 'allpeers', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Wireless LAN Control plane Protocol (WLCP)
    wlcp = 36411, 'wlcp', TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_36412 = 36412, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_36422 = 36422, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_36462 = 36462, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_36524 = 36524, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_36602 = 36602, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_36700 = 36700, 'reserved', TransportProtocol.udp

    #: - [TCP] KastenX Pipe
    #: - [UDP] KastenX Pipe
    kastenxpipe = 36865, 'kastenxpipe', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_37472 = 37472, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] science + computing's Venus Administration Port
    #: - [UDP] science + computing's Venus Administration Port
    neckar = 37475, 'neckar', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_37483 = 37483, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_37601 = 37601, 'reserved', TransportProtocol.udp

    #: - [TCP] Unisys ClearPath ePortal
    #: - [UDP] Unisys ClearPath ePortal
    unisys_eportal = 37654, 'unisys-eportal', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_38000 = 38000, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_38001 = 38001, 'reserved', TransportProtocol.udp

    #: [UDP] Cresco Controller Discovery
    crescoctrl_disc = 38002, 'crescoctrl-disc', TransportProtocol.udp

    #: - [TCP] Galaxy7 Data Tunnel
    #: - [UDP] Galaxy7 Data Tunnel
    galaxy7_data = 38201, 'galaxy7-data', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Fairview Message Service
    #: - [UDP] Fairview Message Service
    fairview = 38202, 'fairview', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] AppGate Policy Server
    #: - [UDP] AppGate Policy Server
    agpolicy = 38203, 'agpolicy', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_38412 = 38412, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_38422 = 38422, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_38462 = 38462, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Reserved
    #: - [UDP] Reserved
    reserved_38472 = 38472, 'reserved', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_38638 = 38638, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_38800 = 38800, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_38865 = 38865, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_39063 = 39063, 'reserved', TransportProtocol.udp

    #: - [TCP] TurboNote Default Port
    #: - [UDP] TurboNote Default Port
    turbonote_1 = 39681, 'turbonote-1', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SafetyNET p
    #: - [UDP] SafetyNET p
    safetynetp = 40000, 'safetynetp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] K-PatentsSensorInformation
    k_patentssensor = 40023, 'k-patentssensor', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_40404 = 40404, 'reserved', TransportProtocol.udp

    #: - [TCP] CSCP
    #: - [UDP] CSCP
    cscp = 40841, 'cscp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSCCREDIR
    #: - [UDP] CSCCREDIR
    csccredir = 40842, 'csccredir', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CSCCFIREWALL
    #: - [UDP] CSCCFIREWALL
    csccfirewall = 40843, 'csccfirewall', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] ORTEC Service Discovery
    ortec_disc = 40853, 'ortec-disc', TransportProtocol.udp

    #: - [TCP] Foursticks QoS Protocol
    #: - [UDP] Foursticks QoS Protocol
    fs_qos = 41111, 'fs-qos', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_41121 = 41121, 'reserved', TransportProtocol.udp

    #: - [TCP] Z-Wave Protocol over SSL/TLS
    #: - [UDP] Z-Wave Protocol over DTLS
    z_wave_s = 41230, 'z-wave-s', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Crestron Control Port
    #: - [UDP] Crestron Control Port
    crestron_cip = 41794, 'crestron-cip', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Crestron Terminal Port
    #: - [UDP] Crestron Terminal Port
    crestron_ctp = 41795, 'crestron-ctp', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_41796 = 41796, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_41797 = 41797, 'reserved', TransportProtocol.udp

    #: - [TCP] Computer Associates network discovery protocol
    #: - [UDP] Computer Associates network discovery protocol
    candp = 42508, 'candp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA discovery response
    #: - [UDP] CA discovery response
    candrp = 42509, 'candrp', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] CA eTrust RPC
    #: - [UDP] CA eTrust RPC
    caerpc = 42510, 'caerpc', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_42999 = 42999, 'reserved', TransportProtocol.udp

    #: [UDP] Receiver Remote Control Discovery
    recvr_rc_disc = 43000, 'recvr-rc-disc', TransportProtocol.udp

    #: - [TCP] REACHOUT
    #: - [UDP] REACHOUT
    reachout = 43188, 'reachout', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] NDM-AGENT-PORT
    #: - [UDP] NDM-AGENT-PORT
    ndm_agent_port = 43189, 'ndm-agent-port', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] IP-PROVISION
    #: - [UDP] IP-PROVISION
    ip_provision = 43190, 'ip-provision', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_43191 = 43191, 'reserved', TransportProtocol.udp

    #: [UDP] Shaper Automation Server Management Discovery
    shaperai_disc = 43210, 'shaperai-disc', TransportProtocol.udp

    #: [UDP] HmIP LAN Routing
    hmip_routing = 43438, 'hmip-routing', TransportProtocol.udp

    #: [UDP] EQ3 discovery and configuration
    eq3_config = 43439, 'eq3-config', TransportProtocol.udp

    #: [UDP] Cisco EnergyWise Discovery and Command Flooding
    ew_disc_cmd = 43440, 'ew-disc-cmd', TransportProtocol.udp

    #: - [TCP] Cisco NetMgmt DB Ports
    #: - [UDP] Cisco NetMgmt DB Ports
    ciscocsdb = 43441, 'ciscocsdb', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_44123 = 44123, 'reserved', TransportProtocol.udp

    #: - [TCP] PCP server (pmcd)
    #: - [UDP] PCP server (pmcd)
    pmcd = 44321, 'pmcd', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] PCP proxy (pmproxy)
    #: - [UDP] PCP proxy (pmproxy)
    pmproxy = 44322, 'pmproxy', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Unassigned
    unassigned_44323 = 44323, 'unassigned', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_44444 = 44444, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_44445 = 44445, 'reserved', TransportProtocol.udp

    #: [UDP] DOMIQ Building Automation
    domiq = 44544, 'domiq', TransportProtocol.udp

    #: - [TCP] REALbasic Remote Debug
    #: - [UDP] REALbasic Remote Debug
    rbr_debug = 44553, 'rbr-debug', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] AudioScience HPI
    asihpi = 44600, 'asihpi', TransportProtocol.udp

    #: - [TCP] EtherNet/IP messaging IANA assigned this well-formed service name as a
    #:   replacement for "EtherNet/IP-2".
    #: - [TCP] EtherNet/IP messaging
    #: - [UDP] EtherNet/IP messaging IANA assigned this well-formed service name as a
    #:   replacement for "EtherNet/IP-2".
    #: - [UDP] EtherNet/IP messaging
    ethernet_ip_2 = 44818, 'ethernet-ip-2', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] M3DA Discovery is used for efficient machine-to-machine communications
    m3da_disc = 44900, 'm3da-disc', TransportProtocol.udp

    #: [UDP] Nuance AutoStore Status Monitoring Protocol (device monitoring)
    asmp_mon = 45000, 'asmp-mon', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_45001 = 45001, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_45002 = 45002, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_45045 = 45045, 'reserved', TransportProtocol.udp

    #: - [TCP] InVision AG
    #: - [UDP] InVision AG
    invision_ag = 45054, 'invision-ag', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Wire and Wireless transfer on synchroniz
    #: - [UDP] Wire and Wireless transfer on synchroniz
    witsnet = 45185, 'witsnet', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] ASSIA CloudCheck WiFi Management keepalive
    cloudcheck_ping = 45514, 'cloudcheck-ping', TransportProtocol.udp

    #: - [TCP] EBA PRISE
    #: - [UDP] EBA PRISE
    eba = 45678, 'eba', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_45824 = 45824, 'reserved', TransportProtocol.udp

    #: - [TCP] Qpuncture Data Access Service
    #: - [UDP] Qpuncture Data Access Service
    qdb2service = 45825, 'qdb2service', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SSRServerMgr
    #: - [UDP] SSRServerMgr
    ssr_servermgr = 45966, 'ssr-servermgr', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_46336 = 46336, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_46998 = 46998, 'reserved', TransportProtocol.udp

    #: - [TCP] MediaBox Server
    #: - [UDP] MediaBox Server
    mediabox = 46999, 'mediabox', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message Bus
    #: - [UDP] Message Bus
    mbus = 47000, 'mbus', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_47001 = 47001, 'reserved', TransportProtocol.udp

    #: [UDP] Configuration of motors connected to Industrial Ethernet
    jvl_mactalk = 47100, 'jvl-mactalk', TransportProtocol.udp

    #: - [TCP] Databeam Corporation
    #: - [UDP] Databeam Corporation
    dbbrowse = 47557, 'dbbrowse', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Direct Play Server
    #: - [UDP] Direct Play Server
    directplaysrvr = 47624, 'directplaysrvr', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] ALC Protocol
    #: - [UDP] ALC Protocol
    ap = 47806, 'ap', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Building Automation and Control Networks
    #: - [UDP] Building Automation and Control Networks
    bacnet = 47808, 'bacnet', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] PreSonus Universal Control Network Protocol
    presonus_ucnet = 47809, 'presonus-ucnet', TransportProtocol.udp

    #: - [TCP] Nimbus Controller
    #: - [UDP] Nimbus Controller
    nimcontroller = 48000, 'nimcontroller', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nimbus Spooler
    #: - [UDP] Nimbus Spooler
    nimspooler = 48001, 'nimspooler', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nimbus Hub
    #: - [UDP] Nimbus Hub
    nimhub = 48002, 'nimhub', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Nimbus Gateway
    #: - [UDP] Nimbus Gateway
    nimgtw = 48003, 'nimgtw', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_48004 = 48004, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_48005 = 48005, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_48048 = 48048, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_48049 = 48049, 'reserved', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_48050 = 48050, 'reserved', TransportProtocol.udp

    #: - [TCP] Image Systems Network Services
    #: - [UDP] Image Systems Network Services
    isnetserv = 48128, 'isnetserv', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Bloomberg locator
    #: - [UDP] Bloomberg locator
    blp5 = 48129, 'blp5', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] com-bardac-dw
    #: - [UDP] com-bardac-dw
    com_bardac_dw = 48556, 'com-bardac-dw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] iqobject
    #: - [UDP] iqobject
    iqobject = 48619, 'iqobject', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Robot Raconteur transport
    #: - [UDP] Robot Raconteur transport
    robotraconteur = 48653, 'robotraconteur', TransportProtocol.tcp | TransportProtocol.udp

    #: [UDP] Reserved
    reserved_49000 = 49000, 'reserved', TransportProtocol.udp

    #: [UDP] Nuance Unity Service Discovery Protocol
    nusdp_disc = 49001, 'nusdp-disc', TransportProtocol.udp

    #: [UDP] Reserved
    reserved_49150 = 49150, 'reserved', TransportProtocol.udp

    #: - [TCP] http protocol over TLS/SSL [:rfc:`9110`]
    #: - [UDP] http protocol over TLS/SSL [:rfc:`9110`]
    #: - [SCTP] HTTPS [:rfc:`9260`]
    https_443 = 443, 'https', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] LonWorks
    #: - [UDP] LonWorks
    lonworks_2540 = 2540, 'lonworks', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Message Queuing Telemetry Transport Protocol
    #: - [UDP] Message Queuing Telemetry Transport Protocol
    mqtt_1883 = 1883, 'mqtt', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] XMPP Link-Local Messaging
    #: - [UDP] XMPP Link-Local Messaging
    presence_5298 = 5298, 'presence', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Profile for Mac
    #: - [UDP] Profile for Mac
    profilemac_4749 = 4749, 'profilemac', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Retrospect backup and restore service
    #: - [UDP] Retrospect backup and restore service
    retrospect_497 = 497, 'retrospect', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCPI-RAW
    #: - [UDP] SCPI-RAW
    scpi_raw_5025 = 5025, 'scpi-raw', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] SCPI-TELNET
    #: - [UDP] SCPI-TELNET
    scpi_telnet_5024 = 5024, 'scpi-telnet', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Grid Engine Qmaster Service IANA assigned this well-formed service
    #:   name as a replacement for "sge_qmaster".
    #: - [TCP] Grid Engine Qmaster Service
    #: - [UDP] Grid Engine Qmaster Service IANA assigned this well-formed service
    #:   name as a replacement for "sge_qmaster".
    #: - [UDP] Grid Engine Qmaster Service
    sge_qmaster_6444 = 6444, 'sge-qmaster', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] The Secure Shell (SSH) Protocol [:rfc:`4251`]
    #: - [UDP] The Secure Shell (SSH) Protocol [:rfc:`4251`]
    #: - [SCTP] SSH [:rfc:`9260`]
    ssh_22 = 22, 'ssh', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp

    #: - [TCP] Subversion
    #: - [UDP] Subversion
    svn_3690 = 3690, 'svn', TransportProtocol.tcp | TransportProtocol.udp

    #: - [TCP] Z-Wave Protocol
    #: - [UDP] Z-Wave Protocol
    z_wave_4123 = 4123, 'z-wave', TransportProtocol.tcp | TransportProtocol.udp
