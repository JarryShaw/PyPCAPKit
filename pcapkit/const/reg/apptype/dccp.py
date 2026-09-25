# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Application Layer Protocol Numbers (DCCP)
===============================================

.. module:: pcapkit.const.reg.apptype.dccp

This module contains the constant enumeration for **Application Layer Protocol Numbers (DCCP)**,
which is automatically generated from :class:`pcapkit.vendor.reg.apptype.dccp.DCCP`.

"""
from pcapkit.const.reg.apptype.apptype import AppType, TransportProtocol
from pcapkit.corekit.multidict import MultiDict

__all__ = ['DCCP']


class DCCP(AppType):
    """[DCCP] Application Layer Protocol Numbers (DCCP)

    Members carry the **whole** transport protocol set IANA assigned the service,
    not just ``dccp``, so a service registered on several transports appears in
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
       * - ``dccp-ping``
         - [DCCP] ping/traceroute using DCCP

    """

    #: Transport protocol whose assignments this registry holds.
    __transport__: 'TransportProtocol' = TransportProtocol.dccp

    #: Members of this registry, keyed on port number. Declared per registry
    #: rather than inherited, since one mapping shared by all four would put
    #: every transport's ports in the same key space.
    __registry__: 'MultiDict[int, DCCP]' = MultiDict()

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
    discard = 9, 'discard', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp | TransportProtocol.dccp

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

    #: - [TCP] Licklider Transmission Protocol [:rfc:`5326`]
    #: - [UDP] Licklider Transmission Protocol [:rfc:`5326`][:rfc:`7122`]
    #: - [DCCP] Licklider Transmission Protocol [:rfc:`7122`]
    ltp_deepspace = 1113, 'ltp-deepspace', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [TCP] AWS protocol for cloud remoting solution
    #: - [UDP] AWS protocol for cloud remoting solution
    #: - [SCTP] AWS protocol for cloud remoting solution
    #: - [DCCP] AWS protocol for cloud remoting solution
    aws_wsp = 4195, 'aws-wsp', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp | TransportProtocol.dccp

    #: - [TCP] DTN Bundle TCP CL Protocol [:rfc:`9174`]
    #: - [UDP] DTN Bundle UDP CL Protocol [:rfc:`7122`]
    #: - [DCCP] DTN Bundle DCCP CL Protocol [:rfc:`7122`]
    dtn_bundle = 4556, 'dtn-bundle', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [TCP] RTP media data [:rfc:`3551`][:rfc:`4571`]
    #: - [UDP] RTP media data [:rfc:`3551`]
    #: - [DCCP] RTP media data [:rfc:`3551`][:rfc:`5762`]
    avt_profile_1 = 5004, 'avt-profile-1', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [TCP] RTP control protocol [:rfc:`3551`][:rfc:`4571`]
    #: - [UDP] RTP control protocol [:rfc:`3551`]
    #: - [DCCP] RTP control protocol [:rfc:`3551`][:rfc:`5762`]
    avt_profile_2 = 5005, 'avt-profile-2', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [TCP] Syslog over TLS [:rfc:`5425`]
    #: - [UDP] syslog over DTLS [:rfc:`6012`]
    #: - [DCCP] syslog over DTLS [:rfc:`6012`]
    syslog_tls = 6514, 'syslog-tls', TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.dccp

    #: - [SCTP] Reserved
    #: - [DCCP] Reserved
    reserved_8282 = 8282, 'reserved', TransportProtocol.sctp | TransportProtocol.dccp
