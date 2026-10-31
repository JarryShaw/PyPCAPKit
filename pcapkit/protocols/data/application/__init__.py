# -*- coding: utf-8 -*-
"""data models for application layer protocols"""

# Datagram Transport Layer Security
from pcapkit.protocols.data.application.dtls import DTLS
from pcapkit.protocols.data.application.dtls import DTLSHandshake as DTLS_Handshake

# File Transfer Protocol
from pcapkit.protocols.data.application.ftp import FTP
from pcapkit.protocols.data.application.ftp import Request as FTP_Request
from pcapkit.protocols.data.application.ftp import Response as FTP_Response

# Hypertext Transfer Protocol (HTTP/1.*)
from pcapkit.protocols.data.application.httpv1 import HTTP as HTTPv1
from pcapkit.protocols.data.application.httpv1 import Header as HTTPv1_Header
from pcapkit.protocols.data.application.httpv1 import RequestHeader as HTTPv1_RequestHeader
from pcapkit.protocols.data.application.httpv1 import ResponseHeader as HTTPv1_ResponseHeader

# Hypertext Transfer Protocol (HTTP/2)
from pcapkit.protocols.data.application.httpv2 import HTTP as HTTPv2
from pcapkit.protocols.data.application.httpv2 import ContinuationFrame as HTTPv2_ContinuationFrame
from pcapkit.protocols.data.application.httpv2 import \
    ContinuationFrameFlags as HTTPv2_ContinuationFrameFlags
from pcapkit.protocols.data.application.httpv2 import DataFrame as HTTPv2_DataFrame
from pcapkit.protocols.data.application.httpv2 import DataFrameFlags as HTTPv2_DataFrameFlags
from pcapkit.protocols.data.application.httpv2 import Flags as HTTPv2_Flags
from pcapkit.protocols.data.application.httpv2 import GoawayFrame as HTTPv2_GoawayFrame
from pcapkit.protocols.data.application.httpv2 import HeadersFrame as HTTPv2_HeadersFrame
from pcapkit.protocols.data.application.httpv2 import HeadersFrameFlags as HTTPv2_HeadersFrameFlags
from pcapkit.protocols.data.application.httpv2 import PingFrame as HTTPv2_PingFrame
from pcapkit.protocols.data.application.httpv2 import PingFrameFlags as HTTPv2_PingFrameFlags
from pcapkit.protocols.data.application.httpv2 import PriorityFrame as HTTPv2_PriorityFrame
from pcapkit.protocols.data.application.httpv2 import PushPromiseFrame as HTTPv2_PushPromiseFrame
from pcapkit.protocols.data.application.httpv2 import \
    PushPromiseFrameFlags as HTTPv2_PushPromiseFrameFlags
from pcapkit.protocols.data.application.httpv2 import RSTStreamFrame as HTTPv2_RSTStreamFrame
from pcapkit.protocols.data.application.httpv2 import Settings as HTTPv2_Settings
from pcapkit.protocols.data.application.httpv2 import SettingsFrame as HTTPv2_SettingsFrame
from pcapkit.protocols.data.application.httpv2 import \
    SettingsFrameFlags as HTTPv2_SettingsFrameFlags
from pcapkit.protocols.data.application.httpv2 import UnassignedFrame as HTTPv2_UnassignedFrame
from pcapkit.protocols.data.application.httpv2 import WindowUpdateFrame as HTTPv2_WindowUpdateFrame

# NG Application Protocol
from pcapkit.protocols.data.application.ngap import IE as NGAP_IE
from pcapkit.protocols.data.application.ngap import NGAP
from pcapkit.protocols.data.application.ngap import BitString as NGAP_BitString
from pcapkit.protocols.data.application.ngap import Choice as NGAP_Choice
from pcapkit.protocols.data.application.ngap import Sequence as NGAP_Sequence

# Open Shortest Path First
from pcapkit.protocols.data.application.ospf import OSPF
from pcapkit.protocols.data.application.ospf import \
    CryptographicAuthentication as OSPF_CryptographicAuthentication

# Transport Layer Security
from pcapkit.protocols.data.application.tls import TLS
from pcapkit.protocols.data.application.tls import Alert as TLS_Alert
from pcapkit.protocols.data.application.tls import ChangeCipherSpec as TLS_ChangeCipherSpec
from pcapkit.protocols.data.application.tls import ClientHello as TLS_ClientHello
from pcapkit.protocols.data.application.tls import Extension as TLS_Extension
from pcapkit.protocols.data.application.tls import Handshake as TLS_Handshake
from pcapkit.protocols.data.application.tls import ServerHello as TLS_ServerHello

__all__ = [
    # Datagram Transport Layer Security
    'DTLS', 'DTLS_Handshake',

    # File Transfer Protocol
    'FTP',
    'FTP_Request', 'FTP_Response',

    # Hypertext Transfer Protocol (HTTP/1.*)
    'HTTPv1',
    'HTTPv1_Header',
    'HTTPv1_RequestHeader', 'HTTPv1_ResponseHeader',

    # Hypertext Transfer Protocol (HTTP/2)
    'HTTPv2',
    'HTTPv2_Flags', 'HTTPv2_Settings',
    'HTTPv2_DataFrameFlags', 'HTTPv2_HeadersFrameFlags', 'HTTPv2_SettingsFrameFlags',
    'HTTPv2_PushPromiseFrameFlags', 'HTTPv2_PingFrameFlags', 'HTTPv2_ContinuationFrameFlags',
    'HTTPv2_UnassignedFrame', 'HTTPv2_DataFrame', 'HTTPv2_HeadersFrame', 'HTTPv2_PriorityFrame',
    'HTTPv2_RSTStreamFrame', 'HTTPv2_SettingsFrame', 'HTTPv2_PushPromiseFrame', 'HTTPv2_PingFrame',
    'HTTPv2_GoawayFrame', 'HTTPv2_WindowUpdateFrame', 'HTTPv2_ContinuationFrame',

    # NG Application Protocol
    'NGAP',
    'NGAP_IE', 'NGAP_Choice', 'NGAP_BitString', 'NGAP_Sequence',

    # Open Shortest Path First
    'OSPF', 'OSPF_CryptographicAuthentication',

    # Transport Layer Security
    'TLS',
    'TLS_Handshake', 'TLS_ClientHello', 'TLS_ServerHello', 'TLS_Extension',
    'TLS_Alert', 'TLS_ChangeCipherSpec',
]
