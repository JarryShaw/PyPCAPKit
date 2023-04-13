# -*- coding: utf-8 -*-
"""data models for application layer protocols"""

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
from pcapkit.protocols.data.application.httpv2 import SettingsFrame as HTTPv2_SettingsFrame
from pcapkit.protocols.data.application.httpv2 import \
    SettingsFrameFlags as HTTPv2_SettingsFrameFlags
from pcapkit.protocols.data.application.httpv2 import UnassignedFrame as HTTPv2_UnassignedFrame
from pcapkit.protocols.data.application.httpv2 import WindowUpdateFrame as HTTPv2_WindowUpdateFrame

__all__ = [
    # File Transfer Protocol
    'FTP',
    'FTP_Request', 'FTP_Response',

    # Hypertext Transfer Protocol (HTTP/1.*)
    'HTTPv1',
    'HTTPv1_Header',
    'HTTPv1_RequestHeader', 'HTTPv1_ResponseHeader',

    # Hypertext Transfer Protocol (HTTP/2)
    'HTTPv2',
    'HTTPv2_Flags',
    'HTTPv2_DataFrameFlags', 'HTTPv2_HeadersFrameFlags', 'HTTPv2_SettingsFrameFlags',
    'HTTPv2_PushPromiseFrameFlags', 'HTTPv2_PingFrameFlags', 'HTTPv2_ContinuationFrameFlags',
    'HTTPv2_UnassignedFrame', 'HTTPv2_DataFrame', 'HTTPv2_HeadersFrame', 'HTTPv2_PriorityFrame',
    'HTTPv2_RSTStreamFrame', 'HTTPv2_SettingsFrame', 'HTTPv2_PushPromiseFrame', 'HTTPv2_PingFrame',
    'HTTPv2_GoawayFrame', 'HTTPv2_WindowUpdateFrame', 'HTTPv2_ContinuationFrame',
]
