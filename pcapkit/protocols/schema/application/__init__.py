# -*- coding: utf-8 -*-
"""header schema for application layer protocols"""

# File Transfer Protocol
from pcapkit.protocols.schema.application.ftp import FTP

# Hypertext Transfer Protocol (HTTP/1.*)
from pcapkit.protocols.schema.application.httpv1 import HTTP as HTTPv1

# Hypertext Transfer Protocol (HTTP/2)
from pcapkit.protocols.schema.application.httpv2 import HTTP as HTTPv2
from pcapkit.protocols.schema.application.httpv2 import \
    ContinuationFrame as HTTPv2_ContinuationFrame
from pcapkit.protocols.schema.application.httpv2 import DataFrame as HTTPv2_DataFrame
from pcapkit.protocols.schema.application.httpv2 import FrameType as HTTPv2_FrameType
from pcapkit.protocols.schema.application.httpv2 import GoawayFrame as HTTPv2_GoawayFrame
from pcapkit.protocols.schema.application.httpv2 import HeadersFrame as HTTPv2_HeadersFrame
from pcapkit.protocols.schema.application.httpv2 import PingFrame as HTTPv2_PingFrame
from pcapkit.protocols.schema.application.httpv2 import PriorityFrame as HTTPv2_PriorityFrame
from pcapkit.protocols.schema.application.httpv2 import PushPromiseFrame as HTTPv2_PushPromiseFrame
from pcapkit.protocols.schema.application.httpv2 import RSTStreamFrame as HTTPv2_RSTStreamFrame
from pcapkit.protocols.schema.application.httpv2 import SettingsFrame as HTTPv2_SettingsFrame
from pcapkit.protocols.schema.application.httpv2 import UnassignedFrame as HTTPv2_UnassignedFrame
from pcapkit.protocols.schema.application.httpv2 import \
    WindowUpdateFrame as HTTPv2_WindowUpdateFrame

__all__ = [
    # File Transfer Protocol
    'FTP',

    # Hypertext Transfer Protocol (HTTP/1.*)
    'HTTPv1',

    # Hypertext Transfer Protocol (HTTP/2)
    'HTTPv2',
    'HTTPv2_FrameType',
    'HTTPv2_UnassignedFrame', 'HTTPv2_DataFrame', 'HTTPv2_HeadersFrame', 'HTTPv2_PriorityFrame',
    'HTTPv2_RSTStreamFrame', 'HTTPv2_SettingsFrame', 'HTTPv2_PushPromiseFrame', 'HTTPv2_PingFrame',
    'HTTPv2_GoawayFrame', 'HTTPv2_WindowUpdateFrame', 'HTTPv2_ContinuationFrame',
]
