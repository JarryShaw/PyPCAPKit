# -*- coding: utf-8 -*-
"""constants for datagram congestion control protocol

.. versionadded:: 1.7.0

"""

from pcapkit.const.dccp.packet_type import PacketType as Enum_PacketType

__all__ = [
    'DCCP_MIN_HEADER_LEN', 'DCCP_MAX_HEADER_LEN', 'DCCP_SINGLE_OCTET_OPTION_MAX',
    'ACK_TYPES', 'SERVICE_TYPES', 'RESET_TYPE',
]

#: Length of the generic header with 24-bit sequence numbers (``X`` clear), the
#: shortest a DCCP header can be, :rfc:`4340#section-5.1`. The one home of this
#: value (:issue:`1739`); it is fixed by the RFC, so it is never configurable.
DCCP_MIN_HEADER_LEN = 12

#: Longest a DCCP header can be -- a Data Offset of 255 words, :rfc:`4340#section-5`.
DCCP_MAX_HEADER_LEN = 1020

#: Option types up to this one are single octets, without a length,
#: :rfc:`4340#section-5.8`.
DCCP_SINGLE_OCTET_OPTION_MAX = 31

#: Packet types carrying an Acknowledgement Number Subheader -- every one
#: :rfc:`4340#section-5` defines but DCCP-Request and DCCP-Data. DCCP-Listen
#: (:rfc:`5596#section-2.2.1`) carries none either.
ACK_TYPES = frozenset({
    Enum_PacketType.DCCP_Response, Enum_PacketType.DCCP_Ack, Enum_PacketType.DCCP_DataAck,
    Enum_PacketType.DCCP_CloseReq, Enum_PacketType.DCCP_Close, Enum_PacketType.DCCP_Reset,
    Enum_PacketType.DCCP_Sync, Enum_PacketType.DCCP_SyncAck,
})

#: Packet types carrying a Service Code -- DCCP-Request, DCCP-Response and
#: DCCP-Listen (:rfc:`4340#section-5.2`, :rfc:`5596#section-2.2.1`).
SERVICE_TYPES = frozenset({
    Enum_PacketType.DCCP_Request, Enum_PacketType.DCCP_Response, Enum_PacketType.DCCP_Listen,
})

#: Packet type of DCCP-Reset, which carries a Reset Code and three Data octets,
#: :rfc:`4340#section-5.6`.
RESET_TYPE = Enum_PacketType.DCCP_Reset
