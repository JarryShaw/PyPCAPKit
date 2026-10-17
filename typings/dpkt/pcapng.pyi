"""``dpkt.pcapng`` as of dpkt 1.9.8: the packet blocks."""
from . import dpkt

# dpkt derives these from a private ``_PcapngBlock``, itself a ``dpkt.Packet``
class EnhancedPacketBlock(dpkt.Packet):
    iface_id: int
    ts_high: int
    ts_low: int
    pkt_len: int
    pkt_data: bytes

class EnhancedPacketBlockLE(EnhancedPacketBlock): ...
class PacketBlock(EnhancedPacketBlock): ...
class PacketBlockLE(PacketBlock): ...
