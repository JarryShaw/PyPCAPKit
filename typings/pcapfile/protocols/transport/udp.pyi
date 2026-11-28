"""``pcapfile.protocols.transport.udp`` as of pypcapfile 0.12.0: the UDP datagram."""
import ctypes

class UDP(ctypes.Structure):
    udp_header_size: int
    src_port: int
    dst_port: int
    # of header and data, in octets
    len: int

    def __init__(self, packet: bytes, layers: int = 0) -> None: ...
