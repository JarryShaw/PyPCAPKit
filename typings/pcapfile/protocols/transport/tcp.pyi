"""``pcapfile.protocols.transport.tcp`` as of pypcapfile 0.12.0: the TCP segment."""
import ctypes

class TCP(ctypes.Structure):
    src_port: int
    dst_port: int
    seqnum: int
    acknum: int
    # in octets, unlike the header field's 32-bit words
    data_offset: int
    rst: bool
    syn: bool
    fin: bool

    def __init__(self, packet: bytes, layers: int = 0) -> None: ...
