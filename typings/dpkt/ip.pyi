"""``dpkt.ip`` as of dpkt 1.9.8: the IPv4 packet."""
from . import dpkt

class IP(dpkt.Packet):
    len: int
    id: int
    p: int
    src: bytes
    dst: bytes

    # bit fields, properties over ``_v_hl`` and ``_flags_offset``
    hl: int
    df: int
    mf: int
    offset: int
