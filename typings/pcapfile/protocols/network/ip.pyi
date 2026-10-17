"""``pcapfile.protocols.network.ip`` as of pypcapfile 0.12.0: the IPv4 packet."""
import ctypes
from typing import Any

class IP(ctypes.Structure):
    v: int
    hl: int
    tos: int
    len: int
    id: int
    flags: int
    off: int
    ttl: int
    p: int
    sum: int
    # ``c_char_p`` fields: the addresses as dotted-decimal text, and the options
    # hexlified
    src: bytes
    dst: bytes
    opt: bytes
    # not a ctypes field: the hexlified payload, or the layer it decoded into
    payload: Any

    def __init__(self, packet: bytes, layers: int = 0) -> None: ...
