"""``pcapfile.protocols.linklayer.ethernet`` as of pypcapfile 0.12.0: the Ethernet frame."""
import ctypes
from typing import Any

class Ethernet(ctypes.Structure):
    # ``c_char_p`` fields, the addresses as colon-separated hex text
    dst: bytes
    src: bytes
    type: int
    # not a ctypes field: the hexlified payload, or the layer it decoded into
    payload: Any

    def __init__(self, packet: bytes, layers: int = 0) -> None: ...
