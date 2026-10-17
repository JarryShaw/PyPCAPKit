"""``pcapfile.structs`` as of pypcapfile 0.12.0: the savefile header and the packet."""
import ctypes
from typing import Any

# A ctypes field reads back as a Python value: ``c_uint`` as ``int``,
# ``c_bool`` as ``bool``, and ``c_char_p`` as ``bytes``, never ``None`` here as
# ``savefile`` always sets it.
class __pcap_header__(ctypes.Structure):
    ll_type: int
    byteorder: bytes
    ns_resolution: bool

class pcap_packet(ctypes.Structure):
    header: ctypes._Pointer[__pcap_header__]
    timestamp: int
    timestamp_us: int
    capture_len: int
    packet_len: int
    # not a ctypes field: the hexlified frame, or the layer it decoded into
    packet: Any

    def __init__(self, header: ctypes._Pointer[__pcap_header__], timestamp: int,
                 timestamp_us: int, capture_len: int, packet_len: int, packet: Any) -> None: ...
