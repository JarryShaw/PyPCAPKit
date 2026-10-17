"""``dpkt.tcp`` as of dpkt 1.9.8: the TCP segment and its flag masks."""
from . import dpkt

TH_FIN: int
TH_SYN: int
TH_RST: int

class TCP(dpkt.Packet):
    sport: int
    dport: int
    seq: int
    ack: int

    # bit fields, properties over ``_off_flags``; ``flags`` is nine bits wide
    off: int
    flags: int

    # ``unpack`` keeps the octets after the options undecoded
    data: bytes
