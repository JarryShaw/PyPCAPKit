"""``dpkt.udp`` as of dpkt 1.9.8: the UDP datagram."""
from . import dpkt

class UDP(dpkt.Packet):
    sport: int
    dport: int

    # ``unpack`` leaves the octets after the header undecoded
    data: bytes
