"""``dpkt.loopback`` as of dpkt 1.9.8: the BSD loopback header."""
from . import dpkt

class Loopback(dpkt.Packet):
    family: int
