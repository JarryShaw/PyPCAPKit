"""``dpkt.ip6`` as of dpkt 1.9.8: the IPv6 packet and its extension headers."""
from . import dpkt

class IP6ExtensionHeader(dpkt.Packet):
    # set by each subclass's ``unpack``: the octets the header occupies
    length: int

class IP6FragmentHeader(IP6ExtensionHeader):
    nxt: int
    id: int

    # bit fields, properties over ``_frag_off_resv_m``
    frag_off: int
    m_flag: int

class IP6(dpkt.Packet):
    plen: int
    src: bytes
    dst: bytes

    # set by ``unpack``: each header by its protocol number, the last of a
    # repeated type winning, and every header in the order it was parsed
    extension_hdrs: dict[int, IP6ExtensionHeader]
    all_extension_headers: list[IP6ExtensionHeader]
