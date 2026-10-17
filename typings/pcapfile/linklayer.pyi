"""``pcapfile.linklayer`` as of pypcapfile 0.12.0: the link layer decoders."""
from pcapfile.protocols.linklayer.ethernet import Ethernet

# the decoder of a link layer type, or ``None`` when pypcapfile has none; only
# Ethernet has one
def clookup(ll_type: int) -> type[Ethernet] | None: ...
