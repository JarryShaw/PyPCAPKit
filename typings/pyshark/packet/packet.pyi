"""``pyshark.packet.packet`` as of pyshark 0.6: the packet, a list of layers."""
from typing import Any

from pyshark.packet.layers.base import BaseLayer

class Packet:
    layers: list[BaseLayer]
    # the constructor defaults it to ``None``, but every tshark output parser
    # passes the frame's layer
    frame_info: BaseLayer
    # a PDML field value, a ``str``, or ``None`` where the record has none; the
    # EK and JSON parsers pass an ``int``
    number: int | str | None
    # PDML's raw timestamp text, or the EK or JSON parser's epoch value
    sniff_timestamp: Any

    def __init__(self, layers: list[BaseLayer] | None = None, frame_info: BaseLayer | None = None,
                 number: int | str | None = None, length: Any = None, captured_length: Any = None,
                 sniff_time: Any = None, interface_captured: Any = None) -> None: ...
