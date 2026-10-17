"""``dpkt.dpkt`` as of dpkt 1.9.8: the base class of every packet."""
from typing import Any, ClassVar

# builds each class's header fields from its ``__hdr__``
class _MetaPacket(type):
    def __new__(cls, clsname: str, clsbases: tuple[type, ...], clsdict: dict[str, Any]) -> _MetaPacket: ...

class Packet(metaclass=_MetaPacket):
    # Set by the metaclass on every subclass that declares ``__hdr__``, which is
    # every protocol class; ``Packet`` itself, and a subclass without
    # ``__hdr__``, have neither.
    __hdr_fields__: ClassVar[list[str]]
    __hdr_len__: ClassVar[int]

    # The payload: ``bytes``, a decoded ``Packet``, or a ``str`` where a layer
    # leaves it so (``dpkt.vrrp.VRRP`` sets ``''``). Each layer decides.
    data: Any

    def __init__(self, *args: bytes, **kwargs: Any) -> None: ...
    def __len__(self) -> int: ...
    def __bytes__(self) -> bytes: ...
    def pack_hdr(self) -> bytes: ...
    def pack(self) -> bytes: ...
    def unpack(self, buf: bytes) -> None: ...
