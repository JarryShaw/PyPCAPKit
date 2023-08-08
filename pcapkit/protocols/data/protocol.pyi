from pcapkit.protocols.data.data import Data

class Packet(Data):
    header: bytes
    payload: bytes
    def __init__(self, header: bytes, payload: bytes) -> None: ...
