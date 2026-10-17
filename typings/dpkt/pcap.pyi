"""``dpkt.pcap`` as of dpkt 1.9.8: the PCAP reader and its record headers."""
from decimal import Decimal
from typing import IO, Iterator

from . import dpkt

class PktHdr(dpkt.Packet):
    tv_sec: int
    tv_usec: int
    caplen: int
    len: int

class PktModHdr(dpkt.Packet):
    tv_sec: int
    tv_usec: int
    caplen: int
    len: int

class Reader:
    # ``self.__f`` and ``self.__ph``, by their mangled names: the stream, and
    # the record header type the magic number selects
    _Reader__f: IO[bytes]
    _Reader__ph: type[PktHdr] | type[PktModHdr]
    # ``Decimal('1E9')`` for a nanosecond file, else ``1E6``
    _divisor: float | Decimal

    def __init__(self, fileobj: IO[bytes]) -> None: ...
    def datalink(self) -> int: ...
    # the timestamp is ``tv_sec + tv_usec / _divisor``, so a ``Decimal`` for a
    # nanosecond file
    def __iter__(self) -> Iterator[tuple[float | Decimal, bytes]]: ...
    def __next__(self) -> tuple[float | Decimal, bytes]: ...
