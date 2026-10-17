"""``pcapfile.savefile`` as of pypcapfile 0.12.0: loading a savefile."""
from typing import Iterable, Protocol

from pcapfile.structs import __pcap_header__, pcap_packet

class _Input(Protocol):
    # what ``load_savefile`` reads of its ``input_file``
    @property
    def name(self) -> str: ...
    def read(self, size: int, /) -> bytes: ...

class pcap_savefile:
    header: __pcap_header__

    # ``packets`` is a list, or with ``lazy=True`` a generator
    def __init__(self, header: __pcap_header__, packets: Iterable[pcap_packet] | None = None) -> None: ...

# Documented as returning ``None`` on failure, which cannot happen:
# ``_load_savefile_header`` raises ``InvalidHeader`` for any header the later
# check would reject.
def load_savefile(input_file: _Input, layers: int = 0, verbose: bool = False,
                  lazy: bool = False) -> pcap_savefile: ...
