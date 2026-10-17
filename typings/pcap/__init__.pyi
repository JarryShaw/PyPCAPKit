"""Type stubs for the part of ``pcap`` that :mod:`pcapkit` uses (#1878).

More than one distribution installs this module. This is written against the
ones pcapkit drives, from the source each publishes on PyPI: pypcap 1.3.0, a
Cython extension, from its ``pcap.pyx``, and pcap-ct 1.3.0b3, a :mod:`ctypes`
reimplementation, from its ``pcap/_pcap.py``. Neither ships type information. A
signature here is one each of them accepts, so pcap-ct's extra ``datalink``
argument to :class:`pcap` is left out.

Only the names :mod:`pcapkit` reads are declared, so this is not a
general-purpose stub: declare a name here before :mod:`pcapkit` starts to use
it.

:file:`mypy.ini` registers this directory through ``mypy_path``. It is not part
of the wheel or the sdist.

"""

__version__: str

class pcap:
    def __init__(self, name: str | None = None, snaplen: int = 65535, promisc: bool = True,
                 timeout_ms: int = 0, immediate: bool = False, rfmon: bool = False,
                 timestamp_in_ns: bool = False, buffer_size: int = 0) -> None: ...
    def datalink(self) -> int: ...
    def close(self) -> None: ...
    def __iter__(self) -> pcap: ...
    # an ``int`` count of nanoseconds instead of a ``float`` of seconds when
    # opened with ``timestamp_in_ns=True``
    def __next__(self) -> tuple[float, bytes]: ...
