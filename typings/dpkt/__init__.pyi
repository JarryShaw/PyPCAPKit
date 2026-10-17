"""Type stubs for the part of ``dpkt`` that :mod:`pcapkit` uses (#1878).

Written against dpkt 1.9.8, from its source as installed; dpkt ships no type
information of its own. Only the names :mod:`pcapkit` reads are declared, so
this is not a general-purpose stub: declare a name here before :mod:`pcapkit`
starts to use it.

:file:`mypy.ini` registers this directory through ``mypy_path``. It is not part
of the wheel or the sdist.

"""
from . import dpkt as dpkt
from . import ethernet as ethernet
from . import ip as ip
from . import ip6 as ip6
from . import loopback as loopback
from . import pcap as pcap
from . import pcapng as pcapng
from . import tcp as tcp

__version__: str
