# -*- coding: utf-8 -*-
"""constants for global header of PCAP file format

.. versionadded:: 1.7.0

"""

from pcapkit.corekit.const.capture import MAGIC_NUMBER

__all__ = ['GLOBAL_HEADER_LEN']

#: Length of the PCAP global header, which opens the file. The one home of
#: this value (:issue:`1739`); the format fixes it, so it is never configurable.
#:
#: .. versionadded:: 1.5.0
GLOBAL_HEADER_LEN = 24

#: The PCAP magic number for each byte order and nanosecond flag, the reverse of
#: :data:`~pcapkit.corekit.const.capture.MAGIC_NUMBER`, so that
#: :meth:`Header._make_magic <pcapkit.protocols.misc.pcap.header.protocol.Header._make_magic>`
#: looks one up rather than searching for it -- an undeclared pair raises
#: :exc:`KeyError`.
_DECLARED_MAGIC = {declared: magic for magic, declared in MAGIC_NUMBER.items()}
