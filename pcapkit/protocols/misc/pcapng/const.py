# -*- coding: utf-8 -*-
"""constants for pcapng file format

.. versionadded:: 1.7.0

"""

from pcapkit.corekit.const.capture import BYTE_ORDER_MAGIC

__all__ = ['PACKET_FLAGS']

#: :data:`~pcapkit.corekit.const.capture.BYTE_ORDER_MAGIC` read in the other
#: byte order, i.e. as a big-endian reader sees a little-endian section's.
_SWAPPED_BYTE_ORDER_MAGIC = int.from_bytes(BYTE_ORDER_MAGIC.to_bytes(4, 'little'), 'big')

#: Sub-fields of the ``epb_flags`` and ``pack_flags`` words. ``reserved`` keeps
#: bits 12 to 23 verbatim -- the reserved bits 12-15 and the link-layer-dependent
#: error bits 16-23 that the data model does not name.
PACKET_FLAGS = {
    'direction': (0, 2),
    'reception': (2, 3),
    'fcs_len': (5, 4),
    'checksum_not_ready': (9, 1),
    'checksum_valid': (10, 1),
    'tcp_segmentation_offloaded': (11, 1),
    'reserved': (12, 12),
    'crc_error': (24, 1),
    'too_long': (25, 1),
    'too_short': (26, 1),
    'gap_error': (27, 1),
    'unaligned_error': (28, 1),
    'delimiter_error': (29, 1),
    'preamble_error': (30, 1),
    'symbol_error': (31, 1),
}  # type: dict[str, tuple[int, int]]
