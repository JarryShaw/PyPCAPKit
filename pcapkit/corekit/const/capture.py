# -*- coding: utf-8 -*-
"""Capture-Format Constants
==============================

.. module:: pcapkit.corekit.const.capture

:mod:`pcapkit.corekit.const.capture` holds the values the PCAP and PCAP-NG
file formats fix and that code beyond their own file-header protocols reads: the
capture engines, the dumpers and the toolkit. Each is the one home of its value
(:issue:`1739`), and none is configurable. It is one topic of
:mod:`pcapkit.corekit.const`; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.7.0

   Moved here from ``pcapkit.protocols.misc.pcap.header.schema``,
   ``pcapkit.protocols.misc.pcap.frame.schema`` and
   ``pcapkit.protocols.misc.pcapng.schema`` (:issue:`2883`).

"""

from typing import TYPE_CHECKING

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType

__all__ = [
    'MAGIC_NUMBER', 'RESOLUTION', 'RESOLUTION_PLACES', 'RECORD_HEADER_LEN',
    'BYTE_ORDER_MAGIC', 'GENERIC_BLOCK_MINIMUM', 'BLOCK_MINIMUM', 'DEFAULT_RESOLUTION',
]

if TYPE_CHECKING:
    from typing import Dict

    from typing_extensions import Literal

#: PCAP magic numbers, as the octets open the file, mapped to the byte order
#: (``'big'`` or ``'little'``) and the timestamp resolution (:data:`True` for
#: nanoseconds, :data:`False` for microseconds) each one declares.
MAGIC_NUMBER = {
    b'\xa1\xb2\x3c\x4d': ('big', True),
    b'\xa1\xb2\xc3\xd4': ('big', False),
    b'\x4d\x3c\xb2\xa1': ('little', True),
    b'\xd4\xc3\xb2\xa1': ('little', False),
}  # type: Dict[bytes, tuple[Literal['big', 'little'], bool]]

#: Units per second of a PCAP record's ``ts_usec`` field, keyed by the
#: nanosecond flag its file's magic number declares (:data:`MAGIC_NUMBER`):
#: microseconds, or nanoseconds.
RESOLUTION = {
    False: 1_000_000,
    True: 1_000_000_000,
}  # type: Dict[bool, int]

#: Decimal places of a ``ts_usec`` fraction at each resolution of
#: :data:`RESOLUTION`, keyed the same way -- six for microseconds, nine for
#: nanoseconds -- and derived from it, so that an epoch rounded to its file's
#: resolution follows the one home.
RESOLUTION_PLACES = {
    flag: len(str(units)) - 1 for flag, units in RESOLUTION.items()
}  # type: Dict[bool, int]

#: Length of a PCAP record header, which precedes each record's packet data.
RECORD_HEADER_LEN = 16

#: Byte-Order Magic of a PCAP-NG Section Header Block, read in the byte order of
#: the section that wrote it.
BYTE_ORDER_MAGIC = 0x1A2B3C4D

#: The octets every PCAP-NG block's fixed fields span -- Block Type and both
#: copies of Block Total Length -- and so the shortest Block Total Length of any
#: block, and the whole of it for a block not in :data:`BLOCK_MINIMUM`.
GENERIC_BLOCK_MINIMUM = 12

#: PCAP-NG block types mapped to the octets their fixed fields span, Block Type
#: and both copies of Block Total Length included; any other block spans
#: :data:`GENERIC_BLOCK_MINIMUM`.
BLOCK_MINIMUM = {
    Enum_BlockType.Section_Header_Block: 28,
    Enum_BlockType.Interface_Description_Block: 20,
    Enum_BlockType.Packet_Block: 32,
    Enum_BlockType.Simple_Packet_Block: 16,
    Enum_BlockType.Interface_Statistics_Block: 24,
    Enum_BlockType.Enhanced_Packet_Block: 32,
    Enum_BlockType.Decryption_Secrets_Block: 20,
    Enum_BlockType.Custom_Block_that_rewriters_can_copy_into_new_files: 16,
    Enum_BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files: 16,
}  # type: Dict[int, int]

#: Units per second of a timestamp on a PCAP-NG interface that carries no
#: ``if_tsresol`` option: microseconds, the default the format gives that
#: option.
DEFAULT_RESOLUTION = 1_000_000
