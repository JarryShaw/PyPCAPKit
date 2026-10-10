# -*- coding: utf-8 -*-
"""byte-order helpers shared by the PCAP and PCAP-NG schemas

:mod:`pcapkit.protocols.schema.misc.byteorder` holds the field callback that
reads a capture file's byte order out of the packet data. The record header of
a classic PCAP file (:mod:`~pcapkit.protocols.schema.misc.pcap.frame`) and the
blocks of a PCAP-NG file (:mod:`~pcapkit.protocols.schema.misc.pcapng`) both use
it.

"""

import sys
from typing import TYPE_CHECKING

__all__ = ['packet_byteorder', 'byteorder_callback']

if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import Literal

    from pcapkit.corekit.fields.numbers import NumberField


def packet_byteorder(packet: 'dict[str, Any]') -> 'Literal["big", "little"]':
    """Byte order declared for the file or section that ``packet`` belongs to.

    A nested schema is handed its parent's packet data under a ``__packet__``
    key (see :meth:`SchemaField.pack
    <pcapkit.corekit.fields.misc.SchemaField.pack>`), so the byte order may
    live one level up.

    Args:
        packet: Packet data.

    Returns:
        Byte order of the enclosing file or section, falling back to the host
        byte order when the packet data declares none.

    """
    if 'byteorder' not in packet and '__packet__' in packet:
        return packet['__packet__'].get('byteorder', sys.byteorder)
    return packet.get('byteorder', sys.byteorder)


def byteorder_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of a PCAP or PCAP-NG file.

    Args:
        field: Field instance.
        packet: Packet data.

    Notes:
        ``byteorder`` is the key a caller has to seed, and
        :func:`packet_byteorder` is what reads it.
        :meth:`Frame.pack <pcapkit.protocols.misc.pcap.frame.Frame.pack>` and
        :meth:`Frame.unpack <pcapkit.protocols.misc.pcap.frame.Frame.unpack>`
        both write it from the global header's magic number. A PCAP-NG Section
        Header Block writes it from its own Byte-Order Magic (see
        :func:`~pcapkit.protocols.schema.misc.pcapng.shb_byteorder_callback`),
        and the blocks, options and records of that section read it, nested or
        not. The fallback to :data:`sys.byteorder` is for a schema packed or
        unpacked on its own, with no header to ask. That also means a
        *misspelled* key looks exactly like an absent one and reports nothing:
        every field would be read in the host's order rather than the file's,
        which is right by coincidence on a little-endian capture and
        byte-swapped on a big-endian one. See
        :file:`tests/protocols/misc/pcap/test_frame_endian_runtime.py` for the
        fixtures that take the other side of the branch.

    """
    field._byteorder = packet_byteorder(packet)
