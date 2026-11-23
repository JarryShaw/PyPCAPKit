# -*- coding: utf-8 -*-
"""Byte-Order Helpers
========================

.. module:: pcapkit.corekit.schema.byteorder

:mod:`pcapkit.corekit.schema.byteorder` reads the byte order a capture file or
section declares out of the packet data: :func:`byteorder_callback` sets it on a
:class:`~pcapkit.corekit.fields.numbers.NumberField` for the record header of a
classic PCAP file (:mod:`~pcapkit.protocols.misc.pcap.frame.schema`) and the
blocks of a PCAP-NG file (:mod:`~pcapkit.protocols.misc.pcapng.schema`), and
:func:`packet_byteorder` is what the callback and the PCAP-NG makers
(:mod:`pcapkit.protocols.misc.pcapng.protocol`) read it with.
:func:`family_byteorder` reads the byte order a BSD loopback header's address
family was written in, for
:class:`~pcapkit.protocols.link.loopback.protocol.Loopback` and the `DPKT`_
engine (:mod:`pcapkit.foundation.engines.dpkt`) alike. It is one of the
:mod:`pcapkit.corekit.schema` helpers the protocols and the capture engines call,
not part of the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.corekit.fields.byteorder``, with both its helpers
   (:issue:`2674`).

.. versionremoved:: 1.6.0

   ``pcapkit.corekit.fields.byteorder``, with no alias (:issue:`2674`).

"""

import sys
from typing import TYPE_CHECKING

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType

__all__ = ['packet_byteorder', 'byteorder_callback', 'family_byteorder']

if TYPE_CHECKING:
    from typing import Any, Optional

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
        :meth:`Frame.pack <pcapkit.protocols.misc.pcap.frame.protocol.Frame.pack>` and
        :meth:`Frame.unpack <pcapkit.protocols.misc.pcap.frame.protocol.Frame.unpack>`
        both write it from the global header's magic number. A PCAP-NG Section
        Header Block writes it from its own Byte-Order Magic (see
        :func:`~pcapkit.protocols.misc.pcapng.schema.shb_byteorder_callback`),
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


def family_byteorder(family: 'bytes', linktype: 'Optional[int]' = None) -> 'Literal["big", "little"]':
    """Byte order a loopback header's address family was written in.

    Args:
        family: The 4 octets of the address family.
        linktype: Link type the frame was captured under; :data:`None` reads as
            ``LINKTYPE_NULL``.

    Returns:
        ``'big'`` for ``LINKTYPE_LOOP`` (108), whose family is in network byte
        order. Otherwise, for ``LINKTYPE_NULL`` (0), ``'big'`` if the octets
        read as a smaller number big-endian than little-endian, else
        ``'little'``.

    Note:
        A ``LINKTYPE_NULL`` family is in the byte order of the host that
        captured the packet, which the capture file does not record. Every
        address family is below ``0x10000``, so its zero octets lie at the high
        end, and the smaller of the two readings is the one in the writer's byte
        order. A family that reads the same both ways, such as 0, packs to the
        same octets either way. A ``LINKTYPE_LOOP`` family is never inferred,
        so one written little-endian reads as a family no table holds.

    .. versionadded:: 1.7.0

       Moved here from ``pcapkit.protocols.link.loopback.protocol``
       (:issue:`2897`).

    """
    if linktype == Enum_LinkType.LOOP:
        return 'big'
    if int.from_bytes(family, 'big') < int.from_bytes(family, 'little'):
        return 'big'
    return 'little'
