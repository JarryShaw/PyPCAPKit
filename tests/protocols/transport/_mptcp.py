# -*- coding: utf-8 -*-
"""Shared Multipath TCP segment builder and header tables for the modules beside this one.

C.f. #3148.

Nothing here imports :mod:`pcapkit` at module level. :func:`build_tcp_segment` imports the
schema when it is called, for the reason
:func:`tests.protocols.transport.test_tcp_mptcp_subtype_unit.build_mptcp_option` records:
another module purges ``pcapkit``'s submodules from :data:`sys.modules`, so a name bound at
collection time can point at a schema class built from a stale ``Schema`` base.

"""

from __future__ import annotations

__all__ = ['TCP_BASE', 'TCP_HEADER', 'build_tcp_segment']

#: Header keywords for :meth:`TCP.from_fields
#: <pcapkit.protocols.transport.tcp.protocol.TCP.from_fields>`, a SYN segment, matching
#: :data:`examples.generators.option_families.tcp.TCP_BASE`.
TCP_BASE = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack': False,
    'psh': False, 'rst': False, 'syn': True, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}

#: :data:`TCP_BASE` without ``syn`` and ``ack``, for a caller that passes both to pick an
#: MP_JOIN layout. ``ack`` is the acknowledgement *flag*, not ``ack_no``, and
#: :meth:`TCP.make <pcapkit.protocols.transport.tcp.protocol.TCP.make>` refuses a keyword it
#: does not declare (#617), so a ``seq`` or an ``ack_flag`` would raise.
TCP_HEADER = {key: value for key, value in TCP_BASE.items() if key not in ('syn', 'ack')}


def build_tcp_segment(option_octets: 'bytes', *, syn: 'bool' = True, ack: 'bool' = False) -> 'bytes':
    """Pack a whole TCP segment carrying ``option_octets`` verbatim as its only option.

    Goes through :class:`~pcapkit.protocols.transport.tcp.schema.TCP`, the schema rather than
    the protocol, whose :class:`~pcapkit.corekit.fields.collections.OptionField` packs raw
    bytes unchanged. So no ``_make_mptcp_*`` maker runs, and the parse side of a test starts
    from hand-built octets rather than from what a maker produced.

    Args:
        option_octets: The whole option, header octets included, already padded to a
            multiple of 4 octets.
        syn: Whether to set the ``SYN`` flag.
        ack: Whether to set the ``ACK`` flag. The MP_JOIN read path picks its reader from
            ``SYN`` and ``ACK``, so a SYN/ACK option in a SYN-only segment would reach the
            wrong one.

    Returns:
        The packed TCP segment.

    Raises:
        ValueError: If ``option_octets`` is not a multiple of 4 octets long, which would
            make the header's ``offset`` unrepresentable.

    """
    from pcapkit.protocols.transport.tcp.schema import TCP as Schema_TCP

    if len(option_octets) % 4:
        raise ValueError('option_octets must already be a multiple of 4 octets long')

    schema = Schema_TCP(
        srcport=50000, dstport=80, seq=1, ack=0,
        offset={'offset': 5 + len(option_octets) // 4, 'reserved': 0, 'ns': 0},
        flags={'cwr': 0, 'ece': 0, 'urg': 0, 'ack': int(ack), 'psh': 0, 'rst': 0,
               'syn': int(syn), 'fin': 0},
        window=8192, checksum=b'\x00\x00', urgent=0,
        options=option_octets,
        payload=b'',
    )
    return schema.pack()
