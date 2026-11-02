# -*- coding: utf-8 -*-
"""The ``tcp-option`` and ``tcp-mptcp`` families: TCP options, and Multipath TCP subtypes.

A family module of :file:`examples/generators/options.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
# Deferring these is the design, as in options.py -- see its module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/options.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any

#: Header fields shared by every constructed TCP segment. Only ``options``
#: varies between cases, so a difference in the octets is a difference in the
#: option and nothing else.
#:
#: Every key here has to be spelled the way :meth:`TCP.make
#: <pcapkit.protocols.transport.tcp.TCP.make>` declares it: an undeclared
#: keyword raises :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` (#617).
#: Without that check, ``make``'s ``**kwargs`` drops it silently, so a key
#: spelled wrong in this table is ignored (GitHub issue #602):
#:
#: * ``'seq'`` for ``seq_no``. The mapping reads as sequence number 1 while
#:   every generated frame carries 0, so the captures are not the packets this
#:   table describes.
#: * ``'urgent_pointer'`` for ``urgent``. Harmless in effect, since the value
#:   asked for and the default are both 0.
#: * ``'ack_flag'`` for ``ack``, where ``ack`` is the *acknowledgement flag*
#:   rather than the acknowledgement number, which is ``ack_no``: ``'ack': 0``
#:   sets the flag (to a falsy 0) and ``'ack_flag': False`` sets nothing at
#:   all.
#:
#: The mapping is a SYN-only segment with sequence number 1, every other flag
#: clear, and the acknowledgement number, checksum and urgent pointer at zero.
TCP_BASE = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack': False,
    'psh': False, 'rst': False, 'syn': True, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}


def _tcp_registry() -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP.__option__


def _tcp_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.tcp.option import Option as Enum_Option
    return {
        # Each of these defaults to an empty variable-length field, which
        # is the one shape that never runs the field's packing loop.
        Enum_Option.SACK: {'sack': [(1, 2), (3, 4)]},
        Enum_Option.TCP_Alternate_Checksum_Data: {'data': b'\x01\x02'},
        Enum_Option.TCP_Authentication_Option: {'mac': b'\x01\x02\x03\x04'},
        Enum_Option.TCP_Fast_Open_Cookie: {'cookie': b'\x01\x02\x03\x04\x05\x06\x07\x08'},
    }


def _tcp_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP(options=[(code, kwargs)], **TCP_BASE)


def _tcp_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP(octets, len(octets))


def _tcp_extract(parsed: 'Any') -> 'Any':
    return parsed.info.options


def _tcp_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP(options=options, **TCP_BASE)


def _mptcp_registry() -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP.__mp_option__


def _mptcp_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
    return {
        Enum_MPTCPOption.MP_CAPABLE: {'skey': 0x0102030405060708},
        Enum_MPTCPOption.DSS: {
            'ack': 1, 'dsn': 2, 'ssn': 3, 'dl_len': 4, 'checksum': b'\x00\x00'},
        Enum_MPTCPOption.ADD_ADDR: {'addr_id': 1, 'addr': '192.0.2.1'},
        Enum_MPTCPOption.REMOVE_ADDR: {'addr_id': [1]},
        Enum_MPTCPOption.MP_PRIO: {'addr_id': 1},
        Enum_MPTCPOption.MP_FAIL: {'dsn': 7},
        Enum_MPTCPOption.MP_FASTCLOSE: {'key': 9},
    }


def _mptcp_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.tcp.option import Option as Enum_Option
    from pcapkit.protocols.transport.tcp import TCP

    # The subtype travels as an argument of the enclosing Multipath TCP option
    # rather than as a registry key of its own, so it is spliced in here rather
    # than repeated in every entry of the table above.
    args = dict(kwargs)
    args['subtype'] = code
    return TCP(options=[(Enum_Option.Multipath_TCP, args)], **TCP_BASE)


#: The families this module adds.
FAMILIES = (
    generator.Family('tcp-option', _tcp_registry, _tcp_overrides,
                     _tcp_build, _tcp_parse, _tcp_extract, _tcp_rebuild,
                     capture='options-tcp.pcap', envelope='ipv4', proto=6),
    generator.Family('tcp-mptcp', _mptcp_registry, _mptcp_overrides,
                     _mptcp_build, _tcp_parse, _tcp_extract, _tcp_rebuild,
                     capture='options-tcp.pcap', envelope='ipv4', proto=6),
)

#: Codes of :data:`FAMILIES` left out of the case list, with the reason; see
#: :data:`examples.generators.options.SKIP`. ``_make_tcp_options`` emits
#: ``EOOL`` and ``NOP`` as given, so the TCP padding cases are distinct
#: headers and both round-trip.
SKIP = {
    # Multipath TCP is the envelope for the whole tcp-mptcp family, so a case
    # here would silently duplicate whichever subtype it defaulted to.
    ('tcp-option', 'Multipath_TCP'): 'envelope for the tcp-mptcp family',
}
