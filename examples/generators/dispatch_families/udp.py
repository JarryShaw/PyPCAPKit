# -*- coding: utf-8 -*-
"""The ``udp`` family: ``UDP.__proto__``, keyed by port (#496).

A family module of :file:`examples/generators/dispatch.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/dispatch.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any

#: The DTLS equivalent of the TLS record the ``tcp`` family probes port 443
#: with: ``application_data``, legacy version 0xFEFD, epoch 0, sequence number
#: 1, zero-length fragment.
_DTLS_RECORD = b'\x17\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00'

#: The DNS query the ``tcp`` family probes port 53 with, without its length field.
_DNS_MESSAGE = bytes.fromhex('0001 0100 0001 0000 0000 0000' '00 0001 0001')

#: A DHCPDISCOVER carrying only its DHCP Message Type option: the fixed header
#: of an Ethernet client, the magic cookie, option 53 of 1, and End.
_DHCP_MESSAGE = (bytes.fromhex('01010600') + bytes(24) + bytes.fromhex('020000000001') + bytes(202)
                 + bytes.fromhex('63825363' '350101' 'ff'))

#: An L2TPv2 data message with every optional field absent, matching
#: :func:`tests.protocols.test_dispatch_bindings_unit.l2tp_data`.
_L2TP_DATA = struct.pack('!HHH', 0x0002, 0x1234, 0x5678) + b'\xff\x03\x00\x21PPP'

#: The payload each registered port is probed with.
_PORT_PAYLOAD = {
    53: _DNS_MESSAGE,
    67: _DHCP_MESSAGE,
    68: _DHCP_MESSAGE,
    80: b'GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n',
    1701: _L2TP_DATA,
    5684: _DTLS_RECORD,
    8080: b'GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n',
}


def _registry() -> 'Any':
    from pcapkit.protocols.transport.udp.protocol import UDP
    return UDP.__proto__


def _build(port: 'int') -> 'Any':
    payload = _PORT_PAYLOAD.get(port)
    if payload is None:
        raise LookupError(f'udp: no payload builder for port {port!r}')
    frame = generator._ethernet(0x0800, generator._ip4(17, generator._udp(port, payload)))
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=1), '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('udp', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'udp/53': ('pcapkit.protocols.application.dns.protocol', 'DNS'),
    'udp/67': ('pcapkit.protocols.application.dhcp.protocol', 'DHCP'),
    'udp/68': ('pcapkit.protocols.application.dhcp.protocol', 'DHCP'),
    'udp/80': ('pcapkit.protocols.application.http.protocol', 'HTTP'),
    'udp/1701': ('pcapkit.protocols.link.l2tpv2.protocol', 'L2TPv2'),
    'udp/5684': ('pcapkit.protocols.application.dtls.protocol', 'DTLS'),
    'udp/8080': ('pcapkit.protocols.application.http.protocol', 'HTTP'),
}
