# -*- coding: utf-8 -*-
"""The ``tcp`` family: ``TCP.__proto__``, keyed by port (#496).

A family module of :file:`examples/generators/dispatch.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/dispatch.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any

#: A minimal, genuine TLS record: ``application_data`` (23), legacy version
#: 3.3, and a zero-length fragment -- content type and legacy version both in
#: range, and the (zero) declared length fits the (zero) remaining buffer, so
#: :meth:`SSL._validate_tls_record <pcapkit.protocols.application.ssl.protocol.SSL._validate_tls_record>`
#: accepts it rather than degrading it to :class:`Raw`.
_TLS_RECORD = b'\x17\x03\x03\x00\x00'

#: The payload each registered port is probed with.
_PORT_PAYLOAD = {
    20: b'binary-file-contents',
    21: b'USER anonymous\r\n',
    80: b'GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n',
    443: _TLS_RECORD,
    8080: b'GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n',
}


def _registry() -> 'Any':
    from pcapkit.protocols.transport.tcp.protocol import TCP
    return TCP.__proto__


def _build(port: 'int') -> 'Any':
    payload = _PORT_PAYLOAD.get(port)
    if payload is None:
        raise LookupError(f'tcp: no payload builder for port {port!r}')
    frame = generator._ethernet(0x0800, generator._ip4(6, generator._tcp(port, payload)))
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=1), '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('tcp', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'tcp/20': ('pcapkit.protocols.application.ftp_data.protocol', 'FTP_DATA'),
    'tcp/21': ('pcapkit.protocols.application.ftp.protocol', 'FTP'),
    # The version-identifying proxy (#682), as for ``udp/80`` and ``udp/8080``;
    # it dispatches to HTTPv1 or HTTPv2 (#2524).
    'tcp/80': ('pcapkit.protocols.application.http.protocol', 'HTTP'),
    'tcp/443': ('pcapkit.protocols.application.tls.protocol', 'TLS'),
    'tcp/8080': ('pcapkit.protocols.application.http.protocol', 'HTTP'),
}
