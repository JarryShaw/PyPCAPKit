# -*- coding: utf-8 -*-
"""The reassemblers :class:`~pcapkit.foundation.extraction.Extractor` ships, for the tests listing them.

A test enumerating the built-in reassemblers reads them here, in the order
:attr:`Extractor.__reassembly__ <pcapkit.foundation.extraction.Extractor.__reassembly__>`
registers them, rather than pinning a copy of the list: a reassembler added to it
gets every case at once, and a table with no entry for it fails by its name. What
each one brings beyond its name -- a complete datagram, and the engines feeding it --
is written once, here. Shared under #3148.

Nothing here imports :mod:`pcapkit` at module level, so each test module keeps its
classes' own import, after :func:`~tests._support.reimport_once_per_class`.

"""
from __future__ import annotations

#: The engines feeding each shipped reassembler, by engine class name: DTLS and
#: SCTP by the default engines alone, TLS by every engine with a TCP adapter, as
#: ``docs/source/contributing/conventions/reassembly-integration.rst`` states.
ENGINES = {
    'ipv4': ('PCAP', 'PCAPNG', 'DPKT', 'Scapy', 'PyPCAPFile'),
    'ipv6': ('PCAP', 'PCAPNG', 'DPKT', 'Scapy'),
    'tcp': ('PCAP', 'PCAPNG', 'DPKT', 'Scapy', 'PyPCAPFile'),
    'dtls': ('PCAP', 'PCAPNG'),
    'sctp': ('PCAP', 'PCAPNG'),
    'tls': ('PCAP', 'PCAPNG', 'DPKT', 'Scapy', 'PyPCAPFile'),
}


def shipped() -> 'dict[str, type]':
    """Each reassembler ``Extractor`` ships, by the name it is registered under, in order."""
    from pcapkit.corekit.module import ModuleDescriptor
    from pcapkit.foundation.extraction import Extractor

    return {name: entry.klass if isinstance(entry, ModuleDescriptor) else entry
            for (name, entry) in Extractor._shipped_reassembly.items()}


def builtins() -> 'tuple[str, ...]':
    """The names :func:`shipped` holds, in order."""
    from pcapkit.foundation.extraction import Extractor

    return tuple(Extractor._shipped_reassembly)


def datagram(name: 'str', packet: 'object') -> 'object':
    """A complete datagram of the shipped reassembler ``name``, holding ``packet`` as given.

    Raises:
        LookupError: If ``name`` has no datagram here.

    """
    from pcapkit.foundation.reassembly.data import Completion
    from pcapkit.foundation.reassembly.dtls.data import Datagram as DTLS_Datagram
    from pcapkit.foundation.reassembly.ip.data import Datagram as IP_Datagram
    from pcapkit.foundation.reassembly.sctp.data import Datagram as SCTP_Datagram
    from pcapkit.foundation.reassembly.tcp.data import Datagram as TCP_Datagram
    from pcapkit.foundation.reassembly.tls.data import Datagram as TLS_Datagram

    def stream(cls: 'type') -> 'object':
        return cls(completed=Completion.COMPLETE, id=None, index=(1,), header=b'', payload=b'payload',
                   packet=packet, conflict=())

    models = {
        'ipv4': lambda: stream(IP_Datagram),
        'ipv6': lambda: stream(IP_Datagram),
        'tcp': lambda: stream(TCP_Datagram),
        'dtls': lambda: DTLS_Datagram(completed=Completion.COMPLETE, id=None, index=(1,), message_seq=0,
                                      msg_type=None, length=7, body=b'payload', packet=packet),
        'sctp': lambda: SCTP_Datagram(completed=Completion.COMPLETE, id=None, index=(1,), chunk=None, stream_id=0,
                                      unordered=False, ssn=0, mid=None, tsn=(1,), ppid=None, payload=b'payload',
                                      packet=packet),
        'tls': lambda: TLS_Datagram(completed=Completion.COMPLETE, id=None, index=(1,), content_type=None,
                                    version=0x0303, length=7, fragment=b'payload', packet=packet),
    }
    if name not in models:
        raise LookupError(f'no datagram for the shipped reassembler {name!r} in {__name__}')
    return models[name]()
