# -*- coding: utf-8 -*-
"""The ``pcap-frame`` and ``pcapng-frame`` families: the LinkType tables (#496, #1574).

``Frame.__proto__`` and ``PCAPNG.__proto__`` are both keyed by LinkType, and a
link type is registered in both, so the two families share this module and its
payload builder. A family module of :file:`examples/generators/dispatch.py`,
which loads it by path and binds ``generator`` to itself before this body runs
(#2615).

"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/dispatch.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any


def _pcap_frame_registry() -> 'Any':
    from pcapkit.protocols.misc.pcap.frame import Frame
    return Frame.__proto__


def _payload(code: 'Any') -> 'tuple[bytes, bool]':
    """The bytes to put in one capture record for LinkType ``code``.

    Args:
        code: The ``LinkType`` under test.

    Returns:
        The record's octets, and whether they still need an Ethernet wrapper
        (true for :attr:`~pcapkit.const.reg.linktype.LinkType.ETHERNET`, false
        for the raw-IP link types, which carry no link layer at all, and
        for the loopback link types, whose header is built here).

    """
    from pcapkit.const.reg.linktype import LinkType

    _ip4, _ip6, _tcp = generator._ip4, generator._ip6, generator._tcp
    if code == LinkType.ETHERNET:
        return _ip4(6, _tcp(9999)), True
    if code == LinkType.IPV4:
        return _ip4(6, _tcp(9999)), False
    if code == LinkType.IPV6:
        return _ip6(6, _tcp(9999)), False
    if code == LinkType.NULL:  # in the capturing host's byte order (#1574)
        return generator._loopback(2, _ip4(6, _tcp(9999))), False
    if code == LinkType.LOOP:  # in network byte order (#1574)
        return generator._loopback(2, _ip4(6, _tcp(9999)), byteorder='big'), False
    if code == LinkType.LINUX_SLL:
        return generator._linux_sll(_ip4(6, _tcp(9999))), False
    if code == LinkType.LINUX_SLL2:
        return generator._linux_sll2(_ip4(6, _tcp(9999))), False
    if code == LinkType.IEEE802_11:
        return _wlan_ack(), False
    if code == LinkType.IEEE802_11_RADIOTAP:
        return _radiotap(_wlan_ack()), False
    raise LookupError(f'linktype: no payload builder for {code!r}')  # pragma: no cover


def _wlan_ack() -> 'bytes':
    """An 802.11 Ack frame, which carries no body."""
    from pcapkit.protocols.link.ieee802_11 import IEEE802_11
    return bytes(IEEE802_11(type='Control', subtype='ACK', addr1='02:00:00:00:00:01'))


def _radiotap(payload: 'bytes') -> 'bytes':
    """A minimal radiotap header carrying ``payload``."""
    from pcapkit.protocols.link.radiotap import Radiotap
    return bytes(Radiotap(payload=payload))


def _pcap_frame_build(code: 'Any') -> 'Any':
    payload, wrap = _payload(code)
    record = generator._ethernet(0x0800, payload) if wrap else payload
    return generator._extract_first(generator._pcap_bytes((record,), linktype=int(code)), '.pcap')


def _pcapng_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__proto__


def _pcapng_build(code: 'Any') -> 'Any':
    payload, wrap = _payload(code)
    record = generator._ethernet(0x0800, payload) if wrap else payload
    return generator._extract_first(generator._pcapng_bytes(code, record), '.pcapng')


#: The families this module adds.
FAMILIES = (
    generator.Family('pcap-frame', _pcap_frame_registry, _pcap_frame_build),
    generator.Family('pcapng-frame', _pcapng_registry, _pcapng_build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    # -- Frame.__proto__ (pcap LinkType) ---------------------------------------
    'pcap-frame/NULL': ('pcapkit.protocols.link', 'Loopback'),
    'pcap-frame/ETHERNET': ('pcapkit.protocols.link', 'Ethernet'),
    'pcap-frame/LOOP': ('pcapkit.protocols.link', 'Loopback'),
    'pcap-frame/IPV4': ('pcapkit.protocols.internet', 'IPv4'),
    'pcap-frame/IPV6': ('pcapkit.protocols.internet', 'IPv6'),
    'pcap-frame/LINUX_SLL': ('pcapkit.protocols.link', 'LinuxSLL1'),
    'pcap-frame/LINUX_SLL2': ('pcapkit.protocols.link', 'LinuxSLL2'),
    'pcap-frame/IEEE802_11': ('pcapkit.protocols.link', 'IEEE802_11'),
    'pcap-frame/IEEE802_11_RADIOTAP': ('pcapkit.protocols.link', 'Radiotap'),

    # -- PCAPNG.__proto__ (LinkType) --------------------------------------------
    'pcapng-frame/NULL': ('pcapkit.protocols.link', 'Loopback'),
    'pcapng-frame/ETHERNET': ('pcapkit.protocols.link', 'Ethernet'),
    'pcapng-frame/LOOP': ('pcapkit.protocols.link', 'Loopback'),
    'pcapng-frame/IPV4': ('pcapkit.protocols.internet', 'IPv4'),
    'pcapng-frame/IPV6': ('pcapkit.protocols.internet', 'IPv6'),
    'pcapng-frame/LINUX_SLL': ('pcapkit.protocols.link', 'LinuxSLL1'),
    'pcapng-frame/LINUX_SLL2': ('pcapkit.protocols.link', 'LinuxSLL2'),
    'pcapng-frame/IEEE802_11': ('pcapkit.protocols.link', 'IEEE802_11'),
    'pcapng-frame/IEEE802_11_RADIOTAP': ('pcapkit.protocols.link', 'Radiotap'),
}
