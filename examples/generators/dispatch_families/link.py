# -*- coding: utf-8 -*-
"""The ``link`` family: ``Link.__proto__``, keyed by EtherType (#496).

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


def _registry() -> 'Any':
    from pcapkit.protocols.link.link import Link
    return Link.__proto__


def _payload(code: 'int') -> 'bytes':
    """The registered target's own wire bytes for ``code``, as an Ethernet payload."""
    from pcapkit.const.reg.ethertype import EtherType

    if code == EtherType.Address_Resolution_Protocol:
        from pcapkit.protocols.link.arp import ARP
        return bytes(ARP(oper=1))
    if code == EtherType.Reverse_Address_Resolution_Protocol:
        from pcapkit.protocols.application.rarp import RARP

        # ARP/RARP/InARP/DRARP all report their alias from the wire ``oper``
        # field rather than from the dispatching EtherType (``ARP.read`` in
        # pcapkit/protocols/link/arp.py, per #496), so ``oper`` has to land in
        # the RARP range (3, 4) or this would silently probe ARP instead while
        # still "passing".
        return bytes(RARP(oper=3))
    if code == EtherType.Customer_VLAN_Tag_Type:
        from pcapkit.protocols.link.c_tag import C_Tag
        return bytes(C_Tag(vid=200, type=0x0800, payload=generator._ip4(6, generator._tcp(9999))))
    if code == EtherType.IEEE_Std_802_1Q_Service_VLAN_tag_identifier:
        from pcapkit.protocols.link.s_tag import S_Tag
        return bytes(S_Tag(vid=100, type=0x0800, payload=generator._ip4(6, generator._tcp(9999))))
    if code == EtherType.Internet_Protocol_version_4:
        return generator._ip4(6, generator._tcp(9999))
    if code == EtherType.Internet_Protocol_version_6:
        return generator._ip6(6, generator._tcp(9999))
    if code == 0x8137:  # Novell IPX.
        from pcapkit.protocols.internet.ipx import IPX
        return bytes(IPX())
    raise LookupError(f'link: no payload builder for {code!r}')  # pragma: no cover


def _build(code: 'int') -> 'Any':
    frame = generator._ethernet(int(code), _payload(code))
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=1), '.pcap')


def _enum() -> 'Any':
    from pcapkit.const.reg.ethertype import EtherType
    return EtherType


#: The families this module adds.
FAMILIES = (
    generator.Family('link', _registry, _build, _enum),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'link/Address_Resolution_Protocol': ('pcapkit.protocols.link.arp', 'ARP'),
    'link/Reverse_Address_Resolution_Protocol': ('pcapkit.protocols.application.rarp', 'RARP'),
    'link/Customer_VLAN_Tag_Type': ('pcapkit.protocols.link.c_tag', 'C_Tag'),
    'link/IEEE_Std_802_1Q_Service_VLAN_tag_identifier': ('pcapkit.protocols.link.s_tag', 'S_Tag'),
    'link/Internet_Protocol_version_4': ('pcapkit.protocols.internet.ipv4', 'IPv4'),
    'link/Internet_Protocol_version_6': ('pcapkit.protocols.internet.ipv6', 'IPv6'),
    'link/Novell_Inc_0x8137': ('pcapkit.protocols.internet.ipx', 'IPX'),
}
