# -*- coding: utf-8 -*-
"""PyShark Tools
===================

:mod:`pcapkit.toolkit.pyshark` contains all you need for
:mod:`pcapkit` handy usage with `PyShark`_ engine. All
reforming functions returns with a flag to indicate if
usable for its caller.

.. _PyShark: https://kiminewt.github.io/pyshark

.. note::

   Due to the lack of functionality of `PyShark`_, some
   functions of :mod:`pcapkit` may not be available with
   the `PyShark`_ engine.

"""
import ipaddress
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.utilities.exceptions import MissingKeyError

if TYPE_CHECKING:
    from typing import Any

    from pyshark.packet.packet import Packet

__all__ = ['packet2dict', 'tcp_traceflow', 'FILTER_NAME_TO_LINKTYPE']

#: Wireshark display-filter name -> :class:`~pcapkit.const.reg.linktype.LinkType` member, for the
#: link-layer protocols :mod:`pyshark` can hand :func:`tcp_traceflow` as
#: ``packet.layers[0].layer_name``. PyShark takes that name verbatim from the PDML ``<proto
#: name=...>`` attribute, which is Wireshark's own dissector *filter* name -- the third argument to
#: ``proto_register_protocol()`` in the relevant ``epan/dissectors/packet-*.c`` -- and that
#: vocabulary is not :class:`LinkType`'s: Ethernet's filter name is ``eth``, never ``ETHERNET``.
#: This table exists so :mod:`pcapkit` can bridge the two without minting a DLT for a name it
#: cannot actually place (see the NOTE in :func:`tcp_traceflow`).
#:
#: Both entries were checked two ways: against Wireshark's dissector registrations, and live with
#: ``tshark`` 4.6.9 plus ``editcap -T <encap>`` to confirm the PDML root each encapsulation
#: actually produces. Note the upper-casing is done by the call site in :func:`tcp_traceflow`,
#: not by :meth:`LinkType.get`, which is a plain subscript.
#:
#: * ``eth`` -> :attr:`~LinkType.ETHERNET` -- ``packet-eth.c`` registers it against
#:   ``WTAP_ENCAP_ETHERNET``, and ``ether`` is the only one of the 158 swept encapsulations that
#:   roots at ``eth``. ``ether-nettl`` is among the 68 unswept, so "exactly one" is unproven.
#: * ``tr`` -> :attr:`~LinkType.IEEE802_5` -- ``packet-tr.c``, ``WTAP_ENCAP_TOKEN_RING``; ``tr``
#:   is the only swept encapsulation rooting at ``tr``, with ``tr-nettl`` likewise unswept.
#:   :class:`LinkType`'s own ``#:`` comment records that ``DLT_IEEE802`` *is* Token Ring, the
#:   missing ``_5`` being historical.
#:
#: Everything else, measured rather than reasoned. A filter name serving several DLTs cannot be
#: mapped, because the PDML node does not say which one arrived:
#:
#: * ``sll`` -- serves :attr:`LinkType.LINUX_SLL` (113) and :attr:`LinkType.LINUX_SLL2` (276).
#:   ``tshark -G protocols`` registers a single ``sll`` name, and ``editcap -T linux-sll`` and
#:   ``-T linux-sll2`` both root at ``sll``. No entry; raises.
#: * ``raw`` -- serves :attr:`LinkType.RAW` (101), :attr:`LinkType.IPV4` (228) and
#:   :attr:`LinkType.IPV6` (229); ``editcap -T rawip``, ``-T rawip4`` and ``-T rawip6`` all root at
#:   ``raw``. It does **not** raise: ``'RAW'`` is a member name, so the fallback answers 101 for all
#:   three -- silently wrong for 228 and 229. Tracked in #843.
#: * ``null`` -- serves :attr:`LinkType.NULL` (0) and :attr:`LinkType.LOOP` (108); ``editcap -T
#:   null`` and ``-T loop`` both root at ``null``. Also does not raise: answers 0 for both, silently
#:   wrong for 108. Tracked in #843. (``loop`` is a different protocol entirely -- ``tshark -G
#:   protocols`` gives it as Configuration Test Protocol, an Ethernet payload on ethertype 0x9000.)
#: * ``ip`` and ``ipv6`` -- never arrive as the root layer. ``editcap -T`` accepts 226
#:   encapsulations; of the **158** an Ethernet source can be rewritten into, neither is ever
#:   ``layers[0]`` -- a raw IPv6 capture roots at ``raw`` and carries ``ipv6`` as the *next* layer.
#:   The other 68 refuse that rewrite (``can't be written as``, not an unknown type) and are
#:   untested. No entry needed for either, and none would be reached.
#: * ``ppp``, ``fddi``, ``lapd`` -- no entry needed; each upper-cases onto a real member name, so
#:   the fallback resolves them. ``ppp`` and ``lapd`` each serve several DLTs and so answer with the
#:   wrong one, which is the same #843 defect rather than anything this table introduces.
#: * ``fr`` -- measured single-DLT after all: ``frelay`` and ``frelay-with-direction`` both write
#:   DLT 107, so it is mappable. Left out only because adding it is scope this change does not need.
#: * ``wlan`` -- not investigated. Left out rather than guessed.
#: * every other :class:`LinkType` member -- no evidence was gathered either way; they are simply
#:   untried, not ruled out.
FILTER_NAME_TO_LINKTYPE = {
    'eth': Enum_LinkType.ETHERNET,
    'tr': Enum_LinkType.IEEE802_5,
}  # type: dict[str, Enum_LinkType]


def packet2dict(packet: 'Packet') -> 'dict[str, Any]':
    """Convert PyShark packet into :obj:`dict`.

    Args:
        packet: Scapy packet.

    Returns:
        A :obj:`dict` mapping of packet data.

    """
    dict_ = {}  # type: dict[str, Any]
    frame = packet.frame_info
    for field in frame.field_names:
        dict_[field] = getattr(frame, field)

    tempdict = dict_
    for layer in packet.layers:
        tempdict[layer.layer_name.upper()] = {}
        tempdict = tempdict[layer.layer_name.upper()]
        for field in layer.field_names:
            tempdict[field] = getattr(layer, field)

    return dict_


def tcp_traceflow(packet: 'Packet') -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: Scapy packet.

    Returns:
        Tuple[bool, Dict[str, Any]]: A tuple of data for TCP reassembly.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be reassembled
          if it contains TCP layer.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    if 'IP' in packet:
        ip = cast('Packet', packet.ip)
    elif 'IPv6' in packet:
        ip = cast('Packet', packet.ipv6)
    else:
        return None

    if 'TCP' in packet:
        tcp = cast('Packet', packet.tcp)

        # NOTE: no default here, deliberately. Since #775 tier 1, ``get()``
        # with no default raises on an unresolvable name instead of minting
        # one. NULL and RAW are genuine DLTs -- BSD loopback and raw IP
        # framing, respectively -- each meant to go with its own handler
        # protocol class, so neither is an honest stand-in for "unknown link
        # type" and this must not paper over the miss with either.
        #
        # PyShark's own layer name is Wireshark's PDML *filter* name (e.g.
        # ``eth``, not ``ethernet``), which is generally not a LinkType member
        # name -- so ``FILTER_NAME_TO_LINKTYPE`` (module level, above) is
        # tried first, on the name as PyShark reports it. Only when that
        # table has nothing for this name does this fall back to
        # :meth:`LinkType.get` on the upper-cased name, which is what lets a
        # filter name that happens to already spell a LinkType member (e.g.
        # ``ppp``, ``fddi``) resolve without needing an entry of its own. The
        # table is consulted first rather than second so that a curated,
        # source-verified entry always wins over an incidental upper-case
        # match, should a future LinkType member ever collide with one of
        # this module's filter names by coincidence. The bare ``KeyError``
        # from either lookup is re-raised as
        # :exc:`~pcapkit.utilities.exceptions.MissingKeyError` -- this
        # package's own house exception for a lookup miss -- rather than
        # letting it escape this public function.
        name = packet.layers[0].layer_name
        try:
            protocol = FILTER_NAME_TO_LINKTYPE[name.lower()]
        except KeyError:
            name = name.upper()
            try:
                protocol = Enum_LinkType.get(name)
            except KeyError:
                raise MissingKeyError(name) from None

        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=protocol,                                                   # data link type
            index=int(packet.number),                                            # frame number
            frame=packet2dict(packet),                                           # extracted packet
            syn=bool(int(tcp.flags_syn)),                                        # TCP synchronise (SYN) flag
            fin=bool(int(tcp.flags_fin)),                                        # TCP finish (FIN) flag
            rst=bool(int(tcp.flags_reset)),                                      # TCP reset (RST) flag
            src=ipaddress.ip_address(ip.src),                                    # source IP
            dst=ipaddress.ip_address(ip.dst),                                    # destination IP
            srcport=int(tcp.srcport),                                            # TCP source port
            dstport=int(tcp.dstport),                                            # TCP destination port
            timestamp=packet.frame_info.time_epoch,                              # timestamp
            seq=int(tcp.seq),                                                    # TCP sequence number
            ack=int(tcp.ack),                                                    # TCP acknowledgement number
            # NOTE: PyShark reports dissected *fields*, not the octets behind
            # them, so there is no header or payload to hand over -- which is
            # the same reason this module carries no ``tcp_reassembly`` at all.
            # ``Extractor`` refuses ``trace_analyse=True`` on this engine, so
            # nothing reads these two.
            header=b'',                                                          # unavailable
            payload=bytearray(),                                                 # unavailable
        )
        return data
    return None
