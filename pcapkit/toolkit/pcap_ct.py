# -*- coding: utf-8 -*-
"""pcap-ct Tools
================

.. module:: pcapkit.toolkit.pcap_ct

:mod:`pcapkit.toolkit.pcap_ct` contains all you need for
:mod:`pcapkit` handy usage with `pcap-ct`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _pcap-ct: https://pypi.org/project/pcap-ct/

.. important::

   `pcap-ct`_ is a :mod:`ctypes` reimplementation of the `PyPCAP`_ interface over
   :manpage:`libpcap(3)`: it hands back the ``(timestamp, bytes)`` pair that
   :c:func:`pcap_next_ex` produced and performs **no protocol dissection
   whatsoever**. There is therefore no IP or TCP layer for this module to read,
   and the reassembly and flow tracing adapters that :mod:`pcapkit.toolkit.dpkt`
   and :mod:`pcapkit.toolkit.scapy` provide cannot be implemented here.

   They are still defined below, but only so that reaching for one fails loudly
   with :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` rather than with an
   :exc:`ImportError` that says nothing about why. Dissecting the raw bytes with
   :mod:`pcapkit`'s own parsers would defeat the point of selecting a third-party
   engine, so it is deliberately not done.

.. seealso::

   :mod:`pcapkit.toolkit.pypcap` is the same adapter for upstream `PyPCAP`_. The
   two are kept apart because the engines are: the distributions are independent
   projects that happen to share the :mod:`pcap` module name, and each engine
   names its own adapter so that a change made for one cannot quietly alter the
   other.

.. _PyPCAP: https://github.com/pynetwork/pypcap

"""
from typing import TYPE_CHECKING

from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any

    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
    from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
    from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
    from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet

__all__ = [
    'packet2chain', 'packet2dict',
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow',
]

#: Explanatory suffix shared by every unsupported adapter below.
_NO_DISSECTION = ("'pcap-ct' is a libpcap binding and performs no protocol "
                  "dissection, so there is no protocol layer to read")


def packet2chain(packet: 'bytes', *, data_link: 'Enum_LinkType') -> 'str':
    """Fetch pcap-ct packet protocol chain.

    Args:
        packet: Raw packet bytes, as returned by :class:`pcap.pcap` iteration.
        data_link: Data link type, from the capture handle.

    Returns:
        Colon (``:``) separated list of protocol chain.

    Note:
        As `pcap-ct`_ does not dissect the packet, the chain is only ever the
        link layer type followed by ``Raw``, e.g. ``ETHERNET:Raw``.

    .. _pcap-ct: https://pypi.org/project/pcap-ct/

    """
    return f'{data_link.name}:Raw'


def packet2dict(packet: 'bytes', timestamp: 'float', *,
                data_link: 'Enum_LinkType') -> 'dict[str, Any]':
    """Convert pcap-ct packet into :obj:`dict`.

    Args:
        packet: Raw packet bytes, as returned by :class:`pcap.pcap` iteration.
        timestamp: Timestamp of packet, as returned by :class:`pcap.pcap` iteration.
        data_link: Data link type, from the capture handle.

    Returns:
        Dict[str, Any]: A :obj:`dict` mapping of packet data.

    Note:
        The mapping carries the captured bytes verbatim rather than a decoded
        protocol tree, since `pcap-ct`_ does not decode anything.

    .. _pcap-ct: https://pypi.org/project/pcap-ct/

    """
    return {
        'timestamp': timestamp,
        'packet': packet,
        data_link.name: {
            'raw_len': len(packet),
            'raw': packet,
        },
    }


def ipv4_reassembly(packet: 'bytes', *, count: 'int' = -1) -> 'IP_Packet[IPv4Address] | None':
    """Make data for IPv4 reassembly.

    Args:
        packet: Raw packet bytes.
        count: Packet index. If not provided, default to ``-1``.

    Raises:
        UnsupportedCall: Always, as `pcap-ct`_ provides no IPv4 layer to read.

    .. _pcap-ct: https://pypi.org/project/pcap-ct/

    """
    raise UnsupportedCall(f'IPv4 reassembly is not supported by the pcap-ct engine: {_NO_DISSECTION}')


def ipv6_reassembly(packet: 'bytes', *, count: 'int' = -1) -> 'IP_Packet[IPv6Address] | None':
    """Make data for IPv6 reassembly.

    Args:
        packet: Raw packet bytes.
        count: Packet index. If not provided, default to ``-1``.

    Raises:
        UnsupportedCall: Always, as `pcap-ct`_ provides no IPv6 layer to read.

    .. _pcap-ct: https://pypi.org/project/pcap-ct/

    """
    raise UnsupportedCall(f'IPv6 reassembly is not supported by the pcap-ct engine: {_NO_DISSECTION}')


def tcp_reassembly(packet: 'bytes', *, count: 'int' = -1) -> 'TCP_Packet | None':
    """Make data for TCP reassembly.

    Args:
        packet: Raw packet bytes.
        count: Packet index. If not provided, default to ``-1``.

    Raises:
        UnsupportedCall: Always, as `pcap-ct`_ provides no TCP layer to read.

    .. _pcap-ct: https://pypi.org/project/pcap-ct/

    """
    raise UnsupportedCall(f'TCP reassembly is not supported by the pcap-ct engine: {_NO_DISSECTION}')


def tcp_traceflow(packet: 'bytes', timestamp: 'float', *, data_link: 'Enum_LinkType',
                  count: 'int' = -1) -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: Raw packet bytes.
        timestamp: Timestamp of the packet.
        data_link: Data link layer protocol (from the capture handle).
        count: Packet index. If not provided, default to ``-1``.

    Raises:
        UnsupportedCall: Always, as `pcap-ct`_ provides no TCP layer to read.

    .. _pcap-ct: https://pypi.org/project/pcap-ct/

    """
    raise UnsupportedCall(f'TCP flow tracing is not supported by the pcap-ct engine: {_NO_DISSECTION}')
