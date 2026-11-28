# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Fragmented Packets Reassembly
===================================

.. module:: pcapkit.foundation.reassembly

:mod:`pcapkit.foundation.reassembly`, based on algorithms described
in :rfc:`791`, :rfc:`815`, :rfc:`6347`, :rfc:`9260`, :rfc:`8260` and :rfc:`9846`,
implements datagram reassembly of IP packets, TCP segments, DTLS handshake
messages, SCTP user messages and TLS records.

"""
# Reassembly for DTLS handshake messages
from pcapkit.foundation.reassembly.dtls.reassembly import DTLS as DTLS_Reassembly
from pcapkit.foundation.reassembly.ip.reassembly import IP as IP_Reassembly
# Reassembly for IP
from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4 as IPv4_Reassembly
from pcapkit.foundation.reassembly.ipv6.reassembly import IPv6 as IPv6_Reassembly
# Base Class for Reassembly
from pcapkit.foundation.reassembly.reassembly import Reassembly
# Reassembly for SCTP user messages
from pcapkit.foundation.reassembly.sctp.reassembly import SCTP as SCTP_Reassembly
# Reassembly for TCP
from pcapkit.foundation.reassembly.tcp.reassembly import TCP as TCP_Reassembly
# Reassembly for TLS records
from pcapkit.foundation.reassembly.tls.reassembly import TLS as TLS_Reassembly

__all__ = [
    'IPv4_Reassembly', 'IPv6_Reassembly',   # IP Reassembly
    'TCP_Reassembly',                       # TCP Reassembly
    'DTLS_Reassembly',                      # DTLS Reassembly
    'SCTP_Reassembly',                      # SCTP Reassembly
    'TLS_Reassembly',                       # TLS Reassembly
    'ReassemblyManager',                    # Reassembly Manager, defined below
]

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

if TYPE_CHECKING:
    from typing import Iterable, Mapping, Optional

    from pcapkit.foundation.reassembly.reassembly import ReassemblyBase


@info_final
class ReassemblyManager(Info):
    """Reassembly manager.

    The enabled reassemblers, each under the name it is registered by in
    :attr:`Extractor.__reassembly__
    <pcapkit.foundation.extraction.Extractor.__reassembly__>`, iterated in the
    order they were given. A name given :data:`None` is left out, so the manager
    holds exactly the reassemblers an engine feeds.

    Args:
        dict_: reassemblers by name, as a mapping or as ``(name, reassembler)``
            pairs
        **kwargs: reassemblers by name

    .. versionchanged:: 1.7.0

       Holds any registered reassembler, and only the enabled ones, where it had
       a field for each built-in, :data:`None` when disabled (:issue:`2814`).

    """

    def __init__(self, dict_: 'Optional[Mapping[str, Optional[ReassemblyBase]] | Iterable[tuple[str, Optional[ReassemblyBase]]]]' = None,  # pylint: disable=line-too-long,super-init-not-called
                 **kwargs: 'Optional[ReassemblyBase]') -> 'None':
        given = dict(dict_ or (), **kwargs)
        held = {name: reasm for (name, reasm) in given.items() if reasm is not None}
        self.__update__(held)
        self.__post_init__()
