# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Fragmented Packets Reassembly
===================================

.. module:: pcapkit.foundation.reassembly

:mod:`pcapkit.foundation.reassembly`, based on algorithms described
in :rfc:`791`, :rfc:`815` and :rfc:`6347`, implements datagram
reassembly of IP packets, TCP segments and DTLS handshake messages.

"""
# Reassembly for DTLS handshake messages
from pcapkit.foundation.reassembly.dtls import DTLS as DTLS_Reassembly
from pcapkit.foundation.reassembly.ip import IP as IP_Reassembly
# Reassembly for IP
from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
from pcapkit.foundation.reassembly.ipv6 import IPv6 as IPv6_Reassembly
# Base Class for Reassembly
from pcapkit.foundation.reassembly.reassembly import Reassembly
# Reassembly for TCP
from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly

__all__ = [
    'IPv4_Reassembly', 'IPv6_Reassembly',   # IP Reassembly
    'TCP_Reassembly',                       # TCP Reassembly
    'DTLS_Reassembly',                      # DTLS Reassembly
    'ReassemblyManager',                    # Reassembly Manager, defined below
]

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

if TYPE_CHECKING:
    from typing import Iterable, Iterator, Mapping, Optional

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

    #: The names held, in the order given, which iterating the manager follows.
    __additional__ = ['__order__']

    def __init__(self, dict_: 'Optional[Mapping[str, Optional[ReassemblyBase]] | Iterable[tuple[str, Optional[ReassemblyBase]]]]' = None,  # pylint: disable=line-too-long,super-init-not-called
                 **kwargs: 'Optional[ReassemblyBase]') -> 'None':
        given = dict(dict_ or (), **kwargs)
        held = {name: reasm for (name, reasm) in given.items() if reasm is not None}
        self.__update__(held)
        object.__setattr__(self, '__order__', tuple(held))
        self.__post_init__()

    def __iter__(self) -> 'Iterator[str]':
        # NOTE: PyPy may lay out an instance's ``__dict__`` in an earlier instance's order, so the
        # order given is recorded (#2814); ``from_dict`` records none, and falls back.
        return iter(self.__dict__.get('__order__') or super().__iter__())
