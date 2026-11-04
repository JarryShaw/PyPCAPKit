# -*- coding: utf-8 -*-
"""InARP - Inverse Address Resolution Protocol
=================================================

.. module:: pcapkit.protocols.link.inarp.protocol

:mod:`pcapkit.protocols.link.inarp.protocol` contains
:class:`~pcapkit.protocols.link.inarp.protocol.InARP` only,
which implements an extractor for Inverse Address
Resolution Protocol (InARP) [*]_, whose frame is the one
:mod:`pcapkit.protocols.link.arp.protocol` describes.

Nothing dispatches to :class:`~pcapkit.protocols.link.inarp.protocol.InARP`:
under EtherType ``0x0806``, an InARP operation parses as
:class:`~pcapkit.protocols.link.arp.protocol.ARP` with alias ``InARP``.

.. [*] https://datatracker.ietf.org/doc/html/rfc2390

.. versionadded:: 1.6.0

   Moved here from :mod:`pcapkit.protocols.link.arp.protocol`, which keeps
   :class:`~pcapkit.protocols.link.arp.protocol.ARP` alone, since a module holds one
   protocol class, named after it (:issue:`2529`).

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.link.arp.data import ARP as Data_ARP
from pcapkit.protocols.link.arp.protocol import ARP
from pcapkit.protocols.link.arp.schema import ARP as Schema_ARP

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['InARP']


class InARP(ARP, schema=Schema_ARP, data=Data_ARP):
    """This class implements Inverse Address Resolution Protocol.

    .. versionchanged:: 1.5.0

       Parses with the ARP schema rather than falling back to the raw one
       (:issue:`1204`).

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["InARP"]]':  # type: ignore[override]
        """Index ID of the protocol."""
        return ('InARP',)
