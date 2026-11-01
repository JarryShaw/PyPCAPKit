# -*- coding: utf-8 -*-
"""DRARP - Dynamic Reverse Address Resolution Protocol
=========================================================

.. module:: pcapkit.protocols.application.drarp

:mod:`pcapkit.protocols.application.drarp` contains
:class:`~pcapkit.protocols.application.drarp.DRARP` only,
which implements an extractor for Dynamic Reverse Address
Resolution Protocol (DRARP) [*]_, whose frame is the one
:mod:`pcapkit.protocols.application.rarp` describes.

Nothing dispatches to :class:`~pcapkit.protocols.application.drarp.DRARP`:
under EtherType ``0x8035``, a DRARP operation parses as
:class:`~pcapkit.protocols.application.rarp.RARP` with alias ``DRARP``.

.. [*] https://datatracker.ietf.org/doc/html/rfc1931

.. versionadded:: 1.6.0

   Moved here from :mod:`pcapkit.protocols.application.rarp`, which keeps
   :class:`~pcapkit.protocols.application.rarp.RARP` alone, since a module
   holds one protocol class, named after it (:issue:`2529`).

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.application.rarp import RARP
from pcapkit.protocols.data.link.arp import ARP as Data_ARP
from pcapkit.protocols.schema.link.arp import ARP as Schema_ARP

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['DRARP']


class DRARP(RARP, schema=Schema_ARP, data=Data_ARP):
    """This class implements Dynamic Reverse Address Resolution Protocol.

    Inherits RARP's bases unchanged, so ``layer == 'Application'`` here too --
    :rfc:`1931` makes it RARP with dynamic allocation, the same function and so
    the same layer.

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["DRARP"]]':  # type: ignore[override]
        """Index ID of the protocol."""
        return ('DRARP',)
