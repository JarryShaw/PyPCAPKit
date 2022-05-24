# -*- coding: utf-8 -*-
"""internet protocol security

:mod:`pcapkit.protocols.internet.ipsec` contains
:class:`~pcapkit.protocols.internet.ipsec.IPsec`
only, which is a base class for Internet Protocol
Security (IPsec) protocol family [*]_, eg.
:class:`~pcapkit.protocols.internet.ah.AH` and
:class:`~pcapkit.protocols.internet.esp.ESP`
(**NOT IMPLEMENTED**).

.. [*] https://en.wikipedia.org/wiki/IPsec

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.protocols.protocol import PT
from pcapkit.protocols.internet.internet import Internet

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['IPsec']


class IPsec(Internet[PT], Generic[PT]):  # pylint: disable=abstract-method
    """Abstract base class for IPsec protocol family.

    - Authentication Header (:class:`~pcapkit.protocols.internet.ah.AH`) [:rfc:`4302`]
    - Encapsulating Security Payload (:class:`~pcapkit.protocols.internet.esp.ESP`) [:rfc:`4303`]

    """

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["AH"], Literal["ESP"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('AH', 'ESP')