# -*- coding: utf-8 -*-
"""IPsec - Internet Protocol Security
========================================

.. module:: pcapkit.protocols.internet.ipsec.protocol

:mod:`pcapkit.protocols.internet.ipsec.protocol` contains
:class:`~pcapkit.protocols.internet.ipsec.protocol.IPsec`
only, which is a base class for Internet Protocol
Security (IPsec) protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.ah.protocol.AH` and
:class:`~pcapkit.protocols.internet.esp.protocol.ESP`.

.. [*] https://en.wikipedia.org/wiki/IPsec

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['IPsec']


class IPsec(Internet[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for IPsec protocol family.

    - Authentication Header (:class:`~pcapkit.protocols.internet.ah.protocol.AH`) [:rfc:`4302`]
    - Encapsulating Security Payload (:class:`~pcapkit.protocols.internet.esp.protocol.ESP`) [:rfc:`4303`]

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["AH"], Literal["ESP"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('AH', 'ESP')
