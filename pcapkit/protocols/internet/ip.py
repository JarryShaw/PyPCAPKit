# -*- coding: utf-8 -*-
"""IP - Internet Protocol
============================

.. module:: pcapkit.protocols.internet.ip

:mod:`pcapkit.protocols.internet.ip` contains
:class:`~pcapkit.protocols.internet.ip.IP` only,
which is a base class for Internet Protocol (IP)
protocol family [*]_, eg.
:class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`, and
:class:`~pcapkit.protocols.internet.ipsec.IPsec`.

.. [*] https://en.wikipedia.org/wiki/Internet_Protocol

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['IP']


class IP(Internet[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """This class implements all protocols in IP family.

    - Internet Protocol version 4 (:class:`~pcapkit.protocols.internet.ipv4.IPv4`) [:rfc:`791`]
    - Internet Protocol version 6 (:class:`~pcapkit.protocols.internet.ipv6.IPv6`) [:rfc:`2460`]
    - Authentication Header (:class:`~pcapkit.protocols.internet.ah.AH`) [:rfc:`4302`]
    - Encapsulating Security Payload (:class:`~pcapkit.protocols.internet.esp.ESP`) [:rfc:`4303`]

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["IPv4"], Literal["IPv6"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('IPv4', 'IPv6')
