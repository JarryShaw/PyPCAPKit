# -*- coding: utf-8 -*-
"""internet protocol

:mod:`pcapkit.protocols.internet.ip` contains
:class:`~pcapkit.protocols.internet.ip.IP` only,
which is a base class for Internet Protocol (IP)
protocol family [*]_, eg.
:class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`, and
:class:`~pcapkit.protocols.internet.ipsec.IPsec`.

.. [*] https://en.wikipedia.org/wiki/Internet_Protocol

"""
from pcapkit.protocols.internet.internet import Internet

__all__ = ['IP']


class IP(Internet):  # pylint: disable=abstract-method
    """This class implements all protocols in IP family.

    - Internet Protocol version 4 (:class:`~pcapkit.protocols.internet.ipv4.IPv4`) [:rfc:`791`]
    - Internet Protocol version 6 (:class:`~pcapkit.protocols.internet.ipv6.IPv6`) [:rfc:`2460`]
    - Authentication Header (:class:`~pcapkit.protocols.internet.ah.AH`) [:rfc:`4302`]
    - Encapsulating Security Payload (:class:`~pcapkit.protocols.internet.esp.ESP`) [:rfc:`4303`]

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    # source IP address
    @property
    def src(self):
        """Source IP address.

        :rtype: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
        """
        return self._info.src  # pylint: disable=E1101

    # destination IP address
    @property
    def dst(self):
        """Destination IP address.

        :rtype: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
        """
        return self._info.dst  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
            Tuple[Literal['IPv4'], Literal['IPv6']]: Index ID of the protocol.

        """
        return ('IPv4', 'IPv6')
