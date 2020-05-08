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
from pcapkit.protocols.internet.ip import IP
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = 'IPsec'


class IPsec(IP):  # pylint: disable=abstract-method
    """Abstract base class for IPsec protocol family.

    - Authentication Header (:class:`~pcapkit.protocols.internet.ah.AH`) [:rfc:`4302`]
    - Encapsulating Security Payload (:class:`~pcapkit.protocols.internet.esp.ESP`) [:rfc:`4303`]

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def src(self):
        """Source IP address.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`src`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'src'")

    @property
    def dst(self):
        """Destination IP address.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`dst`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'dst'")

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
            Tuple[Literal['AH'], Literal['ESP']]: Index ID of the protocol.

        """
        return ('AH', 'ESP')
