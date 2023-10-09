# -*- coding: utf-8 -*-
"""IPv6 Datagram Reassembly
==============================

.. module:: pcapkit.foundation.reassembly.ipv6

:mod:`pcapkit.foundation.reassembly.ipv6` contains
:class:`~pcapkit.foundation.reassembly.ipv6.IPv6`
only, which reconstructs fragmented IPv6 packets back to
origin. Please refer to :doc:`ip` for more information.

"""
from pcapkit.foundation.reassembly.ip import IP
from pcapkit.protocols.internet.ipv6 import IPv6 as IPv6_Protocol

__all__ = ['IPv6']


# BUG: It is supposed to be ``IP[IPv6Address]``. But somehow Python
# thinks that ``IP`` should take 4 arguments as in its parent class
# ``Reassembly``. So we have to drop the type hint here.
class IPv6(IP):
    """Reassembly for IPv6 payload.

    Args:
        strict: if return all datagrams (including those not
                implemented) when submit
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
            (if not, datagram will be discarded after callback)

    Example:
        >>> from pcapkit.foundation.reassembly import IPv6
        # Initialise instance:
        >>> ipv6_reassembly = IPv6()
        # Call reassembly:
        >>> ipv6_reassembly(packet_dict)
        # Fetch result:
        >>> result = ipv6_reassembly.datagram

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object.
    __protocol_name__ = 'IPv6'
    #: Protocol of current reassembly object.
    __protocol_type__ = IPv6_Protocol
