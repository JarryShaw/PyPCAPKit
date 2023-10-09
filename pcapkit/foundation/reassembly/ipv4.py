# -*- coding: utf-8 -*-
"""IPv4 Datagram Reassembly
==============================

.. module:: pcapkit.foundation.reassembly.ipv4

:mod:`pcapkit.foundation.reassembly.ipv4` contains
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4`
only, which reconstructs fragmented IPv4 packets back to
origin. Please refer to :doc:`ip` for more information.

"""
from pcapkit.foundation.reassembly.ip import IP
from pcapkit.protocols.internet.ipv4 import IPv4 as IPv4_Protocol

__all__ = ['IPv4']


# BUG: It is supposed to be ``IP[IPv4Address]``. But somehow Python
# thinks that ``IP`` should take 4 arguments as in its parent class
# ``Reassembly``. So we have to drop the type hint here.
class IPv4(IP):
    """Reassembly for IPv4 payload.

    Args:
        strict: if return all datagrams (including those not
                implemented) when submit
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
            (if not, datagram will be discarded after callback)

    Example:
        >>> from pcapkit.foundation.reassembly import IPv4
        # Initialise instance:
        >>> ipv4_reassembly = IPv4()
        # Call reassembly:
        >>> ipv4_reassembly(packet_dict)
        # Fetch result:
        >>> result = ipv4_reassembly.datagram

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object.
    __protocol_name__ = 'IPv4'
    #: Protocol of current reassembly object.
    __protocol_type__ = IPv4_Protocol
