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
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects :attr:`__timeout__`

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

    #: float: Default reassembly timeout, in seconds, on the capture's clock.
    #:
    #: :rfc:`1122#section-3.3.2` is the governing text and it is emphatic on both
    #: halves: "There MUST be a reassembly timeout. The reassembly timeout value
    #: SHOULD be a fixed value, **not set from the remaining TTL**. It is
    #: recommended that the value lie between 60 seconds and 120 seconds." Its
    #: DISCUSSION explains why it overrode :rfc:`791`: gateways came to treat TTL
    #: as a hop count rather than elapsed seconds, so a TTL-derived deadline
    #: discards datagrams that were merely slow.
    #:
    #: :rfc:`791#section-3.2` is therefore *not* followed to the letter. Its
    #: scheme is ``TIMER <- MAX(TIMER,TTL)`` seeded from a "Timer Lower Bound",
    #: for which "the current recommendation for the initial timer setting is 15
    #: seconds" -- an initial lower bound that a later fragment's TTL raises,
    #: up to the 4.25-minute TTL ceiling, not a 15-second deadline. Two things
    #: rule it out here: the recommendation is superseded, and TTL is not in
    #: :class:`~pcapkit.foundation.reassembly.data.ip.Packet` at all, so the
    #: fragment model would have to grow a field to express a scheme the current
    #: requirement asks implementations not to use.
    #:
    #: 60 seconds is the low end of RFC 1122's range, and it makes IPv4 agree
    #: with the 60 seconds :rfc:`8200#section-4.5` mandates for IPv6 -- so one
    #: timestamp-driven eviction path serves both, which is the whole reason the
    #: buffer models carry a timestamp.
    __timeout__ = 60.0
