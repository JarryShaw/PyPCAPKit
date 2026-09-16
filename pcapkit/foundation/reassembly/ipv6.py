# -*- coding: utf-8 -*-
"""IPv6 Datagram Reassembly
==============================

.. module:: pcapkit.foundation.reassembly.ipv6

:mod:`pcapkit.foundation.reassembly.ipv6` contains
:class:`~pcapkit.foundation.reassembly.ipv6.IPv6`
only, which reconstructs fragmented IPv6 packets back to
origin. Please refer to :doc:`ip` for more information.

"""
from typing import TYPE_CHECKING

from pcapkit.foundation.reassembly.ip import IP
from pcapkit.protocols.internet.ipv6 import IPv6 as IPv6_Protocol

if TYPE_CHECKING:
    from pcapkit.const.reg.transtype import TransType

__all__ = ['IPv6']

#: Length of the fixed IPv6 header, i.e. the offset of the first extension
#: header (:rfc:`8200#section-3`).
_IPV6_HDR_LEN = 40

#: Offset of the Next Header field within the fixed IPv6 header.
_IPV6_NEXT_HEADER = 6

#: Next Header value of the IPv6 Fragment header (:rfc:`8200#section-4.5`).
_NH_IPV6_FRAG = 44

#: Next Header value of the Authentication Header. It is the one extension
#: header that does not measure its length in 8-octet units
#: (:rfc:`4302#section-2.2`), so the header walk below has to special-case it.
_NH_AH = 51


def _next_header_offset(header: 'bytes') -> 'int':
    """Locate the Next Header field of a datagram's last header.

    :rfc:`8200#section-4.5` gives the Next Header field of the *last* header of
    the unfragmentable part -- not necessarily the fixed IPv6 header's, since
    Hop-by-Hop Options, Routing and Destination Options headers may precede the
    Fragment header. Each of those starts with its own Next Header field, so the
    answer is found by walking the chain to its end.

    Args:
        header: Unfragmentable part of a datagram, i.e. every octet of the
            fragment before its Fragment header.

    Returns:
        Offset, within ``header``, of the Next Header field to rewrite.

    """
    offset = _IPV6_NEXT_HEADER
    position = _IPV6_HDR_LEN
    proto = header[offset]

    # NOTE: ``header[position]`` is the Next Header field of the extension
    # header starting at ``position`` and ``header[position + 1]`` its length,
    # but which of the two length encodings applies is decided by the *previous*
    # header's Next Header value -- hence ``proto`` trailing one step behind.
    while position + 1 < len(header):
        offset = position
        if proto == _NH_AH:
            position += (header[position + 1] + 2) * 4
        else:
            position += (header[position + 1] + 1) * 8
        proto = header[offset]
    return offset


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

    ##########################################################################
    # Methods.
    ##########################################################################

    def _rectify_header(self, header: 'bytes', proto: 'TransType') -> 'bytes':
        """Remove the Fragment header from a datagram's header chain.

        :rfc:`8200#section-4.5` states that the Fragment header is not present in
        the reassembled packet, and that the Next Header field of the last header
        of the unfragmentable part comes from the Fragment header's. Left alone,
        the reassembled datagram advertises a Fragment header on a datagram that
        is by definition no longer a fragment, which is what every engine used to
        report -- the toolkit adapters differ over whether the Fragment header's
        *octets* belong to ``header``, but none of them rewrote the field that
        points at it.

        The Fragment header's own octets are already excluded by the adapters, so
        only the field pointing at it is left to fix.

        Args:
            header: Raw header octets of the fragment at fragment offset zero.
            proto: Payload protocol type, i.e. the Fragment header's Next Header
                field, which is what the rewritten field must carry.

        Returns:
            Header octets to keep for the reassembled datagram.

        """
        # a header too short to hold the fixed IPv6 header cannot be walked, and
        # a chain not ending in the Fragment header has nothing to rewrite --
        # which also makes this idempotent
        if len(header) < _IPV6_HDR_LEN:
            return header
        offset = _next_header_offset(header)
        if header[offset] != _NH_IPV6_FRAG:
            return header
        return header[:offset] + bytes((int(proto),)) + header[offset + 1:]
