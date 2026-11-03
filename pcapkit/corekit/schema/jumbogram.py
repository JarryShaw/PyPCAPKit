# -*- coding: utf-8 -*-
"""Jumbo Payload Lookup
====================

.. module:: pcapkit.corekit.schema.jumbogram

:mod:`pcapkit.corekit.schema.jumbogram` finds the Jumbo Payload Length an IPv6
jumbogram declares in its Hop-by-Hop Options header [:rfc:`2675`], which is what
sizes a payload longer than the 16-bit Payload Length holds, for the IPv6 header
schema, the IPv6 pseudo-header and the Scapy toolkit alike. It is one of the
:mod:`pcapkit.corekit.schema` helpers shared across the schema layer, not part of
the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.protocols.schema.internet.ipv6`` (:issue:`2674`).

"""

from typing import TYPE_CHECKING

from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.reg.transtype import TransType as Enum_TransType

__all__ = ['jumbo_payload_length']

if TYPE_CHECKING:
    from typing import Optional


def jumbo_payload_length(next: 'int', data: 'bytes') -> 'Optional[int]':  # pylint: disable=redefined-builtin
    """Find the Jumbo Payload Length of an IPv6 packet [:rfc:`2675`].

    The Jumbo Payload option is only honoured in a Hop-by-Hop Options header
    that immediately follows the IPv6 header, as :rfc:`2675#section-2` and
    :rfc:`8200#section-4.1` place it there; one anywhere else is left to the
    extension header that carries it.

    Args:
        next: Next Header of the IPv6 header.
        data: Octets following the IPv6 header.

    Returns:
        The Jumbo Payload Length, or :data:`None` if ``data`` does not start
        with a Hop-by-Hop Options header carrying a well-formed (four-octet)
        Jumbo Payload option.

    """
    if next != Enum_TransType.HOPOPT or len(data) < 2:
        return None

    end = min((data[1] + 1) * 8, len(data))
    ptr = 2
    while ptr < end:
        code = data[ptr]
        if code == Enum_Option.Pad1:
            ptr += 1
            continue
        if ptr + 1 >= end:
            break
        size = data[ptr + 1]
        if code == Enum_Option.Jumbo_Payload and size == 4 and ptr + 6 <= end:
            return int.from_bytes(data[ptr + 2:ptr + 6], 'big', signed=False)
        ptr += 2 + size
    return None
