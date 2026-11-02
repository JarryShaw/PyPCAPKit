# -*- coding: utf-8 -*-
"""Internet Checksum
=====================

.. module:: pcapkit.corekit.checksum.internet

:mod:`pcapkit.corekit.checksum.internet` contains the one's-complement
Internet checksum (:rfc:`1071`) of the IPv4 header, TCP, UDP, ICMP, ICMPv6
and OSPF: :class:`ChecksumStatus`, the outcome a parse records, and the
functions that compute and verify the checksum. It imports nothing from
:mod:`pcapkit.protocols`, which builds on it (:issue:`2580`).

Verification is opt-in and computation opt-out, by
:data:`~pcapkit.utilities.config.CHECKSUM_VERIFY` and
:data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` (:issue:`2471`). A
mismatch warns with a :exc:`~pcapkit.utilities.warnings.ChecksumWarning`,
which a filter can silence alone (:issue:`2470`).

A checksum over the IP pseudo-header is left to the enclosing IP layer, see
:mod:`pcapkit.protocols.misc.checksum.ip_pseudo`. A checksum over the upper
layer alone, as ICMP's, is verified as it is parsed, unless the IP layer it is
parsed from is a fragment, see :func:`fragment_payload`.

.. versionadded:: 1.6.0

"""
import contextlib
import enum
import struct
from typing import TYPE_CHECKING

from pcapkit.corekit.enum import EnumLookup
from pcapkit.utilities.contextvars import in_fragment, rebuilding
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import ChecksumWarning, warn

if TYPE_CHECKING:
    from typing import Collection, Iterator, Optional

__all__ = [
    'ChecksumStatus',
    'internet_checksum', 'compute_checksum', 'partial_checksum', 'verify_checksum',
    'fragment_payload',
]


class ChecksumStatus(EnumLookup, enum.IntEnum):
    """Outcome of verifying a checksum, as recorded in ``checksum_status``.

    ``get`` / ``get_all`` come from :class:`~pcapkit.corekit.enum.EnumLookup`;
    the class defines no ``_missing_``, so an unknown value raises
    :exc:`ValueError`.

    """

    #: The checksum matches.
    VALID = 0
    #: The checksum does not match, which warns with a
    #: :exc:`~pcapkit.utilities.warnings.ChecksumWarning`.
    INVALID = 1
    #: The field holds no checksum: one the protocol lets the sender leave
    #: out, as UDP over IPv4 does with zero (:rfc:`768`), or what checksum
    #: offload leaves in a capture taken on the sending host. This is the
    #: expected state for such a capture, and is **not** an error.
    NOT_COMPUTED = 2
    #: Fewer octets were captured than the checksum covers.
    TRUNCATED = 3
    #: The enclosing IP layer does not give what the checksum covers: it is
    #: a fragment, holding only part of the datagram, or the pseudo-header
    #: cannot be derived from it.
    NO_PSEUDO_HEADER = 4


def _sum(data: 'bytes') -> 'int':
    """One's-complement sum of ``data`` in 16-bit words (:rfc:`1071`).

    Args:
        data: Octets to sum, padded with a zero octet if of odd length.

    Returns:
        The sum, folded to 16 bits.

    """
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def internet_checksum(data: 'bytes') -> 'int':
    """Compute the Internet checksum of ``data`` (:rfc:`1071`).

    Args:
        data: Octets the checksum covers, with the checksum field zeroed.

    Returns:
        The one's complement of the one's-complement sum of ``data``.

    """
    return ~_sum(data) & 0xFFFF


def compute_checksum(data: 'bytes', *, prefix: 'bytes' = b'', nonzero: 'bool' = False) -> 'bytes':
    """Compute the checksum field of ``data``.

    Args:
        data: Octets the checksum covers, with the checksum field zeroed.
        prefix: Pseudo-header octets the checksum covers ahead of ``data``.
        nonzero: Whether a computed zero is written as ``0xFFFF``, as UDP does
            (:rfc:`768`), since its zero means no checksum.

    Returns:
        The two octets of the checksum field.

    """
    value = internet_checksum(prefix + data)
    if nonzero and not value:
        value = 0xFFFF
    return value.to_bytes(2, 'big')


def partial_checksum(prefix: 'bytes') -> 'bytes':
    """The field checksum offload leaves for a pseudo-header checksum.

    A sender that offloads the checksum to its NIC writes the one's-complement
    sum of the pseudo-header alone, uncomplemented, for the NIC to finish, as
    Linux does for TCP and UDP; a capture taken on that host records it so.

    Args:
        prefix: Pseudo-header octets.

    Returns:
        The two octets of that partial checksum.

    """
    return _sum(prefix).to_bytes(2, 'big')


def verify_checksum(alias: 'str', data: 'bytes', field: 'bytes', *, length: 'Optional[int]' = None,
                    prefix: 'bytes' = b'', absent: 'Optional[bytes]' = None,
                    offload: 'Collection[bytes]' = ()) -> 'ChecksumStatus':
    """Verify the checksum ``field`` of ``data``.

    Args:
        alias: Protocol alias, to name in the warning.
        data: Octets the checksum covers, the checksum field included.
        field: The checksum field, as on the wire.
        length: Octets the checksum covers, as the headers declare it; the
            length of ``data`` by default.
        prefix: Pseudo-header octets the checksum covers ahead of ``data``.
        absent: Field value that means the sender left the checksum out.
        offload: Field values checksum offload leaves on the sending host.

    Returns:
        :attr:`~ChecksumStatus.VALID` if the sum of ``prefix`` and ``data`` is
        all ones (:rfc:`1071`), or the reason it is not.

    Warns:
        ChecksumWarning: If the checksum is :attr:`~ChecksumStatus.INVALID`,
            unless a payload is being rebuilt: the layer it is rebuilt for
            parses the same octets again, so a rebuilt frame warns once.

    """
    if length is not None:
        if len(data) < length:
            return ChecksumStatus.TRUNCATED
        data = data[:length]
    if absent is not None and field == absent:
        return ChecksumStatus.NOT_COMPUTED

    total = _sum(prefix + data)
    if total == 0xFFFF:
        return ChecksumStatus.VALID
    if field in offload:
        return ChecksumStatus.NOT_COMPUTED

    # NOTE: Adding the field's complement takes it back out of the sum, so the
    # value expected is found without knowing where the field sits.
    value = int.from_bytes(field, 'big')
    rest = total + (~value & 0xFFFF)
    expected = ~((rest & 0xFFFF) + (rest >> 16)) & 0xFFFF
    if not rebuilding.get():
        warn(f'{alias}: checksum {value:#06x} is wrong; {expected:#06x} expected',
             ChecksumWarning, stacklevel=stacklevel())
    return ChecksumStatus.INVALID


@contextlib.contextmanager
def fragment_payload(fragment: 'bool') -> 'Iterator[None]':
    """Mark the payload an IP layer parses as a fragment's, or not.

    A checksum over the upper layer alone, as ICMP's (:rfc:`792`), covers all
    of the datagram's data, which a fragment carries part of, so the upper
    layer of one records :attr:`~ChecksumStatus.NO_PSEUDO_HEADER` rather than
    being verified (:issue:`2470`). The nearest enclosing IP layer decides.

    Args:
        fragment: Whether the IP layer is a fragment; an atomic one is not.

    """
    token = in_fragment.set(fragment)
    try:
        yield
    finally:
        in_fragment.reset(token)
