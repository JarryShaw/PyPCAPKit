# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Frame Relay Access Device (FRAD) frames"""

from typing import TYPE_CHECKING, cast

from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['FRAD']

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class AddressType(TypedDict):
        """Type of the Q.922 address field (2-octet form)."""

        #: DLCI, high-order 6 bits.
        dlci_hi: int
        #: Command/response indication.
        cr: int
        #: Address field extension, octet 1 -- ``0`` in the 2-octet form.
        ea1: int
        #: DLCI, low-order 4 bits.
        dlci_lo: int
        #: Forward explicit congestion notification.
        fecn: int
        #: Backward explicit congestion notification.
        becn: int
        #: Discard eligibility.
        de: int
        #: Address field extension, octet 2 -- ``1`` in the 2-octet form.
        ea2: int


def _effective_nlpid(packet: 'dict[str, Any]') -> 'int':
    """Resolve the NLPID that actually selects the encapsulated protocol.

    Args:
        packet: Packet data, built incrementally by :meth:`Schema.unpack
            <pcapkit.protocols.schema.schema.Schema.unpack>` or supplied whole
            by :meth:`FRAD.make <pcapkit.protocols.link.frad.FRAD.make>`.

    Returns:
        :attr:`~FRAD.ext_nlpid` when :attr:`~FRAD.nlpid` is the ``0x00`` pad
        marker :rfc:`2427#section-3` writes ahead of a SNAP header; otherwise
        :attr:`~FRAD.nlpid` itself.

    """
    nlpid = packet['nlpid']
    if nlpid:
        return cast('int', nlpid)
    ext = packet.get('ext_nlpid')
    return ext if isinstance(ext, int) else 0


def _is_snap(packet: 'dict[str, Any]') -> 'bool':
    """Whether the frame is SNAP-encapsulated, per :func:`_effective_nlpid`."""
    return _effective_nlpid(packet) == 0x80


@schema_final
class FRAD(Schema):
    """Header schema for a Frame Relay Access Device (FRAD) frame.

    The frame is Frame Relay's multiprotocol encapsulation [:rfc:`2427`,
    obsoleting :rfc:`1490`] as presented to a ``LINKTYPE_LINUX_SLL``/
    ``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type`` is ``ARPHRD_FRAD``:
    the Q.922 LAPF address onward, with no trailing FCS.

    """

    #: Q.922 address field (2-octet form only; see :rfc:`2427#section-3`).
    addr: 'AddressType' = BitField(length=2, namespace={
        'dlci_hi': (0, 6),
        'cr': (6, 1),
        'ea1': (7, 1),
        'dlci_lo': (8, 4),
        'fecn': (12, 1),
        'becn': (13, 1),
        'de': (14, 1),
        'ea2': (15, 1),
    })
    #: Control field; ``0x03`` (UI) for ordinary data traffic.
    control: 'int' = UInt8Field()
    #: NLPID, or the ``0x00`` pad marker ahead of a SNAP header.
    nlpid: 'int' = UInt8Field()
    #: NLPID proper, present only when :attr:`nlpid` is the pad marker.
    ext_nlpid: 'Optional[int]' = ConditionalField(
        UInt8Field(),
        lambda packet: not packet['nlpid'],
    )
    #: SNAP OUI, present only when the frame is SNAP-encapsulated.
    oui: 'Optional[bytes]' = ConditionalField(BytesField(length=3), _is_snap)
    #: SNAP PID, present only when the frame is SNAP-encapsulated.
    pid: 'Optional[int]' = ConditionalField(UInt16Field(), _is_snap)
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, addr: 'AddressType', control: 'int', nlpid: 'int',  # pylint: disable=unused-argument,super-init-not-called
                     ext_nlpid: 'Optional[int]', oui: 'Optional[bytes]', pid: 'Optional[int]',  # pylint: disable=unused-argument
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements
