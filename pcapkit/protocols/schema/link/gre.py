# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Generic Routing Encapsulation (GRE) frames"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['GRE']

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class FlagsType(TypedDict):
        """Type of the flags-and-version word of a GRE header."""

        #: Checksum Present (``C``).
        checksum_present: int
        #: Reserved bit 1 of the flags word.
        reserved_1: int
        #: Key Present (``K``), :rfc:`2890`.
        key_present: int
        #: Sequence Number Present (``S``), :rfc:`2890`.
        sequence_present: int
        #: Reserved bits 4-12 of the flags word.
        reserved_2: int
        #: Version Number; :rfc:`2784` requires this to be ``0``.
        version: int


@schema_final
class GRE(Schema):
    """Header schema for a Generic Routing Encapsulation (GRE) frame.

    The base header [:rfc:`2784`] plus the optional Key and Sequence Number
    extensions [:rfc:`2890`], as presented to a ``LINKTYPE_LINUX_SLL``/
    ``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type`` is ``ARPHRD_IPGRE``
    or ``ARPHRD_IP6GRE``.

    """

    #: Flags and version.
    flags: 'FlagsType' = BitField(length=2, namespace={
        'checksum_present': (0, 1),
        'reserved_1': (1, 1),
        'key_present': (2, 1),
        'sequence_present': (3, 1),
        'reserved_2': (4, 9),
        'version': (13, 3),
    })
    #: Protocol Type: the EtherType of the encapsulated payload.
    protocol_type: 'Enum_EtherType' = EnumField(length=2, namespace=Enum_EtherType)
    #: Checksum, present only when ``flags.checksum_present`` is set.
    checksum: 'Optional[int]' = ConditionalField(
        UInt16Field(),
        lambda packet: packet['flags']['checksum_present'],
    )
    #: Reserved1, present only when ``flags.checksum_present`` is set.
    reserved1: 'Optional[int]' = ConditionalField(
        UInt16Field(),
        lambda packet: packet['flags']['checksum_present'],
    )
    #: Key, present only when ``flags.key_present`` is set, :rfc:`2890`.
    key: 'Optional[int]' = ConditionalField(
        UInt32Field(),
        lambda packet: packet['flags']['key_present'],
    )
    #: Sequence Number, present only when ``flags.sequence_present`` is set,
    #: :rfc:`2890`.
    sequence_number: 'Optional[int]' = ConditionalField(
        UInt32Field(),
        lambda packet: packet['flags']['sequence_present'],
    )
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, flags: 'FlagsType', protocol_type: 'Enum_EtherType',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     checksum: 'Optional[int]', reserved1: 'Optional[int]',  # pylint: disable=unused-argument
                     key: 'Optional[int]', sequence_number: 'Optional[int]',  # pylint: disable=unused-argument
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument
