# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for global header of PCAP file format"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.fields.numbers import EnumField, Int32Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['Header']

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.corekit.fields.numbers import NumberField


def magic_number_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Calculate byte order of PCAP file.

    Args:
        field: Field instance.
        packet: Packet data.

    """
    magic_number = packet['magic_number']
    if magic_number == b'\xd4\xc3\xb2\xa1':
        field._byteorder = 'little'
    elif magic_number == b'\xa1\xb2\xc3\xd4':
        field._byteorder = 'big'
    elif magic_number == b'\x4d\x3c\xb2\xa1':
        field._byteorder = 'little'
    elif magic_number == b'\xa1\xb2\x3c\x4d':
        field._byteorder = 'big'
    else:
        raise ProtocolError('invalid magic number')


@schema_final
class Header(Schema):
    """Global header of PCAP file."""

    #: Magic number.
    magic_number: 'bytes' = BytesField(length=4)
    #: Version number major.
    version_major: 'int' = UInt16Field(callback=magic_number_callback)
    #: Version number minor.
    version_minor: 'int' = UInt16Field(callback=magic_number_callback)
    #: GMT to local correction.
    thiszone: 'int' = Int32Field(callback=magic_number_callback)
    #: Accuracy of timestamps.
    sigfigs: 'int' = UInt32Field(callback=magic_number_callback)
    #: Max length of captured packets, in octets.
    snaplen: 'int' = UInt32Field(callback=magic_number_callback)
    #: Data link type.
    network: 'Enum_LinkType' = EnumField(length=4, namespace=Enum_LinkType, callback=magic_number_callback)

    if TYPE_CHECKING:
        def __init__(self, magic_number: 'bytes', version_major: 'int', version_minor: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     thiszone: 'int', sigfigs: 'int', snaplen: 'int', network: 'int') -> 'None': ...
