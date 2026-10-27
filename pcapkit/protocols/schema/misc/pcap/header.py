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
    from typing import Any, Dict

    from typing_extensions import Literal

    from pcapkit.corekit.fields.numbers import NumberField

#: Length of the PCAP global header, which opens the file. The one home of
#: this value (:issue:`1739`); the format fixes it, so it is never configurable.
#:
#: .. versionadded:: 1.5.0
GLOBAL_HEADER_LEN = 24

#: PCAP magic numbers, as the octets open the file, mapped to the byte order
#: (``'big'`` or ``'little'``) and the timestamp resolution (:data:`True` for
#: nanoseconds, :data:`False` for microseconds) each one declares. The one home
#: of these values (:issue:`1739`); the format fixes them, so they are never
#: configurable.
#:
#: .. versionadded:: 1.5.0
MAGIC_NUMBER = {
    b'\xa1\xb2\x3c\x4d': ('big', True),
    b'\xa1\xb2\xc3\xd4': ('big', False),
    b'\x4d\x3c\xb2\xa1': ('little', True),
    b'\xd4\xc3\xb2\xa1': ('little', False),
}  # type: Dict[bytes, tuple[Literal['big', 'little'], bool]]

#: Units per second of a record's ``ts_usec`` field, keyed by the nanosecond
#: flag its file's magic number declares (:data:`MAGIC_NUMBER`): microseconds,
#: or nanoseconds. The one home of these values (:issue:`1739`); the format
#: fixes them, so they are never configurable.
#:
#: .. versionadded:: 1.5.0
RESOLUTION = {
    False: 1_000_000,
    True: 1_000_000_000,
}  # type: Dict[bool, int]

#: Decimal places of a ``ts_usec`` fraction at each resolution of
#: :data:`RESOLUTION`, keyed the same way -- six for microseconds, nine for
#: nanoseconds -- and derived from it, so that an epoch rounded to its file's
#: resolution follows the one home (:issue:`1739`).
#:
#: .. versionadded:: 1.5.0
RESOLUTION_PLACES = {
    flag: len(str(units)) - 1 for flag, units in RESOLUTION.items()
}  # type: Dict[bool, int]


def magic_number_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Calculate byte order of PCAP file.

    Args:
        field: Field instance.
        packet: Packet data.

    """
    magic_number = packet['magic_number']
    # NOTE: looked up as :obj:`bytes`, so that a :obj:`bytearray` magic number
    # is matched rather than rejected as unhashable.
    declared = (MAGIC_NUMBER.get(bytes(magic_number))
                if isinstance(magic_number, (bytes, bytearray, memoryview)) else None)
    if declared is None:
        raise ProtocolError(f'PCAP: invalid magic number: {magic_number!r}')
    field._byteorder = declared[0]


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
