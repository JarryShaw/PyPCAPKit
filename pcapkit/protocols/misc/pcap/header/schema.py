# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for global header of PCAP file format

.. versionremoved:: 1.7.0

   ``pcapkit.protocols.misc.pcap.header.schema.MAGIC_NUMBER``,
   ``pcapkit.protocols.misc.pcap.header.schema.RESOLUTION`` and
   ``pcapkit.protocols.misc.pcap.header.schema.RESOLUTION_PLACES``, now
   :data:`pcapkit.corekit.const.capture.MAGIC_NUMBER`,
   :data:`pcapkit.corekit.const.capture.RESOLUTION` and
   :data:`pcapkit.corekit.const.capture.RESOLUTION_PLACES` (:issue:`2883`); and
   ``pcapkit.protocols.misc.pcap.header.schema.GLOBAL_HEADER_LEN``, now
   :data:`pcapkit.protocols.misc.pcap.header.const.GLOBAL_HEADER_LEN` (:issue:`2896`).

"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.const.capture import MAGIC_NUMBER
from pcapkit.corekit.fields.numbers import EnumField, Int32Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import Schema, schema_final
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
