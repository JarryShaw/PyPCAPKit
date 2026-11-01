# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Linux Netlink socket framing

Every field of ``nlmsghdr`` is kept as raw octets rather than unpacked by a
fixed byte order -- the byte order itself is ambiguous (see
:func:`~pcapkit.protocols.link.netlink.nlmsg_byteorder`) and has to be
resolved before any of the fields can be read as integers.

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['Netlink']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class Netlink(Schema):
    """Header schema for Linux Netlink socket framing (``nlmsghdr``)."""

    #: Message length, including this header; 4 octets, byte order ambiguous.
    nlmsg_len: 'bytes' = BytesField(length=4)
    #: Message type; 2 octets, byte order ambiguous.
    nlmsg_type: 'bytes' = BytesField(length=2)
    #: Message flags; 2 octets, byte order ambiguous.
    nlmsg_flags: 'bytes' = BytesField(length=2)
    #: Sequence number; 4 octets, byte order ambiguous.
    nlmsg_seq: 'bytes' = BytesField(length=4)
    #: Sender port ID; 4 octets, byte order ambiguous.
    nlmsg_pid: 'bytes' = BytesField(length=4)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, nlmsg_len: 'bytes', nlmsg_type: 'bytes', nlmsg_flags: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     nlmsg_seq: 'bytes', nlmsg_pid: 'bytes',  # pylint: disable=unused-argument
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument
