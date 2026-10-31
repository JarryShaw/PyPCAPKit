# -*- coding: utf-8 -*-
"""data model for ICMPv6 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.icmpv6.type import Type as Enum_Type

__all__ = [
    'ICMPv6',

    'Unknown', 'DestinationUnreachable', 'PacketTooBig', 'TimeExceeded',
    'ParameterProblem', 'Echo',
]


class ICMPv6(Protocol):
    """Data model for ICMPv6 protocol.

    The fields below are the only ones every ICMPv6 message shares
    (:rfc:`4443`); what follows them is read entirely differently depending
    on :attr:`type`, which is why each message kind below adds its own
    fields rather than this base class growing a union of them all.

    """

    #: ICMPv6 type.
    type: 'Enum_Type'
    #: ICMPv6 code. Left untyped as a bare :obj:`int` here because its
    #: meaning is entirely :attr:`type`-dependent; each subclass below
    #: documents which registry (if any) its own ``code`` values are drawn
    #: from.
    code: 'int'
    #: Checksum, kept as on the wire; it is neither verified nor computed.
    checksum: 'bytes'
    #: Message length, in octets, header included. ICMPv6 messages carry no
    #: length field of their own -- this is simply how many octets
    #: :meth:`ICMPv6.read <pcapkit.protocols.internet.icmpv6.ICMPv6.read>`
    #: was handed, kept here so the whole message can be told apart from a
    #: truncated capture.
    length: 'int'


@info_final
class Unknown(ICMPv6):
    """Data model for ICMPv6 packet of unknown type.

    ``code`` carries no :mod:`pcapkit.const` registry for a type this
    package does not recognise, so it is read as a bare :obj:`int`.

    """

    #: Message body, as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class DestinationUnreachable(ICMPv6):
    """Data model for ICMPv6 Destination Unreachable message (type 1).

    .. seealso::

       :class:`pcapkit.const.icmpv6.destination_unreachable_code.DestinationUnreachableCode`

    """

    #: Unused (four octets, :rfc:`4443#section-3.1`), as captured.
    unused: 'bytes'
    #: As much of the invoking packet as fits the minimum IPv6 MTU, per
    #: :rfc:`4443#section-3.1`, as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     unused: 'bytes', data: 'bytes') -> 'None': ...


@info_final
class PacketTooBig(ICMPv6):
    """Data model for ICMPv6 Packet Too Big message (type 2).

    ``code`` is always ``0`` (:rfc:`4443#section-3.2`), so it is read as a
    bare :obj:`int` rather than typed against a registry of one member.

    """

    #: MTU of the link that could not forward the invoking packet.
    mtu: 'int'
    #: As much of the invoking packet as fits the minimum IPv6 MTU, per
    #: :rfc:`4443#section-3.2`, as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     mtu: 'int', data: 'bytes') -> 'None': ...


@info_final
class TimeExceeded(ICMPv6):
    """Data model for ICMPv6 Time Exceeded message (type 3).

    .. seealso::

       :class:`pcapkit.const.icmpv6.time_exceeded_code.TimeExceededCode`

    """

    #: Unused (four octets, :rfc:`4443#section-3.3`), as captured.
    unused: 'bytes'
    #: As much of the invoking packet as fits the minimum IPv6 MTU, per
    #: :rfc:`4443#section-3.3`, as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     unused: 'bytes', data: 'bytes') -> 'None': ...


@info_final
class ParameterProblem(ICMPv6):
    """Data model for ICMPv6 Parameter Problem message (type 4).

    .. seealso::

       :class:`pcapkit.const.icmpv6.parameter_problem_code.ParameterProblemCode`

    """

    #: Pointer, identifying the octet offset within the invoking packet
    #: where the error was detected (:rfc:`4443#section-3.4`).
    pointer: 'int'
    #: As much of the invoking packet as fits the minimum IPv6 MTU, per
    #: :rfc:`4443#section-3.4`, as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     pointer: 'int', data: 'bytes') -> 'None': ...


@info_final
class Echo(ICMPv6):
    """Data model for ICMPv6 Echo Request/Reply message (types 128 and 129).

    ``code`` is always ``0`` for both types (:rfc:`4443#section-4.1`,
    :rfc:`4443#section-4.2`), so it is read as a bare :obj:`int` rather than
    typed against a registry of one member.

    """

    #: Identifier.
    id: 'int'
    #: Sequence number.
    seq: 'int'
    #: Data, echoed back verbatim by a reply to the same identifier and
    #: sequence number.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     id: 'int', seq: 'int', data: 'bytes') -> 'None': ...
