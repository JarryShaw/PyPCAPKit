# -*- coding: utf-8 -*-
"""data model for ICMP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.icmp.type import Type as Enum_Type
    from pcapkit.corekit.checksum.internet import ChecksumStatus

__all__ = [
    'ICMPv4',

    'Unknown', 'Echo', 'DestinationUnreachable', 'TimeExceeded', 'ParameterProblem',
]


class ICMPv4(Protocol):
    """Data model for ICMP protocol.

    The fields below are the only ones every ICMP message shares
    (:rfc:`792`); what follows them is read entirely differently depending on
    :attr:`type`, which is why each message kind below adds its own fields
    rather than this base class growing a union of them all.

    """

    #: ICMP type.
    type: 'Enum_Type'
    #: ICMP code. Left untyped as a bare :obj:`int` here because its meaning
    #: is entirely :attr:`type`-dependent; each subclass below documents
    #: which registry (if any) its own ``code`` values are drawn from.
    code: 'int'
    #: Checksum.
    checksum: 'bytes'
    #: Message length, in octets, header included. ICMP messages carry no
    #: length field of their own -- this is simply how many octets
    #: :meth:`ICMPv4.read <pcapkit.protocols.internet.icmpv4.ICMPv4.read>` was
    #: handed, kept here so the whole message can be told apart from a
    #: truncated capture.
    length: 'int'

    if TYPE_CHECKING:
        #: Outcome of verifying :attr:`checksum`, present only when
        #: :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY` is on.
        checksum_status: 'ChecksumStatus'


@info_final
class Unknown(ICMPv4):
    """Data model for ICMP packet of unknown type.

    ``code`` carries no :mod:`pcapkit.const` registry for a type this
    package does not recognise, so it is read as a bare :obj:`int`.

    """

    #: Message body, as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class Echo(ICMPv4):
    """Data model for ICMP Echo Request/Reply message (types 8 and 0).

    ``code`` is always ``0`` for both types (:rfc:`792`), so it is read as a
    bare :obj:`int` rather than typed against a registry of one member.

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


@info_final
class DestinationUnreachable(ICMPv4):
    """Data model for ICMP Destination Unreachable message (type 3).

    .. seealso::

       :class:`pcapkit.const.icmp.destination_unreachable_code.DestinationUnreachableCode`

    """

    #: Unused (four octets, :rfc:`792#page-4`), as captured.
    unused: 'bytes'
    #: Internet header plus the first eight octets of the original
    #: datagram's payload (:rfc:`792#page-4`), as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     unused: 'bytes', data: 'bytes') -> 'None': ...


@info_final
class TimeExceeded(ICMPv4):
    """Data model for ICMP Time Exceeded message (type 11).

    .. seealso::

       :class:`pcapkit.const.icmp.time_exceeded_code.TimeExceededCode`

    """

    #: Unused (four octets, :rfc:`792#page-5`), as captured.
    unused: 'bytes'
    #: Internet header plus the first eight octets of the original
    #: datagram's payload (:rfc:`792#page-5`), as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     unused: 'bytes', data: 'bytes') -> 'None': ...


@info_final
class ParameterProblem(ICMPv4):
    """Data model for ICMP Parameter Problem message (type 12).

    .. seealso::

       :class:`pcapkit.const.icmp.parameter_problem_code.ParameterProblemCode`

    """

    #: Pointer, identifying the octet of the original datagram that caused
    #: the error (:rfc:`792#page-5`); meaningless for codes other than
    #: ``0``, but read and written regardless, as the wire layout requires.
    pointer: 'int'
    #: Unused (three octets, :rfc:`792#page-5`), as captured.
    unused: 'bytes'
    #: Internet header plus the first eight octets of the original
    #: datagram's payload (:rfc:`792#page-5`), as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     pointer: 'int', unused: 'bytes', data: 'bytes') -> 'None': ...
