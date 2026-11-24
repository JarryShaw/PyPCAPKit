# -*- coding: utf-8 -*-
"""data model for ICMPv6 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from ipaddress import IPv6Address

    from typing_extensions import Literal

    from pcapkit.const.icmpv6.type import Type as Enum_Type
    from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
    from pcapkit.corekit.checksum.internet import ChecksumStatus

__all__ = [
    'ICMPv6',

    'Unknown', 'DestinationUnreachable', 'PacketTooBig', 'TimeExceeded',
    'ParameterProblem', 'Echo', 'MLDv1', 'MLDv2Query', 'MLDv2Report',

    'MulticastAddressRecord',
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
    #: Checksum.
    checksum: 'bytes'
    #: Message length, in octets, header included. ICMPv6 messages carry no
    #: length field of their own -- this is simply how many octets
    #: :meth:`ICMPv6.read <pcapkit.protocols.internet.icmpv6.protocol.ICMPv6.read>`
    #: was handed, kept here so the whole message can be told apart from a
    #: truncated capture.
    length: 'int'

    if TYPE_CHECKING:
        #: Outcome of verifying :attr:`checksum`, present only when
        #: the enclosing IPv6 layer verified it
        #: under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`.
        checksum_status: 'ChecksumStatus'


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


@info_final
class MLDv1(ICMPv6):
    """Data model for an MLDv1 message (:rfc:`2710#section-3`).

    A Multicast Listener Query (type 130) of fewer than 28 octets
    (:rfc:`9777#section-8.1`), a Multicast Listener Report (131) or a Multicast
    Listener Done (132). ``code`` is zero on the wire and ignored
    (:rfc:`2710#section-3.2`).

    .. versionadded:: 1.7.0

    """

    #: MLD version, always ``1``. It is on no octet; it names the version the
    #: message was read as, which a Query is rebuilt by.
    version: 'Literal[1]'
    #: Maximum Response Delay, in milliseconds (:rfc:`2710#section-3.4`); zero
    #: but in a Query.
    max_resp_delay: 'int'
    #: Reserved (:rfc:`2710#section-3.5`), as captured.
    reserved: 'bytes'
    #: Multicast address (:rfc:`2710#section-3.6`), ``::`` on a General Query
    #: and else the address queried, reported or left.
    multicast_address: 'IPv6Address'
    #: Octets past the 24 :rfc:`2710#section-3` defines, as captured; empty for
    #: a conformant sender.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     version: 'Literal[1]', max_resp_delay: 'int', reserved: 'bytes',
                     multicast_address: 'IPv6Address', data: 'bytes') -> 'None': ...


@info_final
class MLDv2Query(ICMPv6):
    """Data model for an MLDv2 Multicast Listener Query (:rfc:`9777#section-5.1`).

    A Query (type 130) of 28 or more octets (:rfc:`9777#section-8.1`). ``code`` is
    zero on the wire and ignored (:rfc:`9777#section-5.1.1`).

    .. versionadded:: 1.7.0

    """

    #: MLD version, always ``2``; see :attr:`MLDv1.version`.
    version: 'Literal[2]'
    #: Maximum Response Code, as on the wire.
    max_resp_code: 'int'
    #: Maximum Response Delay, in milliseconds, decoded from
    #: :attr:`max_resp_code`: literal below 32768, else ``(mant | 0x1000) <<
    #: (exp + 3)`` (:rfc:`9777#section-5.1.3`).
    max_resp_delay: 'int'
    #: Reserved (:rfc:`9777#section-5.1.4`), as captured.
    reserved: 'bytes'
    #: Multicast address, ``::`` on a General Query and else the address
    #: queried (:rfc:`9777#section-5.1.5`).
    multicast_address: 'IPv6Address'
    #: Flags, the 4 high-order bits of the octet holding :attr:`s_flag`
    #: (:rfc:`9777#section-5.1.6`), as captured.
    flags: 'int'
    #: Suppress Router-Side Processing flag (:rfc:`9777#section-5.1.7`).
    s_flag: 'bool'
    #: Querier's Robustness Variable (:rfc:`9777#section-5.1.8`).
    qrv: 'int'
    #: Querier's Query Interval Code, as on the wire.
    qqic: 'int'
    #: Querier's Query Interval, in seconds, decoded from :attr:`qqic`
    #: (:rfc:`9777#section-5.1.9`).
    qqi: 'int'
    #: Number of source addresses, as on the wire (:rfc:`9777#section-5.1.10`);
    #: more than :attr:`sources` holds where the data ends inside them.
    num_sources: 'int'
    #: Source addresses (:rfc:`9777#section-5.1.11`).
    sources: 'tuple[IPv6Address, ...]'
    #: Additional data (:rfc:`9777#section-5.1.12`), as captured; empty for a
    #: conformant sender.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     version: 'Literal[2]', max_resp_code: 'int', max_resp_delay: 'int', reserved: 'bytes',
                     multicast_address: 'IPv6Address', flags: 'int', s_flag: 'bool', qrv: 'int',
                     qqic: 'int', qqi: 'int', num_sources: 'int', sources: 'tuple[IPv6Address, ...]',
                     data: 'bytes') -> 'None': ...


@info_final
class MulticastAddressRecord(Data):
    """Data model for an MLDv2 multicast address record (:rfc:`9777#section-5.2`).

    .. versionadded:: 1.7.0

    """

    #: Record type (:rfc:`9777#section-5.2.13`).
    record_type: 'Enum_RecordType'
    #: Auxiliary data length, in 32-bit words.
    aux_data_len: 'int'
    #: Number of source addresses, as on the wire.
    num_sources: 'int'
    #: Multicast address the record pertains to.
    multicast_address: 'IPv6Address'
    #: Source addresses (:rfc:`9777#section-5.2.10`).
    sources: 'tuple[IPv6Address, ...]'
    #: Auxiliary data (:rfc:`9777#section-5.2.11`), as captured; empty for an
    #: MLDv2 sender.
    aux_data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, record_type: 'Enum_RecordType', aux_data_len: 'int', num_sources: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called
                     multicast_address: 'IPv6Address', sources: 'tuple[IPv6Address, ...]',
                     aux_data: 'bytes') -> 'None': ...


@info_final
class MLDv2Report(ICMPv6):
    """Data model for an MLDv2 Version 2 Multicast Listener Report (:rfc:`9777#section-5.2`).

    A Report is type 143, and its ``code`` the Reserved octet
    (:rfc:`9777#section-5.2.1`).

    .. versionadded:: 1.7.0

    """

    #: MLD version, always ``2``; see :attr:`MLDv1.version`.
    version: 'Literal[2]'
    #: Flags (:rfc:`9777#section-5.2.3`), as captured.
    flags: 'int'
    #: Number of multicast address records, as on the wire.
    num_records: 'int'
    #: Multicast address records (:rfc:`9777#section-5.2.5`).
    records: 'tuple[MulticastAddressRecord, ...]'
    #: Additional data (:rfc:`9777#section-5.2.12`), as captured; empty for a
    #: conformant sender.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     version: 'Literal[2]', flags: 'int', num_records: 'int',
                     records: 'tuple[MulticastAddressRecord, ...]', data: 'bytes') -> 'None': ...
