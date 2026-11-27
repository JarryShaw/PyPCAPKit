# -*- coding: utf-8 -*-
"""data model for ICMPv6 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Optional

    from typing_extensions import Literal

    from pcapkit.const.icmpv6.nd_option import NDOption as Enum_NDOption
    from pcapkit.const.icmpv6.router_preference import RouterPreference as Enum_RouterPreference
    from pcapkit.const.icmpv6.type import Type as Enum_Type
    from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
    from pcapkit.corekit.checksum.internet import ChecksumStatus
    from pcapkit.corekit.infoclass import OrderedMultiInfo
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'ICMPv6',

    'Unknown', 'DestinationUnreachable', 'PacketTooBig', 'TimeExceeded',
    'ParameterProblem', 'Echo', 'MLDv1', 'MLDv2Query', 'MLDv2Report',
    'RouterSolicitation', 'RouterAdvertisement', 'NeighborSolicitation', 'NeighborAdvertisement',
    'Redirect',

    'MulticastAddressRecord',

    'NDOption', 'UnknownOption', 'LinkLayerAddressOption', 'PrefixInformationOption',
    'RedirectedHeaderOption', 'MTUOption', 'AdvertisementIntervalOption',
    'HomeAgentInformationOption', 'NonceOption', 'RouteInformationOption', 'RDNSSOption',
    'RAFlagsExtensionOption', 'DNSSLOption', 'CaptivePortalOption', 'PREF64Option',
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


@info_final
class RouterSolicitation(ICMPv6):
    """Data model for a Router Solicitation (type 133, :rfc:`4861#section-4.1`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: Options (:rfc:`4861#section-4.6`).
    options: 'OrderedMultiInfo[Enum_NDOption, NDOption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     reserved: 'bytes', options: 'OrderedMultiDict[Enum_NDOption, NDOption]') -> 'None': ...


@info_final
class RouterAdvertisement(ICMPv6):
    """Data model for a Router Advertisement (type 134, :rfc:`4861#section-4.2`).

    Its flags are those IANA's Router Advertisement Flags assigns to the octet
    (:rfc:`5175#section-3`).

    .. versionadded:: 1.9.0

    """

    #: Current hop limit, zero for unspecified.
    cur_hop_limit: 'int'
    #: Managed Address Configuration flag (:rfc:`4861#section-4.2`).
    m_flag: 'bool'
    #: Other Configuration flag (:rfc:`4861#section-4.2`).
    o_flag: 'bool'
    #: Mobile IPv6 Home Agent flag (:rfc:`6275#section-7.1`).
    h_flag: 'bool'
    #: Default Router Preference (:rfc:`4191#section-2.2`).
    prf: 'Enum_RouterPreference'
    #: Neighbor Discovery Proxy flag (:rfc:`4389#section-4.1.3.3`).
    p_flag: 'bool'
    #: SNAC Router flag.
    s_flag: 'bool'
    #: Reserved, the octet's last bit, as captured.
    reserved: 'int'
    #: Router lifetime, in seconds; zero for no default router.
    router_lifetime: 'int'
    #: Reachable time, in milliseconds; zero for unspecified.
    reachable_time: 'int'
    #: Retransmission timer, in milliseconds; zero for unspecified.
    retrans_timer: 'int'
    #: Options (:rfc:`4861#section-4.6`).
    options: 'OrderedMultiInfo[Enum_NDOption, NDOption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     cur_hop_limit: 'int', m_flag: 'bool', o_flag: 'bool', h_flag: 'bool',
                     prf: 'Enum_RouterPreference', p_flag: 'bool', s_flag: 'bool', reserved: 'int',
                     router_lifetime: 'int', reachable_time: 'int', retrans_timer: 'int',
                     options: 'OrderedMultiDict[Enum_NDOption, NDOption]') -> 'None': ...


@info_final
class NeighborSolicitation(ICMPv6):
    """Data model for a Neighbor Solicitation (type 135, :rfc:`4861#section-4.3`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: Target address.
    target_address: 'IPv6Address'
    #: Options (:rfc:`4861#section-4.6`).
    options: 'OrderedMultiInfo[Enum_NDOption, NDOption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     reserved: 'bytes', target_address: 'IPv6Address',
                     options: 'OrderedMultiDict[Enum_NDOption, NDOption]') -> 'None': ...


@info_final
class NeighborAdvertisement(ICMPv6):
    """Data model for a Neighbor Advertisement (type 136, :rfc:`4861#section-4.4`).

    .. versionadded:: 1.9.0

    """

    #: Router flag.
    r_flag: 'bool'
    #: Solicited flag.
    s_flag: 'bool'
    #: Override flag.
    o_flag: 'bool'
    #: Reserved, the 29 bits after the flags, as captured.
    reserved: 'int'
    #: Target address.
    target_address: 'IPv6Address'
    #: Options (:rfc:`4861#section-4.6`).
    options: 'OrderedMultiInfo[Enum_NDOption, NDOption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     r_flag: 'bool', s_flag: 'bool', o_flag: 'bool', reserved: 'int',
                     target_address: 'IPv6Address',
                     options: 'OrderedMultiDict[Enum_NDOption, NDOption]') -> 'None': ...


@info_final
class Redirect(ICMPv6):
    """Data model for a Redirect (type 137, :rfc:`4861#section-4.5`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: Target address, the better first hop.
    target_address: 'IPv6Address'
    #: Destination address, the one redirected.
    destination_address: 'IPv6Address'
    #: Options (:rfc:`4861#section-4.6`).
    options: 'OrderedMultiInfo[Enum_NDOption, NDOption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes', length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     reserved: 'bytes', target_address: 'IPv6Address', destination_address: 'IPv6Address',
                     options: 'OrderedMultiDict[Enum_NDOption, NDOption]') -> 'None': ...


class NDOption(Data):
    """Data model for ICMPv6 Neighbor Discovery options (:rfc:`4861#section-4.6`).

    .. versionadded:: 1.9.0

    """

    #: Option type.
    type: 'Enum_NDOption'
    #: Option length, in octets, type and length included, eight times the
    #: Length on the wire.
    length: 'int'


@info_final
class UnknownOption(NDOption):
    """Data model for an ND option of a type not decoded.

    .. versionadded:: 1.9.0

    """

    #: Option data, as captured.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin


@info_final
class LinkLayerAddressOption(NDOption):
    """Data model for a Source or Target Link-layer Address option (:rfc:`4861#section-4.6.1`).

    .. versionadded:: 1.9.0

    """

    #: Link-layer address, as captured, laid out and padded as the link's own
    #: specification gives, e.g. six octets on Ethernet (:rfc:`2464#section-6`).
    link_layer_address: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', link_layer_address: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class PrefixInformationOption(NDOption):
    """Data model for a Prefix Information option (:rfc:`4861#section-4.6.2`).

    Its flags are those IANA's Prefix Information Option Flags assigns
    (:rfc:`8425`).

    .. versionadded:: 1.9.0

    """

    #: Prefix length, in bits.
    prefix_length: 'int'
    #: On-link flag (:rfc:`4861#section-4.6.2`).
    l_flag: 'bool'
    #: Autonomous Address Configuration flag (:rfc:`4861#section-4.6.2`).
    a_flag: 'bool'
    #: Router Address flag (:rfc:`6275#section-7.2`).
    r_flag: 'bool'
    #: DHCPv6-PD Preferred flag (:rfc:`9762#section-5`).
    p_flag: 'bool'
    #: Reserved1, the low-order 4 bits of the flags octet, as captured.
    reserved1: 'int'
    #: Valid lifetime, in seconds; all ones for infinity.
    valid_lifetime: 'int'
    #: Preferred lifetime, in seconds; all ones for infinity.
    preferred_lifetime: 'int'
    #: Reserved2, as captured.
    reserved2: 'bytes'
    #: Prefix.
    prefix: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', prefix_length: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     l_flag: 'bool', a_flag: 'bool', r_flag: 'bool', p_flag: 'bool', reserved1: 'int',
                     valid_lifetime: 'int', preferred_lifetime: 'int', reserved2: 'bytes',
                     prefix: 'IPv6Address') -> 'None': ...


@info_final
class RedirectedHeaderOption(NDOption):
    """Data model for a Redirected Header option (:rfc:`4861#section-4.6.3`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: As much of the redirected packet, from its IP header, as fits.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class MTUOption(NDOption):
    """Data model for an MTU option (:rfc:`4861#section-4.6.4`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: Recommended MTU of the link.
    mtu: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', mtu: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class AdvertisementIntervalOption(NDOption):
    """Data model for an Advertisement Interval option (:rfc:`6275#section-7.3`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: Largest time between unsolicited Router Advertisements, in milliseconds.
    interval: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', interval: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class HomeAgentInformationOption(NDOption):
    """Data model for a Home Agent Information option (:rfc:`6275#section-7.4`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: Home agent preference; a higher value is more preferable.
    preference: 'int'
    #: Home agent lifetime, in seconds.
    lifetime: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', preference: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     lifetime: 'int') -> 'None': ...


@info_final
class NonceOption(NDOption):
    """Data model for a Nonce option (:rfc:`3971#section-5.3.2`).

    .. versionadded:: 1.9.0

    """

    #: Nonce, as captured.
    nonce: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', nonce: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class RouteInformationOption(NDOption):
    """Data model for a Route Information option (:rfc:`4191#section-2.3`).

    .. versionadded:: 1.9.0

    """

    #: Prefix length, in bits.
    prefix_length: 'int'
    #: Reserved, the high-order 3 bits of the octet holding :attr:`prf`.
    reserved1: 'int'
    #: Route Preference.
    prf: 'Enum_RouterPreference'
    #: Reserved, the low-order 3 bits of the octet holding :attr:`prf`.
    reserved2: 'int'
    #: Route lifetime, in seconds; all ones for infinity.
    lifetime: 'int'
    #: Prefix, the 0, 8 or 16 octets the Length leaves, zero-extended.
    prefix: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', prefix_length: 'int', reserved1: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     prf: 'Enum_RouterPreference', reserved2: 'int', lifetime: 'int',
                     prefix: 'IPv6Address') -> 'None': ...


@info_final
class RDNSSOption(NDOption):
    """Data model for a Recursive DNS Server option (:rfc:`8106#section-5.1`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: Lifetime, in seconds; all ones for infinity.
    lifetime: 'int'
    #: Addresses of the recursive DNS servers.
    addresses: 'tuple[IPv6Address, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', lifetime: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     addresses: 'tuple[IPv6Address, ...]') -> 'None': ...


@info_final
class RAFlagsExtensionOption(NDOption):
    """Data model for an RA Flags Extension option (:rfc:`5175#section-4`).

    .. versionadded:: 1.9.0

    """

    #: Bits 8 onwards of IANA's Router Advertisement Flags, as captured;
    #: none is assigned but to Private Experimentation.
    bits: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', bits: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class DNSSLOption(NDOption):
    """Data model for a DNS Search List option (:rfc:`8106#section-5.2`).

    .. versionadded:: 1.9.0

    """

    #: Reserved, as captured.
    reserved: 'bytes'
    #: Lifetime, in seconds; all ones for infinity.
    lifetime: 'int'
    #: Domain names, in presentation form (:rfc:`1035#section-5.1`).
    domain_names: 'tuple[str, ...]'
    #: Octets past the last name, as captured; zeros for a conformant sender.
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', lifetime: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     domain_names: 'tuple[str, ...]', padding: 'bytes') -> 'None': ...


@info_final
class CaptivePortalOption(NDOption):
    """Data model for a Captive-Portal option (:rfc:`8910#section-2.3`).

    .. versionadded:: 1.9.0

    """

    #: URI of the captive portal API endpoint, the octets ahead of the first NUL.
    uri: 'bytes'
    #: NUL padding, from the first NUL on, as captured.
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', uri: 'bytes', padding: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


@info_final
class PREF64Option(NDOption):
    """Data model for a PREF64 option (:rfc:`8781#section-4`).

    .. versionadded:: 1.9.0

    """

    #: Scaled Lifetime, in units of 8 seconds, as on the wire.
    scaled_lifetime: 'int'
    #: Lifetime, in seconds, decoded from :attr:`scaled_lifetime`
    #: (:rfc:`8781#section-4.1`).
    lifetime: 'int'
    #: Prefix Length Code, as on the wire.
    plc: 'int'
    #: Prefix length, in bits, decoded from :attr:`plc`; :data:`None` for a
    #: code :rfc:`8781#section-4` assigns none.
    prefix_length: 'Optional[int]'
    #: Prefix, its highest 96 bits as carried and the rest zero.
    prefix: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', scaled_lifetime: 'int', lifetime: 'int',  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
                     plc: 'int', prefix_length: 'Optional[int]', prefix: 'IPv6Address') -> 'None': ...
