# -*- coding: utf-8 -*-
"""data model for HOPOPT protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from datetime import timedelta
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from pcapkit.const.ipv6.option import Option as Enum_Option
    from pcapkit.const.ipv6.option_action import OptionAction
    from pcapkit.const.ipv6.qs_function import QSFunction
    from pcapkit.const.ipv6.router_alert import RouterAlert
    from pcapkit.const.ipv6.seed_id import SeedID
    from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
    from pcapkit.const.ipv6.tagger_id import TaggerID
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.infoclass import OrderedMultiInfo
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'HOPOPT',

    'RPLFlags', 'MPLFlags', 'DFFFlags',

    'SMFDPDOption', 'QuickStartOption',
    'UnassignedOption', 'PadOption', 'TunnelEncapsulationLimitOption',
    'RouterAlertOption', 'CALIPSOOption', 'SMFIdentificationBasedDPDOption',
    'SMFHashBasedDPDOption', 'PDMOption', 'QuickStartRequestOption',
    'QuickStartReportOption', 'RPLOption', 'MPLOption', 'ILNPOption',
    'LineIdentificationOption', 'JumboPayloadOption', 'HomeAddressOption',
    'IPDFFOption',
]


class Option(Data):
    """Data model for HOPOPT option data."""

    #: Option type.
    type: 'Enum_Option'
    #: Unknown option action.
    action: 'OptionAction'
    #: Change flag.
    change: 'bool'
    #: Option length (incl. type and length fields).
    length: 'int'


@info_final
class HOPOPT(Protocol):
    """Data model for HOPOPT protocol.

    .. versionchanged:: 1.5.0

       ``options`` is an immutable
       :class:`~pcapkit.corekit.infoclass.OrderedMultiInfo` rather than an
       :class:`~pcapkit.corekit.multidict.OrderedMultiDict` (:issue:`1484`).

    """

    #: Next header.
    next: 'TransType'
    #: Header length, in octets, decoded from ``Hdr Ext Len``.
    length: 'int'
    #: HOPOPT options.
    options: 'OrderedMultiInfo[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class UnassignedOption(Option):
    """Data model for HOPOPT unassigned option."""

    #: Option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class PadOption(Option):
    """Data model for HOPOPT padding options.

    .. versionchanged:: 1.5.0

       New required field ``pad`` (:issue:`1223`).

    """

    #: Padding octets, i.e. the ``PadN`` option data as captured (empty for
    #: a ``Pad1``).
    pad: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', pad: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class TunnelEncapsulationLimitOption(Option):
    """Data model for HOPOPT tunnel encapsulation limit option."""

    #: Tunnel encapsulation limit.
    limit: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', limit: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class RouterAlertOption(Option):
    """Data model for HOPOPT router alert option."""

    #: Router alert value.
    value: 'RouterAlert'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', value: 'RouterAlert') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class CALIPSOOption(Option):
    """Data model for HOPOPT Common Architecture Label IPv6 Security Option (CALIPSO) option.

    .. versionchanged:: 1.5.0

       New required field ``pad`` (:issue:`1403`).

    """

    #: CALIPSO domain of interpretation.
    domain: 'int'
    #: Compartment bitmap length, in octets: four times the ``Cmpt Length``
    #: field, which counts 32-bit words.
    cmpt_len: 'int'
    #: Sensitivity level.
    level: 'int'
    #: Checksum.
    checksum: 'bytes'
    #: Octets after the compartment bitmap that ``Opt Data Len`` covers.
    pad: 'bytes'

    if TYPE_CHECKING:
        #: Compartment bitmap.
        cmpt_bitmap: 'tuple[int, ...]'

        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', domain: 'int', cmpt_len: 'int', level: 'int', checksum: 'bytes', pad: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class SMFDPDOption(Option):
    """Data model for HOPOPT Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) option."""

    #: DPD type.
    dpd_type: 'SMFDPDMode'


@info_final
class SMFIdentificationBasedDPDOption(SMFDPDOption):
    """Data model for HOPOPT **I-DPD** (Identification-Based DPD) option."""

    #: TaggerID type.
    tid_type: 'TaggerID'
    #: ``TidLen`` field as on the wire: the TaggerID length in octets minus
    #: one, or ``0`` when there is no TaggerID [:rfc:`6621#section-6.1.1`].
    tid_len: 'int'
    #: TaggerID.
    tid: 'Optional[bytes | IPv4Address | IPv6Address]'
    #: Identifier.
    id: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', dpd_type: 'SMFDPDMode', tid_type: 'TaggerID', tid_len: 'int', tid: 'Optional[bytes | IPv4Address | IPv6Address]', id: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class SMFHashBasedDPDOption(SMFDPDOption):
    """Data model for HOPOPT **H-DPD** (Hash-Based DPD) option."""

    #: Hash assist value.
    hav: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', dpd_type: 'SMFDPDMode', hav: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class PDMOption(Option):
    """Data model for HOPOPT Performance and Diagnostic Metrics (PDM) option."""

    #: Scale delta time last received.
    scaledtlr: 'int'
    #: Scale delta time last sent.
    scaledtls: 'int'
    #: Packet sequence number this packet.
    psntp: 'int'
    #: Packet sequence number last received.
    psnlr: 'int'
    #: Delta time last received (in attoseconds).
    deltatlr: 'int'
    #: Delta time last sent (in attoseconds).
    deltatls: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', scaledtlr: 'int', scaledtls: 'int', psntp: 'int', psnlr: 'int', deltatlr: 'int', deltatls: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


class QuickStartOption(Option):
    """Data model for HOPOPT Quick Start option.

    .. versionchanged:: 1.5.0

       ``rate`` is an :obj:`int` rather than a :obj:`float` (:issue:`2167`).

    """

    #: QS function.
    func: 'QSFunction'
    #: Rate request/report, in kbps: ``40 * 2 ** N`` for the Rate Request or
    #: Rate Report field ``N``, or ``0`` if ``N`` is ``0`` (:rfc:`4782`
    #: Section 3.1).
    rate: 'int'


@info_final
class QuickStartRequestOption(QuickStartOption):
    """Data model for HOPOPT Quick Start request option.

    .. versionchanged:: 1.5.0

       New required field ``reserved`` (:issue:`1235`).

    """

    #: TTL.
    ttl: 'timedelta'
    #: Nonce.
    nonce: 'int'
    #: Reserved bits (``R``) after the nonce.
    reserved: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', func: 'QSFunction', rate: 'int', ttl: 'timedelta',
                     nonce: 'int', reserved: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class QuickStartReportOption(QuickStartOption):
    """Data model for HOPOPT Quick Start report of approved rate option.

    .. versionchanged:: 1.5.0

       New required fields ``reserved`` (:issue:`1235`) and ``unused``
       (:issue:`1223`).

    """

    #: Nonce.
    nonce: 'int'
    #: Reserved bits (``R``) after the nonce.
    reserved: 'int'
    #: The "Not Used" octet after the rate, as captured.
    unused: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', func: 'QSFunction', rate: 'int', nonce: 'int', reserved: 'int', unused: 'bytes') -> 'None': ...


@info_final
class RPLFlags(Data):
    """Data model for HOPOPT RPL option flags fields.

    .. versionchanged:: 1.5.0

       New required field ``reserved`` (:issue:`1199`).

    """

    #: Down flag.
    down: 'bool'
    #: Rank error flag.
    rank_err: 'bool'
    #: Forwarding error flag.
    fwd_err: 'bool'
    #: Reserved flag bits, carried verbatim so that a rebuild reproduces them.
    reserved: 'int'

    if TYPE_CHECKING:
        def __init__(self, down: 'bool', rank_err: 'bool', fwd_err: 'bool', reserved: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class RPLOption(Option):
    """Data model for HOPOPT Routing Protocol for Low-Power and Lossy Networks (RPL) option.

    .. versionchanged:: 1.5.0

       New required field ``sub_tlvs`` (:issue:`1199`).

    """

    #: Flags.
    flags: 'RPLFlags'
    #: RPL instance ID.
    id: 'int'
    #: Sender rank.
    rank: 'int'
    #: Sub-TLVs [:rfc:`6553#section-3`], kept as raw octets.
    sub_tlvs: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', flags: 'RPLFlags', id: 'int', rank: 'int', sub_tlvs: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class MPLFlags(Data):
    """Data model for HOPOPT MPL option flags fields.

    .. versionchanged:: 1.5.0

       New required field ``reserved`` (:issue:`1235`).

    """

    #: Max flag.
    max: 'bool'
    #: Non-conformance flag.
    drop: 'bool'
    #: Reserved bits (``rsv``).
    reserved: 'int'

    if TYPE_CHECKING:
        def __init__(self, max: 'bool', drop: 'bool', reserved: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class MPLOption(Option):
    """Data model for HOPOPT Multicast Protocol for Low-Power and Lossy Networks (MPL) option.

    .. versionchanged:: 1.5.0

       ``seed_id`` may be an :class:`~ipaddress.IPv6Address`, the source
       address, for a seed-id type of ``IPV6_SOURCE_ADDRESS`` (:issue:`1185`).

    """

    #: Seed-ID type, which gives the length of the Seed-ID.
    seed_type: 'SeedID'
    #: Flags.
    flags: 'MPLFlags'
    #: Sequence number.
    seq: 'int'
    #: Seed ID.
    seed_id: 'Optional[int | IPv6Address]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', seed_type: 'int', flags: 'MPLFlags', seq: 'int', seed_id: 'Optional[int | IPv6Address]') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class ILNPOption(Option):
    """Data model for HOPOPT Identifier-Locator Network Protocol (ILNP) Nonce option."""

    #: Nonce value.
    nonce: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', nonce: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class LineIdentificationOption(Option):
    """Data model for HOPOPT Line-Identification option."""

    #: Line ID length.
    line_id_len: 'int'
    #: Line ID.
    line_id: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', line_id_len: 'int', line_id: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class JumboPayloadOption(Option):
    """Data model for Jumbo Payload option."""

    #: Jumbo payload length.
    jumbo_len: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int',
                     jumbo_len: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class HomeAddressOption(Option):
    """Data model for HOPOPT Home Address option."""

    #: Home address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', address: 'IPv6Address') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class DFFFlags(Data):
    """Data model for HOPOPT ``IP_DFF`` option flags.

    .. versionchanged:: 1.5.0

       New required field ``reserved`` (:issue:`1235`).

    """

    #: Duplicate flag.
    dup: 'bool'
    #: Return flag.
    ret: 'bool'
    #: Reserved bits, i.e. the low four bits of the flags octet.
    reserved: 'int'

    if TYPE_CHECKING:
        def __init__(self, dup: 'bool', ret: 'bool', reserved: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long


@info_final
class IPDFFOption(Option):
    """Data model for HOPOPT Depth-First Forwarding (``IP_DFF``) option."""

    #: Version.
    version: 'int'
    #: Flags.
    flags: 'DFFFlags'
    #: Sequence number.
    seq: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', action: 'int', change: 'bool', length: 'int', version: 'int', flags: 'DFFFlags', seq: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long
