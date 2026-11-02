# -*- coding: utf-8 -*-
"""data model for DCCP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.const.dccp.ack_vector_state import AckVectorState
    from pcapkit.const.dccp.drop_code import DropCode
    from pcapkit.const.dccp.feature import Feature
    from pcapkit.const.dccp.option import Option as OptionType
    from pcapkit.const.dccp.packet_type import PacketType
    from pcapkit.const.dccp.reset_code import ResetCode
    from pcapkit.const.reg.apptype import AppType
    from pcapkit.corekit.checksum.internet import ChecksumStatus
    from pcapkit.corekit.infoclass import OrderedMultiInfo

__all__ = [
    'DCCP',

    'Option',
    'UnassignedOption', 'Padding', 'Mandatory', 'SlowReceiver', 'Change', 'Confirm',
    'InitCookie', 'NDPCount', 'AckVector', 'DataDropped', 'Timestamp', 'TimestampEcho',
    'ElapsedTime', 'DataChecksum',

    'AckVectorRun', 'DataDroppedBlock',
]


@info_final
class DCCP(Protocol):
    """Data model for DCCP packet."""

    #: Source port.
    srcport: 'AppType'
    #: Destination port.
    dstport: 'AppType'
    #: Header length, i.e. the Data Offset in octets.
    hdr_len: 'int'
    #: Value used by the HC-Sender CCID (``CCVal``).
    ccval: 'int'
    #: Checksum coverage (``CsCov``).
    cscov: 'int'
    #: Checksum.
    checksum: 'bytes'
    #: Reserved bits (``Res``).
    reserved: 'int'
    #: Packet type.
    type: 'PacketType'
    #: Extended sequence numbers (``X``), i.e. 48-bit rather than 24-bit ones.
    x: 'bool'
    #: Sequence number.
    seq: 'int'

    if TYPE_CHECKING:
        #: Reserved octet ahead of a 48-bit sequence number, present only when
        #: :attr:`x` is set.
        seq_reserved: 'int'
        #: Reserved bits of the acknowledgement number subheader, present only
        #: in a packet type that carries one.
        ack_reserved: 'int'
        #: Acknowledgement number, present only in a packet type that carries
        #: one.
        ack: 'int'
        #: Service code, present only in a DCCP-Request, DCCP-Response or
        #: DCCP-Listen.
        service_code: 'int'
        #: Reset code, present only in a DCCP-Reset.
        reset_code: 'ResetCode'
        #: Data 1, Data 2 and Data 3 of a DCCP-Reset, present only in one.
        reset_data: 'bytes'
        #: Options, present only when the header has an option area.
        options: 'OrderedMultiInfo[OptionType, Option]'
        #: Outcome of verifying :attr:`checksum`, present only when the
        #: enclosing IP layer verified it under
        #: :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`.
        checksum_status: 'ChecksumStatus'

        def __init__(self, srcport: 'AppType', dstport: 'AppType', hdr_len: 'int', ccval: 'int', cscov: 'int',
                     checksum: 'bytes', reserved: 'int', type: 'PacketType', x: 'bool', seq: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Option(Data):
    """Data model for DCCP options."""

    #: Option type.
    type: 'OptionType'
    #: Option length, ``1`` for a single-octet option.
    length: 'int'


@info_final
class UnassignedOption(Option):
    """Data model for unassigned DCCP option."""

    #: Option data, empty for a single-octet option.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Padding(Option):
    """Data model for DCCP padding option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Mandatory(Option):
    """Data model for DCCP mandatory option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class SlowReceiver(Option):
    """Data model for DCCP slow receiver option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Change(Option):
    """Data model for DCCP Change L and Change R options."""

    #: Feature number, :data:`None` if absent.
    feature: 'Optional[Feature]'
    #: Preference list or value, as on the wire.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', feature: 'Optional[Feature]', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Confirm(Option):
    """Data model for DCCP Confirm L and Confirm R options."""

    #: Feature number, :data:`None` if absent.
    feature: 'Optional[Feature]'
    #: Value, then the preference list for a server-priority feature, as on
    #: the wire.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', feature: 'Optional[Feature]', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class InitCookie(Option):
    """Data model for DCCP init cookie option."""

    #: Cookie.
    cookie: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', cookie: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class NDPCount(Option):
    """Data model for DCCP NDP count option."""

    #: Count of consecutive non-data packets.
    count: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', count: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class AckVectorRun(Data):
    """Data model for one octet of a DCCP Ack Vector."""

    #: State of the packets in the run.
    state: 'AckVectorState'
    #: Number of packets preceding the first one, in the same state.
    run_length: 'int'

    if TYPE_CHECKING:
        def __init__(self, state: 'AckVectorState', run_length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class AckVector(Option):
    """Data model for DCCP Ack Vector options."""

    #: ECN Nonce Echo the option type implies, ``0`` or ``1``.
    nonce: 'int'
    #: Vector, newest packet first.
    vector: 'tuple[AckVectorRun, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', nonce: 'int', vector: 'tuple[AckVectorRun, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class DataDroppedBlock(Data):
    """Data model for one octet of a DCCP Data Dropped vector."""

    #: Whether it is a drop block rather than a normal one.
    dropped: 'bool'
    #: Drop code of a drop block, :data:`None` for a normal one.
    code: 'Optional[DropCode]'
    #: Number of packets preceding the first one, in the same block.
    run_length: 'int'

    if TYPE_CHECKING:
        def __init__(self, dropped: 'bool', code: 'Optional[DropCode]', run_length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class DataDropped(Option):
    """Data model for DCCP data dropped option."""

    #: Vector, newest packet first.
    vector: 'tuple[DataDroppedBlock, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', vector: 'tuple[DataDroppedBlock, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Timestamp(Option):
    """Data model for DCCP timestamp option."""

    #: Timestamp, in units of 10 microseconds.
    timestamp: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', timestamp: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class TimestampEcho(Option):
    """Data model for DCCP timestamp echo option."""

    #: Timestamp echoed.
    timestamp: 'int'
    #: Elapsed time, in hundredths of milliseconds, :data:`None` if absent.
    elapsed: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', timestamp: 'int', elapsed: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ElapsedTime(Option):
    """Data model for DCCP elapsed time option."""

    #: Elapsed time, in hundredths of milliseconds.
    elapsed: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', elapsed: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class DataChecksum(Option):
    """Data model for DCCP data checksum option."""

    #: CRC-32c of the application data, as on the wire.
    checksum: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'OptionType', length: 'int', checksum: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
