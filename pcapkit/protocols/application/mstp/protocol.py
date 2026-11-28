# -*- coding: utf-8 -*-
"""MSTP - Multiple Spanning Tree Protocol
============================================

.. module:: pcapkit.protocols.application.mstp.protocol

:mod:`pcapkit.protocols.application.mstp.protocol` holds
:class:`~pcapkit.protocols.application.mstp.protocol.MSTP`, the extractor for the
MST BPDU of the Multiple Spanning Tree Protocol (MSTP) [:ieee:`802.1Q-2022` clause 14],
an RST BPDU of the Common and Internal Spanning Tree (CIST) extended by the MST
Configuration Identifier, the CIST's regional fields and an MSTI Configuration
Message for each Multiple Spanning Tree Instance (MSTI):

.. table::

   ====== ===== ==================================== ===================================
   Octets Bits  Name                                 Description
   ====== ===== ==================================== ===================================
   0          0                                      Protocol Identifier, zero, not kept
   ------ ----- ------------------------------------ -----------------------------------
   2         16 ``stp.protocol_version``             Protocol Version Identifier
   ------ ----- ------------------------------------ -----------------------------------
   3         24 ``stp.type``                         BPDU Type
   ------ ----- ------------------------------------ -----------------------------------
   4         32 ``stp.flags``                        CIST Flags
   ------ ----- ------------------------------------ -----------------------------------
   5         40 ``stp.cist_root_id``                 CIST Root Identifier
   ------ ----- ------------------------------------ -----------------------------------
   13       104 ``stp.cist_external_root_path_cost`` CIST External Root Path Cost
   ------ ----- ------------------------------------ -----------------------------------
   17       136 ``stp.cist_regional_root_id``        CIST Regional Root Identifier
   ------ ----- ------------------------------------ -----------------------------------
   25       200 ``stp.cist_port_id``                 CIST Port Identifier
   ------ ----- ------------------------------------ -----------------------------------
   27       216 ``stp.message_age``                  Message Age
   ------ ----- ------------------------------------ -----------------------------------
   29       232 ``stp.max_age``                      Max Age
   ------ ----- ------------------------------------ -----------------------------------
   31       248 ``stp.hello_time``                   Hello Time
   ------ ----- ------------------------------------ -----------------------------------
   33       264 ``stp.forward_delay``                Forward Delay
   ------ ----- ------------------------------------ -----------------------------------
   35       280 ``stp.version_1_length``             Version 1 Length, zero
   ------ ----- ------------------------------------ -----------------------------------
   36       288 ``stp.version_3_length``             Version 3 Length
   ------ ----- ------------------------------------ -----------------------------------
   38       304 ``stp.config_id``                    MST Configuration Identifier
   ------ ----- ------------------------------------ -----------------------------------
   89       712 ``stp.cist_internal_root_path_cost`` CIST Internal Root Path Cost
   ------ ----- ------------------------------------ -----------------------------------
   93       744 ``stp.cist_bridge_id``               CIST Bridge Identifier
   ------ ----- ------------------------------------ -----------------------------------
   101      808 ``stp.cist_remaining_hops``          CIST Remaining Hops
   ------ ----- ------------------------------------ -----------------------------------
   102      816 ``stp.msti``                         MSTI Configuration Messages
   ====== ===== ==================================== ===================================

:ieee:`802.1Q-2022` clause 14.4 decodes a BPDU of BPDU Type ``0x02`` and version 3 or
more as an MST BPDU where it holds 102 octets or more, a Version 1 Length of zero
and a Version 3 Length counting 0 to 64 MSTI Configuration Messages after the 64
octets every MST BPDU has there; anything else of that type is an RST BPDU. Only
version 3 is read and built here: a later version holding all that is the SPT BPDU
of Shortest Path Bridging, version 4, which extends the MST BPDU past its messages
and which :mod:`pcapkit` does not dissect. Octets past the messages of an MST BPDU
are kept undissected.

.. versionadded:: 1.9.0

"""
import collections.abc
from typing import TYPE_CHECKING

from pcapkit.const.stp.bpdu_type import BPDUType as Enum_BPDUType
from pcapkit.const.stp.port_role import PortRole as Enum_PortRole
from pcapkit.const.stp.protocol_version import ProtocolVersion as Enum_ProtocolVersion
from pcapkit.corekit.schema.short_read import cut_on_its_own
from pcapkit.protocols.application.mstp.data import MSTP as Data_MSTP
from pcapkit.protocols.application.mstp.data import ConfigID as Data_ConfigID
from pcapkit.protocols.application.mstp.data import MSTIFlags as Data_MSTIFlags
from pcapkit.protocols.application.mstp.data import MSTIMessage as Data_MSTIMessage
from pcapkit.protocols.application.mstp.schema import MSTP as Schema_MSTP
from pcapkit.protocols.application.mstp.schema import MSTIMessage as Schema_MSTIMessage
from pcapkit.protocols.application.stp.protocol import STP
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Iterable, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.application.stp.data import BridgeID as Data_BridgeID
    from pcapkit.protocols.application.stp.data import Flags as Data_Flags
    from pcapkit.protocols.application.stp.data import PortID as Data_PortID
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['MSTP']


class MSTP(STP[Data_MSTP, Schema_MSTP],
           schema=Schema_MSTP, data=Data_MSTP):
    """This class implements the Multiple Spanning Tree Protocol, its MST BPDU.

    .. versionadded:: 1.9.0

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Multiple Spanning Tree Protocol"]':
        """Name of current protocol."""
        return 'Multiple Spanning Tree Protocol'

    @property
    def version(self) -> 'Literal[3]':
        """Version of the member, the Protocol Version Identifier its BPDUs take."""
        return 3

    @property
    def length(self) -> 'int':
        """Header length of current protocol, 102 octets and 16 for each MSTI Configuration Message."""
        return 102 + 16 * len(self._info.msti)

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["MSTP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, narrowed to this member.

        """
        return ('MSTP',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_MSTP':  # pylint: disable=unused-argument
        """Read an MST BPDU.

        Structure of an MST BPDU [:ieee:`802.1Q-2022` clause 14], from its Version 1
        Length on, the octets before it laid out as an RST BPDU's:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Version 1 Len |       Version 3 Length        |Format Selector|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                 Configuration Name (32 octets)                |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Revision Level         |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
           |                Configuration Digest (16 octets)               |
           +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                               |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
           |  CIST Internal Root Path Cost |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
           |                CIST Bridge Identifier (8 octets)              |
           +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                               |  CIST Hops    |               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
           |         MSTI Configuration Messages (16 octets each)          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the Protocol Identifier is not zero, the BPDU Type
                is not ``0x02``, or the version is not 3; or if the BPDU does not
                hold what an MST BPDU does, which makes it RSTP's.

        """
        if length is None:
            length = len(self)
        schema = self.__header__
        self._check_bpdu(schema, types=(Enum_BPDUType.RST,), least=Enum_ProtocolVersion.MSTP,
                         most=Enum_ProtocolVersion.MSTP)
        if not cut_on_its_own(schema, 'version_1_length') and schema.version_1_length != 0:
            raise ProtocolError(f'MSTP: invalid format: Version 1 Length {schema.version_1_length} '
                                'is not zero, so the BPDU is an RST BPDU (IEEE 802.1Q-2022 clause 14.4)')
        extra = schema.version_3_length - 64
        if (not cut_on_its_own(schema, 'version_3_length')
                and not (extra >= 0 and extra % 16 == 0 and extra // 16 <= 64)):
            raise ProtocolError(f'MSTP: invalid format: Version 3 Length {schema.version_3_length} counts no '
                                'whole MSTI Configuration Messages, so the BPDU is an RST BPDU '
                                '(IEEE 802.1Q-2022 clause 14.4)')

        mstp = Data_MSTP(
            protocol_version=schema.version,
            type=schema.type,
            flags=self._read_flags(schema.flags),
            cist_root_id=self._read_bridge_id(schema.cist_root_id),
            cist_external_root_path_cost=schema.cist_external_root_path_cost,
            cist_regional_root_id=self._read_bridge_id(schema.cist_regional_root_id),
            cist_port_id=self._read_port_id(schema.cist_port_id),
            message_age=self._read_timer(schema.message_age),
            max_age=self._read_timer(schema.max_age),
            hello_time=self._read_timer(schema.hello_time),
            forward_delay=self._read_timer(schema.forward_delay),
            version_1_length=schema.version_1_length,
            version_3_length=schema.version_3_length,
            config_id=Data_ConfigID(
                format_selector=schema.format_selector,
                name=schema.config_name,
                revision_level=schema.revision_level,
                digest=schema.config_digest,
            ),
            cist_internal_root_path_cost=schema.cist_internal_root_path_cost,
            cist_bridge_id=self._read_bridge_id(schema.cist_bridge_id),
            cist_remaining_hops=schema.cist_remaining_hops,
            msti=tuple(self._read_msti(message) for message in schema.msti),
        )
        self._info = mstp  # NOTE: :attr:`length` reads the data model.

        # NOTE: The BPDU names no next layer, so what follows it is kept undissected.
        return self._decode_next_layer(mstp, -1, max(length - self.length, 0))

    def make(self, *,
             protocol_version: 'Enum_ProtocolVersion | int' = Enum_ProtocolVersion.MSTP,
             flags: 'Data_Flags | int' = 0,
             cist_root_id: 'Data_BridgeID | bytes' = bytes(8),
             cist_external_root_path_cost: 'int' = 0,
             cist_regional_root_id: 'Data_BridgeID | bytes' = bytes(8),
             cist_port_id: 'Data_PortID | int' = 0,
             message_age: 'float' = 0,
             max_age: 'float' = 0,
             hello_time: 'float' = 0,
             forward_delay: 'float' = 0,
             version_3_length: 'Optional[int]' = None,
             config_id: 'Data_ConfigID | bytes' = bytes(51),
             cist_internal_root_path_cost: 'int' = 0,
             cist_bridge_id: 'Data_BridgeID | bytes' = bytes(8),
             cist_remaining_hops: 'int' = 0,
             msti: 'Iterable[Data_MSTIMessage | bytes]' = (),
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_MSTP':
        """Make (construct) packet data.

        The Version 1 Length is written as zero, as an MST BPDU's must be.

        Args:
            protocol_version: Protocol Version Identifier, 3: a later version is an
                SPT BPDU's, which extends this one.
            flags: CIST Flags, or the octet.
            cist_root_id: CIST Root Identifier, or its eight octets.
            cist_external_root_path_cost: CIST External Root Path Cost.
            cist_regional_root_id: CIST Regional Root Identifier, or its eight
                octets.
            cist_port_id: CIST Port Identifier, or its two octets as an integer.
            message_age: Message Age, in seconds.
            max_age: Max Age, in seconds.
            hello_time: Hello Time, in seconds.
            forward_delay: Forward Delay, in seconds.
            version_3_length: Version 3 Length. If not given, it is computed as
                64 plus 16 for each of ``msti``.
            config_id: MST Configuration Identifier, or its 51 octets.
            cist_internal_root_path_cost: CIST Internal Root Path Cost.
            cist_bridge_id: CIST Bridge Identifier, or its eight octets.
            cist_remaining_hops: CIST Remaining Hops.
            msti: MSTI Configuration Messages, each a data model or its 16 octets.
            payload: Octets past the BPDU.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``protocol_version`` is not 3; if ``msti`` holds more
                than 64 messages, or ``version_3_length`` counts no whole number of
                0 to 64, either of which makes the BPDU RSTP's; or if a value does
                not fit its field.

        """
        version = self._make_protocol_version(protocol_version, least=Enum_ProtocolVersion.MSTP,
                                              most=Enum_ProtocolVersion.MSTP)
        messages = [self._make_msti(message) for message in msti]
        if len(messages) > 64:
            raise ProtocolError(f'MSTP: {len(messages)} MSTI Configuration Messages, past the 64 an MST BPDU holds')
        if version_3_length is None:
            version_3_length = 64 + 16 * len(messages)
        else:
            version_3_length = self._make_uint(version_3_length, bits=16, name='Version 3 Length')
            extra = version_3_length - 64
            if not (extra >= 0 and extra % 16 == 0 and extra // 16 <= 64):
                raise ProtocolError(f'MSTP: invalid Version 3 Length: {version_3_length} counts no whole '
                                    'MSTI Configuration Messages (IEEE 802.1Q-2022 clause 14.4)')

        if isinstance(config_id, collections.abc.Mapping):
            format_selector = self._make_uint(config_id['format_selector'], bits=8,
                                              name='Configuration Identifier Format Selector')
            config_name = self._make_octets(config_id['name'], size=32, name='Configuration Name')
            revision_level = self._make_uint(config_id['revision_level'], bits=16, name='Revision Level')
            config_digest = self._make_octets(config_id['digest'], size=16, name='Configuration Digest')
        else:
            octets = self._make_octets(config_id, size=51, name='MST Configuration Identifier')
            format_selector, config_name = octets[0], octets[1:33]
            revision_level, config_digest = int.from_bytes(octets[33:35], 'big'), octets[35:51]

        return Schema_MSTP(
            pid=0,
            version=version,
            type=Enum_BPDUType.RST,
            flags=self._make_flags(flags),
            cist_root_id=self._make_bridge_id(cist_root_id, name='CIST Root Identifier'),
            cist_external_root_path_cost=self._make_uint(cist_external_root_path_cost, bits=32,
                                                         name='CIST External Root Path Cost'),
            cist_regional_root_id=self._make_bridge_id(cist_regional_root_id, name='CIST Regional Root Identifier'),
            cist_port_id=self._make_port_id(cist_port_id, name='CIST Port Identifier'),
            message_age=self._make_timer(message_age, name='Message Age'),
            max_age=self._make_timer(max_age, name='Max Age'),
            hello_time=self._make_timer(hello_time, name='Hello Time'),
            forward_delay=self._make_timer(forward_delay, name='Forward Delay'),
            version_1_length=0,
            version_3_length=version_3_length,
            format_selector=format_selector,
            config_name=config_name,
            revision_level=revision_level,
            config_digest=config_digest,
            cist_internal_root_path_cost=self._make_uint(cist_internal_root_path_cost, bits=32,
                                                         name='CIST Internal Root Path Cost'),
            cist_bridge_id=self._make_bridge_id(cist_bridge_id, name='CIST Bridge Identifier'),
            cist_remaining_hops=self._make_uint(cist_remaining_hops, bits=8, name='CIST Remaining Hops'),
            msti=messages,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[102]':
        """Return an estimated length for the object."""
        return 102

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_MSTP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'protocol_version': cls._rebuilt_version(data, Enum_ProtocolVersion.MSTP),
            'flags': data.flags,
            'cist_root_id': data.cist_root_id,
            'cist_external_root_path_cost': data.cist_external_root_path_cost,
            'cist_regional_root_id': data.cist_regional_root_id,
            'cist_port_id': data.cist_port_id,
            'message_age': data.message_age,
            'max_age': data.max_age,
            'hello_time': data.hello_time,
            'forward_delay': data.forward_delay,
            # NOTE: Zero only where a capture ended before it, which the rebuild cuts back to.
            'version_3_length': data.version_3_length or None,
            'config_id': data.config_id,
            'cist_internal_root_path_cost': data.cist_internal_root_path_cost,
            'cist_bridge_id': data.cist_bridge_id,
            'cist_remaining_hops': data.cist_remaining_hops,
            'msti': data.msti,
            'payload': cls._make_payload(data),
        }

    def _read_msti(self, message: 'Schema_MSTIMessage') -> 'Data_MSTIMessage':
        """Read an MSTI Configuration Message.

        Args:
            message: Its header schema.

        Returns:
            Parsed message.

        """
        flags = message.flags
        return Data_MSTIMessage(
            flags=Data_MSTIFlags(
                tc=bool(flags & 0x01),
                proposal=bool(flags & 0x02),
                role=Enum_PortRole.get((flags >> 2) & 0b11),
                learning=bool(flags & 0x10),
                forwarding=bool(flags & 0x20),
                agreement=bool(flags & 0x40),
                master=bool(flags & 0x80),
            ),
            regional_root_id=self._read_bridge_id(message.regional_root_id),
            internal_root_path_cost=message.internal_root_path_cost,
            bridge_priority=(message.bridge_priority & 0xF0) << 8,
            bridge_reserved=message.bridge_priority & 0x0F,
            port_priority=message.port_priority & 0xF0,
            port_reserved=message.port_priority & 0x0F,
            remaining_hops=message.remaining_hops,
        )

    def _make_msti(self, message: 'Data_MSTIMessage | bytes') -> 'Schema_MSTIMessage':
        """Make an MSTI Configuration Message.

        Args:
            message: The message, or its 16 octets.

        Returns:
            Its header schema.

        Raises:
            ProtocolError: If ``message`` is neither, or a value does not fit its
                field: a Bridge Priority not a multiple of 4096 in ``0..61440``, or a
                Port Priority not a multiple of 16 in ``0..240``.

        """
        if isinstance(message, (bytes, bytearray)):
            octets = self._make_octets(message, size=16, name='MSTI Configuration Message')
            return Schema_MSTIMessage.unpack(octets)  # type: ignore[call-arg,misc]
        if not isinstance(message, collections.abc.Mapping):
            raise ProtocolError(f'MSTP: invalid MSTI Configuration Message: {message!r}')
        flags = message['flags']
        if isinstance(flags, collections.abc.Mapping):
            octet = self._make_role_flags(flags, last='master', name='Master flag')
        else:
            octet = self._make_uint(flags, bits=8, name='MSTI Flags')
        bridge = self._make_uint(message['bridge_priority'], bits=16, name='MSTI Bridge Priority')
        if bridge & 0x0FFF:
            raise ProtocolError(f'MSTP: invalid MSTI Bridge Priority: {bridge!r} is not a multiple of 4096')
        port = self._make_uint(message['port_priority'], bits=8, name='MSTI Port Priority')
        if port & 0x0F:
            raise ProtocolError(f'MSTP: invalid MSTI Port Priority: {port!r} is not a multiple of 16')
        return Schema_MSTIMessage(
            flags=octet,
            regional_root_id=self._make_bridge_id(message['regional_root_id'],
                                                  name='MSTI Regional Root Identifier'),
            internal_root_path_cost=self._make_uint(message['internal_root_path_cost'], bits=32,
                                                    name='MSTI Internal Root Path Cost'),
            bridge_priority=bridge >> 8 | self._make_uint(message['bridge_reserved'], bits=4,
                                                          name='MSTI Bridge Priority reserved bits'),
            port_priority=port | self._make_uint(message['port_reserved'], bits=4,
                                                 name='MSTI Port Priority reserved bits'),
            remaining_hops=self._make_uint(message['remaining_hops'], bits=8, name='MSTI Remaining Hops'),
        )
