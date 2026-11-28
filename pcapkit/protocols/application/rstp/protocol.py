# -*- coding: utf-8 -*-
"""RSTP - Rapid Spanning Tree Protocol
=========================================

.. module:: pcapkit.protocols.application.rstp.protocol

:mod:`pcapkit.protocols.application.rstp.protocol` holds
:class:`~pcapkit.protocols.application.rstp.protocol.RSTP`, the extractor for the
RST BPDU of the Rapid Spanning Tree Protocol (RSTP) [IEEE 802.1Q-2022 clause 14],
laid out as the Configuration BPDU with a Version 1 Length after it:

.. table::

   ====== ===== ========================= ===================================
   Octets Bits  Name                      Description
   ====== ===== ========================= ===================================
   0          0                           Protocol Identifier, zero, not kept
   ------ ----- ------------------------- -----------------------------------
   2         16 ``stp.protocol_version``  Protocol Version Identifier
   ------ ----- ------------------------- -----------------------------------
   3         24 ``stp.type``              BPDU Type
   ------ ----- ------------------------- -----------------------------------
   4         32 ``stp.flags``             Flags
   ------ ----- ------------------------- -----------------------------------
   5         40 ``stp.root_id``           Root Identifier
   ------ ----- ------------------------- -----------------------------------
   13       104 ``stp.root_path_cost``    Root Path Cost
   ------ ----- ------------------------- -----------------------------------
   17       136 ``stp.bridge_id``         Bridge Identifier
   ------ ----- ------------------------- -----------------------------------
   25       200 ``stp.port_id``           Port Identifier
   ------ ----- ------------------------- -----------------------------------
   27       216 ``stp.message_age``       Message Age
   ------ ----- ------------------------- -----------------------------------
   29       232 ``stp.max_age``           Max Age
   ------ ----- ------------------------- -----------------------------------
   31       248 ``stp.hello_time``        Hello Time
   ------ ----- ------------------------- -----------------------------------
   33       264 ``stp.forward_delay``     Forward Delay
   ------ ----- ------------------------- -----------------------------------
   35       280 ``stp.version_1_length``  Version 1 Length, zero
   ====== ===== ========================= ===================================

IEEE 802.1Q-2022 clause 14.4 decodes a BPDU of BPDU Type ``0x02`` and version 2 as
an RST BPDU, and one of version 3 or more too, where it does not hold what an MST
BPDU does; such a BPDU of 35 octets ends before its Version 1 Length. Its
flags carry the Port Role and the Proposal, Learning, Forwarding and Agreement
flags beside the Topology Change ones.

.. versionadded:: 1.9.0

"""
from typing import TYPE_CHECKING

from pcapkit.const.stp.bpdu_type import BPDUType as Enum_BPDUType
from pcapkit.const.stp.protocol_version import ProtocolVersion as Enum_ProtocolVersion
from pcapkit.corekit.schema.short_read import cut_on_its_own
from pcapkit.protocols.application.rstp.data import RSTP as Data_RSTP
from pcapkit.protocols.application.rstp.schema import RSTP as Schema_RSTP
from pcapkit.protocols.application.stp.protocol import STP
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.application.stp.data import BridgeID as Data_BridgeID
    from pcapkit.protocols.application.stp.data import Flags as Data_Flags
    from pcapkit.protocols.application.stp.data import PortID as Data_PortID
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['RSTP']


class RSTP(STP[Data_RSTP, Schema_RSTP],
           schema=Schema_RSTP, data=Data_RSTP):
    """This class implements the Rapid Spanning Tree Protocol, its RST BPDU.

    .. versionadded:: 1.9.0

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Rapid Spanning Tree Protocol"]':
        """Name of current protocol."""
        return 'Rapid Spanning Tree Protocol'

    @property
    def version(self) -> 'Literal[2]':
        """Version of the member, the Protocol Version Identifier its BPDUs take."""
        return 2

    @property
    def length(self) -> 'Literal[35, 36]':
        """Header length of current protocol, 36 octets or 35 without a Version 1 Length."""
        return 35 if self._info.version_1_length is None else 36

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["RSTP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, narrowed to this member.

        """
        return ('RSTP',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_RSTP':  # pylint: disable=unused-argument
        """Read an RST BPDU.

        Structure of an RST BPDU [IEEE 802.1Q-2022 clause 14]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Protocol Identifier      |    Version    |   BPDU Type   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Flags     |                                               |
           +-+-+-+-+-+-+-+-+          Root Identifier (8 octets)           +
           |                                               |               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
           |                  Root Path Cost               |               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
           |                     Bridge Identifier (8 octets)              |
           +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |               |        Port Identifier        |  Message Age  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Message Age  |            Max Age            |  Hello Time   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Hello Time   |         Forward Delay         | Version 1 Len |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the Protocol Identifier is not zero, the BPDU Type
                is not ``0x02``, or the version is below 2; or if the BPDU holds
                what an MST BPDU does, as an MST or an SPT BPDU does.

        """
        if length is None:
            length = len(self)
        schema = self.__header__
        self._check_bpdu(schema, types=(Enum_BPDUType.RST,), least=Enum_ProtocolVersion.RSTP)
        if (not cut_on_its_own(schema) and schema.version > Enum_ProtocolVersion.RSTP
                and self._is_mst(self._data[:length])):
            raise ProtocolError('RSTP: invalid format: the BPDU holds an MST BPDU, so it is no '
                                'RST BPDU (IEEE 802.1Q-2022 clause 14.4)')

        rstp = Data_RSTP(
            protocol_version=schema.version,
            type=schema.type,
            flags=self._read_flags(schema.flags),
            root_id=self._read_bridge_id(schema.root_id),
            root_path_cost=schema.root_path_cost,
            bridge_id=self._read_bridge_id(schema.bridge_id),
            port_id=self._read_port_id(schema.port_id),
            message_age=self._read_timer(schema.message_age),
            max_age=self._read_timer(schema.max_age),
            hello_time=self._read_timer(schema.hello_time),
            forward_delay=self._read_timer(schema.forward_delay),
            version_1_length=schema.version_1_length,
        )
        self._info = rstp  # NOTE: :attr:`length` reads the data model.

        # NOTE: The BPDU names no next layer, so what follows it is kept undissected.
        return self._decode_next_layer(rstp, -1, max(length - self.length, 0))

    def make(self, *,
             protocol_version: 'Enum_ProtocolVersion | int' = Enum_ProtocolVersion.RSTP,
             flags: 'Data_Flags | int' = 0,
             root_id: 'Data_BridgeID | bytes' = bytes(8),
             root_path_cost: 'int' = 0,
             bridge_id: 'Data_BridgeID | bytes' = bytes(8),
             port_id: 'Data_PortID | int' = 0,
             message_age: 'float' = 0,
             max_age: 'float' = 0,
             hello_time: 'float' = 0,
             forward_delay: 'float' = 0,
             version_1_length: 'Optional[int]' = 0,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_RSTP':
        """Make (construct) packet data.

        Args:
            protocol_version: Protocol Version Identifier, 2 or more.
            flags: Flags, or the octet.
            root_id: Root Identifier, or its eight octets.
            root_path_cost: Root Path Cost.
            bridge_id: Bridge Identifier, or its eight octets.
            port_id: Port Identifier, or its two octets as an integer.
            message_age: Message Age, in seconds.
            max_age: Max Age, in seconds.
            hello_time: Hello Time, in seconds.
            forward_delay: Forward Delay, in seconds.
            version_1_length: Version 1 Length; :data:`None` to end the BPDU
                before it, at 35 octets, which only a version of 3 or more may.
            payload: Octets past the BPDU.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``protocol_version`` is below 2, or is 2 without a
                ``version_1_length``; if the BPDU and ``payload`` would hold what
                an MST BPDU does; or if a value does not fit its field.

        """
        version = self._make_protocol_version(protocol_version, least=Enum_ProtocolVersion.RSTP)
        if version_1_length is None:
            if version == Enum_ProtocolVersion.RSTP:
                raise ProtocolError('RSTP: an RST BPDU of version 2 carries its Version 1 Length')
        else:
            version_1_length = self._make_uint(version_1_length, bits=8, name='Version 1 Length')

        schema = Schema_RSTP(
            pid=0,
            version=version,
            type=Enum_BPDUType.RST,
            flags=self._make_flags(flags),
            root_id=self._make_bridge_id(root_id, name='Root Identifier'),
            root_path_cost=self._make_uint(root_path_cost, bits=32, name='Root Path Cost'),
            bridge_id=self._make_bridge_id(bridge_id, name='Bridge Identifier'),
            port_id=self._make_port_id(port_id, name='Port Identifier'),
            message_age=self._make_timer(message_age, name='Message Age'),
            max_age=self._make_timer(max_age, name='Max Age'),
            hello_time=self._make_timer(hello_time, name='Hello Time'),
            forward_delay=self._make_timer(forward_delay, name='Forward Delay'),
            version_1_length=version_1_length,
            payload=payload,
        )
        if version > Enum_ProtocolVersion.RSTP and self._is_mst(schema.pack()):
            raise ProtocolError('RSTP: invalid format: the BPDU and its payload hold an MST BPDU, '
                                'so they are no RST BPDU (IEEE 802.1Q-2022 clause 14.4)')
        return schema

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[36]':
        """Return an estimated length for the object."""
        return 36

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_RSTP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'protocol_version': cls._rebuilt_version(data, Enum_ProtocolVersion.RSTP),
            'flags': data.flags,
            'root_id': data.root_id,
            'root_path_cost': data.root_path_cost,
            'bridge_id': data.bridge_id,
            'port_id': data.port_id,
            'message_age': data.message_age,
            'max_age': data.max_age,
            'hello_time': data.hello_time,
            'forward_delay': data.forward_delay,
            # NOTE: Absent where a capture ended first too, which the rebuild cuts back to.
            'version_1_length': (0 if data.version_1_length is None and data.get('__short_read__') is not None
                                 else data.version_1_length),
            'payload': cls._make_payload(data),
        }
