# -*- coding: utf-8 -*-
"""STPv0 - Spanning Tree Protocol
====================================

.. module:: pcapkit.protocols.application.stpv0.protocol

:mod:`pcapkit.protocols.application.stpv0.protocol` holds
:class:`~pcapkit.protocols.application.stpv0.protocol.STPv0`, the extractor for the
Configuration and Topology Change Notification (TCN) BPDUs of the Spanning Tree
Protocol (STP) [IEEE 802.1D-2004 clause 9], laid out as below. A TCN BPDU ends
after its BPDU Type.

.. table::

   ====== ===== ======================== ===========================
   Octets Bits  Name                     Description
   ====== ===== ======================== ===========================
   0          0                          Protocol Identifier, zero, not kept
   ------ ----- ------------------------ ---------------------------
   2         16 ``stp.protocol_version`` Protocol Version Identifier
   ------ ----- ------------------------ ---------------------------
   3         24 ``stp.type``             BPDU Type
   ------ ----- ------------------------ ---------------------------
   4         32 ``stp.flags``            Flags
   ------ ----- ------------------------ ---------------------------
   5         40 ``stp.root_id``          Root Identifier
   ------ ----- ------------------------ ---------------------------
   13       104 ``stp.root_path_cost``   Root Path Cost
   ------ ----- ------------------------ ---------------------------
   17       136 ``stp.bridge_id``        Bridge Identifier
   ------ ----- ------------------------ ---------------------------
   25       200 ``stp.port_id``          Port Identifier
   ------ ----- ------------------------ ---------------------------
   27       216 ``stp.message_age``      Message Age
   ------ ----- ------------------------ ---------------------------
   29       232 ``stp.max_age``          Max Age
   ------ ----- ------------------------ ---------------------------
   31       248 ``stp.hello_time``       Hello Time
   ------ ----- ------------------------ ---------------------------
   33       264 ``stp.forward_delay``    Forward Delay
   ====== ===== ======================== ===========================

IEEE 802.1Q-2022 clause 14.4 decodes either BPDU by its type, whatever its Protocol
Version Identifier, so the version is kept as captured and checked against none.

.. versionadded:: 1.9.0

"""
import collections.abc
from typing import TYPE_CHECKING

from pcapkit.const.stp.bpdu_type import BPDUType as Enum_BPDUType
from pcapkit.const.stp.protocol_version import ProtocolVersion as Enum_ProtocolVersion
from pcapkit.protocols.application.stp.protocol import STP
from pcapkit.protocols.application.stpv0.data import ConfigFlags as Data_ConfigFlags
from pcapkit.protocols.application.stpv0.data import STPv0 as Data_STPv0
from pcapkit.protocols.application.stpv0.schema import STPv0 as Schema_STPv0
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.application.stp.data import BridgeID as Data_BridgeID
    from pcapkit.protocols.application.stp.data import PortID as Data_PortID
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['STPv0']


class STPv0(STP[Data_STPv0, Schema_STPv0],
            schema=Schema_STPv0, data=Data_STPv0):
    """This class implements the Spanning Tree Protocol, its Configuration and TCN BPDUs.

    .. versionadded:: 1.9.0

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Spanning Tree Protocol"]':
        """Name of current protocol."""
        return 'Spanning Tree Protocol'

    @property
    def version(self) -> 'Literal[0]':
        """Version of the member, the Protocol Version Identifier its BPDUs take."""
        return 0

    @property
    def length(self) -> 'Literal[4, 35]':
        """Header length of current protocol, 4 octets for a TCN BPDU and 35 otherwise."""
        return 4 if self._info.type == Enum_BPDUType.TCN else 35

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["STP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, narrowed to this member's canonical name.

        """
        return ('STP',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_STPv0':  # pylint: disable=unused-argument
        """Read a Configuration or TCN BPDU.

        Structure of a Configuration BPDU [IEEE 802.1D-2004 clause 9]:

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
           |  Hello Time   |         Forward Delay         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the Protocol Identifier is not zero, or the BPDU
                Type is neither a Configuration BPDU's nor a TCN BPDU's.

        """
        if length is None:
            length = len(self)
        schema = self.__header__
        self._check_bpdu(schema, types=(Enum_BPDUType.Configuration, Enum_BPDUType.TCN))

        stp = Data_STPv0(
            protocol_version=schema.version,
            type=schema.type,
        )
        if schema.type != Enum_BPDUType.TCN:
            stp.__update__([
                ('flags', self._read_config_flags(schema.flags)),  # type: ignore[arg-type]
                ('root_id', self._read_bridge_id(schema.root_id)),  # type: ignore[arg-type]
                ('root_path_cost', schema.root_path_cost),
                ('bridge_id', self._read_bridge_id(schema.bridge_id)),  # type: ignore[arg-type]
                ('port_id', self._read_port_id(schema.port_id)),  # type: ignore[arg-type]
                ('message_age', self._read_timer(schema.message_age)),  # type: ignore[arg-type]
                ('max_age', self._read_timer(schema.max_age)),  # type: ignore[arg-type]
                ('hello_time', self._read_timer(schema.hello_time)),  # type: ignore[arg-type]
                ('forward_delay', self._read_timer(schema.forward_delay)),  # type: ignore[arg-type]
            ])
        self._info = stp  # NOTE: :attr:`length` reads the data model.

        # NOTE: The BPDU names no next layer, so what follows it is kept undissected.
        return self._decode_next_layer(stp, -1, max(length - self.length, 0))

    def make(self, *,
             protocol_version: 'Enum_ProtocolVersion | int' = Enum_ProtocolVersion.STP,
             type: 'Enum_BPDUType | int' = Enum_BPDUType.Configuration,  # pylint: disable=redefined-builtin
             flags: 'Optional[Data_ConfigFlags | int]' = None,
             root_id: 'Optional[Data_BridgeID | bytes]' = None,
             root_path_cost: 'Optional[int]' = None,
             bridge_id: 'Optional[Data_BridgeID | bytes]' = None,
             port_id: 'Optional[Data_PortID | int]' = None,
             message_age: 'Optional[float]' = None,
             max_age: 'Optional[float]' = None,
             hello_time: 'Optional[float]' = None,
             forward_delay: 'Optional[float]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_STPv0':
        """Make (construct) packet data.

        ``type`` decides which fields are carried. A Configuration BPDU carries
        them all, and one the caller leaves out is written as zeros; a TCN BPDU
        carries none past its BPDU Type, which must be left out.

        Args:
            protocol_version: Protocol Version Identifier.
            type: BPDU Type, a Configuration or a TCN BPDU.
            flags: Flags, or the octet.
            root_id: Root Identifier, or its eight octets.
            root_path_cost: Root Path Cost.
            bridge_id: Bridge Identifier, or its eight octets.
            port_id: Port Identifier, or its two octets as an integer.
            message_age: Message Age, in seconds.
            max_age: Max Age, in seconds.
            hello_time: Hello Time, in seconds.
            forward_delay: Forward Delay, in seconds.
            payload: Octets past the BPDU.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``type`` is neither BPDU's, or is a name; if a field
                is given that a TCN BPDU does not carry; or if a value does not fit
                its field.

        """
        version = self._make_protocol_version(protocol_version, least=0)
        type_ = self._make_index(type, Enum_BPDUType, bits=8, name='BPDU Type')
        if type_ not in (Enum_BPDUType.Configuration, Enum_BPDUType.TCN):
            raise ProtocolError(f'{self.alias}: invalid BPDU Type: {int(type_):#04x}')

        fields = {
            'flags': flags, 'root_id': root_id, 'root_path_cost': root_path_cost,
            'bridge_id': bridge_id, 'port_id': port_id, 'message_age': message_age,
            'max_age': max_age, 'hello_time': hello_time, 'forward_delay': forward_delay,
        }  # type: dict[str, Any]
        if type_ == Enum_BPDUType.TCN:
            for name, value in fields.items():
                if value is not None:
                    raise ProtocolError(f'{self.alias}: {name} given, but a TCN BPDU carries none')
            return Schema_STPv0(
                pid=0, version=version, type=type_, flags=None, root_id=None, root_path_cost=None,
                bridge_id=None, port_id=None, message_age=None, max_age=None, hello_time=None,
                forward_delay=None, payload=payload,
            )

        return Schema_STPv0(
            pid=0,
            version=version,
            type=type_,
            flags=self._make_config_flags(0 if flags is None else flags),
            root_id=self._make_bridge_id(bytes(8) if root_id is None else root_id, name='Root Identifier'),
            root_path_cost=self._make_uint(0 if root_path_cost is None else root_path_cost,
                                           bits=32, name='Root Path Cost'),
            bridge_id=self._make_bridge_id(bytes(8) if bridge_id is None else bridge_id, name='Bridge Identifier'),
            port_id=self._make_port_id(0 if port_id is None else port_id, name='Port Identifier'),
            message_age=self._make_timer(0 if message_age is None else message_age, name='Message Age'),
            max_age=self._make_timer(0 if max_age is None else max_age, name='Max Age'),
            hello_time=self._make_timer(0 if hello_time is None else hello_time, name='Hello Time'),
            forward_delay=self._make_timer(0 if forward_delay is None else forward_delay, name='Forward Delay'),
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[35]':
        """Return an estimated length for the object, a Configuration BPDU's."""
        return 35

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_STPv0') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'protocol_version': data.protocol_version,
            'type': data.type,
            'flags': data.get('flags'),
            'root_id': data.get('root_id'),
            'root_path_cost': data.get('root_path_cost'),
            'bridge_id': data.get('bridge_id'),
            'port_id': data.get('port_id'),
            'message_age': data.get('message_age'),
            'max_age': data.get('max_age'),
            'hello_time': data.get('hello_time'),
            'forward_delay': data.get('forward_delay'),
            'payload': cls._make_payload(data),
        }

    @staticmethod
    def _read_config_flags(value: 'int') -> 'Data_ConfigFlags':
        """Read the flags of a Configuration BPDU.

        Args:
            value: The flags octet.

        Returns:
            Parsed flags.

        """
        return Data_ConfigFlags(
            tc=bool(value & 0x01),
            reserved=(value >> 1) & 0x3F,
            tc_ack=bool(value & 0x80),
        )

    def _make_config_flags(self, value: 'Data_ConfigFlags | int') -> 'int':
        """Make the flags of a Configuration BPDU.

        Args:
            value: The flags, as their data model or a mapping of its keys, or the
                octet as an integer.

        Returns:
            The flags octet.

        Raises:
            ProtocolError: If ``value`` is neither, a flag is no :obj:`bool`, or
                the reserved bits do not fit in six.

        """
        if not isinstance(value, collections.abc.Mapping):
            return self._make_uint(value, bits=8, name='flags')
        return (self._make_uint(value['tc'], bits=1, name='Topology Change flag')
                | self._make_uint(value['reserved'], bits=6, name='reserved flags') << 1
                | self._make_uint(value['tc_ack'], bits=1, name='Topology Change Acknowledgment flag') << 7)
