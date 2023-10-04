# -*- coding: utf-8 -*-
"""L2TP - Layer Two Tunnelling Protocol
==========================================

.. module:: pcapkit.protocols.link.l2tp

:mod:`pcapkit.protocols.link.l2tp` contains
:class:`~pcapkit.protocols.link.l2tp.L2TP` only,
which implements extractor for Layer Two Tunnelling
Protocol (L2TP) [*]_, whose structure is described
as below:

.. table::

   ======= ===== ===================== ==========================================
    Octets Bits  Name                  Description
   ======= ===== ===================== ==========================================
    0          0 ``l2tp.flags``        Flags and Version Info
   ------- ----- --------------------- ------------------------------------------
    0          0 ``l2tp.flags.type``   Type (control / data)
   ------- ----- --------------------- ------------------------------------------
    0          1 ``l2tp.flags.len``    Length
   ------- ----- --------------------- ------------------------------------------
    0          2                       Reserved (must be zero ``x00``)
   ------- ----- --------------------- ------------------------------------------
    0          4 ``l2tp.flags.seq``    Sequence
   ------- ----- --------------------- ------------------------------------------
    0          5                       Reserved (must be zero ``x00``)
   ------- ----- --------------------- ------------------------------------------
    0          6 ``l2tp.flags.offset`` Offset
   ------- ----- --------------------- ------------------------------------------
    0          7 ``l2tp.flags.prio``   Priority
   ------- ----- --------------------- ------------------------------------------
    1          8                       Reserved (must be zero ``x00``)
   ------- ----- --------------------- ------------------------------------------
    1         12 ``l2tp.ver``          Version (``2``)
   ------- ----- --------------------- ------------------------------------------
    2         16 ``l2tp.length``       Length (optional by ``len``)
   ------- ----- --------------------- ------------------------------------------
    4         32 ``l2tp.tunnelid``     Tunnel ID
   ------- ----- --------------------- ------------------------------------------
    6         48 ``l2tp.sessionid``    Session ID
   ------- ----- --------------------- ------------------------------------------
    8         64 ``l2tp.ns``           Sequence Number (optional by ``seq``)
   ------- ----- --------------------- ------------------------------------------
    10        80 ``l2tp.nr``           Next Sequence Number (optional by ``seq``)
   ------- ----- --------------------- ------------------------------------------
    12        96 ``l2tp.offset``       Offset Size (optional by ``offset``)
   ======= ===== ===================== ==========================================

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol

"""
from typing import TYPE_CHECKING

from pcapkit.const.l2tp.type import Type as Enum_Type
from pcapkit.protocols.data.link.l2tp import L2TP as Data_L2TP
from pcapkit.protocols.data.link.l2tp import Flags as Data_Flags
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.l2tp import L2TP as Schema_L2TP
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['L2TP']


class L2TP(Link[Data_L2TP, Schema_L2TP],
           schema=Schema_L2TP, data=Data_L2TP):
    """This class implements Layer Two Tunnelling Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Layer 2 Tunnelling Protocol"]':
        """Name of current protocol."""
        return 'Layer 2 Tunnelling Protocol'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.hdr_len

    @property
    def type(self) -> 'Literal["control", "data"]':
        """L2TP type."""
        return self._info.flags.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_L2TP':  # pylint: disable=unused-argument
        """Read Layer Two Tunnelling Protocol.

        Structure of L2TP header [:rfc:`2661`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Tunnel ID           |           Session ID          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |             Ns (opt)          |             Nr (opt)          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Offset Size (opt)        |    Offset pad... (opt)
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        schema = self.__header__
        _flag = schema.flags

        flags = Data_Flags(
            type=Enum_Type(_flag['type']),
            len=bool(_flag['len']),
            seq=bool(_flag['seq']),
            offset=bool(_flag['offset']),
            prio=bool(_flag['prio']),
        )

        _size = schema.offset if flags.offset else 0
        hdr_len = 6 + 2 * (flags.len + 2 * flags.seq + flags.offset) + _size

        l2tp = Data_L2TP(
            flags=flags,
            version=_flag['version'],
            length=schema.length if flags.len else None,
            tunnelid=schema.tunnel_id,
            sessionid=schema.session_id,
            ns=schema.ns if flags.seq else None,
            nr=schema.nr if flags.seq else None,
            offset=_size if flags.offset else None,
        )

        l2tp.__update__([
            ('hdr_len', hdr_len),
        ])
        if _size:
            self._read_fileng(_size)
            # l2tp['padding'] = self._read_fileng(_size)

        length = schema.length if flags.len else (length or len(self))
        return self._decode_next_layer(l2tp, length - hdr_len)

    def make(self,
             version: 'Literal[2]' = 2,
             type: 'Enum_Type | StdlibEnum | AenumEnum | str | int' = Enum_Type.Data,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             priority: 'bool' = False,
             length: 'Optional[int]' = None,
             tunnel_id: 'int' = 0,
             session_id: 'int' = 0,
             ns: 'Optional[int]' = None,
             nr: 'Optional[int]' = None,
             offset: 'Optional[int]' = None,
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_L2TP':  # pylint: disable=unused-argument
        """Make (construct) packet data.

        Args:
            version: L2TP version.
            type: L2TP type.
            type_default: Default value of type.
            type_namespace: Namespace of type.
            type_reversed: Reversed namespace of type.
            priority: Priority flag.
            length: Length of packet data.
            tunnel_id: Tunnel ID.
            session_id: Session ID.
            ns: Sequence number.
            nr: Acknowledgement number.
            offset: Offset size.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        type_ = self._make_index(type, type_default, namespace=type_namespace,
                                 reversed=type_reversed, pack=False)

        return Schema_L2TP(
            flags={
                'type': type_,
                'len': length is not None,
                'seq': ns is not None and nr is not None,
                'offset': offset is not None,
                'prio': priority,
                'version': version,
            },
            length=length,
            tunnel_id=tunnel_id,
            session_id=session_id,
            ns=ns,
            nr=nr,
            offset=offset,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[16]':
        """Return an estimated length for the object."""
        return 16

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_L2TP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'type': data.flags.type,
            'prio': data.flags.prio,
            'version': data.version,
            'length': data.length,
            'tunnel_id': data.tunnelid,
            'session_id': data.sessionid,
            'ns': data.ns,
            'nr': data.nr,
            'offset': data.offset,
            'payload': cls._make_payload(data),
        }
