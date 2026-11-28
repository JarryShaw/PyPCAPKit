# -*- coding: utf-8 -*-
"""SNAP - Subnetwork Access Protocol
=======================================

.. module:: pcapkit.protocols.link.snap.protocol

:mod:`pcapkit.protocols.link.snap.protocol` contains
:class:`~pcapkit.protocols.link.snap.protocol.SNAP` only,
which implements the extractor for the IEEE 802 Subnetwork Access
Protocol (SNAP) [*]_ header, whose structure is described as below:

.. table::

   ====== ===== ================ =========================================
   Octets Bits  Name             Description
   ====== ===== ================ =========================================
   0          0 ``snap.oui``     Organizationally Unique Identifier
   ------ ----- ---------------- -----------------------------------------
   3         24 ``snap.pid``     Protocol identifier
   ====== ===== ================ =========================================

.. [*] https://en.wikipedia.org/wiki/Subnetwork_Access_Protocol

"""
from typing import TYPE_CHECKING

from pcapkit.const.llc.lsap import LSAP as Enum_LSAP
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.link.snap.data import SNAP as Data_SNAP
from pcapkit.protocols.link.snap.schema import SNAP as Schema_SNAP

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['SNAP']


class SNAP(Link[Data_SNAP, Schema_SNAP],
           schema=Schema_SNAP, data=Data_SNAP):
    """This class implements IEEE 802 Subnetwork Access Protocol.

    The header is the information field of an
    :class:`~pcapkit.protocols.link.llc.protocol.LLC` PDU whose DSAP is
    :attr:`~pcapkit.const.llc.lsap.LSAP.SNAP`. Under the OUI ``00-00-00`` the
    protocol identifier is an EtherType (:rfc:`9542#section-3`), and the
    payload is dispatched through :attr:`Link.__proto__
    <pcapkit.protocols.link.link.Link.__proto__>` as Ethernet dispatches it.
    Under any other OUI the protocol identifier is that organization's, and
    the payload is kept as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

    .. versionadded:: 1.9.0

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Subnetwork Access Protocol"]':
        """Name of current protocol."""
        return 'Subnetwork Access Protocol'

    @property
    def length(self) -> 'Literal[5]':
        """Header length of current protocol."""
        return 5

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_SNAP':  # pylint: disable=unused-argument
        """Read IEEE 802 Subnetwork Access Protocol.

        Structure of SNAP header [IEEE Std 802]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Organizationally Unique Identifier       |  Protocol...  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |...Identifier  |
           +-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        oui = int.from_bytes(schema.oui, 'big')
        pid = schema.pid if oui else Enum_EtherType.get(schema.pid)
        snap = Data_SNAP(
            oui=oui,
            pid=pid,
        )
        return self._decode_next_layer(snap, -1 if oui else pid, length - self.length)

    def make(self, *,
             oui: 'int' = 0x000000,
             pid: 'Enum_EtherType | int' = Enum_EtherType.Internet_Protocol_version_4,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_SNAP':
        """Make (construct) packet data.

        Args:
            oui: Organizationally Unique Identifier.
            pid: Protocol identifier, an EtherType where ``oui`` is
                ``00-00-00``.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``oui`` does not fit in 24 bits, or ``pid`` is a
                name, a :obj:`bool`, or a code its field cannot carry.

        """
        oui_ = self._make_uint(oui, bits=24, name='OUI')
        if oui_:
            pid_ = self._make_uint(pid, bits=16, name='PID')
        else:
            pid_ = int(self._make_index(pid, Enum_EtherType, bits=16, name='PID'))

        return Schema_SNAP(
            oui=self._make_pack(oui_, size=3),
            pid=pid_,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[5]':
        """Return an estimated length for the object."""
        return 5

    @classmethod
    def __index__(cls) -> 'Enum_LSAP':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in the LLC address values,
            since no link type, EtherType, protocol number or port names it.

        """
        return Enum_LSAP.SNAP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_SNAP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'oui': data.oui,
            'pid': data.pid,
            'payload': cls._make_payload(data),
        }
