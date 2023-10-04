# -*- coding: utf-8 -*-
"""VLAN - 802.1Q Customer VLAN Tag Type
==========================================

.. module:: pcapkit.protocols.link.vlan

:mod:`pcapkit.protocols.link.vlan` contains
:class:`~pcapkit.protocols.link.vlan.VLAN`
only, which implements extractor for 802.1Q
Customer VLAN Tag Type [*]_, whose structure is
described as below:

======= ========= ====================== =============================
Octets      Bits        Name                    Description
======= ========= ====================== =============================
  1           0   ``vlan.tci``              Tag Control Information
  1           0   ``vlan.tci.pcp``          Priority Code Point
  1           3   ``vlan.tci.dei``          Drop Eligible Indicator
  1           4   ``vlan.tci.vid``          VLAN Identifier
  3          24   ``vlan.type``             Protocol (Internet Layer)
======= ========= ====================== =============================

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q

"""
from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.vlan.priority_level import PriorityLevel as Enum_PriorityLevel
from pcapkit.protocols.data.link.vlan import TCI as Data_TCI
from pcapkit.protocols.data.link.vlan import VLAN as Data_VLAN
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.vlan import TCI as Schema_TCI
from pcapkit.protocols.schema.link.vlan import VLAN as Schema_VLAN
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.link.vlan import TCIType
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['VLAN']


class VLAN(Link[Data_VLAN, Schema_VLAN],
           schema=Schema_VLAN, data=Data_VLAN):
    """This class implements 802.1Q Customer VLAN Tag Type."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["802.1Q Customer VLAN Tag Type"]':
        """Name of current protocol."""
        return '802.1Q Customer VLAN Tag Type'

    @property
    def alias(self) -> 'Literal["802.1Q"]':
        """Acronym of corresponding protocol."""
        return '802.1Q'

    @property
    def info_name(self) -> 'Literal["c_tag"]':
        """Key name of the :attr:`info` dict."""
        return 'c_tag'

    @property
    def length(self) -> 'Literal[4]':
        """Header length of current protocol."""
        return 4

    @property
    def protocol(self) -> 'Enum_EtherType':
        """Name of next layer protocol."""
        return self._info.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_VLAN':  # pylint: disable=unused-argument
        """Read 802.1Q Customer VLAN Tag Type.

        Structure of 802.1Q Customer VLAN Tag Type [`IEEE 802.1Q <https://standards.ieee.org/ieee/802.1Q/6844/>`__]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |              TCI              |                               |
           |-------------------------------|                               |
           |  P  |D|                       |             Type              |
           |  C  |E|          VID          |                               |
           |  P  |I|                       |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        tci = schema.tci
        vlan = Data_VLAN(
            tci=Data_TCI(
                pcp=Enum_PriorityLevel.get(tci['pcp']),
                dei=bool(tci['pcp']),
                vid=int(tci['vid']),
            ),
            type=schema.type,
        )
        return self._decode_next_layer(vlan, schema.type, length - self.length)

    def make(self,
             tci: 'Optional[Schema_TCI | TCIType]' = None,
             pcp: 'Enum_PriorityLevel | StdlibEnum | AenumEnum | str | int' = Enum_PriorityLevel.BE,
             pcp_default: 'Optional[int]' = None,
             pcp_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             pcp_reversed: 'bool' = False,
             dei: 'bool' = False,
             vid: 'int' = 0,
             type: 'Enum_EtherType | StdlibEnum | AenumEnum | str | int' = Enum_EtherType.Internet_Protocol_version_4,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_VLAN':
        """Make (construct) packet data.

        Args:
            tci: TCI field.
            pcp: Priority Code Point (PCP) field.
            pcp_default: Default value of PCP field.
            pcp_namespace: Namespace of PCP field.
            pcp_reversed: Reversed flag of PCP field.
            dei: Drop Eligible Indicator (DEI) field.
            vid: VLAN Identifier (VID) field.
            type: EtherType field.
            type_default: Default value of EtherType field.
            type_namespace: Namespace of EtherType field.
            type_reversed: Reversed flag of EtherType field.
            payload: Payload field.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        if tci is not None:
            pcp_value = tci['pcp']
            dei = tci['dei']  # type: ignore[assignment]
            vid = tci['vid']
        else:
            pcp_value = self._make_index(pcp, pcp_default, namespace=pcp_namespace,
                                         reversed=pcp_reversed, pack=False)

        type_value = self._make_index(type, type_default, namespace=type_namespace,
                                      reversed=type_reversed, pack=False)

        return Schema_VLAN(
            tci={
                'pcp': pcp_value,
                'dei': dei,
                'vid': vid,
            },
            type=type_value,  # type: ignore[arg-type]
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object."""
        return 4

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
    def _make_data(cls, data: 'Data_VLAN') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'tci': {
                'pcp': data.tci.pcp,
                'dei': data.tci.dei,
                'vid': data.tci.vid,
            },
            'type': data.type,
            'payload': cls._make_payload(data),
        }
