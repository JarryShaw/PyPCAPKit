# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DHCP Relay Agent Sub-Option Codes
=======================================

.. module:: pcapkit.const.dhcp.relay_agent_suboption

This module contains the constant enumeration for **DHCP Relay Agent Sub-Option Codes**,
which is automatically generated from :class:`pcapkit.vendor.dhcp.relay_agent_suboption.RelayAgentSubOption`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['RelayAgentSubOption']


class RelayAgentSubOption(EnumRegistry, IntEnum):
    """[RelayAgentSubOption] DHCP Relay Agent Sub-Option Codes"""

    #: Agent Circuit ID Sub-option [:rfc:`3046`]
    Agent_Circuit_ID_Sub_option = 1

    #: Agent Remote ID Sub-option [:rfc:`3046`]
    Agent_Remote_ID_Sub_option = 2

    #: Sub-option 3 is reserved and should not be assigned at this time;
    #: proprietary and incompatible usages of this sub-option value have been seen
    #: limited deployment. [Ralph Droms]
    Reserved_3 = 3

    #: DOCSIS Device Class Suboption [:rfc:`3256`]
    DOCSIS_Device_Class_Suboption = 4

    #: Link selection Sub-option [:rfc:`3527`]
    Link_selection_Sub_option = 5

    #: Subscriber-ID Suboption [:rfc:`3993`]
    Subscriber_ID_Suboption = 6

    #: RADIUS Attributes Sub-option [:rfc:`4014`]
    RADIUS_Attributes_Sub_option = 7

    #: Authentication Suboption [:rfc:`4030`]
    Authentication_Suboption = 8

    #: Vendor-Specific Information Suboption [:rfc:`4243`]
    Vendor_Specific_Information_Suboption = 9

    #: Relay Agent Flags [:rfc:`5010`]
    Relay_Agent_Flags = 10

    #: Server Identifier Override Suboption [:rfc:`5107`]
    Server_Identifier_Override_Suboption = 11

    #: Relay Agent Identifier Sub-option [:rfc:`6925`]
    Relay_Agent_Identifier_Sub_option = 12

    #: Access-Technology-Type Sub-option [:rfc:`7839`]
    Access_Technology_Type_Sub_option = 13

    #: Access-Network-Name Sub-option [:rfc:`7839`]
    Access_Network_Name_Sub_option = 14

    #: Access-Point-Name Sub-option [:rfc:`7839`]
    Access_Point_Name_Sub_option = 15

    #: Access-Point-BSSID Sub-option [:rfc:`7839`]
    Access_Point_BSSID_Sub_option = 16

    #: Operator-Identifier Sub-option [:rfc:`7839`]
    Operator_Identifier_Sub_option = 17

    #: Operator-Realm Sub-option [:rfc:`7839`]
    Operator_Realm_Sub_option = 18

    #: DHCPv4 Relay Source Port Sub-Option [:rfc:`8357`]
    DHCPv4_Relay_Source_Port_Sub_Option = 19

    #: DHCPv4 Virtual Subnet Selection Sub-Option [:rfc:`6607`]
    DHCPv4_Virtual_Subnet_Selection_Sub_Option = 151

    #: DHCPv4 Virtual Subnet Selection Control Sub-Option [:rfc:`6607`]
    DHCPv4_Virtual_Subnet_Selection_Control_Sub_Option = 152

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'RelayAgentSubOption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 20 <= value <= 150:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return cls._unregistered_member(value, 'Unassigned')
