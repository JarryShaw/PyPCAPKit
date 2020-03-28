# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPv4 constant enumerations."""

from pcapkit.const.ipv4.classification_level import ClassificationLevel as IPv4_ClassificationLevel
from pcapkit.const.ipv4.option_class import OptionClass as IPv4_OptionClass
from pcapkit.const.ipv4.option_number import OptionNumber as IPv4_OptionNumber
from pcapkit.const.ipv4.protection_authority import ProtectionAuthority as IPv4_ProtectionAuthority
from pcapkit.const.ipv4.qs_function import QS_Function as IPv4_QS_Function
from pcapkit.const.ipv4.router_alert import RouterAlert as IPv4_RouterAlert
from pcapkit.const.ipv4.tos_del import TOS_DEL as IPv4_TOS_DEL
from pcapkit.const.ipv4.tos_ecn import TOS_ECN as IPv4_TOS_ECN
from pcapkit.const.ipv4.tos_pre import TOS_PRE as IPv4_TOS_PRE
from pcapkit.const.ipv4.tos_rel import TOS_REL as IPv4_TOS_REL
from pcapkit.const.ipv4.tos_thr import TOS_THR as IPv4_TOS_THR

__all__ = ['IPv4_ClassificationLevel', 'IPv4_OptionClass', 'IPv4_OptionNumber', 'IPv4_ProtectionAuthority',
           'IPv4_QS_Function', 'IPv4_RouterAlert', 'IPv4_TOS_DEL', 'IPv4_TOS_ECN', 'IPv4_TOS_PRE', 'IPv4_TOS_REL',
           'IPv4_TOS_THR']
