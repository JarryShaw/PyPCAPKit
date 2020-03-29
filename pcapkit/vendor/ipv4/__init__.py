# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPv4 vendor crawlers for constant enumerations."""

from pcapkit.vendor.ipv4.classification_level import ClassificationLevel as IPv4_ClassificationLevel
from pcapkit.vendor.ipv4.option_class import OptionClass as IPv4_OptionClass
from pcapkit.vendor.ipv4.option_number import OptionNumber as IPv4_OptionNumber
from pcapkit.vendor.ipv4.protection_authority import ProtectionAuthority as IPv4_ProtectionAuthority
from pcapkit.vendor.ipv4.qs_function import QSFunction as IPv4_QSFunction
from pcapkit.vendor.ipv4.router_alert import RouterAlert as IPv4_RouterAlert
from pcapkit.vendor.ipv4.tos_del import ToS_DEL as IPv4_ToS_DEL
from pcapkit.vendor.ipv4.tos_ecn import ToS_ECN as IPv4_ToS_ECN
from pcapkit.vendor.ipv4.tos_pre import ToS_PRE as IPv4_ToS_PRE
from pcapkit.vendor.ipv4.tos_rel import ToS_REL as IPv4_ToS_REL
from pcapkit.vendor.ipv4.tos_thr import ToS_THR as IPv4_ToS_THR

__all__ = ['IPv4_ClassificationLevel', 'IPv4_OptionClass', 'IPv4_OptionNumber', 'IPv4_ProtectionAuthority',
           'IPv4_QSFunction', 'IPv4_RouterAlert', 'IPv4_ToS_DEL', 'IPv4_ToS_ECN', 'IPv4_ToS_PRE', 'IPv4_ToS_REL',
           'IPv4_ToS_THR']
