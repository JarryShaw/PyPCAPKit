# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPv4 constant enumerations."""

from pcapkit.const.ipv4.classification_level import ClassificationLevel as IPv4_ClassificationLevel
from pcapkit.const.ipv4.option_class import OptionClass as IPv4_OptionClass
from pcapkit.const.ipv4.option_number import OptionNumber as IPv4_OptionNumber
from pcapkit.const.ipv4.protection_authority import ProtectionAuthority as IPv4_ProtectionAuthority
from pcapkit.const.ipv4.qs_function import QSFunction as IPv4_QSFunction
from pcapkit.const.ipv4.router_alert import RouterAlert as IPv4_RouterAlert
from pcapkit.const.ipv4.tos_del import ToSDelay as IPv4_ToSDelay
from pcapkit.const.ipv4.tos_ecn import ToSECN as IPv4_ToSECN
from pcapkit.const.ipv4.tos_pre import ToSPrecedence as IPv4_ToSPrecedence
from pcapkit.const.ipv4.tos_rel import ToSReliability as IPv4_ToSReliability
from pcapkit.const.ipv4.tos_thr import ToSThroughput as IPv4_ToSThroughput

__all__ = ['IPv4_ClassificationLevel', 'IPv4_OptionClass', 'IPv4_OptionNumber', 'IPv4_ProtectionAuthority',
           'IPv4_QSFunction', 'IPv4_RouterAlert', 'IPv4_ToSDelay', 'IPv4_ToSECN', 'IPv4_ToSPrecedence',
           'IPv4_ToSReliability', 'IPv4_ToSThroughput']
