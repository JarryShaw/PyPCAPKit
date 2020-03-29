# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPv6 vendor crawler for constant enumerations."""

from pcapkit.vendor.ipv6.extension_header import ExtensionHeader as IPv6_ExtensionHeader
from pcapkit.vendor.ipv6.option import Option as IPv6_Option
from pcapkit.vendor.ipv6.qs_function import QSFunction as IPv6_QSFunction
from pcapkit.vendor.ipv6.router_alert import RouterAlert as IPv6_RouterAlert
from pcapkit.vendor.ipv6.routing import Routing as IPv6_Routing
from pcapkit.vendor.ipv6.seed_id import SeedID as IPv6_SeedID
from pcapkit.vendor.ipv6.tagger_id import TaggerID as IPv6_TaggerID

__all__ = ['IPv6_ExtensionHeader', 'IPv6_Option', 'IPv6_QSFunction', 'IPv6_RouterAlert', 'IPv6_Routing',
           'IPv6_SeedID', 'IPv6_TaggerID']
