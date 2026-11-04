# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPv6-Opts - Destination Options for IPv6
==============================================

.. module:: pcapkit.protocols.internet.ipv6_opts

:mod:`pcapkit.protocols.internet.ipv6_opts` holds the dissector,
:class:`~pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts`, in
:mod:`~pcapkit.protocols.internet.ipv6_opts.protocol`, its header schema in
:mod:`~pcapkit.protocols.internet.ipv6_opts.schema` and its data model in
:mod:`~pcapkit.protocols.internet.ipv6_opts.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts

# Header Schemas
from pcapkit.protocols.internet.ipv6_opts.schema import CALIPSOOption as Schema_CALIPSOOption
from pcapkit.protocols.internet.ipv6_opts.schema import \
    HomeAddressOption as Schema_HomeAddressOption
from pcapkit.protocols.internet.ipv6_opts.schema import ILNPOption as Schema_ILNPOption
from pcapkit.protocols.internet.ipv6_opts.schema import IPDFFOption as Schema_IPDFFOption
from pcapkit.protocols.internet.ipv6_opts.schema import IPv6_Opts as Schema_IPv6_Opts
from pcapkit.protocols.internet.ipv6_opts.schema import \
    JumboPayloadOption as Schema_JumboPayloadOption
from pcapkit.protocols.internet.ipv6_opts.schema import \
    LineIdentificationOption as Schema_LineIdentificationOption
from pcapkit.protocols.internet.ipv6_opts.schema import MPLOption as Schema_MPLOption
from pcapkit.protocols.internet.ipv6_opts.schema import Option as Schema_Option
from pcapkit.protocols.internet.ipv6_opts.schema import PadOption as Schema_PadOption
from pcapkit.protocols.internet.ipv6_opts.schema import PDMOption as Schema_PDMOption
from pcapkit.protocols.internet.ipv6_opts.schema import QuickStartOption as Schema_QuickStartOption
from pcapkit.protocols.internet.ipv6_opts.schema import \
    QuickStartReportOption as Schema_QuickStartReportOption
from pcapkit.protocols.internet.ipv6_opts.schema import \
    QuickStartRequestOption as Schema_QuickStartRequestOption
from pcapkit.protocols.internet.ipv6_opts.schema import \
    RouterAlertOption as Schema_RouterAlertOption
from pcapkit.protocols.internet.ipv6_opts.schema import RPLOption as Schema_RPLOption
from pcapkit.protocols.internet.ipv6_opts.schema import SMFDPDOption as Schema_SMFDPDOption
from pcapkit.protocols.internet.ipv6_opts.schema import \
    SMFHashBasedDPDOption as Schema_SMFHashBasedDPDOption
from pcapkit.protocols.internet.ipv6_opts.schema import \
    SMFIdentificationBasedDPDOption as Schema_SMFIdentificationBasedDPDOption
from pcapkit.protocols.internet.ipv6_opts.schema import \
    TunnelEncapsulationLimitOption as Schema_TunnelEncapsulationLimitOption
from pcapkit.protocols.internet.ipv6_opts.schema import UnassignedOption as Schema_UnassignedOption

# Data Models
from pcapkit.protocols.internet.ipv6_opts.data import CALIPSOOption as Data_CALIPSOOption
from pcapkit.protocols.internet.ipv6_opts.data import DFFFlags as Data_DFFFlags
from pcapkit.protocols.internet.ipv6_opts.data import HomeAddressOption as Data_HomeAddressOption
from pcapkit.protocols.internet.ipv6_opts.data import ILNPOption as Data_ILNPOption
from pcapkit.protocols.internet.ipv6_opts.data import IPDFFOption as Data_IPDFFOption
from pcapkit.protocols.internet.ipv6_opts.data import IPv6_Opts as Data_IPv6_Opts
from pcapkit.protocols.internet.ipv6_opts.data import JumboPayloadOption as Data_JumboPayloadOption
from pcapkit.protocols.internet.ipv6_opts.data import \
    LineIdentificationOption as Data_LineIdentificationOption
from pcapkit.protocols.internet.ipv6_opts.data import MPLFlags as Data_MPLFlags
from pcapkit.protocols.internet.ipv6_opts.data import MPLOption as Data_MPLOption
from pcapkit.protocols.internet.ipv6_opts.data import Option as Data_Option
from pcapkit.protocols.internet.ipv6_opts.data import PadOption as Data_PadOption
from pcapkit.protocols.internet.ipv6_opts.data import PDMOption as Data_PDMOption
from pcapkit.protocols.internet.ipv6_opts.data import QuickStartOption as Data_QuickStartOption
from pcapkit.protocols.internet.ipv6_opts.data import \
    QuickStartReportOption as Data_QuickStartReportOption
from pcapkit.protocols.internet.ipv6_opts.data import \
    QuickStartRequestOption as Data_QuickStartRequestOption
from pcapkit.protocols.internet.ipv6_opts.data import RouterAlertOption as Data_RouterAlertOption
from pcapkit.protocols.internet.ipv6_opts.data import RPLFlags as Data_RPLFlags
from pcapkit.protocols.internet.ipv6_opts.data import RPLOption as Data_RPLOption
from pcapkit.protocols.internet.ipv6_opts.data import SMFDPDOption as Data_SMFDPDOption
from pcapkit.protocols.internet.ipv6_opts.data import \
    SMFHashBasedDPDOption as Data_SMFHashBasedDPDOption
from pcapkit.protocols.internet.ipv6_opts.data import \
    SMFIdentificationBasedDPDOption as Data_SMFIdentificationBasedDPDOption
from pcapkit.protocols.internet.ipv6_opts.data import \
    TunnelEncapsulationLimitOption as Data_TunnelEncapsulationLimitOption
from pcapkit.protocols.internet.ipv6_opts.data import UnassignedOption as Data_UnassignedOption

__all__ = ['IPv6_Opts']
