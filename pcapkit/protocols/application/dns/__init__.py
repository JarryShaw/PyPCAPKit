# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""DNS - Domain Name System
==============================

.. module:: pcapkit.protocols.application.dns

:mod:`pcapkit.protocols.application.dns` holds the dissector,
:class:`~pcapkit.protocols.application.dns.protocol.DNS`, in
:mod:`~pcapkit.protocols.application.dns.protocol`, its header schema and the
domain name codec in :mod:`~pcapkit.protocols.application.dns.schema` and its
data model in :mod:`~pcapkit.protocols.application.dns.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.dns.protocol import DNS

# Header Schemas
from pcapkit.protocols.application.dns.schema import DNS as Schema_DNS

# Data Models
from pcapkit.protocols.application.dns.data import AAAA as Data_AAAA
from pcapkit.protocols.application.dns.data import CAA as Data_CAA
from pcapkit.protocols.application.dns.data import CNAME as Data_CNAME
from pcapkit.protocols.application.dns.data import DNS as Data_DNS
from pcapkit.protocols.application.dns.data import MX as Data_MX
from pcapkit.protocols.application.dns.data import NS as Data_NS
from pcapkit.protocols.application.dns.data import OPT as Data_OPT
from pcapkit.protocols.application.dns.data import PTR as Data_PTR
from pcapkit.protocols.application.dns.data import SOA as Data_SOA
from pcapkit.protocols.application.dns.data import SRV as Data_SRV
from pcapkit.protocols.application.dns.data import TXT as Data_TXT
from pcapkit.protocols.application.dns.data import A as Data_A
from pcapkit.protocols.application.dns.data import ClientSubnet as Data_ClientSubnet
from pcapkit.protocols.application.dns.data import Cookie as Data_Cookie
from pcapkit.protocols.application.dns.data import ExtendedError as Data_ExtendedError
from pcapkit.protocols.application.dns.data import Flags as Data_Flags
from pcapkit.protocols.application.dns.data import Name as Data_Name
from pcapkit.protocols.application.dns.data import Option as Data_Option
from pcapkit.protocols.application.dns.data import OptionData as Data_OptionData
from pcapkit.protocols.application.dns.data import Question as Data_Question
from pcapkit.protocols.application.dns.data import RData as Data_RData
from pcapkit.protocols.application.dns.data import ResourceRecord as Data_ResourceRecord
from pcapkit.protocols.application.dns.data import TCPKeepalive as Data_TCPKeepalive

__all__ = ['DNS']
