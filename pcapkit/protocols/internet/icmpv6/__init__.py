# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""ICMPv6 - Internet Control Message Protocol for IPv6
=========================================================

.. module:: pcapkit.protocols.internet.icmpv6

:mod:`pcapkit.protocols.internet.icmpv6` holds the dissector,
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`, in
:mod:`~pcapkit.protocols.internet.icmpv6.protocol`, its header schema in
:mod:`~pcapkit.protocols.internet.icmpv6.schema` and its data model in
:mod:`~pcapkit.protocols.internet.icmpv6.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

# Header Schemas
from pcapkit.protocols.internet.icmpv6.schema import \
    DestinationUnreachable as Schema_DestinationUnreachable
from pcapkit.protocols.internet.icmpv6.schema import Echo as Schema_Echo
from pcapkit.protocols.internet.icmpv6.schema import ICMPv6 as Schema_ICMPv6
from pcapkit.protocols.internet.icmpv6.schema import ICMPv6Type as Schema_ICMPv6Type
from pcapkit.protocols.internet.icmpv6.schema import PacketTooBig as Schema_PacketTooBig
from pcapkit.protocols.internet.icmpv6.schema import ParameterProblem as Schema_ParameterProblem
from pcapkit.protocols.internet.icmpv6.schema import TimeExceeded as Schema_TimeExceeded
from pcapkit.protocols.internet.icmpv6.schema import Unknown as Schema_Unknown

# Data Models
from pcapkit.protocols.internet.icmpv6.data import \
    DestinationUnreachable as Data_DestinationUnreachable
from pcapkit.protocols.internet.icmpv6.data import Echo as Data_Echo
from pcapkit.protocols.internet.icmpv6.data import ICMPv6 as Data_ICMPv6
from pcapkit.protocols.internet.icmpv6.data import PacketTooBig as Data_PacketTooBig
from pcapkit.protocols.internet.icmpv6.data import ParameterProblem as Data_ParameterProblem
from pcapkit.protocols.internet.icmpv6.data import TimeExceeded as Data_TimeExceeded
from pcapkit.protocols.internet.icmpv6.data import Unknown as Data_Unknown

__all__ = ['ICMPv6']
