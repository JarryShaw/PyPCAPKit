# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""DHCPv4 - Dynamic Host Configuration Protocol
==================================================

.. module:: pcapkit.protocols.application.dhcpv4

:mod:`pcapkit.protocols.application.dhcpv4` holds the dissector,
:class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4`, in
:mod:`~pcapkit.protocols.application.dhcpv4.protocol`, and its data model in
:mod:`~pcapkit.protocols.application.dhcpv4.data`; its header schema is the
family's, :class:`~pcapkit.protocols.application.dhcp.schema.DHCP`.

Its data class is importable as ``Data_DHCPv4``.

.. versionadded:: 1.10.0

"""
from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

# Data Models
from pcapkit.protocols.application.dhcpv4.data import DHCPv4 as Data_DHCPv4

__all__ = ['DHCPv4']
