# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""BOOTP - Bootstrap Protocol
================================

.. module:: pcapkit.protocols.application.bootp

:mod:`pcapkit.protocols.application.bootp` holds the dissector,
:class:`~pcapkit.protocols.application.bootp.protocol.BOOTP`, in
:mod:`~pcapkit.protocols.application.bootp.protocol`, and its data model in
:mod:`~pcapkit.protocols.application.bootp.data`; its header schema is the
family's, :class:`~pcapkit.protocols.application.dhcp.schema.DHCP`.

Its data class is importable as ``Data_BOOTP``.

.. versionadded:: 1.10.0

"""
from pcapkit.protocols.application.bootp.protocol import BOOTP

# Data Models
from pcapkit.protocols.application.bootp.data import BOOTP as Data_BOOTP

__all__ = ['BOOTP']
