# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""PCAP File Headers
=======================

.. module:: pcapkit.protocols.misc.pcap

:mod:`pcapkit.protocols.misc.pcap` contains header descriptions for
PCAP files, including global header
(:class:`~pcapkit.protocols.misc.pcap.header.protocol.Header`) and frame header
(:class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame`).

Each is imported the first time it is reached rather than with this package,
through :func:`~pcapkit.utilities.importlib.lazy_exports` (:issue:`2730`).

"""
from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.protocols.misc.pcap.frame import Frame
    from pcapkit.protocols.misc.pcap.header import Header

__all__ = ['Frame', 'Header']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Frame': ('frame', 'Frame'),
    'Header': ('header', 'Header'),
})
