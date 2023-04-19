# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""PCAP File Headers
=======================

.. module:: pcapkit.protocols.misc.pcap

:mod:`pcapkit.protocols.misc.pcap` contains header descriptions for
PCAP files, including global header
(:class:`~pcapkit.protocols.misc.pcap.header.Header`) and frame header
(:class:`~pcapkit.protocols.misc.pcap.frame.Frame`).

"""
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcap.header import Header

__all__ = ['Frame', 'Header']
