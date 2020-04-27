# -*- coding: utf-8 -*-
# pylint: disable=unused-import,unused-wildcard-import,fixme
"""PCAP file headers

:mod:`pcapkit.protocols.pcap` contains header descriptions for
PCAP files, including global header
(:class:`~pcapkit.protocols.pcap.header.Header`) and frame header
(:class:`~pcapkit.protocols.pcap.frame.Frame`).

"""
from pcapkit.protocols.pcap.frame import Frame
from pcapkit.protocols.pcap.header import Header

__all__ = ['Frame', 'Header']
