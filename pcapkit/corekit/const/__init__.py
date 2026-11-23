# -*- coding: utf-8 -*-
"""Shared Format Constants
=============================

.. module:: pcapkit.corekit.const

:mod:`pcapkit.corekit.const` holds the constants the formats and the RFCs fix
that code beyond their own protocol references, one module per topic:
:mod:`~pcapkit.corekit.const.capture` for the PCAP and PCAP-NG file formats,
:mod:`~pcapkit.corekit.const.ipheader` for the IPv4, IPv6 and AH headers, and
:mod:`~pcapkit.corekit.const.tcpheader` for the TCP header. It sits beside
:mod:`pcapkit.corekit.schema` rather than in it, since most of its readers -- the
engines, the dumpers, IP reassembly and the toolkit -- are not schema code. It is
not :mod:`pcapkit.const`, which holds the enumerations generated from the vendor
registries; see :ref:`utilities-or-corekit`.

The package exports nothing itself, so that a module importing one topic loads no
other: import each constant from its own module.

.. versionadded:: 1.7.0

"""

__all__ = []  # type: list[str]
