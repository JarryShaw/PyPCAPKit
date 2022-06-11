# -*- coding: utf-8 -*-
"""Dump Utilities
====================

:mod:`pcapkit.dumpkit` is the collection of dumpers for
:mod:`pcapkit` implementation, which is alike those described
in :mod:`dictdumper`.

"""
from pcapkit.dumpkit.pcap import PCAPIO
from pcapkit.dumpkit.null import NotImplementedIO

__all__ = ['PCAPIO', 'NotImplementedIO']
