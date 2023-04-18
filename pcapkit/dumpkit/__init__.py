# -*- coding: utf-8 -*-
"""Dump Utilities
====================

.. module:: pcapkit.dumpkit

:mod:`pcapkit.dumpkit` is the collection of dumpers for
:mod:`pcapkit` implementation, which is alike those described
in :mod:`dictdumper`.

"""
from pcapkit.dumpkit.null import NotImplementedIO
from pcapkit.dumpkit.pcap import PCAPIO

__all__ = ['PCAPIO', 'NotImplementedIO']
