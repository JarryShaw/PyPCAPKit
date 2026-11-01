# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Reassembled Payload Analysis
==================================

.. module:: pcapkit.foundation.analysis

:mod:`pcapkit.foundation.analysis` parses what a
:mod:`pcapkit.foundation.reassembly` engine reassembled into a usable result,
so that a caller does not interpret the raw reassembled octets itself
(:ref:`reassembly-integration`).

.. versionadded:: 1.6.0

"""
# Analysis of DTLS handshake messages
from pcapkit.foundation.analysis.dtls import dtls_handshake

__all__ = [
    'dtls_handshake',                       # DTLS Analysis
]
