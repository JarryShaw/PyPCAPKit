# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""TLS Record Reassembly
===========================

.. module:: pcapkit.foundation.reassembly.tls

:mod:`pcapkit.foundation.reassembly.tls` holds the TLS record reassembly class,
:class:`~pcapkit.foundation.reassembly.tls.reassembly.TLS`, in
:mod:`~pcapkit.foundation.reassembly.tls.reassembly`, and its data models in
:mod:`~pcapkit.foundation.reassembly.tls.data`.

Its data classes are importable as ``Data_*``.

.. versionadded:: 1.9.0

"""
from pcapkit.foundation.reassembly.tls.reassembly import TLS

# Data Models
from pcapkit.foundation.reassembly.tls.data import Buffer as Data_Buffer
from pcapkit.foundation.reassembly.tls.data import Datagram as Data_Datagram
from pcapkit.foundation.reassembly.tls.data import DatagramID as Data_DatagramID
from pcapkit.foundation.reassembly.tls.data import Run as Data_Run

__all__ = ['TLS']
