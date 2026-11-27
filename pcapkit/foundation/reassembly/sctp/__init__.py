# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""SCTP User-Message Reassembly
==================================

.. module:: pcapkit.foundation.reassembly.sctp

:mod:`pcapkit.foundation.reassembly.sctp` holds the SCTP user-message
reassembly class, :class:`~pcapkit.foundation.reassembly.sctp.reassembly.SCTP`,
in :mod:`~pcapkit.foundation.reassembly.sctp.reassembly`, and its data models in
:mod:`~pcapkit.foundation.reassembly.sctp.data`.

Its data classes are importable as ``Data_*``.

.. versionadded:: 1.9.0

"""
from pcapkit.foundation.reassembly.sctp.reassembly import SCTP

# Data Models
from pcapkit.foundation.reassembly.sctp.data import Buffer as Data_Buffer
from pcapkit.foundation.reassembly.sctp.data import Datagram as Data_Datagram
from pcapkit.foundation.reassembly.sctp.data import DatagramID as Data_DatagramID
from pcapkit.foundation.reassembly.sctp.data import Fragment as Data_Fragment
from pcapkit.foundation.reassembly.sctp.data import Packet as Data_Packet

__all__ = ['SCTP']
