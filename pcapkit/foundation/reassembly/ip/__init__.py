# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IP Datagram Reassembly
============================

.. module:: pcapkit.foundation.reassembly.ip

:mod:`pcapkit.foundation.reassembly.ip` holds the reassembly base for IP,
:class:`~pcapkit.foundation.reassembly.ip.reassembly.IP`, in
:mod:`~pcapkit.foundation.reassembly.ip.reassembly`, and the data models it
shares with IPv4 and IPv6 reassembly in
:mod:`~pcapkit.foundation.reassembly.ip.data`.

Its data classes are importable as ``Data_*``.

.. versionremoved:: 1.7.0

   ``pcapkit.foundation.reassembly.ip.logger``, with no alias: it is in
   :mod:`~pcapkit.foundation.reassembly.ip.reassembly`, and
   :mod:`pcapkit.foundation.reassembly.ip` exports the reassembly class alone
   (:issue:`2882`).

"""
from pcapkit.foundation.reassembly.ip.reassembly import IP

# Data Models
from pcapkit.foundation.reassembly.ip.data import Buffer as Data_Buffer
from pcapkit.foundation.reassembly.ip.data import Datagram as Data_Datagram
from pcapkit.foundation.reassembly.ip.data import DatagramID as Data_DatagramID
from pcapkit.foundation.reassembly.ip.data import Packet as Data_Packet

__all__ = ['IP']
