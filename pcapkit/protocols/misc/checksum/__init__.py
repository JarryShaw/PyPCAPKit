# -*- coding: utf-8 -*-
"""Checksum Pseudo-Headers
=============================

.. module:: pcapkit.protocols.misc.checksum

:mod:`pcapkit.protocols.misc.checksum` contains the pseudo-header that
upper-layer checksums cover,
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`. The checksum
itself is in :mod:`pcapkit.corekit.checksum`.

"""
from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo

__all__ = ['IP_Pseudo']
