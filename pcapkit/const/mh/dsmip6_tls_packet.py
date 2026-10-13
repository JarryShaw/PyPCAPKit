# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DSMIP6-TLS Packet Types Registry
======================================

.. module:: pcapkit.const.mh.dsmip6_tls_packet

This module contains the constant enumeration for **DSMIP6-TLS Packet Types Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.dsmip6_tls_packet.DSMIP6TLSPacket`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['DSMIP6TLSPacket']


class DSMIP6TLSPacket(EnumRegistry, IntEnum):
    """[DSMIP6TLSPacket] DSMIP6-TLS Packet Types Registry"""

    #: non-encrypted IP packet [:rfc:`6618`]
    non_encrypted_IP_packet = 0

    #: encrypted IP packet [:rfc:`6618`]
    encrypted_IP_packet = 1

    #: mobility header [:rfc:`6618`]
    mobility_header = 8

    @classmethod
    def _missing_(cls, value: 'int') -> 'DSMIP6TLSPacket':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 7:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 9 <= value <= 15:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
