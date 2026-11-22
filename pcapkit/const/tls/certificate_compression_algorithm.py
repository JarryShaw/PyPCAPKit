# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TLS Certificate Compression Algorithm IDs
===============================================

.. module:: pcapkit.const.tls.certificate_compression_algorithm

This module contains the constant enumeration for **TLS Certificate Compression Algorithm IDs**,
which is automatically generated from :class:`pcapkit.vendor.tls.certificate_compression_algorithm.CertificateCompressionAlgorithm`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['CertificateCompressionAlgorithm']


class CertificateCompressionAlgorithm(EnumRegistry, IntEnum):
    """[CertificateCompressionAlgorithm] TLS Certificate Compression Algorithm IDs"""

    #: Reserved [:rfc:`8879`]
    Reserved_0 = 0

    #: zlib [:rfc:`8879`]
    zlib = 1

    #: brotli [:rfc:`8879`]
    brotli = 2

    #: zstd [:rfc:`8879`]
    zstd = 3

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'CertificateCompressionAlgorithm':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 16383:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 16384 <= value <= 65535:
            #: Reserved for Experimental Use [:rfc:`8879`]
            return cls._unregistered_member(value, 'Reserved_for_Experimental_Use')
        return super()._missing_(value)
