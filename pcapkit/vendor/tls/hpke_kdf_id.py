# -*- coding: utf-8 -*-
"""HPKE KDF Identifiers
==========================

.. module:: pcapkit.vendor.tls.hpke_kdf_id

This module contains the vendor crawler for **HPKE KDF Identifiers**,
which is automatically generating :class:`pcapkit.const.tls.hpke_kdf_id.HpkeKdfId`.

The registry is IANA's ``HPKE KDF Identifiers`` table, a five-column CSV --
``Value, KDF, Nh, Two-Stage, Reference``. Its rows are the ``kdf_id`` of an
``encrypted_client_hello`` ``HpkeSymmetricCipherSuite`` (:rfc:`9849#section-4`,
:rfc:`9180#section-7.2`); see :mod:`pcapkit.vendor.tls.hpke_kem_id` for how a
row becomes a member.

"""

import sys

from pcapkit.vendor.tls.hpke_kem_id import HpkeKemId

__all__ = ['HpkeKdfId']


class HpkeKdfId(HpkeKemId):
    """HPKE KDF Identifiers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hpke/hpke-kdf-ids.csv'

    #: Column of the ``Reference`` cell.
    REFERENCE = 4


if __name__ == '__main__':
    sys.exit(HpkeKdfId())  # type: ignore[arg-type]
