# -*- coding: utf-8 -*-
"""HPKE AEAD Identifiers
===========================

.. module:: pcapkit.vendor.tls.hpke_aead_id

This module contains the vendor crawler for **HPKE AEAD Identifiers**,
which is automatically generating :class:`pcapkit.const.tls.hpke_aead_id.HpkeAeadId`.

The registry is IANA's ``HPKE AEAD Identifiers`` table, a six-column CSV --
``Value, AEAD, Nk, Nn, Nt, Reference``. Its rows are the ``aead_id`` of an
``encrypted_client_hello`` ``HpkeSymmetricCipherSuite`` (:rfc:`9849#section-4`,
:rfc:`9180#section-7.3`); see :mod:`pcapkit.vendor.tls.hpke_kem_id` for how a
row becomes a member.

"""

import sys

from pcapkit.vendor.tls.hpke_kem_id import HpkeKemId

__all__ = ['HpkeAeadId']


class HpkeAeadId(HpkeKemId):
    """HPKE AEAD Identifiers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hpke/hpke-aead-ids.csv'

    #: Column of the ``Reference`` cell.
    REFERENCE = 5


if __name__ == '__main__':
    sys.exit(HpkeAeadId())  # type: ignore[arg-type]
