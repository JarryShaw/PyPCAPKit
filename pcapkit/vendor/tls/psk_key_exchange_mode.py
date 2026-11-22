# -*- coding: utf-8 -*-
"""TLS PskKeyExchangeMode Values
===================================

.. module:: pcapkit.vendor.tls.psk_key_exchange_mode

This module contains the vendor crawler for **TLS PskKeyExchangeMode Values**,
which is automatically generating
:class:`pcapkit.const.tls.psk_key_exchange_mode.PskKeyExchangeMode`.

The registry is IANA's ``TLS PskKeyExchangeMode`` table, a five-column CSV --
``Value, Description, Recommended, Reference, Comment``. Its rows are the values a
``psk_key_exchange_modes`` extension lists (:rfc:`9846#section-4.3.9`); see
:mod:`pcapkit.vendor.tls.ec_point_format` for how a row becomes a member.

"""

import sys

from pcapkit.vendor.tls.ec_point_format import ECPointFormat

__all__ = ['PskKeyExchangeMode']


class PskKeyExchangeMode(ECPointFormat):
    """TLS PskKeyExchangeMode Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tls-parameters/tls-pskkeyexchangemode.csv'

    #: Column of the ``Reference`` cell.
    REFERENCE = 3
    #: Column of the ``Comment`` cell.
    COMMENT = 4


if __name__ == '__main__':
    sys.exit(PskKeyExchangeMode())  # type: ignore[arg-type]
