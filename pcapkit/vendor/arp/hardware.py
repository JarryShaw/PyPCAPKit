# -*- coding: utf-8 -*-
"""Hardware Types
====================

.. module:: pcapkit.vendor.arp.hardware

This module contains the vendor crawler for **Hardware Types**,
which is automatically generating :class:`pcapkit.const.arp.hardware.Hardware`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['Hardware']


class Hardware(Vendor):
    """Hardware Types [:rfc:`826`][:rfc:`5494`]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/arp-parameters/arp-parameters-2.csv'


if __name__ == '__main__':
    sys.exit(Hardware())  # type: ignore[arg-type]
