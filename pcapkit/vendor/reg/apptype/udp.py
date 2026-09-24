# -*- coding: utf-8 -*-
"""Application Layer Protocol Numbers (UDP)
=============================================

.. module:: pcapkit.vendor.reg.apptype.udp

This module contains the vendor crawler for **Application Layer Protocol Numbers (UDP)**,
which is automatically generating :class:`pcapkit.const.reg.apptype.udp.UDP`.

"""

import sys

from pcapkit.vendor.reg.apptype.apptype import AppType

__all__ = ['UDP']


class UDP(AppType):
    """Application Layer Protocol Numbers (UDP)"""

    #: Transport protocol whose assignments this crawler renders.
    TRANSPORT = 'udp'


if __name__ == '__main__':
    sys.exit(UDP())  # type: ignore[arg-type]
