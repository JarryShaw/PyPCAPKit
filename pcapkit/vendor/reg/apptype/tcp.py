# -*- coding: utf-8 -*-
"""Application Layer Protocol Numbers (TCP)
=============================================

.. module:: pcapkit.vendor.reg.apptype.tcp

This module contains the vendor crawler for **Application Layer Protocol Numbers (TCP)**,
which is automatically generating :class:`pcapkit.const.reg.apptype.tcp.TCP`.

"""

import sys

from pcapkit.vendor.reg.apptype.apptype import AppType

__all__ = ['TCP']


class TCP(AppType):
    """Application Layer Protocol Numbers (TCP)"""

    #: Transport protocol whose assignments this crawler renders.
    TRANSPORT = 'tcp'


if __name__ == '__main__':
    sys.exit(TCP())  # type: ignore[arg-type]
