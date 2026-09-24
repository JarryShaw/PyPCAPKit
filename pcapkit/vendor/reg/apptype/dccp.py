# -*- coding: utf-8 -*-
"""Application Layer Protocol Numbers (DCCP)
==============================================

.. module:: pcapkit.vendor.reg.apptype.dccp

This module contains the vendor crawler for **Application Layer Protocol Numbers (DCCP)**,
which is automatically generating :class:`pcapkit.const.reg.apptype.dccp.DCCP`.

"""

import sys

from pcapkit.vendor.reg.apptype.apptype import AppType

__all__ = ['DCCP']


class DCCP(AppType):
    """Application Layer Protocol Numbers (DCCP)"""

    #: Transport protocol whose assignments this crawler renders.
    TRANSPORT = 'dccp'


if __name__ == '__main__':
    sys.exit(DCCP())  # type: ignore[arg-type]
