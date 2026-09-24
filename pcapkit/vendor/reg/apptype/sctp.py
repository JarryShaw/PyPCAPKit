# -*- coding: utf-8 -*-
"""Application Layer Protocol Numbers (SCTP)
==============================================

.. module:: pcapkit.vendor.reg.apptype.sctp

This module contains the vendor crawler for **Application Layer Protocol Numbers (SCTP)**,
which is automatically generating :class:`pcapkit.const.reg.apptype.sctp.SCTP`.

"""

import sys

from pcapkit.vendor.reg.apptype.apptype import AppType

__all__ = ['SCTP']


class SCTP(AppType):
    """Application Layer Protocol Numbers (SCTP)"""

    #: Transport protocol whose assignments this crawler renders.
    TRANSPORT = 'sctp'


if __name__ == '__main__':
    sys.exit(SCTP())  # type: ignore[arg-type]
