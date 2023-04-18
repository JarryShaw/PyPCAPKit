# -*- coding: utf-8 -*-
"""Notify Message Types
==========================

.. module:: pcapkit.const.hip.notify_message

This module contains the vendor crawler for **Notify Message Types**,
which is automatically generating :class:`pcapkit.const.hip.notify_message.NotifyMessage`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['NotifyMessage']


class NotifyMessage(Vendor):
    """Notify Message Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-9.csv'


if __name__ == '__main__':
    sys.exit(NotifyMessage())  # type: ignore[arg-type]
