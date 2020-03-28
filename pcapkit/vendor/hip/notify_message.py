# -*- coding: utf-8 -*-
"""HIP Notify Message Types"""

from pcapkit.vendor.default import Vendor

__all__ = ['NotifyMessage']


class NotifyMessage(Vendor):
    """Notify Message Types"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-parameters-9.csv'


if __name__ == "__main__":
    NotifyMessage()
