# -*- coding: utf-8 -*-
"""HIP NAT Traversal Modes"""

from pcapkit.vendor.default import Vendor

__all__ = ['NAT_Traversal']


class NAT_Traversal(Vendor):
    """HIP NAT Traversal Modes"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/hip-parameters/nat-traversal.csv'


if __name__ == "__main__":
    NAT_Traversal()
