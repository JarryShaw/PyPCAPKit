# -*- coding: utf-8 -*-
"""HIP NAT Traversal Modes"""

from pcapkit.vendor.default import Vendor

__all__ = ['NATTraversal']


class NATTraversal(Vendor):
    """HIP NAT Traversal Modes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hip-parameters/nat-traversal.csv'


if __name__ == "__main__":
    NATTraversal()
