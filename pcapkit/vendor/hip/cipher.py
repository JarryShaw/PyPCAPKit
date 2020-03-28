# -*- coding: utf-8 -*-
"""HIP Cipher IDs"""

from pcapkit.vendor.default import Vendor

__all__ = ['Cipher']


class Cipher(Vendor):
    """Cipher IDs"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/hip-parameters/hip-cipher-id.csv'


if __name__ == "__main__":
    Cipher()
