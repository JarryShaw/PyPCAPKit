# -*- coding: utf-8 -*-
"""HIP ESP Transform Suite IDs"""

from pcapkit.vendor.default import Vendor

__all__ = ['ESP_TransformSuite']


class ESP_TransformSuite(Vendor):
    """ESP Transform Suite IDs"""

    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    LINK = 'https://www.iana.org/assignments/hip-parameters/esp-transform-suite-ids.csv'


if __name__ == "__main__":
    ESP_TransformSuite()
