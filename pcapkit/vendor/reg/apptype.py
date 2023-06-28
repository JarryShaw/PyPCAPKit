# -*- coding: utf-8 -*-
"""Application Layer Protocol Numbers
========================================

.. module:: pcapkit.vendor.reg.apptype

This module contains the vendor crawler for **Application Layer Protocol Numbers**,
which is automatically generating :class:`pcapkit.const.reg.apptype.AppType`.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter


__all__ = ['AppType']


class AppType(Vendor):
    """Application Layer Protocol Numbers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'
