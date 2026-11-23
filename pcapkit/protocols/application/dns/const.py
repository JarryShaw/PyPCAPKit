# -*- coding: utf-8 -*-
"""constants for DNS protocol

.. versionadded:: 1.7.0

"""

__all__ = ['HEADER_LENGTH', 'POINTER_LIMIT']

#: Length of the fixed header, before the sections (:rfc:`1035#section-4.1.1`).
HEADER_LENGTH = 12

#: Largest offset a compression pointer can carry, in its 14 bits.
POINTER_LIMIT = 0x3FFF
