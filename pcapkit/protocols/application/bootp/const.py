# -*- coding: utf-8 -*-
"""constants for BOOTP

.. versionadded:: 1.10.0

"""

__all__ = ['VENDOR_EXTENSIONS']

#: Codes of the vendor extensions a BOOTP message carries, which its option
#: parsers decode: those of :rfc:`2132` sections 3 to 8, the :rfc:`1497`
#: extensions and their successors. Section 9 and every later option are DHCP's.
VENDOR_EXTENSIONS = frozenset(range(0, 50)) | frozenset((64, 65)) | frozenset(range(68, 77)) | frozenset((255,))
