# -*- coding: utf-8 -*-
"""constants for ICMPv6 protocol

.. versionadded:: 1.9.0

"""

__all__ = ['PREF64_PREFIX_LENGTH']

#: NAT64 prefix length, in bits, by the PREF64 option's Prefix Length Code
#: (:rfc:`8781#section-4`).
PREF64_PREFIX_LENGTH = {
    0: 96,
    1: 64,
    2: 56,
    3: 48,
    4: 40,
    5: 32,
}
