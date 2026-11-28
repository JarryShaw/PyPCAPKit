# -*- coding: utf-8 -*-
"""constants for Ethernet frames

.. versionadded:: 1.9.0

"""

__all__ = ['LENGTH_MAX']

#: Largest value of the Length/Type field that is a length, the number of
#: octets of MAC client data, rather than an EtherType (:ieee:`802.3-2022`
#: §3.2.6). An EtherType is ``0x0600`` or more, and the values between are
#: neither.
LENGTH_MAX = 0x05DC
