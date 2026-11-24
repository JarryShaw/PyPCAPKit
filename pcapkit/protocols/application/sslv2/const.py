# -*- coding: utf-8 -*-
"""constants for SSLv2 protocol

.. versionadded:: 1.7.0

"""

__all__ = []  # type: list[str]

#: Octets of a hello body's own fixed-width sub-header a forward-match probe
#: ever needs to peek -- enough for the longer of the two,
#: ``SERVER-HELLO``'s 10-octet one (``CLIENT-HELLO``'s is 8).
_HELLO_PROBE_LENGTH = 10
