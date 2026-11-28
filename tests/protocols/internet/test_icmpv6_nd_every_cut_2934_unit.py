# -*- coding: utf-8 -*-
"""Each Neighbor Discovery message cut at every octet rebuilds byte for byte (#2934).

The sweep of :mod:`tests.protocols.internet.test_icmpv6_nd_2934_unit`, whose
docstring gives the issue and the checks: each message there is cut at every octet
rather than at its hand-picked cuts, behind an IPv6 header declaring the whole
message and on its own, and must parse into its data model and rebuild the octets
captured.

The messages are built there; this module is unit-tier and reads no capture.

"""

import unittest

from tests.protocols.internet.test_icmpv6_nd_2934_unit import NDCutMixin

#: Test tier (#1958): a sweep that cuts each message at every offset, which the tier
#: rule puts on ``latest`` alone (#1732, #1958).
__tier__ = 'LATEST'


class EveryNDCutRebuildsTests(NDCutMixin, unittest.TestCase):
    """Each message cut at every octet rebuilds byte for byte."""

    sweep = True


if __name__ == '__main__':
    unittest.main()
