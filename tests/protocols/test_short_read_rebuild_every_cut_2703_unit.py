# -*- coding: utf-8 -*-
"""A message cut at every octet that leaves a short read rebuilds quietly (#2703).

The sweep of :mod:`tests.protocols.test_short_read_rebuild_quiet_2703_unit`, whose
docstring gives the issue and the checks: each message there is cut at every octet
that leaves its header a short read rather than at its hand-picked cuts, built on its
octets or read from a PCAP savefile, and its rebuild must give the octets captured and
the checksum status read, and report nothing.

The octets and captures are built there; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import unittest

from tests.protocols.test_short_read_rebuild_quiet_2703_unit import ShortReadMixin

#: Test tier (#1958): a sweep that cuts each message at every offset, which the tier
#: rule puts on ``latest`` alone (#1732, #1958).
__tier__ = 'LATEST'


class EveryShortReadRebuildsQuietlyTests(ShortReadMixin, unittest.TestCase):
    """Each message cut at every octet that leaves a short read rebuilds as parsed."""

    sweep = True


if __name__ == '__main__':
    unittest.main()
