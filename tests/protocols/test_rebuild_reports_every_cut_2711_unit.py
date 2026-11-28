# -*- coding: utf-8 -*-
"""A frame cut at every offset rebuilds within its parse (#2711).

The sweep of :mod:`tests.protocols.test_rebuild_reports_once_2711_unit`, whose
docstring gives the issue and the checks: each frame there is cut at every offset
rather than at its hand-picked cuts, read from its octets and from a PCAP savefile,
and every layer rebuilt must give the octets parsed and report nothing beyond what
the parse reported, with the default zero-fill ceiling and with one low enough that
the Report's in-frame parse raises.

The octets and captures are built there; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import unittest

from tests.protocols.test_rebuild_reports_once_2711_unit import CutFrameMixin

#: Test tier (#1958): a sweep that cuts each frame at every offset, which the tier
#: rule puts on ``latest`` alone (#1732, #1958).
__tier__ = 'LATEST'


class EveryCutRebuildsWithinItsParseTests(CutFrameMixin, unittest.TestCase):
    """Each frame cut at every offset rebuilds within its parse."""

    sweep = True


if __name__ == '__main__':
    unittest.main()
