"""Unit tests for :mod:`pcapkit.toolkit.pcap_ct`.

`pcap-ct`_ hands back raw bytes, so this toolkit's only working functions are
its auxiliary ones; the reassembly and flow tracing adapters exist purely to refuse
loudly, and that refusal is asserted here so it cannot regress into a silent
:data:`None`. The cases are shared with :mod:`tests.toolkit.test_pypcap_unit`
through :mod:`tests.foundation.engines._libpcap_engine`.

Nothing below imports :mod:`pcap`: the module under test is a pure adapter over
the ``(timestamp, bytes)`` pair, so it is testable with no backend installed at
all -- which is also the point of asserting the refusals here rather than only in
an end-to-end test that skips without one.

.. _pcap-ct: https://pypi.org/project/pcap-ct/

"""
from __future__ import annotations

import unittest

from tests.foundation.engines._libpcap_engine import HAS_RUNTIME, LibpcapToolkitMixin

#: Test tier (#1958): drives a third-party engine whose installable releases vary by
#: interpreter.
__tier__ = 'ALL'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAP_CTToolkitTests(LibpcapToolkitMixin, unittest.TestCase):
    MODULE = 'pcapkit.toolkit.pcap_ct'
    ENGINE = 'PCAP_CT'
    DIST = 'pcap-ct'


if __name__ == '__main__':
    unittest.main()
