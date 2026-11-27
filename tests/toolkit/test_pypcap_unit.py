"""Unit tests for :mod:`pcapkit.toolkit.pypcap`.

`pypcap`_ hands back raw bytes, so this toolkit's only working functions are
its auxiliary ones; the reassembly and flow tracing adapters exist purely to refuse
loudly, and that refusal is asserted here so it cannot regress into a silent
:data:`None`. The cases are shared with :mod:`tests.toolkit.test_pcap_ct_unit`
through :mod:`tests.foundation.engines._libpcap_engine`.

.. _pypcap: https://pypi.org/project/pypcap/

"""
from __future__ import annotations

import unittest

from tests.foundation.engines._libpcap_engine import HAS_RUNTIME, LibpcapToolkitMixin

#: Test tier (#1958): drives a third-party engine whose installable releases vary by
#: interpreter.
__tier__ = 'ALL'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPToolkitTests(LibpcapToolkitMixin, unittest.TestCase):
    MODULE = 'pcapkit.toolkit.pypcap'
    ENGINE = 'PyPCAP'
    DIST = 'pypcap'


if __name__ == '__main__':
    unittest.main()
