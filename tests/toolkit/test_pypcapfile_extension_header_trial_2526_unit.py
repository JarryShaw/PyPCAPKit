# -*- coding: utf-8 -*-
"""GitHub issue #2526: pypcapfile's extension-header trial warns nothing when it raises.

:func:`~pcapkit.toolkit.pypcapfile._default_extension_header` reads a header
inside IPv4 with
:meth:`~pcapkit.protocols.protocol.ProtocolBase._parse_next_layer`, and answers
:data:`None` when that raises, as :func:`~pcapkit.corekit.decorators.beholder`
replaces such a layer. The #2308 rule applies: the trial's warnings describe a
header nothing keeps, so they go with it. Outside ``beholder`` they are reported
as the error leaves, so a HIP header cut to 8 octets warns ``packet length < 0``
twice before the answer. A header the trial keeps warns from the caller's line.

The answers are cached by octets, so each test clears the cache before it asks.
:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import inspect
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): exercises the warning machinery, which free-threaded
#: builds make context-aware.
__tier__ = 'ALL'

#: IP protocol numbers of HIP and the Mobility Header.
HIP, MOBILITY_HEADER = 139, 135
#: The first 8 octets of a HIP header, whose fixed part is 40.
HIP_CUT = bytes.fromhex('b0ff89ff0042ff1c')
#: A Mobility Header of 8 octets, 16 short of the Binding Error message it
#: carries, then 1 octet of its UDP payload.
MH_BINDING_ERROR = bytes.fromhex('11000742d5bd297b99')
#: The warning the Mobility Header's message reports.
MH_WARNING = 'packet length < 0: -16'


class TestExtensionHeaderTrial(unittest.TestCase):
    """Pin that a raising extension-header trial reports nothing, and a kept one does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _ask(self, protocol: 'int', data: 'bytes',
             action: 'str' = 'always') -> 'tuple[object, list[warnings.WarningMessage]]':
        """Ask the uncached reader about ``data``, with the warnings it reports.

        The trial must leave ``beholder``'s flag unset, whatever it answers.

        """
        from pcapkit.toolkit.pypcapfile import _default_extension_header
        from pcapkit.utilities.contextvars import beholding

        _default_extension_header.cache_clear()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter(action)
            answer = _default_extension_header(protocol, data)
        self.assertFalse(beholding.get())
        return answer, caught

    def test_raising_trial_warns_nothing(self) -> None:
        """The cut HIP header raises, answers ``None``, and reports nothing on either channel."""
        from pcapkit.utilities.logging import logger

        with capture(logger) as recorder:
            answer, caught = self._ask(HIP, HIP_CUT)
        self.assertIsNone(answer)
        self.assertEqual([str(item.message) for item in caught], [])
        self.assertEqual([record.getMessage() for record in recorder.records
                          if record.getMessage().startswith('packet length')], [])

    def test_error_filter_answers_none(self) -> None:
        """Control: under ``error``, the cut HIP header answers ``None`` and reports nothing."""
        answer, caught = self._ask(HIP, HIP_CUT, 'error')
        self.assertIsNone(answer)
        self.assertEqual(caught, [])

    def test_kept_header_warns_from_the_callers_line(self) -> None:
        """Control: a Mobility Header the trial keeps reports its message's warning."""
        from pcapkit.toolkit.pypcapfile import _default_extension_header
        from pcapkit.utilities.warnings import SchemaWarning

        _default_extension_header.cache_clear()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            line = inspect.currentframe().f_lineno + 1  # type: ignore[union-attr]
            answer = _default_extension_header(MOBILITY_HEADER, MH_BINDING_ERROR)
        self.assertEqual(answer, (17, 8))
        self.assertEqual([(item.category, str(item.message), item.filename, item.lineno) for item in caught],
                         [(SchemaWarning, MH_WARNING, __file__, line)])


if __name__ == '__main__':
    unittest.main()
