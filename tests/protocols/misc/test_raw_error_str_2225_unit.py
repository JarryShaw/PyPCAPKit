# -*- coding: utf-8 -*-
"""``Raw``'s ``error`` is the message string it holds. C.f. #2225.

``Data_Raw.error`` and ``Raw.read``'s ``error`` were annotated
``Optional[Exception]``, but every producer passes a :obj:`str`:
:func:`~pcapkit.corekit.decorators.beholder` passes the message of the error a
parse raised, and the frame layer limit passes the message saying so.

Each case pins both the runtime type on one of those paths and the annotation.
Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import ast
import inspect
import unittest
import unittest.mock
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): pins annotations and a parse fall-back, which do not
#: differ by interpreter.
__tier__ = 'LATEST'

#: An Ethernet frame whose IPv4 header is too short to parse.
MALFORMED = bytes(12) + b'\x08\x00' + b'\x60' + bytes(30)


class TestRawErrorStr(unittest.TestCase):
    """Pin that ``Raw.info.error`` is a :obj:`str`, as annotated."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_failure_error_is_str(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw = Ethernet(MALFORMED).payload
        self.assertIsInstance(raw, Raw)
        self.assertIsInstance(raw.info.error, str)

    def test_layer_limit_error_is_str(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities import config

        # Ethernet, then IPv4 carrying one octet of TCP: TCP is the second
        # layer after Ethernet, so past a limit of one.
        frame = bytes(12) + b'\x08\x00' + bytes.fromhex('45000015000000004006000000000000' '00000000' '00')
        with unittest.mock.patch.object(config, 'FRAME_LAYER_LIMIT', 1), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw = Ethernet(frame).payload.payload
        self.assertIsInstance(raw, Raw)
        self.assertTrue(raw._past_layer_limit)
        self.assertIsInstance(raw.info.error, str)

    def test_annotations_say_str(self) -> None:
        from pcapkit.protocols.data.misc import raw as data_raw
        from pcapkit.protocols.misc.raw import Raw

        self.assertEqual(data_raw.Raw.__annotations__['error'], 'Optional[str]')
        self.assertEqual(Raw.read.__annotations__['error'], 'Optional[str]')

        # The constructor signature exists only under TYPE_CHECKING, so read it
        # from the source.
        tree = ast.parse(inspect.getsource(data_raw))
        stubs = [node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef) and node.name == '__init__']
        self.assertEqual(len(stubs), 1)
        error = next(arg for arg in stubs[0].args.args if arg.arg == 'error')
        self.assertEqual(ast.literal_eval(error.annotation), 'Optional[str]')


if __name__ == '__main__':
    unittest.main()
