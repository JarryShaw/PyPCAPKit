# -*- coding: utf-8 -*-
"""Every tunable limit has one home, :mod:`pcapkit.utilities.config`.

Guards against the limits being spread across packages, with readers such as
:mod:`pcapkit.protocols.internet.ipv6` and :mod:`pcapkit.toolkit.pypcapfile`
copying them with ``from ... import``, so that patching the defining module leaves
those readers on a stale value (#1726). Each is a ``PCAPKIT_*`` environment
variable read once by :mod:`pcapkit.utilities.config`, every reader looks it up
there at call time, and no other module re-exports it (#1715). A bad value
warns and falls back to the default; ``-1`` lifts a limit, and that or any
value above the default warns of the risk. The :mod:`pcapkit.vendor` crawlers'
variables are not held here: ``tests/vendor/test_vendor_variables_1726_unit.py``
covers them.

"""

import ast
import contextlib
import importlib
import io
import os
import pathlib
import struct
import subprocess  # nosec: B404
import sys
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): exercises integer, bytes and struct edge cases, whose limits
#: differ by interpreter.
__tier__ = 'ALL'

#: Root of the :mod:`pcapkit` package under test.
PACKAGE = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit'

#: Little-endian PCAP global header: v2.4, snaplen 65535, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')

#: Every name that moved, by its old home.
MOVED = {
    'pcapkit.protocols.protocol': ['FRAME_LAYER_LIMIT'],
    'pcapkit.protocols.internet.internet': ['EXTENSION_HEADER_LIMIT'],
    'pcapkit.protocols.internet.ipv6': ['FRAME_LAYER_LIMIT', 'EXTENSION_HEADER_LIMIT'],
    'pcapkit.toolkit.pypcapfile': ['EXTENSION_HEADER_LIMIT'],
    'pcapkit.dumpkit.common': ['FALLBACK_LIMIT'],
    'pcapkit.utilities.chardet': ['DETECT_CACHE_SIZE'],
    'pcapkit.corekit.io': ['_READ_CHUNK'],
    'pcapkit.corekit.fields.field': ['_MAX_ZERO_PAD_LENGTH', '_MAX_ZERO_PAD_SHORTFALL',
                                     '_ZERO_PAD_BUDGET_RATIO'],
}

#: The :mod:`pcapkit.vendor` crawlers' own variables, which
#: :mod:`pcapkit.utilities.config` does not hold (#1726).
VENDOR_NAMES = ('VENDOR_RETRY', 'CI_MODE', 'http_proxy', 'https_proxy')

#: The public readers of :mod:`pcapkit.utilities.config`, which are not variables.
READERS = frozenset({'read_limit', 'read_flag'})

#: Every variable :mod:`pcapkit.utilities.config` declares, as
#: ``(name, default, minimum, a phrase of its risk)``. Written out rather than
#: read back, so that a changed name, default, minimum or risk fails.
DECLARED = (
    ('FRAME_LAYER_LIMIT', 64, 0, 'RecursionError (#1610)'),
    ('EXTENSION_HEADER_LIMIT', 32, 0, 'RecursionError (#1610)'),
    ('IPV6_TCP_WARNED_LIMIT', 32, 0, 'pins one of its packets in memory'),
    ('FALLBACK_LIMIT', 10_000, 0, 'a large or endless object graph'),
    ('DETECT_CACHE_SIZE', 1024, 0, 'never-repeating text'),
    ('READ_CHUNK', 1_048_576, 1, 'a bogus record length allocates'),
    ('MAX_ZERO_PAD_LENGTH', 262_144, 0, 'declare a field that long'),
    ('MAX_ZERO_PAD_SHORTFALL', 65_536, 0, 'without being charged to the running budget'),
    ('ZERO_PAD_BUDGET_RATIO', 16, 0, 'amplify each octet read'),
)


def options(nxt: int) -> bytes:
    """An 8-octet Destination Options header: Hdr Ext Len 0 and one PadN."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, 0])


def chain(count: int) -> bytes:
    """``count`` Destination Options headers, then a TCP segment."""
    return b''.join(options(60 if index < count - 1 else 6) for index in range(count)) + wire.tcp(b'x', seq=1)


@contextlib.contextmanager
def environ(**values: str) -> 'Iterator[None]':
    """Set ``PCAPKIT_<name>`` for each of ``values``, and no other."""
    with mock.patch.dict(os.environ, {f'PCAPKIT_{name}': value for name, value in values.items()}):
        yield


class ReadingTests(unittest.TestCase):
    """How a variable's text becomes its value."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ConfigWarning

        self.config = config
        self.ConfigWarning = ConfigWarning

    def read(self, text: 'str | None', default: int = 64, **kwargs: object) -> 'tuple[int, list[str]]':
        """The value of ``PCAPKIT_TEST`` set to ``text``, and what it warned."""
        values = {} if text is None else {'TEST': text}
        with environ(**values), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            value = self.config.read_limit('TEST', default, **kwargs)
        self.assertTrue(all(issubclass(item.category, self.ConfigWarning) for item in caught), caught)
        return value, [str(item.message) for item in caught]

    def test_unset_or_within_the_default_is_taken_silently(self) -> None:
        self.assertEqual(self.read(None, risk='r'), (64, []))
        self.assertEqual(self.read('8', risk='r'), (8, []))
        self.assertEqual(self.read('0', risk='r'), (0, []))
        self.assertEqual(self.read('64', risk='r'), (64, []))

    def test_a_bad_value_warns_and_falls_back(self) -> None:
        for text in ('', 'abc', '6.4', '0x40', '-2'):
            with self.subTest(text=text):
                value, messages = self.read(text, risk='r')
                self.assertEqual(value, 64)
                self.assertEqual(len(messages), 1)
                self.assertIn('using the default, 64', messages[0])

    def test_minus_one_and_above_the_default_warn_of_the_risk(self) -> None:
        for text, expected in (('-1', -1), ('65', 65), ('1000', 1000)):
            with self.subTest(text=text):
                value, messages = self.read(text, risk='RecursionError (#1610)')
                self.assertEqual(value, expected)
                self.assertEqual(len(messages), 1)
                self.assertIn('RecursionError', messages[0])

    def test_every_message_names_the_variable_and_the_value(self) -> None:
        for text in ('abc', '-2', '-1', '65'):
            with self.subTest(text=text):
                _, messages = self.read(text, risk='r')
                self.assertEqual(len(messages), 1)
                self.assertIn(f'PCAPKIT_TEST={text!r}', messages[0])

    def test_the_readers_are_public(self) -> None:
        self.assertLessEqual(READERS, set(self.config.__all__))
        for name in READERS:
            with self.subTest(name=name):
                self.assertFalse(hasattr(self.config, f'_{name}'))

    def test_without_a_risk_minus_one_is_refused(self) -> None:
        value, messages = self.read('-1', default=5, minimum=1)
        self.assertEqual((value, len(messages)), (5, 1))
        self.assertEqual(self.read('50', default=5, minimum=1), (50, []))

    def test_a_flag(self) -> None:
        with environ(TEST='Yes'):
            self.assertIs(self.config.read_flag('TEST'), True)
        with environ(TEST='maybe'), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertIs(self.config.read_flag('TEST'), False)
        self.assertEqual([item.category for item in caught], [self.ConfigWarning])

    def test_both_flag_readers_strip_whitespace(self) -> None:
        from pcapkit.utilities import logging

        bad = list(logging._BAD_FLAGS)  # pylint: disable=protected-access
        for text, expected in ((' yes ', True), ('\tOff\n', False)):
            with self.subTest(text=text), environ(TEST=text), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                self.assertIs(self.config.read_flag('TEST'), expected)
                self.assertIs(logging._read_flag('PCAPKIT_TEST'), expected)  # pylint: disable=protected-access
            self.assertEqual(caught, [])
            self.assertEqual(logging._BAD_FLAGS, bad)  # pylint: disable=protected-access

    def test_the_frame_layer_limit_names_the_recursion_risk(self) -> None:
        with environ(FRAME_LAYER_LIMIT='-1'), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            try:
                importlib.reload(self.config)
                self.assertEqual(self.config.FRAME_LAYER_LIMIT, -1)
            finally:
                os.environ.pop('PCAPKIT_FRAME_LAYER_LIMIT')
                importlib.reload(self.config)
        messages = [str(item.message) for item in caught if issubclass(item.category, self.ConfigWarning)]
        self.assertEqual(len(messages), 1, messages)
        self.assertIn('PCAPKIT_FRAME_LAYER_LIMIT', messages[0])
        self.assertIn('RecursionError', messages[0])
        self.assertEqual(self.config.FRAME_LAYER_LIMIT, 64)

    def test_a_bad_value_does_not_break_the_import(self) -> None:
        with environ(READ_CHUNK='lots', FALLBACK_LIMIT='-7'), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            try:
                importlib.reload(self.config)
                self.assertEqual((self.config.READ_CHUNK, self.config.FALLBACK_LIMIT), (1 << 20, 10_000))
            finally:
                os.environ.pop('PCAPKIT_READ_CHUNK')
                os.environ.pop('PCAPKIT_FALLBACK_LIMIT')
                importlib.reload(self.config)
        self.assertEqual(len([item for item in caught if issubclass(item.category, self.ConfigWarning)]), 2)


class DeclarationTests(unittest.TestCase):
    """Each variable's name, default, minimum and risk, as :data:`DECLARED` writes them."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ConfigWarning

        self.config = config
        self.ConfigWarning = ConfigWarning

    def load(self, name: str, text: 'str | None') -> 'tuple[object, list[str]]':
        """``config.<name>`` with only ``PCAPKIT_<name>`` set, to ``text``, and the ConfigWarnings given."""
        env = {key: value for key, value in os.environ.items() if not key.startswith('PCAPKIT_')}
        if text is not None:
            env[f'PCAPKIT_{name}'] = text
        try:
            with mock.patch.dict(os.environ, env, clear=True), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                importlib.reload(self.config)
            return getattr(self.config, name), [str(item.message) for item in caught
                                                if issubclass(item.category, self.ConfigWarning)]
        finally:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                importlib.reload(self.config)

    def test_the_table_names_every_variable(self) -> None:
        names = {row[0] for row in DECLARED}
        self.assertEqual(names, set(self.config.__all__) - READERS)

    def test_each_variable_is_read_by_its_own_name(self) -> None:
        for name, default, _, _ in DECLARED:
            with self.subTest(name=name):
                self.assertEqual(self.load(name, str(default - 1)), (default - 1, []))

    def test_each_default(self) -> None:
        for name, default, _, _ in DECLARED:
            with self.subTest(name=name):
                self.assertEqual(self.load(name, None), (default, []))

    def test_below_the_minimum_falls_back(self) -> None:
        for name, default, minimum, _ in DECLARED:
            # -1 means no limit, so the first value refused is -2.
            below = -2 if minimum == 0 else minimum - 1
            with self.subTest(name=name):
                self.assertEqual(self.load(name, str(minimum)), (minimum, []))
                value, messages = self.load(name, str(below))
                self.assertEqual((value, len(messages)), (default, 1), messages)
                self.assertIn(f"PCAPKIT_{name}='{below}' is not an integer of at least {minimum}",
                              messages[0])
                self.assertIn(f'using the default, {default}', messages[0])

    def test_minus_one_and_above_the_default_warn_of_the_risk(self) -> None:
        for name, default, _, risk in DECLARED:
            with self.subTest(name=name):
                for text, lifted in (('-1', 'lifts the limit'),
                                     (str(default + 1), f'is above the default of {default}')):
                    value, messages = self.load(name, text)
                    self.assertEqual((value, len(messages)), (int(text), 1), messages)
                    self.assertIn(f"PCAPKIT_{name}='{text}' {lifted}: ", messages[0])
                    self.assertIn(risk, messages[0])


class LayoutTests(unittest.TestCase):
    """Where the limits live, and what the module may import."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def imports(self, path: 'pathlib.Path') -> 'set[str]':
        """Every :mod:`pcapkit` module ``path`` imports, at any level."""
        found = set()
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('pcapkit'):
                found.update(f'{node.module}.{alias.name}' if node.module == 'pcapkit.utilities' else node.module
                             for alias in node.names)
            elif isinstance(node, ast.Import):
                found.update(alias.name for alias in node.names if alias.name.startswith('pcapkit'))
        return found

    def test_config_imports_only_warnings(self) -> None:
        self.assertEqual(self.imports(PACKAGE / 'utilities' / 'config.py'), {'pcapkit.utilities.warnings'})

    def test_logging_does_not_import_config(self) -> None:
        self.assertNotIn('pcapkit.utilities.config', self.imports(PACKAGE / 'utilities' / 'logging.py'))

    def test_a_moved_name_has_no_re_export(self) -> None:
        for module, names in MOVED.items():
            loaded = importlib.import_module(module)
            for name in names:
                with self.subTest(module=module, name=name):
                    self.assertFalse(hasattr(loaded, name))

    def test_every_variable_is_documented(self) -> None:
        from pcapkit.utilities import config

        docs = (PACKAGE.parent / 'docs' / 'source' / 'pcapkit' / 'utilities' / 'config.rst').read_text('utf-8')
        # A limit is named after its variable.
        for name in set(config.__all__) - READERS:
            with self.subTest(name=name):
                self.assertIn(f'.. envvar:: PCAPKIT_{name}\n', docs)
        for name in READERS:
            with self.subTest(name=name):
                self.assertIn(f'.. autofunction:: pcapkit.utilities.config.{name}\n', docs)

    def test_the_vendor_names_are_not_here(self) -> None:
        # #1726: the crawlers keep their variables in pcapkit.vendor.default.
        from pcapkit.utilities import config

        for name in VENDOR_NAMES:
            with self.subTest(name=name):
                self.assertFalse(hasattr(config, name))
                self.assertNotIn(name, config.__all__)


class ReaderTests(unittest.TestCase):
    """Patching ``config.<NAME>`` reaches every reader of it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.utilities import config

        self.config = config

    def frame(self, data: bytes) -> 'tuple[object, list[str]]':
        """The PCAP frame of ``data``, and the messages of the ProtocolWarnings it gave."""
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.warnings import ProtocolWarning

        header = Header(GLOBAL).info
        record = struct.pack('<IIII', 1_500_000_000, 0, len(data), len(data)) + data
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = Frame(io.BytesIO(record), num=1, header=header)
        return parsed, [str(item.message) for item in caught if issubclass(item.category, ProtocolWarning)]

    def test_frame_layer_limit_in_protocol(self) -> None:
        data = wire.ethernet(wire.ipv4(wire.ipv4(wire.ipv4(wire.tcp(b'x', seq=1), proto=6), proto=4),
                                       proto=4), 0x0800)
        with mock.patch.object(self.config, 'FRAME_LAYER_LIMIT', 2):
            parsed, messages = self.frame(data)
        self.assertNotIn('TCP', parsed)
        self.assertEqual(len(messages), 1, messages)
        self.assertIn('limit of 2 layers', messages[0])

    def test_frame_layer_limit_in_the_ipv6_walk(self) -> None:
        # Unpatched, IPv6 walks all six headers and the frame limit cuts at the
        # TCP; patched, the walk itself stops short of the TCP's headers.
        data = wire.ethernet(wire.ipv6(chain(6), nxt=60), 0x86DD)
        with mock.patch.object(self.config, 'FRAME_LAYER_LIMIT', 5):
            parsed, messages = self.frame(data)
        self.assertNotIn('TCP', parsed)
        self.assertEqual(len(messages), 1, messages)
        self.assertIn('limit of 5 layers', messages[0])
        self.assertIn('from IPv6_Opts on', messages[0])

    def test_extension_header_limit_in_internet_and_the_ipv6_walk(self) -> None:
        for carrier, data in (('ipv4', wire.ethernet(wire.ipv4(chain(4), proto=60), 0x0800)),
                              ('ipv6', wire.ethernet(wire.ipv6(chain(4), nxt=60), 0x86DD))):
            with self.subTest(carrier=carrier):
                with mock.patch.object(self.config, 'EXTENSION_HEADER_LIMIT', 2):
                    parsed, messages = self.frame(data)
                self.assertNotIn('TCP', parsed)
                self.assertEqual(len(messages), 1, messages)
                self.assertIn('limit of 2 headers', messages[0])

    def walked(self, parsed: 'Any') -> int:
        """How many extension headers the frame's IPv6 layer walked itself."""
        return len(list(parsed['IPv6'].extension_headers.items(multi=True)))

    def test_minus_one_lifts_the_frame_layer_limit_in_protocol(self) -> None:
        data = wire.ethernet(wire.ipv4(wire.ipv4(wire.ipv4(wire.tcp(b'x', seq=1), proto=6), proto=4),
                                       proto=4), 0x0800)
        with mock.patch.object(self.config, 'FRAME_LAYER_LIMIT', -1):
            parsed, messages = self.frame(data)
        self.assertIn('TCP', parsed)
        self.assertEqual(messages, [])

    def test_minus_one_lifts_the_frame_layer_limit_in_the_ipv6_walk(self) -> None:
        data = wire.ethernet(wire.ipv6(chain(6), nxt=60), 0x86DD)
        with mock.patch.object(self.config, 'FRAME_LAYER_LIMIT', -1):
            parsed, messages = self.frame(data)
        self.assertIn('TCP', parsed)
        self.assertEqual(messages, [])
        self.assertEqual(self.walked(parsed), 6)

    def test_minus_one_lifts_the_extension_header_limit(self) -> None:
        # 40 headers, past the default of 32.
        for carrier, data in (('ipv4', wire.ethernet(wire.ipv4(chain(40), proto=60), 0x0800)),
                              ('ipv6', wire.ethernet(wire.ipv6(chain(40), nxt=60), 0x86DD))):
            with self.subTest(carrier=carrier):
                parsed, messages = self.frame(data)
                self.assertNotIn('TCP', parsed)
                self.assertEqual(len(messages), 1, messages)
                with mock.patch.object(self.config, 'EXTENSION_HEADER_LIMIT', -1):
                    parsed, messages = self.frame(data)
                self.assertIn('TCP', parsed)
                self.assertEqual(messages, [])
                if carrier == 'ipv6':
                    self.assertEqual(self.walked(parsed), 40)

    def test_extension_header_limit_in_pypcapfile(self) -> None:
        from pcapkit.toolkit import pypcapfile

        walk = pypcapfile._walk_extension_headers  # pylint: disable=protected-access
        self.assertIsNotNone(walk(60, chain(3)))
        with mock.patch.object(self.config, 'EXTENSION_HEADER_LIMIT', 2):
            self.assertIsNone(walk(60, chain(3)))
        with mock.patch.object(self.config, 'EXTENSION_HEADER_LIMIT', -1):
            self.assertIsNotNone(walk(60, chain(40)))

    def test_ipv6_tcp_warned_limit_in_pypcapfile(self) -> None:
        from pcapkit.toolkit import pypcapfile

        warned = pypcapfile._ipv6_tcp_warned  # pylint: disable=protected-access
        saved = dict(warned)
        self.addCleanup(lambda: (warned.clear(), warned.update(saved)))
        for limit, expected in ((1, [2]), (-1, [0, 1, 2])):
            with self.subTest(limit=limit):
                warned.clear()
                keys = iter(range(10))
                with mock.patch.object(pypcapfile, '_capture_of', lambda packet: (next(keys), None)), \
                        mock.patch.object(pypcapfile, '_ipv6_carries_tcp', return_value=True), \
                        mock.patch.object(self.config, 'IPV6_TCP_WARNED_LIMIT', limit), \
                        warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    for count in range(3):
                        pypcapfile._decline_ipv6_tcp(None, count)  # type: ignore[arg-type] # pylint: disable=protected-access
                self.assertEqual(list(warned), expected)

    def test_read_chunk_in_seekable_reader(self) -> None:
        from pcapkit.corekit.io import SeekableReader

        def asked(limit: int) -> 'list[int]':
            """What a 30-octet read asks of a 100-octet stream, with ``READ_CHUNK`` patched."""
            sizes = []  # type: list[int]

            class Stream(io.BytesIO):
                def read1(self, size: int = -1, /) -> bytes:  # type: ignore[override]
                    sizes.append(size)
                    return super().read1(size)

            with mock.patch.object(self.config, 'READ_CHUNK', limit):
                self.assertEqual(SeekableReader(Stream(bytes(100))).read(30), bytes(30))
            return sizes

        sizes = asked(7)
        self.assertTrue(sizes)
        self.assertLessEqual(max(sizes), 7)
        # -1 asks for the whole read at once, and only that: ``read(-1)`` would
        # take the whole stream.
        self.assertEqual(asked(-1), [30])

    def pad_twice(self, **limits: int) -> None:
        """Read 10 octets into a 40-octet field twice, in a fresh budget, with ``config.<name>`` patched.

        Each read pads 30 octets. With ``MAX_ZERO_PAD_SHORTFALL=10``, both are
        charged to the budget, and the second takes it to 60 octets, past the
        ``50 + 0 * 20`` that ``MAX_ZERO_PAD_LENGTH=50`` and
        ``ZERO_PAD_BUDGET_RATIO=0`` allow.

        """
        from pcapkit.corekit.fields import field as module
        from pcapkit.corekit.fields.strings import BytesField

        field = BytesField(length=40)
        with contextlib.ExitStack() as stack:
            for name, value in limits.items():
                stack.enter_context(mock.patch.object(self.config, name, value))
            stack.enter_context(module._zero_pad_budget())  # pylint: disable=protected-access
            for _ in range(2):
                self.assertEqual(field.unpack(bytes(10), {}), bytes(40))

    def test_max_zero_pad_length_in_field(self) -> None:
        from pcapkit.corekit.fields import field as field_module
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.utilities.exceptions import FieldValueError

        field = BytesField(length=100)
        self.assertEqual(field.unpack(bytes(10), {}), bytes(100))
        with mock.patch.object(self.config, 'MAX_ZERO_PAD_LENGTH', 50), self.assertRaises(FieldValueError):
            field.unpack(bytes(10), {})

        # Past the default of 0x40_000, -1 lifts the ceiling, and the budget as
        # well: the 0x3fff7 octets padded are far past what 10 read would earn.
        field = BytesField(length=0x40_001)
        with self.assertRaises(FieldValueError):
            field.unpack(bytes(10), {})
        with mock.patch.object(self.config, 'MAX_ZERO_PAD_LENGTH', -1), \
                field_module._zero_pad_budget():  # pylint: disable=protected-access
            self.assertEqual(field.unpack(bytes(10), {}), bytes(0x40_001))
        self.pad_twice(MAX_ZERO_PAD_SHORTFALL=10, MAX_ZERO_PAD_LENGTH=-1, ZERO_PAD_BUDGET_RATIO=0)

    def test_max_zero_pad_shortfall_in_field(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        self.pad_twice(MAX_ZERO_PAD_LENGTH=50, ZERO_PAD_BUDGET_RATIO=0)
        with self.assertRaises(FieldValueError):
            self.pad_twice(MAX_ZERO_PAD_SHORTFALL=10, MAX_ZERO_PAD_LENGTH=50, ZERO_PAD_BUDGET_RATIO=0)
        self.pad_twice(MAX_ZERO_PAD_SHORTFALL=-1, MAX_ZERO_PAD_LENGTH=50, ZERO_PAD_BUDGET_RATIO=0)

    def test_zero_pad_budget_ratio_in_field(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError):
            self.pad_twice(MAX_ZERO_PAD_SHORTFALL=10, MAX_ZERO_PAD_LENGTH=50, ZERO_PAD_BUDGET_RATIO=0)
        # 50 + 1 * 20 octets read is 70, enough for the 60 padded.
        self.pad_twice(MAX_ZERO_PAD_SHORTFALL=10, MAX_ZERO_PAD_LENGTH=50, ZERO_PAD_BUDGET_RATIO=1)
        self.pad_twice(MAX_ZERO_PAD_SHORTFALL=10, MAX_ZERO_PAD_LENGTH=50, ZERO_PAD_BUDGET_RATIO=-1)

    def test_fallback_limit_in_dumpkit(self) -> None:
        import dictdumper

        from pcapkit.dumpkit.common import make_dumper
        from pcapkit.utilities.exceptions import UnsupportedCall

        class Node:
            def __init__(self, **kwargs: object) -> None:
                self.__dict__.update(kwargs)

        # 2 ** 3 - 1 = 7 objects: within the default, past a patched 3.
        node = Node(leaf=0)
        for _ in range(2):
            node = Node(left=node, right=node)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'out.json')
            make_dumper(dictdumper.JSON)(path)({'node': node}, name='x')
            with mock.patch.object(self.config, 'FALLBACK_LIMIT', 3), \
                    self.assertRaisesRegex(UnsupportedCall, 'more than 3 objects'):
                make_dumper(dictdumper.JSON)(path)({'node': node}, name='x')
            with mock.patch.object(self.config, 'FALLBACK_LIMIT', -1):
                make_dumper(dictdumper.JSON)(path)({'node': node}, name='x')


def run(code: str, **values: str) -> 'subprocess.CompletedProcess[str]':
    """Run ``code`` in a fresh interpreter from the repository root, with ``PCAPKIT_<name>`` set."""
    env = {key: value for key, value in os.environ.items() if not key.startswith('PCAPKIT_')}
    env.update({f'PCAPKIT_{name}': value for name, value in values.items()})
    env['PYTHONPATH'] = os.pathsep.join(filter(None, [str(PACKAGE.parent), env.get('PYTHONPATH')]))
    return subprocess.run([sys.executable, '-c', code], cwd=PACKAGE.parent, env=env,  # nosec: B603
                          capture_output=True, text=True, timeout=120, check=False)


class ImportTimeTests(unittest.TestCase):
    """What a variable read at import does, in a fresh interpreter."""

    def test_detect_cache_size_sizes_the_chardet_cache(self) -> None:
        code = ('import pcapkit.utilities.chardet as c; '
                'print(c.__file__); print(c.detect.cache_info().maxsize)')
        # 0 is no cache, not an unbounded one: only -1 lifts the limit.
        for text, expected in (('7', '7'), ('0', '0'), ('-1', 'None'), (None, '1024')):
            with self.subTest(text=text):
                result = run(code, **({} if text is None else {'DETECT_CACHE_SIZE': text}))
                self.assertEqual(result.returncode, 0, result.stderr)
                path, size = result.stdout.split()
                self.assertTrue(path.startswith(str(PACKAGE)), path)
                self.assertEqual(size, expected)

    def test_a_warning_names_the_importing_module(self) -> None:
        # Not ``<sys>:0``: importlib's frames between the importer and pcapkit
        # are not counted by warnings.warn, so they are not counted for it.
        with tempfile.TemporaryDirectory() as tmpdir:
            pathlib.Path(tmpdir, 'importer_1726.py').write_text('import pcapkit\n', encoding='utf-8')
            code = ('import sys, warnings; warnings.simplefilter("always"); '
                    f'sys.path.insert(0, {tmpdir!r}); import importer_1726')
            result = run(code, FALLBACK_LIMIT='-7', FRAME_LAYER_LIMIT='-1', DEVMODE='maybe')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('FALLBACK_LIMIT', 'FRAME_LAYER_LIMIT', 'DEVMODE'):
            with self.subTest(name=name):
                self.assertIn(f'importer_1726.py:1: ConfigWarning: PCAPKIT_{name}=', result.stderr)
        self.assertNotIn('<sys>', result.stderr)

    def test_an_error_filter_makes_the_import_raise(self) -> None:
        code = ('import warnings; warnings.filterwarnings("error", message="PCAPKIT_"); '
                'import pcapkit')
        for name, text in (('FALLBACK_LIMIT', '-7'), ('FRAME_LAYER_LIMIT', '-1'), ('DEVMODE', 'maybe')):
            with self.subTest(name=name):
                result = run(code, **{name: text})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"ConfigWarning: PCAPKIT_{name}={text!r}", result.stderr)


class ImporterStacklevelTests(unittest.TestCase):
    """GitHub issue #1963: the importer's level leaves out the bootstrap, however it is named.

    CPython names :mod:`importlib`'s bootstrap frames ``<frozen importlib._bootstrap>``
    and ``<frozen importlib._bootstrap_external>``, GraalPy ``<frozen _frozen_importlib>``
    and ``<frozen _frozen_importlib_external>``, and each one's :func:`warnings.warn`
    leaves its own out. Counting GraalPy's would run the level past the outermost
    frame, so the import-time warnings above would name ``<sys>:0`` there.

    """

    def level_under(self, bootstrap: str) -> int:
        """The level a :mod:`pcapkit` frame gets, imported through ``bootstrap`` frames.

        The chain is that of an import: this test, a bootstrap frame, a package
        body, a bootstrap frame, then the reporting module. Leaving the bootstrap
        out, the test is the third frame.

        """
        pcapkit_warnings = importlib.import_module('pcapkit.utilities.warnings')
        namespace = {'_importer_stacklevel': getattr(pcapkit_warnings, '_importer_stacklevel')}
        package = os.path.join(os.sep, 'site-packages', 'pcapkit', 'probe_1963.py')
        reporter = ('def report():\n    return _importer_stacklevel()\n'
                    'def body():\n    return load_inner()\n')
        importer = ('def load_inner():\n    return report()\n'
                    'def load_outer():\n    return body()\n')
        exec(compile(reporter, package, 'exec'), namespace)  # nosec: B102  # pylint: disable=exec-used
        exec(compile(importer, bootstrap, 'exec'), namespace)  # nosec: B102  # pylint: disable=exec-used
        return namespace['load_outer']()

    def test_each_interpreters_bootstrap_frames_are_left_out(self) -> None:
        """Both CPython's names and GraalPy's leave the test the third frame."""
        for bootstrap in ('<frozen importlib._bootstrap>', '<frozen importlib._bootstrap_external>',
                          '<frozen _frozen_importlib>', '<frozen _frozen_importlib_external>'):
            with self.subTest(bootstrap=bootstrap):
                self.assertEqual(self.level_under(bootstrap), 3)

    def test_any_other_frame_is_counted(self) -> None:
        """The control: frames named otherwise are counted, so the level is one further out."""
        self.assertEqual(self.level_under('<string>'), 4)


if __name__ == '__main__':
    unittest.main()
