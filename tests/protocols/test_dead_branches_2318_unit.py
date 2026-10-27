# -*- coding: utf-8 -*-
"""Which guards a reader needs, and which something earlier already runs. C.f. #2318.

A guard is worth keeping only where some route reaches it. The guards removed
here are unreachable, because something earlier raises first:
``Header.read``'s ``FileError`` on an unknown magic number, which the schema's
:func:`~pcapkit.protocols.schema.misc.pcap.header.magic_number_callback` beats
to it; and the ``Opt Data Len`` guards of ``_read_opt_calipso``, which
:func:`~pcapkit.protocols.schema.internet.ipv6_option.calipso_pad_len` beats to
it whether the option is unpacked off the wire or packed from a caller's own
schema. For each, a test feeds the input that would have reached it, pins what
is raised -- or parsed -- instead, and pins the source as holding no such
guard.

The ``unknown QS function`` arm of ``_read_opt_qs`` is reachable, so it stays.
A parse of the stock registry does not reach it, since that registry leaves an
unassigned function with no schema and the option arrives as an
``UnassignedOption``; *construction* reaches it, since the reader is handed the
caller's own option schemas and the schema's selector never runs. A *parse*
reaches it too once a caller has registered a schema of their own against an
unassigned function code, which is what the selector then hands the reader. See
:class:`QuickStartFunctionTests` and
:class:`RegisteredQuickStartFunctionTests`, which pin those routes.

The commented-out ``raise`` lines that sit beside a ``warn`` standing in their
place are audited the same way, over the whole package, since they read as if
the stricter behaviour were one uncomment away from returning.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import ast
import inspect
import io
import pathlib
import re
import tempfile
import tokenize
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): in-memory parses and a source audit, neither of which
#: differs by interpreter.
__tier__ = 'LATEST'

#: The package audited for a commented-out ``raise``.
PACKAGE = pathlib.Path(__file__).resolve().parent.parent.parent / 'pcapkit'

#: How near a ``warn(`` has to be for a commented-out ``raise`` to read as the
#: stricter behaviour a ``warn`` stands in for, in lines either side.
NEARBY = 3


def hopopt_bytes(option: 'bytes') -> 'bytes':
    """A HOPOPT header carrying ``option``, padded to a multiple of 8 octets."""
    pad = -(len(option) + 2) % 8
    if pad == 1:
        option += bytes(1)
    elif pad:
        option += bytes([1, pad - 2]) + bytes(pad - 2)
    return bytes([59, (len(option) + 2) // 8 - 1]) + option


def ipv4_bytes(options: 'bytes') -> 'bytes':
    """An IPv4 header carrying ``options``, padded to a multiple of 4 octets."""
    options += bytes(-len(options) % 4)
    length = 20 + len(options)
    return (bytes([0x40 | length // 4, 0]) + length.to_bytes(2, 'big') + bytes(4)
            + bytes([64, 59, 0, 0]) + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2]) + options)


def commented_raises(path: 'pathlib.Path') -> 'list[int]':
    """The lines of ``path`` holding a commented-out ``raise`` beside a ``warn``.

    A comment counts only when it parses as a lone :keyword:`raise` statement,
    so that prose opening with the word ("raise ``OSError`` on a host with no
    ...") is left alone, and only when a ``warn(`` call sits within
    :data:`NEARBY` lines of it.

    """
    lines = path.read_text(encoding='utf-8').splitlines()
    found = []
    with open(path, 'rb') as stream:
        for token in tokenize.tokenize(stream.readline):
            if token.type != tokenize.COMMENT:
                continue
            try:
                body = ast.parse(token.string.lstrip('#').strip()).body
            except SyntaxError:
                continue
            if len(body) != 1 or not isinstance(body[0], ast.Raise):
                continue
            row = token.start[0] - 1
            if any('warn(' in line for line in lines[max(0, row - NEARBY):row + NEARBY + 1]):
                found.append(row + 1)
    return found


class MagicNumberTests(unittest.TestCase):
    """An unknown magic number raises from the schema, as documented."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unknown_magic_number_raises_protocol_error(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as caught:
            Header(io.BytesIO(b'\x00\x01\x02\x03' + bytes(20)))
        self.assertIn('invalid magic number', str(caught.exception))

    def test_the_header_module_names_protocol_error(self) -> None:
        from pcapkit.protocols.misc.pcap import header

        docstring = header.Header.read.__doc__ or ''
        self.assertIn('ProtocolError', docstring)
        self.assertNotIn('FileError', docstring)
        self.assertNotIn('FileError', inspect.getsource(header))


class QuickStartFunctionTests(unittest.TestCase):
    """An unassigned QS function parses as unassigned, and is rejected on
    construction.

    A parse and a construction reach ``_read_opt_qs`` by different routes, and
    what the parse route carries depends on what the ``QuickStartOption``
    registry holds.

    A parse runs
    :func:`~pcapkit.protocols.schema.internet.ipv6_option.quick_start_data_selector`
    over the octets first, and that selector reads the registry. Under the stock
    registry, which assigns ``Quick_Start_Request`` (``0``) and
    ``Report_of_Approved_Rate`` (``8``) and nothing else, any other ``func``
    nibble arrives as an ``UnassignedOption`` and is read by
    ``_read_opt_none``, so the function arms never see it. A caller who
    registers a schema of their own against an unassigned function code changes
    that, and an ordinary parse then reaches the arms; see
    :class:`RegisteredQuickStartFunctionTests`.

    Construction hands the reader the caller's own schema objects --
    ``_read_hopopt_options`` and its siblings iterate
    ``self.__header__.options``, not a re-parse of the octets they wrote -- so
    the selector never runs. A ``QuickStartRequestOption`` or
    ``QuickStartReportOption`` whose ``func`` names neither assigned layout
    therefore reaches the arms, and the ``unknown QS function`` guard is what
    rejects it. Without that guard such an option is written to the wire for an
    unassigned function, and a request schema is read as a report schema,
    failing on the report layout's ``reserved`` field -- which the request
    layout does not have -- with an :exc:`AttributeError` naming nothing the
    caller got wrong.

    """

    #: QS functions with no assigned layout: either side of the functions the
    #: registry assigns, ``Quick_Start_Request`` (``0``) and
    #: ``Report_of_Approved_Rate`` (``8``), and the top of the nibble.
    UNASSIGNED = (1, 2, 7, 9, 15)

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def qs_cases(self, func: 'int') -> 'list[tuple[str, Any, dict[str, Any], Any]]':
        """Each protocol, with a request and a report schema naming ``func``.

        Returns:
            One ``(label, protocol, construction keywords, option schema)``
            tuple per protocol and schema class, for an option whose ``func``
            nibble is ``func``.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.protocols.schema.internet import hopopt as schema_hopopt
        from pcapkit.protocols.schema.internet import ipv4 as schema_ipv4
        from pcapkit.protocols.schema.internet import ipv6_opts as schema_ipv6_opts

        flags = {'func': func, 'rate': 1}
        nonce = {'nonce': 0x12345, 'reserved': 0}
        cases = []
        for protocol, schema in ((HOPOPT, schema_hopopt), (IPv6_Opts, schema_ipv6_opts)):
            # An extension header option carries ``Opt Data Len``, i.e. the six
            # octets after the two header ones.
            cases.append((f'{protocol.__name__}/request', protocol, {'next': 59, 'payload': b''},
                          schema.QuickStartRequestOption(
                              type=Option.Quick_Start, len=6, flags=flags, ttl=10, nonce=nonce)))
            cases.append((f'{protocol.__name__}/report', protocol, {'next': 59, 'payload': b''},
                          schema.QuickStartReportOption(
                              type=Option.Quick_Start, len=6, flags=flags,
                              reserved=bytes(1), nonce=nonce)))
        # An IPv4 option's ``length`` counts its own header octets too.
        cases.append(('IPv4/request', IPv4, {'protocol': 59},
                      schema_ipv4.QuickStartRequestOption(
                          type=OptionNumber.QS, length=8, flags=flags, ttl=10, nonce=nonce)))
        cases.append(('IPv4/report', IPv4, {'protocol': 59},
                      schema_ipv4.QuickStartReportOption(
                          type=OptionNumber.QS, length=8, flags=flags, reserved=0, nonce=nonce)))
        return cases

    def test_a_constructed_option_with_an_unassigned_function_is_rejected(self) -> None:
        """``make`` rejects an option schema naming a function it cannot be.

        This is the route the schema's selector does not stand in front of, so
        it is the route the ``unknown QS function`` guard answers without a
        caller having registered a schema of their own. The message names the
        function, so that the option -- and not the option-length check the
        reader runs before it -- is what the caller is told about.

        """
        from pcapkit.utilities.exceptions import ProtocolError

        for func in self.UNASSIGNED:
            for label, protocol, keywords, schema in self.qs_cases(func):
                with self.subTest(case=label, func=func):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        with self.assertRaises(ProtocolError) as caught:
                            protocol(options=[schema], **keywords)
                    self.assertIn(f'unknown QS function: {func}', str(caught.exception))

    def test_an_assigned_function_constructs(self) -> None:
        """A schema naming the function its layout is the layout of is written.

        The guard rejects a self-contradictory option, not every constructed
        one, so each schema class is built with its own function and the
        octets it writes are read back.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv6.option import Option

        for func, kind in ((0, 'request'), (8, 'report')):
            for label, protocol, keywords, schema in self.qs_cases(func):
                if not label.endswith(kind):
                    continue
                with self.subTest(case=label, func=func):
                    packet = protocol(options=[schema], **keywords)
                    code = OptionNumber.QS if protocol.__name__ == 'IPv4' else Option.Quick_Start
                    self.assertEqual(type(packet.info.options[code]).__name__,
                                     type(schema).__name__)

    def test_every_function_nibble_parses(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        expected = {0: 'QuickStartRequestOption', 8: 'QuickStartReportOption'}
        for func in range(16):
            name = expected.get(func, 'UnassignedOption')
            option = bytes([38, 6, (func << 4) | 1, 10]) + bytes(4)
            for protocol in (HOPOPT, IPv6_Opts):
                with self.subTest(protocol=protocol.__name__, func=func):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        parsed = protocol(hopopt_bytes(option)).info.options[Option.Quick_Start]
                    self.assertEqual(type(parsed).__name__, name)
            with self.subTest(protocol='IPv4', func=func):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    option4 = bytes([25, 8, (func << 4) | 1, 10]) + bytes(4)
                    parsed = IPv4(ipv4_bytes(option4)).info.options[OptionNumber.QS]
                self.assertEqual(type(parsed).__name__, name)

    def test_every_reader_keeps_the_unknown_function_guard(self) -> None:
        """Each reader holds the guard, and documents that it raises.

        The source is pinned as well as the behaviour, because a parse of the
        stock registry does not reach the guard: a reading of that path alone
        makes it look dead.

        """
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        for protocol in (HOPOPT, IPv6_Opts, IPv4):
            with self.subTest(protocol=protocol.__name__):
                source = inspect.getsource(protocol._read_opt_qs)
                self.assertIn('unknown QS function', source)
                self.assertIn('ProtocolError', protocol._read_opt_qs.__doc__ or '')
                # One ``# pylint: disable=`` pragma per line, not two.
                for line in source.splitlines():
                    self.assertLessEqual(line.count('pylint: disable='), 1, line)


class RegisteredQuickStartFunctionTests(unittest.TestCase):
    """A parse reaches the guard once a caller registers an unassigned function.

    ``QuickStartOption`` is an
    :class:`~pcapkit.protocols.schema.schema.EnumSchema`, so a caller may
    register a layout of their own against a function code the stock registry
    leaves empty.
    :func:`~pcapkit.protocols.schema.internet.ipv6_option.quick_start_data_selector`
    then hands the reader that schema rather than an ``UnassignedOption``, and
    ordinary octets off a file read reach the ``unknown QS function`` arm --
    the arm is therefore not construction-only.

    The registration mutates a package-wide registry, so this class takes its
    :mod:`pcapkit` import with ``restore=True`` and gives it back when it
    finishes.

    """

    #: A QS function the stock registry leaves without a layout.
    FUNC = 3

    def setUp(self) -> None:
        reimport_once_per_class(self, restore=True)

    def register(self, base: 'Any', code: 'Any') -> 'None':
        """Register a caller's own layout for ``code`` against ``base``."""
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.schema import schema_final

        self.assertIsNone(base.registry[code])

        @schema_final
        class CallerQuickStartOption(base, code=code):  # type: ignore[misc,valid-type]
            """A caller's own layout for an unassigned QS function."""

            ttl: 'int' = UInt8Field()
            rest: 'bytes' = BytesField(length=4)

        self.assertIs(base.registry[code], CallerQuickStartOption)

    def test_a_parse_reaches_the_guard(self) -> None:
        """Ordinary octets reach the arm once the function has a layout."""
        from pcapkit.const.ipv4.qs_function import QSFunction as QSFunction4
        from pcapkit.const.ipv6.qs_function import QSFunction as QSFunction6
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.protocols.schema.internet.hopopt import QuickStartOption as QSOption_hopopt
        from pcapkit.protocols.schema.internet.ipv4 import QSOption as QSOption_ipv4
        from pcapkit.protocols.schema.internet.ipv6_opts import \
            QuickStartOption as QSOption_ipv6_opts
        from pcapkit.utilities.exceptions import ProtocolError

        flags = (self.FUNC << 4) | 1
        # An extension header option carries ``Opt Data Len``; an IPv4 option's
        # ``length`` counts its own header octets too.
        extension = hopopt_bytes(bytes([38, 6, flags, 10]) + bytes(4))
        cases = (
            (HOPOPT, QSOption_hopopt, QSFunction6.get(self.FUNC), extension),
            (IPv6_Opts, QSOption_ipv6_opts, QSFunction6.get(self.FUNC), extension),
            (IPv4, QSOption_ipv4, QSFunction4.get(self.FUNC),
             ipv4_bytes(bytes([25, 8, flags, 10]) + bytes(4))),
        )
        for protocol, base, code, packet in cases:
            with self.subTest(protocol=protocol.__name__):
                self.register(base, code)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaises(ProtocolError) as caught:
                        protocol(packet)
                self.assertIn(f'unknown QS function: {self.FUNC}', str(caught.exception))


class CALIPSOLengthTests(unittest.TestCase):
    """A CALIPSO option too short for its bitmap is rejected either way round.

    ``calipso_pad_len`` sizes ``pad`` on both routes that reach the reader --
    a parse, where the option is unpacked off the wire, and a construction,
    where the caller's own option schema is packed -- so each is pinned.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_short_option_raises_from_the_pad_length(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.utilities.exceptions import FieldValueError

        for length, cmpt_len in ((7, 0), (5, 0), (8, 1), (11, 1)):
            option = (bytes([7, length]) + bytes(4) + bytes([cmpt_len, 0]) + b'\xab\xcd'
                      + bytes(max(0, length - 8)))
            for protocol in (HOPOPT, IPv6_Opts):
                with self.subTest(protocol=protocol.__name__, length=length):
                    with self.assertRaises(FieldValueError) as caught:
                        protocol(hopopt_bytes(option))
                    self.assertIn(f'invalid CALIPSO option length: {length}', str(caught.exception))

    def test_a_constructed_option_raises_from_the_pad_length(self) -> None:
        """``make`` rejects the same option, before any reader runs.

        Construction packs the caller's own option schema, so
        :func:`~pcapkit.protocols.schema.internet.ipv6_option.calipso_pad_len`
        sizes ``pad`` there too and raises out of ``schema.pack()`` while the
        header is being made. ``_read_opt_calipso`` never sees the option, so
        a length guard of its own would be unreachable on this route as well
        as on a parse.

        """
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.protocols.schema.internet import hopopt as schema_hopopt
        from pcapkit.protocols.schema.internet import ipv6_opts as schema_ipv6_opts
        from pcapkit.utilities.exceptions import FieldValueError

        for length, cmpt_len in ((7, 0), (5, 0), (8, 1), (11, 1)):
            # ``bitmap`` is conditional on a non-zero ``cmpt_len``, and is the
            # four octets per compartment word that ``Opt Data Len`` is short of.
            bitmap = bytes(cmpt_len * 4) if cmpt_len else None
            for protocol, schema in ((HOPOPT, schema_hopopt), (IPv6_Opts, schema_ipv6_opts)):
                with self.subTest(protocol=protocol.__name__, length=length):
                    option = schema.CALIPSOOption(
                        type=Option.CALIPSO, len=length, domain=0x12345678,
                        cmpt_len=cmpt_len, level=5, checksum=b'\xab\xcd',
                        bitmap=bitmap, pad=b'')
                    with self.assertRaises(FieldValueError) as caught:
                        option.pack()
                    self.assertIn(f'invalid CALIPSO option length: {length}', str(caught.exception))
                    with self.assertRaises(FieldValueError) as caught:
                        protocol(options=[option], next=59, payload=b'')
                    self.assertIn(f'invalid CALIPSO option length: {length}', str(caught.exception))

    def test_the_reader_keeps_no_length_guard(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        for protocol in (HOPOPT, IPv6_Opts):
            with self.subTest(protocol=protocol.__name__):
                source = inspect.getsource(protocol._read_opt_calipso)
                self.assertNotIn('raise', source)

    def test_a_well_formed_option_parses(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT

        option = (bytes([7, 12]) + (0x12345678).to_bytes(4, 'big') + bytes([1, 5])
                  + b'\xab\xcd' + bytes([0xde, 0xad, 0xbe, 0xef]))
        parsed = HOPOPT(hopopt_bytes(option)).info.options[Option.CALIPSO]
        self.assertEqual(parsed.cmpt_len, 4)
        self.assertEqual(parsed.cmpt_bitmap, (0xde, 0xad, 0xbe, 0xef))


class CommentedOutRaiseTests(unittest.TestCase):
    """No commented-out ``raise`` sits beside a ``warn`` standing in its place."""

    def test_the_package_keeps_none(self) -> None:
        offenders = {str(path.relative_to(PACKAGE)): rows
                     for path in sorted(PACKAGE.rglob('*.py'))
                     if (rows := commented_raises(path))}
        self.assertEqual(offenders, {})

    def test_the_audit_finds_one(self) -> None:
        """The audit catches a commented-out ``raise``, and spares the prose."""
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'sample.py'
            path.write_text(
                'def f(bad):\n'
                '    if bad:\n'
                "        # raise ValueError('bad')\n"
                "        warn('bad', UserWarning)\n"
                '\n'
                'def g():\n'
                '    # raise ``OSError`` where the library is absent\n'
                "    warn('absent', UserWarning)\n",
                encoding='utf-8')
            self.assertEqual(commented_raises(path), [3])


class PylintPragmaTests(unittest.TestCase):
    """No source line repeats a ``pylint: disable=`` pragma."""

    def test_no_line_carries_two(self) -> None:
        offenders = []
        for path in sorted(PACKAGE.rglob('*.py')):
            for row, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if len(re.findall(r'pylint: disable=', line)) > 1:
                    offenders.append(f'{path.relative_to(PACKAGE)}:{row}')
        self.assertEqual(offenders, [])


if __name__ == '__main__':
    unittest.main()
