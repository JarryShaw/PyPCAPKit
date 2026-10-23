# -*- coding: utf-8 -*-
"""#2047: :file:`util/_actions.py`, the GitHub Actions plumbing the ``util/`` scripts share.

* :class:`TestStandardLibraryOnly` holds the helper to the standard library and
  to 3.7's syntax, since :file:`util/pip_install.py` imports it on every
  interpreter the matrices hold, before anything is installed.
* :class:`TestCommands`, :class:`TestFiles` and :class:`TestRun` pin each
  function's exact output, GitHub's escaping included.
* :class:`TestScriptsImportIt` loads each script that imports the helper in the
  ways the steps and the tests do, and runs it as the steps do.

"""

from __future__ import annotations

import ast
import contextlib
import importlib
import importlib.util
import io
import os
import pathlib
import re
import subprocess  # nosec: B404
import sys
import tempfile
import tokenize
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from util import _actions

if TYPE_CHECKING:
    from typing import Iterator, Optional

#: Test tier (#1958): reads and runs the tree's own scripts, a question about the tree.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = ROOT / 'util' / '_actions.py'
#: The scripts that import the helper.
SCRIPTS = ('apt_packages', 'check_suite_report', 'ci_timing', 'classify_changes', 'codeql_report',
           'coverage_report', 'leg_summary', 'pip_install', 'regenerate_samples', 'release_status', 'release_tags',
           'release_upload', 'release_vendor_update', 'update_python_versions', 'vendor_code_changed',
           'vendor_test_gate')
#: The top-level modules the helper may import, each in Python 3.7's standard
#: library: the running interpreter's :data:`sys.stdlib_module_names` would
#: pass ``tomllib``, which 3.7 lacks.
STDLIB_37 = frozenset({'__future__', 'contextlib', 'os', 'subprocess', 'sys', 'typing', 'uuid'})
#: A trivial run of each script, ``(arguments, environment)``, that gets past its imports.
RUNS = {
    'apt_packages': (['--help'], {}),
    'check_suite_report': (['--help'], {}),
    'ci_timing': (['--help'], {}),
    'classify_changes': ([], {'OWN_PR': 'false'}),
    'codeql_report': (['--help'], {}),
    'coverage_report': (['--help'], {}),
    'leg_summary': (['ktlo'], {'LEG': 'Python 3.8 (KTLO, non-blocking)', 'STEPS': '{}'}),
    'pip_install': (['--help'], {}),
    'regenerate_samples': (['--help'], {}),
    'release_status': (['--help'], {}),
    'release_tags': (['--help'], {}),
    'release_upload': (['--help'], {}),
    'release_vendor_update': (['--help'], {}),
    'update_python_versions': (['--help'], {}),
    'vendor_code_changed': (['--help'], {}),
    'vendor_test_gate': (['--help'], {}),
}
#: ``-X importtime``'s line for a module, by its name.
IMPORT_TIME = re.compile(r'^import time:.*\|\s*(\S+)\s*$', re.M)


@contextlib.contextmanager
def captured() -> 'Iterator[io.BytesIO]':
    """Standard output, as the bytes written to it, :attr:`~io.TextIOWrapper.buffer` included."""
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding='utf-8', newline='\n', write_through=True)
    try:
        with mock.patch.object(sys, 'stdout', stream):
            yield raw
    finally:
        stream.detach()  # so the wrapper, once collected, leaves ``raw`` open to read


def imported(source: 'str') -> 'set[str]':
    """The top-level module of each import in ``source``, a relative one as ``.``."""
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add('.' if node.level else str(node.module).split('.')[0])
    return names


def self_documenting(source: 'str') -> 'list[str]':
    """Each f-string replacement field in ``source`` that ends in 3.8's ``=``, as ``line:col``.

    ``ast.parse(..., feature_version=(3, 7))`` accepts ``f'{x=}'``. Since 3.12 an
    f-string tokenizes into its fields (PEP 701), and there the form is an ``=``
    token followed at once by the ``}``, ``!`` or ``:`` that ends the expression;
    ``==``, ``:=`` and a keyword argument's ``=`` are other tokens or are followed
    by an operand.

    """
    found = []
    depth = 0
    previous = None  # type: Optional[tokenize.TokenInfo]
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.FSTRING_START:  # pylint: disable=no-member
            depth += 1
        elif token.type == tokenize.FSTRING_END:  # pylint: disable=no-member
            depth -= 1
        elif depth and token.type == tokenize.OP and token.string in ('}', '!', ':') \
                and previous is not None and previous.type == tokenize.OP and previous.string == '=':
            found.append('%d:%d' % previous.start)
        if token.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT):
            previous = token
    return found


class TestStandardLibraryOnly(unittest.TestCase):
    """The helper imports nothing but 3.7's standard library, and is written in 3.7's syntax."""

    def setUp(self) -> None:
        self.source = HELPER.read_text(encoding='utf-8')

    def test_it_parses_as_python_3_7(self) -> None:
        ast.parse(self.source, filename=str(HELPER), feature_version=(3, 7))

    def test_it_imports_only_what_3_7_has(self) -> None:
        extra = sorted(imported(self.source) - STDLIB_37)
        self.assertEqual(extra, [], f'util/_actions.py imports {extra}: check that each is in the standard '
                                    'library of Python 3.7 and every interpreter the matrices hold, then add '
                                    'it to STDLIB_37 in this test')
        self.assertIn('uuid', imported(self.source), 'the import inside a function is seen')

    def test_the_import_check_sees_a_newer_module(self) -> None:
        self.assertEqual(sorted(imported('import tomllib\nfrom os import path\n') - STDLIB_37), ['tomllib'])
        self.assertEqual(sorted(imported('def f():\n    from . import x\n') - STDLIB_37), ['.'])

    @unittest.skipUnless(hasattr(tokenize, 'FSTRING_START'), 'f-strings tokenize into fields from 3.12 (PEP 701)')
    def test_it_has_no_self_documenting_f_string(self) -> None:
        self.assertEqual(self_documenting(self.source), [])

    @unittest.skipUnless(hasattr(tokenize, 'FSTRING_START'), 'f-strings tokenize into fields from 3.12 (PEP 701)')
    def test_the_f_string_check_tells_the_forms_apart(self) -> None:
        for source in ('f"{x=}"', 'f"{x = }"', 'f"{x=!r}"', 'f"{x=:>4}"', 'f"a {f(y)=} b"', 'f"{f\'{x=}\'}"'):
            with self.subTest(source=source):
                self.assertEqual(len(self_documenting(source + '\n')), 1, source)
        for source in ('f"{a==b}"', 'f"x={x!r}"', 'f"{x:=^5}"', 'f"{(y:=1)}"', 'f"{g(a=1)}"', 'f"{x!r:=>4}"',
                       'x = {"a": 1}', 'def f(a=1): return {a: a}', "f'{d[\"k=\"]}'"):
            with self.subTest(source=source):
                self.assertEqual(self_documenting(source + '\n'), [], source)


class TestCommands(unittest.TestCase):
    """Workflow commands, escaped as GitHub's reference and ``@actions/core`` escape them."""

    def test_a_message_escapes_percent_and_line_breaks(self) -> None:
        self.assertEqual(_actions.escape_data('100% a\r\nb: c, d'), '100%25 a%0D%0Ab: c, d')

    def test_a_property_escapes_colon_and_comma_too(self) -> None:
        self.assertEqual(_actions.escape_property('100% a\r\nb: c, d'), '100%25 a%0D%0Ab%3A c%2C d')

    def test_percent_is_escaped_first(self) -> None:
        """An escape already in the text is the text, so its ``%`` is escaped once."""
        self.assertEqual(_actions.escape_data('%0A'), '%250A')
        self.assertEqual(_actions.escape_property('%2C,'), '%252C%2C')

    def test_an_annotation_without_properties(self) -> None:
        self.assertEqual(_actions.annotation('error', 'it failed: 1, 2'), '::error::it failed: 1, 2')

    def test_an_annotation_with_properties_in_order(self) -> None:
        self.assertEqual(_actions.annotation('notice', 'a\nb', line=3, file='x,y.py', title='T: 1, 2'),
                         '::notice title=T%3A 1%2C 2,file=x%2Cy.py,line=3::a%0Ab')
        self.assertEqual(_actions.annotation('warning', 'm', file='f.py'), '::warning file=f.py::m')

    def test_an_annotation_unescaped(self) -> None:
        self.assertEqual(_actions.annotation('warning', '100%\nraw', title='a%2Cb: c', escape=False),
                         '::warning title=a%2Cb: c::100%\nraw')

    def test_an_annotation_names_a_level(self) -> None:
        with self.assertRaises(ValueError):
            _actions.annotation('debug', 'm')

    def test_the_title_escapes_as_the_scripts_did(self) -> None:
        """``leg_summary.py`` escaped only ``,`` in a leg's name; for the legs the matrices name, that is all."""
        for leg in ('Python 3.8 (KTLO, non-blocking)', 'Python 3.14t (experimental, non-blocking)',
                    'Python pypy-3.10', 'Python graalpy-25.0'):
            with self.subTest(leg=leg):
                self.assertEqual(_actions.annotation('warning', 'm', title=f'tests failed on {leg}'),
                                 f"::warning title=tests failed on {leg.replace(',', '%2C')}::m")

    def test_annotate_prints_the_line(self) -> None:
        stream = io.StringIO()
        _actions.annotate('warning', 'a\rb', title='t', stream=stream)
        self.assertEqual(stream.getvalue(), '::warning title=t::a%0Db\n')
        with captured() as raw:
            _actions.annotate('error', 'm')
        self.assertEqual(raw.getvalue(), b'::error::m\n')

    def test_a_group_ends_however_its_block_does(self) -> None:
        with captured() as raw:
            with self.assertRaises(KeyError):
                with _actions.group('a\nb'):
                    print('inside')
                    raise KeyError
        self.assertEqual(raw.getvalue(), b'::group::a%0Ab\ninside\n::endgroup::\n')

    def test_say_and_emit_write_bytes(self) -> None:
        with captured() as raw:
            _actions.say('a\udcff')
            _actions.emit(b'\xfe\n')
        self.assertEqual(raw.getvalue(), b'a\xff\n\xfe\n')

    def test_exit_status_is_the_shells(self) -> None:
        self.assertEqual([_actions.exit_status(code) for code in (0, 1, 2, -9, -15)], [0, 1, 2, 137, 143])


class TestFiles(unittest.TestCase):
    """``$GITHUB_OUTPUT`` and ``$GITHUB_STEP_SUMMARY``, appended to in UTF-8."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = pathlib.Path(tmp.name) / 'file'
        self.path.write_bytes(b'before\n')

    def read(self) -> 'bytes':
        return self.path.read_bytes()

    def test_an_output(self) -> None:
        env = {'GITHUB_OUTPUT': str(self.path)}
        self.assertTrue(_actions.set_output('code', 'true', environ=env))
        self.assertTrue(_actions.set_output('key', 'a=b é', environ=env))
        self.assertEqual(self.read(), 'before\ncode=true\nkey=a=b é\n'.encode('utf-8'))

    def test_a_multiline_output_has_a_fresh_delimiter(self) -> None:
        env = {'GITHUB_OUTPUT': str(self.path)}
        _actions.set_output('list', 'a\nb', environ=env)
        _actions.set_output('list', 'c\n', environ=env)
        text = self.read().decode('utf-8')
        found = re.fullmatch(r'before\nlist<<(EOF_[0-9a-f]{32})\na\nb\n\1\nlist<<(EOF_[0-9a-f]{32})\nc\n\n\2\n', text)
        self.assertIsNotNone(found, text)
        assert found is not None
        self.assertNotEqual(found.group(1), found.group(2))

    def test_a_carriage_return_takes_the_multiline_form_too(self) -> None:
        _actions.set_output('cr', 'a\rb', environ={'GITHUB_OUTPUT': str(self.path)})
        text = self.read()
        found = re.fullmatch(rb'before\ncr<<(EOF_[0-9a-f]{32})\na\rb\n\1\n', text)
        self.assertIsNotNone(found, text)

    def test_an_unset_file(self) -> None:
        """A ``required`` write raises, as ``os.environ[...]`` did; any other writes nothing."""
        for env in ({}, {'GITHUB_OUTPUT': '', 'GITHUB_STEP_SUMMARY': ''}):
            with self.subTest(env=env):
                self.assertFalse(_actions.set_output('code', 'true', required=False, environ=env))
                self.assertFalse(_actions.summary('line', required=False, environ=env))
        with self.assertRaises(KeyError):
            _actions.set_output('code', 'true', environ={})
        with self.assertRaises(KeyError):
            _actions.summary('line', environ={})
        with self.assertRaises(KeyError):
            _actions.open_summary(environ={})

    def test_it_reads_the_environment_by_default(self) -> None:
        with mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(self.path), 'GITHUB_STEP_SUMMARY': str(self.path)}):
            _actions.set_output('a', '1')
            _actions.summary('- one', '- two')
            with _actions.open_summary() as page:
                print('| table |', file=page)
        self.assertEqual(self.read(), b'before\na=1\n- one\n- two\n| table |\n')


class TestRun(unittest.TestCase):
    """:func:`_actions.run` copies a command's output, its errors included, to standard output and the log."""

    def test_it_tees_the_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / 'out.log'
            log.write_bytes(b'stale\n')
            code = ('import sys; sys.stdout.buffer.write(b"one\\n"); sys.stdout.flush(); '
                    'sys.stderr.buffer.write(b"two \\xff\\n"); sys.stderr.flush(); sys.exit(3)')
            with captured() as raw:
                status, output = _actions.run([sys.executable, '-c', code], log)
            self.assertEqual(status, 3)
            self.assertEqual(output, b'one\ntwo \xff\n')
            self.assertEqual(raw.getvalue(), output)
            self.assertEqual(log.read_bytes(), output)


class TestScriptsImportIt(unittest.TestCase):
    """Each script finds the helper as a package module and loaded by path."""

    def test_as_a_package_module(self) -> None:
        for name in SCRIPTS:
            with self.subTest(script=name):
                module = importlib.import_module(f'util.{name}')
                self.assertEqual(pathlib.Path(module._actions.__file__).resolve(), HELPER)

    def test_loaded_by_path(self) -> None:
        for name in SCRIPTS:
            with self.subTest(script=name):
                spec = importlib.util.spec_from_file_location(f'actions_2047_{name}', ROOT / 'util' / f'{name}.py')
                assert spec is not None and spec.loader is not None
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.assertEqual(pathlib.Path(module._actions.__file__).resolve(), HELPER)

    def test_run_as_the_steps_run_it(self) -> None:
        """``python util/<script>.py`` from the root imports ``_actions``, the first branch, not ``util._actions``."""
        self.assertEqual(sorted(RUNS), sorted(SCRIPTS))
        for name, (args, extra) in RUNS.items():
            with self.subTest(script=name), tempfile.TemporaryDirectory() as tmp:
                output = pathlib.Path(tmp) / 'output'
                env = {key: value for key, value in os.environ.items()
                       if not key.startswith(('GITHUB_', 'PYTHON'))}
                env.update(GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(pathlib.Path(tmp) / 'summary'),
                           **extra)
                result = subprocess.run([sys.executable, '-X', 'importtime', f'util/{name}.py', *args],  # nosec: B603
                                        cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                modules = IMPORT_TIME.findall(result.stderr)
                self.assertIn('_actions', modules)
                self.assertNotIn('util._actions', modules)
                if name == 'classify_changes':
                    self.assertEqual(output.read_text(encoding='utf-8'), 'code=true\n')


if __name__ == '__main__':
    unittest.main()
