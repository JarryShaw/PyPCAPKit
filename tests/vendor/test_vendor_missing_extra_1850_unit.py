# -*- coding: utf-8 -*-
"""``pcapkit-vendor`` without the ``vendor`` extra exits on one line, not with a traceback.

GitHub issue #1850. :mod:`pcapkit.vendor` imported every crawler unconditionally,
and :mod:`pcapkit.vendor.default` imports ``requests`` at module scope, so without
the extra importing the package raised :exc:`ModuleNotFoundError`. The console
script and ``python -m pcapkit.vendor`` import that package before any line of
:mod:`pcapkit.vendor.__main__` runs, so the user got a traceback; the
:class:`~pcapkit.utilities.warnings.VendorWarning` emitted first is a
:exc:`ResourceWarning`, which Python hides by default. The owner ruled that the
command should instead exit with one line naming the missing packages and the
extra to install, for a pip install without ``[vendor]`` as much as for the conda
package, which does not vendor the crawlers' dependencies (#1814).

The package now records what is missing in ``_MISSING`` and imports no crawler
while it is not empty. Its :pep:`562` ``__getattr__`` raises a
:exc:`ModuleNotFoundError` carrying the message for a crawler's name, and
:func:`~pcapkit.vendor.__main__.main` prints the message and returns ``1``.

The missing packages are simulated in a fresh interpreter, by a
:file:`sitecustomize.py` that binds them to :data:`None` in :data:`sys.modules`
before anything else is imported, so importing one raises
:exc:`ModuleNotFoundError` just as a missing package does. This interpreter keeps
them, so nothing here disturbs the rest of the suite. ``PYTHONPATH`` puts this
checkout ahead of any installed copy, and
:meth:`MissingExtraTests.test_import_succeeds_and_a_crawler_name_raises` checks
that the child imported this checkout.

Against the unfixed tree every test of :class:`MissingExtraTests` fails on the
traceback of that import, and :class:`MainTests` fails with :exc:`AttributeError`,
as there is no ``_MISSING`` to patch. :class:`PresentExtraTests` passes before and
after the fix, as it should: it pins that nothing changes with the extra installed.

"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import pathlib
import subprocess  # nosec: B404
import sys
import sysconfig
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import scale_timeout

if TYPE_CHECKING:
    from typing import Sequence

#: The package under test, found from this file rather than by importing it, so
#: that a child interpreter can be pointed at the same tree.
PACKAGE = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit'

#: Same gate as the rest of :mod:`tests.vendor`, for the tests that need the
#: crawlers' dependencies installed here: ``requests`` for
#: :mod:`pcapkit.vendor.default` and ``bs4`` for the crawlers that parse HTML.
VENDOR_DEPS = ('requests', 'bs4')

#: Whether the crawler machinery is importable at all. The ``test`` extra ships
#: these (:file:`pyproject.toml`), so this should not skip in CI.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: What a pip install without ``[vendor]`` lacks: the import names of the extra's
#: ``requests[socks]`` and ``beautifulsoup4[html5lib]``. ``pycrate`` stays
#: importable, being a core addon of the ``all`` extra as well, and the crawlers
#: that need it import it only when they run.
EXTRA_MODULES = ('requests', 'socks', 'bs4', 'html5lib')

#: Why no crawler can be imported when none of :data:`EXTRA_MODULES` is installed.
REASON = ('missing dependencies: requests, beautifulsoup4; '
          'install the vendor extra: pip install "pypcapkit[vendor]"')

#: The line :func:`~pcapkit.vendor.__main__.main` writes to stderr for :data:`REASON`.
MESSAGE = f'pcapkit-vendor: error: {REASON}'

#: What the ``pcapkit-vendor`` console script runs: the wrapper pip writes for a
#: ``[project.scripts]`` entry imports the entry point at module scope, so an
#: exception raised by that import escapes it.
CONSOLE_SCRIPT = ('-c', 'import sys; from pcapkit.vendor.__main__ import main; sys.exit(main())')

#: ``python -m pcapkit.vendor``.
RUN_MODULE = ('-m', 'pcapkit.vendor')

#: Whether this interpreter is a free-threaded build. A build option rather than
#: a version, as :data:`sys.version_info` reads the same on either build.
FREE_THREADED = bool(sysconfig.get_config_var('Py_GIL_DISABLED'))

#: The ``PYTHONWARNINGS`` filter for what a free-threaded build writes as it
#: enables the GIL to load :mod:`lxml`, which ``bs4`` imports and which does not
#: declare itself safe to run without the GIL (#1961). Its message part is a
#: literal prefix, so it holds no comma or colon, and it names :mod:`lxml`, so the
#: same warning for any other module still reaches stderr.
LXML_GIL_FILTER = ("ignore:The global interpreter lock (GIL) has been enabled "
                   "to load module 'lxml.:RuntimeWarning")


def child_env() -> 'dict[str, str]':
    """The environment of a child interpreter, with nothing that adds to its stderr.

    ``PCAPKIT_DEVMODE`` writes a warning through :func:`warnings.showwarning`,
    which no filter stops, and ``PYTHONWARNINGS`` or ``PYTHONDEVMODE`` would show
    the :class:`~pcapkit.utilities.warnings.VendorWarning` that Python hides by
    default. ``COLUMNS`` and ``PYTHON_COLORS`` fix how :mod:`argparse` lays out
    and colours its help, so it can be compared with this interpreter's.

    On a free-threaded build ``PYTHONWARNINGS`` is :data:`LXML_GIL_FILTER`, which
    ignores the :mod:`lxml` GIL warning and nothing else. The child still starts
    with the GIL disabled, as it would not under ``PYTHON_GIL=1``, so it runs as
    that build does.

    """
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('PCAPKIT_')
           and key not in ('PYTHONSAFEPATH', 'PYTHONWARNINGS', 'PYTHONDEVMODE')}
    env.update(COLUMNS='80', PYTHON_COLORS='0')
    if FREE_THREADED:
        env['PYTHONWARNINGS'] = LXML_GIL_FILTER
    return env


def run(command: 'Sequence[str]', *args: str,
        blocked: 'Sequence[str]' = ()) -> 'subprocess.CompletedProcess[str]':
    """Run ``command`` with ``args`` in a fresh interpreter, with ``blocked`` not importable."""
    env = child_env()
    with tempfile.TemporaryDirectory() as tempdir:
        with open(os.path.join(tempdir, 'sitecustomize.py'), 'w', encoding='utf-8') as file:
            file.write(f'import sys\nfor name in {tuple(blocked)!r}:\n    sys.modules[name] = None\n')
        env['PYTHONPATH'] = os.pathsep.join(filter(None, [tempdir, str(PACKAGE.parent),
                                                          os.environ.get('PYTHONPATH')]))
        return subprocess.run([sys.executable, *command, *args], cwd=PACKAGE.parent,  # nosec: B603
                              env=env, capture_output=True, text=True,
                              timeout=scale_timeout(120), check=False)


class MissingExtraTests(unittest.TestCase):
    """Without the ``vendor`` extra, in a child interpreter."""

    def assert_one_line_exit(self, result: 'subprocess.CompletedProcess[str]', message: 'str') -> None:
        """``result`` exited ``1`` with ``message`` as its only output."""
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual((result.returncode, result.stdout, result.stderr.splitlines()),
                         (1, '', [message]), result.stderr)

    def test_console_script_exits_on_one_line(self) -> None:
        self.assert_one_line_exit(run(CONSOLE_SCRIPT, blocked=EXTRA_MODULES), MESSAGE)

    def test_python_m_exits_on_one_line(self) -> None:
        self.assert_one_line_exit(run(RUN_MODULE, blocked=EXTRA_MODULES), MESSAGE)

    def test_a_named_target_gets_the_same_line(self) -> None:
        # main() imports a named target itself and reports an ImportError as an
        # invalid target, which would hide the missing package behind a usage error.
        self.assert_one_line_exit(run(RUN_MODULE, 'reg', blocked=EXTRA_MODULES), MESSAGE)

    @unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
    def test_the_line_names_only_what_is_missing(self) -> None:
        self.assert_one_line_exit(run(RUN_MODULE, blocked=('bs4',)),
                                  MESSAGE.replace('requests, ', ''))

    def test_help_needs_no_extra(self) -> None:
        result = run(RUN_MODULE, '--help', blocked=EXTRA_MODULES)
        self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
        self.assertTrue(result.stdout.startswith('usage: pcapkit-vendor '), result.stdout)

    def test_import_succeeds_and_a_crawler_name_raises(self) -> None:
        code = textwrap.dedent('''\
            import pcapkit.vendor
            print(pcapkit.vendor.__file__)
            for statement in ('from pcapkit.vendor import EtherType',
                              'pcapkit.vendor.Vendor',
                              'from pcapkit.vendor import *',
                              'pcapkit.vendor.no_such_name'):
                try:
                    exec(statement, {'pcapkit': pcapkit})
                except (ImportError, AttributeError) as error:
                    print(type(error).__name__, error, sep=': ')
        ''')
        result = run(('-c', code), blocked=EXTRA_MODULES)
        self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            str(PACKAGE / 'vendor' / '__init__.py'),
            f"ModuleNotFoundError: cannot import 'EtherType' from 'pcapkit.vendor': {REASON}",
            f"ModuleNotFoundError: cannot import 'Vendor' from 'pcapkit.vendor': {REASON}",
            # import * reads __all__ in order, so the first crawler it names raises.
            f"ModuleNotFoundError: cannot import 'EtherType' from 'pcapkit.vendor': {REASON}",
            "AttributeError: module 'pcapkit.vendor' has no attribute 'no_such_name'",
        ])


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class PresentExtraTests(unittest.TestCase):
    """With the crawlers' dependencies installed, nothing changes."""

    def test_help_prints_the_parser_help(self) -> None:
        from pcapkit.vendor.__main__ import get_parser

        result = run(RUN_MODULE, '--help')
        self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
        with mock.patch.dict(os.environ, child_env(), clear=True):
            expected = get_parser().format_help()
        self.assertEqual(result.stdout, expected)


class ChildEnvTests(unittest.TestCase):
    """:func:`child_env` on either build, with :data:`FREE_THREADED` patched (#1961)."""

    #: The warning as a free-threaded build words it, for a module named in turn.
    GIL_WARNING = ('The global interpreter lock (GIL) has been enabled to load module {!r}, '
                   'which has not declared that it can run safely without the GIL. To '
                   'override this behavior and keep the GIL disabled (at your own risk), '
                   'run with PYTHON_GIL=0 or -Xgil=0.')

    def warn_in_a_child(self, env: 'dict[str, str]', module: str) -> 'subprocess.CompletedProcess[str]':
        """Emit :attr:`GIL_WARNING` for ``module`` in a child interpreter run under ``env``."""
        code = f'import warnings; warnings.warn({self.GIL_WARNING.format(module)!r}, RuntimeWarning)'
        return subprocess.run([sys.executable, '-c', code], env=env,  # nosec: B603
                              capture_output=True, text=True,
                              timeout=scale_timeout(120), check=False)

    def test_a_free_threaded_build_ignores_the_lxml_gil_warning(self) -> None:
        with mock.patch.object(sys.modules[__name__], 'FREE_THREADED', True):
            env = child_env()
        self.assertEqual(env.get('PYTHONWARNINGS'), LXML_GIL_FILTER)
        result = self.warn_in_a_child(env, 'lxml.etree')
        self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)

    def test_the_filter_keeps_the_warning_for_another_module(self) -> None:
        with mock.patch.object(sys.modules[__name__], 'FREE_THREADED', True):
            env = child_env()
        result = self.warn_in_a_child(env, 'not_lxml')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RuntimeWarning: The global interpreter lock (GIL) has been enabled "
                      "to load module 'not_lxml'", result.stderr)

    def test_a_build_with_the_gil_sets_no_filter(self) -> None:
        with mock.patch.object(sys.modules[__name__], 'FREE_THREADED', False), \
                mock.patch.dict(os.environ, PYTHONWARNINGS='default'):
            self.assertNotIn('PYTHONWARNINGS', child_env())


class MainTests(unittest.TestCase):
    """:func:`~pcapkit.vendor.__main__.main` in this interpreter, with ``_MISSING`` patched."""

    def test_main_reports_on_one_line_and_runs_no_target(self) -> None:
        import pcapkit.vendor
        import pcapkit.vendor.__main__ as vendor_main

        stderr = io.StringIO()
        with mock.patch.object(pcapkit.vendor, '_MISSING', ['requests', 'beautifulsoup4']), \
                mock.patch.object(vendor_main, 'run', side_effect=AssertionError('a target ran')) as runner, \
                mock.patch.object(sys, 'argv', ['pcapkit-vendor']), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(vendor_main.main(), 1)
        runner.assert_not_called()
        self.assertEqual(stderr.getvalue().splitlines(), [MESSAGE])


if __name__ == '__main__':
    unittest.main()
