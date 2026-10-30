# -*- coding: utf-8 -*-
"""Tests for :file:`util/bump_version.py`, the version bump the vendor cron runs.

The script moves ``__version__`` in :file:`pcapkit/__init__.py` on and, since the
owner asked for it -- he pointed out that the version is also cited in
:file:`CITATION.cff` and that the bump script might need to handle that as well
(#625; no issue exists for it) -- the ``version`` and ``date-released`` fields
of :file:`CITATION.cff` with it.

Why the citation half is tested against a fixture
-------------------------------------------------

Every test here builds a minimal Citation File Format 1.2.0 document in a
temporary directory. None of them touches the repository's own
:file:`CITATION.cff`, for the plain reason that a test which rewrites a tracked
file passes once and then fails, having left the version bumped in the working
tree. The fixture also lets the awkward shapes be tested at all -- a file with no
``date-released``, a file with no ``version``, CRLF endings, a nested ``version``
belonging to a ``references`` entry -- none of which the real file has and none of
which it should be contorted into having.

The exception is :class:`RepositoryCitationTests`, which reads the real file but
only ever *reads* it. That one is a gate rather than a unit test: it fails when
:file:`CITATION.cff` has drifted from ``pcapkit.__version__``, which is what the
version changes made by hand would otherwise do, since they never run this script
at all. It reads :file:`pcapkit/__init__.py` as text rather than importing
:mod:`pcapkit`, because the question is what the file in the repository says, and
an installed copy elsewhere on ``sys.path`` would answer a different one.

Calling ``main``
----------------

:func:`~bump_version.main` is called once, with the version reader and
:func:`~bump_version.init_path` patched and the working directory moved into the
scratch tree, because it ends by writing ``conda/build`` relative to the working
directory and by resolving :file:`pcapkit/__init__.py` through
``pcapkit.__path__``; unpatched, it would rewrite the checkout running the tests.
That one call pins what a bump writes into ``date-released`` (#2163). Otherwise
the pieces it wires together are each tested directly, and the ordering
property that matters -- that the one fatal outcome is reached before any file is
written -- is structural:
:func:`~bump_version.plan_citation` takes text and returns text, so it has nothing
to write with.

"""

from __future__ import annotations

import contextlib
import datetime
import importlib.util
import io
import os
import pathlib
import re
import tempfile
import unittest
from unittest import mock

from packaging.version import Version

#: Test tier (#1958): drives util/bump_version.py, which runs on one interpreter.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: A minimal document that ``cffconvert --validate`` accepts, carrying the two
#: traps the rewrite has to survive: ``cff-version`` at column zero, which shares
#: the ``version`` suffix but must never move, and an indented ``version`` under a
#: ``references`` entry, which belongs to that reference and not to this software.
FIXTURE = """\
# A comment that has to survive the rewrite.
cff-version: 1.2.0
message: If you use this software, please cite it as below.
title: Fixture
abstract: A citation file that exists only to be rewritten.
type: software
authors:
  - given-names: Ada
    family-names: Lovelace
license: BSD-3-Clause
version: 1.5.0b4
date-released: '2026-09-20'
keywords:
  - fixture
references:
  - type: software
    title: Some Dependency
    version: 9.9.9
    authors:
      - name: Anonymous
"""


def _load_script():
    """Load :file:`util/bump_version.py` as a module.

    ``util/`` is a directory of scripts rather than a package, so there is no
    import path to it. Loading it by location is safe because the bump runs under
    a ``__main__`` guard; without it, importing the module would rewrite two files
    as a side effect.

    """
    path = ROOT / 'util' / 'bump_version.py'
    spec = importlib.util.spec_from_file_location('bump_version', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bump_version = _load_script()


class CitationTreeMixin:
    """Gives each test a scratch directory and a fixture citation file."""

    def setUp(self) -> None:
        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-bump-version-')
        self.addCleanup(tmpdir.cleanup)
        self.tmp_path = pathlib.Path(tmpdir.name)

    def write_citation(self, text: str = FIXTURE, name: str = 'CITATION.cff') -> pathlib.Path:
        """Write ``text`` to the scratch directory and return its path."""
        path = self.tmp_path / name
        path.write_text(text, encoding='utf-8')
        return path


class CitationVersionTests(CitationTreeMixin, unittest.TestCase):
    """The ``version`` field, which is the field the owner asked about."""

    def test_the_version_field_moves_to_the_new_release(self) -> None:
        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5', '2026-09-22')

        self.assertIn('\nversion: 1.5.0b5\n', rewritten,
                      f'expected the bumped version at column zero, got '
                      f'{[ln for ln in rewritten.splitlines() if ln.startswith("version:")]!r}')
        self.assertNotIn('\nversion: 1.5.0b4\n', rewritten)

    def test_the_format_version_is_not_mistaken_for_the_release_version(self) -> None:
        # ``cff-version`` names the Citation File Format revision, not the
        # software's. It sits at column zero and ends in ``version:``, so a
        # substring match rather than a prefix match would rewrite it and produce
        # a file no validator accepts.
        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5', '2026-09-22')

        self.assertIn('cff-version: 1.2.0', rewritten,
                      'the Citation File Format version was rewritten as if it were '
                      'the software version')

    def test_an_indented_version_key_belongs_to_its_own_reference(self) -> None:
        # ``references[0].version`` is the cited dependency's version. It is
        # indented, so anchoring at column zero is what leaves it alone.
        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5', '2026-09-22')

        self.assertIn('    version: 9.9.9', rewritten,
                      "a reference's own version was overwritten with this project's")

    def test_a_file_with_no_version_field_is_refused(self) -> None:
        # A file that is *present* and has no field to update means the shape has
        # changed underneath the script. Rewriting nothing while reporting success
        # is the staleness this check exists to stop, so it raises instead.
        without = '\n'.join(line for line in FIXTURE.splitlines()
                           if not line.startswith('version:')) + '\n'

        with self.assertRaises(bump_version.CitationFieldError) as error:
            bump_version.plan_citation(without, '1.5.0b5', '2026-09-22')

        self.assertIn('version:', str(error.exception))

    def test_a_space_before_the_colon_is_refused_rather_than_missed(self) -> None:
        # ``version : 1.5.0b4`` is legal YAML that this rewrite does not recognise,
        # and the refusal is what makes that safe: it fails loudly instead of
        # passing over the file having silently changed nothing.
        spaced = FIXTURE.replace('version: 1.5.0b4', 'version : 1.5.0b4')
        self.assertIn('version : 1.5.0b4', spaced, 'the fixture edit did not apply')

        with self.assertRaises(bump_version.CitationFieldError):
            bump_version.plan_citation(spaced, '1.5.0b5', '2026-09-22')

    def test_the_refusal_is_a_runtime_error(self) -> None:
        # Anything catching the ``cannot find version`` RuntimeError this script
        # raises catches this one too.
        self.assertTrue(issubclass(bump_version.CitationFieldError, RuntimeError))


class CitationDateTests(CitationTreeMixin, unittest.TestCase):
    """The ``date-released`` field, which is the judgement call rather than the ask."""

    def test_the_release_date_moves_with_the_version(self) -> None:
        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5', '2026-09-22')

        self.assertIn("date-released: '2026-09-22'", rewritten)
        self.assertNotIn("date-released: '2026-09-20'", rewritten)

    def test_the_release_date_defaults_to_today_in_utc(self) -> None:
        # Not ``date.today()``. A bump made late evening in US-Eastern has a local
        # date a day behind the UTC date of the commit the field is describing.
        opened = datetime.datetime.now(datetime.timezone.utc).date()
        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5')
        closed = datetime.datetime.now(datetime.timezone.utc).date()

        # Both bounds, so a run straddling UTC midnight does not flake.
        wanted = {f"date-released: '{day.isoformat()}'" for day in (opened, closed)}
        self.assertTrue(
            any(candidate in rewritten for candidate in wanted),
            f'expected one of {sorted(wanted)}, got '
            f'{[ln for ln in rewritten.splitlines() if ln.startswith("date-released:")]!r}',
        )

        # Where the runner's local date differs from UTC -- which is the case the
        # choice of clock exists for -- the local one must not be what was written.
        local = datetime.datetime.now().date()
        if local not in (opened, closed):
            self.assertNotIn(f"date-released: '{local.isoformat()}'", rewritten,
                             'the local date was written where UTC was required')

    def test_a_bump_dates_the_release_by_the_bump_itself(self) -> None:
        # #2163: ``date-released`` is the date of the commit that bumps the
        # version, not the date the release is distributed. So the bump writes the
        # run's own UTC date into the field, in the same write that moves
        # ``version``, rather than leaving it for a release step to fill in.
        citation = self.write_citation()
        package = self.tmp_path / 'pcapkit'
        package.mkdir()
        init = package / '__init__.py'
        init.write_text("__version__ = '1.5.0b4'\n", encoding='utf-8')
        (self.tmp_path / 'conda').mkdir()

        # ``main`` writes ``conda/build`` relative to the working directory and
        # finds ``__init__.py`` through ``pcapkit``, so both are pointed at the
        # scratch tree to keep the checkout running the tests untouched.
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.tmp_path)

        with mock.patch.object(bump_version, 'current_version', return_value='1.5.0b4'), \
                mock.patch.object(bump_version, 'init_path', return_value=str(init)):
            opened = datetime.datetime.now(datetime.timezone.utc).date()
            self.assertEqual(bump_version.main(['--citation', str(citation)]), 0)
            closed = datetime.datetime.now(datetime.timezone.utc).date()

        written = citation.read_text(encoding='utf-8')
        self.assertIn('\nversion: 1.5.0b5\n', written)
        # Both bounds, so a run straddling UTC midnight does not flake.
        wanted = {f"\ndate-released: '{day.isoformat()}'\n" for day in (opened, closed)}
        self.assertTrue(
            any(candidate in written for candidate in wanted),
            f'expected the bump to date the release {sorted(wanted)}, got '
            f'{[ln for ln in written.splitlines() if ln.startswith("date-released:")]!r}',
        )
        self.assertIn("__version__ = '1.5.0b5'", init.read_text(encoding='utf-8'))

    def test_a_file_without_a_release_date_does_not_gain_one(self) -> None:
        # The field is optional in Citation File Format 1.2.0. Inventing one would
        # assert a release date the repository never recorded.
        without = '\n'.join(line for line in FIXTURE.splitlines()
                            if not line.startswith('date-released:')) + '\n'

        rewritten = bump_version.plan_citation(without, '1.5.0b5', '2026-09-22')

        self.assertNotIn('date-released', rewritten)
        self.assertIn('\nversion: 1.5.0b5\n', rewritten)

    def test_the_rewritten_date_is_a_string_and_not_a_yaml_date(self) -> None:
        # The quoting is why. Bare ``2026-09-22`` loads as a ``datetime.date``,
        # which is the cast the field was quoted to prevent in the first place.
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML, from the test extra, is not installed; the textual form is '
                          'asserted by test_the_release_date_moves_with_the_version')

        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5', '2026-09-22')
        loaded = yaml.safe_load(rewritten)

        self.assertIsInstance(loaded['date-released'], str)
        self.assertIsInstance(loaded['version'], str)
        self.assertEqual(loaded['version'], '1.5.0b5')
        self.assertEqual(loaded['cff-version'], '1.2.0')


class CitationFormattingTests(CitationTreeMixin, unittest.TestCase):
    """Everything the rewrite must leave exactly as it found it."""

    def test_only_the_two_fields_change(self) -> None:
        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5', '2026-09-22')

        before = FIXTURE.splitlines()
        after = rewritten.splitlines()
        self.assertEqual(len(before), len(after), 'the line count moved')

        moved = [(a, b) for a, b in zip(before, after) if a != b]
        self.assertEqual(moved, [
            ('version: 1.5.0b4', 'version: 1.5.0b5'),
            ("date-released: '2026-09-20'", "date-released: '2026-09-22'"),
        ], f'unexpected lines moved: {moved!r}')

    def test_the_comment_header_survives(self) -> None:
        # The real file opens with a comment block explaining why it omits ``doi``
        # and ``orcid``. A YAML load-and-dump round trip would drop all of it,
        # which is why the rewrite is line-oriented.
        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5', '2026-09-22')

        self.assertTrue(rewritten.startswith('# A comment that has to survive'),
                        f'lost the comment header: {rewritten[:60]!r}')

    def test_existing_quoting_is_preserved_for_each_field(self) -> None:
        # The committed file spells one of each: ``version`` bare and
        # ``date-released`` quoted. Preserving the style keeps the automated
        # commit's diff down to the value that actually moved.
        rewritten = bump_version.plan_citation(FIXTURE, '1.5.0b5', '2026-09-22')

        self.assertIn('\nversion: 1.5.0b5\n', rewritten, 'a bare value gained quotes')
        self.assertIn("\ndate-released: '2026-09-22'\n", rewritten,
                      'a quoted value lost its quotes')

    def test_a_quoted_version_keeps_its_quotes(self) -> None:
        quoted = FIXTURE.replace('version: 1.5.0b4', "version: '1.5.0b4'")

        rewritten = bump_version.plan_citation(quoted, '1.5.0b5', '2026-09-22')

        self.assertIn("\nversion: '1.5.0b5'\n", rewritten)

    def test_a_double_quoted_value_keeps_the_same_quote_character(self) -> None:
        quoted = FIXTURE.replace("date-released: '2026-09-20'",
                                 'date-released: "2026-09-20"')

        rewritten = bump_version.plan_citation(quoted, '1.5.0b5', '2026-09-22')

        self.assertIn('\ndate-released: "2026-09-22"\n', rewritten)

    def test_a_value_with_a_trailing_comment_loses_the_comment(self) -> None:
        # An acknowledged limit rather than a defect. Telling an inline ``#``
        # comment from a ``#`` inside a quoted scalar needs the YAML round trip this
        # rewrite exists to avoid; neither line in the real file carries one, all of
        # its commentary being whole-line; and the loss would be visible in the
        # diff. Pinned here so the behaviour stays a decision rather than becoming
        # a surprise.
        commented = FIXTURE.replace('version: 1.5.0b4',
                                    'version: 1.5.0b4  # from pcapkit/__init__.py')

        rewritten = bump_version.plan_citation(commented, '1.5.0b5', '2026-09-22')

        self.assertIn('\nversion: 1.5.0b5\n', rewritten)
        self.assertNotIn('# from pcapkit/__init__.py', rewritten)

    def test_crlf_line_endings_survive(self) -> None:
        rewritten = bump_version.plan_citation(
            FIXTURE.replace('\n', '\r\n'), '1.5.0b5', '2026-09-22')

        self.assertIn('\r\nversion: 1.5.0b5\r\n', rewritten)
        self.assertNotIn('version: 1.5.0b5\n\r', rewritten)
        self.assertEqual(rewritten.count('\r\n'), rewritten.count('\n'),
                         'a bare newline was introduced into a CRLF file')

    def test_a_missing_final_newline_is_not_added(self) -> None:
        # ``version`` is the last line here, so a rewrite that appended a
        # terminator would change a byte nobody asked it to.
        truncated = 'cff-version: 1.2.0\nversion: 1.5.0b4'

        rewritten = bump_version.plan_citation(truncated, '1.5.0b5', '2026-09-22')

        self.assertEqual(rewritten, 'cff-version: 1.2.0\nversion: 1.5.0b5')


class AbsentCitationFileTests(CitationTreeMixin, unittest.TestCase):
    """The absent-file case, which is a reported skip rather than a failure.

    Not fatal on purpose. :file:`.github/workflows/cron-vendor.yml` runs the script
    in its ``Bump Version`` step, *before* ``Commit changes``, so a non-zero exit there discards
    the whole vendor crawl the run existed to produce and the release that would
    have followed. Announced rather than swallowed, because a bump that quietly
    skips a file it maintains is how the staleness starts.

    """

    def test_an_absent_file_is_reported_and_skipped(self) -> None:
        missing = self.tmp_path / 'CITATION.cff'
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            text = bump_version.read_citation(missing)

        self.assertIsNone(text)
        self.assertIn('is absent', stderr.getvalue())
        self.assertIn(str(missing), stderr.getvalue())

    def test_an_absent_file_is_not_silent(self) -> None:
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            bump_version.read_citation(self.tmp_path / 'CITATION.cff')

        self.assertNotEqual(stderr.getvalue().strip(), '',
                            'an absent citation file was skipped without a word')

    def test_a_present_file_is_returned_verbatim(self) -> None:
        path = self.write_citation()
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            text = bump_version.read_citation(path)

        self.assertEqual(text, FIXTURE)
        self.assertEqual(stderr.getvalue(), '', f'unexpected notice: {stderr.getvalue()!r}')

    def test_a_file_without_a_release_date_is_reported(self) -> None:
        without = '\n'.join(line for line in FIXTURE.splitlines()
                            if not line.startswith('date-released:')) + '\n'
        path = self.write_citation(without)
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            text = bump_version.read_citation(path)

        self.assertEqual(text, without)
        self.assertIn('date-released', stderr.getvalue())


class VersionBumpTests(unittest.TestCase):
    """:func:`~bump_version.bump`, the version arithmetic itself."""

    def test_a_prerelease_bumps_its_counter(self) -> None:
        self.assertEqual(bump_version.bump('1.5.0b4'), '1.5.0b5')
        self.assertEqual(bump_version.bump('1.5.0a1'), '1.5.0a2')
        self.assertEqual(bump_version.bump('1.5.0rc1'), '1.5.0rc2')

    def test_a_development_release_bumps_its_counter(self) -> None:
        self.assertEqual(bump_version.bump('1.5.0.dev1'), '1.5.0.dev2')

    def test_a_development_release_with_a_prerelease_segment_keeps_it(self) -> None:
        # #2459: bumping the dev counter on ``1.6.0rc1.dev2`` was dropping the
        # ``rc1`` segment, returning ``1.6.0.dev3``. Under PEP 440 a bare dev
        # release sorts *before* one carrying ``rc1``, so that "bump" actually
        # moved the version backwards.
        bumped = bump_version.bump('1.6.0rc1.dev2')
        self.assertEqual(bumped, '1.6.0rc1.dev3')

        parsed = Version(bumped)
        self.assertEqual(parsed.pre, ('rc', 1))
        self.assertEqual(parsed.dev, 3)

        # And the ordering regression the bug produced is gone: the bumped
        # version must sort after the one it was bumped from.
        self.assertGreater(parsed, Version('1.6.0rc1.dev2'))

    def test_a_development_release_with_an_alpha_or_beta_segment_keeps_it(self) -> None:
        self.assertEqual(bump_version.bump('1.6.0a1.dev1'), '1.6.0a1.dev2')
        self.assertEqual(bump_version.bump('1.6.0b2.dev5'), '1.6.0b2.dev6')

    def test_a_development_release_with_a_post_release_segment_keeps_it(self) -> None:
        # The same #2459 bug, for post-releases rather than pre-releases: the
        # dev branch rebuilt its output from ``base_version`` (major.minor.micro
        # only) plus the preserved pre-release string plus ``.devN``, but never
        # carried ``post`` forward, so ``1.6.0.post1.dev0`` bumped to
        # ``1.6.0.dev1`` -- which sorts *before* the version it was bumped from.
        bumped = bump_version.bump('1.6.0.post1.dev0')
        self.assertEqual(bumped, '1.6.0.post1.dev1')

        parsed = Version(bumped)
        self.assertEqual(parsed.post, 1)
        self.assertEqual(parsed.dev, 1)
        self.assertGreater(parsed, Version('1.6.0.post1.dev0'))

    def test_a_development_release_with_both_pre_and_post_segments_keeps_both(self) -> None:
        bumped = bump_version.bump('1.6.0rc1.post1.dev2')
        self.assertEqual(bumped, '1.6.0rc1.post1.dev3')

        parsed = Version(bumped)
        self.assertEqual(parsed.pre, ('rc', 1))
        self.assertEqual(parsed.post, 1)
        self.assertEqual(parsed.dev, 3)
        self.assertGreater(parsed, Version('1.6.0rc1.post1.dev2'))

    def test_every_dev_bump_sorts_after_its_input(self) -> None:
        # #2459 twice over: dropping ``pre`` and dropping ``post`` both produce
        # a "bumped" version that sorts *before* the input under PEP 440. Sweep
        # a grid of shapes -- plain dev, pre+dev, post+dev, pre+post+dev, each
        # with and without an epoch -- so a third dropped segment would be
        # caught here rather than requiring another hand-picked case.
        pres = (None, 'a1', 'b2', 'rc1')
        posts = (None, 'post1')
        epochs = (None, '1!')
        for epoch in epochs:
            for pre in pres:
                for post in posts:
                    epoch_str = epoch or ''
                    pre_str = pre or ''
                    post_str = ('.' + post) if post else ''
                    current = f'{epoch_str}1.6.0{pre_str}{post_str}.dev2'
                    with self.subTest(current=current):
                        bumped = bump_version.bump(current)
                        self.assertGreater(
                            Version(bumped), Version(current),
                            f'{current!r} bumped to {bumped!r}, which does not sort after it',
                        )

    def test_a_post_release_bumps_its_counter(self) -> None:
        self.assertEqual(bump_version.bump('1.3.5.post42'), '1.3.5.post43')

    def test_a_final_release_gains_post1(self) -> None:
        self.assertEqual(bump_version.bump('1.4.1'), '1.4.1.post1')

    def test_every_bumped_version_carries_a_non_numeric_suffix(self) -> None:
        # This is what makes leaving ``version`` unquoted safe in YAML: a bare
        # ``2.0`` would load as a float, and no value this function returns can.
        for current in ('1.5.0b4', '1.5.0a1', '1.5.0rc1', '1.5.0.dev1',
                        '1.3.5.post42', '1.4.1', '2.0', '3'):
            bumped = bump_version.bump(current)
            self.assertRegex(bumped, r'[a-z]',
                             f'{current!r} bumped to {bumped!r}, which YAML would '
                             f'read as a number rather than a string')


class InitRewriteTests(CitationTreeMixin, unittest.TestCase):
    """:file:`pcapkit/__init__.py`, which must be rewritten in place, its other lines kept."""

    def write_init(self, version: str = '1.5.0b4') -> pathlib.Path:
        """Write a stand-in :file:`pcapkit/__init__.py` and return its path."""
        package = self.tmp_path / 'pcapkit'
        package.mkdir(exist_ok=True)
        path = package / '__init__.py'
        path.write_text(
            '# -*- coding: utf-8 -*-\n'
            "__all__ = ['Foo']\n"
            '\n'
            '#: version number\n'
            f'__version__ = {version!r}\n',
            encoding='utf-8',
        )
        return path

    def test_the_version_assignment_is_replaced(self) -> None:
        path = self.write_init()

        bump_version.rewrite_init(str(path), '1.5.0b5')

        self.assertEqual(
            path.read_text(encoding='utf-8'),
            '# -*- coding: utf-8 -*-\n'
            "__all__ = ['Foo']\n"
            '\n'
            '#: version number\n'
            "__version__ = '1.5.0b5'\n",
        )

    def test_nothing_but_the_assignment_moves(self) -> None:
        path = self.write_init()
        before = path.read_text(encoding='utf-8').splitlines()

        bump_version.rewrite_init(str(path), '1.5.0b5')

        after = path.read_text(encoding='utf-8').splitlines()
        self.assertEqual(before[:-1], after[:-1])

    def test_the_fallback_reader_strips_the_closing_quote_and_newline(self) -> None:
        # A fallback running ``line.split('=')[1].strip(" '")`` stops at the
        # trailing newline and so returns ``"1.5.0b4'\n"`` -- quote and newline
        # included -- which ``packaging`` rejects as an invalid version. Nothing
        # in CI notices that, because the only caller installs the package first,
        # so ``import pcapkit`` always succeeds and the fallback is unreachable.
        # Forced here by making that import fail.
        self.write_init()
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.tmp_path)

        with mock.patch.dict('sys.modules', {'pcapkit': None}):
            version = bump_version.current_version()

        self.assertEqual(version, '1.5.0b4')
        # And the value is usable, which is what that fallback gets wrong.
        self.assertEqual(bump_version.bump(version), '1.5.0b5')

    def test_the_fallback_still_complains_when_there_is_no_version(self) -> None:
        package = self.tmp_path / 'pcapkit'
        package.mkdir(exist_ok=True)
        (package / '__init__.py').write_text('# nothing here\n', encoding='utf-8')
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.tmp_path)

        with mock.patch.dict('sys.modules', {'pcapkit': None}):
            with self.assertRaises(RuntimeError) as error:
                bump_version.current_version()

        self.assertIn('cannot find version', str(error.exception))


class RepositoryCitationTests(unittest.TestCase):
    """A gate: the committed :file:`CITATION.cff` must name the packaged version.

    This is the half the script cannot guarantee on its own. Measured at
    ``a41137716`` (#625): of the 159 commits that had moved ``__version__`` on
    ``main``, 40 were hand-authored and so never ran :file:`util/bump_version.py`
    -- a quarter over the project's life, and 11 of the latest 25, which is where
    ``1.4.0``, ``1.4.1``, ``1.5.0a1`` and the ``1.5.0b1`` through ``b3`` run all
    came from. Without a check here the citation metadata goes stale through
    exactly such releases.

    """

    def test_the_citation_file_names_the_packaged_version(self) -> None:
        citation = ROOT / 'CITATION.cff'
        init = ROOT / 'pcapkit' / '__init__.py'
        if not citation.is_file() or not init.is_file():
            self.skipTest('CITATION.cff is not shipped in the source distribution')

        declared = re.search(r"^__version__ = '([^']+)'",
                             init.read_text(encoding='utf-8'), re.MULTILINE)
        self.assertIsNotNone(declared, f'no __version__ assignment in {init}')

        cited = re.search(r'^version:[ \t]*[\'"]?([^\'"\s]+)',
                          citation.read_text(encoding='utf-8'), re.MULTILINE)
        self.assertIsNotNone(cited, f'no top-level version field in {citation}')

        assert declared is not None and cited is not None
        self.assertEqual(
            cited.group(1), declared.group(1),
            f'CITATION.cff cites {cited.group(1)} but pcapkit/__init__.py declares '
            f'{declared.group(1)}. util/bump_version.py keeps these in step when it '
            f'runs; a hand-made version bump has to update both.',
        )


if __name__ == '__main__':
    unittest.main()
