# -*- coding: utf-8 -*-
"""The tier guard's own tests.

:mod:`tests._tiers` stops a unit-tier module from reading a generated sample
capture. It is the kind of code that is only exercised when somebody makes the
mistake it exists to catch, so it needs tests of its own -- a guard that has
quietly stopped working is worse than no guard, because everybody has stopped
looking.

Four things are worth pinning, and they are the four ways this could rot:

* the tier rule here still matches the one CI runs
  (:class:`TierClassificationTests`, :class:`WorkflowAgreementTests`);
* committedness comes from git rather than from a list of names that goes stale
  the moment another capture is committed (:class:`CommittedCaptureTests`);
* a violation is caught and explained, the legitimate reads next to it are not,
  and several violations in one module are listed in the order those violations
  appear in the file rather than in the order a tree walk happened to reach them
  (:class:`AuditTests`, :class:`RuntimeCheckTests`);
* the suite as it stands is clean (:class:`SuiteIsCleanTests`), and a checkout
  without git degrades instead of failing (:class:`DegradationTests`).

This module is itself unit-tier, so it reads no capture at all: the violating
modules it needs are written into a temporary directory and audited by path.

"""
from __future__ import annotations

import ast
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest
import unittest.mock

from tests import _tiers

#: The unit-tier workflow job, for :class:`WorkflowAgreementTests`. Absent from a
#: source distribution, which is why that test skips rather than fails.
WORKFLOW = _tiers.ROOT / '.github' / 'workflows' / 'unit-tests.yml'


def write_module(directory: 'pathlib.Path', name: 'str', source: 'str') -> 'pathlib.Path':
    """Write ``source`` to ``directory/name`` and return the path.

    The audit reads modules off disk by path and does not import them, so a
    throwaway file in a temporary directory is enough to drive it -- and keeps a
    deliberately-wrong ``sample_path`` call out of a module :program:`pytest`
    collects, which would trip the very guard under test.

    The leading newline of the triple-quoted literal is stripped as well as the
    indentation, so that the line numbers the assertions quote are the ones a
    reader counts off the literal.

    """
    path = directory / name
    path.write_text(textwrap.dedent(source).lstrip('\n'), encoding='utf-8')
    return path


def job_section(text: 'str', name: 'str') -> 'str':
    """The YAML text of job ``name``, from its header to the next top-level job.

    A plain slice rather than a real YAML parse: :class:`WorkflowAgreementTests`
    and :class:`FixtureTierSelectionTests` both need to know what one job's
    steps say without tripping over another job that happens to mention the
    same words, and a two-space-indented ``key:`` line is what marks a job
    boundary in this file however its body is written.

    """
    match = re.search(rf'(?m)^  {re.escape(name)}:\n(.*?)(?=^  \w[\w-]*:\n|\Z)', text, re.DOTALL)
    if match is None:
        raise AssertionError(f'no job named {name!r} found in the workflow')
    return match.group(1)


def step_run_block(section: 'str', step_name: 'str') -> 'str':
    """The ``run:`` block of the step named ``step_name`` within a job section.

    Scoped to one step, not just one job, because a job can hold several
    steps and only one of them is the one a test cares about -- see
    :func:`job_section` for why a text slice rather than a YAML parse.

    """
    match = re.search(
        rf'(?m)^      - name: {re.escape(step_name)}\n(.*?)(?=^      - name:|\Z)',
        section, re.DOTALL,
    )
    if match is None:
        raise AssertionError(f'no step named {step_name!r} found in this job')
    return match.group(1)


class TierClassificationTests(unittest.TestCase):
    """:func:`~tests._tiers.is_unit_tier` against the CI ignore rules."""

    def test_tier_is_decided_by_path(self) -> None:
        """Each ``--ignore`` and ``--ignore-glob`` of the unit job, and a control."""
        cases = {
            'tests/corekit/test_multidict.py': True,
            'tests/test_tier_guard.py': True,
            'tests/protocols/misc/pcap/test_header_frame_unit.py': True,
            'tests/protocols/transport/test_tcp_runtime.py': False,
            'tests/protocols/test_pcapng_regression.py': False,
            'tests/integration/test_engine_parity.py': False,
            'tests/integration/nested/test_deeper.py': False,
            # Outside tests/ altogether: no tier, so not the unit tier.
            'examples/generators/pcap.py': False,
            'pcapkit/interface/core.py': False,
        }
        for relative, expected in cases.items():
            with self.subTest(module=relative):
                self.assertIs(_tiers.is_unit_tier(relative), expected)

    def test_absolute_and_relative_paths_agree(self) -> None:
        """A path is classified the same however it is spelled."""
        relative = 'tests/protocols/test_pcapng_regression.py'
        self.assertIs(_tiers.is_unit_tier(relative),
                      _tiers.is_unit_tier(_tiers.ROOT / relative))


class WorkflowAgreementTests(unittest.TestCase):
    """The tier rule here matches the one the workflow actually runs."""

    def test_ignore_flags_match_the_fixture_tier_constants(self) -> None:
        """Every ignored path and glob is accounted for by a constant.

        The point of failure this catches: somebody adds a fourth
        fixture-dependent naming convention to the workflow and the guard goes
        on classifying those modules as unit-tier, flagging their perfectly
        legal capture reads.

        """
        if not WORKFLOW.is_file():
            self.skipTest(f'{WORKFLOW} is not present, e.g. in a source distribution')

        text = WORKFLOW.read_text(encoding='utf-8')
        globs = set(re.findall(r"--ignore-glob='\*([^']+)'", text))
        directories = set(re.findall(r'--ignore=tests/(\S+)', text))

        self.assertEqual(globs, set(_tiers.FIXTURE_TIER_SUFFIXES))
        self.assertEqual(directories, set(_tiers.FIXTURE_TIER_DIRS))

    def test_integration_job_selects_positively_by_asking_tiers_for_it(self) -> None:
        """The ``integration`` job's selection runs the other direction, so it
        is checked the other way.

        The ``test`` job above is checked by parsing its ``--ignore`` /
        ``--ignore-glob`` flags out of the workflow text and comparing them to
        :data:`~tests._tiers.FIXTURE_TIER_DIRS` /
        :data:`~tests._tiers.FIXTURE_TIER_SUFFIXES` -- a *negative* selection,
        so those two regexes are what could drift from this module. The
        ``integration`` job instead *selects* the fixture-dependent tier
        positively, and a positive selection spelled out as literal paths
        would be invisible to those same regexes: nothing would stop it from
        drifting from :func:`~tests._tiers.skip_idiom_modules` while this test
        stayed green.

        So the ``integration`` job does not spell the selection out. Its "Run
        full test suite" step has to call
        :func:`~tests._tiers.fixture_tier_paths` directly instead of
        reimplementing the answer -- which makes drift structurally
        impossible rather than merely checked for, and is what this asserts.

        """
        if not WORKFLOW.is_file():
            self.skipTest(f'{WORKFLOW} is not present, e.g. in a source distribution')

        text = WORKFLOW.read_text(encoding='utf-8')
        section = job_section(text, 'integration')
        run_block = step_run_block(section, 'Run full test suite')

        self.assertIn(
            'fixture_tier_paths', run_block,
            "the integration job's \"Run full test suite\" step no longer calls "
            "tests._tiers.fixture_tier_paths() -- see this test's docstring for why a "
            "hand-written selection here can drift silently"
        )
        self.assertIn('pytest', run_block)


class EnclosingScopeTests(unittest.TestCase):
    """:func:`~tests._tiers._enclosing_scope`, on synthetic sources.

    Needs no git and no real module -- it is a pure function of an
    :mod:`ast` tree and a line number, so it is pinned the same way
    :class:`AuditTests` pins :func:`~tests._tiers.audit_module`: against
    source written for the purpose, not against whatever the suite happens to
    contain today.

    """

    def test_a_method_on_a_class_reports_both_names(self) -> None:
        tree = ast.parse(textwrap.dedent("""
            class Tests:
                def test_it(self):
                    line_two = 2
            """))
        # Line 3 is `def test_it(self):` itself; line 4 is its body.
        self.assertEqual(_tiers._enclosing_scope(tree, 4), ('Tests', 'test_it'))

    def test_a_module_level_function_reports_no_class(self) -> None:
        tree = ast.parse(textwrap.dedent("""
            def test_it():
                line_two = 2
            """))
        self.assertEqual(_tiers._enclosing_scope(tree, 3), (None, 'test_it'))

    def test_a_line_outside_every_function_reports_nothing(self) -> None:
        tree = ast.parse(textwrap.dedent("""
            class Tests:
                def test_it(self):
                    pass
            """))
        self.assertIsNone(_tiers._enclosing_scope(tree, 1))

    def test_the_innermost_function_wins_over_its_enclosing_method(self) -> None:
        """A nested helper's line belongs to the helper, not the test method.

        Not a shape the suite's own skip idiom uses today, but
        :func:`~tests._tiers.skip_idiom_test_ids` documents that "most tightly
        wrapping" is the rule, and this is what pins it.

        """
        tree = ast.parse(textwrap.dedent("""
            class Tests:
                def test_it(self):
                    def helper():
                        line_four = 4
                    helper()
            """))
        self.assertEqual(_tiers._enclosing_scope(tree, 5), ('Tests', 'helper'))

    def test_two_sibling_classes_are_not_confused(self) -> None:
        tree = ast.parse(textwrap.dedent("""
            class First:
                def test_a(self):
                    pass

            class Second:
                def test_b(self):
                    line_seven = 7
            """))
        self.assertEqual(_tiers._enclosing_scope(tree, 8), ('Second', 'test_b'))


class FixtureTierSelectionTests(unittest.TestCase):
    """:func:`~tests._tiers.skip_idiom_modules` and :func:`~tests._tiers.fixture_tier_paths`.

    Together these are what the ``integration`` job runs instead of the whole
    suite -- see :class:`WorkflowAgreementTests` for the half of the guarantee
    that lives in the workflow file itself.

    """

    def setUp(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

    def test_skip_idiom_modules_matches_an_independent_scan(self) -> None:
        """Built from the same lower-level facts, but not by calling the function.

        Re-derived here from :func:`~tests._tiers.sample_path_calls` and
        :func:`~tests._tiers.committed_captures` directly, the same way
        :class:`CommittedCaptureTests`'s
        ``test_every_tracked_name_exists_and_matches_git`` re-derives the
        committed set independently of
        :func:`~tests._tiers.committed_captures` -- calling
        :func:`~tests._tiers.skip_idiom_modules` a second time would only show
        that it agrees with itself.

        """
        tracked = _tiers.committed_captures()
        assert tracked is not None

        expected = set()
        for path in sorted(_tiers.TESTS_ROOT.rglob('*.py')):
            if not _tiers.is_unit_tier(path):
                continue
            for call in _tiers.sample_path_calls(str(path)):
                if call.handled and call.name is not None and not _tiers._is_committed(call.name, tracked):
                    expected.add(path)
                    break

        self.assertEqual(set(_tiers.skip_idiom_modules()), expected)

    def test_skip_idiom_modules_matches_a_grep_based_scan(self) -> None:
        """A second, textually independent check, catching a bug the first one could not.

        The scan above is re-derived from :func:`~tests._tiers.sample_path_calls`
        and :func:`~tests._tiers.committed_captures`, so a bug shared by those two
        primitives and :func:`~tests._tiers.skip_idiom_modules` would pass it
        undetected -- all three would agree with each other and still be wrong.
        This check shares nothing with them: it is a plain substring scan of the
        file text, no :mod:`ast` involved.

        Two files are excluded on purpose, not overlooked: :file:`tests/_tiers.py`
        itself and :file:`tests/test_tier_guard.py`, this module. Both mention
        ``sample_path(`` and ``except FileNotFoundError`` freely -- in
        docstrings, in error messages, and in source strings ``write_module()``
        writes out for other tests to audit -- without containing a single real
        call to either. A first version of this check included them and failed
        immediately for exactly that reason, which is the point: a check that
        cannot fail is not a check.

        Restricted to ``test_*.py`` for the same reason :mod:`pytest` itself
        is (see ``python_files`` in :file:`pyproject.toml`): a module outside
        that pattern is not a test module regardless of what
        :func:`~tests._tiers.is_unit_tier` says about its path, and
        :file:`tests/_tiers.py` is the case in point.

        """
        grep_matches = set()
        for path in sorted(_tiers.TESTS_ROOT.rglob('test_*.py')):
            if path == _tiers.TESTS_ROOT / 'test_tier_guard.py':
                continue
            if not _tiers.is_unit_tier(path):
                continue
            text = path.read_text(encoding='utf-8')
            if 'sample_path(' in text and 'except FileNotFoundError' in text:
                grep_matches.add(path)

        self.assertEqual(set(_tiers.skip_idiom_modules()), grep_matches)

    def test_every_handled_call_names_a_literal_capture(self) -> None:
        """A computed name inside a handler would be invisible to the scan above.

        Pins today's fact that no unit-tier module needs the computed case, so
        that the day one does, this fails loudly instead of that module's
        fixture-backed coverage silently dropping out of
        :func:`~tests._tiers.fixture_tier_paths` -- see
        :func:`~tests._tiers.skip_idiom_modules`'s docstring for the mechanism.

        """
        for path in sorted(_tiers.TESTS_ROOT.rglob('*.py')):
            if not _tiers.is_unit_tier(path):
                continue
            for call in _tiers.sample_path_calls(str(path)):
                if call.handled and call.name is None:
                    self.fail(
                        f'{path.relative_to(_tiers.ROOT)}:{call.lineno} handles a computed '
                        f'sample_path() call -- skip_idiom_modules() cannot tell whether it '
                        f'reads a generated capture and may need including by hand'
                    )

    def test_skip_idiom_test_ids_resolve_to_a_real_method_in_a_skip_idiom_module(self) -> None:
        """Every node ID names a method that really exists, in a module the
        module-level scan above also flagged.

        Checked by parsing the module independently with :mod:`ast` rather
        than by importing it -- unit-tier modules are not meant to be imported
        outside pytest collecting them, and a static check is enough to prove
        the node ID is not simply wrong.

        """
        skip_idiom = {module.relative_to(_tiers.ROOT).as_posix() for module in _tiers.skip_idiom_modules()}

        for node_id in _tiers.skip_idiom_test_ids():
            with self.subTest(node_id=node_id):
                parts = node_id.split('::')
                self.assertGreaterEqual(len(parts), 2, f'{node_id!r} is not a module::function node ID')
                relative, *scope = parts
                self.assertIn(relative, skip_idiom, f'{relative} was not flagged by skip_idiom_modules()')

                tree = ast.parse((_tiers.ROOT / relative).read_text(encoding='utf-8'))
                node = tree  # type: ast.AST
                for name in scope:
                    found = next(
                        (child for child in ast.walk(node)
                         if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                         and child.name == name),
                        None,
                    )
                    self.assertIsNotNone(found, f'{node_id}: no definition named {name!r} in {relative}')
                    node = found

    def test_fixture_tier_paths_includes_every_component(self) -> None:
        """The directory, suffix, and skip-idiom components are all present."""
        paths = _tiers.fixture_tier_paths()
        self.assertIn('tests/integration', paths)

        for path in sorted(_tiers.TESTS_ROOT.rglob('*.py')):
            relative_to_tests = path.relative_to(_tiers.TESTS_ROOT)
            under_fixture_dir = not _tiers.FIXTURE_TIER_DIRS.isdisjoint(relative_to_tests.parts[:-1])
            if under_fixture_dir:
                continue
            if path.name.endswith(_tiers.FIXTURE_TIER_SUFFIXES):
                with self.subTest(module=str(relative_to_tests)):
                    self.assertIn(path.relative_to(_tiers.ROOT).as_posix(), paths)

        for node_id in _tiers.skip_idiom_test_ids():
            with self.subTest(node_id=node_id):
                self.assertIn(node_id, paths)

    def test_fixture_tier_paths_never_selects_a_pure_unit_tier_module(self) -> None:
        """The property the whole partition depends on: nothing runs twice.

        Every entry is either outside the unit tier by
        :func:`~tests._tiers.is_unit_tier`, or is a
        :func:`~tests._tiers.skip_idiom_test_ids` node ID scoped to one method
        of a :func:`~tests._tiers.skip_idiom_modules` module -- never a
        unit-tier module, or a bare unit-tier module path with no ``::``
        scope, or the ``test`` and ``integration`` jobs would be back to
        running the same test twice.

        """
        skip_idiom = set(_tiers.skip_idiom_modules())
        node_ids = set(_tiers.skip_idiom_test_ids())
        paths = _tiers.fixture_tier_paths()
        self.assertTrue(paths, 'fixture_tier_paths() returned nothing')

        for entry in paths:
            with self.subTest(entry=entry):
                if '::' in entry:
                    # A skip-idiom node ID: legal only when it is one of the
                    # exact IDs skip_idiom_test_ids() names -- not merely a
                    # module skip_idiom_modules() flagged, which would still
                    # pull the whole file in and reintroduce the duplication
                    # this split exists to avoid.
                    self.assertIn(entry, node_ids)
                    continue

                candidate = _tiers.ROOT / entry
                if candidate.is_dir():
                    continue  # a directory argument, e.g. tests/integration
                self.assertTrue(candidate.is_file(), f'{entry} does not exist')
                if _tiers.is_unit_tier(candidate):
                    self.assertIn(
                        candidate, skip_idiom,
                        f'{entry} is a bare unit-tier module path, not a node ID scoped to one '
                        f'of its methods -- it would run in both the test and integration jobs'
                    )


class CommittedCaptureTests(unittest.TestCase):
    """Committedness is asked of git, not remembered."""

    def setUp(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

    def test_committed_set_comes_from_the_index(self) -> None:
        """A committed capture is in the set and a generated one is not.

        ``in.pcap`` and ``test.pcap`` sit in the same directory and are
        indistinguishable by name -- the only thing that separates them is that
        git tracks one of them.

        """
        tracked = _tiers.committed_captures()
        assert tracked is not None
        self.assertIn('in.pcap', tracked)
        self.assertNotIn('test.pcap', tracked)

    def test_every_tracked_name_exists_and_matches_git(self) -> None:
        """The set is the index's answer verbatim, prefix stripped.

        "Verbatim" is checked by re-deriving the index here, independently of
        :func:`~tests._tiers.committed_captures` -- a second call to that same
        function would only prove it agrees with itself, not that it agrees
        with git. A hardcoded, stale, or otherwise wrong literal set would fail
        the comparison below; it could only have passed the old body, which
        asserted nothing but non-emptiness and the absence of a ``/``.

        """
        tracked = _tiers.committed_captures()
        assert tracked is not None
        self.assertTrue(tracked, 'git tracks no capture at all, which cannot be right')

        relative_root = _tiers.SAMPLE_ROOT.relative_to(_tiers.ROOT).as_posix()
        # Shell out directly rather than through `_tiers._git` -- going through
        # the implementation's own helper would only show that
        # `committed_captures()` agrees with itself, not with git. The failure
        # tolerance mirrors `_git`'s for the same reason it exists there: no
        # executable, no repository, or a non-zero exit is "cannot tell", not
        # "the sets disagree", and a source tarball's test run should not fail
        # for a rule it cannot possibly break.
        try:
            completed = subprocess.run(
                ('git', 'ls-files', '-z', '--', relative_root),
                cwd=str(_tiers.ROOT), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.skipTest(f'git ls-files could not be run independently: {exc}')
        if completed.returncode != 0:
            self.skipTest('git ls-files exited non-zero on a fresh, independent re-derivation')

        listing = completed.stdout.decode('utf-8', 'surrogateescape')
        prefix = relative_root + '/'
        expected = {
            entry[len(prefix):] for entry in listing.split('\0')
            if entry and entry.startswith(prefix)
        }
        self.assertEqual(
            tracked, expected,
            'committed_captures() disagrees with a freshly re-derived `git ls-files`'
        )

        for name in tracked:
            with self.subTest(capture=name):
                self.assertNotIn('/', name, 'names are relative to examples/captures/')
                self.assertTrue(
                    (_tiers.SAMPLE_ROOT / name).is_file(),
                    f'git tracks examples/captures/{name} but it is not on disk'
                )

    def test_capture_suggestions_are_captures(self) -> None:
        """The suggestion is the tracked set filtered to captures and sorted.

        Equality against a set built independently of
        :func:`~tests._tiers.committed_capture_names` is the point, but on an
        empty tracked set it holds vacuously -- both sides would be ``()`` --
        so the ``assertTrue`` guard below comes first, the same guard its
        sibling ``test_every_tracked_name_exists_and_matches_git`` carries for
        the same reason. Only past that guard do the two example-name
        assertions add anything: they are satisfied by any list that happens
        to contain ``in.pcap`` and omit ``out.txt``, hardcoded or not, so they
        stay a readable sanity check on top of the real one rather than the
        thing holding the test up.

        """
        tracked = _tiers.committed_captures()
        assert tracked is not None
        self.assertTrue(tracked, 'git tracks no capture at all, which cannot be right')
        expected = tuple(sorted(name for name in tracked if name.endswith(_tiers.CAPTURE_SUFFIXES)))

        suggestions = _tiers.committed_capture_names()
        self.assertEqual(suggestions, expected)
        self.assertIn('in.pcap', suggestions)
        self.assertNotIn('out.txt', suggestions)


class AuditTests(unittest.TestCase):
    """:func:`~tests._tiers.audit_module` on modules written for the purpose."""

    def setUp(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-tier-guard-')
        self.addCleanup(tmpdir.cleanup)
        self.tmp_path = pathlib.Path(tmpdir.name)

    def test_generated_capture_is_flagged(self) -> None:
        """The mistake the guard exists for, and what it says about it."""
        module = write_module(self.tmp_path, 'test_wrong_unit.py', """
            from tests._support import sample_path


            def test_reads_a_generated_capture():
                assert sample_path('test.pcap')
            """)

        findings = _tiers.audit_module(module)
        self.assertEqual(len(findings), 1)

        message = findings[0]
        self.assertIn('test_wrong_unit.py:5', message)
        self.assertIn("'test.pcap'", message)
        self.assertIn('generated fixture', message)
        self.assertIn('must not depend on a generated fixture', message)
        # The two real ways out have to be named, or the message only tells the
        # reader that they are wrong and not what to do instead.
        self.assertIn('in.pcap', message)
        self.assertIn('*_runtime.py', message)
        self.assertIn('tests/integration/', message)
        self.assertIn(_tiers.REGENERATE_SAMPLES_CMD, message)

    def test_committed_capture_is_not_flagged(self) -> None:
        """The same call with a committed capture is fine."""
        module = write_module(self.tmp_path, 'test_right_unit.py', """
            from tests._support import sample_path


            def test_reads_a_committed_capture():
                assert sample_path('in.pcap')
            """)
        self.assertEqual(_tiers.audit_module(module), [])

    def test_handled_absence_is_not_flagged(self) -> None:
        """The skip idiom opts a call out, because it is tier-safe already."""
        module = write_module(self.tmp_path, 'test_handled_unit.py', """
            import unittest

            from tests._support import sample_path


            class Tests(unittest.TestCase):
                def test_skips_without_the_fixture(self):
                    try:
                        path = sample_path('test.pcap')
                    except FileNotFoundError as exc:
                        self.skipTest(str(exc))
                    assert path
            """)
        self.assertEqual(_tiers.audit_module(module), [])

    def test_handler_elsewhere_in_the_module_does_not_opt_a_call_out(self) -> None:
        """Only the guarded ``try`` body counts, not the whole module."""
        module = write_module(self.tmp_path, 'test_partly_handled_unit.py', """
            import unittest

            from tests._support import sample_path


            class Tests(unittest.TestCase):
                def test_handled(self):
                    try:
                        assert sample_path('test.pcap')
                    except FileNotFoundError as exc:
                        self.skipTest(str(exc))

                def test_unhandled(self):
                    assert sample_path('http6.cap')
            """)

        findings = _tiers.audit_module(module)
        self.assertEqual(len(findings), 1)
        self.assertIn("'http6.cap'", findings[0])

    def test_an_else_clause_is_not_a_handler(self) -> None:
        """A call in ``try``/``else`` is outside the protected body."""
        module = write_module(self.tmp_path, 'test_else_unit.py', """
            import unittest

            from tests._support import sample_path


            class Tests(unittest.TestCase):
                def test_reads_in_the_else_clause(self):
                    try:
                        pass
                    except FileNotFoundError:
                        self.skipTest('no fixture')
                    else:
                        assert sample_path('test.pcap')
            """)
        self.assertEqual(len(_tiers.audit_module(module)), 1)

    def test_a_computed_name_is_left_to_the_runtime_check(self) -> None:
        """A static pass cannot know the name, and does not guess at one."""
        module = write_module(self.tmp_path, 'test_computed_unit.py', """
            from tests._support import sample_path

            CAPTURES = ('test.pcap', 'http6.cap')


            def test_reads_several_captures():
                for capture in CAPTURES:
                    assert sample_path(capture)
            """)

        self.assertEqual(_tiers.audit_module(module), [])
        calls = _tiers.sample_path_calls(str(module))
        self.assertEqual([call.name for call in calls], [None])

    def test_a_qualified_call_is_recognised(self) -> None:
        """``_support.sample_path(...)`` counts as much as the bare name."""
        module = write_module(self.tmp_path, 'test_qualified_unit.py', """
            from tests import _support


            def test_reads_a_generated_capture():
                assert _support.sample_path('test.pcap')
            """)
        self.assertEqual(len(_tiers.audit_module(module)), 1)

    def test_a_module_that_never_mentions_the_helper_is_cheap_and_clean(self) -> None:
        """The fast path: no ``sample_path``, nothing parsed, nothing found."""
        module = write_module(self.tmp_path, 'test_unrelated_unit.py', """
            def test_arithmetic():
                assert 1 + 1 == 2
            """)
        self.assertEqual(_tiers.audit_module(module), [])
        self.assertEqual(_tiers.sample_path_calls(str(module)), ())

    def test_calls_and_findings_come_out_in_source_order(self) -> None:
        """Four violations at three nesting depths, reported top to bottom.

        The arrangement is the whole test, and the module below is wrong for the
        walk in two independent ways, because each half of the ``(lineno,
        col_offset)`` sort key needs a case that fails without it.

        Across lines, ``lineno``: :func:`ast.walk` is breadth-first, so it reaches
        the *shallowest* call first however late in the file it is written. Here
        the earliest call is the most deeply nested one and the latest is at module
        level, so an unsorted collection reports lines 14, 11, 7, 7 -- the file
        read backwards.

        Within line 7, ``col_offset``: the two calls there are the ``body`` and the
        ``test`` of a conditional expression, and :class:`ast.IfExp` stores its
        fields ``test, body, orelse`` while source writes them ``body, test,
        orelse``. The walk therefore reaches ``'http6.cap'`` before
        ``'test.pcap'``, which is written to its left, and sorting on ``lineno``
        alone preserves that -- a stable sort leaves a tie in walk order. Only
        ``col_offset`` puts the pair back.

        A tuple of two calls, which is what this module used to hold here, pins
        neither half: :class:`ast.Tuple` keeps its elements in one field list, so
        the walk yields them left to right already and the test passed with
        ``col_offset`` dropped. :class:`ast.Dict` is the other shape that gets a
        single line wrong, since all of its ``keys`` are walked before any of its
        ``values``.

        """
        module = write_module(self.tmp_path, 'test_order_unit.py', """
            from tests._support import sample_path


            class Tests:
                def test_from_a_nested_function(self):
                    def helper():
                        return sample_path('test.pcap') if sample_path('http6.cap') else None
                    return helper()

                def test_from_a_method(self):
                    return sample_path('http.cap')


            TOP_LEVEL = sample_path('dhcp_big_endian.pcapng')
            """)

        expected = [(7, 'test.pcap'), (7, 'http6.cap'), (11, 'http.cap'),
                    (14, 'dhcp_big_endian.pcapng')]

        calls = _tiers.sample_path_calls(str(module))
        self.assertEqual([(call.lineno, call.name) for call in calls], expected)

        # audit_module emits one finding per call and inherits this order, which is
        # what the reader of a failed collection actually sees. Matched on the
        # capture name as well as the line, because the two calls on line 7 share a
        # line and the name is the only thing that distinguishes them -- so this is
        # the assertion that catches a lost col_offset in the diagnostic itself.
        findings = _tiers.audit_module(module)
        pattern = re.compile(r":(\d+) is a unit-tier test module and reads '([^']+)'")
        located = [pattern.search(finding) for finding in findings]
        self.assertTrue(all(match is not None for match in located), findings)
        self.assertEqual([(int(match.group(1)), match.group(2))
                          for match in located if match is not None], expected)

    def test_an_unparseable_module_is_not_this_guards_problem(self) -> None:
        """A syntax error is reported by pytest, far better than from here."""
        module = write_module(self.tmp_path, 'test_broken_unit.py', """
            def test_broken(:
                sample_path('test.pcap')
            """)
        self.assertEqual(_tiers.audit_module(module), [])


class RuntimeCheckTests(unittest.TestCase):
    """:func:`~tests._tiers.check_unit_tier_read`, the call-time half."""

    #: A unit-tier path that does not exist. Tier membership is a property of the
    #: path, so nothing needs to be on disk to ask about it -- and using a real
    #: module would tie these assertions to that module's line numbers.
    UNIT_MODULE = str(_tiers.TESTS_ROOT / 'protocols' / 'test_imaginary_unit.py')
    #: The same, in a fixture-dependent tier.
    RUNTIME_MODULE = str(_tiers.TESTS_ROOT / 'protocols' / 'test_imaginary_runtime.py')
    INTEGRATION_MODULE = str(_tiers.TESTS_ROOT / 'integration' / 'test_imaginary.py')

    def setUp(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

    def test_unit_tier_read_of_a_generated_capture_is_refused(self) -> None:
        problem = _tiers.check_unit_tier_read('test.pcap', self.UNIT_MODULE, 12)
        self.assertIsNotNone(problem)
        assert problem is not None
        self.assertIn('test_imaginary_unit.py:12', problem)

    def test_unit_tier_read_of_a_committed_capture_is_allowed(self) -> None:
        self.assertIsNone(_tiers.check_unit_tier_read('in.pcap', self.UNIT_MODULE, 12))

    def test_fixture_dependent_tiers_may_read_anything(self) -> None:
        for module in (self.RUNTIME_MODULE, self.INTEGRATION_MODULE):
            with self.subTest(module=module):
                self.assertIsNone(_tiers.check_unit_tier_read('test.pcap', module, 12))

    def test_an_unknown_caller_is_allowed(self) -> None:
        """No ``__file__``, no tier, no judgement."""
        self.assertIsNone(_tiers.check_unit_tier_read('test.pcap', None, None))

    def test_the_decision_does_not_depend_on_the_capture_being_present(self) -> None:
        """The property that makes this fire locally rather than only in CI.

        Asked of a capture that is certainly on disk -- ``in.pcap``, which is
        committed -- while git is made to say it tracks nothing. The read is
        still refused, which is the point: the decision is "is this tracked",
        never "is this here". A guard that waited for the file to be missing
        would go on passing on every machine that has run ``make samples``,
        which is the late failure it exists to replace.

        """
        self.assertTrue((_tiers.SAMPLE_ROOT / 'in.pcap').is_file())

        with unittest.mock.patch.object(_tiers, 'committed_captures',
                                        return_value=frozenset()):
            problem = _tiers.check_unit_tier_read('in.pcap', self.UNIT_MODULE, 12)

        self.assertIsNotNone(problem)
        assert problem is not None
        self.assertIn("'in.pcap'", problem)


class SuiteIsCleanTests(unittest.TestCase):
    """The suite as it stands satisfies the rule."""

    def test_no_unit_tier_module_depends_on_a_generated_capture(self) -> None:
        """Every unit-tier module on disk, not merely the collected ones.

        :file:`tests/conftest.py` audits what the current invocation collected,
        which is the whole unit tier in CI but only a slice of it when somebody
        runs one directory. This covers the rest, so a violation added to a
        module that a narrow run never touches still has something looking at it.

        """
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        findings = []  # type: list[str]
        for path in sorted(_tiers.TESTS_ROOT.rglob('*.py')):
            if _tiers.is_unit_tier(path):
                findings.extend(_tiers.audit_module(path))

        self.assertEqual(findings, [], '\n\n'.join(findings))


class DegradationTests(unittest.TestCase):
    """Without git the guard stands down rather than guessing."""

    def test_audit_finds_nothing_when_git_cannot_answer(self) -> None:
        """A source tarball has no index, so nothing can be called generated."""
        with tempfile.TemporaryDirectory(prefix='pcapkit-tier-guard-') as tmpdir:
            module = write_module(pathlib.Path(tmpdir), 'test_wrong_unit.py', """
                from tests._support import sample_path


                def test_reads_a_generated_capture():
                    assert sample_path('test.pcap')
                """)

            with unittest.mock.patch.object(_tiers, 'committed_captures', return_value=None):
                self.assertEqual(_tiers.audit_module(module), [])

    def test_runtime_check_allows_everything_when_git_cannot_answer(self) -> None:
        with unittest.mock.patch.object(_tiers, 'committed_captures', return_value=None):
            self.assertIsNone(_tiers.check_unit_tier_read(
                'test.pcap', RuntimeCheckTests.UNIT_MODULE, 12))

    def test_a_git_failure_yields_a_reason_rather_than_an_exception(self) -> None:
        """``_git`` swallows every way the subprocess can fail."""
        for failure in (OSError('no git'), FileNotFoundError('no git')):
            with self.subTest(failure=type(failure).__name__):
                with unittest.mock.patch('subprocess.run', side_effect=failure):
                    self.assertIsNone(_tiers._git('rev-parse', '--show-toplevel'))
