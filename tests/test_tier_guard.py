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

A fifth invariant lives next door and is checked here for the same reason, from
:class:`DependencyRequirementTests` onwards: the tier rule decides *which* job
collects a test, and :mod:`tests._dependency_gates` decides whether that job
installs what the test is gated on. A ``skipUnless(HAS_CRYPTO, ...)`` reached
only by a job that does not install ``cryptography`` is a test that never runs
and never says so -- #729 and #738 were that defect, and #745 is the ticket for
stopping the third instance.

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

from tests import _dependency_gates, _tiers

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


def doctored_workflow(case: 'unittest.TestCase', old: 'str', new: 'str') -> 'pathlib.Path':
    """A throwaway copy of the unit-test workflow, with ``old`` replaced by ``new``.

    The only honest way to show a guard works is to break the thing it guards
    and watch it fire, and the thing
    :class:`DependencyGateFalsifiabilityTests` guards is a file no test may edit
    in place -- so the break happens on a copy and
    :func:`~tests._dependency_gates.dependency_gate_gaps` is pointed at that.
    ``old`` has to still be present, or the test would be proving nothing about
    a workflow that has since been rewritten.

    """
    text = _dependency_gates.WORKFLOW.read_text(encoding='utf-8')
    case.assertIn(old, text, f'{old!r} is no longer in the workflow')
    tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-doctored-workflow-')
    case.addCleanup(tmpdir.cleanup)
    path = pathlib.Path(tmpdir.name) / 'unit-tests.yml'
    path.write_text(text.replace(old, new, 1), encoding='utf-8')
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


class DependencyRequirementTests(unittest.TestCase):
    """Reading :file:`pyproject.toml`, and deciding what an extra provides.

    The interesting case is an extra *of a requirement*: the ``test`` extra
    carries plain ``beautifulsoup4`` and the ``vendor`` extra carries
    ``beautifulsoup4[html5lib]``, and the difference between them is exactly the
    difference between ``HAS_CRAWLER_DEPS``, which CI satisfies, and
    ``HAS_VENDOR_DEPS``, which it does not. Collapse the two and the guard
    reports one of them wrongly.

    """

    def test_a_requirement_splits_into_name_extras_and_marker(self) -> None:
        cases = {
            'dpkt': ('dpkt', frozenset(), None),
            'cryptography>=3.4': ('cryptography', frozenset(), None),
            "pypcapfile; python_version < '3.12'":
                ('pypcapfile', frozenset(), "python_version < '3.12'"),
            'requests[socks]': ('requests', frozenset({'socks'}), None),
            'beautifulsoup4[html5lib]': ('beautifulsoup4', frozenset({'html5lib'}), None),
            "pcap-ct>=1.3.0b3; python_version >= '3.10'":
                ('pcap-ct', frozenset(), "python_version >= '3.10'"),
        }
        for text, expected in cases.items():
            with self.subTest(requirement=text):
                requirement = _dependency_gates.requirement_key(text)
                self.assertEqual(
                    (requirement.name, requirement.extras, requirement.marker), expected)
                self.assertEqual(requirement.text, text)

    def test_names_compare_per_pep_503(self) -> None:
        """``pcap_ct``, ``PCAP.CT`` and ``pcap-ct`` are one distribution."""
        for spelling in ('pcap_ct', 'PCAP.CT', 'pcap--ct', 'Pcap-CT'):
            with self.subTest(spelling=spelling):
                self.assertEqual(_dependency_gates.requirement_key(spelling).name, 'pcap-ct')

    def test_asking_for_an_extra_of_a_requirement_is_not_symmetric(self) -> None:
        """The asymmetry the whole ``HAS_VENDOR_DEPS`` verdict rests on.

        ``beautifulsoup4[html5lib]`` installs ``beautifulsoup4``, so it provides
        it. Plain ``beautifulsoup4`` does not install ``html5lib``, so it does
        not provide ``beautifulsoup4[html5lib]``. A matcher that compared only
        distribution names would call the ``test`` extra sufficient for the four
        vendor modules that need :mod:`html5lib`, and the 41 methods they hold
        would read as covered while they went on skipping.

        """
        plain = (_dependency_gates.requirement_key('beautifulsoup4'),)
        with_extra = (_dependency_gates.requirement_key('beautifulsoup4[html5lib]'),)

        self.assertTrue(_dependency_gates.provided_by(with_extra, 'beautifulsoup4'))
        self.assertTrue(_dependency_gates.provided_by(with_extra, 'beautifulsoup4[html5lib]'))
        self.assertTrue(_dependency_gates.provided_by(plain, 'beautifulsoup4'))
        self.assertFalse(_dependency_gates.provided_by(plain, 'beautifulsoup4[html5lib]'))

    def test_a_version_specifier_and_a_marker_do_not_defeat_matching(self) -> None:
        requirements = (_dependency_gates.requirement_key("pypcapfile; python_version < '3.12'"),
                        _dependency_gates.requirement_key('cryptography>=3.4'))
        self.assertTrue(_dependency_gates.provided_by(requirements, 'pypcapfile'))
        self.assertTrue(_dependency_gates.provided_by(requirements, 'cryptography'))
        self.assertFalse(_dependency_gates.provided_by(requirements, 'dpkt'))

    def test_the_extras_read_back_what_pyproject_declares(self) -> None:
        """Spot checks on the four extras the rest of this suite reasons about."""
        declared = _dependency_gates.declared_requirements()

        self.assertEqual([requirement.text for requirement in declared['crypto']],
                         ['cryptography>=3.4'])
        self.assertTrue(_dependency_gates.provided_by(declared['NGAP'], 'pycrate'))
        self.assertTrue(_dependency_gates.provided_by(declared['cli'], 'emoji'))
        # The `test` extra carries requests and bs4 (#507) but not html5lib.
        self.assertTrue(_dependency_gates.provided_by(declared['test'], 'requests'))
        self.assertTrue(_dependency_gates.provided_by(declared['test'], 'beautifulsoup4'))
        self.assertFalse(
            _dependency_gates.provided_by(declared['test'], 'beautifulsoup4[html5lib]'))
        self.assertTrue(
            _dependency_gates.provided_by(declared['vendor'], 'beautifulsoup4[html5lib]'))

    def test_a_bracket_inside_a_requirement_does_not_end_the_array(self) -> None:
        """``vendor`` is the case a "slice to the first ``]``" parse gets wrong.

        ``vendor = [ "requests[socks]", "beautifulsoup4[html5lib]" ]`` holds two
        closing brackets before its own, so a naive scan stops inside the first
        requirement and reports an extra with one malformed entry.

        """
        declared = _dependency_gates.declared_requirements()
        self.assertEqual({requirement.name for requirement in declared['vendor']},
                         {'requests', 'beautifulsoup4'})

    def test_the_core_dependencies_are_read_from_project_not_build_system(self) -> None:
        """``[build-system] requires`` also holds ``setuptools``; this is not it."""
        core = _dependency_gates.declared_requirements()[_dependency_gates.CORE]
        names = {requirement.name for requirement in core}
        self.assertLessEqual({'dictdumper', 'chardet', 'aenum', 'tbtrim'}, names)
        self.assertNotIn('setuptools', names)

    def test_every_extra_any_pytest_job_installs_is_declared(self) -> None:
        """An install line naming an extra that no longer exists resolves to nothing."""
        if not _dependency_gates.WORKFLOW.is_file():
            self.skipTest(f'{_dependency_gates.WORKFLOW} is not present')

        declared = _dependency_gates.declared_requirements()
        jobs = _dependency_gates.pytest_jobs()
        self.assertTrue(jobs, 'no job in the workflow runs pytest, which cannot be right')
        for job in jobs:
            self.assertTrue(job.extras, f'the {job.name!r} job installs no extra at all')
            for extra in job.extras:
                with self.subTest(job=job.name, extra=extra):
                    self.assertIn(extra, declared)


class DependencyGateScanTests(unittest.TestCase):
    """Finding the gates, and resolving what each flag requires.

    Driven against modules written for the purpose rather than against the
    suite, for :class:`AuditTests`' reason: each shape needs a case that fails
    without the code handling it, and several of these shapes appear exactly
    once in the real tree.

    """

    def setUp(self) -> None:
        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-dependency-gates-')
        self.addCleanup(tmpdir.cleanup)
        self.tmp_path = pathlib.Path(tmpdir.name)

    def test_class_level_and_method_level_gates_are_both_found(self) -> None:
        """The claim #745 makes: a text search misses most of them.

        Both decorators below gate tests on ``HAS_DPKT``, and the class-level
        one gates two methods through a single line. Counting decorators that
        sit next to a ``def`` finds one of the two; counting both finds the gate
        on ``Two`` that darkens ``test_a`` and ``test_b`` together.

        The line reported is the decorated ``class`` or ``def``, not the
        decorator above it -- 5 and 15 below, where the decorators are on 4 and
        14 -- because that is the line a reader is being sent to.

        """
        module = write_module(self.tmp_path, 'test_gates_unit.py', """
            import unittest


            @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
            class Two(unittest.TestCase):
                def test_a(self):
                    pass

                def test_b(self):
                    pass


            class One(unittest.TestCase):
                @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
                def test_c(self):
                    pass
            """)

        gates = _dependency_gates.module_gates(module, 'test_gates_unit.py')
        self.assertEqual(
            [(gate.flag, gate.lineno, gate.class_name, gate.func_name) for gate in gates],
            [('HAS_DPKT', 5, 'Two', None), ('HAS_DPKT', 15, 'One', 'test_c')],
        )

    def test_a_decorator_that_is_not_skip_unless_is_ignored(self) -> None:
        """``skipIf`` inverts the condition, and ``expectedFailure`` is unrelated."""
        module = write_module(self.tmp_path, 'test_other_unit.py', """
            import unittest


            class Tests(unittest.TestCase):
                @unittest.skipIf(HAS_DPKT, 'dpkt is installed')
                def test_a(self):
                    pass

                @unittest.expectedFailure
                def test_b(self):
                    pass
            """)
        self.assertEqual(_dependency_gates.module_gates(module, 'test_other_unit.py'), ())

    def test_a_module_level_function_gate_reports_no_class(self) -> None:
        module = write_module(self.tmp_path, 'test_bare_unit.py', """
            import unittest


            @unittest.skipUnless(HAS_EMOJI, 'emoji not installed')
            def test_it():
                pass
            """)
        gates = _dependency_gates.module_gates(module, 'test_bare_unit.py')
        self.assertEqual([(gate.class_name, gate.func_name) for gate in gates],
                         [(None, 'test_it')])

    def test_every_shape_the_suite_writes_a_flag_in_resolves(self) -> None:
        """Five spellings, all in use, none of them interchangeable.

        Each of these is the only shape some real module uses, so a resolver
        that handled only the obvious ``find_spec('x') is not None`` would
        silently report four of the five as gating on nothing -- and a flag that
        requires nothing can never be a gap, which is failure by silence again.

        """
        module = write_module(self.tmp_path, 'test_shapes_unit.py', """
            import importlib
            import importlib.util

            RUNTIME_DEPS = ('tbtrim', 'aenum')


            def _importable(*modules):
                for module in modules:
                    try:
                        importlib.import_module(module)
                    except ImportError:
                        return False
                return True


            def _has_pypcapfile():
                importlib.import_module('pcapfile.savefile')
                return True


            HAS_PLAIN = importlib.util.find_spec('dpkt') is not None
            HAS_TUPLE = all(importlib.util.find_spec(n) is not None for n in RUNTIME_DEPS)
            HAS_INLINE = all(importlib.util.find_spec(n) is not None
                             for n in ('requests', 'bs4'))
            HAS_HELPER_ARGS = _importable('pcap._pcap')
            HAS_HELPER_BODY = _has_pypcapfile()
            """)

        self.assertEqual(_dependency_gates.module_flag_requirements(module), {
            'HAS_PLAIN': frozenset({'dpkt'}),
            'HAS_TUPLE': frozenset({'tbtrim', 'aenum'}),
            'HAS_INLINE': frozenset({'requests', 'bs4'}),
            'HAS_HELPER_ARGS': frozenset({'pcap._pcap'}),
            'HAS_HELPER_BODY': frozenset({'pcapfile.savefile'}),
        })

    def test_a_negated_probe_is_not_a_requirement(self) -> None:
        """``HAS_PYPCAP``'s shape, and why the walk tracks polarity.

        ``_importable('pcap') and not _importable('pcap._pcap')`` is how the
        suite tells upstream ``pypcap`` from ``pcap-ct``: both ship a top-level
        ``pcap``, and only ``pcap-ct``'s is a package with that submodule. A
        flat :func:`ast.walk` would report the flag as *needing* ``pcap._pcap``
        -- the one module whose presence makes it false.

        :func:`~tests._dependency_gates.module_flag_exclusions` is the mirror
        image, pinned on the same module: it is what recovers ``pcap._pcap``
        as the thing this flag needs *absent*, which is exactly what
        :func:`~tests._dependency_gates.module_flag_requirements` correctly
        drops.

        """
        module = write_module(self.tmp_path, 'test_negated_unit.py', """
            import importlib


            def _importable(*modules):
                for module in modules:
                    try:
                        importlib.import_module(module)
                    except ImportError:
                        return False
                return True


            HAS_PYPCAP = _importable('pcap') and not _importable('pcap._pcap')
            """)
        self.assertEqual(_dependency_gates.module_flag_requirements(module),
                         {'HAS_PYPCAP': frozenset({'pcap'})})
        self.assertEqual(_dependency_gates.module_flag_exclusions(module),
                         {'HAS_PYPCAP': frozenset({'pcap._pcap'})})

    def test_a_flag_that_asks_about_something_pip_cannot_install_requires_nothing(self) -> None:
        """``HAS_PROC_FD``'s shape: no probe, so no requirement, so no gap.

        The empty set is the signal, and
        :class:`DependencyGateCoverageTests` is what insists such a flag be
        named in :data:`~tests._dependency_gates.NON_DISTRIBUTION_FLAGS` with a
        reason rather than passing because it resolved to nothing.

        """
        module = write_module(self.tmp_path, 'test_procfd_unit.py', """
            import os

            HAS_PROC_FD = os.path.isdir('/proc/self/fd')
            """)
        self.assertEqual(_dependency_gates.module_flag_requirements(module),
                         {'HAS_PROC_FD': frozenset()})

    def test_a_flag_gated_where_it_is_not_defined_resolves_through_the_import(self) -> None:
        """``HAS_EMOJI`` is defined in a helper and gated two modules away.

        Checked against the real suite rather than a synthetic pair, because the
        import has to resolve to a path on disk and that is the part which
        breaks: :file:`tests/integration/test_cli_subprocess.py` gates on a flag
        whose only definition is in :file:`tests/integration/_helpers.py`, which
        is not a ``test_*.py`` and so is never scanned for gates.

        """
        requirements = _dependency_gates.flag_requirements()
        self.assertEqual(
            requirements[('tests/integration/test_cli_subprocess.py', 'HAS_EMOJI')],
            frozenset({'emoji'}),
        )

    def test_one_flag_name_may_mean_two_things_and_is_resolved_per_module(self) -> None:
        """``HAS_RUNTIME`` is the four core dependencies, except in one module.

        :file:`tests/foundation/engines/test_runtime_engines.py` reuses the name
        for those four plus ``dpkt``, ``scapy`` and ``pyshark``. Resolved by
        name instead of per module, either that module's three extra
        requirements would be demanded of the hundred-odd others, or the
        hundred-odd would excuse it -- and it is the one HAS_RUNTIME gate in the
        suite that really does go dark.

        """
        requirements = _dependency_gates.flag_requirements()
        wide = requirements[('tests/foundation/engines/test_runtime_engines.py', 'HAS_RUNTIME')]
        narrow = requirements[('tests/corekit/test_infoclass.py', 'HAS_RUNTIME')]

        self.assertEqual(narrow, frozenset({'tbtrim', 'aenum', 'chardet', 'dictdumper'}))
        self.assertEqual(wide - narrow, frozenset({'dpkt', 'scapy', 'pyshark'}))

    def test_the_suite_scan_only_looks_at_modules_pytest_collects(self) -> None:
        """A gate in a helper module gates nothing, because nothing collects it."""
        modules = {gate.module for gate in _dependency_gates.gated_scopes()}
        self.assertTrue(modules, 'the suite has no dependency gates at all, which cannot be right')
        for module in sorted(modules):
            with self.subTest(module=module):
                self.assertTrue(pathlib.PurePosixPath(module).name.startswith('test_'))


class DependencyGateSelectionTests(unittest.TestCase):
    """Which :program:`pytest` jobs there are, and which gates each reaches."""

    def setUp(self) -> None:
        if not _dependency_gates.WORKFLOW.is_file():
            self.skipTest(f'{_dependency_gates.WORKFLOW} is not present')

    def test_only_the_jobs_that_run_pytest_are_considered(self) -> None:
        """Keyed on running the suite, not on holding an install line.

        The ``changelog`` job of this workflow installs nothing and runs a
        generator, and six of the seven other workflows install ``.[all]``
        somewhere -- which carries ``pypcapfile``, ``pyshark`` and ``scapy`` --
        without ever invoking :program:`pytest`. A guard that looked at install
        lines anywhere in :file:`.github/workflows/` would find nearly every
        extra it wanted and pass without checking anything.

        """
        text = _dependency_gates.WORKFLOW.read_text(encoding='utf-8')
        jobs = _dependency_gates.pytest_jobs()

        self.assertIn('changelog', _dependency_gates.job_sections(text))
        self.assertNotIn('changelog', {job.name for job in jobs})
        for job in jobs:
            with self.subTest(job=job.name):
                self.assertIn('python -m pytest', job_section(text, job.name))

    def test_job_sections_agrees_with_the_single_job_slice(self) -> None:
        """Two slicers over the same YAML, checked against each other.

        :func:`job_section` above answers for one named job and
        :func:`~tests._dependency_gates.job_sections` enumerates them all. They
        are separate because one is needed where the other cannot be imported,
        so this is what stops the pair from drifting.

        """
        text = _dependency_gates.WORKFLOW.read_text(encoding='utf-8')
        for name, section in _dependency_gates.job_sections(text).items():
            with self.subTest(job=name):
                self.assertEqual(section, job_section(text, name))

    def test_each_job_selection_is_one_of_the_three_recognised_shapes(self) -> None:
        """A fourth shape has to fail here rather than be guessed at.

        The three are the three the workflow uses: subtract ``--ignore`` flags
        from the whole suite (``test``), ask
        :func:`~tests._tiers.fixture_tier_paths` (``integration``), or pass no
        selection at all (``gate``). A new job selecting some fourth way would
        otherwise be classified ``'whole-suite'`` by the fallback and credited
        with reaching gates it does not run.

        """
        for job in _dependency_gates.pytest_jobs():
            with self.subTest(job=job.name):
                self.assertIn(job.selection, ('ignore', 'fixture-tier', 'whole-suite'))

        selections = {job.name: job.selection for job in _dependency_gates.pytest_jobs()}
        self.assertEqual(selections, {'test': 'ignore', 'integration': 'fixture-tier',
                                      'gate': 'whole-suite', 'engine-tests': 'ignore',
                                      'pypcap-parity': 'fixture-tier'})

    def test_the_selection_is_read_off_the_step_that_runs_pytest(self) -> None:
        """Not off the job, whose comments contradict it.

        The ``gate`` job's comment says "an unfiltered ``pytest`` run (no
        ``--ignore``, no tier selection)" and the ``integration`` job's names
        :func:`~tests._tiers.fixture_tier_paths`. Classified on the whole job
        section, ``gate`` reads as an ignore-selection job and is credited with
        reaching only the unit tier -- which would quietly excuse every
        fixture-tier gate it really does run.

        """
        text = _dependency_gates.WORKFLOW.read_text(encoding='utf-8')
        gate = job_section(text, 'gate')
        self.assertIn('--ignore', gate, 'the comment this test is about has been reworded')
        self.assertEqual(
            next(job.selection for job in _dependency_gates.pytest_jobs()
                 if job.name == 'gate'),
            'whole-suite')

    def test_a_job_whose_pytest_step_is_renamed_is_still_classified(self) -> None:
        """The step is found by what it runs, not by what it is called."""
        doctored = doctored_workflow(self, '- name: Run unit tests',
                                     '- name: Execute the unit tier')
        selections = {job.name: job.selection
                      for job in _dependency_gates.pytest_jobs(doctored)}
        self.assertEqual(selections, {'test': 'ignore', 'integration': 'fixture-tier',
                                      'gate': 'whole-suite', 'engine-tests': 'ignore',
                                      'pypcap-parity': 'fixture-tier'})

    def test_two_install_lines_in_one_pytest_job_is_refused(self) -> None:
        """Ambiguity fails loudly instead of the first line winning."""
        doctored = doctored_workflow(
            self,
            "python -m pip install -e '.[test,DPKT,crypto,NGAP]'",
            "python -m pip install -e '.[test,DPKT,crypto,NGAP]'\n"
            "          python -m pip install -e '.[Scapy]'",
        )
        with self.assertRaises(AssertionError) as caught:
            _dependency_gates.pytest_jobs(doctored)
        self.assertIn('2', str(caught.exception))

    def test_two_pytest_steps_in_one_job_is_refused(self) -> None:
        """A second selection in the same job is not silently ignored.

        Two ``pytest`` invocations in one job means two selections under one
        install line, and the guard reads the selection off exactly one step. It
        has no basis for choosing, so it says so.

        """
        doctored = doctored_workflow(
            self,
            '      - name: Run unit tests',
            '      - name: Run the unit tier first\n'
            '        run: python -m pytest -q\n'
            '\n'
            '      - name: Run unit tests',
        )
        with self.assertRaises(AssertionError) as caught:
            _dependency_gates.pytest_jobs(doctored)
        self.assertIn('steps', str(caught.exception))

    def test_the_ignore_selection_is_exactly_the_unit_tier(self) -> None:
        """Answered by :func:`~tests._tiers.is_unit_tier`, not by a second copy."""
        job = next(job for job in _dependency_gates.pytest_jobs() if job.selection == 'ignore')
        cases = {
            'tests/protocols/internet/test_esp_unit.py': True,
            'tests/integration/test_cli_subprocess.py': False,
            'tests/foundation/engines/test_new_engine_parity_runtime.py': False,
        }
        for module, expected in cases.items():
            with self.subTest(module=module):
                gate = _dependency_gates.Gate('HAS_CRYPTO', module, 1, 'Tests', None)
                self.assertIs(_dependency_gates.job_reaches(job, gate), expected)

    def test_the_whole_suite_selection_reaches_everything(self) -> None:
        job = next(job for job in _dependency_gates.pytest_jobs()
                   if job.selection == 'whole-suite')
        for module in ('tests/protocols/internet/test_esp_unit.py',
                       'tests/integration/test_cli_subprocess.py',
                       'tests/foundation/engines/test_new_engine_parity_runtime.py'):
            with self.subTest(module=module):
                gate = _dependency_gates.Gate('HAS_CRYPTO', module, 1, 'Tests', None)
                self.assertTrue(_dependency_gates.job_reaches(job, gate))

    def test_a_node_id_selection_reaches_that_method_and_not_its_neighbours(self) -> None:
        """The granularity that stops the ``integration`` job being over-credited.

        Its selection names two methods of :file:`tests/toolkit/test_dpkt_unit.py`
        rather than the file, because the rest of that file runs in the ``test``
        job. A gate on one of the two named methods' classes is reached; a gate
        on some other class of the same file is not, and crediting it would let
        a dependency the ``test`` job stopped installing look covered.

        Note which way round the class-level case goes, since it reads as
        over-broad and is not: a node ID naming *one* method of a gated class
        does reach that class's gate, because one selected test under the gate is
        enough for the job's install line to decide whether it runs. What must
        not be reached is a gate on a method the selection does not name --
        ``sibling`` below -- and that is the assertion doing the work here.

        """
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        job = next(job for job in _dependency_gates.pytest_jobs()
                   if job.selection == 'fixture-tier')
        node_ids = [entry for entry in _tiers.fixture_tier_paths()
                    if entry.startswith('tests/toolkit/test_dpkt_unit.py::')]
        self.assertTrue(node_ids, 'the selection no longer names a node ID in that module')

        module, _, scope = node_ids[0].partition('::')
        selected_class, selected_method = scope.split('::')

        reached = _dependency_gates.Gate('HAS_DPKT', module, 1, selected_class, None)
        also = _dependency_gates.Gate('HAS_DPKT', module, 1, selected_class, selected_method)
        elsewhere = _dependency_gates.Gate('HAS_DPKT', module, 1, 'NotSelectedTests', None)
        sibling = _dependency_gates.Gate('HAS_DPKT', module, 1, selected_class, 'test_not_selected')

        self.assertTrue(_dependency_gates.job_reaches(job, reached))
        self.assertTrue(_dependency_gates.job_reaches(job, also))
        self.assertFalse(_dependency_gates.job_reaches(job, elsewhere))
        self.assertFalse(_dependency_gates.job_reaches(job, sibling))

    def test_a_directory_entry_reaches_what_is_under_it(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        job = next(job for job in _dependency_gates.pytest_jobs()
                   if job.selection == 'fixture-tier')
        self.assertIn('tests/integration', _tiers.fixture_tier_paths())

        inside = _dependency_gates.Gate('HAS_EMOJI', 'tests/integration/test_cli_subprocess.py',
                                        1, 'CommandLineTests', None)
        outside = _dependency_gates.Gate('HAS_CRYPTO',
                                         'tests/protocols/internet/test_esp_unit.py',
                                         1, 'ESPProtocolTests', None)
        self.assertTrue(_dependency_gates.job_reaches(job, inside))
        self.assertFalse(_dependency_gates.job_reaches(job, outside))


class DependencyGateCoverageTests(unittest.TestCase):
    """The assertion #745 asked for, and the checks that keep it honest."""

    def setUp(self) -> None:
        if not _dependency_gates.WORKFLOW.is_file():
            self.skipTest(f'{_dependency_gates.WORKFLOW} is not present')
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

    def test_every_gate_a_job_reaches_has_its_dependency_installed(self) -> None:
        """The guard itself: no unrecorded gap between a gate and an install line."""
        unexplained = [
            gap for gap in _dependency_gates.dependency_gate_gaps()
            if gap.flag not in _dependency_gates.DEPENDENCY_GATE_EXCLUSIONS
        ]
        self.assertEqual(
            unexplained, [],
            '\n\n'.join(_dependency_gates.describe_gap(gap) for gap in unexplained))

    def test_the_four_gates_737_and_740_fixed_are_covered_on_every_job_reaching_them(self) -> None:
        """What this guard exists to stop regressing, named one flag at a time.

        #737 added ``DPKT`` and #740 added ``crypto``, ``cli`` and ``NGAP`` to
        the install lines. Nothing held those four in place, which is #745's
        whole complaint -- deleting ``crypto`` from the ``test`` job would
        re-dark 14 ESP methods and go green.

        """
        gaps = {gap.flag for gap in _dependency_gates.dependency_gate_gaps()}
        for flag in ('HAS_DPKT', 'HAS_CRYPTO', 'HAS_EMOJI', 'HAS_PYCRATE'):
            with self.subTest(flag=flag):
                self.assertNotIn(flag, gaps)
                self.assertNotIn(flag, _dependency_gates.DEPENDENCY_GATE_EXCLUSIONS)

    def test_the_crawler_dependencies_are_satisfied_by_the_test_extra(self) -> None:
        """Not an exclusion, which is the correction this test records.

        #745's own text lists ``HAS_CRAWLER_DEPS`` alongside ``HAS_VENDOR_DEPS``
        as ruled onto a non-blocking leg. It is not: it asks only for
        ``requests`` and ``bs4``, both of which the ``test`` extra has carried
        since #507, so every job installs it. Only ``HAS_VENDOR_DEPS`` -- which
        additionally wants :mod:`html5lib`, and so
        ``beautifulsoup4[html5lib]`` -- is genuinely dark.

        """
        gaps = {gap.flag for gap in _dependency_gates.dependency_gate_gaps()}
        self.assertNotIn('HAS_CRAWLER_DEPS', gaps)
        self.assertNotIn('HAS_CRAWLER_DEPS', _dependency_gates.DEPENDENCY_GATE_EXCLUSIONS)
        self.assertIn('HAS_VENDOR_DEPS', _dependency_gates.DEPENDENCY_GATE_EXCLUSIONS)

    def test_the_vendor_extra_closes_engine_tests_but_not_test_or_gate(self) -> None:
        """#738's remaining scope: an existing non-blocking leg absorbs it.

        ``engine-tests`` (#751) already reaches these gates through the same
        ignore-shape selection as ``test`` -- see this guard's own
        ``HAS_VENDOR_DEPS`` exclusion -- and it has never been one of ruleset
        23497679's 15 required checks, so it already was the "job that exists
        and reports without gating a merge" #738's ruling asked for. Installing
        ``vendor`` there, rather than opening a sixth job, is what closes the
        41-method gap on it. It is also the only *per-pull-request* job with
        that property: ``gate`` reaches these gates too but never runs on a
        pull request at all (only via a release's ``gate-only: true`` call),
        and ``integration``'s fixture-tier selection never reaches
        :file:`tests/vendor/` in the first place -- so ``engine-tests`` was
        the forced choice, not merely a convenient one.

        ``test`` and ``gate`` stay dark for different reasons, not the same
        one -- see the exclusion's own reason for why ``gate`` is not merely
        "also non-blocking".

        """
        gaps = {(gap.flag, gap.job) for gap in _dependency_gates.dependency_gate_gaps()}
        self.assertNotIn(('HAS_VENDOR_DEPS', 'engine-tests'), gaps)
        self.assertIn(('HAS_VENDOR_DEPS', 'test'), gaps)
        self.assertIn(('HAS_VENDOR_DEPS', 'gate'), gaps)

        exclusion = _dependency_gates.DEPENDENCY_GATE_EXCLUSIONS['HAS_VENDOR_DEPS']
        self.assertNotIn('engine-tests', exclusion.dark)
        self.assertEqual(set(exclusion.dark), {'test', 'gate'})

    def test_the_mypy_gate_is_visible_and_dark_on_every_job_that_reaches_it(self) -> None:
        """#779: a lint-tier tool gated visibly, and declining the install line anyway.

        ``mypy`` is a :file:`Pipfile` ``[dev-packages]`` entry and is in no
        :file:`pyproject.toml` extra, so before #779 it had no
        :data:`~tests._dependency_gates.MODULE_PROVIDERS` entry at all and an
        ``@unittest.skipUnless`` gate on it was not merely undesirable but
        *impossible*: adding one to
        :file:`tests/vendor/test_vendor_reg_apptype_generator_unit.py` and
        nothing else made this class report 2 failures and 5 errors of its 10
        tests, every one of those errors a bare ``KeyError: 'mypy'`` out of
        :func:`~tests._dependency_gates.extras_providing`, upstream of any
        :data:`~tests._dependency_gates.DEPENDENCY_GATE_EXCLUSIONS` filtering.
        (#779 reports 4 errors of 9 tests for the same mutation; it was written
        before #774 added
        :meth:`test_the_vendor_extra_closes_engine_tests_but_not_test_or_gate`,
        which is the tenth and the fifth error. Re-measured here rather than
        copied.)
        The entry is what makes the gate expressible; the exclusion is what
        records that *closing* the gap would be the wrong fix, since a type
        checker belongs to :file:`.github/workflows/lint.yml` rather than to a
        pytest install line.

        So the outcome pinned here is deliberately not "no gap". It is a gap on
        exactly the three jobs that collect the module, explained rather than
        closed -- and, which is the part #745 cares about, countable at all
        rather than hidden in a function body.

        """
        gates = {(gate.flag, gate.module) for gate in _dependency_gates.gated_scopes()}
        self.assertIn(
            ('HAS_MYPY', 'tests/vendor/test_vendor_reg_apptype_generator_unit.py'), gates,
            'the mypy gate is invisible to the scan again -- an inline skipTest in a '
            'function body is exactly the shape _gates_of() cannot see')

        # An empty answer, not a raised exception: no extra carries mypy, which
        # is why the gap below is real rather than a mapping mistake.
        self.assertEqual(_dependency_gates.extras_providing('mypy'), frozenset())

        gaps = {(gap.flag, gap.job) for gap in _dependency_gates.dependency_gate_gaps()}
        for job in ('test', 'engine-tests', 'gate'):
            with self.subTest(reaches=job):
                self.assertIn(('HAS_MYPY', job), gaps)
        # Both select by fixture tier and never collect tests/vendor/ at all --
        # the same reason they are absent from HAS_VENDOR_DEPS above.
        for job in ('integration', 'pypcap-parity'):
            with self.subTest(does_not_reach=job):
                self.assertNotIn(('HAS_MYPY', job), gaps)

        exclusion = _dependency_gates.DEPENDENCY_GATE_EXCLUSIONS['HAS_MYPY']
        self.assertEqual(set(exclusion.dark), {'test', 'engine-tests', 'gate'})

    def test_each_exclusion_still_describes_a_gap_that_is_really_there(self) -> None:
        """The anti-rot half, and the reason this is an allowlist and not a skip list.

        #745 is explicit that "a bare skip list rots into the same
        invisibility": an entry kept after its gap is closed silences a future
        regression of the same dependency, and nothing would say so. So the
        declared jobs and packages have to match what is derived *exactly*, in
        both directions -- a gap that widens, narrows, moves to another job or
        disappears entirely fails here.

        """
        derived = {}  # type: dict[str, dict[str, tuple[str, ...]]]
        for gap in _dependency_gates.dependency_gate_gaps():
            derived.setdefault(gap.flag, {})[gap.job] = gap.missing

        for flag, exclusion in sorted(_dependency_gates.DEPENDENCY_GATE_EXCLUSIONS.items()):
            with self.subTest(flag=flag):
                self.assertIn(
                    flag, derived,
                    f'{flag} is excluded but no job reaches a gate on it without the '
                    f'dependency -- the gap is closed, so delete the entry'
                )
                self.assertEqual(
                    dict(exclusion.dark), derived[flag],
                    f"{flag}'s exclusion no longer matches the gap it describes"
                )

    def test_each_exclusion_gives_a_reason_worth_reading(self) -> None:
        """A one-word reason is how a skip list is born."""
        for flag, exclusion in sorted(_dependency_gates.DEPENDENCY_GATE_EXCLUSIONS.items()):
            with self.subTest(flag=flag):
                self.assertGreater(
                    len(exclusion.reason), 120,
                    f"{flag}'s reason is too short to say why the dependency is absent"
                )
                self.assertTrue(
                    re.search(r'#\d+', exclusion.reason)
                    or re.search(r'wheel|toolchain|libpcap|marker|cost|network|tshark',
                                 exclusion.reason),
                    f"{flag}'s reason names neither a ticket nor a concrete obstacle"
                )

    def test_every_gated_flag_is_classified(self) -> None:
        """A newly gated dependency cannot slip through unmapped.

        Three ways to be classified, and no fourth: the flag probes modules that
        :data:`~tests._dependency_gates.MODULE_PROVIDERS` maps, or it is named in
        :data:`~tests._dependency_gates.NON_DISTRIBUTION_FLAGS` because no extra
        could ever satisfy it, or the scan could not resolve it at all -- which
        is a failure, because an unresolved flag requires nothing and so can
        never be reported as a gap.

        A *required* module missing from :data:`~tests._dependency_gates.MODULE_PROVIDERS`
        fails right here, with this message naming it *and the gate's own file
        and line*. An *excluded* one -- the modules
        :func:`~tests._dependency_gates.flag_exclusions` reads off a negated
        probe -- had neither: nothing looped over them at all, so the same gap
        surfaced only out of :func:`~tests._dependency_gates.module_providers`,
        wherever :func:`~tests._dependency_gates.ambiguous_satisfactions`
        happened to call it. Looping over both here is what gives an excluded
        module the same deliberate contract a required one already has, instead
        of an accident of whichever caller reaches it first.

        Both messages below still earn their place now that
        :func:`~tests._dependency_gates._top_level_providers` names the module
        and the fix on its own (#779): what that cannot say is *which gate*
        wanted the module, and the location is most of what makes the failure
        actionable. This test is also the only one that reaches the excluded
        half without depending on a job's selection happening to collect the
        gate.

        """
        requirements = _dependency_gates.flag_requirements()
        exclusions = _dependency_gates.flag_exclusions()
        gates = _dependency_gates.gated_scopes()
        # Without this the whole loop passes on an empty scan, which is the one
        # way a classification check can be wrong and silent at the same time.
        self.assertGreater(len(gates), 200, 'the gate scan found almost nothing')

        for gate in gates:
            with self.subTest(flag=gate.flag, module=gate.module, line=gate.lineno):
                if gate.flag in _dependency_gates.NON_DISTRIBUTION_FLAGS:
                    continue
                modules = requirements.get((gate.module, gate.flag))
                self.assertTrue(
                    modules,
                    f'{gate.module}:{gate.lineno} gates on {gate.flag}, whose requirements '
                    f'this scan could not resolve -- teach tests._dependency_gates the '
                    f'shape it is written in, or name it in NON_DISTRIBUTION_FLAGS'
                )
                assert modules is not None
                for module in sorted(modules):
                    self.assertIn(module.partition('.')[0],
                                  _dependency_gates.MODULE_PROVIDERS,
                                  f'{module} has no MODULE_PROVIDERS entry, so nothing '
                                  f'knows which extra installs it')

                for module in sorted(exclusions.get((gate.module, gate.flag), ())):
                    self.assertIn(module.partition('.')[0],
                                  _dependency_gates.MODULE_PROVIDERS,
                                  f'{module} is excluded by {gate.flag}\'s own negated probe '
                                  f'but has no MODULE_PROVIDERS entry, so '
                                  f'ambiguous_satisfactions() would fail resolving it '
                                  f'somewhere that cannot name this gate')

    def test_no_provider_mapping_or_exclusion_is_vestigial(self) -> None:
        """Both tables are exactly as wide as the suite needs them to be --
        for every drift this comparison can actually see.

        A required module resolves through the *exact* key when
        :data:`~tests._dependency_gates.MODULE_PROVIDERS` has one (``pcap._pcap``,
        which does not want plain ``pcap``'s two-wide entry) and through its
        top-level truncation otherwise -- the same rule
        :func:`~tests._dependency_gates.module_providers` and
        :func:`~tests._dependency_gates.extras_providing` both apply, so
        ``needed`` is built the same way rather than by truncating every
        required module unconditionally.

        One blind spot, not fixed here because nothing else needs it fixed:
        ``needed`` decides *whether* to truncate a required module by asking
        the very dictionary being checked, so deleting a *dotted* key
        (``pcap._pcap``) removes it from both sides of the comparison in the
        same step -- ``needed`` truncates to ``'pcap'`` the moment the exact
        key is gone, and the assertion below stays green. That deletion is
        not vestigial -- :func:`~tests._dependency_gates.module_providers`'s
        callers still need the entry -- it is just invisible to this
        particular test;
        :meth:`~tests.test_tier_guard.DependencyGateScanTests.test_a_negated_probe_is_not_a_requirement`,
        the two ``#762`` swap tests below, and
        :meth:`~tests.test_tier_guard.DependencyGateFalsifiabilityTests\
.test_removing_the_negation_or_the_exact_path_reopens_762`'s own mutation all
        pin ``pcap._pcap`` directly and would catch it.

        """
        requirements = _dependency_gates.flag_requirements()
        gated = {gate.flag for gate in _dependency_gates.gated_scopes()}
        required = {module
                    for (_, flag), modules in requirements.items() if flag in gated
                    for module in modules}
        needed = {module if module in _dependency_gates.MODULE_PROVIDERS
                 else module.partition('.')[0]
                 for module in required}

        self.assertEqual(set(_dependency_gates.MODULE_PROVIDERS), needed)
        self.assertLessEqual(set(_dependency_gates.NON_DISTRIBUTION_FLAGS),
                             {flag for (_, flag) in requirements})
        self.assertEqual(
            set(_dependency_gates.NON_DISTRIBUTION_FLAGS)
            & set(_dependency_gates.DEPENDENCY_GATE_EXCLUSIONS), set(),
            'a flag no extra could satisfy does not also need an exclusion')

    def test_mutually_exclusive_imports_matches_its_derivation(self) -> None:
        """The liveness half :data:`~tests._dependency_gates.MUTUALLY_EXCLUSIVE_IMPORTS` needs.

        A hand-written set can misname which distribution is right for an
        entry it already has, but it cannot notice a *third* name going
        contested that nobody added -- the exact shape #745's own docstring
        warns a skip list rots into. Comparing it against
        :func:`~tests._dependency_gates.contested_imports`, which counts how
        many of a :data:`~tests._dependency_gates.MODULE_PROVIDERS` entry's
        alternatives some declared extra actually resolves, is what would
        catch that: an entry gaining a second *live* alternative without a
        matching addition here fails this assertion rather than silently
        reopening #762 under a name nobody scoped
        :func:`~tests._dependency_gates.ambiguous_satisfactions` to.

        """
        self.assertEqual(_dependency_gates.MUTUALLY_EXCLUSIVE_IMPORTS,
                         _dependency_gates.contested_imports())

    def test_no_gate_is_satisfied_through_the_wrong_half_of_an_ambiguous_import(self) -> None:
        """#762: a satisfied gate has to resolve to the *right* distribution.

        :meth:`test_every_gate_a_job_reaches_has_its_dependency_installed` only
        asks whether at least one distribution the job installs ships the
        module a gate needs -- which cannot tell PyPCAP's ``pcap`` from
        pcap-ct's, since both are registered under the one
        :data:`~tests._dependency_gates.MODULE_PROVIDERS` entry. This is that
        check's complement: every ``(job, gate)`` pair the gaps pass calls
        satisfied has to resolve to exactly the distribution that is legitimate
        for it -- derived from :func:`~tests._dependency_gates.module_providers`
        and :func:`~tests._dependency_gates.module_flag_exclusions`, not a
        hand-maintained table -- wherever more than one distribution could have
        supplied the import.

        """
        findings = _dependency_gates.ambiguous_satisfactions()
        self.assertEqual(
            findings, (),
            '\n\n'.join(_dependency_gates.describe_ambiguous_satisfaction(finding)
                       for finding in findings))


class DependencyGateFalsifiabilityTests(unittest.TestCase):
    """Break the install lines on a copy, and watch the guard fire.

    These are the only tests here that prove the guard is capable of failing at
    all: every assertion in :class:`DependencyGateCoverageTests` passes today on
    a tree that is correct, and a wrong analysis would pass just as quietly on
    one that had been broken.

    """

    def setUp(self) -> None:
        if not _dependency_gates.WORKFLOW.is_file():
            self.skipTest(f'{_dependency_gates.WORKFLOW} is not present')
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

    def test_removing_crypto_from_the_test_job_is_caught(self) -> None:
        """#745's worked example, verbatim: "deleting ``crypto`` ... would go green"."""
        doctored = doctored_workflow(self, "'.[test,DPKT,crypto,NGAP]'", "'.[test,DPKT,NGAP]'")

        gaps = {(gap.flag, gap.job): gap
                for gap in _dependency_gates.dependency_gate_gaps(doctored)}
        self.assertIn(('HAS_CRYPTO', 'test'), gaps)

        gap = gaps[('HAS_CRYPTO', 'test')]
        self.assertEqual(gap.missing, ('cryptography',))
        self.assertEqual(len(gap.gates), 14)
        self.assertEqual({gate.module for gate in gap.gates},
                         {'tests/protocols/internet/test_esp_unit.py'})

        message = _dependency_gates.describe_gap(gap)
        self.assertIn("the 'test' job", message)
        self.assertIn('cryptography', message)
        self.assertIn('crypto', message)
        self.assertIn('test_esp_unit.py', message)

        self.assertNotIn(
            'HAS_CRYPTO', _dependency_gates.DEPENDENCY_GATE_EXCLUSIONS,
            'the exclusion list would swallow the gap this test relies on'
        )

    def test_removing_dpkt_is_caught_on_every_job_that_installs_it(self) -> None:
        """#729's defect, restaged. Five jobs install ``DPKT``; all five go dark.

        #751 added ``engine-tests`` and ``pypcap-parity`` to the three this test
        used to name, each carrying its own ``DPKT`` for the same reason as the
        original three -- ``engine-tests`` for
        :file:`tests/foundation/engines/test_runtime_engines.py`'s reused
        ``HAS_RUNTIME``, ``pypcap-parity`` for
        :file:`examples/generators/make_samples.py`.

        """
        text = _dependency_gates.WORKFLOW.read_text(encoding='utf-8')
        doctored = doctored_workflow(self, text, text.replace('DPKT,', '').replace(',DPKT', ''))

        gaps = {gap.job: gap for gap in _dependency_gates.dependency_gate_gaps(doctored)
                if gap.flag == 'HAS_DPKT'}
        self.assertEqual(sorted(gaps),
                         ['engine-tests', 'gate', 'integration', 'pypcap-parity', 'test'])
        for job, gap in sorted(gaps.items()):
            with self.subTest(job=job):
                self.assertEqual(gap.missing, ('dpkt',))

    def test_removing_cli_only_darkens_the_jobs_that_reach_the_emoji_gates(self) -> None:
        """Precision, not just detection.

        Every ``HAS_EMOJI`` gate is in :file:`tests/integration/test_cli_subprocess.py`,
        which the ``test`` and ``engine-tests`` jobs both ignore wholesale. So
        dropping ``cli`` must be reported against ``integration``, ``gate`` and
        ``pypcap-parity`` -- #751's job that mirrors ``integration``'s
        fixture-tier selection and so reaches the same gate -- and *not*
        against ``test`` or ``engine-tests``: a guard that flagged those two as
        well would be noise, and noise is what gets a guard allowlisted into
        uselessness.

        """
        text = _dependency_gates.WORKFLOW.read_text(encoding='utf-8')
        doctored = doctored_workflow(self, text, text.replace(',cli', ''))

        jobs = sorted(gap.job for gap in _dependency_gates.dependency_gate_gaps(doctored)
                      if gap.flag == 'HAS_EMOJI')
        self.assertEqual(jobs, ['gate', 'integration', 'pypcap-parity'])

    def test_swapping_pypcap_parity_to_pcap_ct_is_an_ambiguous_satisfaction(self) -> None:
        """#762, direction one: the wrong half of the ``pcap`` ambiguity, installed.

        ``pypcap-parity`` swapped from the ``PyPCAP`` extra to ``PCAP_CT`` still
        reaches all 4 ``HAS_PYPCAP`` gates, and
        :func:`~tests._dependency_gates.dependency_gate_gaps` still calls them
        satisfied -- pcap-ct ships the same top-level ``pcap`` module, so this is
        exactly the blind spot :func:`~tests._dependency_gates.dependency_gate_gaps`
        cannot see on its own. :func:`~tests._dependency_gates.ambiguous_satisfactions`
        is what catches it.

        """
        doctored = doctored_workflow(
            self,
            "python -m pip install -e '.[test,Scapy,DPKT,cli,PyShark,PyPCAP,PyPCAPFile]'",
            "python -m pip install -e '.[test,Scapy,DPKT,cli,PyShark,PCAP_CT,PyPCAPFile]'",
        )

        gaps = {(gap.flag, gap.job) for gap in _dependency_gates.dependency_gate_gaps(doctored)}
        self.assertNotIn(
            ('HAS_PYPCAP', 'pypcap-parity'), gaps,
            'the premise of this test: dependency_gate_gaps must still see no gap on this '
            'job, which is exactly what makes the blind spot invisible to it')

        findings = {(finding.job, finding.flag): finding
                   for finding in _dependency_gates.ambiguous_satisfactions(doctored)}
        self.assertIn(('pypcap-parity', 'HAS_PYPCAP'), findings)
        finding = findings[('pypcap-parity', 'HAS_PYPCAP')]
        self.assertEqual(finding.module, 'pcap')
        self.assertEqual(finding.providers, frozenset({'pypcap', 'pcap-ct'}))
        self.assertEqual(finding.satisfied, frozenset({'pcap-ct'}))

        self.assertEqual(finding.valid, frozenset({'pypcap'}))

        message = _dependency_gates.describe_ambiguous_satisfaction(finding)
        self.assertIn("'pypcap-parity'", message)
        self.assertIn('HAS_PYPCAP', message)
        self.assertIn("it resolves to ['pcap-ct']", message)
        self.assertIn("not to ['pypcap']", message)

    def test_swapping_engine_tests_to_pypcap_is_an_ambiguous_satisfaction(self) -> None:
        """#762, direction two: the wrong half of the ``pcap._pcap`` ambiguity.

        ``engine-tests`` swapped from ``PCAP_CT`` to ``PyPCAP`` still reaches the
        1 ``HAS_PCAP_CT`` gate and still reads as satisfied to
        :func:`~tests._dependency_gates.dependency_gate_gaps`, for the mirrored
        reason: ``extras_providing`` truncates ``pcap._pcap`` to ``pcap`` before
        its lookup, per this module's own docstring.

        """
        doctored = doctored_workflow(
            self,
            "python -m pip install -e '.[test,DPKT,crypto,NGAP,Scapy,PyShark,PyPCAPFile,"
            "PCAP_CT,vendor]'",
            "python -m pip install -e '.[test,DPKT,crypto,NGAP,Scapy,PyShark,PyPCAPFile,"
            "PyPCAP,vendor]'",
        )

        gaps = {(gap.flag, gap.job) for gap in _dependency_gates.dependency_gate_gaps(doctored)}
        self.assertNotIn(('HAS_PCAP_CT', 'engine-tests'), gaps)

        findings = {(finding.job, finding.flag): finding
                   for finding in _dependency_gates.ambiguous_satisfactions(doctored)}
        self.assertIn(('engine-tests', 'HAS_PCAP_CT'), findings)
        finding = findings[('engine-tests', 'HAS_PCAP_CT')]
        self.assertEqual(finding.module, 'pcap._pcap')
        self.assertEqual(finding.providers, frozenset({'pypcap', 'pcap-ct'}))
        self.assertEqual(finding.satisfied, frozenset({'pypcap'}))
        self.assertEqual(finding.valid, frozenset({'pcap-ct'}))

    def test_gaining_the_vendor_extra_is_not_an_ambiguous_satisfaction(self) -> None:
        """The html5lib near-miss: two requirement strings, one distribution.

        ``html5lib`` has two entries in
        :data:`~tests._dependency_gates.MODULE_PROVIDERS`
        (``beautifulsoup4[html5lib]`` and plain ``html5lib``), the same shape
        as ``pcap``'s two. The difference is that both name the *same*
        distribution -- pyproject.toml never declares bare ``html5lib`` -- so
        gaining the ``vendor`` extra (closing #738's ``HAS_VENDOR_DEPS`` gap)
        must not read as ambiguous the way installing the wrong ``pcap``
        distribution does. Scoping
        :func:`~tests._dependency_gates.ambiguous_satisfactions` to
        :data:`~tests._dependency_gates.MUTUALLY_EXCLUSIVE_IMPORTS` rather than
        to every :data:`~tests._dependency_gates.MODULE_PROVIDERS` entry with
        more than one requirement string is what keeps it that way.

        """
        doctored = doctored_workflow(
            self,
            "python -m pip install -e '.[test,DPKT,crypto,NGAP]'",
            "python -m pip install -e '.[test,DPKT,crypto,NGAP,vendor]'",
        )

        gaps = {(gap.flag, gap.job) for gap in _dependency_gates.dependency_gate_gaps(doctored)}
        self.assertNotIn(
            ('HAS_VENDOR_DEPS', 'test'), gaps,
            'the premise of this test: gaining vendor must actually close the gap on '
            'this job, or there is no ambiguity question to ask about it')

        findings = _dependency_gates.ambiguous_satisfactions(doctored)
        self.assertEqual(
            findings, (),
            '\n\n'.join(_dependency_gates.describe_ambiguous_satisfaction(finding)
                       for finding in findings))

    def test_removing_the_negation_or_the_exact_path_reopens_762(self) -> None:
        """Anti-rot: both halves of the fix are load-bearing, checked by removing each.

        Neither doctored scenario above is caught by :func:`~tests._dependency_gates
        .dependency_gate_gaps` on its own (that is their whole premise). If
        either of :func:`~tests._dependency_gates.ambiguous_satisfactions`'s
        two extra sources of information stopped being consulted, the
        corresponding scenario would go back to being invisible -- which is
        exactly what removing each one in turn demonstrates.

        """
        doctored_pypcap_parity = doctored_workflow(
            self,
            "python -m pip install -e '.[test,Scapy,DPKT,cli,PyShark,PyPCAP,PyPCAPFile]'",
            "python -m pip install -e '.[test,Scapy,DPKT,cli,PyShark,PCAP_CT,PyPCAPFile]'",
        )
        doctored_engine_tests = doctored_workflow(
            self,
            "python -m pip install -e '.[test,DPKT,crypto,NGAP,Scapy,PyShark,PyPCAPFile,"
            "PCAP_CT,vendor]'",
            "python -m pip install -e '.[test,DPKT,crypto,NGAP,Scapy,PyShark,PyPCAPFile,"
            "PyPCAP,vendor]'",
        )

        with self.subTest(mutation='flag_exclusions stubbed to report nothing'):
            with unittest.mock.patch.object(_dependency_gates, 'flag_exclusions', lambda: {}):
                findings = {(finding.job, finding.flag)
                           for finding in
                           _dependency_gates.ambiguous_satisfactions(doctored_pypcap_parity)}
            self.assertNotIn(
                ('pypcap-parity', 'HAS_PYPCAP'), findings,
                'without HAS_PYPCAP\'s own negated probe, nothing disqualifies pcap-ct from '
                'plain pcap\'s two-wide entry, and the #762 shape goes uncaught again')

        with self.subTest(mutation="MODULE_PROVIDERS['pcap._pcap'] widened back to both"):
            with unittest.mock.patch.dict(_dependency_gates.MODULE_PROVIDERS,
                                          {'pcap._pcap': ('pypcap', 'pcap-ct')}):
                findings = {(finding.job, finding.flag)
                           for finding in
                           _dependency_gates.ambiguous_satisfactions(doctored_engine_tests)}
            self.assertNotIn(
                ('engine-tests', 'HAS_PCAP_CT'), findings,
                'without the exact-path entry, pcap._pcap falls back to the same two-wide '
                'set as plain pcap, and the #762 shape goes uncaught again')

    def test_a_third_contested_name_going_undeclared_is_caught(self) -> None:
        """Falsifiability for the liveness comparison itself.

        A hand-written set passing a comparison against itself proves
        nothing; this shows the comparison actually distinguishes a set that
        has drifted from one that has not. Doctoring in a module with two
        *live* alternatives -- ``requests`` and ``cryptography`` are both
        already installed everywhere, so both resolve for real, unlike
        ``html5lib``'s second -- and never adding it to
        :data:`~tests._dependency_gates.MUTUALLY_EXCLUSIVE_IMPORTS` is exactly
        the omission the real table must not make.

        """
        with unittest.mock.patch.dict(_dependency_gates.MODULE_PROVIDERS,
                                      {'fakemod': ('requests', 'cryptography')}):
            derived = _dependency_gates.contested_imports()
            self.assertIn(
                'fakemod', derived,
                'the premise of this test: two live alternatives must make it contested')
            self.assertNotEqual(
                _dependency_gates.MUTUALLY_EXCLUSIVE_IMPORTS, derived,
                'the real table was never told about fakemod, so it must disagree here')

    def test_a_non_distribution_flag_is_not_reported_even_when_doctored_ambiguous(self) -> None:
        """:data:`~tests._dependency_gates.NON_DISTRIBUTION_FLAGS`, exercised for real.

        ``HAS_PYSHARK`` (used to stand in for this mechanism elsewhere) never
        reaches :func:`~tests._dependency_gates.ambiguous_satisfactions`'s
        ``MUTUALLY_EXCLUSIVE_IMPORTS`` branch at all -- ``pyshark`` has one
        provider -- so naming it in ``NON_DISTRIBUTION_FLAGS`` would still
        report nothing whether or not this function's own skip line ran,
        which proves nothing about that line specifically. ``HAS_PYPCAP`` on
        the doctored ``pypcap-parity`` workflow does reach it -- there is a
        real finding to suppress -- so naming *that* flag here is what
        actually exercises the skip.

        """
        doctored = doctored_workflow(
            self,
            "python -m pip install -e '.[test,Scapy,DPKT,cli,PyShark,PyPCAP,PyPCAPFile]'",
            "python -m pip install -e '.[test,Scapy,DPKT,cli,PyShark,PCAP_CT,PyPCAPFile]'",
        )

        findings = {(f.job, f.flag) for f in _dependency_gates.ambiguous_satisfactions(doctored)}
        self.assertIn(
            ('pypcap-parity', 'HAS_PYPCAP'), findings,
            'the premise of this test: there must be a real finding here to suppress')

        with unittest.mock.patch.dict(_dependency_gates.NON_DISTRIBUTION_FLAGS,
                                      {'HAS_PYPCAP': 'stood in for this test'}):
            findings = {(f.job, f.flag)
                       for f in _dependency_gates.ambiguous_satisfactions(doctored)}
        self.assertNotIn(('pypcap-parity', 'HAS_PYPCAP'), findings)

    def test_the_undoctored_workflow_produces_no_unexplained_gap(self) -> None:
        """The control: the tests above fail for the doctoring, not by default."""
        unexplained = [gap for gap in _dependency_gates.dependency_gate_gaps()
                       if gap.flag not in _dependency_gates.DEPENDENCY_GATE_EXCLUSIONS]
        self.assertEqual(unexplained, [])
        self.assertEqual(_dependency_gates.ambiguous_satisfactions(), ())

    def test_describe_ambiguous_satisfaction_names_residual_ambiguity_too(self) -> None:
        """The other branch of :func:`~tests._dependency_gates.describe_ambiguous_satisfaction`.

        Both real findings above are the "resolved to something illegitimate"
        shape. The other shape -- resolved to more than one distribution even
        after narrowing to the legitimate set -- has no real workflow state
        that produces it today (the legitimate set for both watched flags is
        always a singleton), so it needs its own construction to reach.

        """
        finding = _dependency_gates.AmbiguousProvider(
            flag='HAS_MADE_UP', job='made-up-job', module='pcap',
            providers=frozenset({'pypcap', 'pcap-ct'}),
            satisfied=frozenset({'pypcap', 'pcap-ct'}),
            valid=frozenset({'pypcap', 'pcap-ct'}))

        message = _dependency_gates.describe_ambiguous_satisfaction(finding)
        self.assertIn('more than one legitimate distribution at once', message)
        self.assertIn('HAS_MADE_UP', message)
        self.assertIn('made-up-job', message)


class DependencyGateDegradationTests(unittest.TestCase):
    """What happens when an input is malformed, missing, or not what was assumed.

    Same posture as :class:`DegradationTests` above with one deliberate
    difference: a module this scan cannot read is a reason to stay quiet, but a
    :file:`pyproject.toml` or workflow it cannot read is a reason to fail. The
    first can happen in a checkout that is mid-edit; the second means the guard
    would be reasoning about extras or jobs it never found, which is precisely
    the vacuous pass #745 is about.

    """

    def setUp(self) -> None:
        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-dependency-gates-')
        self.addCleanup(tmpdir.cleanup)
        self.tmp_path = pathlib.Path(tmpdir.name)

    def test_an_unparseable_module_is_skipped_rather_than_crashing_the_scan(self) -> None:
        """One broken file must not take the whole guard with it -- pytest reports it."""
        module = write_module(self.tmp_path, 'test_broken_unit.py', """
            @unittest.skipUnless(HAS_DPKT,
            class Tests(:
            """)
        self.assertEqual(_dependency_gates.module_gates(module, 'test_broken_unit.py'), ())
        self.assertEqual(_dependency_gates.module_flag_requirements(module), {})
        self.assertEqual(_dependency_gates.module_flag_exclusions(module), {})

    def test_a_missing_module_is_skipped_too(self) -> None:
        absent = self.tmp_path / 'test_absent_unit.py'
        self.assertEqual(_dependency_gates.module_gates(absent, 'test_absent_unit.py'), ())
        self.assertEqual(_dependency_gates.module_flag_requirements(absent), {})
        self.assertEqual(_dependency_gates.module_flag_exclusions(absent), {})

    def test_an_unrecognised_flag_shape_resolves_to_nothing(self) -> None:
        """And :class:`DependencyGateCoverageTests` is what makes that a failure.

        A flag written in some shape this scan does not understand resolves to no
        requirements, and a flag that requires nothing can never be reported as
        a gap. Resolving to nothing is therefore the *safe* answer only because
        ``test_every_gated_flag_is_classified`` refuses to let an unresolved flag
        stay unresolved.

        """
        module = write_module(self.tmp_path, 'test_odd_unit.py', """
            HAS_ODD = (lambda name: True)('dpkt')
            """)
        self.assertEqual(_dependency_gates.module_flag_requirements(module),
                         {'HAS_ODD': frozenset()})

    def test_a_requirement_string_that_cannot_be_split_matches_nothing(self) -> None:
        """Failing to match is safe; guessing a name would not be."""
        for text in ('', '  ', '[weird]'):
            with self.subTest(requirement=text):
                requirement = _dependency_gates.requirement_key(text)
                self.assertFalse(
                    _dependency_gates.provided_by((requirement,), 'beautifulsoup4'))

    def test_a_pyproject_without_the_table_being_read_fails_loudly(self) -> None:
        """Not "no extras declared", which would satisfy nothing and flag everything."""
        self.addCleanup(_dependency_gates.declared_requirements.cache_clear)
        self.addCleanup(_dependency_gates.extras_providing.cache_clear)
        _dependency_gates.declared_requirements.cache_clear()

        broken = self.tmp_path / 'pyproject.toml'
        broken.write_text('[build-system]\nrequires = [ "setuptools" ]\n', encoding='utf-8')
        with unittest.mock.patch.object(_dependency_gates, 'PYPROJECT', broken):
            with self.assertRaises(AssertionError) as caught:
                _dependency_gates.declared_requirements()
        self.assertIn('project', str(caught.exception))

    def test_a_project_table_with_no_dependencies_fails_loudly(self) -> None:
        self.addCleanup(_dependency_gates.declared_requirements.cache_clear)
        self.addCleanup(_dependency_gates.extras_providing.cache_clear)
        _dependency_gates.declared_requirements.cache_clear()

        broken = self.tmp_path / 'pyproject.toml'
        broken.write_text('[project]\nname = "x"\n\n[project.optional-dependencies]\n',
                          encoding='utf-8')
        with unittest.mock.patch.object(_dependency_gates, 'PYPROJECT', broken):
            with self.assertRaises(AssertionError) as caught:
                _dependency_gates.declared_requirements()
        self.assertIn('dependencies', str(caught.exception))

    def test_a_workflow_with_no_jobs_block_fails_loudly(self) -> None:
        with self.assertRaises(AssertionError) as caught:
            _dependency_gates.job_sections('name: Unit Tests\non:\n  push:\n')
        self.assertIn('jobs', str(caught.exception))

    def test_a_flag_no_extra_could_satisfy_is_not_reported_as_a_gap(self) -> None:
        """:data:`~tests._dependency_gates.NON_DISTRIBUTION_FLAGS`, exercised.

        No flag in the suite is *gated* on something pip cannot install today --
        ``HAS_PROC_FD`` asks whether :file:`/proc/self/fd` exists and is consulted
        inline rather than through a decorator -- so this stands a real gated flag
        in for one, to pin that naming a flag there suppresses its gap instead of
        merely documenting it.

        """
        if not _dependency_gates.WORKFLOW.is_file():
            self.skipTest(f'{_dependency_gates.WORKFLOW} is not present')
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        self.assertIn('HAS_PYSHARK',
                      {gap.flag for gap in _dependency_gates.dependency_gate_gaps()})
        with unittest.mock.patch.dict(_dependency_gates.NON_DISTRIBUTION_FLAGS,
                                      {'HAS_PYSHARK': 'stood in for this test'}):
            self.assertNotIn('HAS_PYSHARK',
                             {gap.flag for gap in _dependency_gates.dependency_gate_gaps()})

    def test_an_unmapped_module_names_itself_and_the_table_to_add_it_to(self) -> None:
        """#779's second defect: the table lookup used to die on a bare ``KeyError``.

        Auditing gates is this module's whole purpose, so the worst available
        answer to an unrecognised one was the one it gave: ``KeyError: 'mypy'``
        raised from a dict subscript three call sites deep, naming neither the
        fix nor even the table that wanted the entry. All three subscripts now
        go through :func:`~tests._dependency_gates._top_level_providers`, so
        every entry point fails the same way and says the same thing --
        :func:`~tests._dependency_gates.extras_providing` (which
        :func:`~tests._dependency_gates.dependency_gate_gaps` reaches),
        :func:`~tests._dependency_gates.module_providers` (which
        :func:`~tests._dependency_gates.ambiguous_satisfactions` reaches), and
        the helper itself.

        The message has to name the *dotted* module as given as well as the
        top-level key actually looked up, because those differ exactly when the
        truncation is what a reader would otherwise have to work out for
        themselves.

        """
        unmapped = 'nosuchlinter.plugins'
        for resolve in (_dependency_gates.extras_providing,
                        _dependency_gates.module_providers,
                        _dependency_gates._top_level_providers):
            with self.subTest(resolve=resolve.__name__):
                with self.assertRaises(AssertionError) as caught:
                    resolve(unmapped)
                message = str(caught.exception)
                self.assertIn(repr(unmapped), message)
                self.assertIn(repr('nosuchlinter'), message)
                for table in ('MODULE_PROVIDERS', 'DEPENDENCY_GATE_EXCLUSIONS',
                              'NON_DISTRIBUTION_FLAGS'):
                    self.assertIn(table, message)

    def test_a_mapped_module_still_resolves_through_the_same_truncation(self) -> None:
        """The control for the test above: #779 changed the diagnostic, not the answer.

        :func:`~tests._dependency_gates._top_level_providers` truncates to the
        top-level package unconditionally -- so ``pcap._pcap`` gets plain
        ``pcap``'s two-wide entry there, exactly as the bare subscript it
        replaced did -- while
        :func:`~tests._dependency_gates.module_providers` keeps its own
        exact-key preference on top of that, which is what makes ``pcap._pcap``
        resolve to ``pcap-ct`` alone. Those two answers differing for the same
        module is load-bearing for #762, so a "harmless" unification of the two
        lookups has to fail here.

        """
        self.assertEqual(_dependency_gates._top_level_providers('dpkt'), ('dpkt',))
        self.assertEqual(_dependency_gates._top_level_providers('pcapfile.savefile'),
                         ('pypcapfile',))
        self.assertEqual(_dependency_gates._top_level_providers('mypy'), ('mypy',))

        self.assertEqual(_dependency_gates._top_level_providers('pcap._pcap'),
                         ('pypcap', 'pcap-ct'))
        self.assertEqual(_dependency_gates.module_providers('pcap._pcap'),
                         frozenset({'pcap-ct'}))

    def test_an_excluded_module_outside_any_contested_scope_is_ignored(self) -> None:
        """:func:`~tests._dependency_gates._disqualified_providers`, the safe default.

        A negated probe naming a module this scan has never heard of, whose
        top-level package is not in
        :data:`~tests._dependency_gates.MUTUALLY_EXCLUSIVE_IMPORTS` either,
        contributes nothing to disqualification rather than raising --
        there is no ambiguity to protect here, so there is nothing this
        function needs to know about the module at all.

        """
        self.assertEqual(
            _dependency_gates._disqualified_providers(frozenset({'totally.unmapped.thing'})),
            frozenset())

    def test_an_excluded_module_under_a_contested_top_level_needs_its_own_entry(self) -> None:
        """The over-disqualification case: fails loud, with the right diagnosis.

        ``pcap._pcap``'s real entry is what stops ``pcap``'s two-wide one from
        being borrowed wholesale. Removing that entry (simulating an excluded
        dotted path nobody has mapped yet, under a top-level that *is*
        contested) must not silently fall back to the broader entry -- that
        would disqualify ``pypcap`` too, collapsing every legitimate candidate
        to none and reporting a real satisfaction as ambiguous for the wrong
        reason. It has to fail instead, and name what is missing.

        """
        with unittest.mock.patch.dict(_dependency_gates.MODULE_PROVIDERS):
            del _dependency_gates.MODULE_PROVIDERS['pcap._pcap']
            with self.assertRaises(AssertionError) as caught:
                _dependency_gates._disqualified_providers(frozenset({'pcap._pcap'}))
        self.assertIn("'pcap._pcap'", str(caught.exception))
        self.assertIn('MUTUALLY_EXCLUSIVE_IMPORTS', str(caught.exception))

    def test_an_unrelated_flags_unmapped_exclusion_never_reaches_disqualification(self) -> None:
        """The ordering fix: the contested-scope check has to run *first*.

        :func:`~tests._dependency_gates.ambiguous_satisfactions` used to
        compute disqualified providers for every gate a job reaches, before
        checking whether the gate's own required module was even in
        :data:`~tests._dependency_gates.MUTUALLY_EXCLUSIVE_IMPORTS`. A flag
        with a negated probe on some module with no
        :data:`~tests._dependency_gates.MODULE_PROVIDERS` entry, and nothing
        to do with a contested name, would crash the entire function via
        :func:`~tests._dependency_gates._disqualified_providers` rather than
        being scoped out of it. This pins a synthetic flag shaped exactly
        that way and shows it no longer crashes.

        """
        with unittest.mock.patch.object(
                _dependency_gates, 'flag_exclusions',
                lambda: {('fake/module.py', 'HAS_FAKE'): frozenset({'totally.unmapped.nonsense'})}):
            with unittest.mock.patch.object(
                    _dependency_gates, 'flag_requirements',
                    lambda: {('fake/module.py', 'HAS_FAKE'): frozenset({'dpkt'})}):
                with unittest.mock.patch.object(
                        _dependency_gates, 'gated_scopes',
                        lambda: (_dependency_gates.Gate('HAS_FAKE', 'fake/module.py', 1, None,
                                                        'test_fake'),)):
                    with unittest.mock.patch.object(
                            _dependency_gates, 'job_reaches', lambda job, gate: True):
                        result = _dependency_gates.ambiguous_satisfactions()
        self.assertEqual(result, ())
