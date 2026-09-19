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
  the moment a seventh capture is committed (:class:`CommittedCaptureTests`);
* a violation is caught and explained, the legitimate reads next to it are not,
  and several of them are listed in the order they appear in the file rather
  than in the order a tree walk happened to reach them
  (:class:`AuditTests`, :class:`RuntimeCheckTests`);
* the suite as it stands is clean (:class:`SuiteIsCleanTests`), and a checkout
  without git degrades instead of failing (:class:`DegradationTests`).

This module is itself unit-tier, so it reads no capture at all: the violating
modules it needs are written into a temporary directory and audited by path.

"""
from __future__ import annotations

import pathlib
import re
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
        """The set is the index's answer verbatim, prefix stripped."""
        tracked = _tiers.committed_captures()
        assert tracked is not None
        self.assertTrue(tracked, 'git tracks no capture at all, which cannot be right')
        for name in tracked:
            with self.subTest(capture=name):
                self.assertNotIn('/', name, 'names are relative to examples/captures/')

    def test_capture_suggestions_are_captures(self) -> None:
        """The replacement suggestion offers captures, not reference outputs."""
        suggestions = _tiers.committed_capture_names()
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

        The arrangement is the whole test. :func:`ast.walk` is breadth-first, so
        it reaches the *shallowest* call first however late in the file it is
        written: here the earliest call is the most deeply nested one and the
        latest is at module level, so a breadth-first collection reports them
        14, 11, 7, 7 -- exactly backwards -- and this test fails. It passes only
        once the calls are really sorted by position, which is what
        :func:`~tests._tiers.sample_path_calls` documents.

        The two calls sharing line 7 pin the ``col_offset`` tie-break: they come
        out left to right rather than in whatever order the walk happened to
        reach them.

        """
        module = write_module(self.tmp_path, 'test_order_unit.py', """
            from tests._support import sample_path


            class Tests:
                def test_from_a_nested_function(self):
                    def helper():
                        return sample_path('test.pcap'), sample_path('http6.cap')
                    return helper()

                def test_from_a_method(self):
                    return sample_path('http.cap')


            TOP_LEVEL = sample_path('dhcp_big_endian.pcapng')
            """)

        calls = _tiers.sample_path_calls(str(module))
        self.assertEqual(
            [(call.lineno, call.name) for call in calls],
            [(7, 'test.pcap'), (7, 'http6.cap'), (11, 'http.cap'),
             (14, 'dhcp_big_endian.pcapng')],
        )

        # audit_module emits one finding per call and inherits this order, which
        # is what the reader of a failed collection actually sees.
        findings = _tiers.audit_module(module)
        located = [re.search(r':(\d+) is a unit-tier', finding) for finding in findings]
        self.assertTrue(all(match is not None for match in located), findings)
        self.assertEqual([int(match.group(1)) for match in located if match is not None],
                         [7, 7, 11, 14])

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
