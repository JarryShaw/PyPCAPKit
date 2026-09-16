# -*- coding: utf-8 -*-
"""Self-tests for the benchmark harness's arithmetic and its emitted markup.

A benchmark's output is not self-checking. A ratio computed against the wrong
baseline, a row sorted into the wrong place, or a table that renders as an error
block on GitHub all look exactly like a successful run, so the parts that can be
tested without a stopwatch are tested here:

* the ratio arithmetic, including that it cancels machine drift, which is the
  entire justification for reporting ratios at all;
* the stitching of several environments into one table, which is what makes the
  mutually exclusive ``pypcap`` and ``pcap_ct`` reportable together;
* the overlap marking, which is what stops the report claiming a gap it did not
  measure;
* that the emitted reStructuredText parses under **plain docutils** with no
  errors and uses no Sphinx-only roles -- the README is rendered by docutils on
  GitHub, where ``:mod:`` and friends come out as visible errors.

Run with ``python -m pytest examples/benchmark/test_harness.py``. Nothing here
needs docker, and only the driver-assertion tests need ``pcapkit`` importable.

"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import report  # noqa: E402  pylint: disable=wrong-import-position

#: Roles Sphinx defines and docutils does not. Their appearance in the emitted
#: snippet is the failure this list exists to catch: docutils renders an unknown
#: role as an error block, so a table carrying one is visibly broken on GitHub
#: while looking perfectly fine in the project's own HTML docs.
SPHINX_ONLY_ROLES = (':mod:', ':func:', ':class:', ':meth:', ':attr:', ':data:',
                     ':manpage:', ':envvar:', ':program:', ':doc:', ':exc:', ':obj:',
                     ':term:', ':ref:', ':file:', ':c:func:')


def document(environment, measurements, unmeasured=None, repeats=2, packages=None,
             failures=None, discarded=None):
    """Build a :mod:`benchmark`-shaped document from plain numbers.

    Args:
        environment: Environment label.
        measurements: Mapping of engine name to a list of milliseconds-per-packet
            figures, one per repeat.
        unmeasured: Mapping of engine name to the reason it was not measured.
        repeats: How many repeats the figures represent.
        packages: Resolved package versions, with :data:`None` for a package this
            environment does not have. Defaults to the real shape of the ``pypcap``
            environment, i.e. ``pypcap`` present and ``pcap-ct`` absent.

    Returns:
        A document :mod:`report` can consume.

    """
    if packages is None:
        packages = {'dpkt': '1.9.8', 'pypcap': '1.3.0', 'pcap-ct': None}
    failures = failures or {}
    discarded = discarded or {}
    results = []
    for engine, values in measurements.items():
        results.append({
            'engine': engine,
            'status': 'measured',
            'reason': None,
            'driver': engine.upper(),
            'packets': 6,
            'repeats': [{'repeat': index, 'ms_per_packet': value,
                         'mean_ns_per_extraction': value * 6 * 1e6,
                         'timed_samples': 999,
                         'discarded': ['TSharkCrashException: boom'] * discarded.get(engine, 0)}
                        for index, value in enumerate(values)],
            'failures': failures.get(engine, []),
        })
    for engine, reason in (unmeasured or {}).items():
        results.append({
            'engine': engine, 'status': 'unmeasured', 'reason': reason,
            'driver': None, 'packets': None, 'repeats': [],
            'failures': failures.get(engine, []),
        })
    return {
        'schema': 1,
        'environment': environment,
        'pcapkit_revision': 'abc1234',
        'python': '3.11.14',
        'implementation': 'CPython',
        'machine': 'aarch64',
        'capture': {'name': 'in.pcap', 'bytes': 605, 'sha256': 'a' * 64},
        'rounds': 1000,
        'repeats': repeats,
        'packages': packages,
        'tshark': 'TShark (Wireshark) 4.0.17',
        'libpcap': 'libpcap version 1.10.3',
        'results': results,
    }


class TestRatios:
    """The arithmetic that turns milliseconds into comparable numbers."""

    def test_ratio_is_taken_against_the_same_environment(self):
        """An engine's ratio divides by its own environment's baseline."""
        docs = [document('pypcap', {'default': [0.2, 0.2], 'dpkt': [0.02, 0.02]})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['default'].median == pytest.approx(1.0)
        assert rows['dpkt'].median == pytest.approx(0.1)

    def test_machine_drift_cancels(self):
        """A pass on a machine twice as slow yields the same ratio.

        This is the property that justifies the whole design. The second repeat
        below is uniformly 2x slower -- every engine and the baseline alike -- and
        must not move the reported ratio at all.

        """
        docs = [document('pypcap', {'default': [0.2, 0.4], 'dpkt': [0.02, 0.04]})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['dpkt'].ratios == pytest.approx([0.1, 0.1])
        assert rows['dpkt'].low == pytest.approx(rows['dpkt'].high)
        assert rows['dpkt'].spread == pytest.approx(0.0)

    def test_ratio_pairs_repeats_not_means(self):
        """Repeats are paired one to one, never averaged first.

        Averaging the baseline before dividing would let a slow pass on one engine
        be cancelled by a fast pass on another, which is exactly the error the
        per-repeat pairing exists to avoid.

        """
        # Baseline doubles on the second pass; dpkt does not. The honest answer is
        # two very different ratios, not one tidy average.
        docs = [document('pypcap', {'default': [0.2, 0.4], 'dpkt': [0.02, 0.02]})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['dpkt'].ratios == pytest.approx([0.1, 0.05])

    def test_repeat_without_a_baseline_is_dropped(self):
        """A repeat with no baseline contributes nothing rather than an estimate."""
        docs = [document('pypcap', {'default': [0.2], 'dpkt': [0.02, 0.02]})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['dpkt'].ratios == pytest.approx([0.1])

    def test_a_zero_baseline_is_dropped_rather_than_divided_by(self):
        """A baseline of ``0.0`` drops the pair instead of raising.

        A zero baseline is a broken run, not an absent one, but it is just as
        undividable -- so the sample goes the same way a missing baseline's does,
        and the engine is not credited with a ratio it never had.

        """
        docs = [document('pypcap', {'default': [0.0, 0.2], 'dpkt': [0.02, 0.02]})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['dpkt'].ratios == pytest.approx([0.1])

    def test_an_environment_contributing_no_ratio_is_not_counted(self):
        """An environment only counts once a ratio has actually survived it.

        The engine ran, so its repeats are non-empty, but every one of them lost
        its baseline -- so the environment contributed nothing and must not reach
        the cross-environment check, which would then advertise an agreement it
        has only one side of.

        """
        docs = [
            document('pypcap', {'default': [0.2, 0.2], 'dpkt': [0.02, 0.02]}),
            # ``dpkt`` runs a second pass here that the baseline never reaches.
            document('pcap-ct', {'default': [0.2], 'dpkt': [0.02, 0.02]},
                     packages={'dpkt': '1.9.8', 'pypcap': None, 'pcap-ct': '1.3.0b3'}),
        ]
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['dpkt'].environments == ['pypcap', 'pcap-ct']

        # And with the baseline missing outright, the environment drops away.
        docs[1]['results'] = [entry for entry in docs[1]['results']
                              if entry['engine'] != 'dpkt']
        docs[1]['results'].append({
            'engine': 'dpkt', 'status': 'measured', 'reason': None,
            'driver': 'DPKT', 'packets': 6,
            'repeats': [{'repeat': 7, 'ms_per_packet': 0.02,
                         'mean_ns_per_extraction': 0.12e6, 'timed_samples': 999,
                         'discarded': []}],
            'failures': [],
        })
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['dpkt'].environments == ['pypcap']

    def test_environment_without_a_baseline_is_fatal(self):
        """Nothing in an environment is reportable without its baseline."""
        docs = [document('pypcap', {'dpkt': [0.02, 0.02]})]
        with pytest.raises(ValueError, match="no 'default' measurement"):
            report.collect(docs)

    def test_no_documents_is_fatal(self):
        """An empty run is an error, not an empty table."""
        with pytest.raises(ValueError, match='no benchmark documents'):
            report.collect([])


class TestStitching:
    """Joining the mutually exclusive environments on the shared baseline."""

    def _two_environments(self):
        """Two environments, each with the ``pcap`` provider the other cannot have."""
        return [
            document('pypcap',
                     {'default': [0.20, 0.20], 'dpkt': [0.020, 0.020], 'pypcap': [0.010, 0.010]},
                     {'pcap_ct': 'the installed `pcap` module is pypcap, not pcap-ct'}),
            # Deliberately a slower machine reading, to prove the join normalises.
            document('pcap_ct',
                     {'default': [0.40, 0.40], 'dpkt': [0.040, 0.040], 'pcap_ct': [0.060, 0.060]},
                     {'pypcap': 'the installed `pcap` module is pcap-ct, not pypcap'}),
        ]

    def test_exclusive_engines_both_appear(self):
        """Both ``pypcap`` and ``pcap_ct`` land in one table."""
        rows = {row.engine: row for row in report.collect(self._two_environments())}
        assert rows['pypcap'].measured
        assert rows['pcap_ct'].measured
        assert rows['pypcap'].median == pytest.approx(0.05)
        assert rows['pcap_ct'].median == pytest.approx(0.15)

    def test_shared_engine_pools_both_environments(self):
        """An engine in both environments contributes a ratio from each."""
        rows = {row.engine: row for row in report.collect(self._two_environments())}
        assert len(rows['dpkt'].ratios) == 4
        assert rows['dpkt'].environments == ['pypcap', 'pcap_ct']
        # 0.020/0.20 and 0.040/0.40 are the same ratio on machines 2x apart.
        assert rows['dpkt'].ratios == pytest.approx([0.1, 0.1, 0.1, 0.1])

    def test_measured_somewhere_beats_unmeasured_elsewhere(self):
        """Being unavailable in one environment does not blank the row."""
        rows = {row.engine: row for row in report.collect(self._two_environments())}
        assert rows['pypcap'].measured
        # The reason from the other environment is still recorded, because the
        # mutual exclusion is a fact worth keeping even once the row is filled in.
        assert 'pcap-ct, not pypcap' in rows['pypcap'].reasons['pcap_ct']

    def test_unmeasured_everywhere_keeps_its_reason(self):
        """A row nothing could measure says why, rather than showing a zero."""
        docs = [
            document('pypcap', {'default': [0.2, 0.2]}, {'pyshark': 'no tshark binary'}),
            document('pcap_ct', {'default': [0.2, 0.2]}, {'pyshark': 'no tshark binary'}),
        ]
        rows = {row.engine: row for row in report.collect(docs)}
        assert not rows['pyshark'].measured
        assert rows['pyshark'].reason == 'no tshark binary'

    def test_disagreeing_reasons_are_both_kept(self):
        """Two environments unavailable for different reasons report both."""
        docs = [
            document('pypcap', {'default': [0.2, 0.2]}, {'pyshark': 'no tshark binary'}),
            document('pcap_ct', {'default': [0.2, 0.2]}, {'pyshark': 'python too new'}),
        ]
        rows = {row.engine: row for row in report.collect(docs)}
        assert 'in pcap_ct, python too new' in rows['pyshark'].reason
        assert 'in pypcap, no tshark binary' in rows['pyshark'].reason

    def test_ordering_is_fastest_first_unmeasured_last(self):
        """The table reads top to bottom as fastest to slowest, then the gaps."""
        docs = [document('pypcap',
                         {'default': [0.2, 0.2], 'dpkt': [0.02, 0.02], 'pyshark': [24.0, 24.0]},
                         {'pypcapfile': 'python too new'})]
        assert [row.engine for row in report.collect(docs)] == \
            ['dpkt', 'default', 'pyshark', 'pypcapfile']


class TestOverlap:
    """Marking the gaps this run does not actually establish."""

    def test_overlapping_ranges_are_marked(self):
        """Two engines whose observed ranges cross are not separated."""
        docs = [document('pypcap', {'default': [0.20, 0.20],
                                    'dpkt': [0.020, 0.030],
                                    'scapy': [0.025, 0.035]})]
        marked = report.overlapping(report.collect(docs))
        assert marked == {'dpkt', 'scapy'}

    def test_separated_ranges_are_not_marked(self):
        """A gap wider than the noise is reported as a gap."""
        docs = [document('pypcap', {'default': [0.20, 0.20],
                                    'dpkt': [0.020, 0.021],
                                    'scapy': [0.090, 0.091]})]
        assert report.overlapping(report.collect(docs)) == set()

    def test_a_single_pass_establishes_nothing(self):
        """One pass gives no range, so no row can be separated from another."""
        docs = [document('pypcap', {'default': [0.20], 'dpkt': [0.020]}, repeats=1)]
        marked = report.overlapping(report.collect(docs))
        assert marked == {'default', 'dpkt'}

    def test_a_wide_row_straddles_several_narrow_ones(self):
        """Overlap is checked pairwise across the table, not only between neighbours."""
        docs = [document('pypcap', {'default': [0.20, 0.20],
                                    'dpkt': [0.010, 0.010],
                                    'scapy': [0.005, 0.100],
                                    'pypcapfile': [0.050, 0.050]})]
        marked = report.overlapping(report.collect(docs))
        assert marked == {'dpkt', 'scapy', 'pypcapfile'}


class TestFormatting:
    """Number formatting, which spans three orders of magnitude in one table."""

    @pytest.mark.parametrize(('value', 'expected'), [
        (1.0, '1.00'),
        (0.052134, '0.0521'),
        (0.4587, '0.459'),
        (123.456, '123'),
        # Past three digits the integer part is kept in full rather than rounded to
        # significance: '1234' misleads nobody, and '1.23e+03' in a prose table does.
        # The .5 rounds to even, which is what Python's formatting does.
        (1234.5, '1234'),
        (1235.5, '1236'),
    ])
    def test_significant_figures(self, value, expected):
        """Three significant figures, so neither end of the table is rounded away."""
        assert report._significant(value) == expected  # pylint: disable=protected-access

    def test_zero_is_not_an_exponent(self):
        """Zero formats as zero rather than as scientific notation."""
        assert report._significant(0.0) == '0'  # pylint: disable=protected-access

    def test_tiny_values_avoid_exponent_notation(self):
        """A pathological measurement must not put ``5e-09`` into readable prose."""
        assert 'e' not in report._significant(5e-9)  # pylint: disable=protected-access

    def test_a_tight_range_does_not_read_as_a_range_of_one_value(self):
        """Precision rises until the ends differ, rather than printing ``x-x``.

        Measured: ``pypcap`` came back as ``0.183-0.183`` at three significant
        figures, which looks like a formatting bug and conveys nothing.

        """
        assert report._range(0.18321, 0.18349) == '0.1832-0.1835'  # pylint: disable=protected-access
        assert report._range(0.0612, 0.0620) == '0.0612-0.0620'  # pylint: disable=protected-access

    def test_an_identical_range_shows_one_value(self):
        """When the ends really are equal, one value -- never a fake interval."""
        assert report._range(1.0, 1.0) == '1.00'  # pylint: disable=protected-access


class TestRenderedMarkup:
    """What actually gets pasted into the README."""

    def _snippet(self, emulated=None):
        """Render a full snippet from a two-environment run."""
        docs = [
            document('pypcap',
                     {'default': [0.200, 0.204], 'dpkt': [0.0104, 0.0106],
                      'scapy': [0.0917, 0.0921], 'pypcap': [0.0061, 0.0063],
                      'pyshark': [24.7, 24.9]},
                     {'pcap_ct': 'the installed `pcap` module is pypcap, not pcap-ct'}),
            document('pcap_ct',
                     {'default': [0.201, 0.203], 'dpkt': [0.0105, 0.0107],
                      'scapy': [0.0918, 0.0925], 'pcap_ct': [0.0078, 0.0081],
                      'pyshark': [24.6, 25.0]},
                     {'pypcap': 'the installed `pcap` module is pcap-ct, not pypcap',
                      'pypcapfile': 'pypcapfile does not support Python 3.12'},
                     # The mutual exclusion, as the package table actually sees it:
                     # each environment has exactly one `pcap` provider.
                     packages={'dpkt': '1.9.8', 'pypcap': None, 'pcap-ct': '1.3.0b3'}),
        ]
        rows = report.collect(docs)
        return report.render_rst(rows, docs, image='pcapkit-benchmark:local (sha256:dead)',
                                emulated=emulated), docs, rows

    def test_no_sphinx_only_roles(self):
        """Only literals, because docutils renders unknown roles as errors."""
        snippet, _, _ = self._snippet()
        for role in SPHINX_ONLY_ROLES:
            assert role not in snippet, f'{role} is Sphinx-only and breaks on GitHub'

    def test_parses_under_plain_docutils(self):
        """The snippet renders cleanly with the parser GitHub actually uses."""
        docutils_core = pytest.importorskip('docutils.core')
        from docutils.utils import SystemMessage  # pylint: disable=import-outside-toplevel

        snippet, _, _ = self._snippet()
        messages = []
        try:
            docutils_core.publish_doctree(
                snippet,
                settings_overrides={
                    # halt_level 2 turns a warning into an exception, which is the
                    # only way to make a malformed table fail a test rather than
                    # quietly render as a literal block.
                    'halt_level': 2, 'report_level': 2, 'warning_stream': messages,
                    'input_encoding': 'unicode', 'output_encoding': 'unicode',
                },
            )
        except SystemMessage as exc:  # pragma: no cover - only on a real failure
            pytest.fail(f'docutils rejected the snippet: {exc}\n\n{snippet}')
        assert not messages, f'docutils warned: {messages}\n\n{snippet}'

    def test_table_has_a_row_per_engine(self):
        """Every engine appears, measured or not -- no row is dropped."""
        snippet, _, rows = self._snippet()
        for row in rows:
            assert f'``{row.label}``' in snippet

    def test_unmeasured_row_carries_its_reason(self):
        """A gap is an explained gap, not a blank and not a zero."""
        snippet, _, _ = self._snippet()
        assert '*not measured*' in snippet
        assert 'pypcapfile does not support Python 3.12' in snippet

    def test_baseline_absolute_is_a_footnote_not_a_column(self):
        """One absolute number survives, and it is the baseline's own."""
        snippet, docs, _ = self._snippet()
        assert 'ms per packet' in snippet
        assert report.baseline_absolutes(docs)
        # The table itself must not carry absolute times: they describe the machine
        # at least as much as the engine, and a column of them invites comparison
        # across machines, which is exactly what is not valid.
        table = snippet.split('Test Results')[1]
        assert 'ms per packet' in table  # the footnote lives below the table
        assert table.count('ms per packet') == 1

    def test_spread_is_reported(self):
        """The reader is told how much the run wobbled."""
        snippet, _, _ = self._snippet()
        assert 'Run-to-run spread' in snippet

    def test_overlap_legend_only_appears_when_a_row_carries_it(self):
        """No legend for a marker that is not in the table.

        Explaining a symbol nothing is tagged with reads as though the run failed to
        separate rows it in fact separated cleanly -- which is the opposite of the
        marker's purpose.

        """
        clean = [document('pypcap', {'default': [0.200, 0.201],
                                     'dpkt': [0.0104, 0.0105],
                                     'scapy': [0.0917, 0.0918]})]
        snippet = report.render_rst(report.collect(clean), clean)
        assert report.OVERLAP_MARK not in snippet
        assert 'does not separate these rows' not in snippet
        # ...but the spread is still reported, because it is what makes the gaps
        # above interpretable at all.
        assert 'Run-to-run spread' in snippet

        muddy = [document('pypcap', {'default': [0.200, 0.201],
                                     'dpkt': [0.020, 0.030],
                                     'scapy': [0.025, 0.035]})]
        snippet = report.render_rst(report.collect(muddy), muddy)
        assert report.OVERLAP_MARK in snippet
        assert 'does not separate these rows' in snippet

    def test_provenance_is_present_and_host_free(self):
        """Self-documenting, without identifying the machine it ran on."""
        snippet, _, _ = self._snippet()
        for expected in ('Image', 'Python', 'Architecture', 'Capture', 'Iterations',
                         'Passes', 'CPython 3.11.14', 'in.pcap', '1000', 'abc1234'):
            assert expected in snippet
        # The containerised design is what makes the host irrelevant; printing host
        # details would undo it, and would leak machine identity into a public README.
        import platform as host_platform  # pylint: disable=import-outside-toplevel
        for leak in (host_platform.node(), host_platform.release(), host_platform.version()):
            if leak:
                assert leak not in snippet

    def test_package_versions_are_reported(self):
        """Every engine package's resolved version, per environment."""
        snippet, _, _ = self._snippet()
        assert '``dpkt``' in snippet
        assert '1.9.8' in snippet
        # A package absent from one environment is stated, not left blank: it is the
        # reason two environments exist.
        assert '*absent*' in snippet

    def test_emulation_warning_reaches_the_snippet(self):
        """Emulation is recorded in the table, not only in the script's stderr."""
        snippet, _, _ = self._snippet(emulated='Measured under emulation: linux/amd64 on arm64.')
        assert 'emulation' in snippet.lower()
        assert 'not comparable with native' in snippet

    def test_native_run_says_nothing_about_emulation(self):
        """No scary caveat on a run that did not need one."""
        snippet, _, _ = self._snippet()
        assert 'emulation' not in snippet.lower()


class TestTextReport:
    """The operator-facing summary, which carries more than the table does."""

    def test_cross_environment_check_is_shown(self):
        """Shared engines are reported per environment, so a bad join is visible."""
        docs = [
            document('pypcap', {'default': [0.20, 0.20], 'dpkt': [0.020, 0.020]}),
            document('pcap_ct', {'default': [0.40, 0.40], 'dpkt': [0.040, 0.040]}),
        ]
        text = report.render_text(report.collect(docs), docs)
        assert 'cross-environment check' in text
        assert 'pypcap=0.1' in text
        assert 'pcap_ct=0.1' in text

    def test_absolute_times_are_in_the_text_report(self):
        """Milliseconds stay available to the operator, out of the published table."""
        docs = [document('pypcap', {'default': [0.20, 0.20], 'dpkt': [0.020, 0.020]})]
        text = report.render_text(report.collect(docs), docs)
        assert 'ms/packet' in text
        assert '0.02' in text


class TestDriverAssertion:
    """The harness's single most important correctness property."""

    def test_expected_drivers_come_from_the_registry(self):
        """Derived, not hand-written, so a renamed engine cannot slip past."""
        benchmark = pytest.importorskip('benchmark')
        assert benchmark.expected_drivers('dpkt') == ('DPKT',)
        assert benchmark.expected_drivers('scapy') == ('Scapy',)
        assert benchmark.expected_drivers('pypcap') == ('PyPCAP',)
        assert benchmark.expected_drivers('pcap_ct') == ('PCAP_CT',)

    def test_default_accepts_either_builtin_parser(self):
        """``default`` picks its parser from the magic number, so either is correct."""
        benchmark = pytest.importorskip('benchmark')
        assert set(benchmark.expected_drivers('default')) == {'PCAP', 'PCAP-NG'}
        assert benchmark.expected_drivers('pcapkit') == benchmark.expected_drivers('default')

    def test_an_unknown_engine_is_fatal(self):
        """A typo must not silently benchmark the default engine under another name."""
        benchmark = pytest.importorskip('benchmark')
        with pytest.raises(KeyError):
            benchmark.expected_drivers('not-an-engine')

    def test_a_wrong_driver_refuses_to_report(self, monkeypatch, tmp_path):
        """A measurement whose engine fell back is discarded, not published.

        The fallback only warns, so nothing else in the stack objects. This is the
        check that turns "the extraction succeeded" into "the right engine ran".

        """
        benchmark = pytest.importorskip('benchmark')

        class _FellBack:
            """Stands in for pcapkit's own parser answering for another engine."""
            __engine_name__ = 'PCAP'

        class _Extraction:
            """Minimal stand-in for an Extractor."""
            engine = _FellBack()
            length = 6

        monkeypatch.setattr(benchmark, '_extract', lambda engine, capture: _Extraction())
        with pytest.raises(RuntimeError, match='refusing to report'):
            benchmark.measure('dpkt', str(tmp_path / 'unused.pcap'), rounds=3)

    def test_zero_packets_refuses_to_divide(self, monkeypatch, tmp_path):
        """A capture that yielded nothing is an error, not a division by zero."""
        benchmark = pytest.importorskip('benchmark')

        class _Empty:
            """An extraction that parsed no frames at all."""
            engine = type('_D', (), {'__engine_name__': 'DPKT'})()
            length = 0

        monkeypatch.setattr(benchmark, '_extract', lambda engine, capture: _Empty())
        with pytest.raises(RuntimeError, match='nothing to divide by'):
            benchmark.measure('dpkt', str(tmp_path / 'unused.pcap'), rounds=3)


class TestFlakyEngines:
    """One flaky engine must not cost the others their rows.

    Not hypothetical. On a real 1,000-round run, ``tshark`` crashed on the third
    pass -- ``TSharkCrashException ... retcode: 255``, after roughly two thousand
    process spawns -- and the run produced no table at all. Six working engines went
    unreported because the seventh hiccupped once.

    """

    def test_a_lost_pass_still_reports_the_engine(self):
        """A row built from two passes instead of three is still a row."""
        docs = [document('pypcap',
                         {'default': [0.20, 0.20, 0.20], 'pyshark': [24.0, 24.4]},
                         repeats=3,
                         failures={'pyshark': ['pass 3: TSharkCrashException: retcode 255']})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['pyshark'].measured
        assert len(rows['pyshark'].ratios) == 2
        assert rows['pyshark'].partial

    def test_a_lost_pass_is_marked_and_explained(self):
        """The reader is told what was lost, not left to count passes."""
        docs = [document('pypcap',
                         {'default': [0.20, 0.20, 0.20], 'pyshark': [24.0, 24.4]},
                         repeats=3,
                         failures={'pyshark': ['pass 3: TSharkCrashException: retcode 255']})]
        snippet = report.render_rst(report.collect(docs), docs)
        assert report.PARTIAL_MARK in snippet
        assert 'TSharkCrashException' in snippet
        assert 'in pypcap, pass 3' in snippet

    def test_discarded_extractions_are_counted(self):
        """Discarded extractions are reported, not silently dropped."""
        docs = [document('pypcap', {'default': [0.20, 0.20], 'pyshark': [24.0, 24.4]},
                         discarded={'pyshark': 2})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert rows['pyshark'].discarded == 4  # two per pass, two passes
        snippet = report.render_rst(report.collect(docs), docs)
        assert '4 individual extraction(s) failed and were discarded' in snippet

    def test_a_clean_row_is_not_marked_partial(self):
        """No marker on a row that lost nothing."""
        docs = [document('pypcap', {'default': [0.20, 0.20], 'dpkt': [0.020, 0.020]})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert not rows['dpkt'].partial
        assert report.PARTIAL_MARK not in report.render_rst(report.collect(docs), docs)

    def test_every_pass_failing_makes_the_row_unmeasured(self):
        """An engine that never produced a number reports why, not a zero."""
        docs = [document('pypcap', {'default': [0.20, 0.20]},
                         {'pyshark': 'every timed pass failed: pass 1: TSharkCrashException'})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert not rows['pyshark'].measured
        assert 'TSharkCrashException' in rows['pyshark'].reason

    def test_measure_tolerates_a_bounded_number_of_failures(self, monkeypatch, tmp_path):
        """A flaky extraction is discarded and the pass carries on."""
        benchmark = pytest.importorskip('benchmark')

        class _Extraction:
            """A successful extraction."""
            engine = type('_D', (), {'__engine_name__': 'DPKT'})()
            length = 6

        calls = {'n': 0}

        def _flaky(engine, capture):
            """Fail on the third call only, as a crashing subprocess would."""
            calls['n'] += 1
            if calls['n'] == 3:
                raise OSError('tshark went away')
            return _Extraction()

        monkeypatch.setattr(benchmark, '_extract', _flaky)
        result = benchmark.measure('dpkt', str(tmp_path / 'unused.pcap'), rounds=5)
        # Five good samples were still collected, and the failure is on the record.
        assert result['timed_samples'] == 4  # 5 collected, warm-up discarded
        assert result['discarded'] == ['OSError: tshark went away']

    def test_measure_gives_up_past_the_tolerance(self, monkeypatch, tmp_path):
        """Persistent failure is a failure, not something to retry forever."""
        benchmark = pytest.importorskip('benchmark')

        def _broken(engine, capture):
            """Always fail, as a genuinely unusable engine would."""
            raise OSError('tshark is gone')

        monkeypatch.setattr(benchmark, '_extract', _broken)
        with pytest.raises(OSError, match='tshark is gone'):
            benchmark.measure('dpkt', str(tmp_path / 'unused.pcap'), rounds=5, tolerate=2)

    def test_a_fallback_is_never_tolerated(self, monkeypatch, tmp_path):
        """The escalated EngineWarning is fatal however lenient the tolerance.

        Discarding it would turn the harness's central assertion into a shrug: the
        engine has stopped being itself, and no number should come out of that.

        """
        benchmark = pytest.importorskip('benchmark')
        from pcapkit.utilities.warnings import EngineWarning

        def _falls_back(engine, capture):
            """Warn exactly as Extractor.run does when it falls back."""
            import warnings as warnings_module
            warnings_module.warn('engine DPKT is not installed', EngineWarning)
            raise AssertionError('unreachable: the warning is escalated to an error')

        monkeypatch.setattr(benchmark, '_extract', _falls_back)
        with pytest.raises(EngineWarning):
            benchmark.measure('dpkt', str(tmp_path / 'unused.pcap'), rounds=5, tolerate=100)


class TestInstallFailure:
    """A package that failed to build explains itself in the table."""

    def test_a_recorded_build_failure_becomes_the_reason(self, monkeypatch, tmp_path):
        """The compiler error is the diagnosis, not 'its package is not installed'."""
        benchmark = pytest.importorskip('benchmark')
        (tmp_path / 'pypcap.txt').write_text(
            'pypcap failed to build in this image, so it could not be measured.\n'
            "fatal error: pcap.h: No such file or directory\n",
            encoding='utf-8')
        monkeypatch.setattr(benchmark, 'INSTALL_FAILURES', str(tmp_path))
        recorded = benchmark._install_failure('pypcap')  # pylint: disable=protected-access
        assert 'pcap.h: No such file or directory' in recorded
        # Collapsed to one line, since it lands in a table cell and an RST bullet.
        assert '\n' not in recorded

    def test_no_recorded_failure_is_not_an_error(self, monkeypatch, tmp_path):
        """The normal case, including outside the container, is simply nothing."""
        benchmark = pytest.importorskip('benchmark')
        monkeypatch.setattr(benchmark, 'INSTALL_FAILURES', str(tmp_path / 'absent'))
        assert benchmark._install_failure('pypcap') is None  # pylint: disable=protected-access


class TestRoundTrip:
    """The JSON contract between the two halves of the harness."""

    def test_a_real_document_survives_json(self, tmp_path):
        """What benchmark.py writes is what report.py reads."""
        docs = [document('pypcap', {'default': [0.2, 0.2], 'dpkt': [0.02, 0.02]})]
        path = tmp_path / 'pypcap.json'
        path.write_text(json.dumps(docs[0]), encoding='utf-8')
        reloaded = json.loads(path.read_text(encoding='utf-8'))
        rows = {row.engine: row for row in report.collect([reloaded])}
        assert rows['dpkt'].median == pytest.approx(0.1)
