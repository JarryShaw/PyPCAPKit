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
* the per-version grid, where the arithmetic is the opposite -- absolute
  milliseconds, pooled across the virtualenvs of one interpreter and never divided
  across two of them -- and where a version that could not be measured has to come
  out as an explained column of ``--`` rather than as an absent column;
* the overlap marking, which is what stops the report claiming a gap it did not
  measure;
* that the emitted reStructuredText parses under **plain docutils** with no
  errors and uses no Sphinx-only roles, so that a table stays pasteable into any
  reStructuredText a plain docutils reader will see, where ``:mod:`` and friends
  come out as visible errors.

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
             failures=None, discarded=None, python='3.11.14', image=None,
             tshark='TShark (Wireshark) 4.0.17'):
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
        failures: Mapping of engine name to passes that failed outright.
        discarded: Mapping of engine name to how many extractions were discarded
            per pass.
        python: Interpreter version, which is what decides the column a document
            lands in -- see :func:`report.python_series`.
        image: Reference of the image this was measured in. The matrix runs one per
            Python version, so this travels with the document rather than being
            passed to the report alongside it.
        tshark: Resolved ``tshark`` banner, or :data:`None` where the binary is
            absent.

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
        'image': image,
        'base_image': 'python:3.11-slim-bookworm@sha256:5282',
        'python': python,
        'implementation': 'CPython',
        'machine': 'aarch64',
        'capture': {'name': 'in.pcap', 'bytes': 605, 'sha256': 'a' * 64},
        'rounds': 1000,
        'repeats': repeats,
        'packages': packages,
        'tshark': tshark,
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
    """What actually gets pasted into the documentation."""

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
        # details would undo it, and would leak machine identity into public docs.
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


def matrix(versions=('3.10', '3.11', '3.12', '3.13', '3.14'), missing_pyshark=('3.14',),
           missing_pypcapfile=('3.12', '3.13', '3.14'), pypcap_on=('3.10', '3.11')):
    """A whole matrix run, shaped the way `run.sh` actually produces one.

    One document per (Python version, ``pcap`` provider) pair, with the real
    engine-support ceilings: two virtualenvs where ``pypcap`` can be installed and one
    where it cannot, ``pypcapfile`` gone from 3.12, ``pyshark`` gone from 3.14.

    Args:
        versions: Python series to include.
        missing_pyshark: Series where ``pyshark`` cannot run.
        missing_pypcapfile: Series where ``pypcapfile`` cannot run.
        pypcap_on: Series that get a second, ``pypcap`` virtualenv.

    Returns:
        A list of documents :mod:`report` can consume.

    """
    documents = []
    for index, series in enumerate(versions):
        # Deliberately drifting per version, so a test cannot pass by accident on
        # figures that are all the same number.
        base = 0.20 + index * 0.01
        shared = {'default': [base, base * 1.01],
                  'dpkt': [base / 20, base / 20 * 1.02],
                  'scapy': [base / 7, base / 7 * 1.01]}
        unmeasured = {}
        if series in missing_pyshark:
            unmeasured['pyshark'] = f'pyshark does not support Python {series}'
        else:
            shared['pyshark'] = [base * 70, base * 71]
        if series in missing_pypcapfile:
            unmeasured['pypcapfile'] = f'pypcapfile does not support Python {series}'
        else:
            shared['pypcapfile'] = [base / 15, base / 15 * 1.01]

        ct_unmeasured = dict(unmeasured)
        ct_unmeasured['pypcap'] = (
            'the installed `pcap` module is pcap-ct, not pypcap' if series in pypcap_on else
            'pypcap is not installable on this interpreter, so it was not built into this image'
        )
        documents.append(document(
            f'{series}-pcap_ct', dict(shared, pcap_ct=[base / 25, base / 25 * 1.01]),
            ct_unmeasured, python=f'{series}.7',
            image=f'pcapkit-benchmark:py{series} (sha256:{index}{index})',
            packages={'dpkt': '1.9.8', 'pypcap': None, 'pcap-ct': '1.3.0b3'}))

        if series in pypcap_on:
            documents.append(document(
                f'{series}-pypcap', dict(shared, pypcap=[base / 32, base / 32 * 1.01]),
                dict(unmeasured, pcap_ct='the installed `pcap` module is pypcap, not pcap-ct'),
                python=f'{series}.7',
                image=f'pcapkit-benchmark:py{series} (sha256:{index}{index})'))
    return documents


class TestVersionSeries:
    """Which column a document lands in, and in what order the columns go."""

    def test_series_comes_from_the_interpreter_not_the_label(self):
        """The recorded version wins over the environment's name.

        These are not the same kind of fact. The label is a name the runner chose
        when it started the container; the version is what the interpreter answered
        once it was running. If they ever disagree -- a mislabelled build, a
        hand-edited document -- filing the numbers under the label would put one
        interpreter's figures in another's column, silently, which is the whole class
        of error this harness is built to refuse.

        """
        doc = document('3.12-pcap_ct', {'default': [0.2]}, python='3.11.14')
        assert report.python_series(doc) == '3.11'

    def test_columns_are_ordered_numerically(self):
        """3.9 comes before 3.10, which no string sort of these gets right."""
        docs = [document('3.9-pcap_ct', {'default': [0.2]}, python='3.9.18'),
                document('3.10-pcap_ct', {'default': [0.2]}, python='3.10.19'),
                document('3.11-pcap_ct', {'default': [0.2]}, python='3.11.14')]
        assert report.version_columns(docs) == ['3.9', '3.10', '3.11']

    def test_two_virtualenvs_of_one_version_are_one_column(self):
        """A column is a Python version, not an environment."""
        docs = matrix(versions=('3.11',))
        assert len(docs) == 2
        assert report.version_columns(docs) == ['3.11']

    def test_a_version_that_produced_nothing_still_gets_a_column(self):
        """A version that could not be built is a gap, not a question never asked.

        Dropping the column would make "we could not measure this" indistinguishable
        from "this was not part of the run", and a reader has no way to tell those
        apart from the table alone.

        """
        docs = matrix(versions=('3.11',))
        assert report.version_columns(docs, [('3.15', 'no image')]) == ['3.11', '3.15']


class TestAbsolutesByVersion:
    """The per-version grid, which is milliseconds rather than ratios."""

    def test_a_cell_pools_both_virtualenvs_of_that_interpreter(self):
        """Both environments measure the same engine on the same Python.

        So both readings belong in that interpreter's cell: they differ only in which
        ``pcap`` provider happened to be installed alongside, which is nothing to do
        with the engine being timed.

        """
        docs = matrix(versions=('3.11',))
        grid = report.absolutes_by_version(docs)
        # `dpkt` is in both environments, twice each; `pypcap` only in the one.
        assert len(grid['dpkt']['3.11']) == 4
        assert len(grid['pypcap']['3.11']) == 2

    def test_a_pass_without_a_baseline_still_has_an_absolute_figure(self):
        """A missing baseline costs a ratio, not a measurement.

        :func:`report.collect` must drop such a pass, since there is nothing to divide
        by. The absolute figure is complete on its own, and discarding it here would
        lose a real measurement to a rule that does not apply to it.

        """
        docs = [document('3.11-pcap_ct', {'default': [0.2], 'dpkt': [0.02, 0.03]})]
        rows = {row.engine: row for row in report.collect(docs)}
        assert len(rows['dpkt'].ratios) == 1

        grid = report.absolutes_by_version(docs)
        assert grid['dpkt']['3.11'] == pytest.approx([0.02, 0.03])

    def test_an_engine_measured_nowhere_has_no_cell(self):
        """An engine no interpreter ran contributes nothing to the grid."""
        docs = matrix(versions=('3.12',))
        assert '3.12' not in report.absolutes_by_version(docs).get('pypcap', {})


class TestUnmeasuredByVersion:
    """Explaining the empty cells, and only the empty ones."""

    def test_measured_in_one_virtualenv_is_not_a_gap(self):
        """``pypcap`` has a figure for 3.11 even though one environment lacks it.

        The mutual exclusion is real and is reported in the ratio table's per-row
        reasons, but it is not a gap in *this* table: the cell is filled. A footnote
        explaining a cell that is not empty is a footnote that contradicts the table
        it annotates.

        """
        docs = matrix(versions=('3.11',))
        reasons = report.unmeasured_by_version(docs)
        assert 'pypcap' not in reasons
        assert 'pcap_ct' not in reasons

    def test_a_genuinely_empty_cell_keeps_its_reason(self):
        """Where no environment measured it, the reason survives."""
        docs = matrix(versions=('3.12',))
        reasons = report.unmeasured_by_version(docs)
        assert 'not installable on this interpreter' in reasons['pypcap']['3.12']
        assert 'pypcapfile does not support Python 3.12' in reasons['pypcapfile']['3.12']

    def test_environments_disagreeing_about_one_cell_report_both(self):
        """Two reasons for one empty cell are both kept, attributed.

        A disagreement is the informative case -- an engine unavailable in the
        ``pypcap`` environment because of the ``pcap`` collision is a different fact
        from the same engine unavailable because ``tshark`` is missing -- so picking
        one of them would throw away the half that explains the other.

        """
        docs = [document('3.11-pypcap', {'default': [0.2]},
                         {'pyshark': 'no tshark binary'}),
                document('3.11-pcap_ct', {'default': [0.2]},
                         {'pyshark': 'python too new'})]
        reason = report.unmeasured_by_version(docs)['pyshark']['3.11']
        assert 'in 3.11-pypcap, no tshark binary' in reason
        assert 'in 3.11-pcap_ct, python too new' in reason


class TestVersionsMarkup:
    """The per-version table as it will be pasted into docs/source/index.rst."""

    def _snippet(self, missing=(), emulated=None, **kwargs):
        """Render the per-version snippet from a whole matrix run."""
        docs = matrix(**kwargs)
        rows = report.collect(docs)
        return report.render_versions_rst(rows, docs, missing, emulated), docs, rows

    def test_no_sphinx_only_roles(self):
        """Only literals, because docutils renders unknown roles as errors."""
        snippet, _, _ = self._snippet()
        for role in SPHINX_ONLY_ROLES:
            assert role not in snippet, f'{role} is Sphinx-only and breaks on GitHub'

    def test_parses_under_plain_docutils(self):
        """The snippet renders cleanly with the parser GitHub actually uses.

        A simple table is the format most easily broken by a cell that outgrows its
        column rule, and this table's cells are generated from measurements -- so the
        width that works today is not evidence about the width a slower engine
        produces tomorrow.

        """
        docutils_core = pytest.importorskip('docutils.core')
        from docutils.utils import SystemMessage  # pylint: disable=import-outside-toplevel

        snippet, _, _ = self._snippet(missing=[('3.15', 'the image failed to build')])
        messages = []
        try:
            docutils_core.publish_doctree(
                snippet,
                settings_overrides={
                    'halt_level': 2, 'report_level': 2, 'warning_stream': messages,
                    'input_encoding': 'unicode', 'output_encoding': 'unicode',
                },
            )
        except SystemMessage as exc:  # pragma: no cover - only on a real failure
            pytest.fail(f'docutils rejected the snippet: {exc}\n\n{snippet}')
        assert not messages, f'docutils warned: {messages}\n\n{snippet}'

    def test_the_figures_are_absolute_and_never_a_ratio(self):
        """Milliseconds, said in words, and no ratio anywhere in the snippet.

        Ratios are normalised inside one environment, so a ratio between two columns
        of this table would describe neither interpreter. The baseline row is the test
        that this has not been confused: in the ratio table ``pcapkit`` is 1 by
        definition, and here it must carry its own measured milliseconds like every
        other row.

        """
        snippet, _, _ = self._snippet(versions=('3.11',))
        assert 'milliseconds per' in snippet
        assert 'ratio' not in snippet.lower()
        assert 'relative' not in snippet.lower()
        assert '*baseline*' not in snippet

        pcapkit_row = [line for line in snippet.splitlines()
                       if line.startswith('``pcapkit``')][0]
        # 0.20 and 0.202 from each of the two virtualenvs, so the median of the four
        # pooled readings -- and emphatically not the 1 the ratio table gives it.
        assert '0.2010' in pcapkit_row

    def test_columns_are_labelled_comparable_with_each_other_only(self):
        """The one caveat absolute figures need, in the snippet rather than beside it."""
        snippet, _, _ = self._snippet()
        assert 'compared with each other' in snippet
        assert 'may not be' in snippet
        assert 'another machine' in snippet

    def test_an_unmeasured_cell_is_a_dash(self):
        """Never a zero, and never an absent row."""
        snippet, _, _ = self._snippet()
        pypcap_row = [line for line in snippet.splitlines()
                      if line.startswith('``pypcap``')][0]
        # Measured on 3.10 and 3.11, unmeasurable on the three newer interpreters.
        assert pypcap_row.count('--') == 3

    def test_every_engine_has_a_row_whatever_it_managed(self):
        """A row per engine, in the same order as the ratio table.

        The two tables are read together, and an engine that moves between them costs
        the reader the ability to carry their eye from one to the other.

        """
        snippet, _, rows = self._snippet()
        positions = [snippet.index(f'``{row.label}``') for row in rows]
        assert positions == sorted(positions)
        assert len(positions) == len(rows)

    def test_an_engine_with_a_gap_is_marked_and_explained(self):
        """The mark points at a reason, and the reason is the engine's own."""
        snippet, _, _ = self._snippet()
        assert f'``pypcapfile`` {report.UNMEASURED_MARK}' in snippet
        assert 'pypcapfile does not support Python 3.12' in snippet

    def test_a_fully_measured_engine_is_not_marked(self):
        """No mark on a row with nothing to explain."""
        snippet, _, _ = self._snippet()
        assert f'``dpkt`` {report.UNMEASURED_MARK}' not in snippet

    def test_one_reason_covering_several_versions_is_stated_once(self):
        """Notes are grouped by reason, not one bullet per empty cell.

        With five columns and seven engines the ungrouped form runs to more lines than
        the table it annotates, and reads as though each repetition were a separate
        finding.

        """
        snippet, _, _ = self._snippet()
        note = [line for line in snippet.splitlines()
                if line.startswith('* ``pypcap``')]
        assert len(note) == 1
        assert '3.12, 3.13, 3.14' in note[0]

    def test_a_missing_version_is_a_marked_column_of_dashes(self):
        """A version that produced nothing says so in the table and in a note."""
        snippet, _, _ = self._snippet(
            missing=[('3.15', 'the py3.15 image failed to build')])
        assert f'3.15 {report.UNMEASURED_MARK}' in snippet
        assert '* Python 3.15 -- not measured at all: the py3.15 image failed to build' in snippet

    def test_a_missing_version_does_not_blame_the_engines(self):
        """No engine is marked for a column that never ran.

        The column's own note explains every blank in it, and tagging each engine as
        well would attribute someone else's build failure to seven engines that were
        never given the chance to fail.

        """
        snippet, _, rows = self._snippet(versions=('3.11',),
                                        missing=[('3.15', 'the image failed to build')])
        assert f'3.15 {report.UNMEASURED_MARK}' in snippet
        # Every engine, not a sample of two: on 3.11 all seven are measurable, so the
        # only mark in the whole table should be the one on the 3.15 column heading.
        for row in rows:
            assert f'``{row.label}`` {report.UNMEASURED_MARK}' not in snippet
        assert snippet.count(report.UNMEASURED_MARK) == 2  # the heading, and its legend

    def test_a_partly_measured_version_is_not_called_unmeasured(self):
        """A version can have both figures and a failure note, and both are true.

        `run.sh` copies out whatever a container wrote before it died, so a 3.11 whose
        second virtualenv crashed arrives with real measurements *and* a recorded
        reason. Calling that column "not measured at all" would contradict the numbers
        printed in it, and suppressing the engines' own gap reasons -- as a column with
        nothing in it rightly does -- would leave those gaps unexplained.

        """
        snippet, _, _ = self._snippet(
            versions=('3.11', '3.12'),
            missing=[('3.11', 'the 3.11-pypcap container exited non-zero')])
        assert 'not measured at all' not in snippet
        assert 'the run did not complete' in snippet
        # The column keeps its figures...
        dpkt_row = [line for line in snippet.splitlines() if line.startswith('``dpkt``')][0]
        assert dpkt_row.count('--') == 0
        # ...and an engine with a real gap in it is still marked and still explained.
        assert f'``pypcapfile`` {report.UNMEASURED_MARK}' in snippet
        assert 'pypcapfile does not support Python 3.12' in snippet

    def test_emulation_warning_reaches_the_snippet(self):
        """An absolute figure taken under emulation describes the emulator."""
        snippet, _, _ = self._snippet(
            emulated='Measured under emulation: linux/amd64 on arm64.')
        assert 'emulation' in snippet.lower()
        assert 'not comparable with' in snippet

    def test_figure_columns_all_share_one_width(self):
        """A ragged table of like quantities reads as unlike quantities."""
        snippet, _, _ = self._snippet()
        rule = [line for line in snippet.splitlines() if line.startswith('====')][0]
        widths = [len(run) for run in rule.split()]
        assert len(set(widths[1:])) == 1


class TestMatrixProvenance:
    """What the Test Environment block says once there is more than one interpreter."""

    def test_every_interpreter_is_named(self):
        """Naming only the first would describe one column and imply it stood for all."""
        docs = matrix()
        snippet = report.render_rst(report.collect(docs), docs)
        for version in ('3.10.7', '3.11.7', '3.12.7', '3.13.7', '3.14.7'):
            assert version in snippet

    def test_each_version_names_the_image_it_came_from(self):
        """The image is the only thing tying a column to a specific build."""
        docs = matrix(versions=('3.11', '3.12'))
        snippet = report.render_rst(report.collect(docs), docs)
        assert 'Image (3.11)' in snippet
        assert 'Image (3.12)' in snippet

    def test_a_single_interpreter_still_reports_one_image(self):
        """One version, one image, one row -- not a row labelled with its own version."""
        docs = matrix(versions=('3.11',))
        snippet = report.render_rst(report.collect(docs), docs)
        assert 'Image (3.11)' not in snippet
        assert 'pcapkit-benchmark:py3.11' in snippet

    def test_distinct_tshark_versions_are_all_reported(self):
        """``pyshark``'s figures are as much about tshark as about the package.

        Every image in the matrix is built on the same Debian precisely so that this
        line has one entry, which makes a second entry the signal that something in
        the base images has drifted apart -- so all of them are reported rather than
        just the first.

        """
        docs = [document('3.11-pcap_ct', {'default': [0.2]}, python='3.11.14',
                         tshark='TShark (Wireshark) 4.0.17'),
                document('3.12-pcap_ct', {'default': [0.2]}, python='3.12.12',
                         tshark='TShark (Wireshark) 4.2.2')]
        snippet = report.render_rst(report.collect(docs), docs)
        assert '4.0.17' in snippet
        assert '4.2.2' in snippet

    def test_a_missing_version_is_recorded_in_the_provenance(self):
        """The ratio table pools the interpreters, so it has to say which ones."""
        docs = matrix(versions=('3.11',))
        snippet = report.render_rst(report.collect(docs), docs,
                                    missing=[('3.15', 'the image failed to build')])
        assert 'Python 3.15 (not measured)' in snippet
        assert 'the image failed to build' in snippet

    def test_a_partly_measured_version_says_partly(self):
        """A version that contributed figures before failing is not "not measured"."""
        docs = matrix(versions=('3.11',))
        snippet = report.render_rst(report.collect(docs), docs,
                                    missing=[('3.11', 'one container exited non-zero')])
        assert 'Python 3.11 (partly measured)' in snippet

    def test_pooling_across_interpreters_is_declared(self):
        """A ratio pooled over five interpreters must not read as one interpreter's."""
        docs = matrix()
        snippet = report.render_rst(report.collect(docs), docs)
        assert 'pooled across every environment' in snippet

        # ...and not claimed on a run that had only one interpreter to pool.
        single = matrix(versions=('3.11',))
        assert 'pooled across every environment' not in \
            report.render_rst(report.collect(single), single)

    def test_a_packet_count_disagreement_is_reported_not_dropped(self):
        """One capture must yield one frame count on every interpreter.

        If it does not, that is the most important thing in the report -- and the
        previous behaviour was to print no row at all, which hid precisely the case the
        row exists to establish. With one interpreter the disagreement was barely
        possible; across a matrix it is a real failure mode.

        """
        docs = matrix(versions=('3.11', '3.12'))
        for entry in docs[-1]['results']:
            entry['packets'] = 5 if entry['packets'] else entry['packets']
        snippet = report.render_rst(report.collect(docs), docs)
        assert 'Packets per extraction' in snippet
        assert 'disagreed across the run' in snippet
        assert '3.11 6' in snippet
        assert '3.12 5' in snippet

    def test_an_agreeing_packet_count_is_just_the_number(self):
        """No alarm on the normal case."""
        docs = matrix(versions=('3.11', '3.12'))
        snippet = report.render_rst(report.collect(docs), docs)
        assert 'disagreed' not in snippet
        assert 'Packets per extraction' in snippet

    def test_the_sample_column_is_not_called_passes(self):
        """A pass happens once per environment, so samples outnumber passes.

        The provenance block says "3 passes ... in 7 environments" and the table's own
        count is the product of the two. Calling both "Passes" read as a contradiction
        as soon as there was more than one interpreter.

        """
        docs = matrix(versions=('3.11', '3.12'))
        snippet = report.render_rst(report.collect(docs), docs)
        table = snippet.split('Test Results (Relative)')[1]
        assert 'Samples' in table
        assert 'Passes' not in table
        # ...while the provenance block above still counts passes, in passes.
        assert 'Passes' in snippet.split('Test Results (Relative)')[0]

    def test_the_two_tables_do_not_share_a_heading(self):
        """Two sections named "Test Results" on one page is one too many.

        Both snippets are pasted into the same document, and a reader then has no way
        to say which table a sentence underneath is about.

        """
        docs = matrix(versions=('3.11',))
        rows = report.collect(docs)
        assert 'Test Results (Relative)' in report.render_rst(rows, docs)
        assert 'Test Results (Relative)' not in report.render_versions_rst(rows, docs)


class TestPinsFile:
    """`python-images.txt` is the whole matrix, and nothing else validates it.

    `run.sh` reads it with awk and would happily act on a malformed row -- a missing
    field silently becomes a row awk skips, so the version quietly stops being measured
    with no error anywhere. These are the assertions that would otherwise only be made
    by a benchmark run that takes two hours to reach them.

    """

    #: Field meanings, matching the header comment in the file itself.
    FIELDS = ('version', 'image', 'pypcap', 'tier')

    def _rows(self):
        """The real rows, filtered exactly as `run.sh`'s awk does."""
        path = Path(__file__).resolve().parent / 'python-images.txt'
        rows = []
        for line in path.read_text(encoding='utf-8').splitlines():
            fields = line.split()
            if not fields or fields[0].startswith('#') or len(fields) < len(self.FIELDS):
                continue
            rows.append(dict(zip(self.FIELDS, fields)))
        return rows

    def test_every_row_has_every_field(self):
        """A short row is one awk skips, which is a version silently not measured."""
        rows = self._rows()
        assert rows, 'no rows parsed at all; run.sh would have nothing to measure'
        for row in rows:
            assert all(row[field] for field in self.FIELDS), row

    def test_every_base_image_is_pinned_by_digest(self):
        """A tag pin is not a pin -- the file's own header says so.

        `3.11-slim-bookworm` is rebuilt whenever Debian or CPython ships a patch, so a
        row that lost its digest would keep working and quietly measure a different
        interpreter than the one the last run measured.

        """
        for row in self._rows():
            assert '@sha256:' in row['image'], row
            assert len(row['image'].split('@sha256:')[1]) == 64, row

    def test_the_pypcap_and_tier_columns_use_the_documented_words(self):
        """`run.sh` compares these literally, so a synonym is a silent behaviour change."""
        for row in self._rows():
            assert row['pypcap'] in ('pypcap', 'no-pypcap'), row
            assert row['tier'] in ('default', 'opt-in'), row

    def test_a_default_run_measures_something(self):
        """`run.sh` with no arguments has to have a matrix to run."""
        assert [row['version'] for row in self._rows() if row['tier'] == 'default']

    def test_pypcap_is_offered_only_where_it_can_be_installed(self):
        """The ceiling is 3.11: building that virtualenv on 3.12+ compiles for nothing."""
        for row in self._rows():
            expected = 'pypcap' if tuple(int(part) for part in row['version'].split('.')) \
                <= (3, 11) else 'no-pypcap'
            assert row['pypcap'] == expected, row

    def test_the_dockerfile_default_matches_the_pins_file(self):
        """The 3.11 digest is written in two places, so it can drift in one.

        The Dockerfile needs a usable default so that a bare ``docker build`` works, and
        `run.sh`'s header claims nothing about the matrix is hard-coded elsewhere. Both
        are reasonable; together they are a duplicated pin, and this is the only thing
        that would notice them disagreeing.

        """
        pinned = {row['version']: row['image'] for row in self._rows()}['3.11']
        dockerfile = (Path(__file__).resolve().parent / 'Dockerfile').read_text(encoding='utf-8')
        default = [line.split('=', 1)[1].strip() for line in dockerfile.splitlines()
                   if line.startswith('ARG PYTHON_IMAGE=')]
        assert default == [pinned]


class TestHostileReasons:
    """Reasons are written by compilers and exceptions, not by this harness.

    Every reason in the report comes from somewhere that has never heard of
    reStructuredText: an engine's ``unsupported_reason()``, an exception's ``str()``,
    or the tail of a pip or gcc log that the Dockerfile recorded because a `pypcap`
    build was allowed to fail. All of it is interpolated into emitted markup as prose,
    and the suite's other fixtures are all well-behaved English -- which is exactly why
    this went unnoticed until a hostile string was tried.

    """

    #: Strings a compiler or a Python traceback produces without trying, each of which
    #: broke the emitted snippet under plain docutils before the escaping went in.
    HOSTILE = (
        # `**kwargs` in a gcc diagnostic: inline strong start-string without end-string.
        'gcc: error: **kwargs handling broke the build',
        # GNU tools quote like `this', so the backtick never balances.
        "pip said: cannot find `pcap.h",
        # A trailing underscore is a reference: unknown target name.
        'linklayer imports imp_ which was removed in 3.12',
        # A paragraph ending in `::` promises a literal block that never arrives.
        'the build died here::',
        # And the rest of the inline markup characters, together.
        'a *very* |odd| [1] c:\\path\\to\\thing reason',
    )

    def _documents(self, reason):
        """A two-interpreter run in which every reason is *reason*."""
        return [
            document('3.11-pcap_ct', {'default': [0.2, 0.2], 'dpkt': [0.02, 0.02]},
                     {'pypcap': reason}, failures={'dpkt': [reason]}),
            document('3.12-pcap_ct', {'default': [0.2, 0.2], 'dpkt': [0.02, 0.02]},
                     {'pypcap': reason}, python='3.12.12'),
        ]

    @pytest.mark.parametrize('reason', HOSTILE)
    def test_both_snippets_still_parse(self, reason):
        """A gcc diagnostic in a reason must not break the pasted table.

        The promise is that these snippets go into docs/source/index.rst verbatim,
        and that they stay parseable by plain docutils -- where each of these strings
        produces a visible error block instead of the table.

        """
        docutils_core = pytest.importorskip('docutils.core')
        from docutils.utils import SystemMessage  # pylint: disable=import-outside-toplevel

        docs = self._documents(reason)
        rows = report.collect(docs)
        for snippet in (report.render_versions_rst(rows, docs, [('3.15', reason)]),
                        report.render_rst(rows, docs, missing=[('3.15', reason)])):
            messages = []
            try:
                docutils_core.publish_doctree(
                    snippet,
                    settings_overrides={
                        'halt_level': 2, 'report_level': 2, 'warning_stream': messages,
                        'input_encoding': 'unicode', 'output_encoding': 'unicode',
                    },
                )
            except SystemMessage as exc:  # pragma: no cover - only on a real failure
                pytest.fail(f'docutils rejected a reason it should have survived: '
                            f'{exc}\n\n{snippet}')
            assert not messages, f'docutils warned: {messages}\n\n{snippet}'

    def test_the_reader_still_sees_the_original_text(self):
        """Escaping must not be censoring: the rendered document says what gcc said.

        A backslash escape is removed when reStructuredText is rendered, so this holds
        without the reason being rewritten -- which matters because the reason is
        diagnostic output and a paraphrase of it is worth nothing.

        """
        docutils_core = pytest.importorskip('docutils.core')

        reason = self.HOSTILE[0]
        docs = self._documents(reason)
        snippet = report.render_versions_rst(report.collect(docs), docs)
        rendered = docutils_core.publish_doctree(
            snippet,
            settings_overrides={'input_encoding': 'unicode', 'output_encoding': 'unicode',
                                'report_level': 5},
        ).astext()
        assert reason in rendered

    def test_the_plain_text_report_is_not_escaped(self):
        """Backslashes belong in markup, not in the operator's terminal."""
        reason = 'gcc: error: **kwargs handling broke the build'
        docs = self._documents(reason)
        text = report.render_text(report.collect(docs), docs, missing=[('3.15', reason)])
        assert reason in text
        assert '\\*' not in text

    def test_the_emulation_note_is_escaped_too(self):
        """`--emulated` is outside text as much as any reason is.

        `run.sh` composes that sentence itself, which makes it safe in practice and is
        exactly why it was the last channel left unescaped. It still arrives on the
        command line, and it reaches markup in two places -- a provenance row and a bold
        paragraph -- so a value with a stray ``*`` in it would break the snippet from a
        direction nobody was watching.

        """
        docutils_core = pytest.importorskip('docutils.core')
        from docutils.utils import SystemMessage  # pylint: disable=import-outside-toplevel

        emulated = 'Measured under **emulation**: a linux/amd64 image on an `arm64 host.'
        docs = self._documents('an ordinary reason')
        rows = report.collect(docs)
        for snippet in (report.render_versions_rst(rows, docs, (), emulated),
                        report.render_rst(rows, docs, emulated=emulated)):
            messages = []
            try:
                docutils_core.publish_doctree(
                    snippet,
                    settings_overrides={
                        'halt_level': 2, 'report_level': 2, 'warning_stream': messages,
                        'input_encoding': 'unicode', 'output_encoding': 'unicode',
                    },
                )
            except SystemMessage as exc:  # pragma: no cover - only on a real failure
                pytest.fail(f'docutils rejected the emulation note: {exc}\n\n{snippet}')
            assert not messages, f'docutils warned: {messages}\n\n{snippet}'

        # ...and the operator still sees it as it was written.
        assert emulated in report.render_text(rows, docs, emulated=emulated)


class TestFixedFormatting:
    """Formatting for a column read downwards rather than a value read alone."""

    @pytest.mark.parametrize(('value', 'expected'), [
        (0.017, '0.0170'),
        (14.7434, '14.7434'),
        (0.2516, '0.2516'),
    ])
    def test_four_decimal_places_whatever_the_magnitude(self, value, expected):
        """Decimal points line up, which is what makes a column scannable.

        Significant figures -- which every other number in the report uses -- would
        give ``0.01700`` and ``14.74`` different numbers of decimal places in the same
        column. Four places is also what the hand-maintained table in the docs has
        always used, so a regenerated table diffs its numbers rather than its layout.

        """
        assert report._fixed(value) == expected  # pylint: disable=protected-access


class TestMissingArgument:
    """The interface `run.sh` uses to get a build failure into the table."""

    def _one_document(self, tmp_path):
        """Write a minimal single-environment document to disk."""
        path = tmp_path / '3.11-pcap_ct.json'
        path.write_text(json.dumps(document('3.11-pcap_ct', {'default': [0.2, 0.2]})),
                        encoding='utf-8')
        return path

    def test_a_reason_becomes_a_column_and_a_note(self, tmp_path, capsys):
        """What run.sh records is what the reader sees."""
        path = self._one_document(tmp_path)
        assert report.main([str(path), '--missing', '3.15=no released image exists',
                            '--versions-rst-out', str(tmp_path / 'versions.rst')]) == 0
        snippet = (tmp_path / 'versions.rst').read_text(encoding='utf-8')
        assert '3.15' in snippet
        assert 'no released image exists' in snippet

    def test_a_version_without_a_reason_is_rejected(self, tmp_path):
        """A gap whose note says nothing is the outcome --missing exists to prevent."""
        path = self._one_document(tmp_path)
        with pytest.raises(SystemExit):
            report.main([str(path), '--missing', '3.15'])
        with pytest.raises(SystemExit):
            report.main([str(path), '--missing', '3.15='])

    def test_two_reasons_for_one_version_are_rejected(self, tmp_path):
        """There is no honest rendering of two reasons for one column.

        The provenance block would list both and the table's notes only the last, so the
        same run would report the gap differently in two places. `run.sh` writes one note
        file per version and cannot produce this; a hand-driven invocation is told.

        """
        path = self._one_document(tmp_path)
        with pytest.raises(SystemExit):
            report.main([str(path), '--missing', '3.15=first', '--missing', '3.15=second'])


class TestNotAttempted:
    """An engine the interpreter rules out, told apart from one that failed here."""

    def test_the_recorded_note_is_the_reason(self, monkeypatch, tmp_path):
        """The image says why it did not try, and that is what reaches the table."""
        benchmark = pytest.importorskip('benchmark')
        (tmp_path / 'pypcap.txt').write_text(
            'pypcap is not installable on this interpreter, so it was not built into\n'
            'this image: its pcap.c does not compile against the 3.12+ C API.\n',
            encoding='utf-8')
        monkeypatch.setattr(benchmark, 'NOT_ATTEMPTED', str(tmp_path))
        recorded = benchmark._not_attempted('pypcap')  # pylint: disable=protected-access
        assert 'not installable on this interpreter' in recorded
        # Collapsed to one line, since it lands in a table cell and an RST bullet.
        assert '\n' not in recorded

    def test_it_replaces_the_engine_s_own_reason(self, monkeypatch, tmp_path):
        """The cause wins over the symptom.

        On a 3.12 image the engine's own ``unsupported_reason()`` says the installed
        ``pcap`` module is ``pcap-ct`` -- true, and a description of how this image was
        assembled rather than of why it had to be. The reader is owed the interpreter
        ceiling, and stacking both would bury it behind the consequence.

        """
        benchmark = pytest.importorskip('benchmark')
        (tmp_path / 'pypcap.txt').write_text(
            'pypcap is not installable on this interpreter.\n', encoding='utf-8')
        monkeypatch.setattr(benchmark, 'NOT_ATTEMPTED', str(tmp_path))
        monkeypatch.setattr(benchmark, '_declared_reason',
                            lambda engine: 'the installed `pcap` module is pcap-ct, not pypcap')

        reason, driver = benchmark.preflight('pypcap', str(tmp_path / 'unused.pcap'))
        assert reason == 'pypcap is not installable on this interpreter.'
        assert 'pcap-ct' not in reason
        assert driver is None

    def test_an_engine_that_was_attempted_records_nothing(self, monkeypatch, tmp_path):
        """The normal case, for every engine the image did install."""
        benchmark = pytest.importorskip('benchmark')
        monkeypatch.setattr(benchmark, 'NOT_ATTEMPTED', str(tmp_path / 'absent'))
        assert benchmark._not_attempted('dpkt') is None  # pylint: disable=protected-access

    def test_prose_is_rejoined_as_prose_and_log_output_is_not(self, monkeypatch, tmp_path):
        """A wrapped sentence comes back as a sentence, pip output keeps its records.

        Both notes are flattened to one line, because both end up in a table cell and
        an RST bullet -- but they are not the same kind of text. Measured: the
        interpreter-ceiling note joined with the pip separator read ``not built into
        this | image: pypcap 1.3.0 ships ...``, which is the Dockerfile's line wrapping
        leaking into a published table.

        """
        benchmark = pytest.importorskip('benchmark')
        (tmp_path / 'pypcap.txt').write_text('one sentence wrapped\nacross two lines.\n',
                                             encoding='utf-8')
        monkeypatch.setattr(benchmark, 'NOT_ATTEMPTED', str(tmp_path))
        monkeypatch.setattr(benchmark, 'INSTALL_FAILURES', str(tmp_path))
        assert benchmark._not_attempted('pypcap') == 'one sentence wrapped across two lines.'
        assert benchmark._install_failure('pypcap') == \
            'one sentence wrapped | across two lines.'


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
