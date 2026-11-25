# -*- coding: utf-8 -*-
"""#3054: a table a step writes to its job summary renders as a table.

GitHub renders each step's ``$GITHUB_STEP_SUMMARY`` on its own ("Step isolation and
limits" in the workflow commands reference), so rows render as a table only when the
step that wrote them wrote the header and delimiter rows above them; and a ``|`` that
nothing escaped ends a cell wherever it came from. :func:`problems` reads a page as
GitHub splits it, offline.

* :class:`TestTheEngineCells` runs ``engine-tests``' summary steps in order, each with
  a page of its own as on the runner: every page is whole tables, and an empty KTLO
  tier writes none.
* :class:`TestTheBenchmarkMarkdown` runs :file:`examples/benchmark/report.py`'s
  Markdown tables, and ``Write the report`` over them: a table for each
  reStructuredText one, which the report folds beneath it.

"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import subprocess  # nosec: B404
import tempfile
import unittest
import unittest.mock
from typing import TYPE_CHECKING

from tests._support import bash_argv
from tests._workflows import job

if TYPE_CHECKING:
    from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
REPORT = ROOT / 'examples' / 'benchmark' / 'report.py'
NATIVE = ROOT / 'examples' / 'benchmark' / 'native.sh'
#: A delimiter row's cell: dashes, with a colon at either end or neither.
DELIMITER = re.compile(r'^:?-+:?$')
#: A ``|`` no backslash escapes, where GitHub splits a row into cells.
PIPE = re.compile(r'(?<!\\)\|')
#: ``engine-tests``' steps that write its summary, in order.
WRITER, SUPPORTED = 'Write the per-cell script', 'Run the supported cells'
KTLO = 'Run the KTLO cells (non-blocking)'
#: The cell script's stand-in: a row on a pass, as the real one writes it, and a failure on 3.10.
CELL = ('case "$1" in 3.10) exit 1 ;; esac\n'
        'echo "| $1 | $ENGINE | supported | passed |" '
        '| tee -a "$RUNNER_TEMP/job-summary.md" >> "$GITHUB_STEP_SUMMARY"\n')
#: The ``<details>`` block ``Write the report`` folds a table's reStructuredText in.
FOLD = ('<details>\n<summary>reStructuredText for docs/source/engines.rst</summary>\n\n'
        '```rst\n{}```\n\n</details>\n')


def cells(line: 'str') -> 'list[str]':
    """A table row's cells, split at each unescaped ``|``, without the outer pipes."""
    parts = [part.strip() for part in PIPE.split(line.strip())]
    return parts[1:-1] if len(parts) > 1 and not parts[0] and not parts[-1] else parts


def tables(text: 'str') -> 'list[list[list[str]]]':
    """Each run of lines starting with ``|`` in ``text``, as its rows of cells."""
    found = []  # type: list[list[list[str]]]
    block = []  # type: list[list[str]]
    for line in [*text.splitlines(), '']:
        if line.startswith('|'):
            block.append(cells(line))
        elif block:
            found.append(block)
            block = []
    return found


def problems(text: 'str') -> 'list[str]':
    """Why a table in ``text`` would not render whole, one entry each; empty where none."""
    found = []  # type: list[str]
    for header, *rows in tables(text):
        if not rows or len(rows[0]) != len(header) or not all(map(DELIMITER.match, rows[0])):
            found.append(f'no delimiter row under {header}')
            continue
        found.extend(f'{row} has {len(row)} cells under {len(header)} headers'
                     for row in rows[1:] if len(row) != len(header))
    return found


def step(workflow: 'str', job_id: 'str', name: 'str') -> 'dict[str, Any]':
    """Job ``job_id``'s step named ``name``."""
    return next(entry for entry in job(workflow, job_id)['steps'] if entry.get('name') == name)


def bash(script: 'str', env: 'dict[str, str]', cwd: 'pathlib.Path') -> 'subprocess.CompletedProcess[str]':
    """``script`` as ``shell: bash`` runs it."""
    return subprocess.run(bash_argv('-eo', 'pipefail', '-c', script), env=dict(os.environ, **env),  # nosec: B603
                          cwd=cwd, capture_output=True, text=True, check=False, timeout=60)


class _Scratch(unittest.TestCase):

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-3054-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)


class TestTheEngineCells(_Scratch):
    """``engine-tests``: the step that writes a table's rows writes its header too."""

    def pages(self, ktlo: 'str') -> 'tuple[dict[str, str], str]':
        """Each summary step's page, with the cell script stood in, and the job's copy."""
        runner = pathlib.Path(tempfile.mkdtemp(dir=self.tmp))
        pages = {}  # type: dict[str, str]
        for name, value in ((WRITER, ''), (SUPPORTED, '3.11\n3.12'), (KTLO, ktlo)):
            page = runner / f'{len(pages)}.md'
            page.write_text('', encoding='utf-8')
            env = {'RUNNER_TEMP': str(runner), 'ENGINE': 'Scapy', 'PYTHONS': value,
                   'ANNOTATION_LEVEL': 'warning', 'GITHUB_STEP_SUMMARY': str(page)}
            result = bash(step('unit-tests.yml', 'engine-tests', name)['run'], env, runner)
            self.assertEqual(result.returncode, int(name == KTLO and '3.10' in value), result.stderr)
            if name == WRITER:
                (runner / 'engine-cell.sh').write_text(CELL, encoding='utf-8')
            pages[name] = page.read_text(encoding='utf-8')
        copy = runner / 'job-summary.md'
        return pages, copy.read_text(encoding='utf-8') if copy.exists() else ''

    def test_each_step_writes_whole_tables(self) -> None:
        pages, copy = self.pages('3.10')
        self.assertEqual(pages[WRITER], '')
        for name, rows in ((SUPPORTED, [['3.11', 'Scapy', 'supported', 'passed'],
                                        ['3.12', 'Scapy', 'supported', 'passed']]),
                           (KTLO, [['3.10', 'Scapy', '', 'FAILED (KTLO, non-blocking)']])):
            with self.subTest(step=name):
                self.assertEqual(problems(pages[name]), [])
                [table] = tables(pages[name])
                self.assertEqual(table[0], ['Python', 'Engine', 'Expect', 'Result'])
                self.assertEqual(table[2:], rows)
        self.assertIn('### Engine cells: Scapy\n', pages[SUPPORTED])
        self.assertIn('### Engine cells: Scapy (KTLO, non-blocking)\n', pages[KTLO])
        # The copy the CI-reports post folds in is the pages joined, two tables apart.
        self.assertEqual(copy, pages[SUPPORTED] + pages[KTLO])
        self.assertEqual((problems(copy), len(tables(copy))), ([], 2))

    def test_an_empty_ktlo_tier_writes_no_table(self) -> None:
        for tier in ('', ' ', '\n'):
            with self.subTest(tier=tier):
                pages, copy = self.pages(tier)
                self.assertEqual(pages[KTLO], '')
                self.assertEqual(copy, pages[SUPPORTED])

    def test_the_cell_script_writes_rows_alone(self) -> None:
        """Its summary lines are rows: the steps that run it write the header."""
        writer = step('unit-tests.yml', 'engine-tests', WRITER)
        lines = [line.strip() for line in writer['run'].splitlines() if '"$GITHUB_STEP_SUMMARY"' in line]
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertRegex(line, r'^echo "\| \$PY \| \$ENGINE \| \$EXPECT \| [^|$]+ \|" \| tee ')


class TestTheBenchmarkMarkdown(_Scratch):
    """report.py's Markdown tables, and ``Write the report``, which reads them."""

    HOSTILE = 'tshark | not found: `**kwargs` <none> & [x]_\nsee above'

    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location('benchmark_report_3054', REPORT)
        assert spec is not None and spec.loader is not None  # nosec: B101
        cls.report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.report)  # type: ignore[union-attr]

    @staticmethod
    def document(python: 'str', provider: 'str', measured: 'dict[str, list[float]]',
                 unmeasured: 'dict[str, str]', failures: 'dict[str, list[str]]') -> 'dict[str, Any]':
        """A :mod:`benchmark` document for ``python`` in the ``provider`` environment."""
        results = [{'engine': engine, 'status': 'measured', 'reason': None, 'driver': engine, 'packets': 6,
                    'repeats': [{'repeat': index, 'ms_per_packet': value, 'discarded': []}
                                for index, value in enumerate(values)],
                    'failures': failures.get(engine, [])} for engine, values in measured.items()]
        results += [{'engine': engine, 'status': 'unmeasured', 'reason': reason, 'driver': None, 'packets': None,
                     'repeats': [], 'failures': []} for engine, reason in unmeasured.items()]
        return {'schema': 1, 'environment': f'{python}-{provider}', 'pcapkit_revision': 'abc1234', 'image': None,
                'python': f'{python}.1', 'implementation': 'CPython', 'machine': 'x86_64',
                'capture': {'name': 'in.pcap', 'bytes': 605, 'sha256': 'a' * 64}, 'rounds': 100, 'repeats': 2,
                'packages': {'dpkt': '1.9.8'}, 'tshark': None, 'libpcap': None, 'results': results}

    def documents(self) -> 'list[dict[str, Any]]':
        return [self.document('3.11', 'pcap_ct', {'default': [0.6, 0.62], 'dpkt': [0.3, 0.31]},
                              {'pyshark': self.HOSTILE}, {}),
                self.document('3.12', 'pcap_ct', {'default': [0.5, 0.52], 'dpkt': [0.28, 0.33]},
                              {'pyshark': 'tshark not found'}, {'dpkt': ['pass 1: Timeout | gave up']})]

    def test_each_renders_one_whole_table(self) -> None:
        docs, missing = self.documents(), [('3.13', 'no interpreter | found')]
        rows = self.report.collect(docs)
        ratio = self.report.render_markdown(rows, docs, missing)
        versions = self.report.render_versions_markdown(rows, docs, missing)
        for text in (ratio, versions):
            with self.subTest(text=text.splitlines()[0]):
                self.assertEqual(problems(text), [])
        [table] = tables(ratio)
        self.assertEqual(table[0], ['Engine', 'Relative time', 'Observed range', 'Samples'])
        self.assertEqual([row[0] for row in table[2:]], ['`dpkt` ¶', '`pcapkit`', '`pyshark`'])
        self.assertEqual(table[3], ['`pcapkit`', '1', '*baseline*', '4'])
        self.assertEqual(table[4], ['`pyshark`', '*not measured*', '--', '0'])
        [table] = tables(versions)
        self.assertEqual(table[0], ['Engine', '3.11', '3.12', '3.13'])
        self.assertEqual(table[1], ['---', '--:', '--:', '--:'])
        self.assertEqual(table[3], ['`pcapkit`', '0.6100', '0.5100', '--'])
        self.assertEqual(table[4], ['`pyshark`', '--', '--', '--'])

    def test_outside_text_is_escaped_onto_one_line(self) -> None:
        docs = self.documents()
        rows = self.report.collect(docs)
        escaped = 'tshark \\| not found: \\`\\*\\*kwargs\\` \\<none\\> \\& \\[x\\]\\_ see above'
        self.assertIn(f'- `pyshark` not measured: in 3.11-pcap\\_ct, {escaped}; in 3.12-pcap\\_ct, tshark not '
                      'found\n', self.report.render_markdown(rows, docs))
        self.assertIn('- ¶ `dpkt` rests on less evidence than the rows beside it: in 3.12-pcap\\_ct, '
                      'pass 1: Timeout \\| gave up\n', self.report.render_markdown(rows, docs))
        self.assertIn(f'- `pyshark` not measured on 3.11: {escaped}\n',
                      self.report.render_versions_markdown(rows, docs))

    def test_main_writes_the_markdown_before_the_rst(self) -> None:
        """``Write the report`` runs once ``table.rst`` exists, so it is the last file written."""
        out = self.tmp / 'out'
        out.mkdir()
        paths = []
        for index, document in enumerate(self.documents()):
            paths.append(out / f'{index}.json')
            paths[-1].write_text(json.dumps(document), encoding='utf-8')
        written = []

        def recording(path: 'str', mode: 'str' = 'r', **kwargs: 'Any') -> 'Any':
            if 'w' in mode:
                written.append(pathlib.Path(path).name)
            return open(path, mode, **kwargs)  # pylint: disable=unspecified-encoding

        names = ('table-versions.md', 'table.md', 'table-versions.rst', 'table.rst')
        flags = ('--versions-md-out', '--md-out', '--versions-rst-out', '--rst-out')
        argv = [str(path) for path in paths]
        for flag, name in zip(flags, names):
            argv += [flag, str(out / name)]
        with unittest.mock.patch.object(self.report, 'open', recording, create=True), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.report.main(argv), 0)
        self.assertEqual(written[-1], 'table.rst')
        self.assertEqual(sorted(written), sorted(names))

    def test_the_report_step_folds_the_rst_under_each_table(self) -> None:
        out = self.tmp / 'out'
        out.mkdir()
        docs = self.documents()
        rows = self.report.collect(docs)
        texts = {'table.md': self.report.render_markdown(rows, docs),
                 'table-versions.md': self.report.render_versions_markdown(rows, docs),
                 'table.rst': self.report.render_rst(rows, docs),
                 'table-versions.rst': self.report.render_versions_rst(rows, docs)}
        for name, text in texts.items():
            (out / name).write_text(text, encoding='utf-8')
        summary = self.tmp / 'summary.md'
        env = {'GITHUB_STEP_SUMMARY': str(summary), 'RUNNER_LABEL': 'ubuntu-26.04-arm',
               'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'ARM64'}
        result = bash(step('benchmark.yml', 'benchmark', 'Write the report')['run'], env, self.tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (out / 'report.md').read_text(encoding='utf-8')
        page = summary.read_text(encoding='utf-8')
        self.assertTrue(report.endswith(f"\n{texts['table.md']}\n{FOLD.format(texts['table.rst'])}"))
        versions = FOLD.format(texts['table-versions.rst'])
        self.assertEqual(page, f"{report}\n{texts['table-versions.md']}\n{versions}")
        self.assertEqual((problems(report), problems(page)), ([], []))
        self.assertEqual((len(tables(report)), len(tables(page))), (1, 2))

    def test_native_sh_writes_what_the_step_reads(self) -> None:
        text = NATIVE.read_text(encoding='utf-8')
        self.assertIn('--md-out "${OUT_DIR}/table.md" --versions-md-out "${OUT_DIR}/table-versions.md"', text)
        self.assertIn('for table in table.rst table-versions.rst table.md table-versions.md; do', text)
        self.assertIn('"${OUT_DIR}/table.md" "${OUT_DIR}/table-versions.md"\n', text)


if __name__ == '__main__':
    unittest.main()
