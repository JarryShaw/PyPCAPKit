# -*- coding: utf-8 -*-
"""Turn benchmark JSON documents into paste-ready reStructuredText tables.

The first line above is deliberately free of Sphinx roles: :func:`main` hands it to
:mod:`argparse` as the command's description, where ``:mod:`benchmark``` would be
shown to the user verbatim.

:mod:`benchmark` measures one Python environment. This module stitches all of them
together and emits **two** tables, because the run answers two questions that want
different arithmetic:

**Which engine is faster?** :func:`render_rst` -- ratios against the ``default``
engine. An absolute figure describes the machine it was taken on at least as much as
it describes the engine, so a table of them cannot be reproduced and cannot be
compared with anything. A ratio against the ``default`` engine *measured in the same
environment on the same repeat* divides the machine out. It is also what makes
mutually exclusive environments joinable at all: ``pypcap`` and ``pcap_ct`` both
provide the top-level :mod:`pcap` module and cannot coexist, and ``default`` is the
engine present in every environment. One absolute number survives, as a footnote:
the baseline's own milliseconds per packet, which is what a reader needs to convert
the ratios back.

**How does each engine do on each interpreter?** :func:`render_versions_rst` --
absolute milliseconds per packet, one column per Python version. Here the machine
must *not* be divided out, and a ratio would be actively wrong: ratios are
normalised within one environment, so dividing across two interpreters would report
a number that is neither engine's speed nor the interpreter's. Every column of that
table was measured in one run on one host with everything but the interpreter held
constant, which is exactly the condition under which absolute times are comparable
-- with each other, and with nothing on any other machine.

So the two tables are not two formattings of one result and neither replaces the
other. The ratio table pools every interpreter and answers a question about engines;
the per-version table separates them and answers a question about interpreters.

**Why the spread is reported.** A single pass cannot distinguish a real difference
between two engines from the machine having been briefly busy. So the whole set is
measured several times and each row carries the range actually observed. Rows
whose ranges overlap are marked: this run does not establish which of them is
faster, and reporting their medians as though it did would be inventing precision.

The emitted markup is plain reStructuredText for **docutils**, which is what
renders the project's README on GitHub. No Sphinx-only roles (``:mod:``,
``:func:``, ``:manpage:``) appear in it -- only double-backtick literals -- because
docutils does not know them and renders them as errors.

"""

import argparse
import json
import math
import statistics
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterable, Optional, Sequence

__all__ = ['Row', 'absolutes_by_version', 'baseline_absolutes', 'collect', 'overlapping',
           'python_series', 'render_rst', 'render_text', 'render_versions_rst',
           'unmeasured_by_version', 'version_columns']

#: Engine name reported for ``pcapkit``'s own parser. ``pcapkit.extract`` accepts
#: ``'default'``; the README and the docs call it ``pcapkit``, and that is the
#: spelling the table uses.
BASELINE = 'default'

#: How the baseline is spelled in the report.
BASELINE_LABEL = 'pcapkit'

#: Marks a row whose observed range overlaps another row's, i.e. a gap this run
#: does not resolve. A double dagger rather than a footnote reference, so the
#: emitted snippet cannot collide with footnote numbers already in the README.
OVERLAP_MARK = '‡'

#: Marks a row that was not measured, and points at the note carrying the reason.
UNMEASURED_MARK = '†'

#: Marks a measured row that lost a pass, or had extractions discarded. The number
#: is still reported -- what was collected is real -- but it rests on less evidence
#: than the rows beside it, and that has to be visible rather than inferable from
#: the pass count.
PARTIAL_MARK = '¶'

#: Characters that begin reStructuredText inline markup, and therefore have to be
#: neutralised in any text this module did not write itself. See :func:`_escape`.
#: The backslash is first because the loop that applies these would otherwise escape
#: the backslashes it had just inserted.
RST_SPECIAL = ('\\', '`', '*', '_', '|', '[', ']')


def _escape(text: 'str') -> 'str':
    """Neutralise reStructuredText markup in text that came from elsewhere.

    Every reason in this report is written by something else -- an engine's
    ``unsupported_reason()``, an exception's ``str()``, the tail of a pip or gcc log
    that the image recorded -- and all of it lands in emitted markup as prose. None of
    those sources knows it is writing reStructuredText.

    Measured, with the same ``halt_level=2`` docutils settings the suite's own tests
    use, on strings a compiler produces without trying:

    * ``gcc: error: **kwargs handling broke the build`` -- *inline strong start-string
      without end-string*;
    * ``cannot find `pcap.h`` -- GNU diagnostics quote like that, and an unbalanced
      backtick is *inline interpreted text start-string without end-string*;
    * ``imports imp_ which was removed`` -- a trailing underscore is a reference, so
      *unknown target name: "imp"*;
    * anything ending ``::`` -- *literal block expected; none found*.

    Each of those turns the snippet this module promises can be pasted into
    :file:`README.rst` verbatim into a visible error block on GitHub, and the failure
    is invisible here because the harness's own fixtures are all well-behaved English.

    Args:
        text: Prose from outside this module.

    Returns:
        The same prose, with markup characters escaped. A backslash escape in
        reStructuredText is removed on rendering, so the reader sees the original.

    """
    for char in RST_SPECIAL:
        text = text.replace(char, '\\' + char)
    # Not in the loop above, because a colon is only dangerous at the end of a
    # paragraph -- and every reason here is its own single-line paragraph -- where
    # ``::`` promises a literal block that the next line is not. Escaping every colon
    # instead would put a backslash into the middle of most of these sentences for
    # nothing.
    if text.endswith(':'):
        text = text[:-1] + '\\:'
    return text


class Row:
    """One engine's line in the table.

    Args:
        engine: Engine name as ``pcapkit.extract`` spells it.
        label: How the engine is written in the table.
        ratios: Every ratio observed for it, one per (environment, repeat) pair.
        absolutes: The matching milliseconds per packet, for the human report.
        reasons: Why it could not be measured, keyed by environment. Empty when it
            was measured somewhere.
        environments: Environments that contributed a measurement.
        failures: Passes that failed outright, attributed to their environment.
        discarded: How many individual extractions were discarded as failures.

    """

    def __init__(self, engine: 'str', label: 'str', ratios: 'list[float]',
                 absolutes: 'list[float]', reasons: 'dict[str, str]',
                 environments: 'list[str]', failures: 'Optional[list[str]]' = None,
                 discarded: 'int' = 0) -> 'None':
        self.engine = engine
        self.label = label
        self.ratios = ratios
        self.absolutes = absolutes
        self.reasons = reasons
        self.environments = environments
        self.failures = failures or []
        self.discarded = discarded

    @property
    def partial(self) -> 'bool':
        """Whether this row lost a pass or discarded extractions."""
        return bool(self.failures) or self.discarded > 0

    @property
    def measured(self) -> 'bool':
        """Whether any environment produced a number for this engine."""
        return bool(self.ratios)

    @property
    def median(self) -> 'float':
        """Median of the observed ratios.

        The median rather than the mean: a repeat that landed on a scheduling
        hiccup is an outlier in one direction only, and the mean follows it.

        """
        return statistics.median(self.ratios)

    @property
    def low(self) -> 'float':
        """Smallest ratio observed."""
        return min(self.ratios)

    @property
    def high(self) -> 'float':
        """Largest ratio observed."""
        return max(self.ratios)

    @property
    def spread(self) -> 'float':
        """Observed range as a fraction of the median.

        Returns:
            ``(high - low) / median``, or ``0.0`` from a single sample -- where the
            honest answer is "not observed", which :func:`render_text` says in
            words rather than encoding as a number here.

        """
        if len(self.ratios) < 2 or self.median == 0:
            return 0.0
        return (self.high - self.low) / self.median

    @property
    def reason(self) -> 'str':
        """One phrase explaining why the engine was not measured.

        Environments usually agree, and when they do not the disagreement is the
        interesting part -- ``pypcap`` is unavailable in the ``pcap_ct``
        environment for a completely different reason than on an interpreter too
        new for it -- so every distinct reason is kept, attributed.

        """
        distinct = sorted(set(self.reasons.values()))
        if len(distinct) == 1:
            return distinct[0]
        return '; '.join(f'in {env}, {self.reasons[env]}' for env in sorted(self.reasons))


def _significant(value: 'float', digits: 'int' = 3) -> 'str':
    """Format *value* to *digits* significant figures, without exponent notation.

    Ratios in this table span three orders of magnitude -- ``pyshark`` is a
    subprocess spawn per extraction, ``dpkt`` is not -- so a fixed number of
    decimal places is either noise at one end or a rounded-away difference at the
    other.

    Implemented from the magnitude rather than with ``%g``, which reaches for an
    exponent outside roughly ``1e-5``..``1e6``: ``5e-09`` is correct and unreadable
    in a document that otherwise reads as prose, and a table of ratios should never
    make a reader parse scientific notation to see which row is faster.

    Args:
        value: Number to format.
        digits: Significant figures to keep.

    Returns:
        The formatted number, in plain decimal.

    """
    if value == 0:
        return '0'
    magnitude = math.floor(math.log10(abs(value)))
    # Never negative: a large number keeps its integer part in full rather than
    # being rounded to the requested significance, since '1235' misleads nobody and
    # '1.23e+03' does.
    decimals = max(0, digits - 1 - magnitude)
    return f'{value:.{decimals}f}'


def _range(low: 'float', high: 'float') -> 'str':
    """Format an observed range so it does not read as a range of one value.

    At three significant figures a genuinely tight range collapses: ``pypcap`` was
    measured at ``0.183-0.183``, which looks like a formatting bug and tells the
    reader nothing. So the precision is raised until the two ends differ, and if
    they still do not, the value is shown once -- "the range is narrower than the
    precision shown" rather than a fake interval.

    Args:
        low: Smallest value observed.
        high: Largest value observed.

    Returns:
        Either ``low-high`` or a single value.

    """
    for digits in (3, 4, 5):
        left, right = _significant(low, digits), _significant(high, digits)
        if left != right:
            return f'{left}-{right}'
    return _significant(low)


def _fixed(value: 'float', decimals: 'int' = 4) -> 'str':
    """Format *value* to a fixed number of decimal places.

    Used only by the per-version table, and deliberately not :func:`_significant`,
    which every other number in the report goes through. A column of figures is read
    down rather than one at a time, and significant figures give each row a different
    number of decimal places -- ``0.01700`` above ``14.74`` -- which is precisely the
    layout that makes a column impossible to scan. Fixed places line the decimal
    points up, and they are also what the table this replaces in
    :file:`README.rst` has always used, so a regenerated table is a diff of the
    numbers rather than a diff of the formatting.

    Args:
        value: Number to format.
        decimals: Decimal places to keep.

    Returns:
        The formatted number.

    """
    return f'{value:.{decimals}f}'


def python_series(document: 'dict[str, Any]') -> 'str':
    """The ``major.minor`` Python version a document was measured on.

    Read from the interpreter's own :func:`platform.python_version`, recorded at
    measuring time, rather than parsed out of the environment label. The label is a
    name the runner chose and the recorded version is what actually ran, so they are
    not the same kind of fact -- and if they ever disagreed, putting a document in the
    column its label claimed would be exactly the silent mislabelling the rest of this
    harness refuses to leave open.

    Args:
        document: One :mod:`benchmark` document.

    Returns:
        The series, e.g. ``'3.11'``.

    """
    parts = document['python'].split('.')
    return '.'.join(parts[:2]) if len(parts) >= 2 else document['python']


def _series_key(series: 'str') -> 'tuple[tuple[int, ...], str]':
    """Sort key that orders ``3.9`` before ``3.10`` rather than after it.

    The whole point: these are dotted numbers pretending to be strings, and every
    string sort of them is wrong from the moment a minor version reaches double
    digits. Non-numeric components fall back to the raw string, which keeps the sort
    total rather than raising on something unexpected.

    Args:
        series: A version, e.g. ``'3.10'`` or ``'3.10.19'``.

    Returns:
        A key that sorts numerically.

    """
    return tuple(int(part) for part in series.split('.') if part.isdigit()), series


def _ordered(documents: 'Sequence[dict[str, Any]]') -> 'list[dict[str, Any]]':
    """The documents in reporting order: by interpreter, then by environment name.

    Presentation only -- :func:`collect` keeps the order it was given, since the order
    ratios are pooled in does not change them. This exists so that what the report
    *says* does not depend on the order the JSON files happened to arrive in, which
    for a matrix of nine environments is otherwise a diff between two runs of the same
    thing.

    Args:
        documents: One :mod:`benchmark` document per environment.

    Returns:
        The same documents, ordered.

    """
    return sorted(documents,
                  key=lambda document: (_series_key(python_series(document)),
                                        document['environment']))


def version_columns(documents: 'Sequence[dict[str, Any]]',
                    missing: 'Sequence[tuple[str, str]]' = ()) -> 'list[str]':
    """Every Python version the run covers, oldest first.

    Includes the versions in *missing*, which produced no documents at all. A version
    whose image could not be built is a column of ``--`` with a reason, not an absent
    column: leaving it out would turn "we could not measure this" into "we did not ask
    about this", and the reader has no way to tell those apart from a table alone.

    Args:
        documents: One :mod:`benchmark` document per environment.
        missing: ``(version, reason)`` pairs for versions that produced nothing.

    Returns:
        The versions, in numeric order.

    """
    series = {python_series(document) for document in documents}
    series.update(version for version, _ in missing)
    return sorted(series, key=_series_key)


def absolutes_by_version(documents: 'Sequence[dict[str, Any]]'
                         ) -> 'dict[str, dict[str, list[float]]]':
    """Milliseconds per packet, pooled by engine and Python version.

    An engine measured in both virtualenvs of one interpreter contributes to that
    interpreter's cell from each, since the two are measuring the same engine on the
    same Python and the pooled median is the better figure.

    Note what is *not* required here, in contrast to :func:`collect`: a baseline. A
    pass whose ``default`` reading is missing or zero cannot yield a ratio and is
    dropped there, but its own millisecond figure is complete and is kept here.
    Discarding it would lose a real measurement to a rule that does not apply to it.

    Args:
        documents: One :mod:`benchmark` document per environment.

    Returns:
        ``{engine: {series: [ms_per_packet, ...]}}``, holding only what was measured.

    """
    grid = {}  # type: dict[str, dict[str, list[float]]]
    for document in documents:
        series = python_series(document)
        for entry in document['results']:
            if entry['status'] != 'measured':
                continue
            values = [sample['ms_per_packet'] for sample in entry['repeats']]
            if not values:
                continue
            grid.setdefault(entry['engine'], {}).setdefault(series, []).extend(values)
    return grid


def unmeasured_by_version(documents: 'Sequence[dict[str, Any]]'
                          ) -> 'dict[str, dict[str, str]]':
    """Why each engine has no figure for each Python version it has none for.

    Only cells that really are empty get a reason. An engine unmeasured in the
    ``pypcap`` environment and measured in the ``pcap_ct`` one on the same interpreter
    has a figure for that interpreter, and reporting the mutual exclusion as though it
    were a gap would explain a cell that is not there -- which is how a table acquires
    footnotes that contradict it.

    Args:
        documents: One :mod:`benchmark` document per environment.

    Returns:
        ``{engine: {series: reason}}``. Where the environments of one interpreter
        disagree, each reason is attributed to its environment, since a disagreement
        is more informative than either half of it.

    """
    measured = absolutes_by_version(documents)
    reasons = {}  # type: dict[str, dict[str, dict[str, str]]]
    for document in documents:
        series = python_series(document)
        for entry in document['results']:
            if entry['status'] == 'measured':
                continue
            engine = entry['engine']
            if series in measured.get(engine, {}):
                continue
            reasons.setdefault(engine, {}).setdefault(series, {})[document['environment']] = \
                entry['reason'] or 'no reason recorded'

    collapsed = {}  # type: dict[str, dict[str, str]]
    for engine, by_series in reasons.items():
        for series, by_environment in by_series.items():
            distinct = sorted(set(by_environment.values()))
            if len(distinct) == 1:
                collapsed.setdefault(engine, {})[series] = distinct[0]
            else:
                collapsed.setdefault(engine, {})[series] = '; '.join(
                    f'in {environment}, {by_environment[environment]}'
                    for environment in sorted(by_environment)
                )
    return collapsed


def _usable_baseline(value: 'Optional[float]') -> 'bool':
    """Whether a baseline reading can normalise the pass it was taken alongside.

    Args:
        value: The baseline's milliseconds per packet, or :data:`None` when the
            baseline did not run on that repeat at all.

    Returns:
        Whether dividing by it is meaningful.

    The two rejected cases are different problems that happen to share a fix.
    :data:`None` means no baseline was recorded for the repeat, so there is
    nothing to normalise against; ``0.0`` is a reading that *was* taken and
    cannot be divided by. Testing the value's truthiness alone would conflate
    them, and a zero baseline is a broken run worth telling apart from an absent
    one even though both drop the sample.

    """
    return value is not None and value > 0


def collect(documents: 'Sequence[dict[str, Any]]') -> 'list[Row]':
    """Build the table's rows from the per-environment documents.

    Each ratio is taken **within** one environment and one repeat, against that
    environment's own ``default`` measurement from that same repeat. Doing it any
    other way -- pooling the baselines first, or dividing by the other
    environment's baseline -- would put the drift the repeats exist to cancel
    straight back into the answer.

    An engine present in several environments contributes a ratio from each. That
    is deliberate: those ratios are already machine-normalised, so pooling them
    gives a better estimate, and the extra spread it exposes is a real part of the
    uncertainty rather than something to hide by picking one environment.

    Args:
        documents: One :mod:`benchmark` document per environment.

    Returns:
        One :class:`Row` per engine, ordered fastest first, with unmeasured
        engines last.

    Raises:
        ValueError: If *documents* is empty, or if an environment has no usable
            baseline -- without one, nothing in it can be normalised, and a table
            built from the remainder would silently be missing engines.

    """
    if not documents:
        raise ValueError('no benchmark documents to report on')

    ratios = {}  # type: dict[str, list[float]]
    absolutes = {}  # type: dict[str, list[float]]
    reasons = {}  # type: dict[str, dict[str, str]]
    environments = {}  # type: dict[str, list[str]]
    failures = {}  # type: dict[str, list[str]]
    discarded = {}  # type: dict[str, int]
    order = []  # type: list[str]

    for document in documents:
        env = document['environment']
        results = {entry['engine']: entry for entry in document['results']}

        base = results.get(BASELINE)
        if base is None or base['status'] != 'measured':
            raise ValueError(
                f'environment {env!r} has no {BASELINE!r} measurement, so its '
                f'engines cannot be normalised'
            )
        # Keyed by repeat index, so an engine is only ever divided by the baseline
        # it actually ran alongside.
        base_by_repeat = {sample['repeat']: sample['ms_per_packet']
                          for sample in base['repeats']}

        for entry in document['results']:
            engine = entry['engine']
            if engine not in order:
                order.append(engine)
            ratios.setdefault(engine, [])
            absolutes.setdefault(engine, [])
            reasons.setdefault(engine, {})
            environments.setdefault(engine, [])
            failures.setdefault(engine, [])
            discarded.setdefault(engine, 0)

            # Attributed to the environment: "the third pass failed" is far less
            # useful than knowing which of the two environments it failed in.
            for failure in entry.get('failures') or []:
                failures[engine].append(f'in {env}, {failure}')

            if entry['status'] != 'measured':
                reasons[engine][env] = entry['reason'] or 'no reason recorded'
                continue

            contributed = False
            for sample in entry['repeats']:
                divisor = base_by_repeat.get(sample['repeat'])
                if not _usable_baseline(divisor):
                    # No usable baseline for this repeat: the pair is unusable
                    # rather than approximable, so it is dropped instead of being
                    # divided by a baseline from a different repeat.
                    continue
                ratios[engine].append(sample['ms_per_packet'] / divisor)
                absolutes[engine].append(sample['ms_per_packet'])
                discarded[engine] += len(sample.get('discarded') or [])
                contributed = True
            if contributed:
                # Keyed on a ratio having survived, not on ``entry['repeats']``
                # being non-empty: passes whose baseline was missing contribute
                # nothing, and counting their environment would claim a
                # measurement the cross-environment check cannot then show.
                environments[engine].append(env)

    rows = [
        Row(engine,
            BASELINE_LABEL if engine == BASELINE else engine,
            ratios[engine], absolutes[engine], reasons[engine], environments[engine],
            failures[engine], discarded[engine])
        for engine in order
    ]
    # Fastest first, unmeasured last. The baseline lands wherever its ratio of 1.0
    # puts it, which is the honest place for it.
    rows.sort(key=lambda row: (not row.measured, row.median if row.measured else 0.0))
    return rows


def overlapping(rows: 'Iterable[Row]') -> 'set[str]':
    """Which measured rows have ranges that overlap another row's.

    Two engines whose observed ranges overlap were not separated by this run, and
    saying which is faster on the strength of their medians would be reading
    precision into noise. Compared pairwise across the whole table rather than
    only between neighbours, since a row with a wide range can straddle several
    tighter ones.

    Args:
        rows: The table's rows.

    Returns:
        Engine names to mark. A row measured only once has no range and cannot be
        separated from anything, so it is marked too.

    """
    measured = [row for row in rows if row.measured]
    marked = set()  # type: set[str]
    for row in measured:
        if len(row.ratios) < 2:
            marked.add(row.engine)
    for index, left in enumerate(measured):
        for right in measured[index + 1:]:
            if left.low <= right.high and right.low <= left.high:
                marked.add(left.engine)
                marked.add(right.engine)
    return marked


def baseline_absolutes(documents: 'Sequence[dict[str, Any]]') -> 'list[float]':
    """Every ``default`` milliseconds-per-packet figure across the documents.

    This is the one absolute number the report keeps, and it is what lets a reader
    turn the ratios back into times on the machine the run happened on.

    Args:
        documents: One :mod:`benchmark` document per environment.

    Returns:
        The figures, in the order encountered.

    """
    values = []  # type: list[float]
    for document in documents:
        for entry in document['results']:
            if entry['engine'] == BASELINE and entry['status'] == 'measured':
                values.extend(sample['ms_per_packet'] for sample in entry['repeats'])
    return values


def _simple_table(headers: 'Sequence[str]', body: 'Sequence[Sequence[str]]',
                  numeric: 'bool' = False) -> 'list[str]':
    """Render a reStructuredText simple table.

    Column widths come from the widest cell, and the rule lines are built to
    match. Built here rather than with a library so the harness stays
    dependency-light, and because a simple table is three lines of layout.

    Args:
        headers: Column headings.
        body: Rows of cells, all the same length as *headers*.
        numeric: Right-align every column but the first, for a table of figures.
            Decimal points then line up down each column, which is the difference
            between a table that can be scanned and one that has to be read. The
            first column stays left-aligned whatever this says, and not only for
            looks: in a simple table an indented cell in the first column is how
            docutils spells "this line continues the row above", so right-aligning
            it would silently merge rows.

    Returns:
        The table's lines, without a trailing blank.

    """
    widths = [len(header) for header in headers]
    for row in body:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    if numeric and len(widths) > 1:
        # One width for every figure column, not a width per column. Columns sized
        # individually come out ragged -- the ``pyshark`` row makes one column two
        # characters wider than its neighbours -- and a table of like quantities that
        # is ragged reads as though the columns held different kinds of thing.
        uniform = max(widths[1:])
        widths = [widths[0]] + [uniform] * (len(widths) - 1)

    def line(cells: 'Sequence[str]', align_numeric: 'bool') -> 'str':
        padded = [cell.rjust(widths[index]) if align_numeric and index else
                  cell.ljust(widths[index]) for index, cell in enumerate(cells)]
        # rstrip: trailing padding on the last column is legal but noisy in a diff.
        return ' '.join(padded).rstrip()

    rule = ' '.join('=' * width for width in widths)
    # The header stays left-aligned even in a numeric table, matching the hand-written
    # table this one replaces: a right-aligned ``3.10`` sits over the tail of its
    # column and reads as though it belonged to the column before it.
    lines = [rule, line(headers, False), rule]
    lines.extend(line(row, numeric) for row in body)
    lines.append(rule)
    return lines


def _image_pairs(documents: 'Sequence[dict[str, Any]]',
                 image: 'Optional[str]') -> 'list[tuple[str, str]]':
    """The image each interpreter's figures came out of, as label/value pairs.

    One row when every document shares an image, which is what a single-version run
    produces; one row per version otherwise. A matrix has no single image to name, and
    the reference is the only thing that ties a column of the per-version table to a
    specific build of a specific interpreter -- so it is reported per version rather
    than collapsed into "several".

    Args:
        documents: One :mod:`benchmark` document per environment.
        image: Fallback reference, for documents that carry none of their own.

    Returns:
        Ordered label/value pairs, empty when no reference is known at all.

    """
    seen = []  # type: list[tuple[str, str]]
    for document in _ordered(documents):
        reference = document.get('image') or image
        if not reference:
            continue
        pair = (python_series(document), reference)
        if pair not in seen:
            seen.append(pair)
    if not seen:
        return []
    if len({reference for _, reference in seen}) == 1:
        return [('Image', f'``{seen[0][1]}``')]
    return [(f'Image ({series})', f'``{reference}``') for series, reference in seen]


def _provenance(documents: 'Sequence[dict[str, Any]]', image: 'Optional[str]',
                emulated: 'Optional[str]') -> 'list[tuple[str, str]]':
    """The facts that make a run reproducible, as label/value pairs.

    Deliberately excludes anything identifying the host it ran on -- no hostname,
    no kernel, no CPU model. Containerising the benchmark is what makes the host
    irrelevant, and printing host details would undo that while also making the
    output awkward to paste into a public README. The architecture *is* included,
    because it changes the numbers and identifies nothing.

    Args:
        documents: One :mod:`benchmark` document per environment.
        image: Image reference or digest the run happened in, for documents that do
            not carry their own.
        emulated: Description of the emulation in play, or :data:`None` when the
            run was native.

    Returns:
        Ordered label/value pairs. Versions the run could not measure are *not* here;
        see :func:`_missing_pairs` for why they are assembled by the caller.

    """
    ordered = _ordered(documents)
    first = ordered[0]
    capture = first['capture']
    pairs = _image_pairs(documents, image)
    if first.get('pcapkit_revision'):
        pairs.append(('``pcapkit`` revision', f"``{first['pcapkit_revision']}``"))
    # Every interpreter measured, at patch-level precision. The matrix's whole subject
    # is the difference between these, so naming only the first would describe one
    # column and imply it stood for all of them.
    implementations = '/'.join(sorted({document['implementation'] for document in ordered}))
    versions = sorted({document['python'] for document in ordered}, key=_series_key)
    pairs.append(('Python', f"{implementations} {', '.join(versions)}"))
    pairs.append(('Architecture', f"``{first['machine']}``"))
    if emulated:
        pairs.append(('Emulation', emulated))
    pairs.append(('Capture', f"``{capture['name']}`` -- {capture['bytes']} bytes, "
                             f"SHA-256 ``{capture['sha256'][:16]}...``"))
    # Every engine on every interpreter should see the same number of frames in the same
    # capture, so this row is normally one number. A disagreement is reported rather than
    # dropped: with one interpreter it was barely possible and omitting it cost nothing,
    # but two CPython versions extracting different counts from one file would be the
    # most interesting thing in the report, and the previous behaviour was to hide
    # exactly that by printing no row at all.
    packets = {entry['packets'] for document in ordered for entry in document['results']
               if entry['packets']}
    if len(packets) == 1:
        pairs.append(('Packets per extraction', str(packets.pop())))
    elif packets:
        by_series = {}  # type: dict[str, set[int]]
        for document in ordered:
            for entry in document['results']:
                if entry['packets']:
                    by_series.setdefault(python_series(document), set()).add(entry['packets'])
        detail = ', '.join(
            f"{series} {'/'.join(str(count) for count in sorted(by_series[series]))}"
            for series in sorted(by_series, key=_series_key))
        pairs.append(('Packets per extraction',
                      f'**disagreed across the run** -- {detail}. One capture should yield '
                      f'one frame count everywhere; treat every figure below as suspect '
                      f'until this is explained.'))
    pairs.append(('Iterations', f"{first['rounds']} timed extractions per engine per pass, "
                                f"the first discarded as a warm-up"))
    # "pass" throughout rather than "repeat", so this row and the table's "Samples"
    # column are counting the same unit. They are not the same *number*, and cannot be:
    # a pass happens once per environment, so the table's count is this figure times the
    # number of environments -- 3 passes over 7 environments is 21 samples per engine.
    # The column was called "Passes" while there were two environments and one
    # interpreter, where the difference was easy to overlook; across a matrix it reads as
    # a contradiction, hence the rename.
    environments = ', '.join(f"``{document['environment']}``" for document in ordered)
    noun = 'environment' if len(ordered) == 1 else 'environments'
    pairs.append(('Passes', f"{first['repeats']} over the whole engine set, "
                            f"in {len(ordered)} {noun}: {environments}"))
    tsharks = sorted({document['tshark'] for document in ordered if document.get('tshark')})
    if tsharks:
        pairs.append(('tshark', ', '.join(f'``{value}``' for value in tsharks)))
    libpcaps = sorted({document['libpcap'] for document in ordered if document.get('libpcap')})
    if libpcaps:
        pairs.append(('libpcap', ', '.join(f'``{value}``' for value in libpcaps)))
    return pairs


def _missing_pairs(documents: 'Sequence[dict[str, Any]]',
                   missing: 'Sequence[tuple[str, str]]') -> 'list[tuple[str, str]]':
    """The versions the run could not measure, as label/value pairs.

    A version that was asked for and could not be measured belongs in the record of
    what the run covered. Without it the provenance block reads as the complete matrix,
    and a reader comparing two runs would see one silently narrower than the other.

    Kept out of :func:`_provenance` for one specific reason: the reason string is the
    only value in that block this module did not write itself, so it has to be escaped
    before it enters markup and must *not* be escaped in the plain-text report. A value
    whose correct form depends on where it is going cannot come out of the function both
    destinations share.

    Args:
        documents: One :mod:`benchmark` document per environment.
        missing: ``(version, reason)`` pairs for versions whose build or run failed.

    Returns:
        Ordered label/value pairs, the reason unescaped.

    """
    measured_series = {python_series(document) for document in documents}
    pairs = []  # type: list[tuple[str, str]]
    for version, reason in sorted(missing, key=lambda pair: _series_key(pair[0])):
        # A version that produced some documents before failing is labelled
        # differently, since "not measured" would contradict the figures it did
        # contribute -- and those figures are printed a few lines further down.
        state = 'partly measured' if version in measured_series else 'not measured'
        pairs.append((f'Python {version} ({state})', reason))
    return pairs


def _package_table(documents: 'Sequence[dict[str, Any]]') -> 'list[str]':
    """A simple table of every engine package's resolved version, per environment.

    Args:
        documents: One :mod:`benchmark` document per environment.

    Returns:
        The table's lines.

    """
    ordered = _ordered(documents)
    environments = [document['environment'] for document in ordered]
    names = []  # type: list[str]
    for document in ordered:
        for name in document['packages']:
            if name not in names:
                names.append(name)

    body = []  # type: list[list[str]]
    for name in names:
        cells = [f'``{name}``']
        for document in ordered:
            version = document['packages'].get(name)
            # An absent package is a fact about the environment, not a blank: it is
            # why ``pypcap`` and ``pcap_ct`` need two environments in the first place.
            cells.append(version if version else '*absent*')
        if all(cell == '*absent*' for cell in cells[1:]):
            continue
        body.append(cells)
    return _simple_table(['Package', *environments], body)


def render_versions_rst(rows: 'Sequence[Row]', documents: 'Sequence[dict[str, Any]]',
                        missing: 'Sequence[tuple[str, str]]' = (),
                        emulated: 'Optional[str]' = None) -> 'str':
    """Render the per-version table of absolute milliseconds per packet.

    This is the snippet that replaces :file:`README.rst`'s **Test Results** section
    outright: engines down the side, Python versions across the top, ``--`` for a cell
    that could not be measured. It is self-contained -- heading, prose, table, notes --
    because it is pasted as a unit, and a note explaining a gap is no use in a
    different file from the gap.

    Milliseconds, not ratios, and the prose says so. Two interpreters measured in one
    run on one host differ in the interpreter and nothing else, which is the only
    condition under which absolute times mean anything; a ratio would be worse than
    redundant here, since ratios are normalised inside one environment and dividing
    across two would produce a number describing neither.

    Args:
        rows: The table's rows, from :func:`collect`. Used for its ordering, so that
            this table and the ratio table list the engines in the same order and a
            reader can carry their eye from one to the other.
        documents: One :mod:`benchmark` document per environment.
        missing: ``(version, reason)`` pairs for versions whose build or run failed.
            A version that produced nothing at all becomes a column of ``--``; one
            that failed after writing some of its environments keeps the figures it
            managed and is labelled as incomplete rather than as unmeasured.
        emulated: Description of the emulation in play, or :data:`None`.

    Returns:
        reStructuredText, ready to paste.

    """
    first = _ordered(documents)[0]
    columns = version_columns(documents, missing)
    grid = absolutes_by_version(documents)
    reasons = unmeasured_by_version(documents)

    # A version can be both measured and reported as failed: `run.sh` collects whatever
    # documents a container wrote before it died, so a 3.11 whose second virtualenv
    # crashed arrives with real figures *and* a note. The two cases need telling apart,
    # because "not measured at all" is false of the second one -- and its column, having
    # data, does have gaps worth attributing to the engines that left them.
    measured_series = {python_series(document) for document in documents}
    absent = {version: reason for version, reason in missing
              if version not in measured_series}
    partial = {version: reason for version, reason in missing
               if version in measured_series}

    lines = []  # type: list[str]
    lines.append('Test Results')
    lines.append('~~~~~~~~~~~~')
    lines.append('')
    lines.append(f"Measured with ``examples/benchmark/run.sh``: {first['rounds']} timed")
    lines.append('extractions of ``examples/captures/in.pcap`` per engine and Python version.')
    lines.append('The first extraction is discarded as a warm-up. Values are milliseconds per')
    lines.append(f"packet, the median of {first['repeats']} passes.")
    lines.append('')
    lines.append('All columns come from one run on one machine, differing in the interpreter')
    lines.append('and nothing else, so they may be compared with each other. They may not be')
    lines.append('compared with figures from another machine: absolute times are a property of')
    lines.append('the host as much as of the engine.')
    lines.append('')

    body = []  # type: list[list[str]]
    for row in rows:
        by_series = grid.get(row.engine, {})
        gaps = [series for series in columns
                if series not in by_series and series not in absent]
        # Marked for a gap in a column that produced something only. A blank under a
        # version whose image never built is explained by the column's own note, and
        # tagging the engine for it would blame the engine for someone else's failure.
        name = f'``{row.label}``' + (f' {UNMEASURED_MARK}' if gaps else '')
        cells = [name]
        for series in columns:
            values = by_series.get(series)
            cells.append(_fixed(statistics.median(values)) if values else '--')
        body.append(cells)

    # Marked when there is a note about the column itself, whether that is "nothing was
    # measured here" or "not everything was". A note nothing in the table points at is a
    # note a reader has no reason to look for.
    headers = ['Engine']
    for series in columns:
        noted = series in absent or series in partial
        headers.append(f'{series} {UNMEASURED_MARK}' if noted else series)
    lines.extend(_simple_table(headers, body, numeric=True))
    lines.append('')

    # The owner's own sentence about the old hand-maintained table, kept word for word:
    # it is the right warning, and a regenerated table that rewords it would show up as
    # a diff in the prose every time the numbers changed.
    lines.append('The unavailable cells were attempted. They are not zeroes and must not be')
    lines.append('compared with a measured row.')
    lines.append('')

    notes = []  # type: list[str]
    for version, reason in sorted(absent.items(), key=lambda pair: _series_key(pair[0])):
        notes.append(f'* Python {version} -- not measured at all: {_escape(reason)}')
    for version, reason in sorted(partial.items(), key=lambda pair: _series_key(pair[0])):
        notes.append(f'* Python {version} -- measured, but the run did not complete, so this '
                     f'column may be missing engines that would otherwise have a figure: '
                     f'{_escape(reason)}')
    for row in rows:
        by_reason = {}  # type: dict[str, list[str]]
        for series, reason in sorted(reasons.get(row.engine, {}).items(), key=lambda pair:
                                     _series_key(pair[0])):
            if series in absent:
                continue
            by_reason.setdefault(reason, []).append(series)
        # Grouped by reason rather than one bullet per cell: the usual case is one
        # sentence true of three consecutive versions, and repeating it three times
        # makes the notes longer than the table they annotate.
        for reason, series_list in by_reason.items():
            notes.append(f'* ``{row.label}`` on {", ".join(series_list)} -- {_escape(reason)}')

    if notes:
        lines.append(f'``{UNMEASURED_MARK}`` not measured, or not measured in full, for the')
        lines.append('reason recorded at the time:')
        lines.append('')
        lines.extend(notes)
        lines.append('')

    if emulated:
        lines.append(f'**{emulated}** Timings taken under emulation are not comparable with')
        lines.append('native ones, and an absolute figure taken that way describes the emulator')
        lines.append('as much as the interpreter. Re-run natively before publishing.')
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'


def render_rst(rows: 'Sequence[Row]', documents: 'Sequence[dict[str, Any]]',
               image: 'Optional[str]' = None,
               emulated: 'Optional[str]' = None,
               missing: 'Sequence[tuple[str, str]]' = ()) -> 'str':
    """Render the whole snippet: provenance, table, and notes.

    Args:
        rows: The table's rows, from :func:`collect`.
        documents: One :mod:`benchmark` document per environment.
        image: Image reference or digest the run happened in.
        emulated: Description of the emulation in play, or :data:`None`.
        missing: ``(version, reason)`` pairs for Python versions that produced no
            measurements, recorded in the provenance block so this snippet does not
            read as the complete matrix when it is not.

    Returns:
        reStructuredText, ready to paste.

    """
    marked = overlapping(rows)
    lines = []  # type: list[str]

    lines.append('Test Environment')
    lines.append('~~~~~~~~~~~~~~~~')
    lines.append('')
    lines.append('.. list-table::')
    lines.append('')
    for label, value in _provenance(documents, image, emulated):
        lines.append(f'   * - {label}')
        lines.append(f'     - {value}')
    for label, value in _missing_pairs(documents, missing):
        lines.append(f'   * - {label}')
        lines.append(f'     - {_escape(value)}')
    lines.append('')
    lines.append('Resolved package versions:')
    lines.append('')
    lines.extend(_package_table(documents))
    lines.append('')

    # A heading of its own rather than "Test Results", which is the per-version
    # absolute table's -- both snippets go into the same README, and two sections
    # with one name is a document where a reader cannot say which table a sentence is
    # about.
    heading = 'Test Results (Relative)'
    lines.append(heading)
    lines.append('~' * len(heading))
    lines.append('')
    lines.append(f'Times relative to ``{BASELINE_LABEL}``, which is 1 by definition; lower is')
    lines.append('faster. Each ratio is taken against the baseline measured in the same')
    lines.append('environment on the same pass, so the machine cancels out. "Observed range" is')
    lines.append('the smallest and largest ratio actually seen across the passes.')
    lines.append('')
    if len({python_series(document) for document in documents}) > 1:
        # Said explicitly, because it is the one thing about this table that a reader
        # would otherwise get wrong: it is not "the ratio on some interpreter", it is
        # every interpreter's ratio pooled. Each one was normalised in its own
        # environment before pooling, so the pooling is sound -- and the extra width it
        # puts into the observed range is a real disagreement between interpreters
        # rather than noise to be averaged away.
        lines.append('Ratios are pooled across every environment in the run, which means across')
        lines.append('every Python version measured as well as both ``pcap`` providers. The')
        lines.append('observed range therefore includes any disagreement between interpreters')
        lines.append('about an engine; the per-version table is where that is broken out.')
        lines.append('')

    body = []  # type: list[list[str]]
    for row in rows:
        name = f'``{row.label}``'
        if row.measured:
            if row.engine == BASELINE:
                relative, observed = '1', '*baseline*'
            else:
                relative = _significant(row.median)
                observed = (_range(row.low, row.high)
                            if len(row.ratios) > 1 else '*single pass*')
            if row.engine in marked:
                name += f' {OVERLAP_MARK}'
            if row.partial:
                name += f' {PARTIAL_MARK}'
            body.append([name, relative, observed, str(len(row.ratios))])
        else:
            body.append([f'{name} {UNMEASURED_MARK}', '*not measured*', '--', '0'])

    lines.extend(_simple_table(['Engine', 'Relative time', 'Observed range', 'Samples'], body))
    lines.append('')

    absolutes = baseline_absolutes(documents)
    if absolutes:
        median = statistics.median(absolutes)
        lines.append(f'The single absolute figure, for converting the ratios back: ``{BASELINE_LABEL}``')
        lines.append(f'itself ran at **{_significant(median, 4)} ms per packet** on this run')
        if len(absolutes) > 1:
            lines.append(f'({_range(min(absolutes), max(absolutes))} '
                         f'across {len(absolutes)} passes). Absolute times are a property of the')
        else:
            lines.append('(one pass only). Absolute times are a property of the')
        lines.append('machine as much as of the engine, which is why every other figure here is a')
        lines.append('ratio.')
        lines.append('')

    # The spread is reported whether or not any row is marked -- it is what tells a
    # reader which gaps in the table are large enough to mean anything. The marker's
    # legend, by contrast, is only emitted when a row actually carries it: an
    # explanation of a symbol that does not appear reads as though the run failed to
    # separate rows it in fact separated cleanly.
    spreads = [row.spread for row in rows if row.measured and len(row.ratios) > 1]
    if spreads:
        lines.append(f'Run-to-run spread: the median row varied by '
                     f'{_significant(statistics.median(spreads) * 100, 2)}% of its ratio across')
        lines.append(f'the passes and the widest by {_significant(max(spreads) * 100, 2)}%. '
                     f'A gap between two rows that is')
        lines.append('smaller than that is noise, not a result.')
        lines.append('')

    if marked:
        if spreads:
            lines.append(f'``{OVERLAP_MARK}`` this run does not separate these rows: their observed')
            lines.append('ranges overlap, so the order their medians suggest is not established.')
        else:
            lines.append(f'``{OVERLAP_MARK}`` measured on a single pass, so no run-to-run spread was')
            lines.append('observed and no gap between rows is established. Re-run with more passes.')
        lines.append('')

    partial = [row for row in rows if row.measured and row.partial]
    if partial:
        lines.append(f'``{PARTIAL_MARK}`` measured, but on less evidence than the rows beside it.')
        lines.append('What was collected is real; what was lost is named here rather than left to')
        lines.append('be inferred from the pass count:')
        lines.append('')
        for row in partial:
            detail = []  # type: list[str]
            if row.discarded:
                detail.append(f'{row.discarded} individual extraction(s) failed and were discarded')
            detail.extend(_escape(failure) for failure in row.failures)
            lines.append(f'* ``{row.label}`` -- ' + '; '.join(detail))
        lines.append('')

    unmeasured = [row for row in rows if not row.measured]
    if unmeasured:
        lines.append(f'``{UNMEASURED_MARK}`` not measured, for the reason the engine itself gives:')
        lines.append('')
        for row in unmeasured:
            lines.append(f'* ``{row.label}`` -- {_escape(row.reason)}')
        lines.append('')

    if emulated:
        lines.append(f'**{emulated}** Timings taken under emulation are not comparable with native')
        lines.append('ones, and the ratios are only as trustworthy as the emulator is uniform')
        lines.append('across the work each engine does. Re-run natively before publishing.')
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'


def render_text(rows: 'Sequence[Row]', documents: 'Sequence[dict[str, Any]]',
                image: 'Optional[str]' = None,
                emulated: 'Optional[str]' = None,
                missing: 'Sequence[tuple[str, str]]' = ()) -> 'str':
    """Render the operator-facing summary that precedes the RST snippets.

    Carries more than the tables do: the absolute milliseconds behind each ratio,
    and the per-environment medians for engines measured in more than one, which
    is the cross-check that the stitching worked. If two environments disagree
    about ``dpkt``, the join on ``default`` is not doing its job and no amount of
    tidy formatting downstream would reveal it.

    Args:
        rows: The table's rows, from :func:`collect`.
        documents: One :mod:`benchmark` document per environment.
        image: Image reference or digest the run happened in.
        emulated: Description of the emulation in play, or :data:`None`.
        missing: ``(version, reason)`` pairs for Python versions that produced no
            measurements.

    Returns:
        Plain text.

    """
    marked = overlapping(rows)
    lines = []  # type: list[str]
    lines.append('=' * 78)
    lines.append('pcapkit engine benchmark')
    lines.append('=' * 78)
    for label, value in _provenance(documents, image, emulated):
        lines.append(f'{label + ":":26} {value.replace("``", "")}')
    for label, value in _missing_pairs(documents, missing):
        lines.append(f'{label + ":":26} {value}')
    lines.append('')

    # Absolute milliseconds per interpreter, which the ratio table below cannot show
    # and is the whole reason the run covers several Python versions. Printed here as
    # well as emitted as markup so that the operator watching the run sees the answer
    # without opening a file.
    columns = version_columns(documents, missing)
    if len(columns) > 1:
        grid = absolutes_by_version(documents)
        lines.append('ms per packet by Python version (absolute; comparable across columns,')
        lines.append('since one host measured them all, and with no other machine):')
        lines.append(f'{"engine":14} ' + ' '.join(f'{series:>9}' for series in columns))
        lines.append('-' * 78)
        for row in rows:
            by_series = grid.get(row.engine, {})
            cells = []  # type: list[str]
            for series in columns:
                values = by_series.get(series)
                cells.append(f'{_fixed(statistics.median(values)):>9}' if values
                             else f'{"--":>9}')
            lines.append(f'{row.label:14} ' + ' '.join(cells))
        lines.append('')
        # No per-version failure lines here. The provenance block above already names
        # every version the run could not measure and why, in the same output a few
        # lines up, and a second rendering of the same fact managed to disagree with the
        # first: it called a partly measured version "not measured" while its figures
        # were printed in the grid directly above.

    lines.append(f'{"engine":14} {"relative":>10} {"range":>19} {"ms/packet":>12}  samples')
    lines.append('-' * 78)
    for row in rows:
        if not row.measured:
            lines.append(f'{row.label:14} {"not measured":>10}  {row.reason}')
            continue
        span = _range(row.low, row.high) if len(row.ratios) > 1 else 'single pass'
        absolute = _significant(statistics.median(row.absolutes), 4)
        flag = f' {OVERLAP_MARK}' if row.engine in marked else ''
        if row.partial:
            flag += f' {PARTIAL_MARK}'
        lines.append(f'{row.label:14} {_significant(row.median):>10} {span:>19} '
                     f'{absolute:>12}  {len(row.ratios)}{flag}')
    lines.append('')

    for row in rows:
        if row.measured and row.partial:
            detail = []  # type: list[str]
            if row.discarded:
                detail.append(f'{row.discarded} extraction(s) discarded')
            detail.extend(row.failures)
            lines.append(f'{PARTIAL_MARK} {row.label}: ' + '; '.join(detail))

    shared = [row for row in rows if row.measured and len(row.environments) > 1]
    if shared:
        lines.append('cross-environment check (engines measured in more than one environment;')
        lines.append('the two should agree, since each ratio is normalised in its own):')
        for row in shared:
            per_env = []  # type: list[str]
            for env in row.environments:
                values = _ratios_for(documents, row.engine, env)
                if values:
                    per_env.append(f'{env}={_significant(statistics.median(values))}')
            lines.append(f'  {row.label:14} ' + '  '.join(per_env))
        lines.append('')

    if marked:
        lines.append(f'{OVERLAP_MARK} ranges overlap another row: this run does not establish the order.')
        lines.append('')
    if emulated:
        lines.append(f'WARNING: {emulated}')
        lines.append('Numbers taken under emulation are not comparable with native ones.')
        lines.append('')
    return '\n'.join(lines)


def _ratios_for(documents: 'Sequence[dict[str, Any]]', engine: 'str',
                environment: 'str') -> 'list[float]':
    """Ratios contributed by one engine in one environment.

    Args:
        documents: One :mod:`benchmark` document per environment.
        engine: Engine name.
        environment: Environment label.

    Returns:
        The ratios, or an empty list when that pairing produced none.

    """
    for document in documents:
        if document['environment'] != environment:
            continue
        results = {entry['engine']: entry for entry in document['results']}
        base = results.get(BASELINE)
        entry = results.get(engine)
        if base is None or entry is None or base['status'] != 'measured':
            return []
        by_repeat = {sample['repeat']: sample['ms_per_packet'] for sample in base['repeats']}
        return [sample['ms_per_packet'] / by_repeat[sample['repeat']]
                for sample in entry['repeats']
                if _usable_baseline(by_repeat.get(sample['repeat']))]
    return []


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Command line entry point.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv`.

    Returns:
        Process exit status.

    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('json', nargs='+', help='benchmark JSON documents, one per environment')
    parser.add_argument('--image', default=None,
                        help='image reference or digest the run happened in')
    parser.add_argument('--emulated', default=None,
                        help='describe the emulation in play; omit for a native run')
    parser.add_argument('--missing', action='append', default=[], metavar='VERSION=REASON',
                        help=('a Python version that produced no measurements, and why; '
                              'repeatable. It becomes a column of "--" with the reason '
                              'attached, rather than an absent column'))
    parser.add_argument('--rst-out', default=None,
                        help='also write just the ratio RST snippet here')
    parser.add_argument('--versions-rst-out', default=None,
                        help='also write just the per-version absolute RST snippet here')
    args = parser.parse_args(argv)

    missing = []  # type: list[tuple[str, str]]
    for entry in args.missing:
        version, separator, reason = entry.partition('=')
        # Rejected rather than guessed at: a bare version with no reason would render a
        # column of gaps whose note said nothing, which is the outcome --missing exists
        # to prevent.
        if not separator or not version.strip() or not reason.strip():
            parser.error(f'--missing wants VERSION=REASON, not {entry!r}')
        # Two reasons for one version have no coherent rendering -- the provenance block
        # would list both and the table's notes only the last -- and there is no honest
        # way to pick. `run.sh` writes one note file per version so it cannot happen from
        # there; anyone driving report.py by hand is told rather than shown half of it.
        if version.strip() in {existing for existing, _ in missing}:
            parser.error(f'--missing was given twice for Python {version.strip()}')
        missing.append((version.strip(), reason.strip()))

    documents = []  # type: list[dict[str, Any]]
    for path in args.json:
        with open(path, encoding='utf-8') as file:
            documents.append(json.load(file))

    rows = collect(documents)
    print(render_text(rows, documents, args.image, args.emulated, missing))
    versions_snippet = render_versions_rst(rows, documents, missing, args.emulated)
    snippet = render_rst(rows, documents, args.image, args.emulated, missing)

    print('-' * 78)
    print('reStructuredText below, ready to paste into README.rst')
    print('-' * 78)
    print()
    print(versions_snippet)
    print(snippet)

    if args.versions_rst_out:
        with open(args.versions_rst_out, 'w', encoding='utf-8') as file:
            file.write(versions_snippet)
    if args.rst_out:
        with open(args.rst_out, 'w', encoding='utf-8') as file:
            file.write(snippet)
    return 0


if __name__ == '__main__':
    sys.exit(main())
