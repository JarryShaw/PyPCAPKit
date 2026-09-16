# -*- coding: utf-8 -*-
"""Turn benchmark JSON documents into a paste-ready reStructuredText table.

The first line above is deliberately free of Sphinx roles: :func:`main` hands it to
:mod:`argparse` as the command's description, where ``:mod:`benchmark``` would be
shown to the user verbatim.

:mod:`benchmark` measures one Python environment. This module stitches several
together and reports them as ratios, which is the only form in which the numbers
mean anything to a reader on different hardware.

**Why ratios rather than milliseconds.** An absolute figure describes the machine
it was taken on at least as much as it describes the engine, so a table of them
cannot be reproduced and cannot be compared with anything. A ratio against the
``default`` engine *measured in the same environment on the same repeat* divides
the machine out. It is also what makes the two environments joinable at all: they
have to be separate, because ``pypcap`` and ``pcap_ct`` both provide the
top-level :mod:`pcap` module and cannot coexist, and ``default`` is the engine
present in both. One absolute number survives, as a footnote: the baseline's own
milliseconds per packet, which is what a reader needs to convert the ratios back.

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

__all__ = ['Row', 'baseline_absolutes', 'collect', 'overlapping', 'render_rst', 'render_text']

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


def _simple_table(headers: 'Sequence[str]', body: 'Sequence[Sequence[str]]') -> 'list[str]':
    """Render a reStructuredText simple table.

    Column widths come from the widest cell, and the rule lines are built to
    match. Built here rather than with a library so the harness stays
    dependency-light, and because a simple table is three lines of layout.

    Args:
        headers: Column headings.
        body: Rows of cells, all the same length as *headers*.

    Returns:
        The table's lines, without a trailing blank.

    """
    widths = [len(header) for header in headers]
    for row in body:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def line(cells: 'Sequence[str]') -> 'str':
        # rstrip: trailing padding on the last column is legal but noisy in a diff.
        return ' '.join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    rule = ' '.join('=' * width for width in widths)
    lines = [rule, line(headers), rule]
    lines.extend(line(row) for row in body)
    lines.append(rule)
    return lines


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
        image: Image reference or digest the run happened in.
        emulated: Description of the emulation in play, or :data:`None` when the
            run was native.

    Returns:
        Ordered label/value pairs.

    """
    first = documents[0]
    capture = first['capture']
    pairs = []  # type: list[tuple[str, str]]
    if image:
        pairs.append(('Image', f'``{image}``'))
    if first.get('pcapkit_revision'):
        pairs.append(('``pcapkit`` revision', f"``{first['pcapkit_revision']}``"))
    pairs.append(('Python', f"{first['implementation']} {first['python']}"))
    pairs.append(('Architecture', f"``{first['machine']}``"))
    if emulated:
        pairs.append(('Emulation', emulated))
    pairs.append(('Capture', f"``{capture['name']}`` -- {capture['bytes']} bytes, "
                             f"SHA-256 ``{capture['sha256'][:16]}...``"))
    packets = {entry['packets'] for document in documents for entry in document['results']
               if entry['packets']}
    if len(packets) == 1:
        pairs.append(('Packets per extraction', str(packets.pop())))
    pairs.append(('Iterations', f"{first['rounds']} timed extractions per engine per pass, "
                                f"the first discarded as a warm-up"))
    # "pass" throughout rather than "repeat", so the prose and the table's "Passes"
    # column are talking about the same thing.
    environments = ', '.join(f"``{document['environment']}``" for document in documents)
    noun = 'environment' if len(documents) == 1 else 'environments'
    pairs.append(('Passes', f"{first['repeats']} over the whole engine set, "
                            f"in {len(documents)} {noun}: {environments}"))
    if first.get('tshark'):
        pairs.append(('tshark', f"``{first['tshark']}``"))
    libpcaps = sorted({document['libpcap'] for document in documents if document.get('libpcap')})
    if libpcaps:
        pairs.append(('libpcap', ', '.join(f'``{value}``' for value in libpcaps)))
    return pairs


def _package_table(documents: 'Sequence[dict[str, Any]]') -> 'list[str]':
    """A simple table of every engine package's resolved version, per environment.

    Args:
        documents: One :mod:`benchmark` document per environment.

    Returns:
        The table's lines.

    """
    environments = [document['environment'] for document in documents]
    names = []  # type: list[str]
    for document in documents:
        for name in document['packages']:
            if name not in names:
                names.append(name)

    body = []  # type: list[list[str]]
    for name in names:
        cells = [f'``{name}``']
        for document in documents:
            version = document['packages'].get(name)
            # An absent package is a fact about the environment, not a blank: it is
            # why ``pypcap`` and ``pcap_ct`` need two environments in the first place.
            cells.append(version if version else '*absent*')
        if all(cell == '*absent*' for cell in cells[1:]):
            continue
        body.append(cells)
    return _simple_table(['Package', *environments], body)


def render_rst(rows: 'Sequence[Row]', documents: 'Sequence[dict[str, Any]]',
               image: 'Optional[str]' = None,
               emulated: 'Optional[str]' = None) -> 'str':
    """Render the whole snippet: provenance, table, and notes.

    Args:
        rows: The table's rows, from :func:`collect`.
        documents: One :mod:`benchmark` document per environment.
        image: Image reference or digest the run happened in.
        emulated: Description of the emulation in play, or :data:`None`.

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
    lines.append('')
    lines.append('Resolved package versions:')
    lines.append('')
    lines.extend(_package_table(documents))
    lines.append('')

    lines.append('Test Results')
    lines.append('~~~~~~~~~~~~')
    lines.append('')
    lines.append(f'Times relative to ``{BASELINE_LABEL}``, which is 1 by definition; lower is')
    lines.append('faster. Each ratio is taken against the baseline measured in the same')
    lines.append('environment on the same pass, so the machine cancels out. "Observed range" is')
    lines.append('the smallest and largest ratio actually seen across the passes.')
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

    lines.extend(_simple_table(['Engine', 'Relative time', 'Observed range', 'Passes'], body))
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
            detail.extend(row.failures)
            lines.append(f'* ``{row.label}`` -- ' + '; '.join(detail))
        lines.append('')

    unmeasured = [row for row in rows if not row.measured]
    if unmeasured:
        lines.append(f'``{UNMEASURED_MARK}`` not measured, for the reason the engine itself gives:')
        lines.append('')
        for row in unmeasured:
            lines.append(f'* ``{row.label}`` -- {row.reason}')
        lines.append('')

    if emulated:
        lines.append(f'**{emulated}** Timings taken under emulation are not comparable with native')
        lines.append('ones, and the ratios are only as trustworthy as the emulator is uniform')
        lines.append('across the work each engine does. Re-run natively before publishing.')
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'


def render_text(rows: 'Sequence[Row]', documents: 'Sequence[dict[str, Any]]',
                image: 'Optional[str]' = None,
                emulated: 'Optional[str]' = None) -> 'str':
    """Render the operator-facing summary that precedes the RST snippet.

    Carries more than the table does: the absolute milliseconds behind each ratio,
    and the per-environment medians for engines measured in more than one, which
    is the cross-check that the stitching worked. If the two environments disagree
    about ``dpkt``, the join on ``default`` is not doing its job and no amount of
    tidy formatting downstream would reveal it.

    Args:
        rows: The table's rows, from :func:`collect`.
        documents: One :mod:`benchmark` document per environment.
        image: Image reference or digest the run happened in.
        emulated: Description of the emulation in play, or :data:`None`.

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
    lines.append('')

    lines.append(f'{"engine":14} {"relative":>10} {"range":>19} {"ms/packet":>12}  passes')
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
    parser.add_argument('--rst-out', default=None,
                        help='also write just the RST snippet here')
    args = parser.parse_args(argv)

    documents = []  # type: list[dict[str, Any]]
    for path in args.json:
        with open(path, encoding='utf-8') as file:
            documents.append(json.load(file))

    rows = collect(documents)
    print(render_text(rows, documents, args.image, args.emulated))
    snippet = render_rst(rows, documents, args.image, args.emulated)

    print('-' * 78)
    print('reStructuredText below, ready to paste into README.rst')
    print('-' * 78)
    print()
    print(snippet)

    if args.rst_out:
        with open(args.rst_out, 'w', encoding='utf-8') as file:
            file.write(snippet)
    return 0


if __name__ == '__main__':
    sys.exit(main())
