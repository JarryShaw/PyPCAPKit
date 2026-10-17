# -*- coding: utf-8 -*-
"""Recompute the Python version tiers in :file:`.github/python-versions.toml` (#1660).

:file:`.github/workflows/cron-python-versions.yml` runs this weekly. It reads
these sources:

``release-cycle``
    python.org's release cycle, ``https://peps.python.org/api/release-cycle.json``:
    each CPython branch's ``status``.
``pypy``
    PyPy's releases, ``https://downloads.python.org/pypy/versions.json``.
``manifest``
    setup-python's builds, ``actions/python-versions``' ``versions-manifest.json``,
    per ``platform``, ``platform_version`` and ``arch``.
``runner-images``
    ``actions/runner-images``' README, whose image table says which images GitHub
    hosts and which one ``ubuntu-latest`` is. The manifest alone cannot say either:
    it still lists builds for retired images.

The labels whose builds count are read from the workflows, not written here: the
label the Python matrix jobs default to (``matrix.os || 'ubuntu-latest'``), the
labels of an ``os`` axis, which run the supported tier, and the ``runs-on`` of
each job that installs ``latest``. A ``-latest`` label counts as its image and
every newer one in the table, since GitHub moves the label to the newest image.

The rules are the owner's, from #1633 and #1660:

``latest``
    The newest ``bugfix`` branch with a stable build on every label a job installs
    ``latest`` on.
supported
    ``bugfix`` and ``security``.
KTLO
    ``end-of-life`` and still installable. A version with a stable build on every
    image ``ubuntu-latest`` may mean has no ``runner``; otherwise it names the
    newest hosted Ubuntu image that has one.
dropped
    ``end-of-life`` with no build for any hosted Ubuntu image.
pre-release
    ``feature`` or ``prerelease`` once setup-python has a build. No workflow runs
    pre-release legs yet, and :func:`python_versions.load` refuses the tier, so
    such a version is reported (:data:`HELD`) rather than written.
experimental
    Free-threaded CPython and GraalPy, which no source here rates (#1660), are
    hand-maintained: every recompute keeps their entries as the file has them,
    after the computed versions of their table, and :func:`fingerprint` leaves
    them out, so a hand edit to one neither changes nor re-proposes the tiers.

PyPy has no release cycle of its own: the Python versions of its newest stable
release are supported, an older one the file lists stays KTLO while a stable
build of it remains, and one found only in a numbered pre-release is a
pre-release. A version enters the file as supported or pre-release; an
end-of-life version the file does not list is never added.

Each implementation is one entry of :data:`IMPLEMENTATIONS`, with the sources it
reads, so computing another is one more source and one more entry, besides its
spelling in :file:`util/python_versions.py`.

The tier file is rewritten line by line: a version whose entry is unchanged keeps
its line byte for byte, so comments, the exemptions and the layout survive, and a
run that changes nothing writes nothing. The prose the audit tests pin to the file
is regenerated with it (:data:`CLAIMS`, :data:`REWRITERS`), but nothing under
:file:`.github/workflows/`: an App installation token needs the ``workflows``
permission to push a change there, and the job's token has contents and pull
requests only. Workflow comments name the tiers instead of restating them. Nor
does it retire a job whose matrix the new tiers leave empty: the proposal names
the job as a manual step, for the owner to retire or remove first (#1747).

Its commands:

``update``
    Recompute, print what changed, and with ``--write`` rewrite the files.
    ``--out`` writes the proposal (the changed files, the plan, the commit
    message) for the ``pr`` job. ``--proposal-branch`` reads every commit that
    branch holds ahead of ``main``, merges of ``main`` left out, while its pull
    request is open: when one carries this proposal, hand edits on top or not,
    it is not proposed again, and when the branch holds commits this job did
    not make and proposes other tiers, ``update`` refuses as ``publish`` would,
    rather than have an approval asked for a refusal. A branch with no open
    pull request was merged or closed, and is proposed afresh.
``body``
    Render the pull request body from a proposal, with the audit's result.
``publish``
    In the ``pr`` job: commit the proposal on :data:`BRANCH`, force-push that
    branch only, or recreate it from ``main`` when it has no open pull request,
    and open its pull request or update the open one.

"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import tomllib
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Any, Callable, Iterable, Optional

ROOT = pathlib.Path(__file__).resolve().parents[1]
#: Repository-relative paths.
TIER_FILE = '.github/python-versions.toml'
WORKFLOW_DIR = '.github/workflows'
TEMPLATE = '.github/PULL_REQUEST_TEMPLATE.md'

#: The branch the proposal lives on, and the pull request's base.
BRANCH = 'bot/python-versions'
BASE = 'main'
#: The commit trailer naming the proposal, by :func:`fingerprint`.
TRAILER = 'Python-Versions-Proposal'
#: The audit the ``detect`` job runs on the rewritten tree.
AUDIT = ('tests.project.test_python_versions_1660', 'tests.project.test_python_matrix_tiers_1633',
         'tests.project.test_ktlo_legs_stay_green_1672')
#: Tiers :func:`python_versions.load` refuses, so a version in one is reported, not written.
HELD = ('pre-release',)
#: The job whose blocking legs ruleset 23497679 requires by name, besides the aggregate.
REQUIRED_JOB = ('python-compatibility.yml', 'compatibility')
REQUIRED_AGGREGATE = 'Required checks passed'
#: What GitHub answers a push that changes a workflow file without the permission.
WORKFLOWS_REFUSAL = 'without `workflows` permission'

#: How a workflow runs :file:`util/python_versions.py`, and reads its outputs and labels.
SCRIPT_STEP = 'python3 util/python_versions.py --github-output'
READ = re.compile(r'\$\{\{\s*(fromJSON\(\s*)?((?:needs|steps)\.[\w-]+\.outputs\.[\w-]+)\s*\)?\s*\}\}')
REF = re.compile(r'(needs|steps)\.([\w-]+)\.outputs\.([\w-]+)')
DEFAULT_LABEL = re.compile(r"\$\{\{\s*matrix\.os\s*\|\|\s*'([^']+)'\s*\}\}")
AXIS_LABEL = re.compile(r'\$\{\{\s*matrix\.os\s*\}\}')


def _load_python_versions() -> 'Any':
    """:file:`util/python_versions.py`, the tier file's reader, beside this script."""
    spec = importlib.util.spec_from_file_location('python_versions', pathlib.Path(__file__).with_name(
        'python_versions.py'))
    assert spec is not None and spec.loader is not None  # nosec B101
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pv = _load_python_versions()


###############################################################################
# Sources
###############################################################################


class Source(NamedTuple):
    """Where one source is fetched from, the file it is saved as, and its format."""

    url: str
    filename: str
    kind: str


SOURCES = {
    'release-cycle': Source('https://peps.python.org/api/release-cycle.json', 'release-cycle.json', 'json'),
    'pypy': Source('https://downloads.python.org/pypy/versions.json', 'pypy-versions.json', 'json'),
    'manifest': Source('https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json',
                       'versions-manifest.json', 'json'),
    'runner-images': Source('https://raw.githubusercontent.com/actions/runner-images/main/README.md',
                            'runner-images-readme.md', 'text'),
}


def fetch(name: 'str', attempts: 'int' = 3) -> 'str':
    """Source ``name``'s text, retried twice on a network error or an HTTP error status.

    Fetched with :mod:`requests` (#1894), imported here rather than at the top:
    ``detect`` installs it, but ``pr`` runs ``publish`` on the runner's own
    ``python3`` with nothing installed, and ``publish`` never fetches.

    """
    import requests  # pylint: disable=import-outside-toplevel

    source = SOURCES[name]
    for attempt in range(attempts):
        try:
            response = requests.get(source.url, timeout=60,
                                    headers={'User-Agent': 'PyPCAPKit cron-python-versions (#1660)'})
            response.raise_for_status()
            return response.content.decode('utf-8')
        except OSError as error:  # every requests.RequestException is one
            if attempt + 1 == attempts:
                raise OSError(f'{source.url}: {error}') from error
            time.sleep(5 * (attempt + 1))
    raise AssertionError('unreachable')  # pragma: no cover


def read_sources(directory: 'Optional[pathlib.Path]' = None) -> 'dict[str, str]':
    """Every source's text: from ``directory``'s saved files, or fetched."""
    if directory is None:
        return {name: fetch(name) for name in SOURCES}
    return {name: (directory / source.filename).read_text(encoding='utf-8') for name, source in SOURCES.items()}


def parse_sources(texts: 'dict[str, str]') -> 'dict[str, Any]':
    return {name: json.loads(texts[name]) if source.kind == 'json' else texts[name]
            for name, source in SOURCES.items()}


###############################################################################
# Runner images and labels
###############################################################################


class Image(NamedTuple):
    """One hosted image: ``('ubuntu', '24.04', 'x64', ('ubuntu-latest', 'ubuntu-24.04'))``."""

    family: str
    version: str
    arch: str
    labels: 'tuple[str, ...]'


class Target(NamedTuple):
    """What a setup-python build is for: the manifest's ``platform``, ``platform_version`` and ``arch``.

    macOS builds carry no ``platform_version``, so a macOS target's is :data:`None`.

    """

    platform: str
    version: 'Optional[str]'
    arch: str


#: An image's family and version, at the start of the table's Image cell.
IMAGE = re.compile(r'(Ubuntu|macOS)\s+(\d+(?:\.\d+)?)\b')
PLATFORM = {'ubuntu': 'linux', 'macos': 'darwin'}


def numeric(version: 'str') -> 'tuple[int, ...]':
    """``'24.04'`` as ``(24, 4)``, ``'7.3.12rc1'`` as ``(7, 3, 12)``."""
    match = re.match(r'\d+(?:\.\d+)*', version)
    if match is None:
        raise ValueError(f'not a version: {version!r}')
    return tuple(map(int, match.group(0).split('.')))


def markdown_tables(text: 'str') -> 'list[list[list[Any]]]':
    """Each GFM table in ``text``: its rows, header first, each a list of its cells' inline tokens.

    Parsed with markdown-it-py (#1894), imported here for the reason
    :func:`fetch` imports :mod:`requests` there. An escaped pipe, ``\\|``, stays
    inside its cell, in a code span too, as GitHub renders it; splitting each
    line on ``|`` cut such a cell in two and shifted every column after it.

    """
    from markdown_it import MarkdownIt  # pylint: disable=import-outside-toplevel

    tables = []  # type: list[list[list[Any]]]
    row = None  # type: Optional[list[Any]]
    for token in MarkdownIt('commonmark').enable('table').parse(text):
        if token.type == 'table_open':
            tables.append([])
        elif token.type == 'tr_open':
            row = []
            tables[-1].append(row)
        elif token.type == 'tr_close':
            row = None
        elif token.type == 'inline' and row is not None:
            row.append(token)
    return tables


def parse_images(text: 'str') -> 'list[Image]':
    """The Ubuntu and macOS rows of the runner-images README's image table.

    The labels are the code spans of the YAML Label cell, read from its tokens,
    so a span holding an escaped pipe reads as GitHub shows it, without the
    backslash a backtick pattern over the cell's source would keep.

    """
    table = next((rows for rows in markdown_tables(text)
                  if any('YAML Label' in cell.content for cell in rows[0])), None)
    if table is None:
        raise ValueError('the runner-images README has no table with a "YAML Label" column')
    columns = [cell.content.strip() for cell in table[0]]
    try:
        image, arch, label = columns.index('Image'), columns.index('Architecture'), columns.index('YAML Label')
    except ValueError as error:
        raise ValueError(f'the runner-images table has columns {columns}') from error
    images = []
    for cells in table[1:]:
        match = IMAGE.match(cells[image].content.strip())
        if match is None:
            continue
        labels = tuple(child.content for child in cells[label].children or () if child.type == 'code_inline')
        images.append(Image(match.group(1).lower(), match.group(2), cells[arch].content.strip(), labels))
    if not any(found.family == 'ubuntu' for found in images):
        raise ValueError('the runner-images README lists no Ubuntu image')
    return images


def target_of(image: 'Image') -> 'Target':
    return Target(PLATFORM[image.family], image.version if image.family == 'ubuntu' else None, image.arch)


def label_targets(label: 'str', images: 'list[Image]') -> 'list[Target]':
    """What a job on ``label`` installs from: its image, and for ``-latest`` every newer one."""
    image = next((found for found in images if label in found.labels), None)
    if image is None:
        raise ValueError(f'{label!r} is a label the runner-images README does not list')
    chosen = [image]
    if label.endswith('-latest'):
        chosen += [found for found in images if (found.family, found.arch) == (image.family, image.arch)
                   and numeric(found.version) > numeric(image.version)]
    return sorted({target_of(found) for found in chosen}, key=lambda t: (t.platform, t.version or '', t.arch))


def runner_images(images: 'list[Image]', arch: 'str') -> 'list[tuple[Image, str]]':
    """The hosted Ubuntu images a version may name as its ``runner``, newest first, with that label."""
    found = []
    for image in images:
        label = next((name for name in image.labels if pv.RUNNER.fullmatch(name)), None)
        if image.family == 'ubuntu' and image.arch == arch and label is not None:
            found.append((image, label))
    return sorted(found, key=lambda pair: numeric(pair[0].version), reverse=True)


def describe(target: 'Target') -> 'str':
    return f'{target.platform} {target.version} {target.arch}' if target.version else \
        f'{target.platform} {target.arch}'


###############################################################################
# The workflows
###############################################################################


def load_workflows(root: 'pathlib.Path') -> 'dict[str, dict[str, Any]]':
    """Every workflow under ``root``, parsed."""
    import yaml  # pylint: disable=import-outside-toplevel

    return {path.name: yaml.safe_load(path.read_text(encoding='utf-8'))
            for path in sorted((root / WORKFLOW_DIR).glob('*.yml'))}


def script_output(workflows: 'dict[str, Any]', name: 'str', job_id: 'str', ref: 'str') -> 'Optional[str]':
    """The :file:`util/python_versions.py` output reference ``ref`` in job ``job_id`` ends at, if any."""
    jobs = workflows[name].get('jobs') or {}
    match = REF.fullmatch(ref)
    if match is None:
        return None
    kind, target, output = match.groups()
    if kind == 'needs':
        value = ((jobs.get(target) or {}).get('outputs') or {}).get(output)
        inner = READ.fullmatch(str(value).strip()) if value is not None else None
        if inner is None or inner.group(1):
            return None
        return script_output(workflows, name, target, inner.group(2))
    step = next((step for step in (jobs.get(job_id) or {}).get('steps', []) if step.get('id') == target), None)
    if step is None or str(step.get('run', '')).strip() != SCRIPT_STEP:
        return None
    return output


#: :func:`resolve`'s answer for text that reads no script output.
NOTHING = object()


def resolve(workflows: 'dict[str, Any]', name: 'str', job_id: 'str', text: 'Any', values: 'dict[str, str]') -> 'Any':
    """What ``text`` reads from the script's outputs ``values``, or :data:`NOTHING`."""
    match = READ.fullmatch(str(text).strip())
    if match is None:
        return NOTHING
    output = script_output(workflows, name, job_id, match.group(2))
    if output is None:
        return NOTHING
    return json.loads(values[output]) if match.group(1) else values[output]


def matrix_spec(workflows: 'dict[str, Any]', name: 'str', job_id: 'str',
                values: 'dict[str, str]') -> 'Optional[dict[str, Any]]':
    """Job ``job_id``'s ``strategy.matrix`` read from ``values``, or :data:`None` if it reads none."""
    raw = ((workflows[name]['jobs'][job_id].get('strategy') or {}).get('matrix'))
    if isinstance(raw, str):
        found = resolve(workflows, name, job_id, raw, values)
        return found if isinstance(found, dict) else None
    if not isinstance(raw, dict):
        return None
    spec, reads = {}, False
    for key, value in raw.items():
        found = resolve(workflows, name, job_id, value, values) if isinstance(value, str) else NOTHING
        reads = reads or found is not NOTHING
        spec[key] = value if found is NOTHING else found
    return spec if reads else None


def expand(spec: 'dict[str, Any]') -> 'list[dict[str, Any]]':
    """The legs GitHub expands ``spec`` to, in its order.

    The base axes' product, then each ``include`` entry: merged into every
    combination whose original values it matches, or added as one of its own.

    """
    spec = dict(spec)
    include = spec.pop('include', [])
    combos = [{}]  # type: list[dict[str, Any]]
    for key, axis in spec.items():
        combos = [dict(combo, **{key: str(value)}) for combo in combos for value in axis]
    for entry in include:
        entry = {key: str(value) if key in spec else value for key, value in entry.items()}
        matched = [combo for combo in combos
                   if all(combo.get(key) == value for key, value in entry.items() if key in spec)]
        added = False
        for combo in matched:
            if all(key in spec or key not in combo for key in entry):
                combo.update(entry)
                added = True
        if not added:
            combos.append(dict(entry))
    return combos


def axes(spec: 'dict[str, Any]') -> 'tuple[str, ...]':
    return tuple(key for key in spec if key != 'include')


EXPRESSION = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')


def evaluate(expression: 'str', leg: 'dict[str, Any]') -> 'str':
    """The expression shapes job names use: ``matrix.K``, ``matrix.K && 'A' || 'B'``, ``matrix.K || 'A'``."""
    match = re.fullmatch(r'matrix\.([\w-]+)', expression)
    if match:
        value = leg.get(match.group(1))
        return '' if value is None else str(value)
    match = re.fullmatch(r"matrix\.([\w-]+)\s*&&\s*'([^']*)'\s*\|\|\s*'([^']*)'", expression)
    if match:
        return match.group(2) if leg.get(match.group(1)) not in (None, False, '', 0) else match.group(3)
    match = re.fullmatch(r"matrix\.([\w-]+)\s*\|\|\s*'([^']*)'", expression)
    if match:
        value = leg.get(match.group(1))
        return match.group(2) if value in (None, False, '', 0) else str(value)
    raise ValueError(f'cannot evaluate ${{{{ {expression} }}}} in a job name')


def render_name(template: 'str', leg: 'dict[str, Any]') -> 'str':
    return EXPRESSION.sub(lambda match: evaluate(match.group(1), leg), template)


def matrix_legs(workflows: 'dict[str, Any]', values: 'dict[str, str]') -> 'dict[tuple[str, str], list[dict[str, Any]]]':
    """Every job whose matrix reads the script, as ``(workflow, job)``: its legs."""
    found = {}
    for name, spec in workflows.items():
        for job_id in (spec.get('jobs') or {}):
            matrix = matrix_spec(workflows, name, job_id, values)
            if matrix is not None:
                found[(name, job_id)] = expand(matrix)
    return found


def leg_names(workflows: 'dict[str, Any]', values: 'dict[str, str]') -> 'dict[tuple[str, str], dict[tuple, str]]':
    """Each such job's check-run names, keyed by the leg's base-axis values."""
    found = {}
    for (name, job_id), legs in matrix_legs(workflows, values).items():
        template = str(workflows[name]['jobs'][job_id].get('name', job_id))
        base = axes(matrix_spec(workflows, name, job_id, values) or {})
        found[(name, job_id)] = {tuple((key, leg.get(key)) for key in base): render_name(template, leg)
                                 for leg in legs}
    return found


#: The suffix of a job holding only the KTLO legs of the job named without it (#1738).
KTLO_JOB_SUFFIX = '-ktlo'


def with_ktlo_twins(names: 'dict[tuple[str, str], dict[tuple, str]]') -> 'dict[tuple[str, str], dict[tuple, str]]':
    """:func:`leg_names` with each KTLO job's legs under its gating twin's, as one job.

    A version moving to KTLO moves from ``test`` to ``test-ktlo`` (#1738); keyed
    together, its check run reads as renamed, as when both tiers shared a job.

    """
    found = {}  # type: dict[tuple[str, str], dict[tuple, str]]
    for (name, job_id), legs in names.items():
        if job_id.endswith(KTLO_JOB_SUFFIX):
            job_id = job_id[:-len(KTLO_JOB_SUFFIX)]
        found.setdefault((name, job_id), {}).update(legs)
    return found


def required_contexts(workflows: 'dict[str, Any]', values: 'dict[str, str]') -> 'list[str]':
    """Ruleset 23497679's required contexts for ``values``: the aggregate, and :data:`REQUIRED_JOB`'s blocking legs.

    A KTLO leg never blocks, nor an experimental one (#1660), so neither is ever proposed as required.

    """
    name, job_id = REQUIRED_JOB
    template = str(workflows[name]['jobs'][job_id]['name'])
    legs = matrix_legs(workflows, values)[REQUIRED_JOB]
    return [REQUIRED_AGGREGATE] + [render_name(template, leg) for leg in legs
                                   if leg.get('ktlo') is not True and leg.get('experimental') is not True]


def needed_by(workflow: 'dict[str, Any]', job_id: 'str') -> 'list[str]':
    """The jobs of ``workflow`` whose ``needs:`` lists ``job_id``."""
    found = []
    for other, job in (workflow.get('jobs') or {}).items():
        needs = job.get('needs') or []
        if job_id in ([needs] if isinstance(needs, str) else needs):
            found.append(other)
    return found


def emptied_jobs(workflows: 'dict[str, Any]', before: 'dict[str, str]', after: 'dict[str, str]',
                 why: 'dict[str, str]') -> 'list[str]':
    """A manual step for each job whose matrix the tiers ``after`` leave with no leg (#1747).

    ``pypcap-parity`` holds supported versions below 3.12 only, so 3.11 moving to
    KTLO empties it. The updater retires nothing: dropping a job is a workflow
    edit, which ``pr``'s token cannot push, and the owner's call. So the tiers are
    written as computed, and the job is named here, with each version ``why``
    says leaves it and the jobs that need it, for the owner to retire first.
    A matrix that was empty already is not one this update empties.

    """
    old, new = matrix_legs(workflows, before), matrix_legs(workflows, after)
    found = []
    for name, job_id in sorted(job for job, legs in old.items() if legs and not new.get(job)):
        versions = dict.fromkeys(str(leg.get('python-version')) for leg in old[(name, job_id)])
        reasons = ' and '.join(why.get(version, f'{version} leaves it') for version in versions)
        needs = needed_by(workflows[name], job_id)
        needed = f' (and its `needs:` in {", ".join(f"`{job}`" for job in needs)})' if needs else ''
        found.append(f'{name}: `{job_id}` would have no leg left once {reasons}; retire or remove the '
                     f'job{needed} before merging this update')
    return found


def setup_steps(job: 'dict[str, Any]') -> 'list[dict[str, Any]]':
    return [step for step in job.get('steps', []) if str(step.get('uses', '')).startswith('actions/setup-python@')]


def workflow_labels(workflows: 'dict[str, Any]') -> 'dict[str, list[str]]':
    """The runner labels each tier is installed on, read from the jobs' ``runs-on``.

    ``default``
        Where a version without ``runner`` runs: the label a ``matrix.os || '...'``
        falls back to, or the literal ``runs-on`` of a job installing a tier's list.
    ``supported``
        ``default``, plus each label of a literal ``os`` axis (the conda jobs).
    ``latest``
        The ``runs-on`` of every job whose setup-python reads ``latest``.

    """
    default, axis, latest = set(), set(), set()  # type: set[str], set[str], set[str]
    for name, spec in workflows.items():
        for job_id, job in (spec.get('jobs') or {}).items():
            runs_on = str(job.get('runs-on', ''))
            for step in setup_steps(job):
                text = str((step.get('with') or {}).get('python-version', '')).strip()
                read = READ.fullmatch(text)
                output = None if read is None else script_output(workflows, name, job_id, read.group(2))
                if output is None and 'matrix.python-version' not in text:
                    continue  # a pin the tier file exempts
                if output == 'latest':
                    if '${{' in runs_on:
                        raise ValueError(f'{name} {job_id} installs latest on {runs_on!r}, which this cannot read')
                    latest.add(runs_on)
                    continue
                match = DEFAULT_LABEL.fullmatch(runs_on)
                if match:
                    default.add(match.group(1))
                elif AXIS_LABEL.fullmatch(runs_on):
                    labels = ((job.get('strategy') or {}).get('matrix') or {}).get('os')
                    if not isinstance(labels, list):
                        raise ValueError(f'{name} {job_id} runs on matrix.os, which is not a literal list')
                    axis.update(map(str, labels))
                elif '${{' not in runs_on:
                    default.add(runs_on)
                else:
                    raise ValueError(f'{name} {job_id} runs on {runs_on!r}, which this cannot read')
    if not default or not latest:
        raise ValueError('found no job installing the tiers, or none installing latest')
    return {'default': sorted(default), 'supported': sorted(default | axis), 'latest': sorted(latest)}


###############################################################################
# The tiers
###############################################################################


class Note(NamedTuple):
    """Something a run reports: ``held`` (a tier the file cannot hold), ``warning``, or ``manual``."""

    kind: str
    text: str


class Result(NamedTuple):
    """One implementation's tiers: each version's entry, the reason for it, and what to report."""

    entries: 'dict[str, dict[str, str]]'
    reasons: 'dict[str, str]'
    notes: 'list[Note]'
    latest: 'Optional[str]' = None


class Context(NamedTuple):
    """What every implementation's rule reads: the parsed sources, the images, the labels."""

    sources: 'dict[str, Any]'
    images: 'list[Image]'
    labels: 'dict[str, list[str]]'

    def targets(self, kind: 'str') -> 'list[Target]':
        found = set()  # type: set[Target]
        for label in self.labels[kind]:
            found.update(label_targets(label, self.images))
        return sorted(found, key=lambda t: (t.platform, t.version or '', t.arch))


def cpython_builds(manifest: 'list[dict[str, Any]]') -> 'dict[str, dict[Target, bool]]':
    """Each minor version's build targets, each mapped to whether a stable build exists."""
    builds = {}  # type: dict[str, dict[Target, bool]]
    for release in manifest:
        match = re.match(r'(\d+)\.(\d+)\.\d+', str(release.get('version', '')))
        if match is None:
            continue
        found = builds.setdefault(f'{match.group(1)}.{match.group(2)}', {})
        for file in release.get('files', []):
            platform = file.get('platform')
            target = Target(platform, file.get('platform_version') if platform == 'linux' else None, file.get('arch'))
            found[target] = found.get(target, False) or bool(release.get('stable'))
    return builds


def has(builds: 'dict[str, dict[Target, bool]]', version: 'str', targets: 'Iterable[Target]',
        stable: 'bool' = True) -> 'bool':
    """Whether setup-python builds ``version`` for every target, stable or, with ``stable=False``, any."""
    found = builds.get(version, {})
    return all(target in found and (found[target] or not stable) for target in targets)


def compute_cpython(current: 'dict[str, dict[str, str]]', context: 'Context') -> 'Result':
    """CPython's tiers, from python.org's statuses and setup-python's builds."""
    cycle = context.sources['release-cycle']
    builds = cpython_builds(context.sources['manifest'])
    default, supported = context.targets('default'), context.targets('supported')
    arch = {target.arch for target in default if target.platform == 'linux'}
    if len(arch) != 1:
        raise ValueError(f'the default labels {context.labels["default"]} are not one Linux architecture')
    candidates = runner_images(context.images, arch.pop())
    entries, reasons, notes = {}, {}, []  # type: dict[str, dict[str, str]], dict[str, str], list[Note]
    for version in current:
        if version not in cycle:
            raise ValueError(f'CPython {version} is not in python.org\'s release cycle')
    for version, info in cycle.items():
        if not pv.SPELLING['cpython'].fullmatch(version):
            continue
        status = info.get('status')
        if status in ('bugfix', 'security'):
            entries[version] = {'tier': 'supported'}
            reasons[version] = f'python.org status `{status}`'
            missing = [describe(target) for target in supported if not has(builds, version, [target])]
            if missing:
                notes.append(Note('warning', f'setup-python has no stable build of supported {version} for '
                                             f'{", ".join(missing)}'))
        elif status == 'end-of-life':
            if version not in current:
                continue
            if has(builds, version, default):
                entries[version] = {'tier': 'ktlo'}
                reasons[version] = 'end-of-life; setup-python builds it for `ubuntu-latest`'
                continue
            image = next(((found, label) for found, label in candidates
                          if has(builds, version, [target_of(found)])), None)
            if image is None:
                reasons[version] = 'end-of-life, and setup-python builds it for no hosted Ubuntu image'
            else:
                entries[version] = {'tier': 'ktlo', 'runner': image[1]}
                reasons[version] = (f'end-of-life; setup-python builds it for {image[1]} but not for every image '
                                    '`ubuntu-latest` may mean')
        elif status in ('feature', 'prerelease'):
            if has(builds, version, default, stable=False):
                entries[version] = {'tier': 'pre-release'}
                reasons[version] = f'python.org status `{status}`, and setup-python has a build'
        else:
            raise ValueError(f'CPython {version}: unknown status {status!r}')

    latest, targets = None, context.targets('latest')
    bugfix = sorted((version for version in entries if cycle[version].get('status') == 'bugfix'),
                    key=pv.key, reverse=True)
    for version in bugfix:
        if has(builds, version, targets):
            latest = version
            break
        notes.append(Note('warning', f'{version} is the newest bugfix branch but setup-python has no stable build '
                                     f'of it for {", ".join(map(describe, targets))}, so `latest` stays older'))
    if latest is None:
        raise ValueError('no bugfix branch has a stable build on every label that installs latest')
    return Result(entries, reasons, notes, latest)


def pypy_line(release: 'dict[str, Any]') -> 'Optional[str]':
    """A PyPy release's Python version as ``'3.11'``, or :data:`None` for Python 2."""
    match = re.match(r'3\.(\d+)', str(release.get('python_version', '')))
    return f'3.{match.group(1)}' if match else None


def compute_pypy(current: 'dict[str, dict[str, str]]', context: 'Context') -> 'Result':
    """PyPy's tiers, from its releases: the newest stable release's versions are supported."""
    def usable(release: 'dict[str, Any]') -> 'bool':
        return pypy_line(release) is not None and re.fullmatch(r'\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?',
                                                                 str(release.get('pypy_version', ''))) is not None \
            and any(file.get('platform') == 'linux' and file.get('arch') == 'x64' for file in release.get('files', []))

    releases = [release for release in context.sources['pypy'] if usable(release)]
    stable = [release for release in releases if release.get('stable')]
    if not stable:
        raise ValueError('PyPy lists no stable Linux x64 release')
    newest = max(stable, key=lambda release: numeric(release['pypy_version']))['pypy_version']
    last = {}  # type: dict[str, str]
    for release in stable:
        line = pypy_line(release)
        if line is None:  # pragma: no cover -- usable() keeps Python 3 only
            continue
        if line not in last or numeric(release['pypy_version']) > numeric(last[line]):
            last[line] = release['pypy_version']
    entries, reasons = {}, {}  # type: dict[str, dict[str, str]], dict[str, str]
    for line, pypy_version in last.items():
        if numeric(pypy_version) == numeric(newest):
            entries[f'pypy{line}'] = {'tier': 'supported'}
            reasons[f'pypy{line}'] = f'in PyPy {newest}, the newest stable release'
    for version in current:
        if version in entries:
            continue
        line = version[len('pypy'):]
        if line in last:
            entries[version] = {'tier': 'ktlo'}
            reasons[version] = f'not in PyPy {newest}; its newest stable build is PyPy {last[line]}'
        else:
            reasons[version] = 'PyPy has no stable Linux x64 build of it'
    for release in releases:
        line = pypy_line(release)
        if not release.get('stable') and line not in last and f'pypy{line}' not in entries:
            entries[f'pypy{line}'] = {'tier': 'pre-release'}
            reasons[f'pypy{line}'] = f'only in PyPy {release["pypy_version"]}, a pre-release'
    return Result(entries, reasons, [])


class Implementation(NamedTuple):
    """An implementation's sources, from :data:`SOURCES`, and its rule."""

    sources: 'tuple[str, ...]'
    compute: 'Callable[[dict[str, dict[str, str]], Context], Result]'


#: One entry per implementation, keyed as in :data:`python_versions.SPELLING`.
IMPLEMENTATIONS = {
    'cpython': Implementation(('release-cycle', 'manifest', 'runner-images'), compute_cpython),
    'pypy': Implementation(('pypy',), compute_pypy),
}


###############################################################################
# The tier file
###############################################################################


ENTRY = re.compile(r'^"(?P<version>[^"]+)" = \{[^{}]*\}(?P<comment>[ \t]*#.*)?$')
SECTION = re.compile(r'^\[versions\.(?P<impl>[\w-]+)\]$')
LATEST = re.compile(r'^latest = "[^"]*"(?P<rest>.*)$')


def entry_line(version: 'str', entry: 'dict[str, str]', comment: 'str' = '') -> 'str':
    """One version's line, as the file spells it: ``"3.7" = { tier = "ktlo", runner = "ubuntu-22.04" }``."""
    fields = [f'tier = {json.dumps(entry["tier"])}']
    if 'runner' in entry:
        fields.append(f'runner = {json.dumps(entry["runner"])}')
    return f'"{version}" = {{ {", ".join(fields)} }}{comment}'


def render_tier_file(text: 'str', latest: 'str', versions: 'dict[str, dict[str, dict[str, str]]]') -> 'str':
    """``text`` with ``latest`` and each implementation's versions replaced, every other line kept.

    A version whose entry is unchanged keeps its line byte for byte. Each
    ``[versions.<impl>]`` table's entries must be the lines right below it; a new
    version is placed in order among them.

    """
    old = tomllib.loads(text)
    lines = text.splitlines(keepends=True)
    result = []
    seen = set()  # type: set[str]
    index = 0
    while index < len(lines):
        line = lines[index]
        bare = line.rstrip('\r\n')
        ending = line[len(bare):]
        match = LATEST.match(bare)
        if match and not seen:
            if old.get('latest') != latest:
                line = f'latest = {json.dumps(latest)}{match["rest"]}{ending}'
            result.append(line)
            index += 1
            continue
        section = SECTION.match(bare)
        if section is None:
            result.append(line)
            index += 1
            continue
        impl = section['impl']
        result.append(line)
        index += 1
        block = {}  # type: dict[str, tuple[str, str]]
        eol = ending or '\n'
        while index < len(lines):
            found = ENTRY.match(lines[index].rstrip('\r\n'))
            if found is None:
                break
            block[found['version']] = (lines[index], found['comment'] or '')
            eol = lines[index][len(lines[index].rstrip('\r\n')):] or eol
            index += 1
        for version, entry in versions[impl].items():
            kept = block.get(version)
            if kept is not None and old['versions'][impl].get(version) == entry:
                result.append(kept[0] if kept[0].endswith(('\n', '\r')) else kept[0] + eol)
            else:
                result.append(entry_line(version, entry, kept[1] if kept else '') + eol)
        seen.add(impl)
    if seen != set(versions):
        raise ValueError(f'{TIER_FILE} has tables for {sorted(seen)}, not {sorted(versions)}')
    rendered = ''.join(result)
    parsed = tomllib.loads(rendered)
    if parsed.get('latest') != latest or parsed.get('versions') != versions or \
            {k: v for k, v in parsed.items() if k not in ('latest', 'versions')} != \
            {k: v for k, v in old.items() if k not in ('latest', 'versions')}:
        raise ValueError(f'{TIER_FILE}: a version entry sits outside the line block below its table')
    return rendered


def validate(rendered: 'str') -> 'dict[str, Any]':
    """``rendered`` through :func:`python_versions.load`, which every workflow runs."""
    with tempfile.TemporaryDirectory(prefix='python-versions-') as tmp:
        path = pathlib.Path(tmp) / 'python-versions.toml'
        path.write_text(rendered, encoding='utf-8')
        return pv.load(path)


def computed(versions: 'dict[str, dict[str, Any]]') -> 'dict[str, dict[str, Any]]':
    """``versions`` without the experimental entries, which no rule here computes, and the tables left empty."""
    found = {impl: {version: entry for version, entry in entries.items() if entry['tier'] != 'experimental'}
             for impl, entries in versions.items()}
    return {impl: entries for impl, entries in found.items() if entries}


def fingerprint(latest: 'str', versions: 'dict[str, Any]') -> 'str':
    """A proposal's identity: its computed tiers, whatever else moved on ``main``, hand-kept entries included."""
    canonical = json.dumps({'latest': latest, 'versions': computed(versions)}, sort_keys=True,
                           separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:16]


###############################################################################
# The prose
###############################################################################


#: A line break, and a comment marker after it, as the audit tests' ``prose()`` reads them.
SEPARATOR = re.compile(r'[ \t]*\n[ \t]*(?:#:?[ \t]*)?')


def prose_view(text: 'str') -> 'tuple[str, list[int]]':
    """``text`` as the audit tests read it, and each character's offset in ``text`` (-1 for a joined break)."""
    pieces, origin = [], []  # type: list[str], list[int]
    position = 0
    for match in SEPARATOR.finditer(text):
        pieces.append(text[position:match.start()])
        origin.extend(range(position, match.start()))
        pieces.append(' ')
        origin.append(-1)
        position = match.end()
    pieces.append(text[position:])
    origin.extend(range(position, len(text)))
    return ''.join(pieces), origin


class Claim(NamedTuple):
    """A sentence restating the tiers: its pattern on the prose view, and each group's value."""

    pattern: str
    values: 'Callable[[dict[str, Any]], Optional[tuple[Any, ...]]]'


def apply_claims(text: 'str', claims: 'Iterable[Claim]', facts: 'dict[str, Any]') -> 'tuple[str, list[str]]':
    """``text`` with each claim's groups rewritten, and what could not be."""
    view, origin = prose_view(text)
    edits, problems = [], []  # type: list[tuple[int, int, str]], list[str]
    for claim in claims:
        matches = list(re.finditer(claim.pattern, view))
        if len(matches) != 1:
            problems.append(f'`{claim.pattern}` matches {len(matches)} times')
            continue
        values = claim.values(facts)
        if values is None:
            problems.append(f'`{claim.pattern}` cannot state a tier that is empty or has a gap')
            continue
        for group, value in enumerate(values, 1):
            start, end = matches[0].span(group)
            offsets = origin[start:end]
            if -1 in offsets or offsets != list(range(offsets[0], offsets[0] + len(offsets))):
                problems.append(f'`{claim.pattern}` group {group} spans a line break')
                break
            first, last = offsets[0], offsets[0] + len(offsets)
            edits.append((first, last, str(value)))
    for start, end, value in sorted(edits, reverse=True):
        text = text[:start] + value + text[end:]
    return text, problems


def consecutive(numbers: 'list[int]') -> 'bool':
    return bool(numbers) and numbers == list(range(numbers[0], numbers[0] + len(numbers)))


def span(tier: 'list[str]') -> 'Optional[tuple[str, str]]':
    """A tier's first and last version, if it is every minor version between them.

    "3.8 to 3.10" says 3.9 is in the tier, so a tier with a version dropped from
    its middle is not a span; the sentence is then left for a hand edit.

    """
    return (tier[0], tier[-1]) if consecutive([pv.key(version)[1] for version in tier]) else None


def lines_of(facts: 'dict[str, Any]', tier: 'str') -> 'Optional[tuple[int, int]]':
    """The tier file lines of a CPython tier, if they are one run of lines."""
    numbers = [facts['tier_lines'][version] for version in facts[tier]]
    return (numbers[0], numbers[-1]) if consecutive(numbers) else None


#: The sentences restating the tiers, by file. Never a workflow (see the module docstring).
CLAIMS = {
    'pyproject.toml': (
        Claim(r'\*\*(3\.\d+) through (3\.\d+)\*\* are supported', lambda f: span(f['supported'])),
        Claim(r'\*\*(3\.\d+) through (3\.\d+)\*\* are KTLO', lambda f: span(f['ktlo'])),
        Claim(r'the KTLO tier \((3\.\d+)-(3\.\d+)\)', lambda f: span(f['ktlo'])),
    ),
    'README.md': (
        Claim(r'CI supports (3\.\d+) to (3\.\d+)', lambda f: span(f['supported'])),
        Claim(r'tests the end-of-life (3\.\d+) to (3\.\d+)', lambda f: span(f['ktlo'])),
    ),
    'docs/source/index.rst': (
        Claim(r'CI supports (3\.\d+) to (3\.\d+)', lambda f: span(f['supported'])),
        Claim(r'tests the end-of-life (3\.\d+) to (3\.\d+)', lambda f: span(f['ktlo'])),
        Claim(r'(3\.\d+) to (3\.\d+) are end-of-life and best-effort', lambda f: span(f['ktlo'])),
    ),
    'docs/source/contributing/pep.rst': (
        Claim(r'in CI against Python (3\.\d+) through (3\.\d+)', lambda f: span(f['supported'])),
        Claim(r'against the end-of-life (3\.\d+) through (3\.\d+)', lambda f: span(f['ktlo'])),
    ),
    'docs/source/contributing/workflows.rst': (
        Claim(r'The \*\*supported\*\* tier, (3\.\d+)-(3\.\d+),', lambda f: span(f['supported'])),
        Claim(r'end-of-life (3\.\d+)-(3\.\d+), still built', lambda f: span(f['ktlo'])),
        Claim(r'the required legs are its supported tier \(``python-versions\.toml:(\d+)-(\d+)``\)',
              lambda f: lines_of(f, 'supported')),
        Claim(r'its KTLO legs \(``python-versions\.toml:(\d+)-(\d+)``\)', lambda f: lines_of(f, 'ktlo')),
        Claim(r'and the ``Compat Python (3\.\d+)``-``(3\.\d+)`` legs', lambda f: span(f['supported'])),
        Claim(r'the ``Python (3\.\d+)`` leg of ``test`` \(matrix key ``coverage: true``\)',
              lambda f: (f['latest'],)),
    ),
    'SECURITY.md': (
        Claim(r'blocking tier: CPython (3\.\d+) through (3\.\d+)', lambda f: span(f['supported'])),
        Claim(r'but (3\.\d+) to (3\.\d+) are best-effort', lambda f: span(f['ktlo'])),
    ),
    '.github/coverage.toml': (
        Claim(r'\(`test`, Python (\d+\.\d+)\)', lambda f: (f['latest'],)),
    ),
    'docs/source/contributing/conventions/test-coverage.rst': (
        Claim(r"the ``test`` job's Python (\d+\.\d+) cell", lambda f: (f['latest'],)),
    ),
    'docs/source/contributing/releasing.rst': (
        Claim(r'the sdist kept only on the (\d+\.\d+) leg', lambda f: (f['latest'],)),
    ),
}  # type: dict[str, tuple[Claim, ...]]

#: ``"Programming Language :: Python :: 3.N",``, one line per supported version.
CLASSIFIER = re.compile(r'^(?P<indent>[ \t]*)"Programming Language :: Python :: 3\.\d+",$', re.M)
#: One row of the workflows page's required-contexts table.
COMPAT_ROW = re.compile(r'^(?P<indent>[ \t]*)\* - ``Compat Python (?P<version>3\.\d+)``\n'
                        r'(?P<inner>[ \t]*)- job ``compatibility``, matrix leg ``(?P=version)``\n'
                        r'(?P=inner)- (?P<where>``[^`\n]+``), ``\.github/python-versions\.toml:\d+``\n', re.M)
BUG_VERSIONS = re.compile(r'(Python Version: \[e\.g\. )([^\]\n]+)(\])')


def adjacent(matches: 'list[re.Match[str]]', text: 'str') -> 'bool':
    """Whether ``matches`` are adjacent: each starts where the last one ended, or one newline after."""
    return all(text[a.end():b.start()] in ('', '\n') for a, b in zip(matches, matches[1:]))


def rewrite_classifiers(text: 'str', facts: 'dict[str, Any]') -> 'tuple[str, list[str]]':
    matches = list(CLASSIFIER.finditer(text))
    if not matches or not adjacent(matches, text):
        return text, ['the version classifiers are not one run of lines']
    block = '\n'.join(f'{matches[0]["indent"]}"Programming Language :: Python :: {version}",'
                      for version in facts['supported'])
    return text[:matches[0].start()] + block + text[matches[-1].end():], []


def rewrite_compat_rows(text: 'str', facts: 'dict[str, Any]') -> 'tuple[str, list[str]]':
    matches = list(COMPAT_ROW.finditer(text))
    if not matches or not adjacent(matches, text):
        return text, ['the required-contexts table has no run of `Compat Python` rows']
    first = matches[0]
    block = ''.join(f'{first["indent"]}* - ``Compat Python {version}``\n'
                    f'{first["inner"]}- job ``compatibility``, matrix leg ``{version}``\n'
                    f'{first["inner"]}- {first["where"]}, '
                    f'``.github/python-versions.toml:{facts["tier_lines"][version]}``\n'
                    for version in facts['supported'])
    return text[:first.start()] + block + text[matches[-1].end():], []


def rewrite_bug_template(text: 'str', facts: 'dict[str, Any]') -> 'tuple[str, list[str]]':
    """The bug report's examples: ``latest``, the middle supported version, the oldest."""
    supported = facts['supported']
    examples = list(dict.fromkeys([facts['latest'], supported[len(supported) // 2], supported[0]]))
    matches = list(BUG_VERSIONS.finditer(text))
    if len(matches) != 1:
        return text, [f'the Python Version line matches {len(matches)} times']
    return text[:matches[0].start(2)] + ', '.join(examples) + text[matches[0].end(2):], []


#: Rewriters for what is a list rather than a sentence, by file.
REWRITERS = {
    'pyproject.toml': (rewrite_classifiers,),
    'docs/source/contributing/workflows.rst': (rewrite_compat_rows,),
    '.github/ISSUE_TEMPLATE/bug_report.md': (rewrite_bug_template,),
}  # type: dict[str, tuple[Callable[[str, dict[str, Any]], tuple[str, list[str]]], ...]]

#: Every file this script may write. :func:`publish` refuses any other.
TARGETS = tuple(sorted({TIER_FILE} | set(CLAIMS) | set(REWRITERS)))


def make_facts(data: 'dict[str, Any]', values: 'dict[str, str]', workflows: 'dict[str, Any]',
               tier_file: 'str') -> 'dict[str, Any]':
    """What the prose states, computed from the new tiers and the workflows' matrices."""
    tier_lines = {}
    for number, line in enumerate(tier_file.splitlines(), 1):
        match = ENTRY.match(line)
        if match and pv.SPELLING['cpython'].fullmatch(match['version']):
            tier_lines[match['version']] = number
    return {
        'latest': data['latest'],
        'supported': pv.tier(data, 'cpython', 'supported'),
        'ktlo': pv.tier(data, 'cpython', 'ktlo'),
        'experimental': [version for impl in data['versions'] for version in pv.tier(data, impl, 'experimental')],
        'required': required_contexts(workflows, values),
        'tier_lines': tier_lines,
    }


###############################################################################
# The plan
###############################################################################


def tier_changes(before: 'dict[str, Any]', after: 'dict[str, Any]',
                 reasons: 'dict[str, dict[str, str]]') -> 'list[dict[str, Any]]':
    """Each version whose entry differs, oldest first per implementation."""
    found = []
    for impl in IMPLEMENTATIONS:
        old, new = before['versions'][impl], after['versions'][impl]
        for version in sorted(set(old) | set(new), key=pv.key):
            if old.get(version) != new.get(version):
                found.append({'impl': impl, 'version': version, 'before': old.get(version),
                              'after': new.get(version), 'reason': reasons[impl].get(version, '')})
    return found


def phrase(change: 'dict[str, Any]') -> 'str':
    version, before, after = change['version'], change['before'], change['after']
    if after is None:
        return f'{version} leaves CI'
    if before is None:
        return f'{version} joins the {after["tier"]} tier'
    if before['tier'] != after['tier']:
        return f'{version} moves to {"KTLO" if after["tier"] == "ktlo" else after["tier"]}'
    return f'{version} runs on {after.get("runner", "ubuntu-latest")}'


def title_of(changes: 'list[dict[str, Any]]', latest: 'tuple[str, str]') -> 'str':
    phrases = [phrase(change) for change in changes]
    if latest[0] != latest[1]:
        phrases.append(f'latest moves to {latest[1]}')
    if not phrases:
        return 'ci(python): regenerate the prose that restates the Python version tiers (#1660)'
    title = f'ci(python): {", ".join(phrases)} (#1660)'
    return title if len(title) <= 100 else 'ci(python): update the Python version tiers (#1660)'


def compute_plan(root: 'pathlib.Path', sources: 'dict[str, Any]') -> 'tuple[dict[str, Any], dict[str, str]]':
    """What a run proposes, and the new text of each file it changes."""
    old_tier_text = (root / TIER_FILE).read_bytes().decode('utf-8')
    before = validate(old_tier_text)
    workflows = load_workflows(root)
    before_values = pv.outputs(before)
    context = Context(sources, parse_images(sources['runner-images']), workflow_labels(workflows))

    versions, reasons, notes, latest = {}, {}, [], before['latest']
    for impl, implementation in IMPLEMENTATIONS.items():
        current = computed(before['versions']).get(impl, {})
        result = implementation.compute(current, context)
        kept = {}
        for version in sorted(result.entries, key=pv.key):
            entry = result.entries[version]
            if entry['tier'] in HELD:
                notes.append(Note('held', f'{version} ({result.reasons[version]}) is a {entry["tier"]}, which no '
                                          'workflow runs yet, so it is not written; wire non-blocking legs for the '
                                          'tier first (#1660)'))
                continue
            kept[version] = entry
        versions[impl], reasons[impl] = kept, result.reasons
        notes.extend(result.notes)
        if result.latest is not None:
            latest = result.latest
    # The experimental entries, kept as the file has them, after the computed ones
    # (#1660); so is a table no rule computes, GraalPy's.
    for impl, entries in before['versions'].items():
        versions.setdefault(impl, {}).update(
            (version, entry) for version, entry in entries.items() if entry['tier'] == 'experimental')
    versions = {impl: versions[impl] for impl in before['versions']}
    after = dict(before, latest=latest, versions=versions)
    new_tier_text = render_tier_file(old_tier_text, latest, versions)
    validate(new_tier_text)
    after_values = pv.outputs(after)

    facts = make_facts(after, after_values, workflows, new_tier_text)
    texts = {TIER_FILE: new_tier_text}
    for path in TARGETS:
        if path == TIER_FILE:
            continue
        text = (root / path).read_bytes().decode('utf-8')
        text, problems = apply_claims(text, CLAIMS.get(path, ()), facts)
        for rewrite in REWRITERS.get(path, ()):
            text, more = rewrite(text, facts)
            problems += more
        notes.extend(Note('manual', f'{path}: {problem}') for problem in problems)
        texts[path] = text
    changed = [path for path in TARGETS if texts[path] != (root / path).read_bytes().decode('utf-8')]

    names_before = with_ktlo_twins(leg_names(workflows, before_values))
    names_after = with_ktlo_twins(leg_names(workflows, after_values))
    renamed, added, removed = [], [], []
    for job in sorted(set(names_before) | set(names_after)):
        old, new = names_before.get(job, {}), names_after.get(job, {})
        renamed += [[old[key], new[key]] for key in old if key in new and old[key] != new[key]]
        added += [new[key] for key in new if key not in old]
        removed += [old[key] for key in old if key not in new]
    required_before = required_contexts(workflows, before_values)
    required_after = facts['required']
    pypi = (workflows['create-release.yml']['jobs']['pypi'].get('outputs') or {})
    for leg in matrix_legs(workflows, after_values).get(('create-release.yml', 'pypi'), []):
        key = 'ktlo_' + leg['python-version'].replace('.', '')
        if leg.get('ktlo') is True and key not in pypi:
            notes.append(Note('manual', f'create-release.yml: the `pypi` KTLO leg {leg["python-version"]} needs '
                                        f'its own `{key}` output for `release_status`'))

    changes = tier_changes(before, after, reasons)
    # #1747: in the plan's notes and its own key, which the body puts first.
    # Not in the fingerprint: like the renames, it follows from the tiers and
    # main's workflows, and the owner retiring the job on main must not make
    # the same tiers a new proposal, which would recreate the branch.
    retire = emptied_jobs(workflows, before_values, after_values,
                          {change['version']: phrase(change) for change in changes})
    notes.extend(Note('manual', text) for text in retire)
    plan = {
        'fingerprint': fingerprint(latest, versions),
        'title': title_of(changes, (before['latest'], latest)),
        'changed_files': changed,
        'changes': changes,
        'latest': [before['latest'], latest],
        'required': {'remove': [name for name in required_before if name not in required_after],
                     'add': [name for name in required_after if name not in required_before]},
        'renamed': renamed,
        'added': added,
        'removed': removed,
        'retire': retire,
        'notes': [note._asdict() for note in notes],
    }
    return plan, {path: texts[path] for path in changed}


def commit_message(plan: 'dict[str, Any]') -> 'str':
    lines = [plan['title'], '']
    lines += [f'- {phrase(change)} ({change["reason"]})' for change in plan['changes']]
    if plan['latest'][0] != plan['latest'][1]:
        lines.append(f'- latest: {plan["latest"][0]} -> {plan["latest"][1]}')
    lines += ['', 'Recomputed by .github/workflows/cron-python-versions.yml.', '', f'{TRAILER}: {plan["fingerprint"]}']
    return '\n'.join(lines) + '\n'


###############################################################################
# Pull request body
###############################################################################


def tier_text(entry: 'Optional[dict[str, str]]') -> 'str':
    if entry is None:
        return '--'
    name = 'KTLO' if entry['tier'] == 'ktlo' else entry['tier']
    return f'{name} on `{entry["runner"]}`' if 'runner' in entry else name


def describe_plan(plan: 'dict[str, Any]', audit: 'tuple[str, list[str]]', run_url: 'str') -> 'str':
    """The body's description: what moved and why, what the owner edits by hand, the audit."""
    out = [f'The weekly [Python Versions run]({run_url}) recomputed `{TIER_FILE}` from python.org\'s release '
           'cycle, PyPy\'s releases, setup-python\'s builds and the hosted runner images (#1660), and regenerated '
           'the prose that restates it.', '']
    if plan['changes'] or plan['latest'][0] != plan['latest'][1]:
        out += ['| Version | Before | After | Why |', '|---|---|---|---|']
        out += [f'| `{c["version"]}` | {tier_text(c["before"])} | {tier_text(c["after"])} | {c["reason"]} |'
                for c in plan['changes']]
        if plan['latest'][0] != plan['latest'][1]:
            out.append(f'| `latest` | {plan["latest"][0]} | {plan["latest"][1]} | the newest bugfix branch |')
        out.append('')
    if plan['retire']:
        out.append('**Before merging, retire or remove these jobs by hand** -- the workflow retires nothing and '
                   'never edits a workflow file, and these tiers leave their matrices empty (#1747):')
        out += [f'- {text}' for text in plan['retire']]
        out.append('')
    required = plan['required']
    if required['remove'] or required['add']:
        out.append('**Before merging, edit ruleset 23497679 (`main`)** -- the workflow never edits it:')
        out += [f'- remove `{name}`' for name in required['remove']]
        out += [f'- add `{name}`' for name in required['add']]
    else:
        out.append('Ruleset 23497679 needs no edit: its required contexts are unchanged.')
    out.append('')
    if plan['renamed']:
        out.append('Renamed check runs: ' + ', '.join(f'`{a}` -> `{b}`' for a, b in plan['renamed']) + '.')
    if plan['added']:
        out.append('New check runs: ' + ', '.join(f'`{name}`' for name in plan['added']) + '.')
    if plan['removed']:
        out.append('Removed check runs: ' + ', '.join(f'`{name}`' for name in plan['removed']) + '.')
    rest = [note['text'] for note in plan['notes'] if note['text'] not in plan['retire']]
    if rest:
        out += ['', 'Not done here:'] + [f'- {text}' for text in rest]
    outcome, failures = audit
    names = ', '.join(f'`{module.rsplit(".", 1)[-1]}`' for module in AUDIT)
    if outcome == 'success':
        out += ['', f'Audit ({names}): passed on this tree.']
    else:
        out += ['', f'Audit ({names}): **{outcome}** on this tree; finish the hand edits on this branch -- the '
                    'next run keeps commits that are not its own.']
        out += [f'- `{failure}`' for failure in failures[:15]]
        if len(failures) > 15:
            out.append(f'- and {len(failures) - 15} more; see the run\'s log')
    out += ['', 'Regenerated: ' + ', '.join(f'`{path}`' for path in plan['changed_files']) + '.']
    return '\n'.join(out)


def fill_template(template: 'str', description: 'str', audit_outcome: 'str') -> 'str':
    """The repository's pull request template, ``ci`` ticked, the description filled in."""
    text = re.sub(r'(?m)^- \[ \] `ci`', '- [x] `ci`', template)
    audit = {'success': 'passed', 'failure': 'failed'}.get(audit_outcome, audit_outcome)
    text = re.sub(r'(?m)^(- \[ \] `make test` passes.*)$', rf'\1 -- not run; the audit {audit} (below)', text)
    text = re.sub(r'(?m)^(- \[ \] Added a \[changelog entry\].*)$', r'\1 — N/A — centralised in #657', text)
    placeholder = re.search(r'(?m)^&emsp; Explanation of your \*pull request\*.*$', text)
    if placeholder is None:
        return text.rstrip('\n') + '\n\n' + description + '\n'
    return text[:placeholder.start()] + description + text[placeholder.end():].rstrip('\n') + '\n'


def audit_failures(log: 'str') -> 'list[str]':
    """The failing tests in a ``python -m unittest`` log, as ``module.Class.test``."""
    found = []
    for match in re.finditer(r'(?m)^(?:FAIL|ERROR): (\S+) \(([\w.]+)\)', log):
        name = f'{match.group(2)}.{match.group(1)}' if not match.group(2).endswith(match.group(1)) else match.group(2)
        if name not in found:
            found.append(name)
    return found


###############################################################################
# Git
###############################################################################


def git(root: 'pathlib.Path', *argv: 'str', check: 'bool' = True) -> 'subprocess.CompletedProcess[str]':
    result = subprocess.run(['git', *argv], cwd=root, capture_output=True, text=True, check=False)  # nosec B603 B607
    if check and result.returncode:
        raise RuntimeError(f'git {" ".join(argv)} exited {result.returncode}: {result.stderr.strip()}')
    return result


def proposal_of(message: 'str') -> 'Optional[str]':
    match = re.search(rf'(?m)^{TRAILER}: (\w+)\s*$', message)
    return match.group(1) if match else None


def proposals(root: 'pathlib.Path', *revisions: 'str') -> 'list[Optional[str]]':
    """What each commit ``git log <revisions>`` lists proposes, newest first; :data:`None` for one of none.

    A merge with a parent the range leaves out is left out too. In
    ``main..branch`` that parent is :data:`BASE`'s: the merge is GitHub's
    "Update branch", or ``git merge main`` to resolve a conflict, so it is
    neither a proposal nor a hand edit, and what it brings in is :data:`BASE`'s.

    """
    listed = git(root, 'log', '-z', '--format=%H %P%n%B', *revisions).stdout
    commits = []
    for record in listed.split('\0'):
        if record.strip():
            head, _, message = record.partition('\n')
            sha, *parents = head.split()
            commits.append((sha, parents, message))
    shas = {sha for sha, _, _ in commits}
    return [proposal_of(message) for _, parents, message in commits
            if len(parents) < 2 or all(parent in shas for parent in parents)]


def foreign(held: 'list[Optional[str]]') -> 'bool':
    """Whether a branch holding these commits ahead of :data:`BASE` holds one this workflow did not make.

    The workflow's own is one commit, carrying :data:`TRAILER`, on :data:`BASE`.
    While the branch's pull request is open, ``publish`` will not overwrite
    anything else, and ``update`` refuses first.

    """
    return len(held) > 1 or None in held


def ahead(root: 'pathlib.Path', branch: 'str') -> 'Optional[tuple[str, list[Optional[str]]]]':
    """``origin``'s ``branch``: its tip, and :func:`proposals` of what it holds ahead of :data:`BASE`.

    :data:`None` when there is no such branch. Both branches are fetched whole
    into a scratch repository, commits only (``--filter=tree:0``; 2,917 commits,
    2.4 MB, under a second on 2026-10-13). That is anonymous for a public
    repository and needs no history in ``root``, so ``detect``'s depth-1
    checkout serves and is left as it was. A fetch cut at :data:`BASE`
    (``--shallow-exclude``) stops at a merge of it, and loses the proposal
    under that merge.

    """
    url = git(root, 'remote', 'get-url', 'origin').stdout.strip()
    with tempfile.TemporaryDirectory(prefix='update-python-versions-') as tmp:
        scratch = pathlib.Path(tmp)
        git(scratch, 'init', '--quiet', '--bare')
        # A named remote: a filtered fetch records it as the promisor, which a path cannot be.
        git(scratch, 'remote', 'add', 'origin', url)
        listed = git(scratch, 'ls-remote', '--exit-code', '--heads', 'origin', f'refs/heads/{branch}', check=False)
        if listed.returncode == 2:
            return None
        if listed.returncode:
            raise RuntimeError(f'git ls-remote exited {listed.returncode}: {listed.stderr.strip()}')
        # #1644: no maintenance left running as the directory is removed.
        git(scratch, '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', '-c', 'gc.autoDetach=false', 'fetch',
            '--quiet', '--no-tags', '--filter=tree:0', 'origin', f'+refs/heads/{BASE}:refs/heads/{BASE}',
            f'+refs/heads/{branch}:refs/heads/{branch}')
        tip = git(scratch, 'rev-parse', f'refs/heads/{branch}').stdout.strip()
        return tip, proposals(scratch, f'refs/heads/{BASE}..refs/heads/{branch}')


def proposed(root: 'pathlib.Path', branch: 'str') -> 'Optional[list[Optional[str]]]':
    """What each commit ``origin``'s ``branch`` holds ahead of :data:`BASE` proposes, newest first (:func:`ahead`)."""
    found = ahead(root, branch)
    return None if found is None else found[1]


def repository() -> 'str':
    repo = os.environ.get('GITHUB_REPOSITORY', '')
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', repo):
        raise RuntimeError(f'$GITHUB_REPOSITORY {repo!r} names no repository')
    return repo


def open_pull_requests(branch: 'str') -> 'list[str]':
    """The open pull requests from :func:`repository`'s own ``branch`` into :data:`BASE`, by number; read-only.

    ``gh pr list --head`` also matches a fork's branch of that name, which is not this one.

    """
    return gh('pr', 'list', '--repo', repository(), '--head', branch, '--base', BASE, '--state', 'open',
              '--json', 'number,isCrossRepository', '--jq', '.[] | select(.isCrossRepository | not) | .number').split()


###############################################################################
# Commands
###############################################################################


def escape(text: 'str', title: 'bool' = False) -> 'str':
    """``text`` for a workflow command: data escapes, and in a title ``,`` and ``:`` too."""
    text = text.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    return text.replace(':', '%3A').replace(',', '%2C') if title else text


def annotate(notes: 'Iterable[dict[str, str]]') -> 'None':
    levels = {'held': 'notice', 'warning': 'warning', 'manual': 'warning'}
    for note in notes:
        print(f'::{levels[note["kind"]]} title={escape("Python version tiers", title=True)}::{escape(note["text"])}')


def write_output(path: 'Optional[str]', values: 'dict[str, str]') -> 'None':
    if not path:
        raise RuntimeError('--github-output needs $GITHUB_OUTPUT')
    with open(path, 'a', encoding='utf-8') as file:
        for name, value in values.items():
            file.write(f'{name}={value}\n')


def command_update(args: 'argparse.Namespace', root: 'pathlib.Path' = ROOT) -> 'int':
    texts = read_sources(args.sources)
    plan, new_texts = compute_plan(root, parse_sources(texts))
    for change in plan['changes']:
        print(f'{change["version"]}: {tier_text(change["before"])} -> {tier_text(change["after"])} '
              f'({change["reason"]})')
    if plan['latest'][0] != plan['latest'][1]:
        print(f'latest: {plan["latest"][0]} -> {plan["latest"][1]}')
    for old, new in plan['renamed']:
        print(f'renamed: {old} -> {new}')
    for kind in ('add', 'remove'):
        for name in plan['required'][kind]:
            print(f'ruleset 23497679: {kind} {name}')
    annotate(plan['notes'])
    changed = bool(plan['changed_files'])
    publish, status = changed, 0
    if changed and args.proposal_branch:
        held = proposed(root, args.proposal_branch)
        branch = escape(args.proposal_branch)
        if held is not None and not open_pull_requests(args.proposal_branch):
            print(f'::notice title=Proposing afresh::{branch} has no open pull request, so what it holds was merged '
                  'or closed; publish recreates it from main.')
            held = None
        held = held or []
        if plan['fingerprint'] in held:
            publish = False
            print(f'::notice title=Already proposed::{branch} already proposes these tiers ({plan["fingerprint"]}); '
                  'close its pull request to have them proposed again.')
        elif foreign(held):
            # publish would refuse, so no approval is asked for that.
            publish, status = False, 1
            older = ', '.join(sorted({found for found in held if found})) or 'none'
            print(f'::error title=Not overwriting {escape(args.proposal_branch, title=True)}::it holds commits this '
                  f'workflow did not make and proposes {older}, not these tiers ({plan["fingerprint"]}); merge or '
                  'close its pull request, or delete the branch, to have them proposed.')
    if args.diff:
        for path, text in new_texts.items():
            old = (root / path).read_bytes().decode('utf-8')
            sys.stdout.writelines(difflib.unified_diff(old.splitlines(True), text.splitlines(True),
                                                       f'a/{path}', f'b/{path}'))
    if args.write:
        for path, text in new_texts.items():
            (root / path).write_bytes(text.encode('utf-8'))
    if args.out is not None:
        out = pathlib.Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for path, text in new_texts.items():
            target = out / 'files' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text.encode('utf-8'))
        (out / 'sources').mkdir(exist_ok=True)
        for name, source in SOURCES.items():
            (out / 'sources' / source.filename).write_text(texts[name], encoding='utf-8')
        (out / 'plan.json').write_text(json.dumps(plan, indent=1) + '\n', encoding='utf-8')
        (out / 'commit-message.txt').write_text(commit_message(plan), encoding='utf-8')
    print(f'{len(plan["changed_files"])} file(s) to change: {" ".join(plan["changed_files"]) or "none"}')
    if args.github_output:
        write_output(os.environ.get('GITHUB_OUTPUT'), {'changed': str(changed).lower(),
                                                        'publish': str(publish).lower(),
                                                        'fingerprint': plan['fingerprint']})
    return status


def command_body(args: 'argparse.Namespace', root: 'pathlib.Path' = ROOT) -> 'int':
    out = pathlib.Path(args.proposal)
    plan = json.loads((out / 'plan.json').read_text(encoding='utf-8'))
    log = pathlib.Path(args.audit_log).read_text(encoding='utf-8', errors='replace') if args.audit_log else ''
    description = describe_plan(plan, (args.audit_outcome, audit_failures(log)), args.run_url)
    body = fill_template((root / TEMPLATE).read_text(encoding='utf-8'), description, args.audit_outcome)
    (out / 'pr-body.md').write_text(body, encoding='utf-8')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as file:
            file.write(f'## {plan["title"]}\n\n{description}\n')
    return 0


def check_targets(paths: 'Iterable[str]') -> 'None':
    for path in paths:
        if path not in TARGETS or path.startswith(WORKFLOW_DIR + '/'):
            raise ValueError(f'{path!r} is not a file this script writes')


def gh(*argv: 'str') -> 'str':
    result = subprocess.run(['gh', *argv], capture_output=True, text=True, check=False)  # nosec B603 B607
    if result.returncode:
        raise RuntimeError(f'gh {argv[0]} {argv[1]} exited {result.returncode}: {result.stderr.strip()}')
    return result.stdout


def push(root: 'pathlib.Path', branch: 'str', lease: 'str') -> 'subprocess.CompletedProcess[str]':
    """``HEAD`` to ``origin``'s ``branch`` and nowhere else, if ``branch`` is still at ``lease`` (``''``: absent)."""
    return git(root, 'push', f'--force-with-lease=refs/heads/{branch}:{lease}', 'origin',
               f'HEAD:refs/heads/{branch}', check=False)


def command_publish(args: 'argparse.Namespace', root: 'pathlib.Path' = ROOT) -> 'int':
    """Commit the proposal on :data:`BRANCH`, push that branch, and open or update its pull request."""
    out = pathlib.Path(args.proposal)
    plan = json.loads((out / 'plan.json').read_text(encoding='utf-8'))
    check_targets(plan['changed_files'])
    slug = os.environ.get('APP_SLUG', '')
    if not re.fullmatch(r'[\w-]+', slug):
        raise ValueError(f'APP_SLUG {slug!r} is not an App slug')
    bot_id = os.environ.get('APP_BOT_ID', '')
    email = f'{bot_id}+{slug}[bot]@users.noreply.github.com' if bot_id.isdigit() else \
        f'{slug}[bot]@users.noreply.github.com'
    repo = repository()

    for path in plan['changed_files']:
        shutil.copyfile(out / 'files' / path, root / path)
    git(root, 'add', '--', *plan['changed_files'])
    if not git(root, 'diff', '--cached', '--quiet', check=False).returncode:
        print('::notice title=Nothing to propose::this commit already holds the proposal')
        return 0
    git(root, '-c', f'user.name={slug}[bot]', '-c', f'user.email={email}', 'commit', '--quiet',
        '-F', str(out / 'commit-message.txt'))

    # The lease is the tip whose commits were read, so a push since fails it.
    found = ahead(root, BRANCH)
    lease = '' if found is None else found[0]
    recreate = found is not None and not open_pull_requests(BRANCH)
    if recreate:
        print(f'::notice title=Recreating {escape(BRANCH, title=True)}::it has no open pull request, so what it '
              'holds was merged or closed; it restarts from main.')
    elif found is not None and foreign(found[1]):
        print(f'::error title=Not overwriting {escape(BRANCH, title=True)}::it holds commits this workflow '
              'did not make; merge or close its pull request, or delete the branch, and re-run.')
        return 1
    if not recreate:
        pushed = push(root, BRANCH, lease)
        # main's workflows moved since the branch was cut, so moving the branch
        # would change them, which this token may not do; a new branch does not.
        recreate = bool(pushed.returncode and lease and WORKFLOWS_REFUSAL in pushed.stderr)
        if recreate:
            print(f'::warning title=Recreating {escape(BRANCH, title=True)}::moving it would change workflow files '
                  'main changed since, which needs the workflows permission; its pull request closes and a new one '
                  'opens.')
    if recreate:
        git(root, 'push', f'--force-with-lease=refs/heads/{BRANCH}:{lease}', 'origin', f':refs/heads/{BRANCH}')
        pushed = push(root, BRANCH, '')
    if pushed.returncode:
        raise RuntimeError(f'git push exited {pushed.returncode}: {pushed.stderr.strip()}')

    number = open_pull_requests(BRANCH)
    body = str(out / 'pr-body.md')
    if number:
        gh('pr', 'edit', number[0], '--repo', repo, '--title', plan['title'], '--body-file', body)
        print(f'::notice title=Updated the proposal::pull request #{number[0]}')
    else:
        url = gh('pr', 'create', '--repo', repo, '--base', BASE, '--head', BRANCH, '--title', plan['title'],
                 '--body-file', body).strip()
        print(f'::notice title=Opened the proposal::{escape(url)}')
    return 0


def main(argv: 'Optional[list[str]]' = None, root: 'pathlib.Path' = ROOT) -> 'int':
    """The command line; ``root`` is the checkout it reads and writes."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    commands = parser.add_subparsers(dest='command', required=True)
    update = commands.add_parser('update', help='recompute the tiers and the prose')
    update.add_argument('--sources', type=pathlib.Path, help='read the sources from this directory, not the network')
    update.add_argument('--write', action='store_true', help='rewrite the files in place')
    update.add_argument('--diff', action='store_true', help='print the change as a unified diff')
    update.add_argument('--out', help='write the proposal here')
    update.add_argument('--proposal-branch', help='skip publishing while this branch has an open pull request and '
                                                  'already proposes the same tiers')
    update.add_argument('--github-output', action='store_true', help='write changed, publish, fingerprint')
    body = commands.add_parser('body', help="render a proposal's pull request body")
    body.add_argument('proposal')
    body.add_argument('--audit-outcome', default='success')
    body.add_argument('--audit-log')
    body.add_argument('--run-url', default='')
    publish = commands.add_parser('publish', help="push a proposal's branch and open or update its pull request")
    publish.add_argument('proposal')
    args = parser.parse_args(argv)
    run = {'update': command_update, 'body': command_body, 'publish': command_publish}[args.command]
    try:
        return run(args, root)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        message = escape(f'{type(error).__name__}: {error}')
        print(f'::error title=Cannot {args.command} the Python version tiers::{message}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
