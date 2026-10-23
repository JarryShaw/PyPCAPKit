# -*- coding: utf-8 -*-
"""Write a test workflow run's report from its check suite and its job summaries (#2030).

The ``discussion`` job of :file:`.github/workflows/coverage-comment.yml`, for
Unit Tests, and of :file:`.github/workflows/ci-reports.yml`, for Experimental
Tests and Python Compatibility, runs, from a checkout of the default branch's
script and on the runner's ``python3``::

    python3 util/check_suite_report.py --report FILE

with ``GH_TOKEN`` and ``GITHUB_REPOSITORY``, and the triggering run's
``workflow_run`` fields, in the environment: ``WORKFLOW``, its workflow's name,
which :data:`WORKFLOWS` must hold; ``SUITE``, its check suite's node id;
``RUN_ID``, ``RUN_URL``, ``RUN_EVENT``, ``RUN_CONCLUSION``, ``HEAD_SHA`` and
``HEAD_BRANCH``. It writes the Markdown report to ``FILE``, and the step outputs
``post``, ``title``, ``mode`` and ``status`` that ``Post the report to
Discussions`` hands :file:`util/discussion_report.py`.

The run's jobs are read in one GraphQL call (:data:`SUITE_QUERY`): each job's
conclusion and its first annotations. A job that did not pass is named. A job
that passed is named with its warning and failure annotations, other than those
:func:`ignored` drops: pip's ``Retrying ... after connection`` lines, network
noise on any leg, and the annotations a workflow's ``expected`` list holds as
written on every run by design. Each name and annotation is quoted as a code span,
so none renders or mentions.

The status (:func:`assess`) starts from the run's conclusion (:data:`CONCLUSIONS`).
A green run becomes ``warning`` where a job failed without failing it, and where
an annotation counts. On a push run, the owner's ruling, one counts only on a
non-blocking leg (:func:`nonblocking`), whose steps are forced to succeed: a
``(KTLO)`` or ``(experimental)`` job, or an annotation such a step titles
``(KTLO, non-blocking)``. A passing blocking job's annotations then neither count
nor are listed, unless the run failed. On any other run, which posts every time,
every annotation counts.

A run whose legs, the jobs a workflow's ``legs`` pattern names, all skipped, as
they do where ``current`` or ``changes``' ``code`` is ``false``, tested nothing,
so where it did not fail it posts nothing (``post=false``).

Each job's summary comes from the artifact ``job-summary-*`` the job uploads
(:func:`download`), since the API serves none: ``job-summary.md``, the job's
copy of its summary, and ``job-summary.name``, the job's name. Each is folded
into a ``<details>`` block, and the blocks share what room a comment leaves
(:func:`fit`), each trimmed to its share with a link to the run.

Reporting must never turn a run red: the script exits 0 whatever happens, and
where anything goes wrong it writes a ``::warning`` and the report it can. It is
standard library only, and reaches the API only through :program:`gh`.

"""

from __future__ import annotations

import argparse
import html
import json
import os
import pathlib
import re
# The gh CLI, with a fixed argument list and no shell.
import subprocess  # nosec: B404
import sys
import tempfile
from typing import TYPE_CHECKING, NamedTuple

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Any, Mapping, Optional, Pattern

__all__ = ['Workflow', 'WORKFLOWS', 'CONCLUSIONS', 'LIMIT', 'TITLE', 'Assessment', 'code', 'ignored',
           'nonblocking', 'assess', 'tested', 'thread', 'download', 'fit', 'render', 'main']


class Workflow(NamedTuple):
    """A test workflow the script reports."""

    #: The workflow's file stem, which opens its threads' titles.
    stem: 'str'
    #: The jobs ``current`` and ``changes`` gate, by the start of the name.
    legs: 'Pattern[str]'
    #: The annotations its jobs write on every run by design: per job, ``(level,
    #: title prefix)``, where an empty prefix matches only an empty title, the
    #: runner's own line for the step that failed. Matched on the title, not the
    #: message, which #2041 rewords.
    expected: 'dict[str, tuple[tuple[str, str], ...]]'


#: The workflows reported, by name. No list holds an annotation today: the 3.7
#: legs that stopped at install went with #2051, and pypy3.10 installs since
#: #2040's cryptography cap.
WORKFLOWS = {
    'Unit Tests': Workflow(
        'unit-tests', re.compile(r'(?:Python |Integration Python |Engines \(|PyPCAP/PyPCAPFile parity Python )'),
        {}),
    'Experimental Tests': Workflow('experimental', re.compile(r'Python .* \(experimental\)$'), {}),
    'Python Compatibility': Workflow('python-compatibility', re.compile(r'Compat Python '), {}),
}
#: A run's conclusion, and the ``--status`` it starts from; anything else, ``timed_out``
#: and ``startup_failure`` among them, is a ``failure``.
CONCLUSIONS = {'success': 'success', 'cancelled': 'cancelled', 'stale': 'cancelled', 'skipped': 'skipped',
               'neutral': 'skipped'}
#: The longest body GitHub accepts for a discussion comment, in characters, as
#: :data:`discussion_report.LIMIT <util.discussion_report.LIMIT>` holds it.
LIMIT = 65536
#: The room left in :data:`LIMIT` for the provenance line and marker the post adds.
FOOTER = 1024
#: The title of every warning the script writes.
TITLE = 'CI report not written'
#: How long one ``gh`` call may take, in seconds.
TIMEOUT = 120
#: The longest job summary read, in characters; a longer one is cut there.
MAX_SUMMARY = 1 << 20
#: The check-suite query: each job's name, conclusion and first annotations.
SUITE_QUERY = ('query($id: ID!) { node(id: $id) { ... on CheckSuite { checkRuns(first: 100) {'
               ' pageInfo { hasNextPage }'
               ' nodes { name conclusion annotations(first: 20) { nodes { annotationLevel title message } } } } } } }')
#: pip's line for a request it retries, which a problem matcher annotates (#2030).
RETRY = re.compile(r'Retrying \(Retry\(.*\)\) after connection ')
#: A job whose steps are forced to succeed, by its name.
NONBLOCKING_JOB = re.compile(r'.*\((?:KTLO|experimental)\)$')
#: An annotation a forced step writes, as its title says: the engine KTLO cells'.
NONBLOCKING_NOTE = re.compile(r'\((?:KTLO|experimental), non-blocking\)')
#: An artifact's name, a commit and a run's page, as the report accepts them.
ARTIFACT = 'job-summary-*'
SHA = re.compile(r'[0-9a-f]{40}')
RUN_PAGE = re.compile(r'https://[\w.-]+/[\w.-]+/[\w.-]+/actions/runs/\d+')
#: What ``gh run download`` says, failing, where it found nothing to download, as
#: :file:`pkg/cmd/run/download/download.go` in cli/cli writes each (#2074): a run
#: with no artifact that has not expired, and one with none :data:`ARTIFACT`
#: matches, worded the latter way since gh 2.11.0 and the former before it.
NOTHING = frozenset({
    'no valid artifacts found to download',
    'no artifact matches any of the names or patterns provided',
    'no artifact matches any of the names provided',
})
#: A mention, which a summary's text must not make.
MENTION = re.compile(r'@(?=[A-Za-z0-9])')
#: What the report joins its job summaries' blocks by.
JOIN = '\n\n'


class Assessment(NamedTuple):
    """What :func:`assess` makes of a run's jobs."""

    #: The ``--status``.
    status: 'str'
    #: Each job that did not pass, as a list item.
    failed: 'list[str]'
    #: Each job that passed with annotations listed, as a list item.
    warned: 'list[str]'
    #: Whether an annotation was dropped: by design, pip's retries, or a blocking job's on a push.
    dropped: 'bool'


def code(text: 'object') -> 'str':
    """One line of ``text``, at most 200 characters, as a code span, so it renders and mentions nothing."""
    flat = ' '.join(str(text).replace('`', "'").split())
    return f'`{flat if len(flat) <= 200 else flat[:197] + "..."}`'


def ignored(job: 'str', note: 'dict[str, Any]', expected: 'Mapping[str, tuple[tuple[str, str], ...]]') -> 'bool':
    """Whether ``note``, an annotation of ``job``, counts for nothing: pip retrying, or by design."""
    title = note.get('title') or ''
    if RETRY.search(title) or RETRY.search(note.get('message') or ''):
        return True
    return any(note.get('annotationLevel') == level and (title.startswith(prefix) if prefix else not title)
               for level, prefix in expected.get(job, ()))


def nonblocking(job: 'str', note: 'dict[str, Any]') -> 'bool':
    """Whether ``note``, an annotation of ``job``, is a non-blocking leg's."""
    return bool(NONBLOCKING_JOB.match(job) or NONBLOCKING_NOTE.search(note.get('title') or ''))


def assess(nodes: 'Optional[list[dict[str, Any]]]', conclusion: 'str', mode: 'str',
           expected: 'Mapping[str, tuple[tuple[str, str], ...]]') -> 'Assessment':
    """The status of a run in ``mode`` that ended ``conclusion``, from its jobs ``nodes``, :data:`None` if unread."""
    status = CONCLUSIONS.get(conclusion, 'failure')
    failed, warned, dropped, counted = [], [], False, False
    for node in nodes or []:
        name, result = node.get('name') or '?', (node.get('conclusion') or 'unknown').lower()
        if result not in ('success', 'skipped', 'neutral'):
            failed.append(f'{code(name)} ({result})')
            continue
        if result != 'success':
            continue
        flagged = [note for note in (node.get('annotations') or {}).get('nodes') or []
                   if note and note.get('annotationLevel') in ('WARNING', 'FAILURE')]
        kept = [note for note in flagged if not ignored(name, note, expected)]
        # The owner's push rule: only a non-blocking leg's annotations count.
        counts = [note for note in kept if mode != 'push' or nonblocking(name, note)]
        listed = kept if status != 'success' else counts
        dropped = dropped or len(listed) < len(flagged)
        counted = counted or bool(counts)
        notes = [note.get('title') or note.get('message') or '' for note in listed]
        notes = list(dict.fromkeys(note for note in notes if note.strip()))[:5]
        if notes:
            warned.append(f'{code(name)}: ' + '; '.join(map(code, notes)))
    if status == 'success' and (failed or counted):
        status = 'warning'
    return Assessment(status, failed, warned, dropped)


def tested(nodes: 'Optional[list[dict[str, Any]]]', legs: 'Pattern[str]') -> 'bool':
    """Whether any of the jobs ``nodes`` that ``legs`` names ran; :data:`True` where they were not read."""
    if nodes is None:
        return True
    return any(legs.match(node.get('name') or '') and (node.get('conclusion') or '').lower() != 'skipped'
               for node in nodes)


def thread(stem: 'str', branch: 'str', mode: 'str') -> 'str':
    """The thread of ``stem``'s runs on ``branch`` in ``mode``: ``<stem>: <branch> push runs``."""
    branch = re.sub(r'[^A-Za-z0-9._/-]', '-', branch) or 'unknown'
    return f'{stem}: {branch} {"push" if mode == "push" else "scheduled"} runs'


def read_suite(suite: 'str') -> 'tuple[Optional[list[dict[str, Any]]], bool]':
    """The jobs of the check suite ``suite``, :data:`None` where they cannot be read, and whether more exist."""
    try:
        proc = subprocess.run(['gh', 'api', 'graphql', '-f', f'query={SUITE_QUERY}', '-f', f'id={suite}'],  # nosec
                              capture_output=True, text=True, check=False, timeout=TIMEOUT)
        if proc.returncode:
            raise ValueError(proc.stderr.strip() or proc.stdout.strip())
        runs = json.loads(proc.stdout)['data']['node']['checkRuns']
        return [node for node in runs['nodes'] if node], bool(runs['pageInfo']['hasNextPage'])
    except (OSError, subprocess.SubprocessError, ValueError, LookupError, TypeError) as error:
        _actions.annotate('warning', f"The run's jobs could not be read ({error}), so the report names none of them.",
                          title=TITLE)
        return None, False


def download(repo: 'str', run_id: 'str', directory: 'pathlib.Path') -> 'tuple[list[tuple[str, str]], str]':
    """Each ``(job, summary)`` the run ``run_id`` uploaded, and why none could be read, or ``''``."""
    if not re.fullmatch(r'\d+', run_id):
        return [], f'the run id {run_id!r} is not a number'
    try:
        proc = subprocess.run(['gh', 'run', 'download', run_id, '--repo', repo, '--pattern', ARTIFACT,  # nosec
                               '--dir', str(directory)],
                              capture_output=True, text=True, check=False, timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        return [], f'gh could not run: {error}'
    if proc.returncode:
        text = proc.stderr.strip() or proc.stdout.strip()
        # A run whose jobs wrote no summary uploaded no artifact it matches, which
        # gh reports as one of NOTHING's lines; anything else is an error.
        if any(line.strip() in NOTHING for line in text.splitlines()):
            return [], ''
        return [], (text.splitlines() or ['gh failed'])[-1]
    found = []
    # gh puts each artifact a pattern matches in a folder of its name; a lone
    # one unpacked into the directory itself is read there too.
    folders = [directory] + sorted(path for path in directory.iterdir() if path.is_dir() and not path.is_symlink())
    for folder in folders:
        page, name = folder / 'job-summary.md', folder / 'job-summary.name'
        if not page.is_file() or page.is_symlink():
            continue
        with open(page, encoding='utf-8', errors='replace') as file:
            text = file.read(MAX_SUMMARY)
        job = folder.name
        if name.is_file() and not name.is_symlink():
            with open(name, encoding='utf-8', errors='replace') as file:
                job = (file.read(1000).strip().splitlines() or [job])[0]
        if text.strip():
            found.append((job, text))
    return found, ''


def cut(text: 'str', room: 'int') -> 'str':
    """``text`` cut to at most ``room`` characters, at a line's end where one is near, any code fence closed."""
    if len(text) <= room:
        return text
    head = text[:max(room - 4, 0)]
    end = head.rfind('\n')
    if end > len(head) // 2:
        head = head[:end]
    if head.count('```') % 2:
        head += '\n```'
    return head


def fit(blocks: 'list[tuple[str, str]]', room: 'int', url: 'str') -> 'list[str]':
    """Each ``(job, summary)`` of ``blocks`` as a ``<details>`` block, in order, all within ``room`` characters.

    The room is shared out smallest first, so a short summary is whole and a long
    one gets what the others leave; a summary over its share is cut to it and
    says where the whole one is. One whose share cannot hold even that is left
    out, which :func:`render` says.

    """
    where = f'[the run]({url})' if RUN_PAGE.fullmatch(url) else "the run's page"
    note = f'\n\n*Trimmed to fit the comment; the whole summary is on {where}.*'
    shells = [(f'<details><summary><code>{html.escape(" ".join(job.split())[:200])}</code></summary>\n\n',
               '\n\n</details>') for job, _ in blocks]
    # A word joiner after each `@`, so no summary mentions anyone.
    texts = [MENTION.sub('@\u2060', text.strip()) for _, text in blocks]
    out = [''] * len(blocks)
    left = room
    order = sorted(range(len(blocks)), key=lambda index: len(texts[index]))
    for rank, index in enumerate(order):
        opening, closing = shells[index]
        # Each block costs its shell and the blank line :func:`render` joins it by.
        share = left // (len(order) - rank) - len(opening) - len(closing) - len(JOIN)
        text = texts[index]
        if len(text) > share:
            text = cut(text, share - len(note)) + note if share > 2 * len(note) else ''
        if text:
            out[index] = opening + text + closing
            left -= len(out[index]) + len(JOIN)
    return [block for block in out if block]


def render(workflow: 'str', mode: 'str', conclusion: 'str', sha: 'str', url: 'str', found: 'Assessment',
           nodes: 'Optional[list[dict[str, Any]]]', more: 'bool',
           summaries: 'list[tuple[str, str]]', missing: 'str') -> 'str':
    """The Markdown report of the run, its job summaries last."""
    run = f'The {workflow} run'
    if RUN_PAGE.fullmatch(url):
        run = f'[{workflow} run]({url})'
    commit = f' for `{sha[:9]}`' if SHA.fullmatch(sha) else ''
    kind = 'push' if mode == 'push' else 'scheduled'
    lines = [f'### {workflow} {kind} run', '', f'{run}{commit} concluded {code(conclusion or "unknown")}.']
    if found.failed:
        heading = 'Failed without failing the run' if conclusion == 'success' else 'Did not pass'
        lines += ['', f'**{heading}:**', '', *(f'- {item}' for item in found.failed)]
    if found.warned:
        lines += ['', '**Warned, in jobs that passed:**', '', *(f'- {item}' for item in found.warned)]
    if nodes is None:
        lines += ['', "The run's jobs could not be read, so none is named here."]
    elif more:
        lines += ['', 'Only the first 100 jobs were read.']
    elif not found.failed and not found.warned:
        lines += ['', 'Every job passed, with no warning that counts.' if found.dropped
                  else 'Every job passed, with no warning.']
    if missing:
        lines += ['', f'The job summaries could not be read: {code(missing)}.']
    head = '\n'.join(lines)
    if not summaries:
        return head
    order = {node.get('name'): index for index, node in enumerate(nodes or [])}
    summaries = sorted(summaries, key=lambda item: (order.get(item[0], len(order)), item[0]))
    intro = '\n\n**Job summaries:**\n\n'
    left_out = '\n\n*{} job summaries did not fit; the run holds them.*'
    blocks = fit(summaries, LIMIT - FOOTER - len(head) - len(intro) - len(left_out) - 10, url)
    text = head + (intro + JOIN.join(blocks) if blocks else '')
    if len(blocks) < len(summaries):
        text += left_out.format(len(summaries) - len(blocks))
    return text


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Write the report and the step outputs; the exit status, 0 unless the arguments are bad."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--report', required=True, type=pathlib.Path, help='the Markdown report to write')
    args = parser.parse_args(argv)

    env = os.environ
    name, event = env.get('WORKFLOW', ''), env.get('RUN_EVENT', '')
    conclusion, sha, url = env.get('RUN_CONCLUSION', ''), env.get('HEAD_SHA', ''), env.get('RUN_URL', '')
    mode = 'push' if event == 'push' else 'scheduled'
    status = CONCLUSIONS.get(conclusion, 'failure')
    workflow = WORKFLOWS.get(name)
    outputs = {'post': 'false', 'title': '', 'mode': mode, 'status': status}
    try:
        if workflow is None:
            _actions.annotate('warning', f'{name!r} is no workflow this script reports, so nothing is posted.',
                              title=TITLE)
            return 0
        if event not in ('push', 'schedule', 'workflow_dispatch'):
            print(f'A {event or "unknown"} run has no thread to post to; nothing is posted.', flush=True)
            return 0
        outputs['title'] = thread(workflow.stem, env.get('HEAD_BRANCH', ''), mode)
        nodes, more = read_suite(env.get('SUITE', ''))
        found = assess(nodes, conclusion, mode, workflow.expected)
        outputs['status'] = found.status
        if found.status in ('success', 'skipped') and not tested(nodes, workflow.legs):
            print(f'No leg of the {name} run ran, as when its commit was superseded or it changed no code, '
                  'so nothing is posted.', flush=True)
            return 0
        summaries, missing = [], ''  # type: list[tuple[str, str]], str
        base = env.get('RUNNER_TEMP') or None
        with tempfile.TemporaryDirectory(prefix='job-summaries-', dir=base) as directory:
            summaries, missing = download(env.get('GITHUB_REPOSITORY', ''), env.get('RUN_ID', ''),
                                          pathlib.Path(directory))
        if missing:
            _actions.annotate('warning', f'The job summaries could not be read: {missing}', title=TITLE)
        report = render(name, mode, conclusion, sha, url, found, nodes, more, summaries, missing)
        outputs['post'] = 'true'
    # Anything else is a bug here, which must not fail the run: post the conclusion alone.
    except Exception as error:  # pylint: disable=broad-except
        _actions.annotate('warning', f'{type(error).__name__}: {error}. The report holds the conclusion alone.',
                          title=TITLE)
        report = f'### {name} run, which concluded {code(conclusion or "unknown")}'
        outputs['post'] = 'true' if outputs['title'] else 'false'
    finally:
        for key, value in outputs.items():
            _actions.set_output(key, value, required=False)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report + '\n', encoding='utf-8')
    print(report, flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
