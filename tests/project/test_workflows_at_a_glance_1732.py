# -*- coding: utf-8 -*-
"""The workflows page's count, "At a Glance" table and graph, against the files.

:file:`docs/source/contributing/workflows.rst` opens by counting the workflows under
:file:`.github/workflows/`, tabulates each one's triggers, and draws them as a
graph. #1732 added :file:`experimental.yml` and left all three describing twelve,
so each is checked here against the ``on:`` block of every file: the count, one
table row per file with its name and triggers, and one graph node per file with
an edge for each ``push``, ``pull_request`` and ``workflow_run`` trigger.

"""

from __future__ import annotations

import pathlib
import re
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'
DOC = ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst'

NUMBERS = {'ten': 10, 'eleven': 11, 'twelve': 12, 'thirteen': 13, 'fourteen': 14,
           'fifteen': 15, 'sixteen': 16}
DAYS = {'0': 'Sun', '1': 'Mon', '2': 'Tue', '3': 'Wed', '4': 'Thu', '5': 'Fri', '6': 'Sat',
        '*': 'daily'}
#: Events the table gives a column of their own; the rest go under "other".
COLUMNS = ('push', 'pull_request', 'schedule', 'workflow_run')


def triggers(text: 'str') -> 'dict[str, str]':
    """Each event of a workflow's ``on:`` block, with the text under it."""
    block = re.search(r'(?ms)^on:\s*\n(.*?)(?=^\S)', text)
    assert block is not None, 'no on: block'
    lines = [line for line in block.group(1).splitlines() if not line.lstrip().startswith('#')]
    events = {}  # type: dict[str, str]
    current = None  # type: Optional[str]
    for line in lines:
        key = re.match(r'^  ([\w-]+):', line)
        if key:
            current = key.group(1)
            events[current] = ''
        elif current is not None:
            events[current] += line + '\n'
    return events


def workflow_name(text: 'str') -> 'str':
    """A workflow's top-level ``name:``, unquoted."""
    name = re.search(r'(?m)^name:\s*(.+?)\s*$', text)
    assert name is not None, 'no name:'
    return name.group(1).strip('"')


def expected_row(path: 'pathlib.Path', text: 'str') -> 'list[Any]':
    """The seven cells the table should give this workflow file; "other" as a list."""
    events = triggers(text)

    def branches(event: 'str') -> 'str':
        if event not in events:
            return '--'
        body = events[event]
        if re.search(r'(?m)^    tags:', body):
            return 'tags ' + ', '.join(f'``{tag}``' for tag in re.findall(r"- '([^']+)'", body))
        found = re.search(r'branches:\s*\[([^\]]*)\]', body)
        assert found is not None, f'{event} has neither branches nor tags'
        return ', '.join(f'``{item.strip()}``' for item in found.group(1).split(','))

    if 'schedule' in events:
        cron = re.search(r"cron:\s*'(\d+) (\d+) \* \* ([\d*])'", events['schedule'])
        assert cron is not None, 'a schedule this test cannot read'
        schedule = f'{DAYS[cron.group(3)]} {int(cron.group(2)):02d}:{int(cron.group(1)):02d}'
    else:
        schedule = '--'
    if 'workflow_run' in events:
        sources = re.search(r'workflows:\s*\[([^\]]*)\]', events['workflow_run'])
        assert sources is not None
        upstream = ', '.join(f'**{item.strip().strip(chr(34))}**' for item in sources.group(1).split(','))
    else:
        upstream = '--'
    other = sorted(event for event in events if event not in COLUMNS)
    return [workflow_name(text), f':file:`{path.name}`', branches('push'),
            branches('pull_request'), schedule, upstream, other or ['--']]


def table_rows(page: 'str') -> 'list[list[str]]':
    """The "At a Glance" list-table's body rows, cell by cell."""
    section = page.split('At a Glance\n-----------\n', 1)[1].split('\n.. note::', 1)[0]
    rows = []  # type: list[list[str]]
    for line in section.splitlines():
        cell = re.match(r'^   (\*| ) - (.*)$', line)
        if cell is None:
            continue
        if cell.group(1) == '*':
            rows.append([])
        rows[-1].append(cell.group(2).strip())
    return rows[1:]


def graph(page: 'str') -> 'tuple[dict[str, str], set[str]]':
    """The mermaid graph's workflow nodes, by file, and its edges."""
    section = page.split('.. mermaid::', 1)[1].split('\nThe double relationship', 1)[0]
    nodes = {match.group(3): match.group(1)
             for match in re.finditer(r'(?m)^ +(\w+)\["([^"<]+)<br/>([\w.-]+\.yml)"\]$', section)}
    edges = {' '.join(line.split()) for line in section.splitlines() if '-->' in line or '==>' in line}
    return nodes, edges


def problems(page: 'str', files: 'dict[pathlib.Path, str]') -> 'list[str]':
    """Every way the page disagrees with the workflow files."""
    found = []  # type: list[str]
    count = re.search(r'The (\w+) workflows under :file:`\.github/workflows/`', ' '.join(page.split()))
    if count is None or NUMBERS.get(count.group(1)) != len(files):
        found.append(f'the note counts {count and count.group(1)!r} workflows; there are {len(files)}')

    rows = {row[1]: row for row in table_rows(page)}
    nodes, edges = graph(page)
    by_name = {workflow_name(text): nodes.get(path.name) for path, text in files.items()}
    for path, text in sorted(files.items()):
        want = expected_row(path, text)
        key = f':file:`{path.name}`'
        row = rows.pop(key, None)
        if row is None:
            found.append(f'no table row for {path.name}')
        else:
            other = sorted(re.findall(r'``(\w+)``', row[6])) or ['--']
            if row[:6] != want[:6] or other != want[6]:
                found.append(f'{path.name}: the row reads {row}, the file gives {want}')
        node = nodes.pop(path.name, None)
        if node is None:
            found.append(f'no graph node for {path.name}')
            continue
        events = triggers(text)
        wanted = set()
        if 'push' in events:
            wanted.add(f'{"TAG" if "tags:" in events["push"] else "PUSH"} --> {node}')
        if 'pull_request' in events:
            wanted.add(f'PR --> {node}')
        for upstream in re.findall(r'"([^"]+)"', events.get('workflow_run', '')):
            wanted.add(f'{by_name.get(upstream.strip())} ==>|workflow_run: completed| {node}')
        for edge in sorted(wanted - edges):
            found.append(f'{path.name}: no graph edge {edge!r}')
    found += [f'a table row for {key}, which is no file' for key in rows]
    found += [f'a graph node for {name}, which is no file' for name in nodes]
    return found


FILES = {path: path.read_text(encoding='utf-8') for path in sorted(WORKFLOWS.glob('*.yml'))}


class TestTheWorkflowsPage(unittest.TestCase):

    def test_the_page_describes_every_workflow_file(self) -> None:
        self.assertEqual(problems(DOC.read_text(encoding='utf-8'), FILES), [])

    def test_a_missing_row_is_caught(self) -> None:
        """The check bites: drop experimental.yml's row, node and count, and it fails."""
        page = DOC.read_text(encoding='utf-8')
        row = re.search(r'(?m)^   \* - Experimental Tests\n(?:     - .*\n)+', page)
        self.assertIsNotNone(row)
        assert row is not None
        found = problems(page.replace(row.group(0), ''), FILES)
        self.assertEqual(found, ['no table row for experimental.yml'])
        found = problems(page.replace('The thirteen workflows', 'The twelve workflows'), FILES)
        self.assertEqual(found, ["the note counts 'twelve' workflows; there are 13"])


if __name__ == '__main__':
    unittest.main()
