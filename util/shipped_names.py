# -*- coding: utf-8 -*-
"""The names a release shipped under :mod:`pcapkit.protocols`, as the fixture a removal guard reads (#2534).

``python3 util/shipped_names.py v1.5.1`` reads the tag's tree with ``git`` and
writes :file:`tests/project/shipped_names_fixtures/v1.5.1.json`, which
:class:`~tests.project.test_no_moved_name_re_exports_1744_unit.TestShippedNames`
reads. CI checks out no tags, so the file is checked in; the same command
writes it again byte for byte, and the file names the tag, its commit and this
command. For each module under :file:`pcapkit/protocols/` in the tag it lists:

``defined``
    The public names the module binds at module level: classes, functions and
    assigned names, outside ``if TYPE_CHECKING:``, including the TypedDicts
    bound only for Sphinx.
``exported``
    The names its ``__all__`` lists that it imports rather than defines, the
    re-exports an aggregating module carries.
``documented``
    The other names the tag's docs pages document at the module's path, a
    private one included.

A name documented with an ``auto`` directive or a ``data``, ``function``,
``class``, ``exception`` or ``decorator`` directive under a ``module``,
``currentmodule`` or ``automodule`` counts; the changelogs do not.

Standard library only, in Python 3.8's syntax.

"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
# git, with a fixed argument list and no shell.
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Optional

__all__ = ['git', 'defined', 'exported', 'module_name', 'documented', 'collect', 'render', 'main']

#: The repository root.
ROOT = pathlib.Path(__file__).resolve().parents[1]

#: The tree the fixture covers.
SCOPE = 'pcapkit/protocols'

#: A module-level object directive on a docs page, and its target.
DIRECTIVE = re.compile(r'^\.\. (?:auto(?:class|function|data|exception|decorator|module)'
                       r'|(?:py:)?(?:data|function|class|exception|decorator))::[ \t]+(?P<target>[\w.]+)',
                       re.M)

#: A ``module``, ``currentmodule`` or ``automodule`` directive: the module the next targets are in.
CONTEXT = re.compile(r'^\.\. (?:(?:py:)?(?:current)?module|automodule)::[ \t]+(?P<module>[\w.]+)', re.M)


def git(root: 'pathlib.Path', *args: 'str') -> 'str':
    """The output of ``git args`` run in ``root``; a failure raises."""
    return subprocess.run(['git', *args], cwd=root, check=True,  # nosec: B603 B607
                          stdout=subprocess.PIPE).stdout.decode('utf-8')


def _type_checking(test: 'ast.expr') -> 'bool':
    """Whether an ``if`` test is ``TYPE_CHECKING``, bare or as an attribute."""
    return (isinstance(test, ast.Name) and test.id == 'TYPE_CHECKING') \
        or (isinstance(test, ast.Attribute) and test.attr == 'TYPE_CHECKING')


def defined(body: 'list[ast.stmt]') -> 'list[str]':
    """The names ``body`` binds at its own level, outside ``if TYPE_CHECKING:``.

    A class, a function and a name assigned to count, also inside an ``if``,
    ``else`` or ``try`` block; a subscript or an attribute assigned to does not.

    """
    names = []  # type: list[str]
    for node in body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            todo = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
            while todo:
                target = todo.pop(0)
                if isinstance(target, ast.Name):
                    names.append(target.id)
                elif isinstance(target, (ast.Tuple, ast.List)):
                    todo.extend(target.elts)
        elif isinstance(node, ast.If):
            if not _type_checking(node.test):
                names.extend(defined(node.body))
            names.extend(defined(node.orelse))
        elif isinstance(node, ast.Try):
            names.extend(defined(node.body))
            for handler in node.handlers:
                names.extend(defined(handler.body))
            names.extend(defined(node.orelse))
            names.extend(defined(node.finalbody))
    return names


def exported(tree: 'ast.Module') -> 'list[str]':
    """The names a module's ``__all__`` lists, if it assigns one literal list."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '__all__'
                                                for target in node.targets):
            return [str(name) for name in ast.literal_eval(node.value)]
    return []


def module_name(path: 'str') -> 'str':
    """The dotted module a source path under :file:`pcapkit/` is."""
    parts = path[:-len('.py')].split('/')
    if parts[-1] == '__init__':
        parts.pop()
    return '.'.join(parts)


def documented(text: 'str', modules: 'set[str]') -> 'dict[str, set[str]]':
    """The module-level names a docs page documents, as ``{module: names}``, for ``modules`` alone.

    A target with no dots is in the module the last ``module`` or
    ``currentmodule`` directive above it set; a dotted one is split after the
    longest prefix that is one of ``modules``.

    """
    found = {}  # type: dict[str, set[str]]
    marks = sorted([(m.start(), 'context', m.group('module')) for m in CONTEXT.finditer(text)]
                   + [(m.start(), 'target', m.group('target')) for m in DIRECTIVE.finditer(text)])
    current = None  # type: Optional[str]
    for _, kind, value in marks:
        if kind == 'context':
            current = value
            continue
        if not value.startswith('pcapkit.'):
            if current is None:
                continue
            value = f'{current}.{value}'
        parts = value.split('.')
        for end in range(len(parts), 1, -1):
            module = '.'.join(parts[:end])
            if module in modules:
                if end < len(parts):
                    found.setdefault(module, set()).add(parts[end])
                break
    return found


def collect(root: 'pathlib.Path', tag: 'str') -> 'dict[str, Any]':
    """The fixture for ``tag``: its provenance, and each module's names."""
    files = [path for path in git(root, 'ls-tree', '-r', '--name-only', tag, '--', SCOPE).split()
             if path.endswith('.py')]
    modules = {}  # type: dict[str, dict[str, list[str]]]
    for path in files:
        tree = ast.parse(git(root, 'show', f'{tag}:{path}'), filename=path)
        own = set(defined(tree.body))
        modules[module_name(path)] = {
            'defined': sorted(name for name in own if not name.startswith('_')),
            'exported': sorted(set(exported(tree)) - own),
            'documented': [],
        }
    pages = [path for path in git(root, 'ls-tree', '-r', '--name-only', tag, '--', 'docs/source').split()
             if path.endswith('.rst') and '/changelog/' not in path]
    for page in pages:
        for module, names in documented(git(root, 'show', f'{tag}:{page}'), set(modules)).items():
            entry = modules[module]
            entry['documented'] = sorted(set(entry['documented'])
                                         | (names - set(entry['defined']) - set(entry['exported'])))
    return {
        'tag': tag,
        'commit': git(root, 'rev-parse', f'{tag}^{{commit}}').strip(),
        'generator': f'python3 util/shipped_names.py {tag}',
        'scope': SCOPE,
        'modules': modules,
    }


def render(fixture: 'dict[str, Any]') -> 'str':
    """The fixture as the file holds it: sorted keys, one name a line."""
    return json.dumps(fixture, indent=1, sort_keys=True) + '\n'


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Write the fixture for the tag ``argv`` names; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('tag', help='the release tag to read, such as v1.5.1')
    args = parser.parse_args(argv)
    out = ROOT / 'tests' / 'project' / 'shipped_names_fixtures' / f'{args.tag}.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(collect(ROOT, args.tag)), encoding='utf-8')
    print(out.relative_to(ROOT), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
