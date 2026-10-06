# -*- coding: utf-8 -*-
"""Tests that nothing in :file:`.github/workflows/create-release.yml` publishes ungated.

#641: the ``pypi`` job's ``environment: release`` was commented out while the
``id-token: write`` from the same upstream snippet had been re-added live below it,
and the ``conda`` job never had an ``environment:`` at all. A scheduled vendor crawl
that bumps the version is enough to enter that workflow, so both package indexes
were reachable with no human in the path.

What makes that worth a test rather than just a fix is how quietly it came about.
Nothing about a missing ``environment:`` line fails, warns, or shows up in a run's
output -- the job simply runs -- and the line that was missing sat inside a
commented block that read as though it had been disabled deliberately and as a
unit. So the regression is invisible by construction, and the only thing that can
notice it is an assertion over the file.

The rule asserted here is not a copy of the current file: **any job in that
workflow which runs a publishing action or pushes to git must declare an
``environment:``.** Stated that way it also catches a *new* publishing job added
later without a gate, and a job renamed or reordered.

Be clear about how far that generalises, though, because it is easy to overstate.
:data:`PUBLISHING_MARKERS` is what decides "publishing", and it is a finite,
hand-maintained list of four substrings. So the rule generalises across job
*identity* and not across publishing *mechanism*: a job uploading by some route
none of those four names -- ``twine upload``, ``gh release upload``, a fork of a
pinned action under another name, a ``curl`` straight at an index -- matches no
marker, and would pass this test while genuinely ungated.
:class:`TestMarkersStillMatch` only keeps the existing four from going blind; it
cannot invent a fifth. Adding a publishing route to this workflow therefore means
adding its marker here, and that is a maintenance obligation rather than something
the test enforces.

Two things this deliberately does **not** test, because it cannot:

* **Whether the environments exist, and whether they have required reviewers.**
  That is repository settings, not repository content, and an ``environment:``
  naming an environment that does not exist is created implicitly with no
  protection rules -- so the workflow half passing here is necessary and not
  sufficient. The check needs an authenticated ``GET
  /repos/{owner}/{repo}/environments``, which a unit-tier test may not make: the
  tier runs on a fresh clone with no network and no token. It is written down in
  the workflow's own comment and in #641 instead.
* **Whether GitHub requests one approval per environment or one per matrix leg.**
  ``pypi`` is a 7-leg matrix and ``conda`` a 10-leg one. That is a property of
  the Actions runner, observable only from a real run -- and now moot for both,
  since #887 removed their required reviewers. The question would resurface
  only if a matrix job were gated by its own environment again.

:mod:`yaml` is not in the ``test`` extra, so the scanner in this module is
hand-rolled and dependency-free, and :class:`TestYAMLAgreesWithTheScanner` checks
it against :func:`yaml.safe_load` only when PyYAML happens to be installed. The
same split as ``test_the_rewritten_date_is_a_string_and_not_a_yaml_date`` in
:file:`tests/project/test_bump_version.py`: the assertion that must run everywhere
does not need the dependency, and the one that needs it guards the substitute.

#888: every job past ``version_check`` used to share one guard -- "the ``v*``
tag exists" -- as a proxy for "this version was already published", which
diverges exactly when a release half-completes and made every downstream job
skip silently while the run reported green. :class:`TestEvidenceBasedGating`
below asserts the fix: ``tag``, ``pypi`` and ``conda`` each read their own
evidence instead of that shared tag, and -- the part that is easy to get
subtly wrong -- their ``if:`` conditions bypass GitHub's default status check
explicitly (``!cancelled()``) rather than relying on evidence alone, because a
job whose ``needs:`` includes a legitimately-skipped predecessor is skipped
before its own ``if:`` is even evaluated otherwise. :func:`declared_if` is
what makes an ``if:`` condition -- including the multi-line, folded-scalar
form this fix introduces -- checkable the same coarse, textual way the rest of
this module already checks ``environment:`` and ``needs:``.

A cross-review of the #888 change (PR #905) found two defects that every test
above -- being a string assertion over the YAML -- was structurally unable to
catch, because none of them executed anything the workflow itself executes:

* **``release_status``'s branch logic demanded uniformity across all four
  release jobs**, reading a self-heal -- ``github``/``tag`` legitimately
  skipping because their artefacts already exist, ``pypi``/``conda`` running
  and succeeding because theirs did not -- as the stranded-partial shape #888
  is about, and erroring on the very run that fixed it.
  :class:`TestReleaseStatusScriptExecutesCorrectly` actually runs the
  extracted shell script, over a table of the shapes a real run can take,
  and checks which branch each one takes -- the uniformity bug fails exactly
  the self-heal row.
* **The ``python3 -c`` snippets computing PyPI/Anaconda evidence had their
  source indented**, which only ``compile()``s on Python 3.14 -- every
  interpreter from 3.9 through 3.13 raises ``IndentationError: unexpected
  indent`` on the leading whitespace the surrounding YAML block scalar's own
  indentation forces onto it, measured directly against each one. Two of the
  three snippets run before ``actions/setup-python`` even installs a chosen
  version, so ``python3`` there is whatever the runner image ships by
  default -- 3.12 on ``ubuntu-latest`` as of writing, never 3.14.
  :class:`TestPythonSnippetsSurviveOlderInterpreters` extracts each snippet
  and actually runs it under an interpreter older than 3.14 when one can be
  found on ``PATH``, skipping otherwise -- ``compile()`` under whatever
  interpreter happens to be running this test suite proves nothing when that
  interpreter is 3.14 itself, which is exactly how both defects shipped
  despite every earlier test in this module passing.

#962: the same argument, one layer up, now against the ``if:`` expressions
themselves. Four review rounds on #961 produced twenty mutations of a single
clause, and each strengthening of the text assertions was defeated by one the
previous round had not anticipated -- because vocabulary is not structure and
structure is not meaning. :class:`TestGateExpressionsEvaluateCorrectly`
**evaluates** each gate instead, over a table of the scenarios a real run can
be in, so a mutation is caught when it changes the gate's truth table however
it is spelled: reversed operands, ``contains(fromJSON(...))``, a ``!=``
negation, a ``true ||`` prefix and a one-character ``&&``-to-``||`` slip all
land in the same place.

The text assertions **stay** rather than being replaced, settled on #962
itself. They cost nothing, they fail with a message naming the clause rather
than naming a scenario row, and an evaluator bug would otherwise leave the
gates unpinned entirely -- which is #962's own failure mode reintroduced one
layer down. The two layers also catch genuinely different things, and
:class:`TestGateMutationsChangeTheTruthTable` records which layer rejects
which mutation instead of leaving that to be assumed: a ``true ||`` prefix is
invisible to the text layer and obvious to the evaluator, while reversed
operands are the exact opposite -- they do not change the truth table at all,
so only the text layer has anything to say about them.

#967: a truth table is only as discriminating as its rows, and #962's could not
tell ``<evidence> == 'false'`` from ``<evidence> != 'true'``. Every row held the
evidence outputs at a literal ``'true'`` or ``'false'``, where the two spellings
agree, and the text layer never looks at *which* comparison is made against an
output at all -- so the edit was invisible to both layers at once. They diverge
only on an output that is neither, and for a publishing job that is the
dangerous direction: ``!= 'true'`` runs where ``== 'false'`` skips, so evidence
nothing established becomes a publish attempt. :func:`gate_rows` therefore
carries one row per gated job holding that job's own evidence at ``null``, which
is the only row in the table that mutation fails.

:func:`evaluate_condition` implements the subset this workflow uses and
nothing more: ``!``, ``&&``, ``||``, parentheses, ``==``/``!=`` against
single-quoted literals, ``startsWith``, ``contains``, ``fromJSON``, the
status-check functions, and ``needs.<job>.result`` /
``needs.<job>.outputs.<NAME>`` / ``github.*`` lookups. ``contains``,
``fromJSON`` and ``always()`` appear in no gate on the tree -- they are
implemented because the mutation table needs them *evaluated* rather than
rejected, since a parse error would otherwise look like a caught mutation
while proving nothing about the truth table. Anything outside the subset
raises :exc:`UnsupportedExpression`, and
``test_every_declared_if_is_evaluable`` is what makes the file growing past
that subset a loud failure rather than a silent gap.

Two things the evaluator deliberately does **not** model, both of them runner
behaviour rather than expression semantics:

* **The implicit ``success()``** Actions prepends to an ``if:`` that calls no
  status-check function itself. It applies to ``github``, which is why
  ``test_github_runs_when_its_own_v_tag_is_missing`` evaluates the *declared*
  condition and says so; it does not apply to ``tag``/``pypi``/``conda``,
  which all open with ``!cancelled()``, so for those three the declared
  condition is the whole gate.
* **The cascade-skip** that skips a job whose ``needs:`` included a skipped
  job before that job's own ``if:`` is evaluated at all. Escaping it is what
  ``!cancelled()`` is *for*, and
  ``test_evidence_gated_jobs_survive_a_legitimately_skipped_predecessor``
  pins it textually above, because nothing runnable here can observe it.

"""

from __future__ import annotations

import itertools
import json
import pathlib
import re
import shutil
import subprocess
import sys
import unittest
from typing import TYPE_CHECKING

from tests._support import scale_timeout

if TYPE_CHECKING:
    from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The workflow under test. The only one that publishes: :file:`cron-conda.yml`
#: and :file:`cron-vendor.yml` build and commit but upload nothing, and
#: :file:`deploy-pages.yml` publishes documentation rather than a package, which is
#: a separate question from #641 and is not gated here.
WORKFLOW = ROOT / '.github' / 'workflows' / 'create-release.yml'

#: Strings whose presence in a job means that job has an effect outside the run,
#: each mapped to what it does, so a failure can say *why* the job needed a gate.
#:
#: Matched as substrings of the job's source with comments stripped, which is
#: coarse on purpose -- an action pinned to a different version, or reached through
#: a different input, still matches. ``git push`` is here because the ``tag`` job's
#: write to ``main`` does not go through an action at all, and its ``permissions:
#: {}`` makes the job look inert while the deploy key it loads does the writing.
#:
#: **Extend this when a new publishing route is added to the workflow.** Being an
#: allowlist, it is silent about a mechanism it does not name -- see the limitation
#: spelled out in this module's docstring.
PUBLISHING_MARKERS = {
    'pypa/gh-action-pypi-publish': 'uploads a distribution to PyPI or TestPyPI',
    'anaconda/actions/upload-package': 'uploads a package to anaconda.org',
    'softprops/action-gh-release': 'creates a public GitHub Release, and the tag it names',
    'git push': 'pushes a commit or a tag to the repository',
}

#: A top-level job header, i.e. a mapping key at two spaces of indent.
_JOB_HEADER = re.compile(r'^ {2}([A-Za-z_][A-Za-z0-9_-]*):[ \t]*(?:#.*)?$')
#: A job-level ``environment:`` key, i.e. at four spaces of indent. A commented
#: ``#environment:`` cannot match this, which is the whole point -- that is the
#: exact shape #641 was.
_ENVIRONMENT = re.compile(r'^ {4}environment:[ \t]*(.*)$')
#: The ``name:`` of an ``environment:`` written in its mapping form.
_ENVIRONMENT_NAME = re.compile(r'^ {6}name:[ \t]*(\S+)')
#: A job-level ``needs:`` key written as a single-line inline list, i.e.
#: ``needs: [ a, b ]``. The only form this workflow uses -- confirmed by
#: :class:`TestYAMLAgreesWithTheScanner` -- so, like :data:`PUBLISHING_MARKERS`,
#: extending it to the multi-line ``needs:\n  - a`` form is a maintenance
#: obligation for whoever adds one, not something this scan infers.
_NEEDS = re.compile(r'^ {4}needs:[ \t]*\[([^\]]*)\][ \t]*(?:#.*)?$')
#: A job-level ``if:`` key, either inline (``if: ${{ ... }}``) or opening a
#: folded block scalar (``if: >-``, continued below at six spaces). #888
#: introduced the second form, since ``tag``/``pypi``/``conda``'s conditions
#: grew past one comfortable line; :func:`declared_if` handles both.
_IF = re.compile(r'^ {4}if:[ \t]*(.*)$')


def strip_comments(text: 'str') -> 'str':
    """``text`` with YAML comments removed, for substring matching only.

    Naive -- it would also cut a ``#`` inside a scalar -- and that is acceptable
    here because the result is never parsed, only searched for the literals in
    :data:`PUBLISHING_MARKERS`. Doing it at all matters: without it, a comment
    *explaining* why a job is gated would count as evidence that it publishes.

    """
    return '\n'.join(re.sub(r'(?:(?<=\s)|^)#.*$', '', line) for line in text.splitlines())


def job_blocks(text: 'str') -> 'dict[str, str]':
    """``{job name: the job's own lines}`` for a workflow's top-level ``jobs:``.

    Indentation-based rather than a YAML parse, so that this module keeps working
    on a fresh clone where PyYAML is not installed.
    :class:`TestYAMLAgreesWithTheScanner` is what stops the two from drifting.

    """
    lines = text.splitlines()

    try:
        start = next(i for i, line in enumerate(lines) if line.rstrip() == 'jobs:')
    except StopIteration:
        raise AssertionError(f'no top-level `jobs:` mapping found in {WORKFLOW}') from None

    blocks = {}  # type: dict[str, list[str]]
    current = None  # type: Optional[str]
    for line in lines[start + 1:]:
        stripped = line.strip()
        # A blank line or a comment belongs to whatever block is open; neither
        # carries indentation that can be trusted to end one.
        if stripped and not stripped.startswith('#') and not line.startswith('  '):
            break  # dedented back to a top-level key, so `jobs:` is over

        header = _JOB_HEADER.match(line)
        if header is not None:
            current = header.group(1)
            blocks[current] = []
            continue
        if current is not None:
            blocks[current].append(line)

    return {name: '\n'.join(body) for name, body in blocks.items()}


def declared_environment(block: 'str') -> 'Optional[str]':
    """The environment a job block declares, or :data:`None` for an ungated job.

    Handles both spellings: ``environment: pypi`` and the mapping form that
    carries a ``url:`` alongside its ``name:``.

    """
    lines = block.splitlines()
    for index, line in enumerate(lines):
        match = _ENVIRONMENT.match(line)
        if match is None:
            continue

        inline = match.group(1).split('#')[0].strip()
        if inline:
            return inline.strip('\'"')

        for nested in lines[index + 1:]:
            name = _ENVIRONMENT_NAME.match(nested)
            if name is not None:
                return name.group(1).strip('\'"')
            if nested.strip() and not nested.startswith(' ' * 6):
                break
        raise AssertionError(f'`environment:` declared with no name:\n{line!r}')
    return None


def declared_needs(block: 'str') -> 'list[str]':
    """The job names in this job's ``needs: [ ... ]`` list, empty if it has none.

    ``version_check`` has no ``needs:`` at all and correctly returns ``[]``
    rather than raising, since it is the root of the graph this module walks --
    since #1052, when it moved ahead of ``unit-tests``.

    """
    for line in block.splitlines():
        match = _NEEDS.match(line)
        if match is not None:
            return [name.strip() for name in match.group(1).split(',') if name.strip()]
    return []


def declared_if(block: 'str') -> 'str':
    """The job's own ``if:`` condition, flattened to one line; ``''`` if it has none.

    Handles both the single-line ``if: ${{ ... }}`` form used elsewhere in this
    file and the folded block-scalar form (``if: >-``, continued below at six
    spaces) #888 introduces for ``tag``, ``pypi`` and ``conda``, whose
    conditions grew past one line. Folding is exactly what YAML itself does to
    a ``>``/``>-`` scalar -- join each continuation line with a single space --
    so flattening it the same way here reproduces a real parse rather than
    approximating one; :class:`TestYAMLAgreesWithTheScanner` is what checks
    that claim against :func:`yaml.safe_load` when it is installed.

    """
    lines = block.splitlines()
    for index, line in enumerate(lines):
        match = _IF.match(line)
        if match is None:
            continue

        inline = match.group(1).split('#')[0].strip()
        if inline and inline not in ('>', '>-', '|', '|-'):
            return inline

        parts = []
        for nested in lines[index + 1:]:
            if nested.strip() and not nested.startswith(' ' * 6):
                break
            if nested.strip():
                parts.append(nested.strip())
        return ' '.join(parts)
    return ''


def needs_closure(jobs: 'dict[str, str]', name: str) -> 'set[str]':
    """Every job ``name`` depends on, directly or transitively.

    A plain graph walk over :func:`declared_needs`, not a topological sort --
    nothing here needs an order, only membership. A dependency that is not a
    key of ``jobs`` (there is none in this workflow, but a rename could produce
    one) is walked as if it declared no ``needs:`` of its own, rather than
    raising, so a scanner bug surfaces as a missing closure member instead of
    an exception unrelated to what the caller is checking.

    """
    seen = set()  # type: set[str]
    stack = list(declared_needs(jobs[name]))
    while stack:
        dep = stack.pop()
        if dep in seen:
            continue
        seen.add(dep)
        stack.extend(declared_needs(jobs.get(dep, '')))
    return seen


def publishing_reasons(block: 'str') -> 'list[str]':
    """Why this job has an effect outside the run, empty when it has none."""
    body = strip_comments(block)
    return [reason for marker, reason in sorted(PUBLISHING_MARKERS.items()) if marker in body]


#: A job-level ``run:`` key opening a literal block scalar (``run: |``), at
#: whatever indent the step it belongs to happens to sit -- unlike
#: :data:`_ENVIRONMENT`/:data:`_NEEDS`/:data:`_IF`, this one is not pinned to
#: a fixed column, since a step's ``run:`` is one level deeper than a job's
#: own keys and this module has no reason to otherwise care how deep.
_RUN_LITERAL = re.compile(r'^(\s*)run:\s*\|\s*$')


def block_scalar_after(block: 'str', key: 're.Pattern[str]') -> 'str':
    """The dedented body of the literal block scalar (``|``) opened by the
    first line in ``block`` matching ``key``.

    Only used for :data:`_RUN_LITERAL` against ``release_status``, which has
    exactly one step and therefore exactly one ``run:`` -- ambiguous for a
    job with more than one, which is why this is not the general-purpose
    ``run:`` extractor the rest of this module reaches for. Dedents by the
    body's *own* first line, the same rule a real YAML literal block scalar
    follows, rather than assuming a fixed indent.

    """
    lines = block.splitlines()
    for index, line in enumerate(lines):
        if key.match(line) is None:
            continue

        base_indent = None  # type: Optional[int]
        body = []
        for nested in lines[index + 1:]:
            if not nested.strip():
                body.append('')
                continue
            indent = len(nested) - len(nested.lstrip(' '))
            if base_indent is None:
                base_indent = indent
            if indent < base_indent:
                break
            body.append(nested[base_indent:])
        return '\n'.join(body)
    raise AssertionError(f'no line in the block matches {key.pattern!r}')


#: A ``printf '%s\n' "line" "line" ... | python3 -`` snippet, #905's fix for
#: feeding Python source through a `python3 -c "..."` argument whose
#: indentation only ``compile()``s on 3.14 -- see this module's docstring.
#: Matches the exact shape :func:`printf_python_snippets` was written
#: against; a differently-formatted equivalent (different quoting, `printf`
#: on one line, ...) would need this pattern extended, same maintenance
#: obligation as :data:`PUBLISHING_MARKERS`.
_PRINTF_PYTHON_SNIPPET = re.compile(
    r"printf '%s\\n' \\\n"
    r"(?P<lines>(?:[ \t]*\"[^\"\n]*\"[ \t]*\\\n)+)"
    r"[ \t]*\|[ \t]*python3 -",
)
_PRINTF_LINE = re.compile(r'"([^"\n]*)"')


def printf_python_snippets(text: 'str') -> 'list[str]':
    """Every :data:`_PRINTF_PYTHON_SNIPPET` in ``text``, reconstructed as the
    Python source ``python3 -`` actually receives on stdin -- each snippet's
    lines joined with ``\\n``, carrying none of the YAML block scalar's own
    indentation, since that indentation is exactly what this scan is for:
    confirming it never reaches the Python source itself.

    """
    snippets = []
    for match in _PRINTF_PYTHON_SNIPPET.finditer(text):
        lines = _PRINTF_LINE.findall(match.group('lines'))
        snippets.append('\n'.join(lines))
    return snippets


def pre_314_interpreter() -> 'Optional[str]':
    """A Python executable older than 3.14, or :data:`None` if none is found.

    Only 3.14 tolerates the leading-whitespace-on-``-c``-source hazard
    :class:`TestPythonSnippetsSurviveOlderInterpreters` exists to catch --
    measured directly against 3.9 through 3.14, see this module's docstring.
    :data:`sys.executable` is exactly that hazard's blind spot whenever *this*
    test suite happens to be running under 3.14 itself, which is why this
    looks for another interpreter on ``PATH`` rather than trusting its own.

    """
    if sys.version_info < (3, 14):
        return sys.executable
    for minor in (13, 12, 11, 10, 9):
        candidate = shutil.which(f'python3.{minor}')
        if candidate:
            return candidate
    return None


class UnsupportedExpression(Exception):
    """Expression syntax :func:`evaluate_condition` does not implement.

    #962 asks for an evaluator over the subset the gates in this workflow
    actually use, and explicitly not for a GitHub Actions expression
    implementation. The two agree only while the file stays inside that
    subset, so leaving it has to be loud: a condition this module cannot parse
    is a condition it is not checking, and quietly treating one as true or as
    false would leave the gates unpinned while the suite still reported green
    -- which is #962's own failure mode, reintroduced one layer down.

    """


class _Null:
    """GitHub Actions' ``null``, which an unset context property evaluates to.

    Kept distinct from :data:`None` so that a scenario row holding ``None`` by
    mistake cannot be read as a deliberate unset, and so a failure message
    spells the value the way Actions does.

    """

    __slots__ = ()

    def __repr__(self) -> 'str':
        return 'null'


#: Actions' ``null``, compared by identity. An unset context property is this
#: rather than ``''``: ``null == 'false'`` is false, which is what makes a
#: *skipped* ``version_check`` -- a job that published no outputs at all --
#: stop the gates below it rather than being read as "evidence says incomplete".
NULL = _Null()

#: The key under which an evaluation context carries the status-check
#: functions' answers. Spelled with parentheses so no lookup can reach it:
#: :data:`_EXPR_TOKEN` cannot produce ``status()`` as a name, so this cannot
#: collide with a real Actions context root however the workflow grows.
STATUS = 'status()'

#: One token of the expression subset. ``!=`` precedes ``!`` because a regex
#: alternation is ordered and ``!`` would otherwise swallow the ``!`` of
#: ``!=``, turning ``a != b`` into a negation followed by a stray ``=``.
#: Property paths are tokenised whole, dots and hyphens included, since
#: ``needs.unit-tests.result`` is one lookup and not an arithmetic expression.
_EXPR_TOKEN = re.compile(
    r"""  (?P<space>\s+)
        | (?P<op>&&|\|\||==|!=|\(|\)|,|!)
        | (?P<string>'(?:[^']|'')*')
        | (?P<name>[A-Za-z_][A-Za-z0-9_.-]*)
    """,
    re.VERBOSE,
)

#: A whole-value interpolation, which is the only form any ``if:`` in this
#: workflow uses. Actions also accepts a bare expression for ``if:``, which
#: :func:`parse_condition` allows; what it does not allow is a *template* --
#: two interpolations, or text around one -- since concatenating a condition
#: out of fragments is outside the subset and must not be guessed at.
_INTERPOLATION = re.compile(r'^\$\{\{(?P<body>.*)\}\}$', re.DOTALL)

#: ``{name: argument count}`` for the functions evaluated here, matched
#: case-insensitively the way Actions matches them. ``success`` and ``failure``
#: are parsed but have no answer without a scenario that says what they
#: return, so :func:`_call` raises for them rather than guessing -- no gate in
#: this workflow calls either, and a fabricated answer would quietly decide a
#: row that nothing had actually modelled.
_FUNCTIONS = {
    'always': 0,
    'cancelled': 0,
    'success': 0,
    'failure': 0,
    'startswith': 2,
    'contains': 2,
    'fromjson': 1,
}


def _tokenize(body: 'str') -> 'list[tuple[str, str]]':
    """``[(kind, text)]`` for ``body``, with whitespace dropped.

    Raises at the first character no token matches rather than skipping it: a
    dropped character silently turns the expression under test into a
    different expression, which is the one outcome this module must not have.

    """
    tokens = []  # type: list[tuple[str, str]]
    position = 0
    while position < len(body):
        match = _EXPR_TOKEN.match(body, position)
        if match is None:
            raise UnsupportedExpression(
                f'cannot tokenise {body[position:position + 24]!r} at offset {position} '
                f'of {body!r}; see this module\'s docstring for the subset implemented'
            )
        position = match.end()
        if match.lastgroup != 'space':
            tokens.append((str(match.lastgroup), match.group()))
    return tokens


class _Parser:
    """Recursive-descent parser for the subset, producing a tuple tree.

    A tree rather than evaluating as it goes, for two reasons. One parse then
    serves every row of a scenario table, which is most of what the table
    costs. And ``&&``/``||`` can short-circuit *evaluation* without also
    short-circuiting the parse, which has to consume its right operand's
    tokens either way -- conflating the two is how a parser silently accepts
    an expression it never looked at.

    Precedence, tightest first: ``!``, then ``==``/``!=``, then ``&&``, then
    ``||``. That is Actions' own order, and it is the whole reason a
    ``&&``-to-``||`` slip is a weakening rather than a syntax error.

    """

    def __init__(self, tokens: 'list[tuple[str, str]]') -> None:
        self.tokens = tokens
        self.index = 0

    def parse(self) -> 'tuple':
        """The whole token list as one tree, or raise if any token is left over."""
        node = self.disjunction()
        if self.index != len(self.tokens):
            raise UnsupportedExpression(
                f'{self.tokens[self.index][1]!r} is left over after a complete '
                f'expression, at token {self.index} of {self.tokens!r}'
            )
        return node

    def _peek(self) -> 'Optional[tuple[str, str]]':
        if self.index < len(self.tokens):
            return self.tokens[self.index]
        return None

    def _accept(self, text: 'str') -> 'bool':
        token = self._peek()
        if token is not None and token[1] == text:
            self.index += 1
            return True
        return False

    def _expect(self, text: 'str') -> None:
        if not self._accept(text):
            raise UnsupportedExpression(f'expected {text!r}, found {self._peek()!r}')

    def disjunction(self) -> 'tuple':
        node = self.conjunction()
        while self._accept('||'):
            node = ('or', node, self.conjunction())
        return node

    def conjunction(self) -> 'tuple':
        node = self.comparison()
        while self._accept('&&'):
            node = ('and', node, self.comparison())
        return node

    def comparison(self) -> 'tuple':
        node = self.unary()
        for operator, kind in (('==', 'eq'), ('!=', 'ne')):
            if self._accept(operator):
                return (kind, node, self.unary())
        return node

    def unary(self) -> 'tuple':
        if self._accept('!'):
            return ('not', self.unary())
        return self.primary()

    def primary(self) -> 'tuple':
        token = self._peek()
        if token is None:
            raise UnsupportedExpression('the expression ends where a term was expected')

        kind, text = token
        if text == '(':
            self.index += 1
            node = self.disjunction()
            self._expect(')')
            return node

        if kind == 'string':
            self.index += 1
            # Actions escapes a single quote inside a single-quoted literal by
            # doubling it, so `'it''s'` is one literal and not two.
            return ('lit', text[1:-1].replace("''", "'"))

        if kind == 'name':
            self.index += 1
            lowered = text.casefold()
            if lowered in ('true', 'false'):
                return ('lit', lowered == 'true')
            if lowered == 'null':
                return ('lit', NULL)
            if self._accept('('):
                return ('call', lowered, self._arguments(text))
            return ('path', text)

        raise UnsupportedExpression(f'unexpected {text!r} where a term was expected')

    def _arguments(self, name: 'str') -> 'list[tuple]':
        """The argument list of ``name(...)``, with its arity checked here.

        Checked at parse time rather than at evaluation time so that an
        unknown function, or a known one called wrongly, fails once for the
        whole scenario table instead of once per row.

        """
        arguments = []  # type: list[tuple]
        if not self._accept(')'):
            arguments.append(self.disjunction())
            while self._accept(','):
                arguments.append(self.disjunction())
            self._expect(')')

        lowered = name.casefold()
        if lowered not in _FUNCTIONS:
            raise UnsupportedExpression(
                f'`{name}()` is outside the subset this module implements; see '
                f'the module docstring'
            )
        if len(arguments) != _FUNCTIONS[lowered]:
            raise UnsupportedExpression(
                f'`{name}()` takes {_FUNCTIONS[lowered]} argument(s), called with '
                f'{len(arguments)}'
            )
        return arguments


def parse_condition(condition: 'str') -> 'tuple':
    """``condition`` -- an ``if:`` value -- as a tree :func:`_evaluate` can walk.

    Strips the surrounding ``${{ ... }}`` when there is one. A value holding
    more than one interpolation, or text outside it, raises: that is template
    concatenation rather than an expression, and nothing in this workflow uses
    it.

    """
    body = condition.strip()
    match = _INTERPOLATION.match(body)
    if match is not None:
        body = match.group('body')
    if '${{' in body or '}}' in body:
        raise UnsupportedExpression(
            f'{condition!r} is not a single whole-value expression; an `if:` built '
            f'out of several interpolations is outside the subset'
        )
    return _Parser(_tokenize(body)).parse()


def _truthy(value: 'object') -> 'bool':
    """Actions' own truthiness: ``false``, ``''``, ``0`` and ``null`` are false.

    This is what an ``if:`` is finally reduced to, so it is also where a
    mutation that keeps every token and changes only the *shape* of the
    expression shows up as a different answer.

    """
    if value is NULL:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value != ''
    if isinstance(value, (int, float)):
        return value != 0
    return True  # an array or object, e.g. from `fromJSON`, is truthy


def _as_string(value: 'object') -> 'str':
    """``value`` cast to a string the way Actions casts it."""
    if value is NULL:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)


def _as_number(value: 'object') -> 'float':
    """``value`` cast to a number the way Actions casts it for a comparison.

    A non-numeric string becomes ``NaN``, which is never equal to anything --
    including to itself. That is not a detail: it is why ``'true' == true`` is
    *false* in Actions, and getting it wrong here would make the evaluator
    disagree with the runner on exactly the kind of mixed comparison a
    mutation is likely to introduce.

    """
    if value is NULL:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, str):
        if not value.strip():
            return 0.0
        try:
            return float(value.strip())
        except ValueError:
            return float('nan')
    if isinstance(value, (int, float)):
        return float(value)
    return float('nan')  # an array or object never equals a scalar


def _loose_eq(left: 'object', right: 'object') -> 'bool':
    """``left == right`` under Actions' rules.

    Same-type operands compare directly, and **string comparison is
    case-insensitive** -- Actions documents that, and every literal in this
    workflow is lower case, so it changes no answer here and is implemented
    only so that the evaluator does not diverge from the runner on a mutation
    that changes case. Mixed types are cast to a number first, per
    :func:`_as_number`.

    """
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    if isinstance(left, bool) and isinstance(right, bool):
        return left is right
    if left is NULL and right is NULL:
        return True
    return _as_number(left) == _as_number(right)


def _lookup(path: 'str', context: 'dict[str, object]') -> 'object':
    """The value at a dotted context ``path``, or :data:`NULL` if unset.

    An unset *property* is ``null``, which is what Actions serves and what a
    skipped job's outputs actually look like. An unknown context *root*
    raises instead: ``steps.foo.bar`` in a job-level ``if:`` is not an unset
    property, it is an expression this module has never modelled, and
    answering ``null`` for it would decide a scenario row by accident.

    """
    parts = path.split('.')
    if parts[0] not in context:
        raise UnsupportedExpression(
            f'`{path}` reads the context root `{parts[0]}`, which no scenario here '
            f'models; known roots are {sorted(context)}'
        )

    current = context  # type: object
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return NULL
    return current


def _call(name: 'str', arguments: 'list[object]', context: 'dict[str, object]') -> 'object':
    """One function call, its arguments already evaluated."""
    if name == 'always':
        return True
    if name in ('cancelled', 'success', 'failure'):
        status = context.get(STATUS, {})
        if not isinstance(status, dict) or name not in status:
            raise UnsupportedExpression(
                f'this condition calls `{name}()`, which no scenario row says the '
                f'answer to -- add it to `release_context` rather than letting the '
                f'row be decided by a default'
            )
        return bool(status[name])
    if name == 'fromjson':
        return json.loads(_as_string(arguments[0]))
    if name == 'startswith':
        # `startsWith` is case-insensitive and casts both operands, same as `==`.
        return _as_string(arguments[0]).casefold().startswith(_as_string(arguments[1]).casefold())
    if name == 'contains':
        haystack, needle = arguments
        if isinstance(haystack, list):
            return any(_loose_eq(item, needle) for item in haystack)
        return _as_string(needle).casefold() in _as_string(haystack).casefold()
    raise UnsupportedExpression(f'`{name}()` is parsed but not evaluated')  # pragma: no cover


def _evaluate(node: 'tuple', context: 'dict[str, object]') -> 'object':
    """One tree node, returning the *value* and not its truthiness.

    ``&&`` and ``||`` return an operand rather than a boolean, which is what
    Actions does, and it matters for the ``true ||`` mutation: the answer to
    ``true || <anything>`` is ``true`` without ``<anything>`` being looked at
    at all.

    """
    kind = node[0]
    if kind == 'lit':
        return node[1]
    if kind == 'path':
        return _lookup(node[1], context)
    if kind == 'not':
        return not _truthy(_evaluate(node[1], context))
    if kind == 'and':
        left = _evaluate(node[1], context)
        return _evaluate(node[2], context) if _truthy(left) else left
    if kind == 'or':
        left = _evaluate(node[1], context)
        return left if _truthy(left) else _evaluate(node[2], context)
    if kind == 'eq':
        return _loose_eq(_evaluate(node[1], context), _evaluate(node[2], context))
    if kind == 'ne':
        return not _loose_eq(_evaluate(node[1], context), _evaluate(node[2], context))
    if kind == 'call':
        return _call(node[1], [_evaluate(argument, context) for argument in node[2]], context)
    raise UnsupportedExpression(f'no evaluation rule for {node!r}')  # pragma: no cover


def evaluate_condition(condition: 'str', context: 'dict[str, object]') -> 'bool':
    """Whether a job carrying this ``if:`` would run in ``context``.

    The answer an ``if:`` finally reduces to, which is the thing #962 asks to
    be checked -- as opposed to the text that produced it.

    """
    return _truthy(_evaluate(parse_condition(condition), context))


#: The four values a job's ``needs.<job>.result`` can take. The axis #962 is
#: about: a gate can be weakened without any of these changing what its *text*
#: says, and walking all four is what notices.
JOB_RESULTS = ('success', 'failure', 'cancelled', 'skipped')

#: ``{job: output}``, naming the ``version_check`` output each gated job reads
#: as its own evidence. #888's whole point is that these are four different
#: questions rather than four spellings of one -- see
#: :class:`TestEvidenceBasedGating`. The mapping is what lets a scenario row
#: set one output to ``'true'`` and the rest to ``'false'``, so a gate reading
#: somebody else's evidence reads the opposite answer and the row fails.
GATE_EVIDENCE = {
    'github': 'PCAPKIT_TAG_EXISTS',
    'tag': 'PCAPKIT_CONDA_TAG_EXISTS',
    'pypi': 'PCAPKIT_PYPI_COMPLETE',
    'conda': 'PCAPKIT_CONDA_COMPLETE',
}

#: ``{job: predecessors}``, naming the *publishing* predecessors each gated job
#: holds to the ``== 'success' || == 'skipped'`` equality pair.
#: ``version_check`` is deliberately absent: it is a direct
#: dependency of all three and is held to the stricter ``== 'success'`` alone,
#: which is the distinction #960 found the workflow's own comment had blurred.
#: ``test_the_table_covers_every_declared_dependency`` is what stops this from
#: going stale against the file's real ``needs:``.
PUBLISHING_PREDECESSORS = {
    'tag': ('github',),
    'pypi': ('github',),
    'conda': ('github', 'tag'),
}

#: The direct dependencies every downstream gate holds to ``== 'success'``
#: alone, with no ``|| 'skipped'``: ``version_check`` because it produces the
#: evidence they read, and -- #1052 -- ``unit-tests`` because it is the
#: release test gate, which since that issue skips whenever nothing is
#: publishable and so no longer gates by sitting first in the chain. A
#: skipped gate admitted here would publish untested.
STRICT_PREDECESSORS = ('version_check', 'unit-tests')


def release_context(version_check: 'str' = 'success',
                    unit_tests: 'str' = 'success',
                    github: 'str' = 'success',
                    tag: 'str' = 'success',
                    ref_name: 'str' = 'main',
                    complete: 'tuple[str, ...]' = (),
                    unknown: 'tuple[str, ...]' = (),
                    cancelled: 'bool' = False,
                    outputs_present: 'bool' = True,
                    event_name: 'str' = 'workflow_run',
                    workflow_run_conclusion: 'str' = 'success') -> 'dict[str, object]':
    """The ``needs``/``github``/status context one scenario row stands for.

    Every default is a value that, on its own, lets a gate run, so a row
    changes exactly the one thing its name says it changes. That is deliberate
    and it is what makes a row discriminating: a row holding two clauses false
    passes for any mutation that keeps either of them, which is how a truth
    table ends up proving less than it looks like it does.

    ``complete`` names the evidence outputs that say *already published*
    (``'true'``); every other output says ``'false'``. Naming the true ones
    rather than passing a whole mapping is what makes the cross-evidence trap
    free: a row that marks only ``PCAPKIT_PYPI_COMPLETE`` complete leaves the
    other three incomplete, so a gate reading the wrong one reads the opposite
    answer.

    ``unknown`` names the outputs that say *neither*, i.e. that hold
    :data:`NULL` -- the value Actions serves for an output a job never set. One
    output at ``null`` while the rest hold literals is the shape a third-party
    action returning nothing leaves behind, and -- #967 -- the only shape on
    which ``== 'false'`` and ``!= 'true'`` disagree. An output named in both
    ``complete`` and ``unknown`` is ``null``: ``unknown`` is applied second, and
    is written that way so the resolution is stated rather than incidental.

    ``outputs_present=False`` is the shape a *skipped* ``version_check``
    leaves behind -- no outputs at all, which Actions serves as ``null``
    rather than as ``''`` or as a zero. ``ref_name`` defaults to ``main``
    because a ``workflow_run`` trigger runs against the default branch;
    ``v1.5.0`` is the other real value, from this workflow's ``push: tags:
    ['v*']`` trigger.

    """
    outputs = {}  # type: dict[str, object]
    if outputs_present:
        outputs = {name: ('true' if name in complete else 'false')
                   for name in GATE_EVIDENCE.values()}
        outputs.update({name: NULL for name in unknown})
        outputs['PCAPKIT_VERSION'] = '1.5.0'
        outputs['PCAPKIT_PRERELEASE'] = 'false'
        outputs['PCAPKIT_CONDA_LABEL'] = 'main'

    return {
        'needs': {
            'unit-tests': {'result': unit_tests},
            'version_check': {'result': version_check, 'outputs': outputs},
            'github': {'result': github},
            'tag': {'result': tag},
            'pypi': {'result': 'success'},
            'conda': {'result': 'success'},
        },
        'github': {
            'ref_name': ref_name,
            'event_name': event_name,
            'event': {'workflow_run': {'conclusion': workflow_run_conclusion}},
        },
        STATUS: {'cancelled': cancelled},
    }


def gate_rows(job: 'str') -> 'list[tuple[str, dict[str, object], bool]]':
    """``[(row name, context, whether the gate must run)]`` for a gated job.

    One axis per row, with everything else held at a running value -- see
    :func:`release_context`. The rows, and what each is for:

    * **``version_check`` over all four results**, with its outputs still
      *present*. #962's own axis, and the load-bearing row of the set: a
      failed job does publish the outputs of the steps that already ran, so
      holding them present is both realistic and the only way the row notices
      the clause being deleted outright rather than merely reworded.
    * **The same four, with its outputs gone**, which is what a *skipped*
      ``version_check`` actually leaves. Weaker as a guard, and kept because
      it is the shape the retry case takes.
    * **``unit-tests`` over all four results**, #1052's axis. Only
      ``success`` runs: since that issue the release test gate skips whenever
      nothing is publishable, so a ``skipped`` gate is a normal result, and a
      publisher that admitted one would publish untested.
    * **Each publishing predecessor over all four results.** ``success`` and a
      legitimate ``skipped`` both run -- that is #888's escape hatch, and the
      ``skipped`` row is what stops it being quietly removed again -- while
      ``failure`` and ``cancelled`` do not. ``cancelled`` is the one
      ``!= 'failure'`` would admit.
    * **A cancelled run**, twice: once with everything else running, and once
      on a ``v*`` tag push with this job's evidence already complete. Either
      alone catches ``!cancelled()`` becoming ``always()``; the second also
      catches a ``true ||`` prefix on a row where every inner clause is true.
    * **All four corners of the ``startsWith(github.ref_name, 'v') ||
      <evidence> == 'false'`` disjunction**, with the other three evidence
      outputs inverted so that a gate reading the wrong one fails the row.
    * **This job's own evidence at ``null``**, on a non-``v`` ref and with
      ``version_check`` otherwise successful. #967: the one shape on which
      ``== 'false'`` and ``!= 'true'`` disagree, and the only row of this table
      that tells them apart. Every row above holds the evidence outputs at a
      literal, where the two spellings agree; the ``its outputs never
      published`` rows do hold them at ``null``, but only alongside a
      non-``success`` ``version_check``, where the gate is already false before
      the evidence clause is reached. The other three outputs stay ``'false'``,
      so a gate reading somebody else's evidence runs where this row demands a
      skip, and the row keeps the cross-evidence trap the rows above set.

    Held false in every row but the two cancellation rows: ``cancelled()``.
    Holding it *true* elsewhere would make each row pass for any mutation that
    keeps ``!cancelled()``, which is most of them.

    The ``null`` row guards a future change rather than a present bug, and is
    kept on those terms. Neither curl-based evidence check can produce an empty
    output as the workflow stands: ``PCAPKIT_PYPI_COMPLETE`` and
    ``PCAPKIT_CONDA_COMPLETE`` both default ``complete=false`` and only then set
    ``true``, under ``set -euo pipefail``. ``PCAPKIT_TAG_EXISTS`` and
    ``PCAPKIT_CONDA_TAG_EXISTS`` are the ones not in this repository's hands:
    they come from ``mukunku/tag-exists-action@v1.7.0``, in ``version_check``'s
    ``check_tag`` and ``check_conda_tag`` steps, and ``tag``'s gate reads the
    second of them. So for one of the three jobs the shape is a third party's
    to produce, and for the other two it is one rewritten shell step away.

    """
    evidence = GATE_EVIDENCE[job]
    rows = []  # type: list[tuple[str, dict[str, object], bool]]

    for result in JOB_RESULTS:
        rows.append((f'version_check={result}',
                     release_context(version_check=result),
                     result == 'success'))
        if result != 'success':
            rows.append((f'version_check={result}, its outputs never published',
                         release_context(version_check=result, outputs_present=False),
                         False))

    for result in JOB_RESULTS:
        rows.append((f'unit-tests={result}',
                     release_context(unit_tests=result),
                     result == 'success'))

    for predecessor in PUBLISHING_PREDECESSORS[job]:
        for result in JOB_RESULTS:
            rows.append((f'{predecessor}={result}',
                         release_context(**{predecessor: result}),
                         result in ('success', 'skipped')))

    rows.append(('the run was cancelled', release_context(cancelled=True), False))
    rows.append((f'the run was cancelled on a v* tag push with {evidence}=true',
                 release_context(cancelled=True, ref_name='v1.5.0', complete=(evidence,)),
                 False))

    others = tuple(name for name in GATE_EVIDENCE.values() if name != evidence)
    for ref_name in ('main', 'v1.5.0'):
        for already in (False, True):
            rows.append((
                f'ref_name={ref_name}, {evidence}={str(already).lower()}',
                release_context(ref_name=ref_name,
                                complete=(evidence,) if already else others),
                ref_name.startswith('v') or not already,
            ))

    rows.append((f'ref_name=main, {evidence}=null',
                 release_context(unknown=(evidence,)), False))
    return rows


def gate_violations(condition: 'str', job: 'str') -> 'list[str]':
    """Every row of :func:`gate_rows` on which ``condition`` disagrees with the gate.

    Returns the disagreements rather than asserting them, so the same table
    can be run against a deliberately mutated condition. That is what lets
    :class:`TestGateMutationsChangeTheTruthTable` *show* these rows failing
    without the clauses they protect, instead of asserting that they would.

    """
    tree = parse_condition(condition)
    violations = []  # type: list[str]
    for name, context, expected in gate_rows(job):
        if _truthy(_evaluate(tree, context)) != expected:
            violations.append(
                f'{name}: expected the gate to '
                f'{"run" if expected else "skip"}, it did not'
            )
    return violations


def text_gate_violations(condition: 'str', job: 'str') -> 'list[str]':
    """The existing text layer for a gated job, as a list rather than as assertions.

    A deliberate mirror of the three assertions
    :class:`TestEvidenceBasedGating` already makes about these conditions --
    the evidence it reads, its treatment of each publishing predecessor, and
    ``version_check`` having strictly succeeded. The mirror exists so that
    :class:`TestGateMutationsChangeTheTruthTable` can report *which* layer
    rejects each mutation; #962 settled that the text assertions themselves
    stay exactly as #961 left them, so they are copied here rather than
    refactored into a helper the real tests then call.
    ``test_the_real_conditions_violate_neither_layer`` is what keeps the
    mirror from drifting away from the original.

    Only the three downstream gates, since those are the three the mirrored
    assertions are about; ``github`` is the deliberate asymmetry they exist to
    preserve rather than a fourth case of it.

    """
    violations = []  # type: list[str]

    if GATE_EVIDENCE[job] not in condition:
        violations.append(f'does not read its own evidence output {GATE_EVIDENCE[job]}')
    if 'PCAPKIT_TAG_EXISTS ==' in condition:
        violations.append("reads github's v* tag as its gating evidence")
    if 'cancelled()' not in condition and 'always()' not in condition:
        violations.append('calls no status-check function, so a skipped predecessor '
                          'cascade-skips it before this condition is even evaluated')

    for predecessor in PUBLISHING_PREDECESSORS[job]:
        if f"needs.{predecessor}.result == 'success'" not in condition:
            violations.append(f'does not explicitly accept {predecessor} succeeding')
        if f"needs.{predecessor}.result == 'skipped'" not in condition:
            violations.append(f'does not explicitly accept {predecessor} having skipped')
        if f"needs.{predecessor}.result != 'failure'" in condition:
            violations.append(f"checks {predecessor} with != 'failure', which admits cancelled")

    compact = re.sub(r'\s+', '', condition)
    for strict in STRICT_PREDECESSORS:
        if f"&&needs.{strict}.result=='success'&&" not in compact:
            violations.append(f'does not require {strict} to have succeeded as a '
                              'top-level && conjunct')
        if compact.count(f'.{strict}.result') != 1:
            violations.append(f'refers to {strict}.result more than once')

    return violations


class WorkflowMixin:
    """Reads and scans the workflow once per test."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding='utf-8')  # type: ignore[attr-defined]
        cls.jobs = job_blocks(cls.text)  # type: ignore[attr-defined]


class TestPublishingJobsAreGated(WorkflowMixin, unittest.TestCase):
    """The rule #641 asks for: publish, and you declare an environment."""

    def test_the_scan_found_the_jobs(self) -> None:
        """A scanner that finds nothing would pass every test below it."""
        self.assertEqual(
            sorted(self.jobs),
            ['conda', 'github', 'pypi', 'release_status', 'tag', 'unit-tests', 'version_check'],
            'the job list moved; if that is intended, the expectations in this '
            'module need revisiting rather than this line being updated alone',
        )

    def test_every_publishing_job_declares_an_environment(self) -> None:
        """No job may reach PyPI, Anaconda, a Release or a git push unapproved.

        An ``environment:`` is what lets Actions hold a job for a human, but
        since #887 only ``github-release``'s actually does -- ``conda-tag``,
        ``pypi`` and ``anaconda`` kept their environments with no reviewer on
        them, and are held instead by depending on ``github`` through
        ``needs:``. This test only checks that the line is present, not that
        it still carries a reviewer or that the dependency exists;
        :class:`TestGatedJobsDependOnGithub` below is what checks the latter.
        Without either, the job runs the moment its ``needs:`` are met, which
        for this workflow means "whenever a version bump lands".

        """
        ungated = {
            name: reasons
            for name, block in self.jobs.items()
            if (reasons := publishing_reasons(block)) and declared_environment(block) is None
        }
        self.assertEqual(
            ungated, {},
            'these jobs publish with no `environment:`, so nothing holds them for '
            'approval: ' + '; '.join(
                f'{name} ({", ".join(reasons)})' for name, reasons in sorted(ungated.items())
            ),
        )

    def test_the_gated_jobs_are_the_publishing_ones(self) -> None:
        """Stated the other way round, so a gate on the wrong job is visible too."""
        gated = {name for name, block in self.jobs.items()
                 if declared_environment(block) is not None}
        publishing = {name for name, block in self.jobs.items() if publishing_reasons(block)}
        self.assertEqual(gated, publishing)
        self.assertEqual(gated, {'github', 'tag', 'pypi', 'conda'})


class TestEnvironmentsAreNotShared(WorkflowMixin, unittest.TestCase):
    """One environment per target, which is a decision and not an accident."""

    def test_each_gated_job_has_its_own_environment(self) -> None:
        """Approval is granted to an environment, so sharing one merges two gates.

        A single ``release`` environment approved once would release PyPI
        *and* Anaconda together, which is the outcome #641's fix was meant to
        prevent rather than rename. Different credentials reach the two
        indexes -- OIDC trusted publishing and ``ANACONDA_TOKEN`` -- and
        ``tag``'s write to ``main`` uses a third, so sharing one environment
        would still merge those blast radii even though, since #887, only
        ``github-release`` carries a reviewer of its own; the other three are
        held by depending on it instead. That each *does* depend on it is
        :class:`TestGatedJobsDependOnGithub`'s check, not this one -- this
        test only stops the four gates from being collapsed back into one.

        """
        environments = {}  # type: dict[str, list[str]]
        for name, block in sorted(self.jobs.items()):
            environment = declared_environment(block)
            if environment is not None:
                environments.setdefault(environment, []).append(name)

        shared = {env: jobs for env, jobs in environments.items() if len(jobs) > 1}
        self.assertEqual(
            shared, {},
            'these environments gate more than one job, so one approval releases '
            f'all of them: {shared}',
        )

    def test_pypi_and_anaconda_are_separate(self) -> None:
        """Named explicitly, because these two are the ones #641 is about."""
        pypi = declared_environment(self.jobs['pypi'])
        anaconda = declared_environment(self.jobs['conda'])
        self.assertIsNotNone(pypi)
        self.assertIsNotNone(anaconda)
        self.assertNotEqual(pypi, anaconda)


class TestGatedJobsDependOnGithub(WorkflowMixin, unittest.TestCase):
    """#887: with only ``github-release`` still holding a required reviewer,
    the other three gated jobs have to reach it through ``needs:`` instead,
    or removing their own reviewer left them ungated in every sense that
    matters.

    Nothing above this class reads ``needs:`` at all -- :class:`WorkflowMixin`
    aside, every test in :class:`TestPublishingJobsAreGated` and
    :class:`TestEnvironmentsAreNotShared` passes identically if ``tag``'s
    ``needs:`` is reverted to ``[ version_check ]``, which is the exact
    regression #887 fixed. This is the one test in the module that would
    catch it.

    """

    def test_every_gated_job_depends_on_github(self) -> None:
        """Every ``environment:``-declaring job but ``github`` itself must
        have ``github`` in its ``needs:`` closure, directly or transitively.

        """
        for name, block in sorted(self.jobs.items()):
            if name == 'github' or declared_environment(block) is None:
                continue
            with self.subTest(job=name):
                closure = needs_closure(self.jobs, name)
                self.assertIn(
                    'github', closure,
                    f'`{name}` declares an environment but its `needs:` closure '
                    f'{sorted(closure)} does not include `github` -- removing '
                    f'its own required reviewer (#887) would let it run before '
                    f'the one approval left to gate it',
                )


#: The disjunct of the release test gate's ``if:`` that is not about evidence.
#: Named so that :meth:`TestNothingPublishesWithoutTheGate.test_dropping_any_gate_clause_is_caught`
#: can drop it, alongside each evidence clause, from a scratch copy.
_GATE_REF_CLAUSE = "startsWith(github.ref_name, 'v') ||"


def gate_coverage_violations(gate: 'str', jobs: 'dict[str, str]') -> 'list[str]':
    """Every evidence state in which a publisher would run and the gate would not.

    Walks both refs, every ``'true'``/``'false'``/``null`` assignment of the four
    evidence outputs, and ``github``/``tag`` at ``success`` and at ``skipped`` --
    648 contexts -- with ``version_check`` and ``unit-tests`` themselves at
    ``success``, since the question is what the gate's own ``if:`` decides.
    ``github``'s condition is evaluated as declared; its implicit ``success()``
    only ever makes it run *less*, so this over-approximates when it runs,
    which is the safe direction for a coverage check.

    """
    names = tuple(GATE_EVIDENCE.values())
    gate_tree = parse_condition(gate)
    publishers = {name: parse_condition(declared_if(jobs[name])) for name in GATE_EVIDENCE}
    violations = []  # type: list[str]
    for ref_name in ('main', 'v1.5.0'):
        for states in itertools.product(('true', 'false', 'null'), repeat=len(names)):
            for github, tag in itertools.product(('success', 'skipped'), repeat=2):
                context = release_context(
                    ref_name=ref_name, github=github, tag=tag,
                    complete=tuple(n for n, v in zip(names, states) if v == 'true'),
                    unknown=tuple(n for n, v in zip(names, states) if v == 'null'),
                )
                running = sorted(name for name, tree in publishers.items()
                                 if _truthy(_evaluate(tree, context)))
                if running and not _truthy(_evaluate(gate_tree, context)):
                    violations.append(
                        f'ref_name={ref_name}, github={github}, tag={tag}, '
                        f'{dict(zip(names, states))}: {running} would run, the gate would not'
                    )
    return violations


class TestNothingPublishesWithoutTheGate(WorkflowMixin, unittest.TestCase):
    """#1052: the release test gate now skips when nothing is publishable, and
    no release may skip it.

    Until #1052 ``unit-tests`` was the root of the graph, so every job reached
    it through ``version_check``'s implicit ``success()`` and no publisher had
    to name it. It now runs *after* ``version_check`` and only when a release
    will happen, so a ``skipped`` gate is routine and position no longer gates
    anything. Two independent halves keep "nothing publishes without a passing
    gate" true, and each is asserted here on its own, so that losing either is
    a failure even while the other still holds:

    * **Every publisher requires the gate's success.** Directly, by name --
      either an explicit ``needs.unit-tests.result == 'success'`` conjunct, or
      for ``github``, whose ``if:`` keeps the implicit ``success()``, a direct
      ``needs:`` on it. This is the half that makes a drifted predicate fail
      *closed*.
    * **The gate runs whenever any publisher would.** Checked exhaustively over
      the evidence states rather than by row, so a release can never be
      blocked by a gate that wrongly skipped.

    """

    def test_every_gated_job_depends_on_the_gate(self) -> None:
        for name, block in sorted(self.jobs.items()):
            if declared_environment(block) is None:
                continue
            with self.subTest(job=name):
                self.assertIn('unit-tests', needs_closure(self.jobs, name))

    def test_every_gated_job_requires_the_gate_to_have_succeeded(self) -> None:
        """Transitive ``needs:`` is not enough on its own.

        ``tag``, ``pypi`` and ``conda`` accept a ``skipped`` ``github``, so a
        gate reached only through ``github`` would be waved through exactly
        when it skipped. A job that opts out of the implicit ``success()`` must
        name the gate in its condition; a job that keeps it must list the gate
        in its own ``needs:``, which is what that implicit check reads.

        """
        for name, block in sorted(self.jobs.items()):
            if declared_environment(block) is None:
                continue
            with self.subTest(job=name):
                condition = declared_if(block)
                compact = re.sub(r'\s+', '', condition)
                if 'cancelled()' in condition or 'always()' in condition:
                    self.assertIn(
                        "&&needs.unit-tests.result=='success'&&", compact,
                        f'`{name}` opts out of the implicit `success()` but does '
                        f'not require the release test gate to have succeeded',
                    )
                else:
                    self.assertIn(
                        'unit-tests', declared_needs(block),
                        f'`{name}` relies on the implicit `success()`, which reads '
                        f'only its direct `needs:`, and the gate is not among them',
                    )

    def test_a_gate_that_did_not_pass_stops_every_downstream_publisher(self) -> None:
        """On the one ref and evidence state where they would otherwise run."""
        for job in ('tag', 'pypi', 'conda'):
            condition = declared_if(self.jobs[job])
            self.assertTrue(evaluate_condition(condition, release_context(ref_name='v1.5.0')))
            for result in ('failure', 'cancelled', 'skipped'):
                with self.subTest(job=job, gate=result):
                    self.assertFalse(evaluate_condition(
                        condition, release_context(ref_name='v1.5.0', unit_tests=result)))

    def test_the_gate_runs_whenever_any_publisher_would(self) -> None:
        violations = gate_coverage_violations(declared_if(self.jobs['unit-tests']), self.jobs)
        self.assertEqual(
            violations, [],
            f'the release test gate skips in {len(violations)} state(s) where a '
            f'publisher would run -- which then skips behind it, losing the '
            f'release: ' + '; '.join(violations[:5]),
        )

    def test_the_gate_skips_when_everything_is_already_published(self) -> None:
        """The point of #1052, and only safe because no publisher runs there."""
        context = release_context(complete=tuple(GATE_EVIDENCE.values()))
        self.assertFalse(evaluate_condition(declared_if(self.jobs['unit-tests']), context))
        for job in GATE_EVIDENCE:
            with self.subTest(job=job):
                self.assertFalse(evaluate_condition(declared_if(self.jobs[job]), context))

    def test_dropping_any_gate_clause_is_caught(self) -> None:
        """The coverage check above has to be able to fail.

        Each of the gate's five disjuncts is removed in turn from a scratch
        copy; every removal must leave some state in which a publisher runs
        and the gate does not.

        """
        gate = declared_if(self.jobs['unit-tests'])
        clauses = [_GATE_REF_CLAUSE] + [
            f"needs.version_check.outputs.{name} != 'true' ||" for name in
            list(GATE_EVIDENCE.values())[:-1]
        ] + [f"|| needs.version_check.outputs.{list(GATE_EVIDENCE.values())[-1]} != 'true'"]
        for clause in clauses:
            with self.subTest(dropped=clause):
                self.assertIn(clause, gate)
                mutant = gate.replace(clause, '')
                self.assertTrue(gate_coverage_violations(mutant, self.jobs))


class TestEvidenceBasedGating(WorkflowMixin, unittest.TestCase):
    """#888: ``tag``, ``pypi`` and ``conda`` read their own evidence now,
    instead of ``PCAPKIT_TAG_EXISTS`` -- the tag ``github`` creates, which
    answers "was this tagged" and not "was this published", and those diverge
    exactly when a release half-completes.

    """

    def test_github_still_gates_on_the_v_tag_it_creates(self) -> None:
        """The one job for which ``PCAPKIT_TAG_EXISTS`` *is* the right question.

        ``github``'s own artefact is the ``v*`` tag that output answers for,
        so this is deliberate asymmetry, not a leftover of the bug -- this
        test is what stops a future "fix" from making it symmetric by mistake.

        """
        condition = declared_if(self.jobs['github'])
        self.assertIn('PCAPKIT_TAG_EXISTS', condition)

    def test_tag_gates_on_its_own_conda_tag_evidence(self) -> None:
        condition = declared_if(self.jobs['tag'])
        self.assertIn('PCAPKIT_CONDA_TAG_EXISTS', condition)
        self.assertNotIn(
            'PCAPKIT_TAG_EXISTS ==', condition,
            '`tag` still reads the v* tag as its gating evidence, which is '
            "github's artefact, not tag's",
        )

    def test_pypi_gates_on_its_own_file_count_evidence(self) -> None:
        condition = declared_if(self.jobs['pypi'])
        self.assertIn('PCAPKIT_PYPI_COMPLETE', condition)
        self.assertNotIn('PCAPKIT_TAG_EXISTS ==', condition)

    def test_conda_gates_on_its_own_aggregate_evidence(self) -> None:
        condition = declared_if(self.jobs['conda'])
        self.assertIn('PCAPKIT_CONDA_COMPLETE', condition)
        self.assertNotIn('PCAPKIT_TAG_EXISTS ==', condition)

    def test_evidence_gated_jobs_survive_a_legitimately_skipped_predecessor(self) -> None:
        """The half of the fix that has nothing to do with *which* evidence is read.

        ``tag``, ``pypi`` and ``conda`` each depend (directly) on ``github``,
        and ``conda`` also on ``tag``. GitHub Actions skips a job whose
        ``needs:`` included a job that itself skipped -- before that job's own
        ``if:`` is even evaluated -- unless the ``if:`` itself calls a
        status-check function. ``github`` legitimately skips whenever its own
        tag already exists, which is exactly the retry case #888 is about, so
        without this escape hatch the evidence checks above would never get a
        chance to run: a correctly-computed "not yet on PyPI, please run"
        would still be silently discarded by the default ``success()`` check.

        The escape hatch has to be a real status-check function
        (``!cancelled()``, ``always()``, ...), not just the *word* appearing
        in a comment -- so this greps the condition text itself, the same
        coarse substring style :data:`PUBLISHING_MARKERS` already uses.

        Each dependency has to be checked for ``== 'success' || == 'skipped'``
        explicitly, not merely ``!= 'failure'``: the latter still admits
        ``cancelled``, and a cancelled ``tag`` would send ``conda`` into its
        ``actions/checkout`` with ``ref: conda-<version>+0`` for a tag ``tag``
        never pushed -- a checkout failure standing in for a clean skip,
        found on the same cross-review as the two blocking defects above.

        """
        direct_deps = {
            'tag': ['github'],
            'pypi': ['github'],
            'conda': ['github', 'tag'],
        }
        for name, deps in sorted(direct_deps.items()):
            with self.subTest(job=name):
                condition = declared_if(self.jobs[name])
                self.assertTrue(
                    'cancelled()' in condition or 'always()' in condition,
                    f'`{name}`\'s `if:` ({condition!r}) calls neither `cancelled()` '
                    f'nor `always()`, so the default `success()` check GitHub Actions '
                    f'prepends will skip it the moment any direct dependency skips -- '
                    f'including a dependency that skipped for the legitimate #888 '
                    f'reason that its own artefact already exists',
                )
                for dep in deps:
                    self.assertIn(
                        f"needs.{dep}.result == 'success'", condition,
                        f'`{name}` does not explicitly accept `{dep}` (a direct '
                        f'dependency) succeeding',
                    )
                    self.assertIn(
                        f"needs.{dep}.result == 'skipped'", condition,
                        f'`{name}` does not explicitly accept `{dep}` (a direct '
                        f'dependency) having legitimately skipped',
                    )
                    self.assertNotIn(
                        f"needs.{dep}.result != 'failure'", condition,
                        f'`{name}` checks `{dep}` with `!= \'failure\'`, which still '
                        f'admits `cancelled` -- see this test\'s own docstring',
                    )

    def test_version_check_must_strictly_succeed(self) -> None:
        """``version_check`` is not one of the *publishing* predecessors the
        equality-pair escape hatch above exists for -- it produces the
        evidence ``tag``, ``pypi`` and ``conda`` read, so a skipped or
        cancelled ``version_check`` must stop them rather than being waved
        through the way a legitimately-skipped ``github`` or ``tag`` is.

        #960: the comment above ``jobs:`` once read as though the equality
        pair applied to "each of their own direct dependencies", which is
        false for ``version_check`` specifically -- a direct dependency of
        all three, required to have *strictly* succeeded, with no
        ``|| 'skipped'``. Nothing in this module pinned that before.

        An ``assertNotIn`` over known-bad spellings cannot pin this, because a
        weakening can keep the ``== 'success'`` literal while meaning the
        opposite -- ``(!= 'failure' || == 'success')`` is just
        ``!= 'failure'``, which admits both ``skipped`` and ``cancelled``.
        Hence two assertions instead: the clause must appear as a top-level
        ``&&`` conjunct, since vocabulary is not structure and a
        one-character ``&&``-to-``||`` slip keeps every token while nullifying
        the gate; and ``version_check.result`` must be referenced exactly
        once, which closes the rest, since anything added alongside the real
        clause raises the count however it is spelled.

        Whitespace is stripped first so the pattern cannot be defeated by
        padding around the property dots. That trade is deliberate: it closes
        a hole that fails *open*, at the cost of reading an identifier or a
        literal split across the folded scalar's line break as though it were
        whole -- which fails *closed*, since Actions rejects the real
        expression and nothing publishes.

        **Not closed by this test:** a top-level ``||`` outside the
        conjunction chain. Appending ``|| github.event_name ==
        'workflow_dispatch'`` to the end of the condition, or wrapping it in
        ``true || ...``, bypasses the gate while leaving the compacted clause
        byte-identical. Conjunction is monotone, so *adding* ``&&`` conjuncts
        can only strengthen the gate and needs no guard; disjunction is the
        only remaining weakening, and catching it needs the expression
        evaluated rather than matched.
        :class:`TestGateExpressionsEvaluateCorrectly` is where #962 does that,
        and ``TestGateMutationsChangeTheTruthTable.MUTATIONS`` is where the
        ``true ||`` prefix is recorded as caught by the evaluator and missed
        here. This test stays as #961 left it: it fails with a message naming
        the clause rather than a scenario row, and it catches the one thing the
        evaluator cannot -- operands reversed, which keeps the truth table
        intact.

        """
        for name in ('tag', 'pypi', 'conda'):
            with self.subTest(job=name):
                compact = re.sub(r'\s+', '', declared_if(self.jobs[name]))
                self.assertIn(
                    "&&needs.version_check.result=='success'&&", compact,
                    f'`{name}` does not require `version_check` to have '
                    f'succeeded as a top-level `&&` conjunct -- a disjunct or '
                    f'a negation keeps the same tokens while nullifying the '
                    f'gate',
                )
                self.assertEqual(
                    compact.count('version_check.result'), 1,
                    f'`{name}` refers to `version_check.result` more than '
                    f"once; the gate is one comparison, `== 'success'`, and a "
                    f'second reference can only weaken it',
                )

    def test_the_release_test_gate_must_strictly_succeed(self) -> None:
        """#1052: the same bar, for ``unit-tests``.

        Before #1052 the gate sat first in the chain and ``version_check``'s
        implicit ``success()`` carried it to every publisher, so no publisher
        named it. Now ``version_check`` runs first and the gate skips whenever
        nothing is publishable, so a ``skipped`` gate is routine -- and these
        three open with ``!cancelled()``, which opts them out of the implicit
        check that would otherwise have stopped them. Hence an explicit
        top-level ``needs.unit-tests.result == 'success'`` conjunct, referenced
        exactly once, for the reasons the test above gives.

        """
        for name in ('tag', 'pypi', 'conda'):
            with self.subTest(job=name):
                compact = re.sub(r'\s+', '', declared_if(self.jobs[name]))
                self.assertIn(
                    "&&needs.unit-tests.result=='success'&&", compact,
                    f'`{name}` does not require the release test gate to have '
                    f'succeeded as a top-level `&&` conjunct, so a skipped or '
                    f'cancelled gate would let it publish untested',
                )
                self.assertEqual(compact.count('unit-tests.result'), 1)

    def test_conda_checks_its_own_leg_before_uploading(self) -> None:
        """The correctness half for ``conda``: ``anaconda/actions/upload-package``
        has no ``skip-existing``, so the job-level evidence above is only a cost
        saver -- each matrix leg has to check for itself.

        """
        block = self.jobs['conda']
        self.assertIn('api.anaconda.org/release/jarryshaw/pypcapkit', block)
        self.assertIn('PCAPKIT_LEG_EXISTS', block)
        self.assertIn(
            "steps.check_leg.outputs.PCAPKIT_LEG_EXISTS != 'true'", block,
            "the 'Upload conda packages to Anaconda' step has no `if:` gating "
            'it on the per-leg evidence check, so a leg that already has this '
            'exact distribution would fail outright on retry instead of skipping',
        )

    def test_a_predicted_skip_is_announced(self) -> None:
        """#888's other half: a skip must never be silent.

        ``conda``'s per-leg skip gets its own ``::notice`` at the point of the
        skip, since ``release_status`` only sees the job's aggregate result and
        cannot say *which* leg was already published.

        """
        self.assertIn('::notice title=conda leg already published', self.jobs['conda'])

    def test_version_check_exposes_the_new_evidence_outputs(self) -> None:
        """The three outputs the jobs above actually read have to exist for
        them to read anything at all -- a typo'd output name fails silently
        (an empty string, not an error), so this is worth asserting directly.

        """
        block = self.jobs['version_check']
        for output in ('PCAPKIT_CONDA_TAG_EXISTS', 'PCAPKIT_PYPI_COMPLETE', 'PCAPKIT_CONDA_COMPLETE'):
            with self.subTest(output=output):
                self.assertIn(f'{output}:', block)

    def test_pypi_evidence_reads_the_per_version_endpoint(self) -> None:
        """Not ``releases[<version>]``: that field was empty on every live
        request made while building this check, including against a version
        that genuinely has all 8 files -- ``urls`` is what the per-version
        endpoint actually populates. A regression back to ``releases`` would
        make the evidence check always read 0 files.

        """
        block = self.jobs['version_check']
        self.assertIn('pypi.org/pypi/pypcapkit/', block)
        self.assertIn("data.get('urls'", block)

    def test_conda_evidence_checks_both_platforms(self) -> None:
        block = self.jobs['version_check']
        self.assertIn('linux-64', block)
        self.assertIn('osx-64', block)


class TestGateExpressionsEvaluateCorrectly(WorkflowMixin, unittest.TestCase):
    """#962: the gates' ``if:`` conditions *evaluated* over a scenario table,
    rather than matched as text.

    :class:`TestEvidenceBasedGating` above asserts over the conditions'
    spelling, and four review rounds on #961 showed where that ends: twenty
    mutations of one clause, three successive strengthenings, and each
    strengthening defeated by a mutation the previous round had not thought
    of. The reason is structural rather than a matter of the assertions not
    being clever enough -- a gate's job is to produce an answer, and no amount
    of matching on the text that produces it is the same as checking the
    answer.

    So this walks the scenarios instead and checks what each condition
    actually decides. A mutation is then caught when it changes the truth
    table, whatever it looks like: ``&&``-to-``||``, ``== 'success'`` to
    ``!= 'failure'``, a ``contains(fromJSON(...))`` membership test, a
    ``true ||`` prefix outside the conjunction chain -- all of them land on
    the same rows. :class:`TestGateMutationsChangeTheTruthTable` below is
    where that claim is demonstrated rather than asserted.

    """

    #: ``(row name, context, whether github must run)``, for the one gate that
    #: is deliberately asymmetric: ``github``'s own artefact *is* the ``v*``
    #: tag ``PCAPKIT_TAG_EXISTS`` answers for, so unlike the three jobs below
    #: it that output is the right question for it -- see
    #: ``test_github_still_gates_on_the_v_tag_it_creates``.
    #:
    #: Its condition calls no status-check function, so Actions additionally
    #: conjoins the default ``success()`` that this evaluator does not model
    #: (see the module docstring). These rows are therefore about the declared
    #: condition only: each says "``github`` runs *as far as its own ``if:``
    #: is concerned*", which is a necessary and not a sufficient condition for
    #: the job running.
    #:
    #: ``version_check published no outputs at all`` carries more weight than
    #: its name suggests. It holds every output at ``null`` while leaving
    #: ``version_check.result`` at ``success``, which makes it the one row here
    #: that tells ``== 'false'`` from ``!= 'true'`` -- the #967 hole the three
    #: downstream tables did have. Both halves of it are load-bearing, and
    #: ``test_githubs_own_table_tells_equal_false_from_not_equal_true`` is what
    #: records that rather than leaving it to be rediscovered.
    GITHUB_ROWS = [
        ('a fresh version, not yet tagged', release_context(), True),
        ('the v* tag already exists',
         release_context(complete=('PCAPKIT_TAG_EXISTS',)), False),
        ('a v* tag push, not yet tagged', release_context(ref_name='v1.5.0'), True),
        ('a v* tag push and the tag already exists',
         release_context(ref_name='v1.5.0', complete=('PCAPKIT_TAG_EXISTS',)), True),
        ('version_check published no outputs at all',
         release_context(outputs_present=False), False),
    ]

    #: ``(row name, context, whether version_check must run)``. Its ``if:``
    #: is the workflow's outermost gate -- held by ``unit-tests`` until #1052
    #: moved ``version_check`` ahead of it: a ``workflow_run`` trigger only
    #: proceeds when the Vendor Update run that triggered it concluded
    #: ``success``, and every other trigger proceeds unconditionally.
    VERSION_CHECK_ROWS = [
        ('a v* tag push', release_context(event_name='push'), True),
        ('Vendor Update succeeded', release_context(), True),
        ('Vendor Update found nothing to update',
         release_context(workflow_run_conclusion='skipped'), False),
        ('Vendor Update failed',
         release_context(workflow_run_conclusion='failure'), False),
        ('Vendor Update was cancelled',
         release_context(workflow_run_conclusion='cancelled'), False),
    ]

    #: ``(row name, context, whether the release test gate must run)``. #1052:
    #: the gate runs only when a release will -- on a ``v*`` ref, or when any
    #: target's own evidence is not ``'true'``. The ``null`` row is the
    #: deliberate ``!= 'true'``: evidence nobody set runs the gate.
    #: :class:`TestNothingPublishesWithoutTheGate` checks the stronger claim
    #: exhaustively; these rows are the readable spot checks.
    UNIT_TESTS_ROWS = [
        ('a v* tag push, everything already published',
         release_context(ref_name='v1.5.0', complete=tuple(GATE_EVIDENCE.values())), True),
        ('nothing published yet', release_context(), True),
        ('everything already published -- the 2026-10-05 case',
         release_context(complete=tuple(GATE_EVIDENCE.values())), False),
        ('only PyPI incomplete',
         release_context(complete=('PCAPKIT_TAG_EXISTS', 'PCAPKIT_CONDA_TAG_EXISTS',
                                   'PCAPKIT_CONDA_COMPLETE')), True),
        ('only the PyPI evidence unknown',
         release_context(complete=tuple(GATE_EVIDENCE.values()),
                         unknown=('PCAPKIT_PYPI_COMPLETE',)), True),
        ('version_check failed',
         release_context(version_check='failure'), False),
        ('version_check skipped, no outputs',
         release_context(version_check='skipped', outputs_present=False), False),
    ]

    def _assert_rows(self, job: 'str',
                     rows: 'list[tuple[str, dict[str, object], bool]]') -> None:
        condition = declared_if(self.jobs[job])
        for name, context, expected in rows:
            with self.subTest(job=job, scenario=name):
                self.assertEqual(
                    evaluate_condition(condition, context), expected,
                    f'`{job}`\'s `if:` ({condition!r}) decides the wrong thing for '
                    f'{name!r}: it should {"run" if expected else "skip"}',
                )

    def test_the_tables_are_not_empty(self) -> None:
        """A table that generated no rows would pass every test below it.

        The same failure mode as ``test_the_scan_found_the_jobs``, and worse
        here: :func:`gate_violations` reports disagreements, so no rows means
        no disagreements means a green result for any condition at all,
        including ``if: false``. Both polarities have to be present too -- a
        table whose every row expects a skip is satisfied by a gate that never
        runs, which is #888 rather than a fix for it.

        """
        for job, expected in (('tag', 22), ('pypi', 22), ('conda', 26)):
            with self.subTest(job=job):
                rows = gate_rows(job)
                self.assertEqual(
                    len(rows), expected,
                    f'the scenario table for `{job}` generated {len(rows)} rows, '
                    f'expected {expected}; if an axis was added or removed on '
                    f'purpose, this count needs revisiting alongside it',
                )
                outcomes = {row[2] for row in rows}
                self.assertEqual(outcomes, {True, False})

    def test_the_table_covers_every_declared_dependency(self) -> None:
        """The scenario table has to name the same predecessors the file does.

        :data:`PUBLISHING_PREDECESSORS` is hand-written, so a ``needs:`` added
        to one of these jobs would otherwise be absent from every row --
        held at a running default and never varied, which is a gate the table
        silently stops checking. :data:`STRICT_PREDECESSORS` --
        ``version_check`` and, since #1052, ``unit-tests`` -- are added back
        here because they are deliberately *not* in that mapping: they are held
        to the stricter ``== 'success'`` alone, with no ``|| 'skipped'``.

        """
        for job in ('tag', 'pypi', 'conda'):
            with self.subTest(job=job):
                self.assertEqual(
                    set(declared_needs(self.jobs[job])),
                    set(PUBLISHING_PREDECESSORS[job]) | set(STRICT_PREDECESSORS),
                    f'`{job}`\'s `needs:` and the scenario table disagree about its '
                    f'predecessors, so at least one of them is not being varied',
                )

    def test_each_downstream_gate_agrees_with_its_truth_table(self) -> None:
        """The headline assertion: ``tag``, ``pypi`` and ``conda`` decide
        correctly on every row of :func:`gate_rows`.

        Which includes, as the four rows #962 was opened for, that each one is
        false for every value of ``needs.version_check.result`` but
        ``success``.

        """
        for job in ('tag', 'pypi', 'conda'):
            with self.subTest(job=job):
                violations = gate_violations(declared_if(self.jobs[job]), job)
                self.assertEqual(
                    violations, [],
                    f'`{job}`\'s `if:` disagrees with the release gate on '
                    f'{len(violations)} scenario(s): ' + '; '.join(violations),
                )

    def test_github_runs_when_its_own_v_tag_is_missing(self) -> None:
        """``github``'s gate, whose evidence is the ``v*`` tag it creates itself."""
        self._assert_rows('github', self.GITHUB_ROWS)

    def test_version_check_requires_a_successful_vendor_update(self) -> None:
        """``version_check``'s gate, the outermost one in the file."""
        self._assert_rows('version_check', self.VERSION_CHECK_ROWS)

    def test_the_release_test_gate_runs_only_when_something_is_publishable(self) -> None:
        """``unit-tests``'s gate, #1052."""
        self._assert_rows('unit-tests', self.UNIT_TESTS_ROWS)

    def test_release_status_runs_unless_the_run_was_cancelled(self) -> None:
        """``!cancelled()`` on its own, which is the whole of that condition.

        ``test_it_runs_regardless_of_what_upstream_did`` below accepts either
        ``cancelled()`` or ``always()``, as the escape hatch it checks for; the
        workflow's own comment says ``!cancelled()`` was chosen over
        ``always()`` deliberately, so that cancelling a run cancels the report
        too rather than leaving it to describe a run it cannot fully see.
        These two rows are what pin that choice.

        """
        condition = declared_if(self.jobs['release_status'])
        self.assertTrue(evaluate_condition(condition, release_context()))
        self.assertFalse(evaluate_condition(condition, release_context(cancelled=True)))

    def test_every_declared_if_is_evaluable(self) -> None:
        """Nothing in the file may leave the subset :func:`parse_condition` implements.

        The evaluator is only as good as its coverage of the file, and a
        condition it cannot parse is a condition it is not checking. Failing
        here, with the offending text in the message, is what keeps that from
        being a silent gap -- and the fix is to extend the subset, not to
        exempt the job.

        """
        for name, block in sorted(self.jobs.items()):
            condition = declared_if(block)
            if not condition:
                continue
            with self.subTest(job=name):
                try:
                    evaluate_condition(condition, release_context())
                except UnsupportedExpression as error:
                    self.fail(f'`{name}`\'s `if:` is outside the evaluated subset: {error}')


class TestGateMutationsChangeTheTruthTable(WorkflowMixin, unittest.TestCase):
    """Every mutation, applied to a scratch copy of each real condition, with
    the layer that rejects it recorded.

    This is the part the three earlier attempts at #961 got wrong: a test that
    passes against the current file says nothing about what it would catch.
    So each mutation below is actually applied and actually run, against both
    layers -- :func:`gate_violations` (the evaluator) and
    :func:`text_gate_violations` (the assertions
    :class:`TestEvidenceBasedGating` already makes) -- and the set of layers
    that rejected it is asserted exactly rather than "at least one did".

    Asserting the exact set is what makes the two layers' division of labour a
    recorded fact instead of a hope. Two rows carry the whole argument for
    keeping both:

    * **``true ||`` prefixed onto the whole expression** is rejected by the
      evaluator alone. It is #961's one knowingly-unclosed residual -- it
      leaves the compacted clause byte-identical, so no text assertion over
      the clause can see it -- and closing it is why #962 exists.
    * **Reversed operands** are rejected by the text layer alone, and *should*
      be: ``'success' == needs.version_check.result`` has exactly the same
      truth table, so the evaluator has nothing to say about it and saying
      something anyway would be wrong. It is a readability regression rather
      than a weakening. Had the text assertions been replaced instead of kept,
      nothing would notice it at all.

    """

    #: ``(name, substring, replacement, the layers that must reject it)``.
    #: ``<evidence>`` stands for the job's own evidence output, so one row
    #: covers all three jobs. Substitution rather than a rewrite because the
    #: mutations have to be the *small* edits a review round produces -- a
    #: regenerated condition would differ in ways nobody would have typed.
    #:
    #: The first eight are the mutations #962 names; the next five are this
    #: module's own, covering the clauses the issue only points at -- the
    #: publishing predecessors' equality pair, the ``startsWith``
    #: short-circuit, and reading somebody else's evidence. The ``!= 'true'``
    #: row is #967's, and is the only row here that the table as #962 left it
    #: did not catch at all: it is rejected by exactly one scenario -- the
    #: ``null`` evidence row :func:`gate_rows` grew for it -- and by no text
    #: assertion. The last three are #1052's, for the release test gate
    #: conjunct that issue added.
    MUTATIONS = [
        ('the && before the version_check clause becomes ||',
         "!cancelled() && needs.version_check.result",
         "!cancelled() || needs.version_check.result",
         ('evaluator', 'text')),
        ('the && after the version_check clause becomes ||',
         "needs.version_check.result == 'success' &&",
         "needs.version_check.result == 'success' ||",
         ('evaluator', 'text')),
        ("== 'success' becomes != 'failure'",
         "needs.version_check.result == 'success'",
         "needs.version_check.result != 'failure'",
         ('evaluator', 'text')),
        ("== 'success' also admits 'skipped', unparenthesised",
         "needs.version_check.result == 'success'",
         "needs.version_check.result == 'success' || needs.version_check.result == 'skipped'",
         ('evaluator', 'text')),
        ("== 'success' also admits 'skipped', parenthesised",
         "needs.version_check.result == 'success'",
         "(needs.version_check.result == 'success' || needs.version_check.result == 'skipped')",
         ('evaluator', 'text')),
        ('the comparison operands are reversed',
         "needs.version_check.result == 'success'",
         "'success' == needs.version_check.result",
         ('text',)),
        ("contains(fromJSON(...)) admits 'skipped'",
         "needs.version_check.result == 'success'",
         'contains(fromJSON(\'["success","skipped"]\'), needs.version_check.result)',
         ('evaluator', 'text')),
        ('the whole expression is prefixed with true ||',
         '${{ ', '${{ true || ',
         ('evaluator',)),
        ('the version_check conjunct is dropped entirely',
         "needs.version_check.result == 'success' && ", '',
         ('evaluator', 'text')),
        ('!cancelled() becomes always()',
         '!cancelled()', 'always()',
         ('evaluator',)),
        ("the publishing predecessor's equality pair becomes != 'failure'",
         "(needs.github.result == 'success' || needs.github.result == 'skipped')",
         "needs.github.result != 'failure'",
         ('evaluator', 'text')),
        ('a legitimately skipped publishing predecessor is no longer accepted',
         " || needs.github.result == 'skipped'", '',
         ('evaluator', 'text')),
        ("startsWith's prefix is emptied, so every ref matches",
         "startsWith(github.ref_name, 'v')", "startsWith(github.ref_name, '')",
         ('evaluator',)),
        ("the gate reads github's v* tag as its evidence again",
         '<evidence>', 'PCAPKIT_TAG_EXISTS',
         ('evaluator', 'text')),
        ("the evidence check becomes != 'true', so unknown evidence publishes",
         "<evidence> == 'false'", "<evidence> != 'true'",
         ('evaluator',)),
        ('the release test gate conjunct is dropped entirely',
         "needs.unit-tests.result == 'success' && ", '',
         ('evaluator', 'text')),
        ("the release test gate's == 'success' becomes != 'failure'",
         "needs.unit-tests.result == 'success'",
         "needs.unit-tests.result != 'failure'",
         ('evaluator', 'text')),
        ("the release test gate's == 'success' also admits 'skipped'",
         "needs.unit-tests.result == 'success'",
         "(needs.unit-tests.result == 'success' || needs.unit-tests.result == 'skipped')",
         ('evaluator', 'text')),
    ]

    def _mutate(self, condition: 'str', job: 'str', old: 'str', new: 'str') -> 'str':
        """``condition`` with ``old`` replaced by ``new``, and ``<evidence>`` resolved."""
        evidence = GATE_EVIDENCE[job]
        return condition.replace(old.replace('<evidence>', evidence),
                                 new.replace('<evidence>', evidence))

    def test_the_real_conditions_violate_neither_layer(self) -> None:
        """Both layers have to be clean on the file as it stands.

        Otherwise every row below reads as "caught" for the wrong reason, and
        this is also what keeps :func:`text_gate_violations` from drifting
        away from the assertions in :class:`TestEvidenceBasedGating` it
        mirrors: if the two ever disagree about the real file, one of them
        fails here.

        """
        for job in ('tag', 'pypi', 'conda'):
            with self.subTest(job=job):
                condition = declared_if(self.jobs[job])
                self.assertEqual(gate_violations(condition, job), [])
                self.assertEqual(text_gate_violations(condition, job), [])

    def test_every_mutation_actually_changes_the_condition(self) -> None:
        """A mutation whose substring is not in the file mutates nothing.

        And a no-op mutation is reported as caught by no layer, which reads
        identically to a mutation that defeats both. So the substring has to
        be checked for presence explicitly -- this is the assertion that
        stops the table below rotting quietly as the conditions are reworded.

        """
        for job in ('tag', 'pypi', 'conda'):
            condition = declared_if(self.jobs[job])
            for name, old, new, _ in self.MUTATIONS:
                with self.subTest(job=job, mutation=name):
                    mutant = self._mutate(condition, job, old, new)
                    self.assertIn(old.replace('<evidence>', GATE_EVIDENCE[job]), condition)
                    self.assertNotEqual(mutant, condition)

    def test_each_mutation_is_rejected_by_exactly_the_layers_it_should_be(self) -> None:
        for job in ('tag', 'pypi', 'conda'):
            condition = declared_if(self.jobs[job])
            for name, old, new, expected in self.MUTATIONS:
                with self.subTest(job=job, mutation=name):
                    mutant = self._mutate(condition, job, old, new)
                    rejected = []
                    if gate_violations(mutant, job):
                        rejected.append('evaluator')
                    if text_gate_violations(mutant, job):
                        rejected.append('text')
                    self.assertEqual(
                        tuple(rejected), tuple(expected),
                        f'mutating `{job}` so that {name} is rejected by '
                        f'{rejected or "no layer at all"}, expected {list(expected)}: '
                        f'{mutant!r}',
                    )

    def test_no_mutation_survives_both_layers(self) -> None:
        """Stated as the property that actually matters, separately from the
        bookkeeping above.

        ``test_each_mutation_is_rejected_by_exactly_the_layers_it_should_be``
        is precise and therefore brittle -- a future row's expectation could
        be edited to match whatever the code does, which is how a mutation
        table stops meaning anything. This one cannot be satisfied that way:
        every mutation has to be caught by *something*.

        """
        for job in ('tag', 'pypi', 'conda'):
            condition = declared_if(self.jobs[job])
            for name, old, new, _ in self.MUTATIONS:
                with self.subTest(job=job, mutation=name):
                    mutant = self._mutate(condition, job, old, new)
                    self.assertTrue(
                        gate_violations(mutant, job) or text_gate_violations(mutant, job),
                        f'mutating `{job}` so that {name} is caught by neither layer: '
                        f'{mutant!r}',
                    )

    def test_githubs_own_table_tells_equal_false_from_not_equal_true(self) -> None:
        """#967 for ``github``, which the table above cannot reach.

        Both layers are downstream-only -- :func:`gate_rows` keys on
        :data:`PUBLISHING_PREDECESSORS`, which has no ``github`` entry, and
        :func:`text_gate_violations` says in its own docstring why ``github``
        is not a fourth case of the assertions it mirrors. So the same question
        has to be asked of ``github``'s own table separately, and the answer
        measured rather than assumed: the hole #967 found in the three
        downstream tables is *not* in this one.
        ``TestGateExpressionsEvaluateCorrectly.GITHUB_ROWS`` already
        discriminates, via ``version_check published no outputs at all`` --
        which holds every output at ``null`` while leaving
        ``version_check.result`` at ``success``, so this gate's evidence clause
        alone decides the row.

        That is a property of that row rather than of the gate, which is why it
        is pinned here: a row rewritten to fail ``version_check`` as well, or
        dropped as redundant, would take the discrimination with it and nothing
        else in this module would notice. The assertion is about the *declared*
        condition, per the framing on ``GITHUB_ROWS``: the mutation turns a row
        that definitely skips into one whose ``if:`` no longer says so, and
        whether the job then runs is the implicit ``success()``'s business.

        """
        condition = declared_if(self.jobs['github'])
        evidence = GATE_EVIDENCE['github']
        mutant = condition.replace(f"{evidence} == 'false'", f"{evidence} != 'true'")
        self.assertNotEqual(mutant, condition)

        rows = TestGateExpressionsEvaluateCorrectly.GITHUB_ROWS
        disagreements = [name for name, context, expected in rows
                         if evaluate_condition(mutant, context) != expected]
        self.assertTrue(
            disagreements,
            f'no row of `GITHUB_ROWS` tells `{evidence} == \'false\'` from '
            f'`{evidence} != \'true\'`, so `github`\'s gate could be weakened into '
            f'one that runs on evidence nothing established without this table '
            f'noticing: {mutant!r}',
        )


class TestTheExpressionEvaluator(unittest.TestCase):
    """The evaluator against hand-written expressions, not against the workflow.

    #962 settled that the text assertions stay partly because an evaluator bug
    would otherwise leave the gates unpinned while the suite reported green.
    This class is the other half of that answer: the semantics the gate tables
    above depend on, each pinned where a mistake in it is a failure here
    rather than a quietly wrong row there. Like
    :class:`TestScannerRecognisesTheDefect`, it reads fixtures rather than the
    repository, so it keeps meaning the same thing after the file moves on.

    """

    def evaluate(self, condition: 'str', **overrides: 'object') -> 'bool':
        return evaluate_condition(condition, release_context(**overrides))  # type: ignore[arg-type]

    def test_and_binds_tighter_than_or(self) -> None:
        """The precedence the ``&&``-to-``||`` mutations turn on.

        If ``||`` bound tighter, ``false || true && false`` would be true, and
        every row that catches a ``&&``-to-``||`` slip would be catching it by
        accident.

        """
        self.assertFalse(self.evaluate('${{ false || true && false }}'))
        self.assertTrue(self.evaluate('${{ false && false || true }}'))
        self.assertTrue(self.evaluate('${{ true || false && false }}'))
        self.assertTrue(self.evaluate('${{ (false || true) && true }}'))

    def test_or_short_circuits_without_evaluating_its_right_operand(self) -> None:
        """Which is exactly what a ``true ||`` prefix does to a whole gate.

        The right operand here would raise if it were evaluated, since
        ``steps`` is a context no scenario models -- so this passing is proof
        that it was not.

        """
        self.assertTrue(self.evaluate("${{ true || steps.nope.outputs.x == 'y' }}"))
        with self.assertRaises(UnsupportedExpression):
            self.evaluate("${{ false || steps.nope.outputs.x == 'y' }}")

    def test_a_bare_expression_is_accepted_as_well_as_an_interpolated_one(self) -> None:
        """Actions accepts both for ``if:``; this workflow only uses the second."""
        self.assertTrue(self.evaluate("needs.version_check.result == 'success'"))
        self.assertTrue(self.evaluate("${{ needs.version_check.result == 'success' }}"))

    def test_string_comparison_ignores_case(self) -> None:
        """Documented Actions behaviour, and the reason the evaluator cannot
        be relied on to catch a mutation that only changes case -- which is
        why it is not claimed to.

        """
        self.assertTrue(self.evaluate("${{ 'SUCCESS' == 'success' }}"))
        self.assertTrue(self.evaluate("${{ startsWith('V1.5.0', 'v') }}"))

    def test_a_string_never_equals_a_boolean(self) -> None:
        """``'true' == true`` is false in Actions: mixed types are cast to a
        number, and a non-numeric string casts to ``NaN``.

        Worth pinning because the evidence outputs are the *strings*
        ``'true'`` and ``'false'``, so a mutation comparing one to a boolean
        literal is a plausible edit whose answer is not the obvious one.

        """
        self.assertFalse(self.evaluate("${{ 'true' == true }}"))
        self.assertFalse(self.evaluate("${{ 'false' == false }}"))
        self.assertTrue(self.evaluate("${{ 'false' == 'false' }}"))

    def test_an_unset_property_is_null_and_equals_nothing_useful(self) -> None:
        """A skipped ``version_check`` publishes no outputs at all, and the
        gates below it must not read that as "evidence says incomplete".

        """
        condition = "${{ needs.version_check.outputs.PCAPKIT_PYPI_COMPLETE == 'false' }}"
        self.assertTrue(self.evaluate(condition))
        self.assertFalse(self.evaluate(condition, outputs_present=False))
        self.assertFalse(self.evaluate("${{ needs.nope.result == 'success' }}"))

    def test_an_unknown_context_root_raises_rather_than_answering_null(self) -> None:
        """An unset property is ``null``; an unmodelled *context* is a gap.

        Answering ``null`` for ``steps.*`` or ``env.*`` would let a scenario
        row be decided by something the row never described, which is the
        quiet failure this whole module is about.

        """
        for condition in ("${{ steps.check_tag.outputs.exists == 'true' }}",
                          "${{ env.PCAPKIT_VERSION == '1.5.0' }}"):
            with self.subTest(condition=condition):
                with self.assertRaises(UnsupportedExpression):
                    self.evaluate(condition)

    def test_contains_over_a_fromjson_array_is_a_membership_test(self) -> None:
        """Neither function appears in the workflow. Both are implemented so
        that the mutation spelling the gate as a membership test is
        *evaluated* -- a parse error there would look like a caught mutation
        while proving nothing about the truth table.

        """
        condition = ('${{ contains(fromJSON(\'["success","skipped"]\'), '
                     'needs.version_check.result) }}')
        self.assertTrue(self.evaluate(condition, version_check='skipped'))
        self.assertFalse(self.evaluate(condition, version_check='failure'))
        self.assertTrue(self.evaluate("${{ contains('conda-1.5.0+0', 'conda-') }}"))

    def test_always_is_true_and_cancelled_comes_from_the_scenario(self) -> None:
        self.assertTrue(self.evaluate('${{ always() }}'))
        self.assertTrue(self.evaluate('${{ always() }}', cancelled=True))
        self.assertFalse(self.evaluate('${{ !cancelled() }}', cancelled=True))

    def test_a_status_function_no_scenario_models_raises(self) -> None:
        """``success()`` and ``failure()`` are parsed and not answered.

        No gate in this workflow calls either, and a fabricated answer would
        decide a scenario row that nothing had modelled. Raising says so;
        the fix would be to give :func:`release_context` a knob for it.

        """
        with self.assertRaises(UnsupportedExpression):
            self.evaluate('${{ success() }}')

    def test_a_doubled_quote_inside_a_literal_is_one_literal(self) -> None:
        self.assertTrue(self.evaluate("${{ 'it''s' == 'IT''S' }}"))

    def test_syntax_outside_the_subset_raises_rather_than_guessing(self) -> None:
        """Each of these is a real Actions expression this module does not
        implement, and each has to fail loudly rather than be approximated.

        """
        for condition in ('${{ 1 > 2 }}',                       # no ordering operators
                          "${{ join(needs.*.result, ',') }}",   # no `*` and no `join`
                          '${{ toJSON(needs) }}',               # not in the subset
                          '${{ needs.version_check.result == }}',
                          '${{ startsWith(github.ref_name) }}',  # wrong arity
                          "${{ 'a' }} && ${{ 'b' }}"):          # a template, not an expression
            with self.subTest(condition=condition):
                with self.assertRaises(UnsupportedExpression):
                    self.evaluate(condition)


class TestMarkersStillMatch(WorkflowMixin, unittest.TestCase):
    """:data:`PUBLISHING_MARKERS` has to keep matching the file it describes."""

    def test_each_marker_matches_at_least_one_job(self) -> None:
        """A marker that matches nothing is a rule that has stopped being checked.

        This is the failure mode of the test above: bump ``action-gh-release`` to a
        fork under another name, or replace the ``git push`` with an action, and
        ``test_every_publishing_job_declares_an_environment`` keeps passing while
        checking less. Better to fail here, where the message says which marker
        went stale.

        """
        bodies = {name: strip_comments(block) for name, block in self.jobs.items()}
        unmatched = [marker for marker in PUBLISHING_MARKERS
                     if not any(marker in body for body in bodies.values())]
        self.assertEqual(
            unmatched, [],
            'these publishing markers no longer match any job, so they are '
            f'checking nothing: {unmatched}',
        )

    def test_the_test_gate_is_not_mistaken_for_a_publisher(self) -> None:
        """``unit-tests``, ``version_check`` and ``release_status`` have no
        outward effect.

        ``unit-tests`` could not carry an ``environment:`` even if it wanted one --
        a job that calls a reusable workflow may not declare one -- so a marker
        broad enough to match it would make the rule unsatisfiable.
        ``release_status`` (#888) only reads the ``needs:`` context and prints
        ``::notice``/``::warning``/``::error`` annotations; it touches neither
        the repository nor either package index.

        """
        for name in ('unit-tests', 'version_check', 'release_status'):
            with self.subTest(job=name):
                self.assertEqual(publishing_reasons(self.jobs[name]), [])


class TestReleaseStatusReportsHonestly(WorkflowMixin, unittest.TestCase):
    """#888's other job: a run that released nothing must say why, in one
    place, regardless of which upstream job or gate made it release nothing.

    """

    def test_it_depends_directly_on_every_other_job(self) -> None:
        """Not a closure -- a *direct* ``needs:`` on each one.

        ``needs.<job>.result`` and ``needs.<job>.outputs`` are only readable
        for jobs actually named in this job's own ``needs:``; a transitive
        dependency (the shortcut :class:`TestGatedJobsDependOnGithub` allows
        for the other four jobs) would leave this one unable to see, say,
        ``pypi``'s result at all.

        """
        self.assertEqual(
            declared_needs(self.jobs['release_status']),
            ['unit-tests', 'version_check', 'github', 'tag', 'pypi', 'conda'],
        )

    def test_it_runs_regardless_of_what_upstream_did(self) -> None:
        """``unit-tests`` and ``version_check`` can each skip before any
        evidence output exists at all, so this job cannot condition on their
        outputs the way the gated jobs do -- it has to bypass the default
        status check outright.

        """
        condition = declared_if(self.jobs['release_status'])
        self.assertTrue(
            'cancelled()' in condition or 'always()' in condition,
            f'`release_status`\'s `if:` ({condition!r}) would otherwise skip '
            f'the moment anything it depends on skips, which is precisely the '
            f'situation it exists to report on',
        )

    def test_it_has_no_outward_effect(self) -> None:
        self.assertIsNone(declared_environment(self.jobs['release_status']))
        self.assertEqual(publishing_reasons(self.jobs['release_status']), [])

    def test_the_888_shape_is_reported_as_a_real_failure(self) -> None:
        """The one case this job must never let pass as green: the tag exists,
        the release is not fully out, and yet nothing ran to finish it. With
        the evidence-based guards in place this should be unreachable, but if
        it is ever reached it must fail loudly, not print a warning and exit 0
        the way every other branch does.

        """
        block = self.jobs['release_status']
        self.assertIn('::error title=Stranded partial release (#888)', block)
        self.assertIn('exit 1', block)

    def test_routine_skips_are_quiet(self) -> None:
        """The steady state -- nothing to release, or a release that just
        completed -- must not read as a problem.

        """
        block = self.jobs['release_status']
        self.assertIn('::notice title=Nothing to release', block)
        self.assertIn('::notice title=Release complete', block)


class TestReleaseStatusScriptExecutesCorrectly(WorkflowMixin, unittest.TestCase):
    """Actually runs ``release_status``'s shell script, rather than only
    grepping it, over a table of the shapes a real run can take.

    A cross-review of the #888 change found that an earlier revision of this
    script demanded the same outcome (all four release jobs ``skipped``, or
    all four ``success``) before treating a run as complete, which reads a
    self-heal -- ``github``/``tag`` skipping because their artefacts already
    exist, ``pypi``/``conda`` running and succeeding because theirs did not --
    as the #888 shape itself, erroring on the run that just fixed it. Every
    other test in this module is a string assertion over the YAML, so none
    of them executed the script and none of them could have caught that.

    """

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if shutil.which('bash') is None:
            raise unittest.SkipTest('bash not found on PATH')
        cls.script = block_scalar_after(cls.jobs['release_status'], _RUN_LITERAL)  # type: ignore[attr-defined]

    def _run(self, overrides: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
        env = {
            'PCAPKIT_EVENT_NAME': 'workflow_run',
            'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'success',
            'PCAPKIT_UNIT_TESTS': 'success',
            'PCAPKIT_VERSION_CHECK': 'success',
            'PCAPKIT_GITHUB_JOB': 'success',
            'PCAPKIT_TAG_JOB': 'success',
            'PCAPKIT_PYPI_JOB': 'success',
            'PCAPKIT_CONDA_JOB': 'success',
            'PCAPKIT_VERSION': '1.5.0',
            'PCAPKIT_TAG_EXISTS': 'false',
            'PCAPKIT_CONDA_TAG_EXISTS': 'false',
            'PCAPKIT_PYPI_COMPLETE': 'false',
            'PCAPKIT_CONDA_COMPLETE': 'false',
        }
        env.update(overrides)
        return subprocess.run(  # type: ignore[return-value]
            ['bash', '-c', self.script],  # type: ignore[attr-defined]
            env=env, capture_output=True, text=True, timeout=scale_timeout(10),
        )

    #: ``(scenario name, env overrides, expected title substring, expected exit code)``.
    #: The self-heal row is the one an earlier revision of the script got
    #: wrong: mixed results, all reconciled against their own evidence.
    VECTORS = [
        (
            'vendor_update_had_nothing_to_do',
            {'PCAPKIT_VERSION_CHECK': 'skipped', 'PCAPKIT_UNIT_TESTS': 'skipped',
             'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'skipped'},
            '::notice title=Nothing to release',
            0,
        ),
        (
            'vendor_update_itself_broke',
            {'PCAPKIT_VERSION_CHECK': 'skipped', 'PCAPKIT_UNIT_TESTS': 'skipped',
             'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'failure'},
            '::warning title=Release skipped',
            0,
        ),
        (
            'version_check_failed',
            {
                'PCAPKIT_VERSION_CHECK': 'failure', 'PCAPKIT_UNIT_TESTS': 'skipped',
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
            },
            '::warning title=Release blocked before it could start',
            0,
        ),
        (
            # #1052: the gate now runs after version_check, so its failure
            # is reported with the evidence already in hand.
            'release_test_gate_failed',
            {
                'PCAPKIT_UNIT_TESTS': 'failure',
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
            },
            '::warning title=Release blocked by the test gate',
            0,
        ),
        (
            # #1052: the 2026-10-05 shape -- a successful Vendor Update with
            # nothing publishable. The gate skips, and that is quiet.
            'release_test_gate_skipped_nothing_publishable',
            {
                'PCAPKIT_UNIT_TESTS': 'skipped',
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
                'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                'PCAPKIT_PYPI_COMPLETE': 'true', 'PCAPKIT_CONDA_COMPLETE': 'true',
            },
            '::notice title=Nothing to release',
            0,
        ),
        (
            # #1052: a gate predicate that drifted and skipped with PyPI still
            # incomplete. Every publisher skips behind it, and it must be loud.
            'release_test_gate_skipped_with_work_outstanding',
            {
                'PCAPKIT_UNIT_TESTS': 'skipped',
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
                'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                'PCAPKIT_CONDA_COMPLETE': 'true',
            },
            '::error title=Stranded partial release (#888)',
            1,
        ),
        (
            'steady_state_already_fully_released',
            {
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
                'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                'PCAPKIT_PYPI_COMPLETE': 'true', 'PCAPKIT_CONDA_COMPLETE': 'true',
            },
            '::notice title=Nothing to release',
            0,
        ),
        (
            'self_heal_mixed_skip_and_success',
            {
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'success', 'PCAPKIT_CONDA_JOB': 'success',
                'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                'PCAPKIT_PYPI_COMPLETE': 'false', 'PCAPKIT_CONDA_COMPLETE': 'false',
            },
            '::notice title=Release complete',
            0,
        ),
        (
            'fresh_full_release_all_four_ran',
            {},  # every override already defaults to `success` / `false`
            '::notice title=Release complete',
            0,
        ),
        (
            'a_release_job_genuinely_failed',
            {
                'PCAPKIT_PYPI_JOB': 'failure',
                'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                'PCAPKIT_CONDA_COMPLETE': 'true',
            },
            '::warning title=Release did not complete',
            0,
        ),
        (
            'stranded_partial_the_888_shape',
            {
                'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped',
                'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_CONDA_JOB': 'skipped',
                'PCAPKIT_TAG_EXISTS': 'true',  # github's own evidence: reconciled
                # everything else still incomplete, yet its job skipped anyway
            },
            '::error title=Stranded partial release (#888)',
            1,
        ),
    ]

    def test_each_scenario_takes_the_right_branch(self) -> None:
        for name, overrides, expected_marker, expected_rc in self.VECTORS:
            with self.subTest(scenario=name):
                result = self._run(overrides)
                self.assertEqual(
                    result.returncode, expected_rc,
                    f'scenario {name!r} exited {result.returncode}, expected '
                    f'{expected_rc}. stdout={result.stdout!r} stderr={result.stderr!r}',
                )
                self.assertIn(
                    expected_marker, result.stdout,
                    f'scenario {name!r} did not print {expected_marker!r}. '
                    f'stdout={result.stdout!r}',
                )


class TestPythonSnippetsSurviveOlderInterpreters(WorkflowMixin, unittest.TestCase):
    """A cross-review of the #888 change found that the ``python3 -c``
    snippets computing PyPI/Anaconda evidence had their source indented by
    the surrounding YAML block scalar, which only ``compile()``s on Python
    3.14 -- 3.9 through 3.13 all raise ``IndentationError: unexpected
    indent``, measured directly. Two of the three run before
    ``actions/setup-python`` installs a chosen version, so ``python3`` there
    is the runner image's default (3.12 on ``ubuntu-latest`` as of writing),
    never 3.14. #905's fix feeds one line per ``printf`` argument instead, so
    no line in the actual Python source is indented that Python did not
    itself put there -- this class is what actually runs each snippet under
    an older interpreter to check that claim, rather than trusting it.

    """

    def test_the_scan_found_the_snippets(self) -> None:
        """A scan that finds nothing would pass every test below it."""
        snippets = printf_python_snippets(self.text)  # type: ignore[attr-defined]
        self.assertEqual(
            len(snippets), 3,
            'expected exactly 3 printf-fed python3 snippets (the PyPI and '
            'Anaconda evidence checks in version_check, plus the per-leg '
            'check in conda); found a different count -- if that is '
            'intended, this expectation needs revisiting alongside it',
        )

    def test_each_snippet_runs_without_an_indentation_error(self) -> None:
        interpreter = pre_314_interpreter()
        if interpreter is None:
            self.skipTest('no Python interpreter older than 3.14 found on PATH')

        version = subprocess.run(
            [interpreter, '--version'], capture_output=True, text=True,
        ).stdout.strip()

        for index, snippet in enumerate(printf_python_snippets(self.text)):  # type: ignore[attr-defined]
            with self.subTest(snippet=index):
                # `$target_platform`/`$py_tag` are bash interpolation the real
                # step performs before Python ever sees this text; harmless
                # stand-ins reproduce the same shape without needing bash here.
                source = (
                    snippet
                    .replace('$target_platform', 'linux-64')
                    .replace('$py_tag', 'py310')
                )
                result = subprocess.run(
                    [interpreter, '-'], input=source, capture_output=True,
                    text=True, timeout=scale_timeout(10),
                )
                self.assertNotIn(
                    'IndentationError', result.stderr,
                    f'snippet {index} raised IndentationError under '
                    f'{interpreter} ({version}):\n{result.stderr}',
                )


class TestScannerRecognisesTheDefect(unittest.TestCase):
    """The scanner, against the shape #641 actually had.

    Unlike everything above, these read a fixture rather than the repository, so
    they keep pinning the defect after the file has moved on.

    """

    #: The ``pypi`` job as #641 found it, trimmed to the keys that matter.
    COMMENTED_OUT = (
        'jobs:\n'
        '  pypi:\n'
        '    runs-on: ubuntu-latest\n'
        '    ## Specifying a GitHub environment is optional, but strongly encouraged\n'
        '    #environment: release\n'
        '    #permissions:\n'
        '    #  # IMPORTANT: this permission is mandatory for trusted publishing\n'
        '    #  id-token: write\n'
        '    permissions:\n'
        '      contents: write\n'
        '      id-token: write\n'
        '    steps:\n'
        '      - name: Publish to PyPI\n'
        '        uses: pypa/gh-action-pypi-publish@release/v1\n'
    )

    def test_a_commented_environment_is_not_a_gate(self) -> None:
        """``#environment: release`` is prose, and must read as ungated."""
        block = job_blocks(self.COMMENTED_OUT)['pypi']

        self.assertIsNone(declared_environment(block))
        self.assertEqual(publishing_reasons(block),
                         ['uploads a distribution to PyPI or TestPyPI'])

    def test_an_explaining_comment_is_not_evidence_of_publishing(self) -> None:
        """The converse: a comment naming an action does not make a job publish."""
        block = job_blocks(
            'jobs:\n'
            '  notes:\n'
            '    runs-on: ubuntu-latest\n'
            '    # Unlike softprops/action-gh-release, this uploads nothing.\n'
            '    steps:\n'
            '      - run: echo hello\n'
        )['notes']

        self.assertEqual(publishing_reasons(block), [])

    def test_the_mapping_form_of_environment_is_read(self) -> None:
        """``environment:`` with a nested ``name:`` and ``url:`` is still a gate."""
        block = job_blocks(
            'jobs:\n'
            '  pypi:\n'
            '    environment:\n'
            '      name: pypi\n'
            '      url: https://pypi.org/p/pypcapkit\n'
            '    steps:\n'
            '      - uses: pypa/gh-action-pypi-publish@release/v1\n'
        )['pypi']

        self.assertEqual(declared_environment(block), 'pypi')

    def test_a_quoted_inline_environment_is_read(self) -> None:
        block = job_blocks(
            'jobs:\n'
            '  pypi:\n'
            "    environment: 'pypi'  # quoted, and with a trailing comment\n"
        )['pypi']

        self.assertEqual(declared_environment(block), 'pypi')

    def test_jobs_end_at_the_next_top_level_key(self) -> None:
        """A key after ``jobs:`` is not a job, however tempting its name."""
        blocks = job_blocks(
            'jobs:\n'
            '  build:\n'
            '    runs-on: ubuntu-latest\n'
            'environment: not-a-job\n'
        )

        self.assertEqual(sorted(blocks), ['build'])


class TestYAMLAgreesWithTheScanner(WorkflowMixin, unittest.TestCase):
    """The hand-rolled scan has to say what a real YAML parse says."""

    def test_the_same_job_to_environment_mapping(self) -> None:
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML is not in the test extra; the textual scan is '
                          'asserted by TestPublishingJobsAreGated')

        parsed = yaml.safe_load(self.text)
        self.assertIsInstance(parsed, dict, 'the workflow is not a YAML mapping')

        expected = {name: job.get('environment')
                    for name, job in parsed['jobs'].items()}
        scanned = {name: declared_environment(block) for name, block in self.jobs.items()}

        self.assertEqual(scanned, expected,
                         'the indentation-based scanner and yaml.safe_load disagree '
                         'about which jobs are gated')

    def test_the_same_job_to_needs_mapping(self) -> None:
        """:func:`declared_needs` against the same real parse, for the same reason."""
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML is not in the test extra; the textual scan is '
                          'asserted by TestGatedJobsDependOnGithub')

        parsed = yaml.safe_load(self.text)
        self.assertIsInstance(parsed, dict, 'the workflow is not a YAML mapping')

        expected = {name: list(job.get('needs', []))
                    for name, job in parsed['jobs'].items()}
        scanned = {name: declared_needs(block) for name, block in self.jobs.items()}

        self.assertEqual(scanned, expected,
                         'the indentation-based `needs:` scanner and yaml.safe_load '
                         'disagree about the dependency graph')

    def test_the_same_job_to_if_mapping(self) -> None:
        """:func:`declared_if` against the same real parse, for the same reason.

        This is the one that actually exercises the folded block-scalar form
        #888 introduces -- ``test_the_same_job_to_environment_mapping`` and
        ``test_the_same_job_to_needs_mapping`` above only ever see single-line
        values, so neither would have caught a folding mistake the way this
        one does.

        """
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML is not in the test extra; the textual scan is '
                          'asserted by TestEvidenceBasedGating')

        parsed = yaml.safe_load(self.text)
        self.assertIsInstance(parsed, dict, 'the workflow is not a YAML mapping')

        expected = {name: (job.get('if') or '') for name, job in parsed['jobs'].items()}
        scanned = {name: declared_if(block) for name, block in self.jobs.items()}

        self.assertEqual(scanned, expected,
                         'the indentation-based `if:` scanner and yaml.safe_load '
                         'disagree about at least one job\'s condition')


if __name__ == '__main__':
    unittest.main()
