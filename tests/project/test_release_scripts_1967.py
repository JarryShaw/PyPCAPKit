# -*- coding: utf-8 -*-
"""#1967: :file:`util/release_tags.py` and :file:`util/release_upload.py`, run as Create Release's steps run them.

* :class:`TestReleaseTags` runs both of ``release_tags.py``'s commands against a
  stand-in ``git``: each outcome of "Check the release tags name this run's
  commit" and of "Check which commit the version's tag names".
* :class:`TestReleaseUpload` runs ``release_upload.py``, "Upload package to
  GitHub Release", against a stand-in ``gh``.
* :class:`TestTheFormerShellAgrees` runs those steps' inline shell form, the
  reference the scripts must match, against the same stand-ins and requires the same status, standard
  output and error, ``$GITHUB_OUTPUT`` and calls.
* :class:`TestTheStepsRunTheScripts` pins each step to its script, after a whole
  checkout of the repository, and the scripts to Python 3.8's syntax.

Their runs against a real repository, and the steps' ``env:``, are
:mod:`tests.project.test_release_tags_the_run_sha_1634`'s.

"""

from __future__ import annotations

import ast
import functools
import os
import pathlib
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._workflows import load, steps
from tests.project.test_requires_python_floor_2051 import FLOOR

if TYPE_CHECKING:
    from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL = ROOT / 'util'
WORKFLOW = 'create-release.yml'
BASH = shutil.which('bash') or ''

RUN = '1' * 40
OTHER = '2' * 40

#: A ``git`` answering as the scripts call it: ``rev-parse --verify`` with
#: ``$RUN_COMMIT`` or ``$RUN_FAIL``'s status (``TERM``, killed by SIGTERM), each
#: ``fetch`` with a line on standard output and, under ``$FETCH_FAIL``, an error,
#: and ``rev-parse -q --verify refs/tags/<tag>^{commit}`` from ``$GIT_TAGS``.
FAKE_GIT = r'''#!/bin/sh
printf '%s\n' "$*" >> "$GIT_LOG"
case "$1" in
  fetch)
    printf 'fetching %s\n' "$5"
    [ -z "${FETCH_FAIL:-}" ] || { echo "fatal: couldn't find remote ref $5" >&2; exit 128; }
    ;;
  rev-parse)
    if [ "$2" = --verify ]; then
      [ -n "${RUN_FAIL:-}" ] || { echo "$RUN_COMMIT"; exit 0; }
      echo "fatal: Needed a single revision" >&2
      [ "$RUN_FAIL" != TERM ] || kill -TERM $$
      exit "$RUN_FAIL"
    fi
    tag="${4#refs/tags/}"
    tag="${tag%'^{commit}'}"
    sha="$(awk -v tag="$tag" '$1 == tag { print $2 }' "$GIT_TAGS")"
    [ -n "$sha" ] || exit 1
    echo "$sha"
    ;;
  *) exit 99 ;;
esac
'''

#: A ``gh`` answering ``release view`` with ``$GH_ASSETS``, or failing with
#: ``$VIEW_FAIL``'s status, and ``release upload`` with a line, or failing with
#: ``$UPLOAD_FAIL``'s.
FAKE_GH = r'''#!/bin/sh
printf '%s\n' "$*" >> "$GH_LOG"
case "$1 $2" in
  'release view')
    [ -z "${VIEW_FAIL:-}" ] || { echo 'release not found' >&2; exit "$VIEW_FAIL"; }
    cat "$GH_ASSETS"
    ;;
  'release upload')
    [ -z "${UPLOAD_FAIL:-}" ] || { echo "HTTP 502: $4 failed" >&2; exit "$UPLOAD_FAIL"; }
    printf 'uploaded %s\n' "$4"
    ;;
  *) exit 99 ;;
esac
'''

#: "Check the release tags name this run's commit" in ``github``, ``pypi`` and
#: ``conda``, in its inline shell form, the reference :file:`util/release_tags.py`
#: must match.
FORMER_CHECK = textwrap.dedent(r'''
    set -euo pipefail

    run_commit="$(git rev-parse --verify "${PCAPKIT_RUN_SHA}^{commit}")"
    for tag in ${PCAPKIT_TAGS}; do
      git fetch --quiet --force origin "refs/tags/${tag}:refs/tags/${tag}" || true
      tagged="$(git rev-parse -q --verify "refs/tags/${tag}^{commit}" || true)"
      if [ "$tagged" != "$run_commit" ]; then
        echo "::error title=${tag} is not this run's commit (#1634)::${tag} resolves to '${tagged:-no commit}', but this run was created for ${run_commit}. Refusing to publish this tree under it: every artefact of a release comes from its tag's commit, so finish that release by re-running the run created for that commit."
        exit 1
      fi
      echo "${tag} -> ${run_commit}"
    done
''').lstrip()

#: "Check which commit the version's tag names" in ``version_check``, likewise.
FORMER_OWNER = textwrap.dedent(r'''
    set -euo pipefail

    run_commit="$(git rev-parse --verify "${PCAPKIT_RUN_SHA}^{commit}")"
    git fetch --quiet --force origin "refs/tags/${PCAPKIT_TAG}:refs/tags/${PCAPKIT_TAG}" || true
    tagged="$(git rev-parse -q --verify "refs/tags/${PCAPKIT_TAG}^{commit}" || true)"
    elsewhere=false
    if [ -n "$tagged" ] && [ "$tagged" != "$run_commit" ]; then
      elsewhere=true
    fi

    echo "${PCAPKIT_TAG} -> ${tagged:-no commit}; this run's commit is ${run_commit}; released elsewhere: ${elsewhere}"
    echo "PCAPKIT_RELEASED_AT=${tagged}" >> "$GITHUB_OUTPUT"
    echo "PCAPKIT_RELEASED_ELSEWHERE=${elsewhere}" >> "$GITHUB_OUTPUT"
''').lstrip()

#: "Upload package to GitHub Release" in ``pypi`` and ``conda``, in its inline
#: shell form, the reference :file:`util/release_upload.py` must match.
FORMER_UPLOAD = textwrap.dedent(r'''
    set -euo pipefail

    published="$(gh release view "$PCAPKIT_RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --json assets --jq '.assets[] | [.name, .state] | @tsv')"
    while IFS= read -r pattern; do
      [ -n "$pattern" ] || continue
      for file in $pattern; do
        if [ ! -f "$file" ]; then
          echo "::error title=Nothing to upload::'${pattern}' matches no file, so ${PCAPKIT_RELEASE_TAG} would go without it."
          exit 1
        fi
        name="${file##*/}"
        state=""
        while IFS=$'\t' read -r asset asset_state; do
          [ "$asset" != "$name" ] || state="$asset_state"
        done <<< "$published"
        if [ "$state" = uploaded ]; then
          echo "::notice title=${name} already on ${PCAPKIT_RELEASE_TAG}::Left as published (#1640): this run's rebuild is not byte-identical to it."
          continue
        fi
        if [ -n "$state" ]; then
          echo "::warning title=${name} uploaded again::${PCAPKIT_RELEASE_TAG} holds it in state '${state}', not 'uploaded' -- an upload that failed partway -- so it is deleted and this file uploaded in its place."
          gh release upload "$PCAPKIT_RELEASE_TAG" "$file" --repo "$GITHUB_REPOSITORY" --clobber
        else
          gh release upload "$PCAPKIT_RELEASE_TAG" "$file" --repo "$GITHUB_REPOSITORY"
        fi
        echo "${name} -> ${PCAPKIT_RELEASE_TAG}"
      done
    done <<< "$PCAPKIT_ASSETS"
''').lstrip()

#: Each step, as ``(job, step name)``, and the ``run:`` it holds.
STEPS = {
    ('version_check', "Check which commit the version's tag names"): 'python3 util/release_tags.py owner',
    ('github', "Check the release tags name this run's commit"): 'python3 util/release_tags.py check',
    ('pypi', "Check the release tags name this run's commit"): 'python3 util/release_tags.py check',
    ('conda', "Check the release tags name this run's commit"): 'python3 util/release_tags.py check',
    ('pypi', 'Upload package to GitHub Release'): 'python3 util/release_upload.py',
    ('conda', 'Upload package to GitHub Release'): 'python3 util/release_upload.py',
}

#: ``release_tags.py check``'s outcomes: ``(name, $PCAPKIT_TAGS, tags on origin, extra env)``.
CHECK_CASES = (
    ('every tag names the run', 'v1.5.0 conda-1.5.0+0', {'v1.5.0': RUN, 'conda-1.5.0+0': RUN}, {}),
    ('tabs, newlines and runs of spaces split', ' v1.5.0\t\tconda-1.5.0+0\n  v1.5.0 ',
     {'v1.5.0': RUN, 'conda-1.5.0+0': RUN}, {}),
    ('the second names another commit', 'v1.5.0 conda-1.5.0+0', {'v1.5.0': RUN, 'conda-1.5.0+0': OTHER}, {}),
    ('the first is missing', 'v1.5.0 conda-1.5.0+0', {'conda-1.5.0+0': RUN}, {}),
    ('a failed fetch is ignored', 'v1.5.0', {'v1.5.0': RUN}, {'FETCH_FAIL': '1'}),
    ('a failed fetch of a missing tag', 'v1.5.0', {}, {'FETCH_FAIL': '1'}),
    ('no tags at all', '', {}, {}),
    ('an unresolvable run sha', 'v1.5.0', {'v1.5.0': RUN}, {'RUN_FAIL': '128'}),
    ('a run sha whose git is killed', 'v1.5.0', {'v1.5.0': RUN}, {'RUN_FAIL': 'TERM'}),
)

#: ``release_tags.py owner``'s outcomes: ``(name, tags on origin, extra env)``, for ``v1.5.0``.
OWNER_CASES = (
    ('tagged elsewhere', {'v1.5.0': OTHER}, {}),
    ('tagged here', {'v1.5.0': RUN}, {}),
    ('not tagged', {}, {}),
    ('a failed fetch is ignored', {'v1.5.0': OTHER}, {'FETCH_FAIL': '1'}),
    ('an unresolvable run sha', {'v1.5.0': OTHER}, {'RUN_FAIL': '128'}),
    ('a run sha whose git is killed', {}, {'RUN_FAIL': 'TERM'}),
)

WHEEL = 'pypcapkit-1.5.0-cp312-none-any.whl'
SDIST = 'pypcapkit-1.5.0.tar.gz'
CONDA = 'pypcapkit-1.5.0-py312_0.tar.bz2'

#: ``release_upload.py``'s outcomes: ``(name, $PCAPKIT_ASSETS, files built, the view's lines, extra env)``.
#: ``{tmp}`` in the assets is the scratch directory; ``{dir}/`` in a file builds a directory.
UPLOAD_CASES = (
    ('a new release gets every file, sorted', 'dist/*', [SDIST, WHEEL], '', {}),
    ('a published file is left alone', 'dist/*', [WHEEL, SDIST], f'{WHEEL}\tuploaded\n', {}),
    ('a failed upload is clobbered', 'dist/*', [WHEEL], f'{WHEEL}\tstarter\n{SDIST}\tuploaded\n', {}),
    ('a name listed twice keeps its last state', 'dist/*', [WHEEL, SDIST],
     f'{WHEEL}\tuploaded\n{WHEEL}\topen\n{SDIST}\tstarter\n{SDIST}\tuploaded\n', {}),
    ('tabs around a line and between its fields', 'dist/*', [WHEEL, SDIST],
     f'\t{WHEEL}\t\tuploaded\t\n\t\t{SDIST}\t open\n', {}),
    ('paths a line apart, blank lines and spaces between', '\n{tmp}/linux-64/' + CONDA + '\n\n'
     'dist/' + WHEEL + ' \t dist/' + SDIST + '\n', [WHEEL, SDIST, 'linux-64/' + CONDA], '', {}),
    ('every glob form', 'dist/pypcapkit-1.5.0-cp31?-*.whl dist/[p]*.gz', [WHEEL, SDIST], '', {}),
    ('a glob matching nothing', 'dist/*', [], '', {}),
    ('a path that is not there', 'dist/' + WHEEL + '\ndist/' + SDIST, [WHEEL], '', {}),
    ('a glob matching a directory', 'dist/*', [WHEEL, 'zz/'], '', {}),
    ('a name holding a space splits', 'dist/a b.whl', ['a b.whl'], '', {}),
    ('no release', 'dist/*', [WHEEL], '', {'VIEW_FAIL': '1'}),
    ('a failing view keeps its status', 'dist/*', [WHEEL], '', {'VIEW_FAIL': '4'}),
    ('a failed upload stops the rest', 'dist/*', [SDIST, WHEEL], '', {'UPLOAD_FAIL': '1'}),
    ('a failed clobber keeps its status', 'dist/*', [WHEEL], f'{WHEEL}\topen\n', {'UPLOAD_FAIL': '3'}),
)


class _Stand(unittest.TestCase):
    """A scratch directory with the stand-in ``git`` and ``gh`` first on ``PATH``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-release-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        for name, text in (('git', FAKE_GIT), ('gh', FAKE_GH)):
            (bin_dir / name).write_text(text, encoding='utf-8')
            (bin_dir / name).chmod(0o755)
        self.work = self.tmp / 'work'
        self.work.mkdir()
        self.output = self.tmp / 'output'
        self.git_log = self.tmp / 'git.log'
        self.gh_log = self.tmp / 'gh.log'
        self.tags = self.tmp / 'tags'
        self.assets = self.tmp / 'assets'
        self.base = {
            'PATH': f'{bin_dir}{os.pathsep}{os.environ.get("PATH", "")}', 'HOME': str(self.tmp), 'LC_ALL': 'C',
            'GITHUB_OUTPUT': str(self.output), 'GITHUB_REPOSITORY': 'JarryShaw/PyPCAPKit',
            'GIT_LOG': str(self.git_log), 'GIT_TAGS': str(self.tags), 'RUN_COMMIT': RUN,
            'GH_LOG': str(self.gh_log), 'GH_ASSETS': str(self.assets), 'GH_TOKEN': 'not-a-token',
        }

    def reset(self) -> None:
        """Leave nothing of an earlier run but the stand-ins."""
        for path in (self.output, self.git_log, self.gh_log):
            if path.exists():
                path.unlink()
        shutil.rmtree(self.work)
        self.work.mkdir()

    def prepare_tags(self, tagged: 'dict[str, str]') -> None:
        self.tags.write_text(''.join(f'{tag} {sha}\n' for tag, sha in tagged.items()), encoding='utf-8')

    def prepare_assets(self, built: 'list[str]', published: 'str') -> None:
        for name in built:
            if name.endswith('/'):
                (self.work / 'dist' / name).mkdir(parents=True)
                continue
            path = self.work / name if '/' in name else self.work / 'dist' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name, encoding='utf-8')
        self.assets.write_text(published, encoding='utf-8')

    def script(self, name: 'str', *args: 'str', env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
        """``python3 util/<name>`` as the step runs it, with this interpreter."""
        return subprocess.run([sys.executable, str(UTIL / name), *args], cwd=self.work,  # nosec: B603
                              env=env, capture_output=True, text=True, check=False, timeout=120)

    def former(self, shell: 'str', env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
        """``shell`` as ``shell: bash`` runs it, ``bash --noprofile --norc -eo pipefail``."""
        script = self.tmp / 'step.sh'
        script.write_text(shell, encoding='utf-8')
        return subprocess.run([BASH, '--noprofile', '--norc', '-eo', 'pipefail', str(script)],  # nosec: B603
                              cwd=self.work, env=env, capture_output=True, text=True, check=False, timeout=120)

    def state(self, result: 'subprocess.CompletedProcess[str]') -> 'tuple[object, ...]':
        """What a run left: status, both streams, ``$GITHUB_OUTPUT`` and each stand-in's calls."""
        read = [path.read_text(encoding='utf-8') if path.exists() else None
                for path in (self.output, self.git_log, self.gh_log)]
        return (result.returncode, result.stdout, result.stderr, *read)

    def tags_env(self, case_env: 'dict[str, str]', **variables: 'str') -> 'dict[str, str]':
        return dict(self.base, PCAPKIT_RUN_SHA=RUN, **variables, **case_env)

    def upload_env(self, assets: 'str', case_env: 'dict[str, str]') -> 'dict[str, str]':
        return dict(self.base, PCAPKIT_RELEASE_TAG='v1.5.0', PCAPKIT_ASSETS=assets.format(tmp=self.work),
                    **case_env)


class TestReleaseTags(_Stand):
    """``check`` refuses the first tag not naming the run's commit; ``owner`` says where the tag is."""

    def check(self, tags: 'str', tagged: 'dict[str, str]', **extra: 'str') -> 'subprocess.CompletedProcess[str]':
        self.prepare_tags(tagged)
        return self.script('release_tags.py', 'check', env=self.tags_env(extra, PCAPKIT_TAGS=tags))

    def owner(self, tagged: 'dict[str, str]', **extra: 'str') -> 'subprocess.CompletedProcess[str]':
        self.prepare_tags(tagged)
        return self.script('release_tags.py', 'owner', env=self.tags_env(extra, PCAPKIT_TAG='v1.5.0'))

    def test_every_tag_on_the_run_commit_passes(self) -> None:
        result = self.check('v1.5.0 conda-1.5.0+0', {'v1.5.0': RUN, 'conda-1.5.0+0': RUN})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f'fetching refs/tags/v1.5.0:refs/tags/v1.5.0\nv1.5.0 -> {RUN}\n'
                                        'fetching refs/tags/conda-1.5.0+0:refs/tags/conda-1.5.0+0\n'
                                        f'conda-1.5.0+0 -> {RUN}\n')
        self.assertEqual(self.git_log.read_text(encoding='utf-8').splitlines(), [
            f'rev-parse --verify {RUN}^{{commit}}',
            'fetch --quiet --force origin refs/tags/v1.5.0:refs/tags/v1.5.0',
            'rev-parse -q --verify refs/tags/v1.5.0^{commit}',
            'fetch --quiet --force origin refs/tags/conda-1.5.0+0:refs/tags/conda-1.5.0+0',
            'rev-parse -q --verify refs/tags/conda-1.5.0+0^{commit}',
        ])

    def test_a_tag_on_another_commit_stops_the_check(self) -> None:
        result = self.check('conda-1.5.0+0 v1.5.0', {'v1.5.0': RUN, 'conda-1.5.0+0': OTHER})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.splitlines()[-1], (
            f"::error title=conda-1.5.0+0 is not this run's commit (#1634)::conda-1.5.0+0 resolves to '{OTHER}', "
            f'but this run was created for {RUN}. Refusing to publish this tree under it: every artefact of a '
            "release comes from its tag's commit, so finish that release by re-running the run created for that "
            'commit.'))
        self.assertNotIn('v1.5.0', self.git_log.read_text(encoding='utf-8'))

    def test_a_missing_tag_is_no_commit(self) -> None:
        result = self.check('v1.5.0', {}, FETCH_FAIL='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn("v1.5.0 resolves to 'no commit', but", result.stdout)
        self.assertIn("fatal: couldn't find remote ref", result.stderr)

    def test_an_unresolvable_run_sha_ends_with_gits_status(self) -> None:
        for fail, status in (('128', 128), ('TERM', 143)):
            with self.subTest(fail=fail):
                result = self.check('v1.5.0', {'v1.5.0': RUN}, RUN_FAIL=fail)
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stdout, '')
                self.assertEqual(self.git_log.read_text(encoding='utf-8').count('\n'), 1)
                self.git_log.unlink()

    def test_no_git_is_the_shells_127(self) -> None:
        env = self.tags_env({}, PCAPKIT_TAGS='v1.5.0', PATH=str(self.tmp / 'empty'))
        result = self.script('release_tags.py', 'check', env=env)
        self.assertEqual(result.returncode, 127)

    def test_owner_writes_both_outputs(self) -> None:
        for tagged, released, elsewhere in (({'v1.5.0': OTHER}, OTHER, 'true'), ({'v1.5.0': RUN}, RUN, 'false'),
                                            ({}, '', 'false')):
            with self.subTest(tagged=tagged):
                self.output.write_text('earlier=1\n', encoding='utf-8')
                result = self.owner(tagged)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines()[-1],
                                 f"v1.5.0 -> {released or 'no commit'}; this run's commit is {RUN}; "
                                 f'released elsewhere: {elsewhere}')
                self.assertEqual(self.output.read_text(encoding='utf-8'),
                                 f'earlier=1\nPCAPKIT_RELEASED_AT={released}\n'
                                 f'PCAPKIT_RELEASED_ELSEWHERE={elsewhere}\n')

    def test_owner_without_an_output_file_fails_after_reporting(self) -> None:
        self.prepare_tags({})
        env = self.tags_env({}, PCAPKIT_TAG='v1.5.0')
        del env['GITHUB_OUTPUT']
        result = self.script('release_tags.py', 'owner', env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn('released elsewhere: false', result.stdout)

    def test_another_command_is_refused(self) -> None:
        result = self.script('release_tags.py', 'tag', env=self.tags_env({}))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.git_log.exists())


class TestReleaseUpload(_Stand):
    """Only what the release lacks goes up; anything else ends the step."""

    def upload(self, assets: 'str', built: 'list[str]', published: 'str',
               **extra: 'str') -> 'subprocess.CompletedProcess[str]':
        self.prepare_assets(built, published)
        return self.script('release_upload.py', env=self.upload_env(assets, extra))

    def calls(self) -> 'list[str]':
        return self.gh_log.read_text(encoding='utf-8').splitlines() if self.gh_log.exists() else []

    VIEW = 'release view v1.5.0 --repo JarryShaw/PyPCAPKit --json assets --jq .assets[] | [.name, .state] | @tsv'

    def test_each_state_is_handled(self) -> None:
        result = self.upload('dist/*', [WHEEL, SDIST, CONDA], f'{WHEEL}\tuploaded\n{SDIST}\tstarter\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        # In byte order, as the shell's glob sorted them under the runner's C.UTF-8.
        self.assertEqual(self.calls(), [
            self.VIEW,
            f'release upload v1.5.0 dist/{CONDA} --repo JarryShaw/PyPCAPKit',
            f'release upload v1.5.0 dist/{SDIST} --repo JarryShaw/PyPCAPKit --clobber',
        ])
        self.assertEqual(result.stdout.splitlines(), [
            f"::notice title={WHEEL} already on v1.5.0::Left as published (#1640): this run's rebuild is not "
            'byte-identical to it.',
            f'uploaded dist/{CONDA}', f'{CONDA} -> v1.5.0',
            f"::warning title={SDIST} uploaded again::v1.5.0 holds it in state 'starter', not 'uploaded' -- an "
            'upload that failed partway -- so it is deleted and this file uploaded in its place.',
            f'uploaded dist/{SDIST}', f'{SDIST} -> v1.5.0',
        ])

    def test_nothing_to_upload_is_an_error(self) -> None:
        result = self.upload('dist/*', [], '')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "::error title=Nothing to upload::'dist/*' matches no file, so v1.5.0 "
                                        'would go without it.\n')
        self.assertEqual(self.calls(), [self.VIEW])

    def test_a_failing_gh_ends_with_its_status(self) -> None:
        for extra, status, calls in (({'VIEW_FAIL': '4'}, 4, 1), ({'UPLOAD_FAIL': '3'}, 3, 2)):
            with self.subTest(extra=extra):
                self.reset()
                result = self.upload('dist/*', [SDIST, WHEEL], '', **extra)
                self.assertEqual(result.returncode, status)
                self.assertEqual(len(self.calls()), calls)
                self.assertNotIn('->', result.stdout)

    def test_no_gh_is_the_shells_127(self) -> None:
        self.prepare_assets([WHEEL], '')
        env = dict(self.upload_env('dist/*', {}), PATH=str(self.tmp / 'empty'))
        result = self.script('release_upload.py', env=env)
        self.assertEqual(result.returncode, 127)

    def test_it_takes_no_arguments(self) -> None:
        result = self.script('release_upload.py', 'dist/*', env=self.upload_env('dist/*', {}))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])


@unittest.skipIf(not BASH, 'needs bash, which ran the former shell')
class TestTheFormerShellAgrees(_Stand):
    """Each script exits, prints, writes and calls exactly as its step's inline shell form, on every case."""

    def both(self, shell: 'str', command: 'list[str]', env: 'dict[str, str]',
             prepare: 'Callable[[], None]') -> 'tuple[tuple[object, ...], tuple[object, ...]]':
        found = []
        for run in (lambda: self.former(shell, env), lambda: self.script(*command, env=env)):
            self.reset()
            prepare()
            found.append(self.state(run()))
        return found[0], found[1]

    def test_the_tag_check(self) -> None:
        for name, tags, tagged, extra in CHECK_CASES:
            with self.subTest(case=name):
                old, new = self.both(FORMER_CHECK, ['release_tags.py', 'check'],
                                     self.tags_env(extra, PCAPKIT_TAGS=tags),
                                     functools.partial(self.prepare_tags, tagged))
                self.assertEqual(new, old)

    def test_the_owner_check(self) -> None:
        for name, tagged, extra in OWNER_CASES:
            with self.subTest(case=name):
                old, new = self.both(FORMER_OWNER, ['release_tags.py', 'owner'],
                                     self.tags_env(extra, PCAPKIT_TAG='v1.5.0'),
                                     functools.partial(self.prepare_tags, tagged))
                self.assertEqual(new, old)

    def test_the_upload(self) -> None:
        for name, assets, built, published, extra in UPLOAD_CASES:
            with self.subTest(case=name):
                old, new = self.both(FORMER_UPLOAD, ['release_upload.py'], self.upload_env(assets, extra),
                                     functools.partial(self.prepare_assets, built, published))
                self.assertEqual(new, old)

    def test_every_case_was_reached(self) -> None:
        """The check and upload cases end each shell in success, in refusal and with ``git``'s or ``gh``'s
        own failing status, so agreement is not agreement on one path."""
        statuses = set()
        for shell, cases in ((FORMER_CHECK, CHECK_CASES), (FORMER_UPLOAD, UPLOAD_CASES)):
            for case in cases:
                self.reset()
                if shell is FORMER_CHECK:
                    self.prepare_tags(case[2])
                    env = self.tags_env(case[3], PCAPKIT_TAGS=case[1])
                else:
                    self.prepare_assets(case[2], case[3])
                    env = self.upload_env(case[1], case[4])
                statuses.add((shell is FORMER_CHECK, self.former(shell, env).returncode))
        self.assertEqual(statuses, {(True, 0), (True, 1), (True, 128), (True, 143),
                                    (False, 0), (False, 1), (False, 3), (False, 4)})


class TestTheStepsRunTheScripts(unittest.TestCase):
    """Each step runs its script from a whole checkout."""

    def test_each_step_runs_its_script(self) -> None:
        for (job, name), run in sorted(STEPS.items()):
            found = [step for step in steps(WORKFLOW, job) if step.get('name') == name]
            with self.subTest(job=job, step=name):
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]['run'], run)

    def test_no_other_step_holds_the_former_shell(self) -> None:
        for job, found in sorted(load(WORKFLOW)['jobs'].items()):
            for step in found.get('steps', []):
                for line in ('gh release', 'for tag in ${PCAPKIT_TAGS}', 'released elsewhere'):
                    with self.subTest(job=job, step=step.get('name'), line=line):
                        self.assertNotIn(line, step.get('run', ''))

    def test_each_job_checks_the_whole_tree_out_first(self) -> None:
        """A sparse checkout, or none, would leave ``util/`` out."""
        for job in sorted({job for job, _ in STEPS}):
            found = steps(WORKFLOW, job)
            with self.subTest(job=job):
                checkout = found[0]
                self.assertTrue(str(checkout.get('uses', '')).startswith('actions/checkout@'))
                self.assertEqual(checkout['with'].get('fetch-depth'), 0)
                self.assertNotIn('sparse-checkout', checkout['with'])
                self.assertNotIn('path', checkout['with'])
                self.assertFalse([step for step in found if (step.get('name'), job) in {(n, j) for j, n in STEPS}
                                  and 'working-directory' in step])

    def test_the_scripts_parse_as_python_3_8(self) -> None:
        """The steps run them on the image's ``python3``, or on a KTLO leg's.

        ``feature_version`` is best-effort on a newer interpreter, so the 3.8
        compat leg's ``Compile the 3.8-floor util scripts`` is the authoritative
        check (#2206).

        """
        for name in ('release_tags.py', 'release_upload.py'):
            with self.subTest(script=name):
                ast.parse((UTIL / name).read_text(encoding='utf-8'), feature_version=FLOOR)


if __name__ == '__main__':
    unittest.main()
