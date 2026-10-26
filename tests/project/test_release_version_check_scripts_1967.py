# -*- coding: utf-8 -*-
"""#1967: ``version_check``'s :file:`util/` scripts, run as Create Release runs them.

* :class:`TestTheStepMatchesTheReferenceShell` runs ``version_check``'s "Read the released
  Python versions", "Check PyPI publish completeness" and "Check Anaconda
  publish completeness" in their inline shell form, the reference
  :file:`util/release_tiers.py` and :file:`util/release_published.py` must
  match, on the cases below, and each script on the
  same, against stand-in ``python3``, ``git``, ``mktemp`` and ``curl``, and
  requires the same status, standard output and error,
  ``$GITHUB_OUTPUT``, calls and scratch files. The step bodies are kept here
  verbatim, and each case table is checked to reach every way its shell ends
  and every path through it.
* :class:`TestAPlantedDivergenceIsCaught` changes each script in a copy, one
  plant at a time, and requires the cases to tell it from the shell.
* :class:`TestTheStepsRunTheScripts` pins each step to its script, and the
  scripts to :file:`util/`, the standard library and Python 3.8's syntax.

The steps run with no ``shell:``, so on the runner's ``bash -e``, and ``bash``
prefixes each of its own errors with the script's path and line, which
:meth:`_Stand.reference` strips; the rest of standard error is compared whole,
``[``'s complaint as bash 5.2, ``ubuntu-latest``'s, words it. The runs against
a real repository are
:mod:`tests.project.test_release_tags_the_run_sha_1634`'s.

"""

from __future__ import annotations

import ast
import os
import pathlib
import re
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
    from typing import Optional, Union

#: Test tier (#1958): runs the tree's own scripts and the steps' inline shell form.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL = ROOT / 'util'
WORKFLOW = 'create-release.yml'
BASH = shutil.which('bash') or ''


def bash_version() -> 'str':
    """The ``bash`` on ``PATH``'s ``major.minor``, or ``''``."""
    if not BASH:
        return ''
    found = subprocess.run([BASH, '-c', 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"'],  # nosec: B603
                           capture_output=True, text=True, check=False, timeout=30)
    return found.stdout.strip()


#: Whether ``bash`` is 5.2, the runner's, whose ``[`` errors the scripts copy.
BASH_52 = bash_version() == '5.2'

RUN = '1' * 40
OTHER = '2' * 40
ADDED = '3' * 40
TAG = 'v1.5.0b12'

#: A ``python3`` copying a ``-`` snippet to the log and running it on this
#: interpreter, or answering it with ``$COUNT_REPLY``; and answering a tag's
#: ``python_versions.py`` with ``$READER_WHEELS`` or ``$READER_BUILDS``, or
#: failing with ``$READER_FAIL``'s status.
FAKE_PYTHON3 = r'''#!/bin/sh
printf 'python3 %s\n' "$*" >> "$CALL_LOG"
if [ "$1" = - ]; then
  cat > "$CALL_LOG.src"
  cat "$CALL_LOG.src" >> "$CALL_LOG"
  [ -z "${COUNT_REPLY+set}" ] || { printf '%s\n' "$COUNT_REPLY"; exit 0; }
  exec "$REAL_PYTHON" - < "$CALL_LOG.src"
fi
case "$1" in
  */python_versions.py)
    [ -z "${READER_FAIL:-}" ] || { echo 'Traceback (most recent call last): reader' >&2; exit "$READER_FAIL"; }
    for last; do :; done
    case "$last" in
      pypi-wheels) printf '%s\n' "$READER_WHEELS" ;;
      conda-builds) printf '%s\n' "$READER_BUILDS" ;;
      *) exit 98 ;;
    esac
    ;;
  *) exit 99 ;;
esac
'''

#: A ``git`` answering as "Read the released Python versions" calls it, from
#: the tags in ``$GIT_TAGS`` and ``$GIT_REMOTE_TAGS`` (``<tag> <sha>`` lines),
#: the ``<sha>:<path>`` blobs in ``$GIT_FILES``, ``$GIT_LOG_REPLY``'s bytes,
#: and ``$GIT_HEAD``; ``$SHOW_FAIL`` fails ``show`` for a path ending in it,
#: and each other ``*_FAIL`` fails its command with that status.
FAKE_GIT = r'''#!/bin/sh
printf 'git %s\n' "$*" >> "$CALL_LOG"
die() { [ "$1" != TERM ] || kill -TERM $$; exit "$1"; }
lookup() { awk -v tag="$1" '$1 == tag { print $2; exit }' "$2"; }
case "$1" in
  rev-parse)
    if [ "$2" = HEAD ]; then
      [ -z "${HEAD_FAIL:-}" ] || { echo "fatal: ambiguous argument 'HEAD'" >&2; die "$HEAD_FAIL"; }
      echo "$GIT_HEAD"
      exit 0
    fi
    if [ "$2" = -q ]; then ref="$4"; else ref="$2"; fi
    tag="${ref#refs/tags/}"
    tag="${tag%'^{commit}'}"
    sha="$(lookup "$tag" "$GIT_TAGS")"
    if [ -z "$sha" ]; then
      [ "$2" = -q ] && exit 1
      echo "fatal: ambiguous argument '$ref': unknown revision" >&2
      die "${RESOLVE_FAIL:-128}"
    fi
    echo "$sha"
    ;;
  fetch)
    [ -z "${FETCH_FAIL:-}" ] || { echo "fatal: couldn't find remote ref $6" >&2; die "$FETCH_FAIL"; }
    tag="${6#+refs/tags/}"
    tag="${tag%%:*}"
    sha="$(lookup "$tag" "$GIT_REMOTE_TAGS")"
    [ -z "$sha" ] || printf '%s %s\n' "$tag" "$sha" >> "$GIT_TAGS"
    ;;
  cat-file)
    grep -qxF -- "$3" "$GIT_FILES" || { echo "fatal: path '$3' does not exist" >&2; exit 128; }
    ;;
  log)
    [ -z "${LOG_FAIL:-}" ] || { echo 'fatal: bad revision' >&2; die "$LOG_FAIL"; }
    cat "$GIT_LOG_REPLY"
    ;;
  show)
    case "$2" in *"${SHOW_FAIL:-/none/}") echo "fatal: path '$2' does not exist" >&2; die 128 ;; esac
    printf 'shown %s\n' "$2"
    ;;
  *) exit 99 ;;
esac
'''

#: A ``mktemp`` making ``$SCRATCH``, or failing with ``$MKTEMP_FAIL``'s status.
FAKE_MKTEMP = r'''#!/bin/sh
printf 'mktemp %s\n' "$*" >> "$CALL_LOG"
[ -z "${MKTEMP_FAIL:-}" ] || { echo 'mktemp: failed to create directory via template' >&2; exit "$MKTEMP_FAIL"; }
mkdir -p "$SCRATCH"
echo "$SCRATCH"
'''

#: A ``curl`` writing ``$CURL_BODY`` to its ``-o`` file, printing ``$CURL_CODE``
#: for ``-w`` (``200`` unless set), and failing with ``$CURL_FAIL``'s status; it
#: logs whether ``PCAPKIT_CONDA_SUBDIRS`` reached it.
FAKE_CURL = r'''#!/bin/sh
printf 'curl [%s] %s\n' "${PCAPKIT_CONDA_SUBDIRS-unset}" "$*" >> "$CALL_LOG"
out=
while [ $# -gt 0 ]; do
  [ "$1" != -o ] || { out="$2"; shift; }
  shift
done
[ -z "${CURL_STDERR:-}" ] || echo "$CURL_STDERR" >&2
[ -z "${CURL_BODY:-}" ] || cp "$CURL_BODY" "$out"
printf '%s' "${CURL_CODE-200}"
[ -z "${CURL_FAIL:-}" ] || { [ "$CURL_FAIL" != TERM ] || kill -TERM $$; exit "$CURL_FAIL"; }
'''

#: What the stand-ins and the shell forms run besides each other and bash's builtins.
TOOLS = ('awk', 'cat', 'cp', 'grep', 'mkdir', 'tail')
#: Each stand-in, by name.
FAKES = {'python3': FAKE_PYTHON3, 'git': FAKE_GIT, 'mktemp': FAKE_MKTEMP, 'curl': FAKE_CURL}

#: "Read the released Python versions" in its inline shell form, the reference
#: :file:`util/release_tiers.py` must match.
REFERENCE_TIERS = textwrap.dedent(r'''
    set -euo pipefail

    wheels="$PCAPKIT_PYPI_WHEELS"
    builds="$PCAPKIT_CONDA_BUILDS"
    tiers=.github/python-versions.toml
    if [ "$PCAPKIT_TAG_EXISTS" = true ]; then
      # The checkout fetched every tag, but not one pushed since.
      git rev-parse -q --verify "refs/tags/${PCAPKIT_TAG}^{commit}" > /dev/null \
        || git fetch -q --no-tags origin "+refs/tags/${PCAPKIT_TAG}:refs/tags/${PCAPKIT_TAG}"
      from="$(git rev-parse "refs/tags/${PCAPKIT_TAG}^{commit}")"
      if ! git cat-file -e "${from}:${tiers}" 2> /dev/null; then
        from="$(git log --diff-filter=A --format=%H -- "$tiers" | tail -n 1)"
        if [ -z "$from" ]; then
          echo "::error title=No tier file in the history::${tiers} was never added to this checkout's history."
          exit 1
        fi
        echo "::notice title=Released before the tier file::${PCAPKIT_TAG} predates ${tiers}; counting the tiers ${from} added it with."
      fi
      if [ "$from" != "$(git rev-parse HEAD)" ]; then
        released="$(mktemp -d)"
        git show "${from}:${tiers}" > "${released}/python-versions.toml"
        git show "${from}:util/python_versions.py" > "${released}/python_versions.py"
        # #2047: the reader imports util/_actions.py from beside it, from the
        # commit that has it.
        if git cat-file -e "${from}:util/_actions.py" 2> /dev/null; then
          git show "${from}:util/_actions.py" > "${released}/_actions.py"
        fi
        wheels="$(python3 "${released}/python_versions.py" --file "${released}/python-versions.toml" pypi-wheels)"
        builds="$(python3 "${released}/python_versions.py" --file "${released}/python-versions.toml" conda-builds)"
      fi
    fi

    echo "${PCAPKIT_TAG}: counting the wheels ${wheels} and the conda builds ${builds}"
    echo "pypi-wheels=${wheels}" >> "$GITHUB_OUTPUT"
    echo "conda-builds=${builds}" >> "$GITHUB_OUTPUT"
''').lstrip()

#: "Check PyPI publish completeness" in its inline shell form, the reference
#: :file:`util/release_published.py` must match.
REFERENCE_PYPI = textwrap.dedent(r'''
    set -euo pipefail

    # One wheel per supported leg, plus the sdist.
    read -r -a wheels <<< "$PCAPKIT_PYPI_WHEELS"
    expected=$(( ${#wheels[@]} + 1 ))
    # `--retry-connrefused` and `|| echo 000` keep a pypi.org outage from
    # failing `version_check` under `set -e`, which every publisher
    # requires; "incomplete" is the safe default.
    status="$(curl -s --retry 3 --retry-connrefused \
      -o /tmp/pypi_release.json -w '%{http_code}' \
      "https://pypi.org/pypi/pypcapkit/${PCAPKIT_VERSION}/json" || echo 000)"

    count=0
    if [ "$status" = "200" ]; then
      # One line per `printf` argument, so the block scalar's indentation
      # never reaches the source `python3 -` reads: indented `python3 -c`
      # source compiles only on Python 3.14 (3.9 through 3.13 raise
      # `IndentationError: unexpected indent`, measured). Not leaning on
      # the setup-python above: the conda job's check runs before its own.
      count="$(printf '%s\n' \
        "import json, os" \
        "with open('/tmp/pypi_release.json') as f:" \
        "    data = json.load(f)" \
        "supported = set(os.environ['PCAPKIT_PYPI_WHEELS'].split())" \
        "names = [u.get('filename', '') for u in data.get('urls', [])]" \
        "wheels = {n.split('-')[2] for n in names if n.endswith('.whl') and n.count('-') == 4}" \
        "print(len(wheels & supported) + any(n.endswith('.tar.gz') for n in names))" \
        | python3 -)"
    fi

    complete=false
    if [ "$count" -ge "$expected" ]; then
      complete=true
    fi

    echo "http $status, found $count of $expected expected files for ${PCAPKIT_VERSION} on PyPI"
    echo "PCAPKIT_PYPI_COMPLETE=$complete" >> "$GITHUB_OUTPUT"
''').lstrip()

#: "Check Anaconda publish completeness", likewise.
REFERENCE_ANACONDA = textwrap.dedent(r'''
    set -euo pipefail

    # Each platform the ``conda`` legs publish, for each supported version.
    # win-64 since the conda job's Windows leg publishes it (#2060).
    export PCAPKIT_CONDA_SUBDIRS="linux-64 osx-64 osx-arm64 win-64"
    read -r -a subdirs <<< "$PCAPKIT_CONDA_SUBDIRS"
    read -r -a builds <<< "$PCAPKIT_CONDA_BUILDS"
    expected=$(( ${#subdirs[@]} * ${#builds[@]} ))
    # Same coupling risk, and the same fix, as the PyPI check above.
    status="$(curl -s --retry 3 --retry-connrefused \
      -o /tmp/anaconda_release.json -w '%{http_code}' \
      "https://api.anaconda.org/release/jarryshaw/pypcapkit/${PCAPKIT_VERSION}" || echo 000)"

    count=0
    if [ "$status" = "200" ]; then
      # The same `printf` form as the PyPI check above.
      count="$(printf '%s\n' \
        "import json, os" \
        "with open('/tmp/anaconda_release.json') as f:" \
        "    data = json.load(f)" \
        "platforms = set(os.environ['PCAPKIT_CONDA_SUBDIRS'].split())" \
        "py_tags = set(os.environ['PCAPKIT_CONDA_BUILDS'].split())" \
        "seen = {" \
        "    (d.get('attrs', {}).get('subdir'), tag)" \
        "    for d in data.get('distributions', [])" \
        "    for tag in py_tags" \
        "    if d.get('attrs', {}).get('build', '').startswith(tag + '_')" \
        "    and d.get('attrs', {}).get('subdir') in platforms" \
        "}" \
        "print(len(seen))" \
        | python3 -)"
    fi

    complete=false
    if [ "$count" -ge "$expected" ]; then
      complete=true
    fi

    echo "http $status, found $count of $expected expected platform/Python combinations for ${PCAPKIT_VERSION} on Anaconda"
    echo "PCAPKIT_CONDA_COMPLETE=$complete" >> "$GITHUB_OUTPUT"
''').lstrip()

#: Each step, its id, the ``run:`` it holds, and its inline shell form, the
#: ``/tmp`` file it writes standing for where the cases write it.
STEPS = {
    'Read the released Python versions': ('released', 'python3 util/release_tiers.py', REFERENCE_TIERS),
    'Check PyPI publish completeness': ('check_pypi', 'python3 util/release_published.py pypi /tmp/pypi_release.json',
                                        REFERENCE_PYPI),
    'Check Anaconda publish completeness': (
        'check_conda', 'python3 util/release_published.py anaconda /tmp/anaconda_release.json', REFERENCE_ANACONDA),
}

#: A value standing for a variable left unset.
UNSET = None
#: A case's overrides: a variable's value, :data:`UNSET`, or bytes for one not in UTF-8.
Overrides = 'dict[str, Optional[Union[str, bytes]]]'

#: "Read the released Python versions"'s base: this run's tiers, untagged.
TIERS_BASE = {'PCAPKIT_TAG': TAG, 'PCAPKIT_TAG_EXISTS': 'false', 'PCAPKIT_PYPI_WHEELS': 'py311 py312 pp311',
              'PCAPKIT_CONDA_BUILDS': 'py311 py312', 'GIT_HEAD': RUN, 'READER_WHEELS': 'py311 pp311',
              'READER_BUILDS': 'py311'}
#: The tier file, and the helper its reader imports (#2047), at a commit, as ``$GIT_FILES`` lists them.
TIERS_AT = '{}:.github/python-versions.toml'
HELPER_AT = '{}:util/_actions.py'
TAGGED = {'PCAPKIT_TAG_EXISTS': 'true'}
#: Its cases: ``(name, overrides, local tags, remote tags, blobs, git log's reply)``.
TIERS_CASES = (
    ('untagged', {}, '', '', '', b''),
    ('the check found no tag', {'PCAPKIT_TAG_EXISTS': ''}, '', '', '', b''),
    ('the check spelt it otherwise', {'PCAPKIT_TAG_EXISTS': 'True'}, f'{TAG} {OTHER}', '', '', b''),
    ('a tag on this commit', TAGGED, f'{TAG} {RUN}', '', TIERS_AT.format(RUN), b''),
    ('a tag on an earlier commit', TAGGED, f'{TAG} {OTHER}', '', TIERS_AT.format(OTHER), b''),
    ('a reader with its helper', TAGGED, f'{TAG} {OTHER}', '',
     TIERS_AT.format(OTHER) + '\n' + HELPER_AT.format(OTHER), b''),
    ('a helper on this commit is not copied', TAGGED, f'{TAG} {RUN}', '',
     TIERS_AT.format(RUN) + '\n' + HELPER_AT.format(RUN), b''),
    ('the helper did not show', {**TAGGED, 'SHOW_FAIL': '_actions.py'}, f'{TAG} {OTHER}', '',
     TIERS_AT.format(OTHER) + '\n' + HELPER_AT.format(OTHER), b''),
    ('the helper beside the tier file it was added with', TAGGED, f'{TAG} {OTHER}', '',
     HELPER_AT.format(ADDED), f'{ADDED}\n'.encode()),
    ('a helper only at the tagged commit', TAGGED, f'{TAG} {OTHER}', '', HELPER_AT.format(OTHER),
     f'{ADDED}\n'.encode()),
    ('a tag pushed since the checkout', TAGGED, '', f'{TAG} {OTHER}', TIERS_AT.format(OTHER), b''),
    ('a tag fetched onto this commit', TAGGED, '', f'{TAG} {RUN}', TIERS_AT.format(RUN), b''),
    ('the fetch failed', {**TAGGED, 'FETCH_FAIL': '1'}, '', f'{TAG} {OTHER}', '', b''),
    ('the fetch failed otherwise', {**TAGGED, 'FETCH_FAIL': '128'}, '', '', '', b''),
    ('the fetch was killed', {**TAGGED, 'FETCH_FAIL': 'TERM'}, '', '', '', b''),
    ('no such tag anywhere', TAGGED, '', '', '', b''),
    ('the tag would not resolve', {**TAGGED, 'RESOLVE_FAIL': '1'}, '', '', '', b''),
    ('older than the tier file', TAGGED, f'{TAG} {OTHER}', '', '', f'{ADDED}\n'.encode()),
    ('older, the file added on this commit', {**TAGGED, 'GIT_HEAD': ADDED}, f'{TAG} {OTHER}', '', '',
     f'{ADDED}\n'.encode()),
    ('older, the file added twice', TAGGED, f'{TAG} {OTHER}', '', '', f'{OTHER}\n{ADDED}\n'.encode()),
    ('older, no trailing newline', TAGGED, f'{TAG} {OTHER}', '', '', ADDED.encode()),
    ('older, trailing blank lines', TAGGED, f'{TAG} {OTHER}', '', '', f'{ADDED}\n\n'.encode()),
    ('no tier file in the history', TAGGED, f'{TAG} {OTHER}', '', '', b''),
    ('the log failed', {**TAGGED, 'LOG_FAIL': '128'}, f'{TAG} {OTHER}', '', '', b''),
    ('the log was killed', {**TAGGED, 'LOG_FAIL': 'TERM'}, f'{TAG} {OTHER}', '', '', b''),
    ('HEAD did not read', {**TAGGED, 'HEAD_FAIL': '128'}, f'{TAG} {RUN}', '', TIERS_AT.format(RUN), b''),
    ('mktemp failed', {**TAGGED, 'MKTEMP_FAIL': '1'}, f'{TAG} {OTHER}', '', TIERS_AT.format(OTHER), b''),
    ('the tier file did not show', {**TAGGED, 'SHOW_FAIL': 'python-versions.toml'}, f'{TAG} {OTHER}', '',
     TIERS_AT.format(OTHER), b''),
    ('the reader did not show', {**TAGGED, 'SHOW_FAIL': 'python_versions.py'}, f'{TAG} {OTHER}', '',
     TIERS_AT.format(OTHER), b''),
    ('the reader failed', {**TAGGED, 'READER_FAIL': '1'}, f'{TAG} {OTHER}', '', TIERS_AT.format(OTHER), b''),
    ('the reader read nothing', {**TAGGED, 'READER_WHEELS': '', 'READER_BUILDS': ''}, f'{TAG} {OTHER}', '',
     TIERS_AT.format(OTHER), b''),
    ('the reader printed two lines', {**TAGGED, 'READER_WHEELS': 'py311\npp311'}, f'{TAG} {OTHER}', '',
     TIERS_AT.format(OTHER), b''),
    ('the scratch directory has no name', {**TAGGED, 'SCRATCH': ''}, f'{TAG} {OTHER}', '',
     TIERS_AT.format(OTHER), b''),
    ('awkward values pass through', {'PCAPKIT_TAG': "v1 'a' $b%:", 'PCAPKIT_PYPI_WHEELS': ' py311\tpp311 ',
                                     'PCAPKIT_CONDA_BUILDS': '\npy311'}, '', '', '', b''),
    ('values not in utf-8', {'PCAPKIT_PYPI_WHEELS': b'py3\xff', **TAGGED, 'PCAPKIT_TAG': 'v1.5.0\u00e9'},
     'v1.5.0\u00e9 ' + RUN, '', TIERS_AT.format(RUN), b''),
    ('no git at all', {**TAGGED, 'PATH': 'nogit'}, '', '', '', b''),
    ('no python3 at all', {**TAGGED, 'PATH': 'nopython3'}, f'{TAG} {OTHER}', '', TIERS_AT.format(OTHER), b''),
    ('no wheels variable', {'PCAPKIT_PYPI_WHEELS': UNSET}, '', '', '', b''),
    ('no builds variable', {'PCAPKIT_CONDA_BUILDS': UNSET}, '', '', '', b''),
    ('no tag-exists variable', {'PCAPKIT_TAG_EXISTS': UNSET}, '', '', '', b''),
    ('no tag variable, untagged', {'PCAPKIT_TAG': UNSET}, '', '', '', b''),
    ('no tag variable, tagged', {**TAGGED, 'PCAPKIT_TAG': UNSET}, '', '', '', b''),
    ('no output file', {'GITHUB_OUTPUT': UNSET}, '', '', '', b''),
    ('an output file in no directory', {'GITHUB_OUTPUT': '/nonexistent/output'}, '', '', '', b''),
)

#: "Check PyPI publish completeness"'s base, and the files of a complete release.
PYPI_BASE = {'PCAPKIT_VERSION': '1.5.0', 'PCAPKIT_PYPI_WHEELS': 'py311 py312 pp311'}
WHEELS = ['pypcapkit-1.5.0-py311-none-any.whl', 'pypcapkit-1.5.0-py312-none-any.whl',
          'pypcapkit-1.5.0-pp311-none-any.whl']
SDIST = 'pypcapkit-1.5.0.tar.gz'


def urls(*names: 'str') -> 'str':
    """A PyPI reply listing ``names``."""
    return '{"urls": [%s]}' % ', '.join('{"filename": "%s"}' % name for name in names)


#: Its cases: ``(name, overrides, the reply's body)``.
PYPI_CASES = (
    ('complete', {}, urls(*WHEELS, SDIST)),
    ('complete with a ktlo wheel', {}, urls(*WHEELS, 'pypcapkit-1.5.0-py310-none-any.whl', SDIST)),
    ('a wheel missing', {}, urls(*WHEELS[1:], SDIST)),
    ('the sdist missing', {}, urls(*WHEELS)),
    ('a wheel twice', {}, urls(WHEELS[0], WHEELS[0], WHEELS[1], SDIST)),
    ('a name of the wrong shape', {}, urls('pypcapkit-1.5.0-py311-x-none-any.whl', *WHEELS[1:], SDIST)),
    ('no files', {}, urls()),
    ('releases alone', {}, '{"releases": {"1.5.0": [{"filename": "%s"}]}}' % SDIST),
    ('no wheels expected', {'PCAPKIT_PYPI_WHEELS': ''}, urls(SDIST)),
    ('the wheels on two lines', {'PCAPKIT_PYPI_WHEELS': 'py311 py312\npp311'}, urls(*WHEELS[:2], SDIST)),
    ('the wheels split by tabs', {'PCAPKIT_PYPI_WHEELS': '\tpy311\t py312  pp311 '}, urls(*WHEELS[1:], SDIST)),
    ('the wheels after a blank line', {'PCAPKIT_PYPI_WHEELS': '\npy311'}, urls(SDIST)),
    ('not found', {'CURL_CODE': '404'}, '{"message": "Not Found"}'),
    ('a server error, said', {'CURL_CODE': '503', 'CURL_STDERR': 'curl: (22) 503'}, ''),
    ('no connection', {'CURL_CODE': '000', 'CURL_FAIL': '7'}, ''),
    ('a 200 that failed to write', {'CURL_FAIL': '23'}, urls(*WHEELS, SDIST)),
    ('curl was killed', {'CURL_CODE': '', 'CURL_FAIL': 'TERM'}, ''),
    ('no curl at all', {'PATH': 'nocurl'}, urls(*WHEELS, SDIST)),
    ('a body that is not json', {}, '<html>'),
    ('a body that is a list', {}, '[]'),
    ('no python3 at all', {'PATH': 'nopython3'}, urls(*WHEELS, SDIST)),
    ('a count that is not a number', {'COUNT_REPLY': 'four'}, urls(SDIST)),
    ('an empty count', {'COUNT_REPLY': ''}, urls(SDIST)),
    ('a count with blanks', {'COUNT_REPLY': '\t 4'}, urls(SDIST)),
    ('a signed count', {'COUNT_REPLY': '+4'}, urls(SDIST)),
    ('a negative count', {'COUNT_REPLY': '-4'}, urls(SDIST)),
    ('a count past 64 bits', {'COUNT_REPLY': '9223372036854775808'}, urls(SDIST)),
    ('a count at 64 bits', {'COUNT_REPLY': '9223372036854775807'}, urls(SDIST)),
    ('a count with trailing blanks', {'COUNT_REPLY': '4 \t'}, urls(SDIST)),
    ('a count after a vertical tab', {'COUNT_REPLY': '\v4'}, urls(SDIST)),
    ('an awkward version', {'PCAPKIT_VERSION': "1.5 'a' $b"}, urls(*WHEELS, SDIST)),
    ('a version not in utf-8', {'PCAPKIT_VERSION': b'1.5\xff'}, urls(SDIST)),
    ('no version variable', {'PCAPKIT_VERSION': UNSET}, urls(*WHEELS, SDIST)),
    ('no wheels variable', {'PCAPKIT_PYPI_WHEELS': UNSET}, urls(*WHEELS, SDIST)),
    ('no output file', {'GITHUB_OUTPUT': UNSET}, urls(*WHEELS, SDIST)),
    ('an output file in no directory', {'GITHUB_OUTPUT': '/nonexistent/output'}, urls(*WHEELS, SDIST)),
)

#: "Check Anaconda publish completeness"'s base, and its platforms.
#: #2060: untagged, as the shell form knows no tag; a tagged version's platforms are
#: test_release_tags_the_run_sha_1634.TestTheCountsAreOfTheReleasedPlatforms'.
ANACONDA_BASE = {'PCAPKIT_VERSION': '1.5.0', 'PCAPKIT_CONDA_BUILDS': 'py311 py312', 'PCAPKIT_TAG_EXISTS': 'false'}
PLATFORMS = ('linux-64', 'osx-64', 'osx-arm64', 'win-64')


def distributions(*pairs: 'tuple[str, str]') -> 'str':
    """An Anaconda reply holding each ``(subdir, build)``."""
    return '{"distributions": [%s]}' % ', '.join('{"attrs": {"subdir": "%s", "build": "%s"}}' % pair
                                                  for pair in pairs)


EVERY = tuple((platform, f'{build}_0') for platform in PLATFORMS for build in ('py311', 'py312'))
#: Its cases: ``(name, overrides, the reply's body)``.
ANACONDA_CASES = (
    ('complete', {}, distributions(*EVERY)),
    ('complete twice over', {}, distributions(*EVERY, *EVERY)),
    ('a platform missing', {}, distributions(*(pair for pair in EVERY if pair[0] != 'osx-64'))),
    ('osx-arm64 missing for one build', {}, distributions(*(pair for pair in EVERY
                                                             if pair != ('osx-arm64', 'py312_0')))),
    ('another platform is not counted', {}, distributions(*EVERY[1:], ('linux-aarch64', 'py311_0'))),
    ('a build without its underscore', {}, distributions(*EVERY[1:], ('linux-64', 'py311'))),
    ('a build of another tag', {}, distributions(*EVERY[1:], ('linux-64', 'py3110_0'))),
    ('no attrs', {}, '{"distributions": [{}]}'),
    ('no distributions', {}, '{}'),
    ('no builds expected, found', {'PCAPKIT_CONDA_BUILDS': ''}, distributions()),
    ('no builds expected, not found', {'PCAPKIT_CONDA_BUILDS': '', 'CURL_CODE': '404'}, ''),
    ('no builds expected, no connection', {'PCAPKIT_CONDA_BUILDS': '  ', 'CURL_CODE': '000', 'CURL_FAIL': '6'},
     ''),
    ('the builds on two lines', {'PCAPKIT_CONDA_BUILDS': 'py311\npy312'}, distributions(*EVERY)),
    ('not found', {'CURL_CODE': '404'}, ''),
    ('no connection', {'CURL_CODE': '000', 'CURL_FAIL': '7'}, ''),
    ('curl was killed', {'CURL_CODE': '', 'CURL_FAIL': 'TERM'}, ''),
    ('no curl at all', {'PATH': 'nocurl'}, distributions(*EVERY)),
    ('a body that is not json', {}, 'not json'),
    ('a distribution that is a string', {}, '{"distributions": ["x"]}'),
    ('no python3 at all', {'PATH': 'nopython3'}, distributions(*EVERY)),
    ('a count that is not a number', {'COUNT_REPLY': '8.0'}, distributions()),
    ('a count past what is expected', {'COUNT_REPLY': '9'}, distributions()),
    ('a version not in utf-8', {'PCAPKIT_VERSION': b'1.5\xff'}, distributions()),
    ('no version variable', {'PCAPKIT_VERSION': UNSET}, distributions(*EVERY)),
    ('no builds variable', {'PCAPKIT_CONDA_BUILDS': UNSET}, distributions(*EVERY)),
    ('no output file', {'GITHUB_OUTPUT': UNSET}, distributions(*EVERY)),
    ('an output file in no directory', {'GITHUB_OUTPUT': '/nonexistent/output'}, distributions(*EVERY)),
)


class _Stand(unittest.TestCase):
    """A scratch directory with the stand-ins first on ``PATH``, and bin directories each lacking one."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-version-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bins = {}  # type: dict[str, pathlib.Path]
        for label, left_out in (('bin', ''), ('nogit', 'git'), ('nopython3', 'python3'), ('nocurl', 'curl')):
            directory = self.tmp / label
            directory.mkdir()
            for name, text in FAKES.items():
                if name != left_out:
                    (directory / name).write_text(text, encoding='utf-8')
                    (directory / name).chmod(0o755)
            self.bins[label] = directory
        self.tools = self.tmp / 'tools'
        self.tools.mkdir()
        for name in TOOLS:
            found = shutil.which(name)
            assert found is not None, name
            (self.tools / name).symlink_to(found)
        self.work = self.tmp / 'work'
        self.work.mkdir()
        self.output = self.tmp / 'output'
        self.calls = self.tmp / 'calls'
        self.reply = self.tmp / 'reply.json'
        self.scratch = self.tmp / 'scratch'
        self.shell = self.tmp / 'step.sh'
        self.tags = self.tmp / 'tags'
        self.remote = self.tmp / 'remote-tags'
        self.files = self.tmp / 'files'
        self.log = self.tmp / 'log'

    def path(self, label: 'str') -> 'str':
        """``PATH`` for the bin directory ``label``: it, then :data:`TOOLS`."""
        return f'{self.bins[label]}{os.pathsep}{self.tools}'

    def env(self, base: 'dict[str, str]', overrides: 'Overrides') -> 'dict[str, bytes]':
        """The step's environment: the stand-ins' settings, ``base``, then ``overrides``.

        ``PATH`` holds the stand-ins and :data:`TOOLS` alone; a case's ``PATH``
        names one of the bin directories, each lacking one stand-in, or a path
        to use instead.

        """
        env = {'PATH': self.path('bin'), 'HOME': str(self.tmp), 'LC_ALL': 'C', 'GITHUB_OUTPUT': str(self.output),
               'CALL_LOG': str(self.calls), 'REAL_PYTHON': sys.executable, 'SCRATCH': str(self.scratch),
               'GIT_TAGS': str(self.tags), 'GIT_REMOTE_TAGS': str(self.remote), 'GIT_FILES': str(self.files),
               'GIT_LOG_REPLY': str(self.log), 'CURL_BODY': str(self.reply),
               **base}  # type: dict[str, Union[str, bytes]]
        for name, value in overrides.items():
            if value is UNSET:
                env.pop(name, None)
            elif name == 'PATH' and value in self.bins:
                env[name] = self.path(str(value))
            else:
                env[name] = value
        return {name: os.fsencode(value) for name, value in env.items()}

    def state(self, command: 'list[str]', env: 'dict[str, bytes]', reply: 'bytes',
              git: 'tuple[str, str, str, bytes]') -> 'tuple[object, ...]':
        """What ``command`` left: status, both streams, ``$GITHUB_OUTPUT``, the calls and the scratch files.

        The output file holds a line already, as a job's earlier steps leave.

        """
        for path in (self.output, self.calls, self.reply):
            if path.exists():
                path.unlink()
        shutil.rmtree(self.scratch, ignore_errors=True)
        self.output.write_text('earlier=1\n', encoding='utf-8')
        self.reply.write_bytes(reply)
        for path, text in zip((self.tags, self.remote, self.files), git[:3]):
            path.write_text(text + '\n' if text else '', encoding='utf-8')
        self.log.write_bytes(git[3])
        result = subprocess.run(command, cwd=self.work, env=env, capture_output=True,  # nosec: B603
                                check=False, timeout=120)
        scratch = sorted((path.name, path.read_bytes()) for path in self.scratch.iterdir()) \
            if self.scratch.is_dir() else None
        return (result.returncode, result.stdout.decode('utf-8', 'surrogateescape'),
                result.stderr.decode('utf-8', 'surrogateescape'),
                *(path.read_text(encoding='utf-8', errors='surrogateescape') if path.exists() else None
                  for path in (self.output, self.calls)), scratch)

    def reference(self, shell: 'str', env: 'dict[str, bytes]', reply: 'bytes' = b'',
               git: 'tuple[str, str, str, bytes]' = ('', '', '', b'')) -> 'tuple[object, ...]':
        """``shell`` as a step with no ``shell:`` runs it, ``bash -e``, its own errors' ``<path>: line N:`` dropped."""
        self.shell.write_text(shell.replace('/tmp/pypi_release.json', str(self.tmp / 'release.json'))
                              .replace('/tmp/anaconda_release.json', str(self.tmp / 'release.json')),
                              encoding='utf-8')
        found = self.state([BASH, '-e', str(self.shell)], env, reply, git)
        stderr = re.sub(rf'(?m)^{re.escape(str(self.shell))}: line \d+: ', '', str(found[2]))
        if not BASH_52:
            # Bash 5.3 shortened ``[``'s message; 5.2, the runner's, is the one kept.
            stderr = re.sub(r'(?m)^(\[: .*): integer expected$', r'\1: integer expression expected', stderr)
        return (*found[:2], stderr, *found[3:])

    def script(self, run: 'str', env: 'dict[str, bytes]', reply: 'bytes' = b'',
               git: 'tuple[str, str, str, bytes]' = ('', '', '', b''),
               util: 'pathlib.Path' = UTIL) -> 'tuple[object, ...]':
        """``run``, ``python3 util/<script> ...``, on this interpreter from ``util``, writing where the cases do."""
        words = run.replace('/tmp/pypi_release.json', str(self.tmp / 'release.json')) \
            .replace('/tmp/anaconda_release.json', str(self.tmp / 'release.json')).split()
        assert words[0] == 'python3' and words[1].startswith('util/'), run
        return self.state([sys.executable, str(util / words[1][len('util/'):]), *words[2:]], env, reply, git)


def compared(name: 'str', state: 'tuple[object, ...]') -> 'tuple[object, ...]':
    """What of ``state`` case ``name`` compares: all of it, but standard error for :data:`SIGNALLED`."""
    return state[:2] + state[3:] if name in SIGNALLED else state


#: Each step's base environment, and its cases as ``(name, overrides, reply, git)``.
def cases(step: 'str') -> 'list[tuple[str, Overrides, bytes, tuple[str, str, str, bytes]]]':
    nothing = ('', '', '', b'')
    if step == 'Read the released Python versions':
        return [(name, overrides, b'', (tags, remote, files, log))
                for name, overrides, tags, remote, files, log in TIERS_CASES]
    table = PYPI_CASES if step == 'Check PyPI publish completeness' else ANACONDA_CASES
    return [(name, overrides, body.encode(), nothing) for name, overrides, body in table]


BASES = {'Read the released Python versions': TIERS_BASE,
         'Check PyPI publish completeness': PYPI_BASE, 'Check Anaconda publish completeness': ANACONDA_BASE}


def http(state: 'tuple[object, ...]') -> 'Optional[str]':
    """The code a completeness check's log line names, or :data:`None`."""
    found = re.search(r'^http (\S*), found ', str(state[1]), re.M)
    return found.group(1) if found else None


def written(state: 'tuple[object, ...]') -> 'str':
    """What the step appended to ``$GITHUB_OUTPUT``."""
    return str(state[3])[len('earlier=1\n'):] if state[3] is not None else ''


def unbound(state: 'tuple[object, ...]') -> 'bool':
    return state[0] == 1 and 'unbound variable' in str(state[2])


#: The case killing a command the shell ran itself, not inside ``$(...)``:
#: bash reports that kill on standard error, as ``Terminated``, with the line
#: and the command's source text from 5.3 and alone in 5.2, and with the pid for
#: other signals, which the script does not copy; the rest is compared.
SIGNALLED = frozenset({'the fetch was killed'})

#: Each way each shell form ends, as a predicate on its state; every case
#: meets exactly one.
EXITS = {
    'Read the released Python versions': {
        'an unset variable': unbound,
        'a command failed': lambda s: s[0] != 0 and not unbound(s) and 'counting the wheels' not in s[1]
        and '::error' not in s[1],
        'no tier file': lambda s: s[0] == 1 and '::error title=No tier file in the history::' in s[1],
        'the output did not open': lambda s: s[0] == 1 and 'counting the wheels' in s[1] and not written(s)
        and not unbound(s),
        'written': lambda s: s[0] == 0 and written(s).startswith('pypi-wheels='),
    },
}
EXITS['Check PyPI publish completeness'] = EXITS['Check Anaconda publish completeness'] = {
    'an unset variable': unbound,
    'the count failed': lambda s: s[0] != 0 and not unbound(s) and http(s) is None,
    'the output did not open': lambda s: s[0] == 1 and http(s) is not None and not written(s) and not unbound(s),
    'incomplete': lambda s: s[0] == 0 and written(s).endswith('_COMPLETE=false\n'),
    'complete': lambda s: s[0] == 0 and written(s).endswith('_COMPLETE=true\n'),
}

#: Each path through each shell form short of its end; every one is taken.
PATHS = {
    'Read the released Python versions': {
        "this run's tiers": lambda s: s[4] is None,
        'the tag was already here': lambda s: 'git rev-parse -q' in str(s[4]) and 'git fetch' not in str(s[4]),
        'the tag was fetched': lambda s: 'git fetch' in str(s[4]) and 'git rev-parse refs/tags' in str(s[4]),
        'older than the tier file': lambda s: '::notice title=Released before the tier file::' in s[1],
        'read at another commit': lambda s: 'pypi-wheels' in str(s[4]) and 'conda-builds' in str(s[4]),
        'read with its helper': lambda s: s[0] == 0 and any(name == '_actions.py' for name, _ in s[5] or ()),
        'read without a helper': lambda s: s[0] == 0 and s[5] is not None
        and not any(name == '_actions.py' for name, _ in s[5]),
        'read at this commit': lambda s: 'git rev-parse HEAD' in str(s[4]) and 'mktemp' not in str(s[4])
        and s[0] == 0,
        'a command missing': lambda s: s[0] == 127,
        'killed': lambda s: s[0] == 143,
    },
}
PATHS['Check PyPI publish completeness'] = {
    'counted': lambda s: http(s) == '200',
    'not counted': lambda s: http(s) not in (None, '200'),
    'curl failed': lambda s: str(http(s)).endswith('000'),
    'not an integer': lambda s: 'integer expression expected' in s[2],
    'a command missing': lambda s: s[0] == 127 or 'command not found' in s[2],
}
PATHS['Check Anaconda publish completeness'] = {
    **PATHS['Check PyPI publish completeness'],
    'complete unread': lambda s: http(s) not in (None, '200') and written(s).endswith('=true\n'),
}


@unittest.skipIf(not BASH, 'needs bash, which runs the reference shell')
class TestTheStepMatchesTheReferenceShell(_Stand):
    """Each script exits, prints, writes and calls exactly as its step's inline shell form, on every case."""

    def compare(self, step: 'str') -> 'None':
        _, run, reference = STEPS[step]
        for name, overrides, reply, git in cases(step):
            with self.subTest(case=name):
                env = self.env(BASES[step], overrides)
                new, old = self.script(run, env, reply, git), self.reference(reference, env, reply, git)
                if name in SIGNALLED:
                    self.assertRegex(str(old[2]), r'(?m)^Terminated\b')
                self.assertEqual(compared(name, new), compared(name, old))

    def test_read_the_released_python_versions(self) -> None:
        self.compare('Read the released Python versions')

    def test_check_pypi_publish_completeness(self) -> None:
        self.compare('Check PyPI publish completeness')

    def test_check_anaconda_publish_completeness(self) -> None:
        self.compare('Check Anaconda publish completeness')

    def reached(self, step: 'str') -> 'None':
        """Every case meets exactly one of the step's :data:`EXITS`, and each exit and path is met."""
        exits = {}  # type: dict[str, list[str]]
        paths = {}  # type: dict[str, list[str]]
        for name, overrides, reply, git in cases(step):
            old = self.reference(STEPS[step][2], self.env(BASES[step], overrides), reply, git)
            met = [label for label, test in EXITS[step].items() if test(old)]
            with self.subTest(case=name):
                self.assertEqual(len(met), 1, f'{name} meets {met}: {old!r}')
            for label in met:
                exits.setdefault(label, []).append(name)
            for label, test in PATHS[step].items():
                if test(old):
                    paths.setdefault(label, []).append(name)
        self.assertEqual(sorted(exits), sorted(EXITS[step]))
        self.assertEqual(sorted(paths), sorted(PATHS[step]))

    def test_every_released_branch_is_reached(self) -> None:
        self.reached('Read the released Python versions')

    def test_every_pypi_branch_is_reached(self) -> None:
        self.reached('Check PyPI publish completeness')

    def test_every_anaconda_branch_is_reached(self) -> None:
        self.reached('Check Anaconda publish completeness')


#: Plants, each ``(step, script, the text it replaces, its replacement)``: each
#: changes what the step does on some case.
PLANTS = (
    ('Read the released Python versions', 'release_tiers.py', "'fetch', '-q', '--no-tags', 'origin'",
     "'fetch', '-q', 'origin'"),
    ('Read the released Python versions', 'release_tiers.py', "    return output.rsplit(b'\\n', 1)[-1]",
     "    return output.split(b'\\n', 1)[0]"),
    ('Read the released Python versions', 'release_tiers.py', 'if start != head:', 'if True:'),
    ('Read the released Python versions', 'release_tiers.py', '            if not lacks:', '            if lacks:'),
    ('Read the released Python versions', 'release_tiers.py', "HELPER = 'util/_actions.py'",
     "HELPER = 'util/actions.py'"),
    ('Read the released Python versions', 'release_tiers.py', "_, head = command('git', 'rev-parse', 'HEAD',",
     "_, head = must('git', 'rev-parse', 'HEAD',"),
    ('Check PyPI publish completeness', 'release_published.py', "'--retry', '3'", "'--retry', '4'"),
    ('Check PyPI publish completeness', 'release_published.py', "        output += b'000\\n'",
     '        pass'),
    ('Check PyPI publish completeness', 'release_published.py', "len(words(var('PCAPKIT_PYPI_WHEELS'))) + 1",
     "len(words(var('PCAPKIT_PYPI_WHEELS')))"),
    ('Check PyPI publish completeness', 'release_published.py', 'value >= expected', 'value > expected'),
    ('Check PyPI publish completeness', 'release_published.py', "value.split(b'\\n', 1)[0]", 'value'),
    ('Check Anaconda publish completeness', 'release_published.py', "SUBDIRS = 'linux-64 osx-64 osx-arm64 win-64'",
     "SUBDIRS = 'linux-64 osx-64 osx-arm64'"),
    ('Check Anaconda publish completeness', 'release_published.py',
     "    os.environ['PCAPKIT_CONDA_SUBDIRS'] = os.fsdecode(subdirs)\n", ''),
    ('Check Anaconda publish completeness', 'release_published.py', "ANACONDA_URL = 'https://api.anaconda.org/",
     "ANACONDA_URL = 'http://api.anaconda.org/"),
)


@unittest.skipIf(not BASH, 'needs bash, which runs the reference shell')
class TestAPlantedDivergenceIsCaught(_Stand):
    """The cases tell each plant from the shell form, so their agreement means something."""

    def test_each_plant_applies_once(self) -> None:
        for step, name, old, _ in PLANTS:
            with self.subTest(step=step, plant=old):
                self.assertEqual((UTIL / name).read_text(encoding='utf-8').count(old), 1)

    def test_each_plant_is_caught(self) -> None:
        for step, name, old, new in PLANTS:
            util = self.tmp / f'util-{PLANTS.index((step, name, old, new))}'
            util.mkdir()
            shutil.copy(UTIL / '_actions.py', util / '_actions.py')
            (util / name).write_text((UTIL / name).read_text(encoding='utf-8').replace(old, new), encoding='utf-8')
            _, run, reference = STEPS[step]
            caught = []
            for case, overrides, reply, git in cases(step):
                env = self.env(BASES[step], overrides)
                if compared(case, self.script(run, env, reply, git, util=util)) \
                        != compared(case, self.reference(reference, env, reply, git)):
                    caught.append(case)
                    break
            with self.subTest(step=step, plant=new):
                self.assertTrue(caught, f'no case tells {old!r} -> {new!r} from the shell')


class TestTheStepsRunTheScripts(unittest.TestCase):
    """Each step runs its script under its own ``id``, after a whole checkout and setup-python."""

    def test_each_step_runs_its_script(self) -> None:
        found = steps(WORKFLOW, 'version_check')
        names = [step.get('name') for step in found]
        for name, (step_id, run, _) in sorted(STEPS.items()):
            with self.subTest(step=name):
                self.assertEqual(names.count(name), 1)
                step = found[names.index(name)]
                self.assertEqual((step.get('id'), step['run']), (step_id, run))
                self.assertFalse(set(step) - {'name', 'id', 'env', 'run'})

    def test_the_scripts_run_after_the_checkout_and_setup_python(self) -> None:
        """``python3`` is setup-python's, and the checkout holds :file:`util/` and its history."""
        found = steps(WORKFLOW, 'version_check')
        uses = [str(step.get('uses', '')) for step in found]
        checkout = next(index for index, use in enumerate(uses) if use.startswith('actions/checkout@'))
        setup = next(index for index, use in enumerate(uses) if use.startswith('actions/setup-python@'))
        self.assertEqual(found[checkout]['with'], {'ref': '${{ github.sha }}', 'fetch-depth': 0})
        first = min(index for index, step in enumerate(found) if step.get('name') in STEPS)
        self.assertLess(checkout, setup)
        self.assertLess(setup, first)
        self.assertEqual(load(WORKFLOW)['jobs']['version_check']['permissions'], {'contents': 'read'})

    def test_no_step_holds_the_reference_shell(self) -> None:
        for job, spec in sorted(load(WORKFLOW)['jobs'].items()):
            for step in spec.get('steps', []):
                for line in ('python-versions.toml', "data.get('urls'", 'PCAPKIT_CONDA_SUBDIRS',
                             'counting the wheels'):
                    with self.subTest(job=job, step=step.get('name'), line=line):
                        self.assertNotIn(line, step.get('run', ''))

    def test_the_scripts_need_only_util_and_python_3_8(self) -> None:
        """Each imports only :file:`util/` and the standard library, and parses at the floor.

        ``feature_version`` is best-effort on a newer interpreter, so the 3.8
        compat leg's ``Compile the 3.8-floor util scripts`` is the authoritative
        check (#2206).

        """
        allowed = {'__future__', 'argparse', 'os', 're', 'subprocess', 'sys', 'typing', '_actions', 'util'}
        for name in ('release_tiers.py', 'release_published.py'):
            with self.subTest(script=name):
                tree = ast.parse((UTIL / name).read_text(encoding='utf-8'), feature_version=FLOOR)
                imported = {alias.name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                            for alias in node.names}
                imported |= {str(node.module).split('.')[0] for node in ast.walk(tree)
                             if isinstance(node, ast.ImportFrom)}
                self.assertLessEqual(imported, allowed)

    def test_each_snippet_is_unindented_python(self) -> None:
        """#905: the source ``python3 -`` reads starts each line where Python put it, and compiles."""
        from util import release_published  # pylint: disable=import-outside-toplevel
        for source in (release_published.pypi_source, release_published.anaconda_source):
            with self.subTest(snippet=source.__name__):
                text = source('/tmp/release.json')
                compile(text, '<stdin>', 'exec')
                self.assertTrue(text.startswith('import json, os\n'))


if __name__ == '__main__':
    unittest.main()
