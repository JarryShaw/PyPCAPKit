# -*- coding: utf-8 -*-
"""#2061: there is no :file:`setup.py`, and the benchmark image copies only files that exist.

``pyproject.toml`` declares everything, and the 3.8 floor (#2051) left
:file:`setup.py` a Python 2 guard and a bare ``setup()``, so it went.

* :class:`TestNoSetupPy` fails if one comes back at the repository root.
* :class:`TestBenchmarkDockerfileCopies` checks every source a ``COPY`` in
  :file:`examples/benchmark/Dockerfile` names is in the build context, the
  repository root that ``run.sh`` passes. Its ``COPY`` of the packaging files
  named :file:`setup.py` too, and a missing source fails only at ``docker
  build``, which no CI job runs.

"""

from __future__ import annotations

import pathlib
import shlex
import shutil
import subprocess  # nosec: B404
import unittest

#: Test tier (#1958): reads the repository's files and asks git which it tracks.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / 'examples' / 'benchmark' / 'Dockerfile'


def instructions(text: 'str') -> 'list[str]':
    """The Dockerfile's instructions, each with its continuation lines joined."""
    result = []  # type: list[str]
    pending = ''
    for line in text.splitlines():
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith('#')):
            continue
        if pending and stripped.startswith('#'):  # a comment inside a continuation
            continue
        if stripped.endswith('\\'):
            pending += stripped[:-1] + ' '
            continue
        result.append(pending + stripped)
        pending = ''
    if pending:
        result.append(pending)
    return result


def copy_sources(text: 'str') -> 'list[str]':
    """Every source path a build-context ``COPY`` names, in order.

    A ``COPY --from=...`` reads another stage or image, not the context, so it
    is left out; so are flags and the destination.

    """
    sources = []  # type: list[str]
    for instruction in instructions(text):
        keyword, _, rest = instruction.partition(' ')
        if keyword.upper() != 'COPY':
            continue
        words = shlex.split(rest)
        if any(word.startswith('--from=') for word in words):
            continue
        operands = [word for word in words if not word.startswith('--')]
        sources.extend(operands[:-1])
    return sources


def tracked() -> 'set[str] | None':
    """Every path git tracks, or :data:`None` when this is not a checkout."""
    if shutil.which('git') is None or not (ROOT / '.git').exists():
        return None
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT,  # nosec
                            capture_output=True, check=True)
    return {name for name in result.stdout.decode('utf-8').split('\0') if name}


class TestNoSetupPy(unittest.TestCase):
    """``pyproject.toml`` is the only build configuration."""

    def test_there_is_no_setup_py(self) -> None:
        self.assertFalse((ROOT / 'setup.py').exists(),
                         'setup.py is back; pyproject.toml declares everything (#2061)')


class TestBenchmarkDockerfileCopies(unittest.TestCase):
    """Every ``COPY`` source in the benchmark image is in the build context."""

    def setUp(self) -> None:
        if not DOCKERFILE.is_file():  # pragma: no cover - an sdist does not ship it
            self.skipTest('examples/benchmark/Dockerfile is not in this tree')
        self.sources = copy_sources(DOCKERFILE.read_text(encoding='utf-8'))

    def test_the_parser_finds_the_packaging_copy(self) -> None:
        """A parser that found nothing would pass the check below vacuously."""
        for name in ('pyproject.toml', 'MANIFEST.in', 'README.md', 'pcapkit'):
            with self.subTest(name=name):
                self.assertIn(name, self.sources)

    def test_every_source_exists(self) -> None:
        """Tracked, on a checkout: ``docker build`` runs from a fresh clone too."""
        files = tracked()
        for source in self.sources:
            with self.subTest(source=source):
                if files is None:
                    self.assertTrue((ROOT / source).exists())
                else:
                    prefix = source.rstrip('/') + '/'
                    self.assertTrue(source in files or any(name.startswith(prefix) for name in files),
                                    f'{source} is not tracked, so a COPY of it fails the build')


if __name__ == '__main__':
    unittest.main()
