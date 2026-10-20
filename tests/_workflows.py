"""The workflow files under :file:`.github/workflows`, parsed once per process (#1967).

The tests that pin workflow structure read the same files over and over, and
PyYAML's pure-Python loader is slow on the larger ones. :func:`load` parses a file's text once and hands every caller its own deep
copy, so a test may edit what it gets without the next caller seeing the edit.

* **The cache is keyed on the text**, which is read again on every call. A test
  that writes a doctored copy of a workflow, or rewrites a file in place, gets
  that text parsed, however the file's size and modification time compare.
* **The C loader is used where PyYAML was built with libyaml**, and the
  pure-Python :class:`yaml.SafeLoader` otherwise. Both build the same objects
  from these files; :mod:`tests.project.test_workflow_loader_1967_unit` checks it.
* **The top-level** ``on:`` **key is spelt** ``'on'``. YAML 1.1, which PyYAML
  implements, reads a plain ``on`` as the boolean :data:`True`, where GitHub reads
  the trigger key.
* **Without PyYAML** (the ``test`` extra) every helper raises
  :exc:`unittest.SkipTest`, so a test that needs one skips.

"""

from __future__ import annotations

import copy
import functools
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

try:
    from yaml import CSafeLoader as Loader
except ImportError:  # pragma: no cover - no PyYAML, or one built without libyaml
    Loader = None if yaml is None else yaml.SafeLoader

if TYPE_CHECKING:
    import os
    from typing import Any, Union

    PathLike = Union[str, 'os.PathLike[str]']

__all__ = ['WORKFLOWS', 'NO_YAML', 'load', 'loads', 'job', 'steps']

#: Directory holding the workflow files. A relative name given to :func:`load` is
#: read from here; an absolute path is read as it stands.
WORKFLOWS = ROOT / '.github' / 'workflows'
#: Why a helper skips its caller where PyYAML is missing.
NO_YAML = 'PyYAML, from the test extra, is not installed'
#: How many distinct texts :func:`_parse` keeps. The workflow files, the same files
#: as an older commit held them, and the copies a test doctors all fit.
CACHE_SIZE = 128


@functools.lru_cache(maxsize=CACHE_SIZE)
def _parse(text: 'str') -> 'Any':
    """``text`` parsed, with the top-level ``on`` key restored; shared, so never handed out."""
    document = yaml.load(text, Loader=Loader)  # nosec: B506 - Loader is a safe loader
    if isinstance(document, dict):
        document = {('on' if key is True else key): value for key, value in document.items()}
    return document


def loads(text: 'str') -> 'Any':
    """``text``, a workflow's contents, parsed: a fresh copy the caller may change."""
    if yaml is None:  # pragma: no cover
        raise unittest.SkipTest(NO_YAML)
    return copy.deepcopy(_parse(text))


def load(path: 'PathLike') -> 'Any':
    """The workflow at ``path``, a name under :data:`WORKFLOWS` or an absolute path, parsed.

    The file is read on every call and parsed only when its text is new to this
    process. The result is the caller's own copy.

    """
    if yaml is None:  # pragma: no cover
        raise unittest.SkipTest(NO_YAML)
    return loads((WORKFLOWS / path).read_text(encoding='utf-8'))


def job(path: 'PathLike', job_id: 'str') -> 'dict[str, Any]':
    """Job ``job_id`` of the workflow at ``path``, as :func:`load` reads it."""
    return load(path)['jobs'][job_id]


def steps(path: 'PathLike', job_id: 'str') -> 'list[dict[str, Any]]':
    """The ``steps`` of job ``job_id`` of the workflow at ``path``, as :func:`load` reads it."""
    return job(path, job_id)['steps']
