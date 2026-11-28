"""The checkout's source files, read, parsed and tokenized once per process (#3148).

The tests that scan a tree -- every module of :mod:`pcapkit`, every test module,
every tracked ``.py`` -- read and parse the same files in each test that scans,
and parsing is what the scan costs. These helpers do that work once per file, or
once per file and ``extract`` for :func:`parsed`, and hand every later caller the
result.

* **What is kept is small.** :func:`text` keeps a file's text and :func:`comments`
  its comment tokens. :func:`parsed` keeps what its ``extract`` returns, never the
  tree: a tree takes many times the memory of its text, and every full
  :func:`gc.collect` walks each node kept, which :file:`util/run_unittest_leg.py`
  runs every few tests.
* **A file is read again when it changes.** Each entry is keyed by the resolved
  path and checked on every call against the file's inode, size, modification and
  status-change times. A filesystem advances those times in coarse ticks, so a
  same-size rewrite within one would keep them: a file changed within
  :data:`RACY_NS` of the call is read again every time and kept nowhere, as git
  treats a racy timestamp.
* **Only the checkout is cached.** A path outside :data:`~tests._tiers.ROOT`, as a
  test's temporary tree is, is read and parsed on every call and kept nowhere.

Nothing here imports :mod:`pcapkit`, so a project pin may use it (#1954).

"""

from __future__ import annotations

import ast
import io
import pathlib
import time
import tokenize
from typing import TYPE_CHECKING, NamedTuple

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any, Callable, TypeVar, Union

    T = TypeVar('T')
    PathLike = Union[str, 'pathlib.Path']

__all__ = ['RACY_NS', 'Comment', 'text', 'parsed', 'comments', 'comments_in']

#: How recently a file may have changed, in nanoseconds, and still be kept: well
#: past a filesystem's timestamp tick.
RACY_NS = 100 * 10**6


class Comment(NamedTuple):
    """A ``#`` comment token: where it starts and its text, ``#`` included."""

    #: 1-based line number.
    line: 'int'
    #: 0-based column.
    column: 'int'
    #: The comment, as :mod:`tokenize` gives it.
    string: 'str'


#: ``(kind, path)`` to the file's ``(ino, size, mtime_ns, ctime_ns)`` and what was
#: computed from it, where ``kind`` is ``'text'``, ``'comments'`` or a :func:`parsed`
#: ``extract``.
_CACHE = {}  # type: dict[tuple[object, pathlib.Path], tuple[tuple[int, int, int, int], Any]]


def _resolve(path: 'PathLike') -> 'pathlib.Path':
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    return candidate.resolve()


def _cached(kind: 'object', path: 'pathlib.Path', compute: 'Callable[[pathlib.Path], T]') -> 'T':
    """``compute(path)``, kept under ``kind`` while the file stays as it was."""
    try:
        path.relative_to(ROOT)
    except ValueError:
        return compute(path)
    stat = path.stat()
    if time.time_ns() - max(stat.st_mtime_ns, stat.st_ctime_ns) < RACY_NS:
        _CACHE.pop((kind, path), None)
        return compute(path)
    stamp = (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    found = _CACHE.get((kind, path))
    if found is None or found[0] != stamp:
        found = _CACHE[kind, path] = (stamp, compute(path))
    return found[1]


def _read(path: 'pathlib.Path') -> 'str':
    return path.read_text(encoding='utf-8')


def text(path: 'PathLike') -> 'str':
    """The text of ``path``, absolute or relative to :data:`~tests._tiers.ROOT`, read as UTF-8."""
    return _cached('text', _resolve(path), _read)


def parsed(path: 'PathLike', extract: 'Callable[[ast.Module, str], T]') -> 'T':
    """``extract(tree, source)`` for the Python file at ``path``.

    ``extract`` is the cache key with the path, so it should be a module-level
    function, and what it returns should hold no node of the tree, which is
    parsed for the call and then dropped.

    """
    resolved = _resolve(path)

    def compute(where: 'pathlib.Path') -> 'T':
        source = text(where)
        return extract(ast.parse(source, filename=str(where)), source)
    return _cached(extract, resolved, compute)


def comments_in(source: 'Union[bytes, str]') -> 'tuple[Comment, ...]':
    """Every comment token of Python ``source``, in order.

    ``bytes`` are read as Python reads a file, an encoding cookie or a BOM honoured;
    a ``str`` is read as it stands.

    """
    if isinstance(source, bytes):
        tokens = tokenize.tokenize(io.BytesIO(source).readline)
    else:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    return tuple(Comment(token.start[0], token.start[1], token.string)
                 for token in tokens if token.type == tokenize.COMMENT)


def _comments(path: 'pathlib.Path') -> 'tuple[Comment, ...]':
    return comments_in(path.read_bytes())


def comments(path: 'PathLike') -> 'tuple[Comment, ...]':
    """:func:`comments_in` the Python file at ``path``, from its bytes."""
    return _cached('comments', _resolve(path), _comments)
