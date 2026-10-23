# -*- coding: utf-8 -*-
"""The GitHub Actions plumbing the :file:`util/` scripts share (#2047).

Workflow commands, ``$GITHUB_OUTPUT`` and ``$GITHUB_STEP_SUMMARY`` writes, the
run that copies a command's output to the log and to a file, and a variable
read as bytes on Windows too (#2120), written once here instead of in each
script. A script that the steps run as ``python util/<script>.py`` has
:file:`util/` first on :data:`sys.path`, so it imports this module as
``_actions``; imported as ``util.<script>``, or loaded by path, from the
repository root, it imports ``util._actions``.

The scripts run on the image's ``/usr/bin/python3``, or on a leg's own
interpreter, which may be 3.7, GraalPy or a free-threaded build, and
:file:`util/pip_install.py` is the step that installs anything at all. So this
module is standard library only and keeps to 3.7's syntax; a project test,
:file:`tests/project/test_actions_helper_2047.py`, holds it to both.

The escaping is GitHub's, from the "Workflow commands for GitHub Actions"
reference (https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands)
and ``escapeData`` and ``escapeProperty`` in ``@actions/core``'s ``command.ts``:
a command's message escapes ``%``, ``\\r`` and ``\\n``, and each property's value
escapes ``:`` and ``,`` as well.

A step that sets ``JOB_SUMMARY_COPY`` to a file has :func:`summary` and
:func:`open_summary` append what they write to that file too, the job's copy of
its summary (#2030). GitHub serves no job summary through its API, so the jobs
whose runs :file:`util/check_suite_report.py` reports upload the copy as an
artifact for the report to fold in. Only a step that writes the summary sets it,
never one that runs the test suite, whose tests write summaries of their own
through this module; :file:`util/superseded.py`, which runs the suite, takes the
copy's path as its ``--summary-copy`` option instead (#2078).

"""

from __future__ import annotations

import contextlib
import os
import subprocess  # nosec: B404
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from os import PathLike
    from typing import IO, Iterator, Mapping, Optional, Sequence, Tuple, Union

__all__ = ['LEVELS', 'SUMMARY_COPY', 'escape_data', 'escape_property', 'annotation', 'annotate', 'group',
           'set_output', 'summary', 'open_summary', 'emit', 'say', 'exit_status', 'run', 'getenvb']

#: The annotation commands, by level.
LEVELS = ('error', 'warning', 'notice')
#: The variable naming the job's copy of its summary (#2030).
SUMMARY_COPY = 'JOB_SUMMARY_COPY'


def escape_data(text: 'str') -> 'str':
    """``text`` as a workflow command's message must hold it."""
    return text.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def escape_property(text: 'str') -> 'str':
    """``text`` as the value of a workflow command's property must hold it."""
    return escape_data(text).replace(':', '%3A').replace(',', '%2C')


def annotation(level: 'str', message: 'str', *, title: 'Optional[str]' = None, file: 'Optional[str]' = None,
               line: 'Optional[int]' = None, escape: 'bool' = True) -> 'str':
    """The ``::<level>`` command, without its newline, of ``message`` and the properties given.

    The properties are ``title``, ``file`` and ``line``, in that order, each left
    out where it is :data:`None`. ``escape=False`` writes ``message`` and the
    properties as they are, for a caller that escapes them its own way.

    """
    if level not in LEVELS:
        raise ValueError(f'{level!r} is not one of {", ".join(LEVELS)}')
    data = escape_data if escape else str
    value = escape_property if escape else str
    properties = ','.join(name + '=' + value(str(setting)) for name, setting
                          in (('title', title), ('file', file), ('line', line)) if setting is not None)
    return '::' + level + (' ' + properties if properties else '') + '::' + data(message)


def annotate(level: 'str', message: 'str', *, title: 'Optional[str]' = None, file: 'Optional[str]' = None,
             line: 'Optional[int]' = None, escape: 'bool' = True, stream: 'Optional[IO[str]]' = None) -> 'None':
    """Print :func:`annotation` to ``stream``, standard output by default, at once."""
    print(annotation(level, message, title=title, file=file, line=line, escape=escape),
          file=sys.stdout if stream is None else stream, flush=True)


@contextlib.contextmanager
def group(title: 'str', *, escape: 'bool' = True) -> 'Iterator[None]':
    """Fold what the block prints into one ``::group::`` of the log, titled ``title``."""
    print('::group::' + (escape_data(title) if escape else title), flush=True)
    try:
        yield
    finally:
        print('::endgroup::', flush=True)


def _path(variable: 'str', required: 'bool', environ: 'Optional[Mapping[str, str]]') -> 'Optional[str]':
    """The file ``$variable`` names: :exc:`KeyError` where it is unset and ``required``, else :data:`None`."""
    environ = os.environ if environ is None else environ
    if required:
        return environ[variable]
    return environ.get(variable) or None


def set_output(name: 'str', value: 'str', *, required: 'bool' = True,
               environ: 'Optional[Mapping[str, str]]' = None) -> 'bool':
    """Append the step output ``name`` to ``$GITHUB_OUTPUT``; whether it was written.

    A ``value`` holding a line break, ``\\n`` or ``\\r``, is written under a fresh
    delimiter, ``name<<EOF_<hex>``, as GitHub's multiline form requires, since the
    runner reads the file a line at a time. Where ``$GITHUB_OUTPUT`` is unset, a
    ``required`` write raises :exc:`KeyError` and any other writes nothing.

    """
    path = _path('GITHUB_OUTPUT', required, environ)
    if path is None:
        return False
    if '\n' in value or '\r' in value:
        import uuid  # pylint: disable=import-outside-toplevel
        delimiter = f'EOF_{uuid.uuid4().hex}'
        text = f'{name}<<{delimiter}\n{value}\n{delimiter}\n'
    else:
        text = name + '=' + value + '\n'
    with open(path, 'a', encoding='utf-8') as file:
        file.write(text)
    return True


class _Teed:
    """The summary, open to append to, whose writes go to the job's copy of it too (#2030).

    The copy is best effort: once a write to it fails it is closed and left
    behind, and the summary is written all the same.

    """

    def __init__(self, page: 'IO[str]', copy: 'IO[str]') -> 'None':
        self._page = page
        self._copy = copy  # type: Optional[IO[str]]

    def _drop(self) -> 'None':
        copy, self._copy = self._copy, None
        if copy is not None:
            with contextlib.suppress(OSError):
                copy.close()

    def write(self, text: 'str') -> 'int':
        """Write ``text`` to the summary and to the copy; the characters written to the summary."""
        written = self._page.write(text)
        if self._copy is not None:
            try:
                self._copy.write(text)
            except OSError:
                self._drop()
        return written

    def flush(self) -> 'None':
        """Flush the summary and the copy."""
        self._page.flush()
        if self._copy is not None:
            try:
                self._copy.flush()
            except OSError:
                self._drop()

    def close(self) -> 'None':
        """Close the summary and the copy."""
        try:
            self._page.close()
        finally:
            self._drop()

    def __enter__(self) -> '_Teed':
        return self

    def __exit__(self, *_: 'object') -> 'None':
        self.close()


def open_summary(*, environ: 'Optional[Mapping[str, str]]' = None) -> 'IO[str]':
    """``$GITHUB_STEP_SUMMARY``, open to append to, in UTF-8; :exc:`KeyError` where it is unset.

    Where ``$JOB_SUMMARY_COPY`` names a file that opens, what is written goes
    there too; one that does not open is left out.

    """
    environ = os.environ if environ is None else environ
    # Both are the caller's to close, as the file this returned before #2030 was.
    page = open(environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8')  # pylint: disable=consider-using-with
    path = environ.get(SUMMARY_COPY)
    if not path:
        return page
    try:
        copy = open(path, 'a', encoding='utf-8')  # pylint: disable=consider-using-with
    except OSError:
        return page
    return _Teed(page, copy)  # type: ignore[return-value]


def summary(*lines: 'str', required: 'bool' = True, environ: 'Optional[Mapping[str, str]]' = None) -> 'bool':
    """Append each of ``lines``, and a newline, to ``$GITHUB_STEP_SUMMARY``; whether it was written.

    Where ``$GITHUB_STEP_SUMMARY`` is unset, a ``required`` write raises
    :exc:`KeyError` and any other writes nothing. The lines go to
    ``$JOB_SUMMARY_COPY`` too, as :func:`open_summary` writes.

    """
    if _path('GITHUB_STEP_SUMMARY', required, environ) is None:
        return False
    with open_summary(environ=environ) as file:
        for text in lines:
            file.write(text + '\n')
    return True


def emit(data: 'bytes') -> 'None':
    """Write ``data`` to standard output as it is, at once, ahead of any command's."""
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def say(text: 'str') -> 'None':
    """Write ``text`` and a newline to standard output at once, a lone surrogate as the byte it stands for."""
    emit(text.encode('utf-8', 'surrogateescape') + b'\n')


def exit_status(code: 'int') -> 'int':
    """``code`` as the shell reports it: a signal ``N`` as ``128 + N``."""
    return code if code >= 0 else 128 - code


def run(command: 'Sequence[str]', log_path: 'Union[str, PathLike[str]]') -> 'Tuple[int, bytes]':
    """Run ``command``, its standard error with its output, copying each line to standard output and the log.

    Each line goes out as it arrives, through :func:`emit`, and is flushed to
    the file ``log_path``, which is truncated first. The result is the command's
    return code, negative for a signal as :mod:`subprocess` gives it, and the
    whole of its output.

    """
    output = bytearray()
    with open(log_path, 'wb') as log:
        with subprocess.Popen(list(command), stdout=subprocess.PIPE,  # nosec: B603
                              stderr=subprocess.STDOUT) as process:
            assert process.stdout is not None  # nosec: B101
            for line in process.stdout:
                emit(line)
                log.write(line)
                log.flush()
                output.extend(line)
        status = process.returncode
    return status, bytes(output)


def getenvb(name: 'str') -> 'bytes':
    """``$name``, as bytes; :exc:`KeyError` where it is unset.

    That is :data:`os.environb`'s value where :data:`os.supports_bytes_environ`
    holds, and :data:`os.environ`'s, encoded as :func:`os.fsencode` encodes it,
    where it does not, as on Windows, which has no :data:`os.environb`.

    """
    if os.supports_bytes_environ:
        return os.environb[name.encode()]
    # #2120: Windows keeps its environment as text and has no os.environb, so
    # reading it there raised AttributeError on the win-64 conda leg.
    return os.fsencode(os.environ[name])
