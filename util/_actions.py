# -*- coding: utf-8 -*-
"""The GitHub Actions plumbing the :file:`util/` scripts share (#2047).

Workflow commands, ``$GITHUB_OUTPUT`` and ``$GITHUB_STEP_SUMMARY`` writes, and
the run that copies a command's output to the log and to a file, written once
here instead of in each script. A script that the steps run as ``python
util/<script>.py`` has :file:`util/` first on :data:`sys.path`, so it imports
this module as ``_actions``; imported as ``util.<script>``, or loaded by path,
from the repository root, it imports ``util._actions``.

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

__all__ = ['LEVELS', 'escape_data', 'escape_property', 'annotation', 'annotate', 'group',
           'set_output', 'summary', 'open_summary', 'emit', 'say', 'exit_status', 'run']

#: The annotation commands, by level.
LEVELS = ('error', 'warning', 'notice')


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


def open_summary(*, environ: 'Optional[Mapping[str, str]]' = None) -> 'IO[str]':
    """``$GITHUB_STEP_SUMMARY``, open to append to, in UTF-8; :exc:`KeyError` where it is unset."""
    return open((os.environ if environ is None else environ)['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8')


def summary(*lines: 'str', required: 'bool' = True, environ: 'Optional[Mapping[str, str]]' = None) -> 'bool':
    """Append each of ``lines``, and a newline, to ``$GITHUB_STEP_SUMMARY``; whether it was written.

    Where ``$GITHUB_STEP_SUMMARY`` is unset, a ``required`` write raises
    :exc:`KeyError` and any other writes nothing.

    """
    path = _path('GITHUB_STEP_SUMMARY', required, environ)
    if path is None:
        return False
    with open(path, 'a', encoding='utf-8') as file:
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
