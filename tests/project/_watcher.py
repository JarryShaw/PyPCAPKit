# -*- coding: utf-8 -*-
"""The harness the superseded-run tests share: ``Run unit tests`` under the real watcher (#3148).

Four modules run experimental.yml's ``Run unit tests`` step with ``python`` a
stub and the API a local server (#1938, #2073, #2077, #2078). This module holds
what they would otherwise each copy: the server, the stubbed ``PATH``, the
environment, and the step's script with the watcher's timings shortened.

"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import sys
import tempfile
import threading
from typing import TYPE_CHECKING

from tests.project.test_python_versions_1660 import ROOT
from tests.project.test_resource_monitor_1740 import TESTS, step

if TYPE_CHECKING:
    import unittest
    from typing import Any, Optional

#: The commit a run tests, and the one that supersedes it.
OURS, NEWER = 'a' * 40, 'b' * 40
REPO = 'JarryShaw/PyPCAPKit'
#: ``python`` as a stub that runs until stopped.
COLLECTS = 'echo collected\nexec sleep 60\n'
#: ``sudo`` as a stub whose probe fails, so the tests run uncapped.
NO_SUDO = 'echo "sudo: a password is required" >&2\nexit 1\n'


class Server(http.server.ThreadingHTTPServer):
    """The API, answering ``/repos/<repo>/commits/main`` with ``head``."""

    head = NEWER


class Handler(http.server.BaseHTTPRequestHandler):

    def do_GET(self) -> 'None':  # pylint: disable=invalid-name
        if self.path != f'/repos/{REPO}/commits/main':
            self.send_error(404)
            return
        body = json.dumps({'sha': self.server.head}).encode()  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: 'str', *args: 'Any') -> 'None':  # pylint: disable=redefined-builtin
        pass


def tmpdir(case: 'unittest.TestCase', prefix: 'str') -> 'pathlib.Path':
    """A scratch directory, removed when ``case`` ends."""
    tmp = tempfile.TemporaryDirectory(prefix=prefix)  # pylint: disable=consider-using-with
    case.addCleanup(tmp.cleanup)
    return pathlib.Path(tmp.name)


def quickened(case: 'unittest.TestCase') -> 'str':
    """``Run unit tests``'s script, its watcher polling in half-seconds so a stop takes seconds."""
    script = step(TESTS)['run']
    quick = script.replace('watch --interval 60 --grace 30 ', 'watch --interval 0.5 --grace 2 --kill-wait 2 ')
    case.assertNotEqual(quick, script)
    return quick


class Runner:
    """What ``Run unit tests`` runs against: a ``PATH`` of stubs, a server and an environment.

    Args:
        case: The test, whose cleanups stop the server.
        root: The scratch directory; the stubs go in its ``bin``.
        temp: ``RUNNER_TEMP``, made if absent.
        summary: The job summary file.
        output: The step-output file, if the test reads the step's outputs.
        python: The ``python`` stub's body.

    Attributes:
        env: The step's environment, to extend with ``dict(runner.env, ...)``.
        server: The API; set ``server.head`` to the commit it reports.
        python: The ``python`` stub, to rewrite for a different run.
        bindir: The stubs' directory, first on ``PATH``.

    """

    def __init__(self, case: 'unittest.TestCase', root: 'pathlib.Path', temp: 'pathlib.Path',
                 summary: 'pathlib.Path', output: 'Optional[pathlib.Path]' = None,
                 python: 'str' = COLLECTS) -> 'None':
        self.bindir = root / 'bin'
        self.bindir.mkdir()
        temp.mkdir(exist_ok=True)
        (temp / 'resource-monitor.log').write_text('', encoding='utf-8')
        self.python = self.bindir / 'python'
        for name, body in (('sudo', NO_SUDO), ('python', python)):
            (self.bindir / name).write_text('#!/bin/sh\n' + body, encoding='utf-8')
            (self.bindir / name).chmod(0o755)
        self.server = Server(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        case.addCleanup(self.server.server_close)
        case.addCleanup(self.server.shutdown)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith('GITHUB_') and key != 'JOB_SUMMARY_COPY'}
        self.env.update(RUNNER_TEMP=str(temp), GITHUB_WORKSPACE=str(ROOT), WORKERS='3', GRAAL_PYTHON_VM_ARGS='',
                        GITHUB_STEP_SUMMARY=str(summary), GH_TOKEN='token',
                        GITHUB_API_URL=f'http://127.0.0.1:{self.server.server_address[1]}',
                        GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_SHA=OURS,
                        GITHUB_REPOSITORY=REPO, PATH=str(self.bindir) + os.pathsep + os.environ.get('PATH', ''),
                        # `watcher-python` and its requests: this interpreter, which has requests.
                        WATCHER='success', WATCHER_PYTHON=sys.executable)
        if output is not None:
            self.env['GITHUB_OUTPUT'] = str(output)
