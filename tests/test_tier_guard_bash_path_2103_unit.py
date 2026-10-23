# -*- coding: utf-8 -*-
"""The tier guard's workflow steps run the ``bash`` its skip guard found (#2103).

On Windows, ``shutil.which('bash')`` finds Git Bash, but a bare ``'bash'`` handed to
:func:`subprocess.run` resolves to System32's ``bash.exe``, the WSL launcher, which
fails with ``Windows Subsystem for Linux has no installed distributions.``. Here a
``bash`` that fails the same way is put first on ``PATH`` after the guard has looked,
so only a step that runs the path the guard found still succeeds.

"""
from __future__ import annotations

import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

from tests import test_tier_guard

#: A ``bash`` that answers as the WSL launcher does with no distribution installed.
WSL_BASH = "#!/bin/sh\necho 'Windows Subsystem for Linux has no installed distributions.'\nexit 1\n"


@unittest.skipIf(os.name == 'nt' or shutil.which('bash') is None,
                 'the stand-in launcher is a sh script, and the steps are bash scripts')
class StubbedStepsRunTheBashTheGuardFound(unittest.TestCase):

    def test_a_bash_earlier_on_path_is_not_the_one_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            launcher = pathlib.Path(temp, 'bash')
            launcher.write_text(WSL_BASH, encoding='utf-8')
            launcher.chmod(0o755)
            with mock.patch.dict(os.environ, PATH=temp + os.pathsep + os.environ.get('PATH', '')):
                self.assertEqual(test_tier_guard.stubbed_argv('python -m pytest -q', {}),
                                 ['-m', 'pytest', '-q'])
