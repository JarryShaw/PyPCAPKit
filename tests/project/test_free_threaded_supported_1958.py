# -*- coding: utf-8 -*-
"""#1958, phase 4: free-threaded CPython 3.14t is supported, and runs with the GIL off.

By the owner's ruling 3.14t leaves experimental.yml for unit-tests.yml's ``test``
and ``integration``, which block, and gains a ``Compat Python 3.14t`` leg, a
required context. It has no wheel, conda build or ``engine-tests`` cell of its
own: 3.14's pure-Python wheel is the one it installs. Its legs set
``PYTHON_GIL=0``, leave ``lxml`` out of the install, and fail where a test still
finds the GIL on (:mod:`tests._gil_guard`).

"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess  # nosec B404
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests import _gil_guard
from tests.project.test_ktlo_legs_stay_green_1672 import leg_env
from tests.project.test_python_matrix_tiers_1633 import job, legs
from tests.project.test_python_versions_1660 import ROOT, live_outputs, prose, script, write_tiers
from tests.project.test_python_versions_update_1660 import FROZEN, as_of_the_file, scratch, snapshot, updater

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflows and the tier file, imports no pcapkit.
__tier__ = 'LATEST'

FREE = '3.14t'
#: The jobs whose legs run the tests, each with its install step.
TESTED = {('unit-tests.yml', 'test'): 'Install package and test dependencies',
          ('unit-tests.yml', 'integration'): 'Install package, test and generator dependencies'}
#: The free-threaded check the Compat leg's ``Verify package`` runs.
COMPAT_CHECK = ("python -c 'import sys, sysconfig, pcapkit; "
                "sys.exit(sysconfig.get_config_var(\"Py_GIL_DISABLED\") == 1 and sys._is_gil_enabled())'")
#: A ``python`` that answers the install step's free-threading probe from ``$FREE``
#: and records every other call's arguments in ``$ARGS_FILE``, one call a line.
STUB = '''#!/bin/sh
case "$*" in
  *Py_GIL_DISABLED*) if [ "$FREE" = 1 ]; then echo 1; else echo None; fi; exit 0 ;;
esac
echo "$*" >> "$ARGS_FILE"
'''


def step(where: 'tuple[str, str]', name: 'str') -> 'dict[str, Any]':
    found = [entry for entry in job(*where)['steps'] if entry.get('name') == name]
    if len(found) != 1:
        raise AssertionError(f'{where}: {len(found)} steps named {name!r}')
    return found[0]


class TestTheTierFile(unittest.TestCase):
    """3.14t is supported; every job but the tested ones and Compat leaves it out."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1958-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def test_3_14t_is_supported_and_hand_kept(self) -> None:
        data = script().load()
        self.assertEqual(data['versions']['cpython'][FREE], {'tier': 'supported'})
        self.assertIn(FREE, script().tier(data, 'cpython', 'supported'))
        self.assertNotIn(FREE, script().builds(data, 'cpython', 'supported'))
        self.assertTrue(script().hand_kept('cpython', FREE))
        self.assertNotIn(FREE, script().tier(data, 'cpython', 'experimental'))

    def test_it_runs_test_integration_and_compat_alone(self) -> None:
        values = live_outputs()
        for output in ('test', 'integration', 'compatibility'):
            with self.subTest(output=output):
                self.assertIn(FREE, json.loads(values[output])['python-version'])
        for output in ('experimental', 'test-ktlo', 'integration-ktlo', 'pypcap-parity', 'pypi', 'conda'):
            with self.subTest(output=output):
                self.assertNotIn(FREE, json.dumps(json.loads(values[output])))
        for output in ('engine-supported', 'engine-ktlo', 'pypi-wheels', 'conda-builds'):
            with self.subTest(output=output):
                self.assertNotIn(FREE, values[output].split())
        self.assertEqual(values['pypi-wheels'].split().count('cp314'), 1)

    def test_conda_vendor_refreshes_pins_for_the_conda_builds_alone(self) -> None:
        """util/conda_vendor.py's Pythons are the ``conda`` output's, so no pin waits on a cp314t wheel."""
        spec = importlib.util.spec_from_file_location('conda_vendor_1958', ROOT / 'util' / 'conda_vendor.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        self.assertEqual(module.conda_pythons(), json.loads(live_outputs()['conda']))
        self.assertNotIn(FREE, module.conda_pythons())

    def test_load_holds_a_free_threaded_build_to_its_default_build(self) -> None:
        data = script().load()
        cpython = dict(data['versions']['cpython'])
        cases = {
            'free-threaded KTLO': dict(cpython, **{FREE: {'tier': 'ktlo'}}),
            'supported without its default build': dict(cpython, **{'3.16t': {'tier': 'supported'}}),
            'listed among the computed versions': dict(
                {key: value for key, value in cpython.items() if key not in ('3.15', FREE)},
                **{FREE: {'tier': 'supported'}, '3.15': {'tier': 'supported'}}),
        }
        for label, versions in cases.items():
            with self.subTest(case=label), self.assertRaises(ValueError):
                script().load(write_tiers(self.tmp, dict(data, versions=dict(data['versions'], cpython=versions))))
        with self.assertRaises(ValueError):
            script().load(write_tiers(self.tmp, dict(data, latest=FREE)))

    def test_the_weekly_job_keeps_its_line_and_leaves_it_out_of_the_prose(self) -> None:
        """Hand-kept though supported: byte for byte, no classifier, but a Compat row and context."""
        root = scratch(self)
        module = updater()
        tier_file = root / module.TIER_FILE
        line = '"3.14t" = { tier = "supported" }  # free-threaded, hand-kept\n'
        text = tier_file.read_text(encoding='utf-8')
        anchor = '"3.15" = { tier = "supported" }\n'
        self.assertEqual(text.count(anchor), 1)
        tier_file.write_text(text.replace(anchor, anchor + line), encoding='utf-8')
        plan, texts = module.compute_plan(root, as_of_the_file(snapshot()))
        self.assertEqual(plan['changes'], [])
        self.assertNotIn(module.TIER_FILE, texts)
        self.assertNotIn('pyproject.toml', texts)
        page = texts['docs/source/contributing/workflows.rst']
        self.assertIn('* - ``Compat Python 3.14t``\n', page)
        self.assertIn('``.github/python-versions.toml:25``', page.split('Compat Python 3.14t', 1)[1][:200])
        values = module.pv.outputs(module.validate(tier_file.read_text(encoding='utf-8')))
        self.assertIn('Compat Python 3.14t', module.required_contexts(module.load_workflows(root), values))


class TestTheLegsKeepTheGilOff(unittest.TestCase):

    def test_python_gil_is_0_on_the_free_threaded_legs_alone(self) -> None:
        for where in TESTED:
            found = [leg['python-version'] for leg in legs(*where)]
            self.assertIn(FREE, found)
            for leg in legs(*where):
                with self.subTest(job=where[1], python=leg['python-version']):
                    expected = '0' if leg['python-version'] == FREE else ''
                    self.assertEqual(leg_env(where[0], job(*where), leg)['PYTHON_GIL'], expected)

    def run_install(self, where: 'tuple[str, str]', free: 'bool') -> 'list[str]':
        with tempfile.TemporaryDirectory() as temp:
            stub = pathlib.Path(temp, 'python')
            stub.write_text(STUB, encoding='utf-8')
            stub.chmod(0o755)
            record = pathlib.Path(temp, 'args')
            record.touch()
            env = dict(os.environ, FREE='1' if free else '0', ARGS_FILE=str(record), RUNNER_TEMP=temp,
                       LEG='Python 3.14t', ANNOTATION_LEVEL='error',
                       PATH=temp + os.pathsep + os.environ.get('PATH', ''))
            result = subprocess.run(['bash', '-eo', 'pipefail', '-c', step(where, TESTED[where])['run']],  # nosec
                                    env=env, cwd=ROOT, capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return record.read_text(encoding='utf-8').splitlines()

    def test_the_install_leaves_lxml_out_on_a_free_threaded_build(self) -> None:
        for where in TESTED:
            for free in (True, False):
                with self.subTest(job=where[1], free_threaded=free):
                    calls = self.run_install(where, free)
                    self.assertTrue(calls and calls[-1 if not free else -2].startswith('-m pip install -e '), calls)
                    self.assertEqual('-m pip uninstall -y lxml' in calls, free, calls)

    def test_the_compat_leg_fails_where_pcapkit_turns_the_gil_on(self) -> None:
        verify = step(('python-compatibility.yml', 'compatibility'), 'Verify package')
        self.assertIn(COMPAT_CHECK, verify['run'])
        # With no PYTHON_GIL, so the GIL stays off only if no module pcapkit imports turns it on.
        spec = job('python-compatibility.yml', 'compatibility')
        for env in [spec.get('env') or {}] + [entry.get('env') or {} for entry in spec['steps']]:
            self.assertNotIn('PYTHON_GIL', env)

    def test_the_conftest_asks_the_guard_after_every_teardown(self) -> None:
        text = (ROOT / 'tests' / 'conftest.py').read_text(encoding='utf-8')
        self.assertIn('def pytest_runtest_makereport(item', text)
        self.assertIn('message = _gil_guard.failure(report.when, item.nodeid)', text)


class TestTheGuard(unittest.TestCase):

    def setUp(self) -> None:
        # The process's own state, put back after: the conftest's guard reads it too.
        self.addCleanup(setattr, _gil_guard, '_reported', _gil_guard._reported)  # pylint: disable=protected-access
        _gil_guard._reported = False  # pylint: disable=protected-access

    def test_it_fails_the_first_teardown_that_finds_the_gil_on(self) -> None:
        def on() -> bool:
            return True

        self.assertIsNone(_gil_guard.failure('call', 'a', enforce=on, probe=on))
        message = _gil_guard.failure('teardown', 'tests/test_a.py::test', enforce=on, probe=on)
        self.assertIsNotNone(message)
        self.assertIn('tests/test_a.py::test', str(message))
        self.assertIn('PYTHON_GIL=0', str(message))
        self.assertIsNone(_gil_guard.failure('teardown', 'b', enforce=on, probe=on))

    def test_it_passes_with_the_gil_off_or_unenforced(self) -> None:
        def on() -> bool:
            return True

        def off() -> bool:
            return False

        self.assertIsNone(_gil_guard.failure('teardown', 'a', enforce=on, probe=off))
        self.assertIsNone(_gil_guard.failure('teardown', 'a', enforce=off, probe=on))

    def test_it_enforces_on_a_free_threaded_build_under_actions_alone(self) -> None:
        free = _gil_guard.free_threaded()
        self.assertEqual(_gil_guard.enforced({'GITHUB_ACTIONS': 'true'}), free)
        self.assertFalse(_gil_guard.enforced({}))

    def test_the_docs_say_so(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        for phrase in ('3.14t is supported', '``PYTHON_GIL=0``', ':file:`tests/_gil_guard.py`',
                       '``Compat Python 3.14t``', 'LP#2111289'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)


if __name__ == '__main__':
    unittest.main()
