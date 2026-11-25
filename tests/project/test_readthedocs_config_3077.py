# -*- coding: utf-8 -*-
"""#3077: :file:`.readthedocs.yaml`, which Read the Docs builds each version from.

It installs as the GitHub Pages build does, and on a CPython the repository
supports. Which versions the project builds, and its webhook, are settings of the
Read the Docs project that no test here can read. :mod:`tests.project.test_pages_dev_latest_3077`
pins what :file:`docs/source/conf.py` does on a Read the Docs build.

"""

from __future__ import annotations

import pathlib
import re
import unittest

from tests import _workflows
from tests.project.test_python_versions_1660 import NO_TOMLLIB, python_versions

#: Test tier (#1958): reads the repository's text.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / '.readthedocs.yaml'
#: The Pages build's step that installs the documentation's dependencies.
INSTALL = 'Install and Build 🔧'


@unittest.skipIf(_workflows.yaml is None, _workflows.NO_YAML)
class TestTheConfig(unittest.TestCase):

    def setUp(self) -> None:
        self.assertTrue(CONFIG.is_file(), f'{CONFIG.name} is missing, so Read the Docs cannot build a version')
        self.config = _workflows.load(CONFIG)
        step = next(step for step in _workflows.steps('deploy-pages.yml', 'deploy-pages')
                    if step.get('name') == INSTALL)
        self.pages = step['run']

    def test_it_is_a_version_2_sphinx_build(self) -> None:
        self.assertEqual(self.config['version'], 2)
        self.assertRegex(self.config['build']['os'], r'^ubuntu-\d\d\.04$')
        configuration = self.config['sphinx']['configuration']
        self.assertEqual(configuration, 'docs/source/conf.py')
        self.assertTrue((ROOT / configuration).is_file())

    @unittest.skipIf(python_versions is None, NO_TOMLLIB)
    def test_its_python_is_a_supported_cpython(self) -> None:
        version = self.config['build']['tools']['python']
        self.assertIsInstance(version, str, 'quote the version, or YAML reads 3.10 as 3.1')
        self.assertIn(version, python_versions.tier(python_versions.load(), 'cpython', 'supported'))

    def test_it_installs_what_the_pages_build_does(self) -> None:
        requirements, package = self.config['python']['install']
        self.assertEqual(requirements, {'requirements': 'docs/requirements.txt'})
        self.assertIn(f"pip install -r {requirements['requirements']}\n", self.pages)
        extras = re.search(r"pip install -e '\.\[(?P<extras>[\w,]+)\]'", self.pages)
        assert extras is not None, f'{INSTALL} installs no extras'
        self.assertEqual(package, {'method': 'pip', 'path': '.',
                                   'extra_requirements': extras.group('extras').split(',')})


if __name__ == '__main__':
    unittest.main()
