# -*- coding: utf-8 -*-
"""Conda Update's GitHub upload keeps the release's name and notes (#1657).

``conda-dist`` in :file:`.github/workflows/cron-conda.yml` attaches each build
bump's packages with ``ncipollo/release-action@v1.21.0`` and ``allowUpdates:
true``, which calls Update a release before uploading (``Action.updateRelease``
in ``src/Action.ts``). That request sends ``name``, ``body``, ``prerelease`` and
``draft`` whether or not the step sets them, and unset they are the tag, ``""``
and ``false`` (``CoreInputs``'s ``body`` and ``name`` getters and its
``updated*`` ones, in ``src/Inputs.ts``). ``v1.3.5.post42``, ``v1.4.1``,
``v1.4.1.post2`` and ``v1.5.0a1`` read name-is-tag and a 0-character body that
way. Each ``omit*DuringUpdate`` input makes its field ``undefined`` (the
``updated*`` getters), which Octokit drops from the request body
(``removeUndefinedProperties``, which the bundled ``merge`` calls in
``dist/index.js``), so the release keeps what Create Release wrote.

The step is read with the scanner of ``test_release_tags_the_run_sha_1634.py``,
which runs without PyYAML; :meth:`TestTheUploadKeepsTheRelease.test_yaml_reads_the_same`
checks it against :func:`yaml.safe_load` where PyYAML is installed.

"""

from __future__ import annotations

import unittest

from tests import _workflows
from tests.project.test_release_tags_the_run_sha_1634 import (CONDA_WORKFLOW, UPLOAD_STEP,
                                                              CondaDistMixin)

#: The pinned action, and the release its commit is (#1968). The input names and
#: the citations above are for this tag, so a bump means reading the action again.
ACTION = 'ncipollo/release-action'
VERSION = 'v1.21.0'

#: The inputs that leave a field out of Update a release, and the field each keeps.
OMITTED = {
    'omitBodyDuringUpdate': 'body',
    'omitDraftDuringUpdate': 'draft',
    'omitNameDuringUpdate': 'name',
    'omitPrereleaseDuringUpdate': 'prerelease',
}

#: Every input the step sets. Another one changes what the update sends -- a
#: ``makeLatest``, say, whose ``legacy`` default is already sent as
#: ``make_latest`` (the ``makeLatest`` input in ``action.yml``, and
#: ``GithubReleases.update`` in ``src/Releases.ts``) -- so adding
#: one means reading the action again before adding it here.
INPUTS = {'allowUpdates', 'artifacts', 'commit', 'tag', 'token', *OMITTED}


class TestTheUploadKeepsTheRelease(CondaDistMixin, unittest.TestCase):
    """Update a release leaves the name, body and flags as Create Release wrote them."""

    def test_the_action_is_the_one_read(self) -> None:
        self.assertTrue(_workflows.pinned(self.upload().get('uses'), ACTION), self.upload().get('uses'))
        self.assertEqual(_workflows.versions(CONDA_WORKFLOW, ACTION), [VERSION])
        self.assertEqual(self.upload()['with'].get('allowUpdates'), 'true')

    def test_each_field_the_update_would_reset_is_omitted(self) -> None:
        inputs = self.upload()['with']
        for flag, field in OMITTED.items():
            with self.subTest(flag=flag):
                self.assertEqual(inputs.get(flag), 'true',
                                 f'without {flag}, every bump resets the release\'s {field}')

    def test_every_input_is_accounted_for(self) -> None:
        self.assertEqual(sorted(self.upload()['with']), sorted(INPUTS))

    def test_yaml_reads_the_same(self) -> None:
        """A key the scanner reads but YAML places elsewhere would pass vacuously."""
        try:
            import yaml  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.skipTest('PyYAML is not installed (the `test` extra)')
        steps = yaml.safe_load(CONDA_WORKFLOW.read_text(encoding='utf-8'))['jobs']['conda-dist']['steps']
        found = [step for step in steps if step.get('name') == UPLOAD_STEP]
        self.assertEqual(len(found), 1)
        inputs = found[0]['with']
        self.assertEqual(sorted(inputs), sorted(INPUTS))
        for flag in OMITTED:
            with self.subTest(flag=flag):
                self.assertIs(inputs[flag], True)


if __name__ == '__main__':
    unittest.main()
