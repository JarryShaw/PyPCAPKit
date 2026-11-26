# -*- coding: utf-8 -*-
"""#3077: GitHub Pages serves ``main``'s build alone, and sends a version's path to Read the Docs.

* :class:`TestTheVersions` checks :file:`util/pages_versions.py`'s map from each
  version's path segment to its Read the Docs URL, and :class:`TestTheScript` runs
  it as ``Write the version redirects`` does, on a scratch build and a scratch
  remote's tags.
* :class:`TestTheNotFoundPage` runs the ``404.html`` it writes under Node.js, where
  it is installed, for each kind of missing path.
* :class:`TestTheWorkflow` evaluates :file:`.github/workflows/deploy-pages.yml`
  per event: no push triggers it, every build writes the redirects, and the one
  publish cleans the whole site.
* :class:`TestTheConf` runs the statements of :file:`docs/source/conf.py` that
  follow the host, and :class:`TestTheVersionsLink` renders the sidebar
  template, where Jinja2 is installed.

No test reads Read the Docs itself, whose versions are the project's settings.

"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import pathlib
import random
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import types
import unittest
import urllib.parse
from typing import TYPE_CHECKING

from tests import _workflows
from tests._support import scale_timeout
from tests.project.test_release_gates import STATUS, job_blocks, job_runs

try:
    import jinja2
except ImportError:  # pragma: no cover - Sphinx's dependency, not the test extra's
    jinja2 = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the repository's text and drives a ``util/`` script.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'pages_versions.py'
CONF = ROOT / 'docs' / 'source' / 'conf.py'
TEMPLATE = ROOT / 'docs' / 'source' / '_templates' / 'sidebar' / 'versions.html'
PAGES = 'deploy-pages.yml'
#: The site root GitHub Pages serves, a project site under ``/PyPCAPKit/``.
SITE = 'https://jarryshaw.github.io/PyPCAPKit/'
#: Where Read the Docs serves every version.
READ_THE_DOCS = 'https://pypcapkit.jarryshaw.me/'
#: The events the workflow runs on; a pull request and a manual run build but
#: publish nothing.
EVENTS = ('workflow_run', 'schedule', 'pull_request', 'workflow_dispatch')
#: Release tags in PEP 440 order, each kind of pre- and post-release among them.
RELEASES = ('v0.9.0', 'v1.2.0', 'v1.10.0.dev1', 'v1.10.0a1', 'v1.10.0a2', 'v1.10.0b1', 'v1.10.0rc1',
            'v1.10.0', 'v1.10.0.post1.dev1', 'v1.10.0.post1', 'v1.10.0.post2', 'v1.10.1')
#: Tags that name no docs version.
NOT_RELEASES = ('conda-1.10.0', 'conda-v1.10.0', 'v1.10.0+local', 'vfoo', 'v1.10.0-rc1', '1.10.0')
#: The versions built from a branch, in the map's order: ``develop`` as ``latest``,
#: Stable Branch's mirror of ``main`` as ``stable``, and ``develop`` again as ``dev``.
BRANCHES = ('latest', 'stable', 'dev')
#: Node.js, which runs the ``404.html`` script.
NODE = shutil.which('node')
#: Runs ``404.html``'s script with ``location`` and ``fetch`` stubbed, and prints
#: what it fetched and where it sent the reader.
HARNESS = r'''
const vm = require('vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {fetched: [], replaced: null};
const location = {pathname: input.pathname, search: input.search, hash: input.hash,
                  replace: (url) => { out.replaced = url; }};
const fetch = (url) => {
  out.fetched.push(url);
  if (input.offline) return Promise.reject(new Error('offline'));
  return Promise.resolve({ok: input.ok, json: () => Promise.resolve(input.versions)});
};
vm.runInNewContext(input.script, {location, fetch});
setTimeout(() => process.stdout.write(JSON.stringify(out)), 50);
'''


def load_script() -> 'types.ModuleType':
    spec = importlib.util.spec_from_file_location('pages_versions', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def github(event: 'str') -> 'dict[str, Any]':
    run = {'conclusion': 'success', 'event': 'push', 'head_branch': 'main'}
    return {'event_name': event, 'ref': 'refs/heads/main', 'run_id': '7', 'sha': '1' * 40,
            'event': {'workflow_run': run} if event == 'workflow_run' else {}}


class TestTheVersions(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_script()

    def test_the_branches_lead_and_each_release_follows_by_version(self) -> None:
        tags = list(RELEASES + NOT_RELEASES)
        random.Random(3077).shuffle(tags)
        mapping = self.module.versions(tags)
        self.assertEqual(list(mapping), [*BRANCHES, *RELEASES])
        for name in (*BRANCHES, *RELEASES):
            with self.subTest(version=name):
                self.assertEqual(mapping[name], f'{READ_THE_DOCS}en/{name}/')

    def test_it_is_deterministic(self) -> None:
        tags = list(RELEASES + NOT_RELEASES)
        expected = json.dumps(self.module.versions(tags))
        for seed in range(5):
            random.Random(seed).shuffle(tags)
            with self.subTest(seed=seed):
                self.assertEqual(json.dumps(self.module.versions(tags + tags[:3])), expected)

    def test_no_branch_alone_is_a_release(self) -> None:
        self.assertEqual(list(self.module.versions(NOT_RELEASES).items()),
                         [(name, f'{READ_THE_DOCS}en/{name}/') for name in BRANCHES])


class TestTheScript(unittest.TestCase):
    """``python util/pages_versions.py BUILD --remote REPO``, against a scratch repository's tags."""

    def setUp(self) -> None:
        if shutil.which('git') is None:
            raise unittest.SkipTest('git not found on PATH')
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.build = self.root / 'html'
        self.build.mkdir()
        (self.build / 'index.html').write_text('index', encoding='utf-8')
        self.repo = self.root / 'repo'
        # Isolated from the caller's git configuration, and with no automatic
        # maintenance, whose detached repack can race the cleanup.
        home = self.root / 'home'
        home.mkdir()
        (home / '.gitconfig').write_text(
            '[user]\n\tname = t\n\temail = t@example.com\n[commit]\n\tgpgsign = false\n'
            '[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n', encoding='utf-8')
        self.env = {'PATH': os.environ.get('PATH', ''), 'HOME': str(home), 'GIT_CONFIG_NOSYSTEM': '1',
                    'LC_ALL': 'C'}
        self.git('init', '-q', str(self.repo), cwd=self.root)
        self.git('commit', '-q', '--allow-empty', '-m', 'root')

    def git(self, *args: 'str', cwd: 'Optional[pathlib.Path]' = None) -> 'None':
        subprocess.run(['git', *args], cwd=cwd or self.repo, env=self.env, check=True,  # nosec: B603 B607
                       capture_output=True, timeout=scale_timeout(30))

    def run_script(self) -> 'subprocess.CompletedProcess[str]':
        return subprocess.run([sys.executable, str(SCRIPT), str(self.build), '--remote', str(self.repo)],  # nosec
                              capture_output=True, text=True, check=False, env=self.env,
                              timeout=scale_timeout(60))

    def test_it_writes_both_files_from_the_tags(self) -> None:
        for tag in ('v1.10.0', 'v1.2.0', 'v1.10.0rc1', 'conda-1.10.0', 'vfoo'):
            self.git('tag', tag)
        self.git('tag', '-a', 'v1.10.1', '-m', 'annotated')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # One warning, for `vfoo`: an annotated tag is listed once, not peeled too.
        self.assertEqual(re.findall(r'::warning title=Not a release tag::(\S+)', result.stdout), ['vfoo'])
        text = (self.build / 'versions.json').read_text(encoding='utf-8')
        self.assertTrue(text.endswith('}\n'))
        self.assertEqual(list(json.loads(text).items()), [
            (name, f'{READ_THE_DOCS}en/{name}/')
            for name in (*BRANCHES, 'v1.2.0', 'v1.10.0rc1', 'v1.10.0', 'v1.10.1')])
        self.assertEqual((self.build / '404.html').read_text(encoding='utf-8'), load_script().page())

    def test_it_refuses_to_overwrite_either_file(self) -> None:
        self.git('tag', 'v1.0.0')
        for name in ('versions.json', '404.html'):
            with self.subTest(name=name):
                (self.build / name).write_text('built', encoding='utf-8')
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('already in the build', result.stderr)
                self.assertEqual((self.build / name).read_text(encoding='utf-8'), 'built')
                (self.build / name).unlink()

    def test_it_refuses_a_remote_with_no_release(self) -> None:
        self.git('tag', 'conda-1.0.0')
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('::error title=No release tags::', result.stdout)
        self.assertEqual(sorted(path.name for path in self.build.iterdir()), ['index.html'])

    def test_it_refuses_a_folder_that_is_no_build(self) -> None:
        self.git('tag', 'v1.0.0')
        (self.build / 'index.html').unlink()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('::error title=No documentation build::', result.stdout)
        self.assertEqual(list(self.build.iterdir()), [])


class TestTheNotFoundPage(unittest.TestCase):
    """The page against the map the script writes for one release, its branches included."""

    @classmethod
    def setUpClass(cls) -> None:
        module = load_script()
        cls.page = module.page()
        cls.VERSIONS = module.versions(['v1.7.0'])

    def run_page(self, pathname: 'str', search: 'str' = '', fragment: 'str' = '',
                 ok: 'bool' = True, offline: 'bool' = False) -> 'dict[str, Any]':
        if NODE is None:
            self.skipTest('Node.js not found on PATH')
        scripts = re.findall(r'(?s)<script>(.*?)</script>', self.page)
        self.assertEqual(len(scripts), 1)
        stdin = json.dumps({'script': scripts[0], 'pathname': pathname, 'search': search, 'hash': fragment,
                            'versions': self.VERSIONS, 'ok': ok, 'offline': offline})
        result = subprocess.run([NODE, '-e', HARNESS], input=stdin, capture_output=True,  # nosec: B603
                                text=True, check=False, timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_a_version_path_goes_to_its_page_on_read_the_docs(self) -> None:
        rows = (
            ('/PyPCAPKit/latest/pcapkit/foundation/extraction.html', '?q=1', '#the-extractor',
             f'{READ_THE_DOCS}en/latest/pcapkit/foundation/extraction.html?q=1#the-extractor'),
            ('/PyPCAPKit/stable/pcapkit/index.html', '', '#pcapkit',
             f'{READ_THE_DOCS}en/stable/pcapkit/index.html#pcapkit'),
            ('/PyPCAPKit/dev/', '', '', f'{READ_THE_DOCS}en/dev/'),
            ('/PyPCAPKit/dev', '', '', f'{READ_THE_DOCS}en/dev/'),
            ('/PyPCAPKit/v1.7.0/index.html', '', '#top', f'{READ_THE_DOCS}en/v1.7.0/index.html#top'),
        )
        for pathname, search, fragment, target in rows:
            with self.subTest(pathname=pathname):
                self.assertEqual(self.run_page(pathname, search, fragment),
                                 {'fetched': ['/PyPCAPKit/versions.json'], 'replaced': target})

    def test_any_other_path_stays_not_found(self) -> None:
        for pathname in ('/PyPCAPKit/pcapkit/missing.html', '/PyPCAPKit/v9.9.9/index.html',
                         '/PyPCAPKit/toString/index.html', '/PyPCAPKit/latest.html'):
            with self.subTest(pathname=pathname):
                self.assertEqual(self.run_page(pathname)['replaced'], None)
        # Nothing to look up: the site root, or a path outside the project site.
        for pathname in ('/PyPCAPKit/', '/latest/index.html', '/pypcapkit/latest/index.html'):
            with self.subTest(pathname=pathname):
                self.assertEqual(self.run_page(pathname), {'fetched': [], 'replaced': None})

    def test_an_unreadable_map_stays_not_found(self) -> None:
        for flags in ({'ok': False}, {'offline': True}):
            with self.subTest(**flags):
                self.assertEqual(self.run_page('/PyPCAPKit/latest/index.html', **flags),
                                 {'fetched': ['/PyPCAPKit/versions.json'], 'replaced': None})

    def test_it_is_self_contained(self) -> None:
        """No resource but ``versions.json``, and one link, to the site root."""
        self.assertNotRegex(self.page, r'<(link|img|iframe|style)\b|\bsrc=')
        self.assertEqual(re.findall(r'href="([^"]*)"', self.page), [SITE])
        self.assertEqual(re.findall(r'fetch\(([^)]*)\)', self.page), ['base + "versions.json"'])
        self.assertIn('<h1>Page not found</h1>', self.page)


@unittest.skipIf(_workflows.yaml is None, _workflows.NO_YAML)
class TestTheWorkflow(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (_workflows.WORKFLOWS / PAGES).read_text(encoding='utf-8')
        cls.spec = _workflows.load(PAGES)
        cls.jobs = job_blocks(cls.text)
        cls.build = {step.get('name'): step for step in cls.spec['jobs']['deploy-pages']['steps']}
        cls.deploy = next(step for step in cls.spec['jobs']['publish-pages']['steps']
                          if str(step.get('uses', '')).startswith('JamesIves/github-pages-deploy-action@'))

    def test_no_push_triggers_it(self) -> None:
        """``main``'s build chains off Unit Tests (#715), and Read the Docs serves ``develop``'s."""
        self.assertEqual(sorted(self.spec['on']), sorted(EVENTS))
        self.assertNotIn('PAGES_FOLDER', self.text)

    def test_every_build_writes_the_redirects_and_no_stubs(self) -> None:
        redirects = self.build['Write the version redirects']
        names = list(self.build)
        self.assertLess(names.index('Install and Build 🔧'), names.index('Write the version redirects'))
        self.assertLess(names.index('Write the version redirects'), names.index('Upload the built site'))
        self.assertEqual(redirects['run'], 'python util/pages_versions.py docs/build/html')
        self.assertNotIn('if', redirects)
        self.assertNotIn('env', self.build['Install and Build 🔧'])
        # #3077's `/latest/` stubs are gone with their script.
        self.assertNotIn('latest/', self.text)
        self.assertFalse((ROOT / 'util' / 'pages_latest.py').exists())

    def test_each_publishing_event_runs_the_gate_and_reports(self) -> None:
        self.assertNotIn('if', self.spec['jobs']['head'])
        for event in ('workflow_run', 'schedule'):
            context = {STATUS: {'cancelled': False}, 'github': github(event), 'needs': {
                'head': {'result': 'success', 'outputs': {'verified': 'true'}},
                'deploy-pages': {'result': 'success', 'outputs': {}},
                'publish-pages': {'result': 'success', 'outputs': {}}}}
            for job in ('deploy-pages', 'publish-pages', 'discussion'):
                with self.subTest(event=event, job=job):
                    self.assertTrue(job_runs(self.jobs, job, context))

    def test_one_target_publishes(self) -> None:
        publish = self.spec['jobs']['publish-pages']
        self.assertEqual(publish['concurrency'], {'group': 'publish-pages-${{ github.ref }}',
                                                  'cancel-in-progress': False})
        self.assertNotIn('env', publish)
        self.assertEqual(self.deploy['with']['commit-message'], 'Publish the documentation of ${{ github.sha }}')

    def test_the_publish_cleans_the_whole_site(self) -> None:
        """The redirects are in the folder published, so ``clean`` keeps them."""
        options = self.deploy['with']
        self.assertIs(options['clean'], True)
        self.assertEqual(options['folder'], self.build['Write the version redirects']['run'].split()[-1])
        for option in ('target-folder', 'clean-exclude'):
            with self.subTest(option=option):
                self.assertNotIn(option, options)

    def test_no_page_takes_a_redirect_path(self) -> None:
        """A version's segment, or ``404.html``, built by Sphinx would shadow the redirect."""
        module = load_script()
        tops = {path.stem for path in CONF.parent.iterdir()}
        self.assertFalse(tops & {*module.BRANCHES, '404'})
        self.assertFalse([name for name in tops if module.RELEASE.fullmatch(name)])
        # Nor may the build copy in files of its own at the root.
        tree = ast.parse(CONF.read_text(encoding='utf-8'))
        self.assertNotIn('html_extra_path', {target.id for node in tree.body for target in getattr(node, 'targets', [])
                                             if isinstance(target, ast.Name)})


class TestTheConf(unittest.TestCase):
    """What the host sets, by running the statements of conf.py that read it."""

    NAMES = {'READTHEDOCS', 'html_theme_options', 'html_sidebars', 'ogp_site_url', 'html_baseurl', 'html_css_files'}
    #: A version's URL, as Read the Docs gives it.
    CANONICAL = f'{READ_THE_DOCS}en/latest/'

    @classmethod
    def setUpClass(cls) -> None:
        cls.tree = ast.parse(CONF.read_text(encoding='utf-8'))
        body = []
        for node in cls.tree.body:
            targets = {target.id for target in getattr(node, 'targets', []) if isinstance(target, ast.Name)}
            inside = {name.id for name in ast.walk(node) if isinstance(name, ast.Name)}
            if targets & cls.NAMES or (isinstance(node, ast.If) and inside & cls.NAMES):
                body.append(node)
        cls.code = compile(ast.Module(body=body, type_ignores=[]), str(CONF), 'exec')

    def settings(self, **environ: 'str') -> 'dict[str, Any]':
        namespace = {'os': types.SimpleNamespace(environ=environ)}
        exec(self.code, namespace)  # nosec: B102 - conf.py's own statements
        return namespace

    def test_read_the_docs_names_its_own_url_and_drops_the_link(self) -> None:
        settings = self.settings(READTHEDOCS='True', READTHEDOCS_CANONICAL_URL=self.CANONICAL)
        self.assertEqual((settings['ogp_site_url'], settings['html_baseurl']), (self.CANONICAL, self.CANONICAL))
        self.assertNotIn('sidebar/versions.html', settings['html_sidebars']['**'])
        self.assertEqual(settings['html_sidebars']['**'],
                         [name for name in self.settings()['html_sidebars']['**'] if name != 'sidebar/versions.html'])

    def test_every_other_build_is_mains_at_the_root(self) -> None:
        """A build reads no folder: #3077's ``PAGES_FOLDER`` changes nothing."""
        names = {name.id for name in ast.walk(self.tree) if isinstance(name, ast.Name)}
        self.assertFalse(names & {'PAGES_FOLDER', 'html_context'})
        for environ in ({}, {'PAGES_FOLDER': 'dev'}):
            settings = self.settings(**environ)
            with self.subTest(environ=environ):
                self.assertEqual((settings['ogp_site_url'], settings['html_baseurl']), (SITE, SITE))
                self.assertEqual(settings['html_theme_options']['source_branch'], 'main')

    def test_the_redirects_name_the_same_sites(self) -> None:
        module = load_script()
        self.assertEqual(module.SITE, self.settings()['ogp_site_url'])
        self.assertEqual(module.READ_THE_DOCS, f'{READ_THE_DOCS}en/')

    def test_the_link_is_under_the_brand(self) -> None:
        settings = self.settings()
        sidebars = settings['html_sidebars']['**']
        self.assertEqual(sidebars[:2], ['sidebar/brand.html', 'sidebar/versions.html'])
        self.assertTrue(TEMPLATE.is_file())
        self.assertIn('versions.css', settings['html_css_files'])
        self.assertTrue((CONF.parent / '_static' / 'versions.css').is_file())


@unittest.skipIf(jinja2 is None, 'Jinja2, which Sphinx installs, is not installed')
class TestTheVersionsLink(unittest.TestCase):

    def links(self, pagename: 'str') -> 'list[tuple[str, str]]':
        """Each link's title and the URL it resolves to from the page."""
        template = jinja2.Environment(autoescape=True).from_string(TEMPLATE.read_text(encoding='utf-8'))
        depth = pagename.count('/')
        text = template.render(pagename=pagename, file_suffix='.html', content_root='../' * depth or './')
        page = f'{SITE}{pagename}.html'
        links = []
        for anchor in text.split('<a ')[1:]:
            href = anchor.split('href="', 1)[1].split('"', 1)[0]
            title = anchor.split('>', 1)[1].split('<', 1)[0]
            links.append((title, urllib.parse.urljoin(page, href)))
        return links

    def test_one_link_names_read_the_docs_from_every_page(self) -> None:
        for pagename in ('index', 'pcapkit/foundation/extraction'):
            with self.subTest(pagename=pagename):
                self.assertEqual(self.links(pagename), [('All versions on Read the Docs', READ_THE_DOCS)])


if __name__ == '__main__':
    unittest.main()
