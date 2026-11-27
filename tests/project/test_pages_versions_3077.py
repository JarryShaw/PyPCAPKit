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
  follow the host, and :class:`TestTheSwitch` renders the sidebar template with
  each host's context, where Jinja2 is installed (#3134).

No test reads Read the Docs itself, whose versions are the project's settings.

"""

from __future__ import annotations

import ast
import functools
import html.parser
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
#: The release tags Read the Docs never built, as its API listed them for #3135 and
#: again for #3144: each active, with every build failed. Read the Docs itself is not
#: read here.
UNBUILT = frozenset({'v1.0.0b1', 'v1.3.1.dev0', 'v1.3.1.dev1', 'v1.3.1.dev2', 'v1.3.5.post38', 'v1.3.5.post39',
                     'v1.3.5.post40', 'v1.3.5.post42', 'v1.3.5.post43', 'v1.4.0', 'v1.5.0a1', 'v1.5.0b1',
                     'v1.5.0b2', 'v1.5.0b4'})
#: The versions built from a branch, in the map's order: ``develop`` as ``latest``,
#: and Stable Branch's mirror of ``main`` as ``stable``. ``dev`` is none: it would
#: duplicate ``latest`` (#3077).
BRANCHES = ('latest', 'stable')
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


@functools.lru_cache(maxsize=1)
def conf_tree() -> 'ast.Module':
    return ast.parse(CONF.read_text(encoding='utf-8'))


@functools.lru_cache(maxsize=1)
def conf_code() -> 'types.CodeType':
    """The statements of conf.py that bind one of :data:`CONF_NAMES`, or branch on one."""
    body = []
    for node in conf_tree().body:
        targets = {target.id for target in getattr(node, 'targets', []) if isinstance(target, ast.Name)}
        inside = {name.id for name in ast.walk(node) if isinstance(name, ast.Name)}
        if targets & CONF_NAMES or (isinstance(node, ast.If) and inside & CONF_NAMES):
            body.append(node)
    return compile(ast.Module(body=body, type_ignores=[]), str(CONF), 'exec')


def conf_settings(release: 'str' = '1.8.1', **environ: 'str') -> 'dict[str, Any]':
    """What those statements set, for ``release`` as ``pcapkit.__version__`` and ``environ`` as the environment."""
    namespace = {'os': types.SimpleNamespace(environ=environ), 're': re, 'release': release}
    exec(conf_code(), namespace)  # nosec: B102 - conf.py's own statements
    return namespace


def read_the_docs(version: 'str', kind: 'str') -> 'dict[str, str]':
    """The variables Read the Docs sets for building ``version`` from a ``kind``."""
    return {'READTHEDOCS': 'True', 'READTHEDOCS_VERSION': version, 'READTHEDOCS_VERSION_TYPE': kind,
            'READTHEDOCS_CANONICAL_URL': f'{READ_THE_DOCS}en/{version}/'}


#: The names conf.py binds from the host.
CONF_NAMES = frozenset({
    'READTHEDOCS', 'html_theme_options', 'html_sidebars', 'ogp_site_url', 'html_baseurl', 'html_css_files',
    'READ_THE_DOCS', 'DOCS_VERSION', 'DOCS_VERSION_TYPE', 'AUTOMATED_RELEASE', 'DOCS_RELEASE',
    'DOCS_VERSION_LABEL', 'DOCS_SWITCH', 'html_context',
})
#: The switch's branch versions, by slug and label, on every host (#3134).
SWITCH = [('stable', 'stable'), ('latest', 'latest (develop)')]
#: Each host's build, the environment it sets and the release it builds, and the
#: version, label and switch versions conf.py gives it (#3134). A pre-release on
#: ``main`` gets no release entry, as Read the Docs' automation rule builds none.
HOSTS = (
    ('GitHub Pages', {}, '1.8.1', 'stable', '1.8.1 (stable)', [*SWITCH, ('v1.8.1', 'v1.8.1')]),
    ('GitHub Pages, a post-release', {}, '1.8.1.post1', 'stable', '1.8.1.post1 (stable)',
     [*SWITCH, ('v1.8.1.post1', 'v1.8.1.post1')]),
    ('GitHub Pages, a pre-release', {}, '1.9.0b1', 'stable', '1.9.0b1 (stable)', SWITCH),
    ('Read the Docs stable', read_the_docs('stable', 'branch'), '1.8.1', 'stable', '1.8.1 (stable)',
     [*SWITCH, ('v1.8.1', 'v1.8.1')]),
    ('Read the Docs latest', read_the_docs('latest', 'branch'), '1.8.1', 'latest', 'latest (develop)', SWITCH),
    ('Read the Docs tag', read_the_docs('v1.9.0', 'tag'), '1.9.0', 'v1.9.0', '1.9.0',
     [*SWITCH, ('v1.9.0', 'v1.9.0')]),
    ('Read the Docs pull request', read_the_docs('3134', 'external'), '1.8.1', '3134', 'pull request #3134',
     SWITCH),
)


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

    def test_a_release_read_the_docs_never_built_is_left_out(self) -> None:
        """#3135: its Pages path would otherwise redirect to Read the Docs' 404."""
        tags = list(RELEASES + tuple(UNBUILT))
        random.Random(3135).shuffle(tags)
        self.assertEqual(list(self.module.versions(tags)), [*BRANCHES, *RELEASES])
        # Their neighbours stay, as Read the Docs built them.
        self.assertEqual(list(self.module.versions(['v1.3.5.post40', 'v1.3.5.post41', 'v1.4.0', 'v1.4.1'])),
                         [*BRANCHES, 'v1.3.5.post41', 'v1.4.1'])
        self.assertEqual(self.module.UNBUILT, UNBUILT)
        for tag in sorted(UNBUILT):
            with self.subTest(tag=tag):
                self.assertTrue(self.module.RELEASE.fullmatch(tag))


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
        # `v1.4.0` is a release Read the Docs never built (#3135).
        for tag in ('v1.10.0', 'v1.2.0', 'v1.10.0rc1', 'conda-1.10.0', 'vfoo', 'v1.4.0'):
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
    """The page against the map the script writes for a release and one Read the Docs never built."""

    @classmethod
    def setUpClass(cls) -> None:
        module = load_script()
        cls.page = module.page()
        cls.VERSIONS = module.versions(['v1.7.0', 'v1.4.0'])

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
            ('/PyPCAPKit/stable/', '', '', f'{READ_THE_DOCS}en/stable/'),
            ('/PyPCAPKit/stable', '', '', f'{READ_THE_DOCS}en/stable/'),
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

    def test_a_dev_path_stays_not_found(self) -> None:
        """``latest`` builds ``develop``, so ``dev`` is no version: its paths get the plain page (#3077)."""
        for pathname in ('/PyPCAPKit/dev/pcapkit/foundation/extraction.html', '/PyPCAPKit/dev/', '/PyPCAPKit/dev'):
            with self.subTest(pathname=pathname):
                self.assertEqual(self.run_page(pathname, '?q=1', '#top'),
                                 {'fetched': ['/PyPCAPKit/versions.json'], 'replaced': None})

    def test_a_release_read_the_docs_never_built_stays_not_found(self) -> None:
        """Rather than redirect to Read the Docs' 404 (#3135)."""
        self.assertNotIn('v1.4.0', self.VERSIONS)
        for pathname in ('/PyPCAPKit/v1.4.0/index.html', '/PyPCAPKit/v1.4.0/', '/PyPCAPKit/v1.4.0'):
            with self.subTest(pathname=pathname):
                self.assertEqual(self.run_page(pathname, '', '#top'),
                                 {'fetched': ['/PyPCAPKit/versions.json'], 'replaced': None})

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

    def test_read_the_docs_names_its_own_url_and_keeps_the_switch(self) -> None:
        """#3134: every build shows the switch, Read the Docs' beside its flyout."""
        pages = conf_settings()['html_sidebars']
        for host, environ, release, *_ in HOSTS:
            if not environ:
                continue
            settings = conf_settings(release, **environ)
            canonical = environ['READTHEDOCS_CANONICAL_URL']
            with self.subTest(host=host):
                self.assertEqual((settings['ogp_site_url'], settings['html_baseurl']), (canonical, canonical))
                self.assertEqual(settings['html_sidebars'], pages)

    def test_every_other_build_is_mains_at_the_root(self) -> None:
        """A build reads no folder: #3077's ``PAGES_FOLDER`` changes nothing."""
        names = {name.id for name in ast.walk(conf_tree()) if isinstance(name, ast.Name)}
        self.assertNotIn('PAGES_FOLDER', names)
        for environ in ({}, {'PAGES_FOLDER': 'dev'}):
            settings = conf_settings(**environ)
            with self.subTest(environ=environ):
                self.assertEqual((settings['ogp_site_url'], settings['html_baseurl']), (SITE, SITE))
                self.assertEqual(settings['html_theme_options']['source_branch'], 'main')
                self.assertEqual(settings['html_context']['docs_version'], 'stable')

    def test_each_host_names_its_version_and_the_others(self) -> None:
        """#3134: the version, its label, and the switch's versions, per host."""
        for host, environ, release, version, label, switch in HOSTS:
            with self.subTest(host=host):
                self.assertEqual(conf_settings(release, **environ)['html_context'], {
                    'docs_read_the_docs': f'{READ_THE_DOCS}en/', 'docs_version': version,
                    'docs_version_label': label, 'docs_switch': switch, 'docs_on_read_the_docs': bool(environ)})

    def test_the_context_turns_on_no_furo_template(self) -> None:
        """furo's Read the Docs templates render on a ``READTHEDOCS`` or ``versions`` key (#3134)."""
        for host, environ, release, *_ in HOSTS:
            context = conf_settings(release, **environ)['html_context']
            with self.subTest(host=host):
                self.assertEqual([key for key in context if not key.startswith('docs_')], [])

    def test_the_redirects_name_the_same_sites(self) -> None:
        module = load_script()
        settings = conf_settings()
        self.assertEqual(module.SITE, settings['ogp_site_url'])
        self.assertEqual(module.READ_THE_DOCS, f'{READ_THE_DOCS}en/')
        self.assertEqual(module.READ_THE_DOCS, settings['READ_THE_DOCS'])

    def test_the_switch_is_under_the_brand(self) -> None:
        for host, environ, release, *_ in HOSTS:
            settings = conf_settings(release, **environ)
            with self.subTest(host=host):
                self.assertEqual(settings['html_sidebars']['**'][:2], ['sidebar/brand.html', 'sidebar/versions.html'])
                self.assertIn('versions.css', settings['html_css_files'])
        self.assertTrue(TEMPLATE.is_file())
        self.assertTrue((CONF.parent / '_static' / 'versions.css').is_file())


class Switch(html.parser.HTMLParser):
    """The rendered switch: its label, each entry's text, URL and whether it is current, and its note."""

    def __init__(self, text: 'str') -> None:
        super().__init__()
        self.nav = {}  # type: dict[str, Optional[str]]
        self.label = ''
        self.entries = []  # type: list[tuple[str, Optional[str], bool]]
        self.notes = []  # type: list[str]
        self.stack = []  # type: list[tuple[str, dict[str, Optional[str]]]]
        self.feed(text)
        self.close()

    def handle_starttag(self, tag: 'str', attrs: 'list[tuple[str, Optional[str]]]') -> None:
        if tag == 'nav':
            self.nav = dict(attrs)
        self.stack.append((tag, dict(attrs)))

    def handle_endtag(self, tag: 'str') -> None:
        self.stack.pop()

    def handle_data(self, data: 'str') -> None:
        if not data.strip() or not self.stack:
            return
        tag, attrs = self.stack[-1]
        if tag == 'strong':
            self.label += data
        elif tag in ('a', 'span'):
            self.entries.append((data, attrs.get('href'), attrs.get('aria-current') == 'page'))
        elif tag == 'p' and 'sidebar-versions-note' in (attrs.get('class') or ''):
            self.notes.append(data)


@unittest.skipIf(jinja2 is None, 'Jinja2, which Sphinx installs, is not installed')
class TestTheSwitch(unittest.TestCase):
    """The sidebar template, rendered with each host's ``html_context`` (#3134)."""

    PAGES = ('index', 'pcapkit/foundation/extraction')

    def render(self, context: 'dict[str, Any]', pagename: 'str') -> 'Switch':
        template = jinja2.Environment(autoescape=True).from_string(TEMPLATE.read_text(encoding='utf-8'))
        return Switch(template.render(pagename=pagename, file_suffix='.html',
                                      content_root='../' * pagename.count('/') or './', **context))

    def test_each_version_opens_the_same_page_on_read_the_docs(self) -> None:
        for host, environ, release, version, label, switch in HOSTS:
            context = conf_settings(release, **environ)['html_context']
            for pagename in self.PAGES:
                rendered = self.render(context, pagename)
                page = f'{SITE}{pagename}.html'
                with self.subTest(host=host, pagename=pagename):
                    self.assertEqual(rendered.nav, {'class': 'sidebar-versions', 'aria-label': 'Documentation versions'})
                    self.assertEqual(rendered.label, label)
                    self.assertEqual(
                        [(text, href and urllib.parse.urljoin(page, href), current)
                         for text, href, current in rendered.entries],
                        [*((name, None, True) if slug == version else
                           (name, f'{READ_THE_DOCS}en/{slug}/{pagename}.html', False) for slug, name in switch),
                         ('all releases', f'{SITE}changelog.html', False)])

    def test_only_github_pages_says_where_the_others_are(self) -> None:
        for host, environ, release, *_ in HOSTS:
            rendered = self.render(conf_settings(release, **environ)['html_context'], 'index')
            with self.subTest(host=host):
                self.assertEqual(rendered.notes, [] if environ else ['latest and each release are on Read the Docs'])


if __name__ == '__main__':
    unittest.main()
