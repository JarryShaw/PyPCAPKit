# -*- coding: utf-8 -*-
"""#3077: GitHub Pages serves ``main``'s build at the root, aliased as ``/latest/``, and ``develop``'s at ``/dev/``.

* :class:`TestLatestStubs` runs :file:`util/pages_latest.py` as ``Write the
  /latest/ redirects`` does, on a scratch build: a stub per HTML page, each
  resolving to that page at the site root.
* :class:`TestTheWorkflow` evaluates :file:`.github/workflows/deploy-pages.yml`
  per event: a push to ``develop`` builds into ``dev/`` without the gate or the
  report, each target publishes in a concurrency group of its own, and the root
  publish keeps ``dev/``.
* :class:`TestTheConf` runs the statements of :file:`docs/source/conf.py` that
  follow the build's folder, and :class:`TestTheSwitcher` renders the sidebar
  template, where Jinja2 is installed.

The ``clean-exclude`` filter itself is the action's: v4.9.0 passes each line to
rsync as ``--filter "P <line>"``, which protects ``/dev/`` and what it holds.

"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import subprocess  # nosec: B404
import sys
import tempfile
import types
import unittest
import urllib.parse
from typing import TYPE_CHECKING

from tests import _workflows
from tests.project.test_release_gates import STATUS, evaluate_condition, evaluate_expression, job_blocks, job_runs

try:
    import jinja2
except ImportError:  # pragma: no cover - Sphinx's dependency, not the test extra's
    jinja2 = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the repository's text and drives a ``util/`` script.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'pages_latest.py'
CONF = ROOT / 'docs' / 'source' / 'conf.py'
TEMPLATE = ROOT / 'docs' / 'source' / '_templates' / 'sidebar' / 'versions.html'
PAGES = 'deploy-pages.yml'
#: The site root GitHub Pages serves.
SITE = 'https://jarryshaw.github.io/PyPCAPKit/'
#: Each event's ``github`` context, and the folder its build is served from: a
#: pull request and a manual run build as the root does, and publish nothing.
EVENTS = {'push': 'dev', 'workflow_run': '', 'schedule': '', 'pull_request': '', 'workflow_dispatch': ''}
#: Pages of a scratch build, and files that are not pages.
BUILD = ('index.html', 'pcapkit/foundation/extraction.html', '_modules/pcapkit/corekit/fields/field.html')
NOT_PAGES = ('_static/furo.css', 'objects.inv', '.nojekyll')


def github(event: 'str') -> 'dict[str, Any]':
    ref = 'refs/heads/develop' if event == 'push' else 'refs/heads/main'
    return {'event_name': event, 'ref': ref, 'run_id': '7', 'sha': '1' * 40, 'event': {}}


class TestLatestStubs(unittest.TestCase):

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.build = pathlib.Path(tmp.name) / 'html'
        for name in BUILD + NOT_PAGES:
            (self.build / name).parent.mkdir(parents=True, exist_ok=True)
            (self.build / name).write_text(name, encoding='utf-8')

    def run_script(self) -> 'subprocess.CompletedProcess[str]':
        return subprocess.run([sys.executable, str(SCRIPT), str(self.build)], capture_output=True,  # nosec: B603
                              text=True, check=False, timeout=60)

    def test_each_page_gets_a_stub_naming_its_root_page(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        latest = self.build / 'latest'
        self.assertEqual(sorted(path.relative_to(latest).as_posix() for path in latest.rglob('*') if path.is_file()),
                         sorted(BUILD))
        for page in BUILD:
            text = (latest / page).read_text(encoding='utf-8')
            target = '../' * (page.count('/') + 1) + page
            with self.subTest(page=page):
                # Resolved from its own URL, the stub's target is the root page.
                self.assertEqual(urllib.parse.urljoin(f'{SITE}latest/{page}', target), SITE + page)
                self.assertIn(f'<link rel="canonical" href="{SITE}{page}">', text)
                self.assertIn(f'location.replace("{target}" + location.search + location.hash);', text)
                self.assertIn(f'<meta http-equiv="refresh" content="0; url={target}">', text)
                # The pages themselves are untouched.
                self.assertEqual((self.build / page).read_text(encoding='utf-8'), page)

    def test_it_refuses_to_overwrite_a_latest_folder(self) -> None:
        (self.build / 'latest').mkdir()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already in the build', result.stderr)
        self.assertEqual(list((self.build / 'latest').iterdir()), [])

    def test_it_refuses_a_folder_that_is_no_build(self) -> None:
        (self.build / 'index.html').unlink()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn('::error title=No documentation build::', result.stdout)
        self.assertFalse((self.build / 'latest').exists())


@unittest.skipIf(_workflows.yaml is None, _workflows.NO_YAML)
class TestTheWorkflow(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = _workflows.load(PAGES)
        cls.jobs = job_blocks((_workflows.WORKFLOWS / PAGES).read_text(encoding='utf-8'))
        cls.build = {step.get('name'): step for step in cls.spec['jobs']['deploy-pages']['steps']}
        cls.deploy = next(step for step in cls.spec['jobs']['publish-pages']['steps']
                          if str(step.get('uses', '')).startswith('JamesIves/github-pages-deploy-action@'))

    def test_develop_pushes_and_nothing_else_push(self) -> None:
        self.assertEqual(self.spec['on']['push'], {'branches': ['develop']})

    def test_each_event_builds_its_folder(self) -> None:
        env = self.build['Install and Build 🔧']['env']['PAGES_FOLDER']
        stubs = self.build['Write the /latest/ redirects']
        names = list(self.build)
        self.assertLess(names.index('Install and Build 🔧'), names.index('Write the /latest/ redirects'))
        self.assertLess(names.index('Write the /latest/ redirects'), names.index('Upload the built site'))
        self.assertEqual(stubs['run'], 'python util/pages_latest.py docs/build/html')
        for event, folder in EVENTS.items():
            context = {'github': github(event)}
            with self.subTest(event=event):
                self.assertEqual(evaluate_expression(env, context), folder)
                self.assertIs(evaluate_condition(stubs['if'], context), folder == '')

    def test_a_develop_push_runs_no_gate_and_posts_no_report(self) -> None:
        for event, folder in EVENTS.items():
            head = 'skipped' if folder else 'success'
            context = {STATUS: {'cancelled': False}, 'github': github(event), 'needs': {
                'head': {'result': head, 'outputs': {}}, 'deploy-pages': {'result': 'success', 'outputs': {}},
                'publish-pages': {'result': 'success', 'outputs': {}}}}
            with self.subTest(event=event):
                self.assertIs(evaluate_condition(self.spec['jobs']['head']['if'], context), folder == '')
                if event in ('push', 'schedule'):
                    self.assertTrue(job_runs(self.jobs, 'deploy-pages', context))
                    self.assertTrue(job_runs(self.jobs, 'publish-pages', context))
                    self.assertIs(job_runs(self.jobs, 'discussion', context), event == 'schedule')

    def test_each_target_publishes_alone(self) -> None:
        publish = self.spec['jobs']['publish-pages']
        group, published = publish['concurrency']['group'], publish['env']['PUBLISHED']
        found = {}
        for event in ('push', 'workflow_run', 'schedule'):
            context = {'github': github(event)}
            prefix, _, body = group.partition('${{')
            found[event] = (prefix + str(evaluate_expression('${{' + body, context)),
                            evaluate_expression(published, context),
                            evaluate_expression(self.deploy['with']['target-folder'], context))
        self.assertEqual(found['push'], ('publish-pages-dev', 'Publish the develop documentation of', 'dev'))
        root = ('publish-pages-root', 'Publish the documentation of', '')
        self.assertEqual((found['workflow_run'], found['schedule']), (root, root))
        self.assertIs(publish['concurrency']['cancel-in-progress'], False)

    def test_the_root_publish_keeps_dev_and_no_publish_forces(self) -> None:
        options = self.deploy['with']
        self.assertIs(options['clean'], True)
        self.assertEqual(options['clean-exclude'], '/dev/')
        self.assertIs(options['force'], False)
        self.assertEqual(options['commit-message'], '${{ env.PUBLISHED }} ${{ github.sha }}')
        # A protect filter keeps `dev/` from deletion, not from a root page synced
        # over it, and the stubs take `latest/`: no source may build into either.
        for folder in ('latest', 'dev'):
            with self.subTest(folder=folder):
                self.assertFalse((CONF.parent / folder).exists())
                self.assertFalse((CONF.parent / f'{folder}.rst').exists())


class TestTheConf(unittest.TestCase):
    """What the host and ``PAGES_FOLDER`` set, by running the statements of conf.py that read them."""

    NAMES = {'PAGES_FOLDER', 'READTHEDOCS', 'html_theme_options', 'html_context', 'html_sidebars', 'ogp_site_url',
             'html_baseurl', 'html_css_files'}
    #: A version's URL, as Read the Docs gives it.
    CANONICAL = 'https://pypcapkit.jarryshaw.me/en/develop/'

    @classmethod
    def setUpClass(cls) -> None:
        tree = ast.parse(CONF.read_text(encoding='utf-8'))
        body = []
        for node in tree.body:
            targets = {target.id for target in getattr(node, 'targets', []) if isinstance(target, ast.Name)}
            inside = {name.id for name in ast.walk(node) if isinstance(name, ast.Name)}
            if targets & cls.NAMES or (isinstance(node, ast.If) and inside & cls.NAMES):
                body.append(node)
        cls.code = compile(ast.Module(body=body, type_ignores=[]), str(CONF), 'exec')

    def settings(self, folder: 'str', **environ: 'str') -> 'dict[str, Any]':
        if folder:
            environ['PAGES_FOLDER'] = folder
        namespace = {'os': types.SimpleNamespace(environ=environ)}
        exec(self.code, namespace)  # nosec: B102 - conf.py's own statements
        return namespace

    def test_read_the_docs_names_its_own_url_and_drops_the_switch(self) -> None:
        settings = self.settings('', READTHEDOCS='True', READTHEDOCS_CANONICAL_URL=self.CANONICAL)
        self.assertEqual((settings['ogp_site_url'], settings['html_baseurl']), (self.CANONICAL, self.CANONICAL))
        self.assertNotIn('sidebar/versions.html', settings['html_sidebars']['**'])
        self.assertEqual(settings['html_sidebars']['**'],
                         [name for name in self.settings('')['html_sidebars']['**'] if name != 'sidebar/versions.html'])

    def test_each_build_names_where_it_is_served(self) -> None:
        for folder, url, branch in (('', SITE, 'main'), ('dev', SITE + 'dev/', 'develop')):
            settings = self.settings(folder)
            with self.subTest(folder=folder):
                self.assertEqual((settings['ogp_site_url'], settings['html_baseurl']), (url, url))
                self.assertEqual(settings['html_context'], {'pages_folder': folder})
                self.assertEqual(settings['html_theme_options']['source_branch'], branch)

    def test_the_stubs_name_the_same_site(self) -> None:
        spec = importlib.util.spec_from_file_location('pages_latest', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.SITE, self.settings('')['ogp_site_url'])

    def test_any_other_folder_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "not 'latest'"):
            self.settings('latest')

    def test_the_switcher_is_under_the_brand(self) -> None:
        settings = self.settings('')
        sidebars = settings['html_sidebars']['**']
        self.assertEqual(sidebars[:2], ['sidebar/brand.html', 'sidebar/versions.html'])
        self.assertTrue(TEMPLATE.is_file())
        self.assertIn('versions.css', settings['html_css_files'])
        self.assertTrue((CONF.parent / '_static' / 'versions.css').is_file())


@unittest.skipIf(jinja2 is None, 'Jinja2, which Sphinx installs, is not installed')
class TestTheSwitcher(unittest.TestCase):

    def render(self, folder: 'str', pagename: 'str') -> 'dict[str, tuple[str, bool]]':
        """Each link's title, mapped to the URL it resolves to from the page and whether it is current."""
        template = jinja2.Environment(autoescape=True).from_string(TEMPLATE.read_text(encoding='utf-8'))
        depth = pagename.count('/')
        text = template.render(pages_folder=folder, pagename=pagename, file_suffix='.html',
                               content_root='../' * depth or './')
        page = f'{SITE}{folder + "/" if folder else ""}{pagename}.html'
        links = {}
        for anchor in text.split('<a ')[1:]:
            href = anchor.split('href="', 1)[1].split('"', 1)[0]
            title = anchor.split('>', 1)[1].split('<', 1)[0]
            links[title] = (urllib.parse.urljoin(page, href), 'aria-current="page"' in anchor.split('>', 1)[0])
        return links

    def test_each_link_names_this_page_in_the_other_build(self) -> None:
        for folder in ('', 'dev'):
            for pagename in ('index', 'pcapkit/foundation/extraction'):
                with self.subTest(folder=folder, pagename=pagename):
                    self.assertEqual(self.render(folder, pagename), {
                        'latest release': (f'{SITE}{pagename}.html', folder == ''),
                        'development': (f'{SITE}dev/{pagename}.html', folder == 'dev'),
                    })


if __name__ == '__main__':
    unittest.main()
