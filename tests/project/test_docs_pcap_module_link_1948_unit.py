# -*- coding: utf-8 -*-
"""Pins the ``|pcap|_`` link to the note on which distribution owns ``pcap`` (#1948).

PyPCAP and pcap-ct both install a top-level ``pcap`` module, so a bare
``pcap`` literal does not say which of them it means, and neither project page
is the right target for it. The docs explain the collision in a note in
:file:`docs/source/pcapkit/foundation/engines/3rdparty.rst`, labelled
``pcap-module``, and ``|pcap|_`` links the module to that note from every page.

* :class:`LabelTests` -- the label exists once, on that note, and is the one
  :file:`conf.py` names.
* :class:`EpilogTests` -- ``rst_epilog`` defines ``|pcap|`` and its target.
* :class:`BareLiteralTests` -- no rendered ``pcap`` literal that names the module
  is left bare.
* :class:`LinkHookTests` -- ``link_pcap_module`` in :file:`conf.py` points the
  target at the note's page from any other page. These need Sphinx and the
  pinned sphinx-autodoc-typehints, and skip without them, but run no build.

Only the text Sphinx renders is scanned, read as
:file:`test_docs_epilog_links_1936_unit.py` reads it: ``.rst`` pages under
:file:`docs/` apart from the changelog, and docstrings and ``#:`` comments under
:file:`pcapkit/`. A dotted name such as ``pcap.pcap`` or a code expression such as
``import pcap`` is a different literal, and is not matched.

"""

from __future__ import annotations

import ast
import re
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, SPHINX_SKIP_REASON, connections,
                                                               load_conf)
from tests.project.test_docs_epilog_links_1936_unit import (CONF, ENGINE_LIST, ROOT, SUBST, TARGET,
                                                            _epilog, _line, _norm, _rel, _rendered,
                                                            _sources)

if TYPE_CHECKING:
    from typing import Any

#: The label ``|pcap|_`` links to.
LABEL = 'pcap-module'

#: The page that carries the note, relative to :data:`ROOT`.
NOTE_PAGE = 'docs/source/pcapkit/foundation/engines/3rdparty.rst'

#: The page's docname, as Sphinx names it.
NOTE_DOC = 'pcapkit/foundation/engines/3rdparty'

#: A bare ``pcap`` literal, and not ``pcap.pcap`` or ``import pcap``.
BARE = re.compile(r'``pcap``')

#: Bare literals kept on purpose, by path. Each pattern must still match, so an
#: entry cannot outlive the text it was written for.
KEPT = {
    # The note the label marks: a link there would point at itself.
    NOTE_PAGE: (
        r'`pcap-ct`_ installs the same top-level ``pcap`` module as `PyPCAP`_',
    ),
    # The dump formats table: ``pcap`` is a format name there, not the module.
    'docs/source/ext.rst': (
        r'PCAP \(``cap``/``pcap``\)',
    ),
}

#: Pages and modules that name the module, each of which links it.
LINKING = (
    'docs/source/contributing/conventions/process.rst',
    'docs/source/contributing/pep.rst',
    'docs/source/ext.rst',
    'docs/source/index.rst',
    NOTE_PAGE,
    'docs/source/pcapkit/foundation/engines/index.rst',
    'pcapkit/foundation/engines/_pcap_backend.py',
    'pcapkit/foundation/engines/pcap_ct.py',
    'pcapkit/foundation/engines/pypcap.py',
    'pcapkit/toolkit/pcap_ct.py',
)


def _conf_label() -> 'str':
    """``PCAP_MODULE_LABEL``, read from :file:`conf.py` without importing it."""
    for node in ast.parse(CONF.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'PCAP_MODULE_LABEL' for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('conf.py assigns no PCAP_MODULE_LABEL')


def bare_literals() -> 'list[str]':
    """Every rendered bare ``pcap`` literal outside the kept contexts."""
    offenders = []
    for path in _sources():
        rel = _rel(path)
        text = _rendered(path)
        # An engine or an adapter named ``pcap`` is pcapkit's own, not the module.
        spans = [m.span() for m in ENGINE_LIST.finditer(text)]
        for pattern in KEPT.get(rel, ()):
            found = [m.span() for m in re.finditer(pattern, text)]
            if not found:
                offenders.append(f'{rel}: stale exemption {pattern!r}')
            spans += found
        for match in BARE.finditer(text):
            if not any(start <= match.start() < end for start, end in spans):
                offenders.append(f'{rel}:{_line(text, match.start())}: {match.group(0)}')
    return offenders


class LabelTests(unittest.TestCase):
    """The label is on the note, once."""

    def test_conf_names_the_label(self) -> 'None':
        """``PCAP_MODULE_LABEL`` is the label this module pins."""
        self.assertEqual(_conf_label(), LABEL)

    def test_label_marks_the_note(self) -> 'None':
        """It sits directly above the note that says both distributions install ``pcap``."""
        text = (ROOT / NOTE_PAGE).read_text(encoding='utf-8')
        match = re.search(r'(?m)^\.\. _%s:\n\n\.\. important::\n\n(.*)$' % re.escape(LABEL), text)
        self.assertIsNotNone(match, f'{NOTE_PAGE} has no .. _{LABEL}: above an important note')
        self.assertIn('installs the same top-level ``pcap`` module as', match.group(1))

    def test_label_is_defined_once(self) -> 'None':
        """A second label of one name is a Sphinx warning, and an ambiguous target."""
        label = re.compile(r'(?m)^[ \t]*\.\. _%s:[ \t]*$' % re.escape(LABEL))
        found = [_rel(path) for path in sorted((ROOT / 'docs').rglob('*.rst'))
                 for _ in label.finditer(path.read_text(encoding='utf-8'))]
        self.assertEqual(found, [NOTE_PAGE])


class EpilogTests(unittest.TestCase):
    """``rst_epilog`` defines ``|pcap|_``."""

    def test_substitution_is_the_literal(self) -> 'None':
        """``|pcap|`` renders as ``pcap``, like the other ``|pkg|`` names."""
        self.assertIn('pcap', SUBST.findall(_epilog()))
        self.assertIn('.. |pcap| replace:: ``pcap``\n', _epilog())

    def test_target_is_the_label_anchor(self) -> 'None':
        """The anchor, which ``link_pcap_module`` qualifies with the note's page."""
        targets = {_norm(name): url for name, url in TARGET.findall(_epilog())}
        self.assertEqual(targets.get('pcap'), f'#{LABEL}')


class BareLiteralTests(unittest.TestCase):
    """A rendered ``pcap`` that names the module is written ``|pcap|_``."""

    def test_the_scan_reads_the_sources_it_claims_to(self) -> 'None':
        """An empty or misrooted scan would pass the next test vacuously."""
        names = {_rel(path) for path in _sources()}
        for expected in LINKING:
            self.assertIn(expected, names)
        self.assertFalse(any(name.startswith('docs/source/changelog/') for name in names))

    def test_no_bare_module_literal(self) -> 'None':
        """A ``pcap`` literal outside :data:`KEPT` and engine lists fails here."""
        self.assertEqual(bare_literals(), [], 'write the module as |pcap|_, defined in rst_epilog')

    def test_each_page_that_names_the_module_links_it(self) -> 'None':
        """So a revert to the literal is not mistaken for a page that never named it."""
        missing = [rel for rel in LINKING if '|pcap|_' not in _rendered(ROOT / rel)]
        self.assertEqual(missing, [])

    def test_kept_contexts_are_narrow(self) -> 'None':
        """An engine list is kept, prose naming the module is not."""
        self.assertTrue(ENGINE_LIST.search('the ``default``, ``pcap`` and ``pcapng`` engines'))
        self.assertIsNone(ENGINE_LIST.search('both install a top-level ``pcap`` module'))
        self.assertIsNone(BARE.search('``pcap.pcap`` and ``import pcap``'))


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class LinkHookTests(unittest.TestCase):
    """``link_pcap_module`` points ``|pcap|_`` at the note's page."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def app(self, *, labelled: 'bool' = True) -> 'Any':
        """An application whose HTML builder spells URIs as Sphinx's does."""
        from sphinx.util.osutil import relative_uri  # pylint: disable=import-outside-toplevel
        app = mock.Mock()
        app.env.domains.standard_domain.anonlabels = {LABEL: (NOTE_DOC, LABEL)} if labelled else {}
        app.builder.get_relative_uri.side_effect = lambda src, dst: relative_uri(f'{src}.html', f'{dst}.html')
        return app

    @staticmethod
    def doctree(*uris: 'str') -> 'Any':
        """A document holding a reference to each of ``uris``, as docutils resolves them."""
        from docutils import nodes  # pylint: disable=import-outside-toplevel
        from docutils.utils import new_document  # pylint: disable=import-outside-toplevel
        document = new_document('<test>')
        para = nodes.paragraph()
        for uri in uris:
            para += nodes.reference('', '', nodes.literal('pcap', 'pcap'), name='pcap', refuri=uri)
        document += para
        return document

    def refs(self, document: 'Any') -> 'list[Any]':
        from docutils import nodes  # pylint: disable=import-outside-toplevel
        return list(document.findall(nodes.reference))

    def test_another_page_links_the_note_page(self) -> 'None':
        """From the page of :mod:`pcapkit.foundation.extraction`, a directory above the note's."""
        document = self.doctree(f'#{LABEL}')
        self.conf.link_pcap_module(self.app(), document, 'pcapkit/foundation/extraction')
        ref, = self.refs(document)
        self.assertEqual(ref['refuri'], f'engines/3rdparty.html#{LABEL}')
        self.assertTrue(ref['internal'])

    def test_the_note_page_keeps_its_anchor(self) -> 'None':
        """On its own page the anchor is already right."""
        document = self.doctree(f'#{LABEL}')
        self.conf.link_pcap_module(self.app(), document, NOTE_DOC)
        ref, = self.refs(document)
        self.assertEqual(ref['refuri'], f'#{LABEL}')

    def test_other_references_are_left_alone(self) -> 'None':
        """Only the label's anchor is rewritten."""
        document = self.doctree('https://pypi.org/project/pcap-ct/', '#elsewhere')
        self.conf.link_pcap_module(self.app(), document, 'index')
        self.assertEqual([ref['refuri'] for ref in self.refs(document)],
                         ['https://pypi.org/project/pcap-ct/', '#elsewhere'])

    def test_a_missing_label_warns(self) -> 'None':
        """Rather than leave each page linking an anchor it does not have, silently."""
        document = self.doctree(f'#{LABEL}')
        with self.assertLogs('sphinx', level='WARNING') as logs:
            self.conf.link_pcap_module(self.app(labelled=False), document, 'index')
        self.assertIn(LABEL, logs.output[0])

    def test_setup_connects_it_on_doctree_resolved(self) -> 'None':
        """Each written page is resolved for its own docname, which the URI depends on."""
        wired = [event for event, handler, _ in connections(self.conf)
                 if handler is self.conf.link_pcap_module]
        self.assertEqual(wired, ['doctree-resolved'])

    def test_epilog_target_is_the_hook_anchor(self) -> 'None':
        """The two sides of the link agree on the label."""
        self.assertEqual(self.conf.PCAP_MODULE_LABEL, LABEL)
        self.assertIn(f'.. _pcap: #{LABEL}\n', self.conf.rst_epilog)


if __name__ == '__main__':
    unittest.main()
