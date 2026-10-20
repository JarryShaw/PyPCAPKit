# -*- coding: utf-8 -*-
"""Pins the fixes for the docs build's ambiguous cross-references.

GitHub issue #1775: the docs build gave ``more than one target found for
cross-reference`` warnings, and every one of those links landed on the wrong
object. They had these causes, each fixed where it starts rather than at the
references:

* A bare builtin name in a type -- ``dict``, ``type``, ``set`` -- was
  suffix-matched to registry members such as ``TCP.dict``.
  ``resolve_builtins_exactly`` in :file:`docs/source/conf.py` stops it.
* Napoleon read a URL's colon in a registry member's docstring as Google's inline
  ``type: description`` form, and the bogus type was then parsed as references --
  ``http``, ``Echo``. ``save_enum_member_docstring`` and
  ``restore_enum_member_docstring`` undo it.
* Hand-written ``.. data::`` and ``.. function::`` directives spelled out their
  full dotted name under a ``.. module::`` that already supplied it, so each was
  registered as ``<module>.<module>.<name>``. The exact lookup for a TypeVar such
  as ``_AT`` then failed, and the fuzzy one found every ``_AT`` in the package --
  the remaining warnings.

The hook tests drive the hooks with the nodes Sphinx's own producers build and
with napoleon itself, and check that ``setup`` connects each one where the build
needs it, so they need Sphinx and the pinned sphinx-autodoc-typehints, and skip
without them. The directive test is textual and runs everywhere.

This module also holds what every test loading :file:`conf.py` shares: the
loader, the ``setup`` connection reader, and :data:`HAS_SPHINX` with its skip
message.

"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import inspect
import os
import pathlib
import re
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): drives a hook of docs/source/conf.py, which the docs build runs
#: on one interpreter.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The documentation tree, and the configuration whose hooks are tested.
DOCS = ROOT / 'docs' / 'source'
CONF = DOCS / 'conf.py'

#: The distribution whose private modules ``conf.py`` imports.
TYPEHINTS = 'sphinx-autodoc-typehints'

#: The requirements file the docs build installs, which pins :data:`TYPEHINTS`.
REQUIREMENTS = ROOT / 'docs' / 'requirements.txt'


def pinned_release() -> 'str':
    """The release of :data:`TYPEHINTS` that :data:`REQUIREMENTS` pins."""
    text = REQUIREMENTS.read_text(encoding='utf-8')
    match = re.search(rf'^{re.escape(TYPEHINTS)}==(\S+)\s*$', text, re.MULTILINE)
    if match is None:
        raise AssertionError(f'{REQUIREMENTS} pins no exact {TYPEHINTS} release')
    return match.group(1)


def installed_release() -> 'Optional[str]':
    """The installed release of :data:`TYPEHINTS`, or :data:`None` without one."""
    try:
        return importlib.metadata.version(TYPEHINTS)
    except importlib.metadata.PackageNotFoundError:
        return None


def runs_pinned_release() -> 'bool':
    """Whether the installed :data:`TYPEHINTS` is the release ``conf.py`` is written against."""
    return installed_release() == pinned_release()


#: ``conf.py`` imports these at module level, and imports private modules of
#: sphinx-autodoc-typehints that only the pinned release is known to have. Another release would
#: fail the load, or load and test something the docs build never runs, so a
#: test that loads ``conf.py`` gates on this and skips with
#: :data:`SPHINX_SKIP_REASON`.
HAS_SPHINX = (all(importlib.util.find_spec(name) is not None
                  for name in ('sphinx', 'sphinx_autodoc_typehints'))
              and runs_pinned_release())


def sphinx_skip_reason() -> 'str':
    """Why :data:`HAS_SPHINX` is false, for a skip message; empty when it is true."""
    if HAS_SPHINX:
        return ''
    if any(importlib.util.find_spec(name) is None for name in ('sphinx', 'sphinx_autodoc_typehints')):
        return 'Sphinx and sphinx-autodoc-typehints are not installed'
    return (f'{TYPEHINTS} {installed_release()} is installed, not the {pinned_release()} '
            f'that docs/requirements.txt pins and docs/source/conf.py is written against')


#: The skip message of every test gated on :data:`HAS_SPHINX`.
SPHINX_SKIP_REASON = sphinx_skip_reason()

#: A Python domain directive, or one that sets the current module.
DIRECTIVE = re.compile(r'^\s*\.\. (?:py:)?(?P<kind>[a-z]+)::\s*(?P<name>\S+)')

#: Directives that set the current module for those after them.
MODULE_KINDS = frozenset({'module', 'currentmodule', 'automodule'})

#: Directives that register an object under the current module.
OBJECT_KINDS = frozenset({
    'data', 'function', 'class', 'exception', 'attribute', 'method',
    'classmethod', 'staticmethod', 'property', 'decorator', 'type',
})

#: The module and class every node below is built in, as autodoc would set them.
REF_CONTEXT = {'py:module': 'pcapkit.foundation.extraction', 'py:class': 'Extractor'}

#: Two registry members named like the builtin, as ``TCP`` and ``UDP`` have.
REGISTRY_MEMBERS = ('pcapkit.const.reg.apptype.tcp.TCP.dict',
                    'pcapkit.const.reg.apptype.udp.UDP.dict')

#: A registry member's docstring whose first line napoleon used to split.
H_323 = 'pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier.H_323'
H_323_DOC = ['H.323 [http://standard.pictel.com/ftp/avc-site/0206 Bru/AVD-2198.zip][H.323',
             'over SCTP October 2002.]']


def doubled_names() -> 'list[str]':
    """Every object directive whose name repeats the module it is declared in."""
    found = []  # type: list[str]
    for path in sorted(DOCS.rglob('*.rst')):
        module = None
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            match = DIRECTIVE.match(line)
            if match is None:
                continue
            kind, name = match.group('kind'), match.group('name')
            if kind in MODULE_KINDS:
                module = None if name == 'None' else name
            elif kind in OBJECT_KINDS and module is not None and name.startswith('pcapkit.'):
                found.append(f'{path.relative_to(ROOT)}:{number}: {name} (under {module})')
    return found


def load_conf() -> 'types.ModuleType':
    """Execute :file:`docs/source/conf.py`, without keeping its environment change."""
    spec = importlib.util.spec_from_file_location('_docs_conf_1775', CONF)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'unable to load {CONF}')
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ):
        spec.loader.exec_module(module)
    return module


def connections(conf: 'types.ModuleType') -> 'list[tuple[str, Any, int]]':
    """What ``conf.setup`` connects, as ``(event, handler, priority)`` in call order.

    The application is an autospec of :class:`~sphinx.application.Sphinx`, so any
    other call ``setup`` makes is accepted, and a priority left out is read as the
    default :meth:`~sphinx.application.Sphinx.connect` would give it.

    """
    from sphinx.application import Sphinx  # pylint: disable=import-outside-toplevel
    app = mock.create_autospec(Sphinx, instance=True)
    conf.setup(app)
    signature = inspect.signature(Sphinx.connect)
    found = []  # type: list[tuple[str, Any, int]]
    for call in app.connect.call_args_list:
        bound = signature.bind(app, *call.args, **call.kwargs)
        bound.apply_defaults()
        found.append((bound.arguments['event'], bound.arguments['callback'],
                      bound.arguments['priority']))
    return found


class DirectiveNameTests(unittest.TestCase):
    """A hand-written directive takes the bare name under its ``.. module::``."""

    def test_no_directive_repeats_its_module(self) -> 'None':
        """``.. data:: pcapkit.x._T`` under ``.. module:: pcapkit.x`` registers ``pcapkit.x.pcapkit.x._T``.

        The fix is ``.. data:: _T``, with a ``:module:`` option when the object
        lives in a module other than the current one.

        """
        self.assertEqual(doubled_names(), [])


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class BuiltinReferenceTests(unittest.TestCase):
    """``resolve_builtins_exactly`` keeps builtin names off registry members."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def setUp(self) -> 'None':
        # pylint: disable=import-outside-toplevel
        from sphinx.domains.python import ObjectEntry, PythonDomain
        from sphinx.util.docutils import new_document

        self.env = types.SimpleNamespace(
            ref_context=dict(REF_CONTEXT), domaindata={},
            config=types.SimpleNamespace(python_use_unqualified_type_names=False),
            current_document=types.SimpleNamespace(docname='index', default_role=None),
        )
        self.domain = PythonDomain(self.env)
        self.env.get_domain = lambda name: self.domain
        for name in REGISTRY_MEMBERS:
            self.domain.objects[name] = ObjectEntry('pcapkit/const/reg', name, 'attribute', False)
        self.document = new_document('<test>')
        self.document.settings.env = self.env

    def annotation(self, target: 'str') -> 'Any':
        """The node a signature annotation becomes."""
        from sphinx.domains.python._annotations import type_to_xref  # pylint: disable=import-outside-toplevel
        return type_to_xref(target, self.env)

    def field_type(self, target: 'str') -> 'Any':
        """The node a ``:rtype:`` field becomes."""
        from sphinx.domains.python._object import PyField  # pylint: disable=import-outside-toplevel
        field = PyField('returntype', label='Return type', has_arg=False,
                        names=('rtype',), bodyrolename='class')
        return field.make_xref('class', 'py', target, env=self.env)

    def role(self, text: 'str') -> 'Any':
        """The node an explicit ``:py:class:`` role becomes."""
        from sphinx.domains.python import PyXRefRole  # pylint: disable=import-outside-toplevel
        inliner = types.SimpleNamespace(document=self.document, reporter=types.SimpleNamespace(
            get_source_and_line=lambda lineno=None: ('<test>', lineno)))
        result, messages = PyXRefRole()('py:class', f':py:class:`{text}`', text, 1, inliner)
        self.assertEqual(messages, [])
        return result[0]

    def resolve(self, node: 'Any') -> 'Any':
        """What the Python domain links ``node`` to, after the hook has seen it."""
        from docutils import nodes  # pylint: disable=import-outside-toplevel
        self.document += nodes.paragraph('', '', node)
        self.conf.resolve_builtins_exactly(None, self.document)
        builder = types.SimpleNamespace(name='html', get_relative_uri=lambda source, target: '')
        with mock.patch('sphinx.domains.python.logger'):
            return self.domain.resolve_xref(self.env, 'index', builder, node['reftype'],
                                            node['reftarget'], node, nodes.literal('', 'x'))

    def test_annotation_builtin_is_left_to_intersphinx(self) -> 'None':
        """``dict`` in an annotation used to link to ``TCP.dict``."""
        self.assertIsNone(self.resolve(self.annotation('dict')))

    def test_field_type_builtin_is_left_to_intersphinx(self) -> 'None':
        """``dict`` in a ``:rtype:`` field used to link to ``TCP.dict`` too."""
        self.assertIsNone(self.resolve(self.field_type('dict')))

    def test_dotted_role_keeps_its_fuzzy_search(self) -> 'None':
        """``:class:`.dict``` asks for the member by its leading dot, and still finds it."""
        reference = self.resolve(self.role('.dict'))
        self.assertIsNotNone(reference)
        self.assertEqual(reference['reftitle'], REGISTRY_MEMBERS[0])

    def test_other_names_keep_their_fuzzy_search(self) -> 'None':
        """A relative name such as ``_pcap_backend.Probe`` resolves only by suffix."""
        from sphinx.domains.python import ObjectEntry  # pylint: disable=import-outside-toplevel
        probe = 'pcapkit.foundation.engines._pcap_backend.Probe'
        self.domain.objects[probe] = ObjectEntry('engines', probe, 'class', False)
        reference = self.resolve(self.annotation('_pcap_backend.Probe'))
        self.assertIsNotNone(reference)
        self.assertEqual(reference['reftitle'], probe)

    def test_setup_connects_it_to_doctree_read(self) -> 'None':
        """Unconnected, the hook never runs and the builtin warnings come back."""
        wired = [(event, priority) for event, handler, priority in connections(self.conf)
                 if handler is self.conf.resolve_builtins_exactly]
        self.assertEqual(wired, [('doctree-read', 500)])


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class EnumMemberDocstringTests(unittest.TestCase):
    """Napoleon's inline type is undone on enum members, and only there."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def process(self, name: 'str', obj: 'object', lines: 'list[str]') -> 'list[str]':
        """Run ``lines`` through the hooks and napoleon, in the build's order."""
        from sphinx.ext import napoleon  # pylint: disable=import-outside-toplevel
        settings = {key: getattr(self.conf, key) for key in dir(self.conf) if key.startswith('napoleon_')}
        app = types.SimpleNamespace(config=napoleon.Config(**settings))
        lines = list(lines)
        self.conf.save_enum_member_docstring(app, 'attribute', name, obj, None, lines)
        napoleon._process_docstring(app, 'attribute', name, obj, None, lines)  # pylint: disable=protected-access
        self.conf.restore_enum_member_docstring(app, 'attribute', name, obj, None, lines)
        return lines

    def test_registry_member_keeps_its_docstring(self) -> 'None':
        """The URL's colon used to turn ``H.323 [http`` into the member's type.

        Autodoc hands over the plain value -- ``13``, not the member -- so that is
        what is passed here.

        """
        self.assertEqual(self.process(H_323, 13, H_323_DOC), H_323_DOC)

    def test_attribute_keeps_napoleons_inline_type(self) -> 'None':
        """An inline type on anything but an enum member is still napoleon's to read."""
        name = 'pcapkit.foundation.extraction.Extractor._flag_a'
        self.assertEqual(self.process(name, 1, ['int: Number of frames.']),
                         ['Number of frames.', '', ':type: int'])

    def test_setup_runs_the_pair_either_side_of_napoleon(self) -> 'None':
        """Napoleon connects at the default 500: the save runs before it, the restore after.

        :meth:`process` calls the three in that order by hand; this is what makes
        the build call them in it too.

        """
        pair = (self.conf.save_enum_member_docstring, self.conf.restore_enum_member_docstring)
        wired = sorted((priority, event, handler.__name__)
                       for event, handler, priority in connections(self.conf) if handler in pair)
        self.assertEqual(wired, [
            (400, 'autodoc-process-docstring', 'save_enum_member_docstring'),
            (600, 'autodoc-process-docstring', 'restore_enum_member_docstring'),
        ])


if __name__ == '__main__':
    unittest.main()
