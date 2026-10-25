# -*- coding: utf-8 -*-
"""Pins the cross-references in the docs build's ``Warns:`` sections.

GitHub issue #2094: napoleon turns a ``Raises:`` entry into a ``:raises:``
field, which the Python domain links to the exception, but writes a ``Warns:``
entry into a plain field with the class name in bold, linking nothing -- and a
``~`` prefix was printed as it stands. ``parse_warns_section`` in
:file:`docs/source/conf.py`, which ``setup`` installs over napoleon's own parser,
writes each warning class as an ``exc`` role that searches the way the
``:raises:`` field does.

The tests run napoleon itself with the build's settings, and resolve the role
and the ``:raises:`` field's node through the Python domain side by side. They
need Sphinx and the pinned ``sphinx-autodoc-typehints``, and skip without them,
but run no build.

"""

from __future__ import annotations

import inspect
import re
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, REF_CONTEXT, SPHINX_SKIP_REASON,
                                                               connections, load_conf)

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives a hook of docs/source/conf.py, which the docs build runs
#: on one interpreter.
__tier__ = 'LATEST'

#: Where the warning classes are documented, and one of them.
WARNINGS = 'pcapkit.utilities.warnings'
REGISTRY_WARNING = f'{WARNINGS}.RegistryWarning'

#: A Google ``Warns:`` section in each form an entry's name takes.
GOOGLE = '''Do something.

Warns:
    RegistryWarning: If bare.
    pcapkit.utilities.warnings.EngineWarning: If dotted, over
        two lines.
    ~pcapkit.utilities.warnings.FormatWarning: If shortened.
    AttributeWarning, UserWarning: If several, one a builtin.

'''

#: What the section above becomes.
GOOGLE_WARNS = [
    ':Warns: * :exc:`.RegistryWarning` -- If bare.',
    '        * :exc:`.pcapkit.utilities.warnings.EngineWarning` -- If dotted, over',
    '          two lines.',
    '        * :exc:`~.pcapkit.utilities.warnings.FormatWarning` -- If shortened.',
    '        * :exc:`.AttributeWarning`, :exc:`UserWarning` -- If several, one a builtin.',
]

#: An ``exc`` role, as the hook writes it.
EXC_ROLE = re.compile(r':exc:`([^`]+)`')


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class WarnsSectionTests(unittest.TestCase):
    """Napoleon links the warning classes of a ``Warns:`` section."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        from sphinx.ext.napoleon.docstring import GoogleDocstring  # pylint: disable=import-outside-toplevel

        # ``setup`` replaces napoleon's parser on the class; put napoleon's back after.
        patcher = mock.patch.object(GoogleDocstring, '_parse_warns_section',
                                    GoogleDocstring.__dict__['_parse_warns_section'])
        patcher.start()
        cls.addClassCleanup(patcher.stop)
        cls.conf = load_conf()
        cls.wired = connections(cls.conf)

    def config(self) -> 'Any':
        """Napoleon's settings, as the build reads them from ``conf.py``."""
        from sphinx.ext.napoleon import Config  # pylint: disable=import-outside-toplevel
        return Config(**{key: getattr(self.conf, key) for key in dir(self.conf)
                         if key.startswith('napoleon_')})

    def google(self, text: 'str', what: 'str' = 'function') -> 'list[str]':
        """``text`` as napoleon's Google parser writes it."""
        from sphinx.ext.napoleon.docstring import GoogleDocstring  # pylint: disable=import-outside-toplevel
        return GoogleDocstring(text, self.config(), what=what).lines()

    def numpy(self, text: 'str') -> 'list[str]':
        """``text`` as napoleon's NumPy parser writes it."""
        from sphinx.ext.napoleon.docstring import NumpyDocstring  # pylint: disable=import-outside-toplevel
        return NumpyDocstring(text, self.config(), what='function').lines()

    def test_setup_installs_the_parser(self) -> 'None':
        """Without it, napoleon's own parser writes the name in bold and nothing links it."""
        from sphinx.ext.napoleon.docstring import GoogleDocstring  # pylint: disable=import-outside-toplevel
        self.assertIs(GoogleDocstring.__dict__['_parse_warns_section'],
                      getattr(self.conf, 'parse_warns_section', None))

    def test_google_section_links_every_form_of_name(self) -> 'None':
        """Bare, dotted, ``~``-prefixed and several names, each as an ``exc`` role."""
        lines = self.google(GOOGLE)
        start = next(index for index, line in enumerate(lines) if line.startswith(':Warns:'))
        self.assertEqual(lines[start:start + len(GOOGLE_WARNS)], GOOGLE_WARNS)

    def test_numpy_section_is_linked_too(self) -> 'None':
        """``NumpyDocstring`` inherits the parser, so its ``Warns`` section is linked."""
        lines = self.numpy('Do something.\n\nWarns\n-----\nRegistryWarning\n    If bare.\n')
        self.assertIn(':Warns: :exc:`.RegistryWarning` -- If bare.', lines)

    def test_name_with_a_type_is_left_alone(self) -> 'None':
        """The ``name (type): description`` form names no warning class by itself."""
        lines = self.google('Do something.\n\nWarns:\n    count (int): If typed.\n')
        self.assertIn(':Warns: **count** (:py:class:`int`) -- If typed.', lines)

    def test_a_role_is_kept_as_written(self) -> 'None':
        """An entry already written as a role is not wrapped in a second one."""
        self.assertEqual(self.conf.warning_reference(':class:`~pcapkit.utilities.warnings.InfoWarning`'),
                         ':class:`~pcapkit.utilities.warnings.InfoWarning`')

    def test_real_docstring(self) -> 'None':
        """``register_protocol``'s ``Warns:`` entry is not ``**pcapkit.utilities.warnings.RegistryWarning**``."""
        from pcapkit.foundation.registry.protocols import register_protocol  # pylint: disable=import-outside-toplevel
        lines = self.google(inspect.getdoc(register_protocol))
        warns = [line for line in lines if line.startswith(':Warns:')]
        self.assertEqual(len(warns), 1)
        self.assertTrue(warns[0].startswith(f':Warns: :exc:`.{REGISTRY_WARNING}` -- '), warns[0])
        self.assertNotIn(f'**{REGISTRY_WARNING}**', '\n'.join(lines))


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class RaisesParityTests(unittest.TestCase):
    """A ``Warns:`` role resolves to what a ``:raises:`` field of the same name does."""

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
        self.domain.objects[REGISTRY_WARNING] = ObjectEntry('warnings', REGISTRY_WARNING, 'exception', False)
        self.document = new_document('<test>')
        self.document.settings.env = self.env

    def raises_field(self, name: 'str') -> 'Any':
        """The node a ``:raises name:`` field becomes, by the Python domain's field type."""
        from sphinx.domains.python._object import PyGroupedField  # pylint: disable=import-outside-toplevel
        field = PyGroupedField('exceptions', label='Raises', rolename='exc',
                               names=('raises',), can_collapse=True)
        return field.make_xref('exc', 'py', name, env=self.env)

    def warns_role(self, name: 'str') -> 'Any':
        """The node the hook's role for ``name`` becomes."""
        from sphinx.domains.python import PyXRefRole  # pylint: disable=import-outside-toplevel
        text = EXC_ROLE.fullmatch(self.conf.warning_reference(name)).group(1)
        inliner = types.SimpleNamespace(document=self.document, reporter=types.SimpleNamespace(
            get_source_and_line=lambda lineno=None: ('<test>', lineno)))
        result, messages = PyXRefRole()('py:exc', f':py:exc:`{text}`', text, 1, inliner)
        self.assertEqual(messages, [])
        return result[0]

    def resolve(self, node: 'Any') -> 'Any':
        """What the Python domain links ``node`` to, after ``resolve_builtins_exactly``."""
        from docutils import nodes  # pylint: disable=import-outside-toplevel
        self.document += nodes.paragraph('', '', node)
        self.conf.resolve_builtins_exactly(None, self.document)
        builder = types.SimpleNamespace(name='html', get_relative_uri=lambda source, target: '')
        with mock.patch('sphinx.domains.python.logger'):
            return self.domain.resolve_xref(self.env, 'index', builder, node['reftype'],
                                            node['reftarget'], node, nodes.literal('', 'x'))

    def test_names_resolve_alike(self) -> 'None':
        """Bare, dotted and ``~``-prefixed, from a module other than the class's own."""
        for name in ('RegistryWarning', REGISTRY_WARNING, f'~{REGISTRY_WARNING}'):
            with self.subTest(name=name):
                raises = self.resolve(self.raises_field(name))
                warns = self.resolve(self.warns_role(name))
                self.assertIsNotNone(raises)
                self.assertIsNotNone(warns)
                self.assertEqual(warns['reftitle'], raises['reftitle'])
                self.assertEqual(warns['reftitle'], REGISTRY_WARNING)

    def test_titles_read_alike(self) -> 'None':
        """``~`` shortens the title to the class name, and nothing else does."""
        for name, title in (('RegistryWarning', 'RegistryWarning'),
                            (REGISTRY_WARNING, REGISTRY_WARNING),
                            (f'~{REGISTRY_WARNING}', 'RegistryWarning')):
            with self.subTest(name=name):
                self.assertEqual(self.raises_field(name).astext(), title)
                self.assertEqual(self.warns_role(name).astext(), title)

    def test_builtin_is_left_to_intersphinx(self) -> 'None':
        """A builtin warning is searched for exactly, so the Python docs link it."""
        from sphinx.domains.python import ObjectEntry  # pylint: disable=import-outside-toplevel
        lookalike = 'pcapkit.const.misc.UserWarning'
        self.domain.objects[lookalike] = ObjectEntry('misc', lookalike, 'attribute', False)
        self.assertIsNone(self.resolve(self.raises_field('UserWarning')))
        self.assertIsNone(self.resolve(self.warns_role('UserWarning')))


if __name__ == '__main__':
    unittest.main()
