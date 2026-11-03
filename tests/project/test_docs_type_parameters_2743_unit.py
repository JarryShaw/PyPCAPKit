# -*- coding: utf-8 -*-
"""Pins the docs build's links from a generic class's type parameters.

GitHub issue #2743: ``sphinx-autodoc-typehints`` writes a generic class's type
parameters after its name, and renders a legacy ``TypeVar``'s string bound or
constraints verbatim, so each name in them is a bare reference.
:class:`~pcapkit.foundation.reassembly.data.data.Deferred` takes ``_KT``, whose
constraints name ``TransType`` and ``HandshakeType``, as crawlers under
:mod:`pcapkit.vendor` are also named: the build warned for both, and linked
``HandshakeType`` to the SSLv2 enumeration. ``qualify_type_parameters`` in
:file:`docs/source/conf.py` points each such name at the class its module binds.

The tests call the hook directly, on the nodes Sphinx's own parser builds. They
need Sphinx and the pinned ``sphinx-autodoc-typehints``, and skip without them,
but run no build.

"""

from __future__ import annotations

import importlib
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, SPHINX_SKIP_REASON, connections,
                                                               load_conf)

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): drives a hook of docs/source/conf.py, which the docs build runs
#: on one interpreter.
__tier__ = 'LATEST'

#: The module declaring ``_KT``, and the class taking it.
MODULE, CLASS = 'pcapkit.foundation.reassembly.data.data', 'Deferred'

#: Every documented class a bare name in ``_KT``'s constraints suffix-matches.
CANDIDATES = (
    'pcapkit.const.reg.transtype.TransType',
    'pcapkit.vendor.reg.transtype.TransType',
    'pcapkit.const.sslv2.handshake_type.HandshakeType',
    'pcapkit.const.tls.handshake_type.HandshakeType',
    'pcapkit.vendor.sslv2.handshake_type.HandshakeType',
    'pcapkit.vendor.tls.handshake_type.HandshakeType',
    'pcapkit.const.reg.apptype.tcp.TCP',
)


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class TypeParameterReferenceTests(unittest.TestCase):
    """``qualify_type_parameters`` links a type parameter's names to what its module binds."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def setUp(self) -> 'None':
        # pylint: disable=import-outside-toplevel
        from sphinx.domains.python import ObjectEntry, PythonDomain
        from sphinx.util.docutils import new_document

        # bind the module's guarded names as ``bind_type_checking_names`` does, undone after
        self.module = importlib.import_module(MODULE)
        self.conf.resolve_type_guarded_imports([], self.module)
        for name, value in self.conf.guarded_names(self.module).items():
            if name not in vars(self.module):
                patcher = mock.patch.object(self.module, name, value, create=True)
                patcher.start()
                self.addCleanup(patcher.stop)

        self.env = types.SimpleNamespace(
            ref_context={'py:module': MODULE, 'py:class': CLASS}, domaindata={},
            config=types.SimpleNamespace(python_use_unqualified_type_names=False,
                                         python_display_short_literal_types=False),
            current_document=types.SimpleNamespace(docname='index', default_role=None),
        )
        self.domain = PythonDomain(self.env)
        self.env.get_domain = lambda name: self.domain
        for name in CANDIDATES:
            self.domain.objects[name] = ObjectEntry('pcapkit', name, 'class', False)
        self.document = new_document('<test>')
        self.document.settings.env = self.env

    def parameters(self, declaration: 'str') -> 'Any':
        """The node a type-parameter list becomes."""
        from sphinx.domains.python._annotations import _parse_type_list  # pylint: disable=import-outside-toplevel
        return _parse_type_list(declaration, self.env)

    def links(self, node: 'Any') -> 'dict[str, Optional[str]]':
        """What each reference in ``node`` links to, after the hook has seen it; no warning allowed."""
        # pylint: disable=import-outside-toplevel
        from docutils import nodes
        from sphinx import addnodes

        self.document += nodes.paragraph('', '', node)
        self.conf.qualify_type_parameters(None, self.document)
        builder = types.SimpleNamespace(name='html', get_relative_uri=lambda source, target: '')
        found = {}  # type: dict[str, Optional[str]]
        with mock.patch('sphinx.domains.python.logger') as logger:
            for ref in node.findall(addnodes.pending_xref):
                resolved = self.domain.resolve_xref(self.env, 'index', builder, ref['reftype'],
                                                    ref['reftarget'], ref, nodes.literal('', 'x'))
                found[ref.astext()] = None if resolved is None else resolved['reftitle']
        self.assertEqual(logger.warning.call_args_list, [])
        return found

    def test_constraints_link_to_what_the_module_imports(self) -> 'None':
        """``_KT``'s constraints, rendered as the library renders them, link to the module's imports."""
        from sphinx.util.typing import stringify_annotation  # pylint: disable=import-outside-toplevel
        constraints = ', '.join(stringify_annotation(constraint, 'smart')
                                for constraint in self.module._KT.__constraints__)  # pylint: disable=protected-access
        found = self.links(self.parameters(f'_KT: ({constraints})'))
        self.assertEqual({name: found[name] for name in ('TransType', 'AppType_TCP', 'HandshakeType')}, {
            'TransType': 'pcapkit.const.reg.transtype.TransType',
            'AppType_TCP': 'pcapkit.const.reg.apptype.tcp.TCP',
            'HandshakeType': 'pcapkit.const.tls.handshake_type.HandshakeType',
        })

    def test_other_bindings_are_left_alone(self) -> 'None':
        """A name the module binds to a class outside :mod:`pcapkit` keeps its default resolution."""
        from sphinx import addnodes  # pylint: disable=import-outside-toplevel
        node = self.parameters('_T: Any')
        self.links(node)
        self.assertEqual([ref['reftarget'] for ref in node.findall(addnodes.pending_xref)], ['Any'])

    def test_references_outside_type_parameters_are_left_alone(self) -> 'None':
        """The hook reads type-parameter lists only; annotations elsewhere resolve as they did."""
        # pylint: disable=import-outside-toplevel
        from docutils import nodes
        from sphinx.domains.python._annotations import type_to_xref

        node = type_to_xref('HandshakeType', self.env)
        self.document += nodes.paragraph('', '', node)
        self.conf.qualify_type_parameters(None, self.document)
        self.assertEqual(node['reftarget'], 'HandshakeType')

    def test_setup_connects_it_to_doctree_read(self) -> 'None':
        """Unconnected, the hook never runs and the ambiguity warnings come back."""
        wired = [(event, priority) for event, handler, priority in connections(self.conf)
                 if handler is self.conf.qualify_type_parameters]
        self.assertEqual(wired, [('doctree-read', 500)])


if __name__ == '__main__':
    unittest.main()
