# -*- coding: utf-8 -*-
"""Pins the internal references and special-method docstrings of the AppType and OptionType templates (#1947).

#1940 converts library-internal literals to roles and gives every special
method that an API page names an entry; the AppType and OptionType templates,
and the const modules generated from them, are the part #1947 covers.

* :class:`ConvertedReferenceTests` -- the references in those templates and
  their generated modules, pinned as roles naming a declared entry.
* :class:`SpecialMethodDocstringTests` -- the special methods ``reg.rst`` and
  ``pcapng.rst`` declare have docstrings to render.
* :class:`TemplateParityTests` -- each of those docstrings is the one its vendor
  template renders, so regenerating the const module keeps it.

"""

from __future__ import annotations

import ast
import importlib
import inspect
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_internal_refs_1940_unit import (DOCS, ROLE, ROOT, _resolve, declared,
                                                             declared_anywhere, is_declared)

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): checks the references in the vendor templates and the generated
#: constant modules.
__tier__ = 'LATEST'

TRANSPORT_PROTOCOL = ':class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol`'
APPTYPE_GET = ':meth:`AppType.get() <pcapkit.const.reg.apptype.apptype.AppType.get>`'

#: ``(source, literal in context, the same context with the role)``.
CONVERTED = (
    ('pcapkit/vendor/reg/apptype/apptype.py', '``TransportProtocol`` is an ``IntEnum``',
     f'{TRANSPORT_PROTOCOL}\n                is an ``IntEnum``'),
    ('pcapkit/const/reg/apptype/apptype.py', '``TransportProtocol`` is an ``IntEnum``',
     f'{TRANSPORT_PROTOCOL}\n                is an ``IntEnum``'),
    ('pcapkit/vendor/reg/apptype/apptype.py', 'as a ``TransportProtocol`` expression',
     f'as a\n        {TRANSPORT_PROTOCOL} expression'),
) + tuple(
    (f'pcapkit/{kind}/reg/apptype/{name}.py', '#: what ``AppType.get()`` answers with.',
     f'#: what {APPTYPE_GET} answers with.')
    for kind, name in (('vendor', 'apptype'), ('const', 'tcp'), ('const', 'udp'),
                       ('const', 'sctp'), ('const', 'dccp'))
)

#: ``(page, const class, vendor module, template, special methods)``.
SPECIAL = (
    ('pcapkit/const/reg.rst', 'pcapkit.const.reg.apptype.apptype.AppType',
     'pcapkit.vendor.reg.apptype.apptype', 'BASE', ('__new__', '__repr__', '__str__', '__int__', '__eq__')),
    ('pcapkit/const/pcapng.rst', 'pcapkit.const.pcapng.option_type.OptionType',
     'pcapkit.vendor.pcapng.option_type', 'LINE', ('__new__',)),
)

#: Stand-ins for the crawled parts of a template, enough to make it parse.
PARTS = {'TABLE': '', 'ENUM': 'pass', 'MISS': 'return None'}


def klass(path: 'str') -> 'type':
    """The class at the dotted ``path``."""
    obj = _resolve(path)
    assert isinstance(obj, type), path
    return obj


def own(cls: 'type', name: 'str') -> 'Any':
    """The function a class body defines as ``name``; for an enumeration's
    ``__new__`` that is ``_new_member_``, where the enum machinery keeps it."""
    obj = vars(cls)['_new_member_' if name == '__new__' else name]
    return getattr(obj, '__func__', obj)


def rendered_docstrings(modname: 'str', template: 'str', clsname: 'str') -> 'dict[str, str | None]':
    """Docstring of each method of ``clsname`` in the module ``template`` renders."""
    module = importlib.import_module(modname)
    vendor = getattr(module, clsname)
    args = {'NAME': clsname, 'DOCS': vendor.__doc__, 'FLAG': vendor.FLAG, 'MODL': modname, **PARTS}
    func = getattr(module, template)
    names = func.__code__.co_varnames[:func.__code__.co_argcount]
    tree = ast.parse(func(*(args[name] for name in names)))
    body = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == clsname)
    return {node.name: ast.get_docstring(node) for node in body.body if isinstance(node, ast.FunctionDef)}


class ConvertedReferenceTests(unittest.TestCase):
    """Each reference is a role, not a literal, and names a declared entry."""

    def test_literal_is_a_role(self) -> 'None':
        for source, literal, role in CONVERTED:
            with self.subTest(source=source, literal=literal):
                text = (ROOT / source).read_text(encoding='utf-8')
                self.assertIn(role, text)
                self.assertNotIn(literal, text)

    def test_role_targets_are_declared_entries(self) -> 'None':
        found = declared_anywhere()
        for role in (TRANSPORT_PROTOCOL, APPTYPE_GET):
            with self.subTest(role=role):
                match = ROLE.fullmatch(role)
                if match is None:
                    self.fail(f'{role} is not a Python-domain role')
                target = match.group(2)
                _resolve(target)
                self.assertTrue(is_declared(target, found), f'no API page declares {target}')


class SpecialMethodDocstringTests(unittest.TestCase):
    """Each special method an API page declares has a docstring of its own."""

    def test_pages_declare_the_methods(self) -> 'None':
        for page, path, _, _, methods in SPECIAL:
            found = set(declared((DOCS / page).read_text(encoding='utf-8')))
            for name in methods:
                with self.subTest(path=path, name=name):
                    self.assertIn(f'{path}.{name}', found)

    def test_methods_have_docstrings(self) -> 'None':
        for _, path, _, _, methods in SPECIAL:
            cls = klass(path)
            for name in methods:
                with self.subTest(path=path, name=name):
                    func = own(cls, name)
                    self.assertEqual(func.__qualname__, f'{cls.__qualname__}.{name}')
                    self.assertTrue((func.__doc__ or '').strip(), f'{path}.{name} has no docstring')


class TemplateParityTests(unittest.TestCase):
    """Each docstring in the const module is the one its vendor template renders."""

    def test_const_docstring_matches_template(self) -> 'None':
        for _, path, modname, template, methods in SPECIAL:
            cls = klass(path)
            rendered = rendered_docstrings(modname, template, cls.__name__)
            for name in methods:
                with self.subTest(path=path, name=name):
                    self.assertIsNotNone(rendered.get(name),
                                         f'{modname}.{template} renders no docstring for {name}')
                    self.assertEqual(inspect.cleandoc(own(cls, name).__doc__ or ''), rendered[name])


if __name__ == '__main__':
    unittest.main()
