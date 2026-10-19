# -*- coding: utf-8 -*-
"""Pins the registry ``get`` overrides as documented API targets.

GitHub issue #1921: ``Command.get``, ``Method.get``, ``OptionType.get``,
``TransportProtocol.get`` and ``AppType.get`` are documented rather than marked
``:meta private:``, per the owner's ruling, because they carry contract the base
:meth:`~pcapkit.corekit.enum.EnumLookup.get` does not describe. Autodoc leaves a
private member off its page, so a ``:meth:`get``` naming one renders as an
unlinked ``get()`` chip.

Whether a reference resolves is a property of the built inventory, which the
pull request checks in the rendered HTML. What this pins is the source-side
precondition: no override carries the tag, in the generated module or in the
vendor template that regenerates it, and no ``:meth:`` reference to one lands
on a member marked private.

"""

from __future__ import annotations

import importlib
import inspect
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterator, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The directive that hides a member from autodoc.
PRIVATE = ':meta private:'

#: Each override, as ``(const module, class, vendor template)``.
OVERRIDES = (
    ('pcapkit.const.ftp.command', 'Command', 'pcapkit/vendor/ftp/command.py'),
    ('pcapkit.const.http.method', 'Method', 'pcapkit/vendor/http/method.py'),
    ('pcapkit.const.pcapng.option_type', 'OptionType', 'pcapkit/vendor/pcapng/option_type.py'),
    ('pcapkit.const.reg.apptype.apptype', 'TransportProtocol',
     'pcapkit/vendor/reg/apptype/apptype.py'),
    ('pcapkit.const.reg.apptype.apptype', 'AppType', 'pcapkit/vendor/reg/apptype/apptype.py'),
)

#: Modules whose docstrings name an override relatively, as ``:meth:`get```.
RELATIVE_MODULES = (
    'pcapkit.const.ftp.command',
    'pcapkit.const.http.method',
    'pcapkit.const.pcapng.option_type',
    'pcapkit.const.reg.apptype.apptype',
    'pcapkit.const.reg.apptype.tcp',
    'pcapkit.const.reg.apptype.udp',
    'pcapkit.const.reg.apptype.sctp',
    'pcapkit.const.reg.apptype.dccp',
)

#: Docstrings whose relative ``:meth:`get``` must be among the references found.
RELATIVE_PINS = (
    'pcapkit.const.ftp.command.Command.register',
    'pcapkit.const.http.method.Method._missing_',
    'pcapkit.const.pcapng.option_type.OptionType.register_alias',
    'pcapkit.const.reg.apptype.apptype.AppType.get_all',
    'pcapkit.const.reg.apptype.apptype.AppType.register',
)

#: ``(file, target)`` pairs that must be among the fully qualified references found.
ABSOLUTE_PINS = (
    ('pcapkit/vendor/http/method.py', 'pcapkit.const.ftp.command.Command.get'),
    ('pcapkit/vendor/ftp/command.py', 'pcapkit.const.http.method.Method.get'),
    ('pcapkit/protocols/schema/misc/pcapng.py',
     'pcapkit.const.pcapng.option_type.OptionType.get'),
)

#: A ``:meth:`` role, with or without a title, capturing its target.
METH = re.compile(r':meth:`(?:[^`<]*<)?[~.]*(?P<target>[\w.]+)>?`')


def raw_get(cls: 'type') -> 'tuple[type, Any]':
    """The class that defines ``get`` for ``cls``, and its undecorated function."""
    for owner in cls.__mro__:
        if 'get' in vars(owner):
            attr = vars(owner)['get']
            return owner, getattr(attr, '__func__', attr)
    raise AssertionError(f'{cls!r} has no get')


def docstrings(cls: 'type') -> 'Iterator[tuple[str, str]]':
    """Yield ``(qualified name, docstring)`` for ``cls`` and the members it defines."""
    yield cls.__qualname__, inspect.cleandoc(cls.__doc__ or '')
    for name, attr in vars(cls).items():
        func = getattr(attr, '__func__', getattr(attr, 'fget', attr))
        doc = getattr(func, '__doc__', None)
        if isinstance(doc, str) and callable(func):
            yield f'{cls.__qualname__}.{name}', doc


def resolve(target: 'str', module: 'Any', cls: 'Optional[type]') -> 'Optional[type]':
    """The class whose ``get`` a ``:meth:`` ``target`` ending in ``get`` names."""
    *path, last = target.split('.')
    if last != 'get':
        return None
    obj: 'Any'
    if path[:1] == ['pcapkit']:
        for cut in range(len(path), 0, -1):
            try:
                obj = importlib.import_module('.'.join(path[:cut]))
            except ImportError:
                continue
            for part in path[cut:]:
                obj = getattr(obj, part, None)
            return obj if isinstance(obj, type) else None
        return None
    scopes = [cls, module] if cls is not None else [module]
    for scope in scopes:
        obj = scope
        try:
            for part in path:
                obj = getattr(obj, part)
        except AttributeError:
            continue
        if isinstance(obj, type):
            return obj
    return None


def template_get_docstrings(path: 'pathlib.Path') -> 'list[tuple[int, str]]':
    """The ``def get`` docstrings in a vendor template, with their line numbers.

    A template is an f-string inside a lambda, so the class body it renders is
    text rather than code: each ``def get(`` is found by its line and its
    docstring read up to the closing triple quote.

    """
    lines = path.read_text(encoding='utf-8').splitlines()
    found = []
    for index, line in enumerate(lines):
        if not re.match(r'\s+def get\(', line):
            continue
        start = next(i for i in range(index, len(lines)) if '"""' in lines[i])
        end = next(i for i in range(start + 1, len(lines)) if '"""' in lines[i])
        found.append((start + 1, '\n'.join(lines[start:end + 1])))
    return found


class OverrideDocstringTests(unittest.TestCase):
    """No ``get`` override is hidden from autodoc."""

    def test_const_overrides_are_not_private(self) -> 'None':
        """The generated modules' ``get`` overrides carry no ``:meta private:``."""
        for modname, clsname, _ in OVERRIDES:
            with self.subTest(override=f'{modname}.{clsname}.get'):
                cls = getattr(importlib.import_module(modname), clsname)
                owner, func = raw_get(cls)
                self.assertIs(owner, cls, f'{clsname} does not override get')
                self.assertTrue(func.__doc__, f'{clsname}.get has no docstring')
                self.assertFalse(PRIVATE in func.__doc__, f'{clsname}.get is marked private')

    def test_templates_are_not_private(self) -> 'None':
        """The vendor templates' ``get`` docstrings carry no ``:meta private:``.

        The scripts write a template's tag into the const module whenever they
        regenerate it, so the template is checked separately.

        """
        for template in sorted({path for _, _, path in OVERRIDES}):
            found = template_get_docstrings(ROOT / template)
            with self.subTest(template=template):
                self.assertTrue(found, f'{template} has no def get')
                for line, doc in found:
                    self.assertFalse(PRIVATE in doc, f'{template}:{line}: get is marked private')


class ReferenceTargetTests(unittest.TestCase):
    """Every ``:meth:`` reference to a ``get`` override lands on a documented member."""

    def check(self, where: 'str', target: 'str', cls: 'Optional[type]') -> 'bool':
        """Whether ``cls`` names an override; if so, assert it is not private.

        Called inside a ``subTest``, so the answer is reported whether or not
        the assertion fails.

        """
        if cls is None:
            return False
        owner, func = raw_get(cls)
        if not owner.__module__.startswith('pcapkit.const.'):
            return False
        with self.subTest(where=where, target=target):
            self.assertFalse(PRIVATE in (func.__doc__ or ''),
                             f'{where}: :meth:`{target}` targets {owner.__qualname__}.get, '
                             'which is marked private')
        return True

    def test_relative_references(self) -> 'None':
        """``:meth:`get``` in a registry docstring targets a documented override."""
        hits = set()
        for modname in RELATIVE_MODULES:
            module = importlib.import_module(modname)
            for cls in vars(module).values():
                if not (isinstance(cls, type) and cls.__module__ == modname):
                    continue
                for where, doc in docstrings(cls):
                    for match in METH.finditer(doc):
                        target = match.group('target')
                        if self.check(f'{modname}.{where}', target,
                                      resolve(target, module, cls)):
                            hits.add(f'{modname}.{where}')
        for pin in RELATIVE_PINS:
            self.assertTrue(pin in hits, f'{pin} has no :meth:`get` reaching an override')

    def test_absolute_references(self) -> 'None':
        """A fully qualified ``:meth:`` to an override, in code or docs, is documented."""
        paths = sorted((ROOT / 'pcapkit').rglob('*.py')) + sorted((ROOT / 'docs').rglob('*.rst'))
        hits = set()
        for path in paths:
            text = path.read_text(encoding='utf-8')
            for match in METH.finditer(text):
                target = match.group('target')
                if not target.startswith('pcapkit.const.') or not target.endswith('.get'):
                    continue
                line = text.count('\n', 0, match.start()) + 1
                relative = path.relative_to(ROOT).as_posix()
                if self.check(f'{relative}:{line}', target, resolve(target, None, None)):
                    hits.add((relative, target))
        for pin in ABSOLUTE_PINS:
            self.assertTrue(pin in hits, f'{pin[0]} has no :meth:`{pin[1]}` reaching an override')


if __name__ == '__main__':
    unittest.main()
