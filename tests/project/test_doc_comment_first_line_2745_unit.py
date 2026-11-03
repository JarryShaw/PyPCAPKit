# -*- coding: utf-8 -*-
"""Pins that no doc comment's first line reads to napoleon as an inline type (#2745).

Napoleon takes the first line of an attribute's documentation -- a ``#:`` doc
comment, the docstring under an assignment, or a property's docstring -- as
Google's inline ``type: description`` form wherever a colon outside a role or a
literal has text after it. The text before the colon then renders as a *Type*
field and drops out of the prose, and the build says nothing unless that text
happens to name several classes (#2743).

* :class:`FirstLineTests` -- runs napoleon's own ``autodoc-process-docstring``
  handler, configured as :file:`docs/source/conf.py` configures it, over every
  such documentation under :file:`pcapkit/`, and fails on a type napoleon reads
  off a first line that is prose rather than a type expression.
* :class:`ReaderTests` -- the readers that verdict rests on.

An inline type is kept where it is meant: ``#: int: Frame counter.`` renders
*Type:* ``int`` on purpose. A first line counts as one when the text before its
colon parses as a type expression -- a name, a dotted name, a union, a subscript
or a quoted forward reference -- and a bare name in it is one the module binds or
a builtin, since a single word of prose parses as a name too. An enum member is
left out, since ``restore_enum_member_docstring`` in :file:`conf.py` undoes any
type napoleon reads off one (#1775).

The sweep reads the sources with :mod:`ast` and Sphinx's own attribute-comment
parser, and imports nothing it scans. It needs Sphinx for napoleon, and skips
without it.

"""

from __future__ import annotations

import ast
import builtins
import functools
import importlib.util
import pathlib
import re
import sys
import types
import unittest
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the repository's sources, and imports nothing it scans.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The package whose documentation is swept.
PACKAGE = ROOT / 'pcapkit'

#: The configuration whose napoleon settings the sweep runs under.
CONF = ROOT / 'docs' / 'source' / 'conf.py'

#: Napoleon ships with Sphinx; without it there is nothing to run.
HAS_SPHINX = importlib.util.find_spec('sphinx') is not None

#: The modules whose classes are enumerations, wherever a base resolves to one.
ENUM_MODULES = frozenset({'enum', 'aenum'})

#: The decorators that make autodoc document a function as a property.
PROPERTY_DECORATORS = frozenset({'property', 'cached_property'})

#: Top-level names a fully qualified type may start from without the module binding them.
QUALIFIED_ROOTS = frozenset(getattr(sys, 'stdlib_module_names', ())) | {'pcapkit'}

#: The ``~`` that shortens a cross-reference's displayed name, as in ``~typing.Type``.
TILDE = re.compile(r'~(?=[A-Za-z_])')


class Documentation(NamedTuple):
    """One attribute's documentation, as autodoc hands it to napoleon."""

    #: The module's path, relative to :data:`ROOT`.
    path: 'str'
    #: The attribute's name, qualified by its class where it has one.
    qualname: 'str'
    #: What autodoc documents it as: ``attribute``, ``data`` or ``property``.
    what: 'str'
    #: Its lines.
    lines: 'list[str]'

    @property
    def key(self) -> 'str':
        """How a failure names it."""
        return f'{self.path}: {self.qualname}'


def napoleon_config() -> 'Any':
    """Napoleon's configuration, from the ``napoleon_*`` assignments in :data:`CONF`."""
    from sphinx.ext.napoleon import Config  # pylint: disable=import-outside-toplevel

    settings = {}  # type: dict[str, Any]
    for node in ast.parse(CONF.read_text(encoding='utf-8')).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id.startswith('napoleon_')):
            settings[node.targets[0].id] = ast.literal_eval(node.value)
    return Config(**settings)


def inline_type(documentation: 'Documentation', config: 'Any') -> 'Optional[str]':
    """The inline type napoleon reads off ``documentation``, or :data:`None` where it reads none.

    Runs the handler napoleon connects to ``autodoc-process-docstring`` itself,
    so the reading is napoleon's rather than a copy of its rule. A ``:type:``
    field the documentation writes for itself is no reading.
    """
    from sphinx.ext.napoleon import _process_docstring  # pylint: disable=import-outside-toplevel

    if any(line.startswith(':type:') for line in documentation.lines):
        return None
    result = list(documentation.lines)
    _process_docstring(types.SimpleNamespace(config=config), documentation.what,  # type: ignore[arg-type]
                       documentation.qualname, None, None, result)
    return next((line[len(':type:'):].strip() for line in result if line.startswith(':type:')), None)


def module_name(path: 'pathlib.Path') -> 'str':
    """The dotted name of the module at ``path``."""
    parts = path.relative_to(ROOT).with_suffix('').parts
    return '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)


class Module:
    """What the sweep needs of one module: its tree, its bindings and its classes."""

    def __init__(self, path: 'pathlib.Path') -> 'None':
        self.path = path
        self.name = module_name(path)
        self.source = path.read_text(encoding='utf-8')
        self.tree = ast.parse(self.source, str(path))
        package = self.name if path.name == '__init__.py' else self.name.rpartition('.')[0]

        #: Each name an import binds, to the dotted name it binds.
        self.imports = {}  # type: dict[str, str]
        #: Every name the module binds anywhere, imported or defined.
        self.bound = set()  # type: set[str]
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.partition('.')[0]
                    self.imports[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ''
                if node.level:
                    anchor = package.split('.')[:len(package.split('.')) - node.level + 1]
                    base = '.'.join(anchor + ([base] if base else []))
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = f'{base}.{alias.name}'
            elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                self.bound.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self.bound.add(node.id)
        self.bound.update(self.imports)

        #: Every class, by its qualified name within the module.
        self.classes = {}  # type: dict[str, ast.ClassDef]
        todo = [('', self.tree)]  # type: list[tuple[str, ast.AST]]
        while todo:
            prefix, parent = todo.pop()
            for node in ast.iter_child_nodes(parent):
                if isinstance(node, ast.ClassDef):
                    self.classes[prefix + node.name] = node
                    todo.append((f'{prefix}{node.name}.', node))
                elif not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    todo.append((prefix, node))

    @functools.cached_property
    def documentation(self) -> 'list[Documentation]':
        """Every attribute and property documentation autodoc would read from the module."""
        from sphinx.pycode import ModuleAnalyzer  # pylint: disable=import-outside-toplevel

        path = self.path.relative_to(ROOT).as_posix()
        found = [Documentation(path, f'{namespace}.{name}' if namespace else name,
                               'attribute' if namespace else 'data', list(lines))
                 for (namespace, name), lines
                 in ModuleAnalyzer.for_string(self.source, self.name).find_attr_docs().items()]
        for qualname, cls in self.classes.items():
            for node in cls.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and is_property(node):
                    docstring = ast.get_docstring(node)
                    if docstring:
                        found.append(Documentation(path, f'{qualname}.{node.name}', 'property',
                                                   docstring.splitlines()))
        return found


def is_property(node: 'ast.FunctionDef | ast.AsyncFunctionDef') -> 'bool':
    """Whether ``node`` is decorated as a property; its setter and deleter are not."""
    for decorator in node.decorator_list:
        name = decorator.attr if isinstance(decorator, ast.Attribute) else getattr(decorator, 'id', None)
        if name in PROPERTY_DECORATORS:
            return True
    return False


def dotted(node: 'ast.expr') -> 'Optional[str]':
    """The dotted name ``node`` spells, through a subscript, or :data:`None`."""
    if isinstance(node, ast.Subscript):
        return dotted(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = dotted(node.value)
        return None if head is None else f'{head}.{node.attr}'
    return None


class Package:
    """Every module under :data:`PACKAGE`, and which of their classes are enumerations."""

    def __init__(self) -> 'None':
        self.modules = {}  # type: dict[str, Module]
        for path in sorted(PACKAGE.rglob('*.py')):
            module = Module(path)
            self.modules[module.name] = module

    def is_enum(self, module: 'str', qualname: 'str', seen: 'Optional[set[tuple[str, str]]]' = None) -> 'bool':
        """Whether the class ``qualname`` of ``module`` has an enumeration among its bases."""
        seen = set() if seen is None else seen
        if (module, qualname) in seen:
            return False
        seen.add((module, qualname))
        node = self.modules[module].classes.get(qualname) if module in self.modules else None
        return node is not None and any(self.names_enum(module, name, seen)
                                        for name in map(dotted, node.bases) if name is not None)

    def names_enum(self, module: 'str', name: 'str', seen: 'set[tuple[str, str]]') -> 'bool':
        """Whether ``name``, as ``module`` spells it, is an enumeration class."""
        if name in self.modules[module].classes:
            return self.is_enum(module, name, seen)
        head, _, rest = name.partition('.')
        target = self.modules[module].imports.get(head)
        if target is None:
            return False
        target = f'{target}.{rest}' if rest else target
        if target.partition('.')[0] in ENUM_MODULES:
            return True
        parts = target.split('.')
        for split in range(len(parts) - 1, 0, -1):
            owner = '.'.join(parts[:split])
            if owner in self.modules:
                return self.names_enum(owner, '.'.join(parts[split:]), seen)
        return False

    def is_enum_member(self, module: 'str', documentation: 'Documentation') -> 'bool':
        """Whether ``documentation`` is an enum member's, which :file:`conf.py` restores."""
        owner, _, member = documentation.qualname.rpartition('.')
        if documentation.what != 'attribute' or member.startswith('__') or (
                member.startswith('_') and member.endswith('_')):
            return False
        return self.is_enum(module, owner)


def is_type_expression(text: 'str', bound: 'set[str]') -> 'bool':
    """Whether ``text`` is a type expression, its bare names held by ``bound`` or the builtins."""
    try:
        tree = ast.parse(TILDE.sub('', text.strip()), mode='eval').body
    except SyntaxError:
        return False
    if isinstance(tree, ast.Constant) and isinstance(tree.value, str):
        return is_type_expression(tree.value, bound)
    return _is_type(tree, bound)


def _is_type(node: 'ast.expr', bound: 'Optional[set[str]]') -> 'bool':
    """Whether ``node`` is a name, a dotted name, a union or a subscript of a type.

    A bare name, and a dotted name's root, is one that ``bound`` or the builtins
    hold, or for a dotted name one of :data:`QUALIFIED_ROOTS`, since a single word
    of prose parses as a name too. Prose never reaches a subscript, so a
    subscript's names need no binding: there ``bound`` is :data:`None`.
    """
    if isinstance(node, ast.Name):
        return bound is None or node.id in bound or hasattr(builtins, node.id)
    if isinstance(node, ast.Attribute):
        name = dotted(node)
        roots = None if bound is None else bound | QUALIFIED_ROOTS
        return name is not None and _is_type(ast.Name(id=name.partition('.')[0]), roots)
    if isinstance(node, ast.Subscript):
        inner = node.slice
        items = inner.elts if isinstance(inner, ast.Tuple) else [inner]
        return dotted(node.value) is not None and all(_is_argument(item) for item in items)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_type(node.left, bound) and _is_type(node.right, bound)
    return isinstance(node, ast.Constant) and node.value is None


def _is_argument(node: 'ast.expr') -> 'bool':
    """Whether ``node`` can stand in a type's subscript: a type, a literal or a list of either."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.List):
        return all(_is_argument(item) for item in node.elts)
    return _is_type(node, None)


def inline_types(package: 'Package', config: 'Any') -> 'tuple[dict[str, str], dict[str, str]]':
    """Every inline type napoleon reads off a first line, by :attr:`Documentation.key`.

    Returns:
        The types that are prose, and the types that are type expressions. An enum
        member's are in neither.

    """
    misread, typed = {}, {}  # type: dict[str, str], dict[str, str]
    for name, module in package.modules.items():
        for documentation in module.documentation:
            text = inline_type(documentation, config)
            if text is None or package.is_enum_member(name, documentation):
                continue
            (typed if is_type_expression(text, module.bound) else misread)[documentation.key] = text
    return misread, typed


@unittest.skipUnless(HAS_SPHINX, 'Sphinx is not installed')
class FirstLineTests(unittest.TestCase):
    """No first line of an attribute's documentation renders as a *Type* field."""

    maxDiff = None
    package = None  # type: Optional[Package]
    found = {}  # type: dict[str, str]
    typed = {}  # type: dict[str, str]

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.package = Package()
        cls.found, cls.typed = inline_types(cls.package, napoleon_config())

    def test_the_sweep_reads_documentation(self) -> 'None':
        """The sweep reads ``#:`` comments and properties, and napoleon types some on purpose."""
        assert self.package is not None
        kinds = {documentation.what for module in self.package.modules.values()
                 for documentation in module.documentation}
        self.assertEqual(kinds, {'attribute', 'data', 'property'})
        self.assertTrue(self.typed, 'napoleon read no inline type at all, so the sweep reads nothing')

    def test_enum_classes(self) -> 'None':
        """A class is an enumeration through :mod:`enum`, ``aenum`` or a module re-exporting one."""
        assert self.package is not None
        self.assertTrue(self.package.is_enum('pcapkit.corekit.checksum.internet', 'ChecksumStatus'))
        self.assertTrue(self.package.is_enum('pcapkit.foundation.reassembly.data.data', 'Completion'))
        self.assertTrue(self.package.is_enum('pcapkit.const.sctp.payload_protocol_identifier',
                                             'PayloadProtocolIdentifier'))
        self.assertFalse(self.package.is_enum('pcapkit.protocols.data.internet.igmp', 'IGMP'))

    def test_no_first_line_reads_as_a_type(self) -> 'None':
        """A misread first line names its documentation and the *Type* it renders."""
        off = sorted(f'{key}: renders Type: {text!r}' for key, text in self.found.items())
        self.assertEqual(off, [], 'keep the colon off the first line, e.g. "Checksum. The 16-bit ..."')


@unittest.skipUnless(HAS_SPHINX, 'Sphinx is not installed')
class ReaderTests(unittest.TestCase):
    """The readers :class:`FirstLineTests` rests on."""

    config = napoleon_config() if HAS_SPHINX else None

    def read(self, first: 'str', what: 'str' = 'attribute') -> 'Optional[str]':
        """The inline type napoleon reads off a documentation opening on ``first``."""
        return inline_type(Documentation('pcapkit/x.py', 'X.x', what, [first, 'the rest of it.', '']), self.config)

    def test_napoleon_reads_a_first_line_colon_as_a_type(self) -> 'None':
        """The text before the colon is the type, for every kind of documentation."""
        for what in ('attribute', 'data', 'property'):
            self.assertEqual(self.read('Group address: the IPv4 multicast group', what), 'Group address')
        self.assertEqual(self.read('int: Frame counter.'), 'int')

    def test_napoleon_reads_no_type_off_these(self) -> 'None':
        """A colon on a later line, at the end, doubled or inside a role or literal is no type."""
        self.assertIsNone(self.read('Checksum. The 16-bit one\'s complement'))
        self.assertIsNone(self.read('Group address -- the IPv4 multicast group'))
        self.assertIsNone(self.read('The fields, in order:'))
        self.assertIsNone(self.read('See :rfc:`3376#section-4.1.2` for the sum'))
        self.assertIsNone(self.read('The ``a:b`` pair'))
        self.assertIsNone(self.read('A scope :: of its own'))

    def test_napoleon_reads_a_role_split_across_lines(self) -> 'None':
        """A role whose closing backtick is on the next line is no role on the first."""
        self.assertEqual(self.read('Max response code; the raw octet :meth:`IGMPv3.read'),
                         'Max response code; the raw octet')

    def test_type_expressions(self) -> 'None':
        """Bound names, builtins, qualified names, unions, subscripts and forward references are types."""
        bound = {'Optional', 'Sentinel', 'logging'}
        for text in ('int', 'logging.Logger', 'Optional[str]', "Literal['little', 'big']",
                     '~typing.Type[Dumper]', "'Sentinel | None'", 'dict[str, ~pcapkit.protocols.Protocol]',
                     'Optional[int] | str', 'tuple[int, ...]', 'Callable[[int], object]', 'Pattern[str]',
                     're.Pattern', 'Sentinel | None'):
            self.assertTrue(is_type_expression(text, bound), text)

    def test_prose_is_no_type_expression(self) -> 'None':
        """Prose, an unbound word and a dotted name rooted nowhere are not types."""
        for text in ('Group address', 'Checksum', 'Version of IGMP, always ``3``. It is on no octet',
                     'Max response code; the raw octet', 'i.e', 'Additional data (:rfc:`3376`)',
                     'Checksum | None', 'Data link type'):
            self.assertFalse(is_type_expression(text, {'Optional'}), text)

    def test_conf_py_restores_enum_members(self) -> 'None':
        """The enum-member exclusion stands only while :file:`conf.py` undoes napoleon there."""
        text = CONF.read_text(encoding='utf-8')
        self.assertIn("'sphinx.ext.napoleon'", text)
        self.assertIn("app.connect('autodoc-process-docstring', restore_enum_member_docstring", text)


if __name__ == '__main__':
    unittest.main()
