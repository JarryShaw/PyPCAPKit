# -*- coding: utf-8 -*-
"""Pins library-internal references in rendered text as roles with a documented target (#1940).

A library-internal name written as a double-backtick literal in rendered prose
never links, and neither does a role whose target has no documented entry. #1940
converts those literals to Python-domain roles wherever the prose means the
object, and every object such a reference names has an entry -- the public
classes, and the private helpers and special methods that rendered text refers
to -- so that each reference has a target.

* :class:`DocumentedEntryTests` -- the public classes #1940 documents, each with an ``autoclass``.
* :class:`HelperEntryTests` -- the private helpers and special methods that
  rendered text names, each declared on an API page.
* :class:`ConvertedReferenceTests` -- a curated set of the converted references,
  the two examples #1940 names among them, pinned as roles rather than literals
  and as naming a declared entry.
* :class:`EnumOwnNewTests` -- the ``conf.py`` attribute getter that lets
  ``:special-members: __new__`` document an enumeration's own ``__new__``.

Whether a role resolves is a property of the built inventory, not of the source,
so the honest check is a ``sphinx-build`` run, recorded in the pull request. What
this pins is the textual precondition a plain (non-nitpicky) build would not
notice losing: the entry is declared, the role is written, and the dotted path it
names is a real object.

"""

from __future__ import annotations

import enum
import importlib
import pathlib
import re
import types
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_ambiguous_xrefs_1775_unit import HAS_SPHINX, SPHINX_SKIP_REASON, load_conf

if TYPE_CHECKING:
    from typing import Any, Iterator

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs' / 'source'

#: ``(page, dotted path)`` for every public class #1940 gave an entry.
ENTRIES = (
    ('pcapkit/const/ftp.rst', 'pcapkit.const.ftp.command.CommandType'),
    ('pcapkit/const/ftp.rst', 'pcapkit.const.ftp.command.ConformanceRequirement'),
    ('pcapkit/const/ftp.rst', 'pcapkit.const.ftp.return_code.ResponseKind'),
    ('pcapkit/const/ftp.rst', 'pcapkit.const.ftp.return_code.GroupingInformation'),
    ('pcapkit/protocols/application/httpv2.rst', 'pcapkit.protocols.data.application.httpv2.Settings'),
    ('pcapkit/protocols/misc/pcapng.rst', 'pcapkit.protocols.schema.misc.pcapng.OptionEnumField'),
)

#: Private helpers and special methods that rendered text names, and the page
#: that declares each. The changelog names several of them.
HELPERS = (
    ('pcapkit/const/ftp.rst', 'pcapkit.const.ftp.command.Command.__new__'),
    ('pcapkit/const/reg.rst', 'pcapkit.const.reg.apptype.apptype.AppType.__eq__'),
    ('pcapkit/dumpkit/pcap.rst', 'pcapkit.dumpkit.pcap.PCAPIO.__init__'),
    ('pcapkit/foundation/extraction.rst', 'pcapkit.foundation.extraction.Extractor._note_eof_progress'),
    ('pcapkit/foundation/extraction.rst', 'pcapkit.foundation.extraction.Extractor._owns_input'),
    ('pcapkit/foundation/extraction.rst', 'pcapkit.foundation.extraction.Extractor._register_internal_engine'),
    ('pcapkit/protocols/application/http.rst', 'pcapkit.protocols.application.http.HTTP.from_data'),
    ('pcapkit/protocols/application/httpv2.rst', 'pcapkit.protocols.application.httpv2.HTTP.unpack'),
    ('pcapkit/protocols/application/ngap.rst', 'pcapkit.protocols.application.ngap._convert'),
    ('pcapkit/protocols/application/ngap.rst', 'pcapkit.protocols.application.ngap._revert'),
    ('pcapkit/protocols/application/ngap.rst', 'pcapkit.protocols.application.ngap._PYCRATE'),
    ('pcapkit/protocols/application/ngap.rst', 'pcapkit.protocols.application.ngap._PDU_LOCK'),
    ('pcapkit/protocols/application/ospf.rst', 'pcapkit.protocols.application.ospf.OSPF._make_id_numbers'),
    ('pcapkit/protocols/internet/esp.rst', 'pcapkit.protocols.internet.esp._resolve'),
    ('pcapkit/protocols/internet/esp.rst', 'pcapkit.protocols.internet.esp._CRYPTO'),
    ('pcapkit/protocols/internet/ipv6.rst', 'pcapkit.protocols.internet.ipv6.IPv6._read_ip_hextet'),
    ('pcapkit/protocols/link/arp.rst', 'pcapkit.protocols.link.arp.ARP._make_addr_resolve'),
    ('pcapkit/protocols/link/arp.rst', 'pcapkit.protocols.link.arp.ARP._make_proto_resolve'),
    ('pcapkit/protocols/link/ethernet.rst', 'pcapkit.protocols.link.ethernet.Ethernet._make_mac_addr'),
    ('pcapkit/protocols/misc/pcap.rst', 'pcapkit.protocols.misc.pcap.header.Header._read_protos'),
    ('pcapkit/protocols/misc/pcapng.rst', 'pcapkit.protocols.misc.pcapng.PCAPNG.PACKET_TYPES'),
    ('pcapkit/protocols/misc/pcapng.rst', 'pcapkit.protocols.misc.pcapng.PCAPNG._make_mac_addr'),
    ('pcapkit/protocols/misc/pcapng.rst', 'pcapkit.protocols.schema.misc.pcapng.OptionEnumField.post_process'),
    ('pcapkit/protocols/protocol.rst', 'pcapkit.protocols.protocol._declared_keywords'),
    ('pcapkit/utilities/exceptions.rst', 'pcapkit.utilities.exceptions.BaseError.__init__'),
    ('pcapkit/utilities/index.rst', 'pcapkit.utilities.compat.cached_property'),
    ('pcapkit/utilities/index.rst', 'pcapkit.utilities.compat.unquote'),
    ('pcapkit/vendor/default.rst', 'pcapkit.vendor.default.Vendor.__init__'),
    ('pcapkit/vendor/reg.rst', 'pcapkit.vendor.reg.ethertype.EtherType._insert_range'),
)

#: ``(source, literal, the role that replaced it)``. The first two are the
#: examples #1940 names.
CONVERTED = (
    ('docs/source/contributing/conventions/registry-protocol.rst', '``AppType.get``',
     ':meth:`AppType.get <pcapkit.const.reg.apptype.apptype.AppType.get>`'),
    ('docs/source/contributing/conventions/registry-protocol.rst', '``FrameType.Flags``',
     ':class:`FrameType.Flags <pcapkit.protocols.schema.application.httpv2.FrameType.Flags>`'),
    ('docs/source/contributing/conventions/registry-protocol.rst', '``CommandType``',
     ':class:`~pcapkit.const.ftp.command.CommandType`'),
    ('docs/source/contributing/conventions/sentinel-convention.rst', '``NoDefaultType``',
     ':class:`~pcapkit.corekit.sentinels.NoDefaultType`'),
    ('docs/source/contributing/conventions/documentation.rst', '``cached_property``',
     ':class:`~pcapkit.utilities.compat.cached_property`'),
    ('docs/source/contributing/releasing.rst', '``pcapkit.__version__``',
     ':data:`pcapkit.__version__`'),
    ('docs/source/pcapkit/const/ftp.rst', '``Command.get()``',
     ':meth:`Command.get() <pcapkit.const.ftp.command.Command.get>`'),
    ('pcapkit/corekit/fields/numbers.py', '``OptionEnumField.post_process``',
     ':meth:`OptionEnumField.post_process <pcapkit.protocols.schema.misc.pcapng.OptionEnumField.post_process>`'),
    ('pcapkit/corekit/sentinels.py', '``pcapkit.protocols.protocol._declared_keywords()``',
     ':func:`pcapkit.protocols.protocol._declared_keywords`'),
    ('pcapkit/foundation/extraction.py', '``Dumper``',
     ':class:`~pcapkit.dumpkit.common.Dumper`'),
    ('pcapkit/vendor/default.py', '``Vendor.__init__``',
     ':meth:`Vendor.__init__ <pcapkit.vendor.default.Vendor.__init__>`'),
)

#: A Python-domain role, bare or with an explicit title; group 2 is the target.
ROLE = re.compile(r':(mod|class|meth|func|attr|exc|data):`(?:[^`<]*<)?~?([\w.]+)>?`')

#: An rst directive, with its name.
DIRECTIVE = re.compile(r'^(?P<indent> *)\.\. (?:py:)?(?P<kind>[\w-]+)::\s*(?P<name>\S+)')

#: Member options of an ``autoclass`` that may name members explicitly.
MEMBER_OPTIONS = ('members', 'special-members', 'private-members')


def _resolve(path: 'str') -> 'object':
    """Import the longest module prefix of ``path`` and walk the rest as attributes."""
    parts = path.split('.')
    for cut in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module('.'.join(parts[:cut]))
        except ImportError:
            continue
        for name in parts[cut:]:
            obj = getattr(obj, name)
        return obj
    raise ImportError(path)


def declared(text: 'str') -> 'Iterator[str]':
    """Every dotted name ``text``, an rst page, declares an entry for.

    That is an ``auto*`` directive naming it in full, a hand-written ``function``,
    ``data`` or ``class`` directive under the current ``module``, and a member a
    class directive names in a member option or in a nested ``auto*`` directive.
    A bare ``:members:`` is reported as ``<class>.*``, for :func:`is_declared`.

    """
    module = None
    owner = None  # type: Any
    for line in text.splitlines():
        match = DIRECTIVE.match(line)
        if match is None:
            if owner is not None:
                option = re.match(r'^   :([\w-]+):\s*(.*)$', line)
                if option and option.group(1) in MEMBER_OPTIONS:
                    names = [name.strip() for name in option.group(2).split(',') if name.strip()]
                    for name in names:
                        yield f'{owner}.{name}'
                    if option.group(1) == 'members' and not names:
                        yield f'{owner}.*'
            continue
        indent, kind, name = len(match.group('indent')), match.group('kind'), match.group('name')
        if kind in ('module', 'currentmodule'):
            module, owner = name, None
        elif indent == 0 and kind.startswith('auto'):
            yield name
            owner = name if kind in ('autoclass', 'autoexception') else None
        elif indent == 0 and kind in ('function', 'data', 'class') and module:
            yield f'{module}.{name.split("(")[0]}'
            owner = None
        elif indent and owner is not None and kind.startswith('auto'):
            yield f'{owner}.{name}'
        elif indent == 0:
            owner = None


def is_declared(path: 'str', found: 'set[str]') -> 'bool':
    """Whether ``path`` is in ``found``, or is a public member with a docstring of
    its own on a class whose bare ``:members:`` documents it."""
    if path in found:
        return True
    owner, _, name = path.rpartition('.')
    if f'{owner}.*' not in found or name.startswith('_'):
        return False
    value = vars(_resolve(owner)).get(name)
    return bool(getattr(getattr(value, '__func__', value), '__doc__', None))


def declared_anywhere() -> 'set[str]':
    """Every dotted name an API page declares, the changelog excluded."""
    found = set()  # type: set[str]
    for path in sorted(DOCS.rglob('*.rst')):
        if 'changelog' not in path.parts:
            found.update(declared(path.read_text(encoding='utf-8')))
    return found


class DocumentedEntryTests(unittest.TestCase):
    """Each public class #1940 documents has an ``autoclass``."""

    def test_pages_declare_the_entries(self) -> 'None':
        for page, path in ENTRIES:
            with self.subTest(path=path):
                text = (DOCS / page).read_text(encoding='utf-8')
                self.assertRegex(text, rf'(?m)^\.\. autoclass:: {re.escape(path)}\n   :members:\n',
                                 f'{page} has no autoclass with :members: for {path}')

    def test_entries_are_real_documented_classes(self) -> 'None':
        for _, path in ENTRIES:
            with self.subTest(path=path):
                obj = _resolve(path)
                self.assertIsInstance(obj, type)
                self.assertTrue((obj.__doc__ or '').strip(), f'{path} has no docstring to render')


class HelperEntryTests(unittest.TestCase):
    """Each private helper or special method rendered text names has an entry."""

    def test_pages_declare_the_helpers(self) -> 'None':
        for page, path in HELPERS:
            with self.subTest(path=path):
                text = (DOCS / page).read_text(encoding='utf-8')
                self.assertTrue(is_declared(path, set(declared(text))), f'{page} declares no entry for {path}')

    def test_helpers_are_real_objects(self) -> 'None':
        for _, path in HELPERS:
            with self.subTest(path=path):
                _resolve(path)

    def test_documented_functions_have_docstrings(self) -> 'None':
        """A helper's entry renders its docstring, so a function must have one of its own."""
        for _, path in HELPERS:
            owner, _, name = path.rpartition('.')
            parent = _resolve(owner)
            obj = vars(parent).get(name) if isinstance(parent, type) else getattr(parent, name)
            if name == '__new__' and isinstance(parent, enum.EnumMeta):
                obj = vars(parent)['_new_member_']
            func = getattr(obj, '__func__', obj)
            if isinstance(func, types.FunctionType):
                with self.subTest(path=path):
                    self.assertTrue((func.__doc__ or '').strip(), f'{path} has no docstring')


class ConvertedReferenceTests(unittest.TestCase):
    """Each curated reference is a role, not a literal."""

    def test_literal_is_now_a_role(self) -> 'None':
        for source, literal, role in CONVERTED:
            with self.subTest(source=source, literal=literal):
                text = (ROOT / source).read_text(encoding='utf-8')
                self.assertIn(role, text)
                self.assertNotIn(literal, text)

    def test_role_targets_are_declared_entries(self) -> 'None':
        found = declared_anywhere()
        for _, _, role in CONVERTED:
            with self.subTest(role=role):
                match = ROLE.fullmatch(role)
                self.assertIsNotNone(match, role)
                _resolve(match.group(2))
                self.assertTrue(is_declared(match.group(2), found), f'no API page declares {match.group(2)}')


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class EnumOwnNewTests(unittest.TestCase):
    """``read_own_enum_new`` answers ``__new__`` with the class body's own."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def test_registry_new_is_its_own(self) -> 'None':
        from pcapkit.const.ftp.command import Command  # pylint: disable=import-outside-toplevel
        found = self.conf.read_own_enum_new(Command, '__new__')
        self.assertEqual(found.__qualname__, 'Command.__new__')
        self.assertTrue(found.__doc__)
        self.assertIsNot(found, getattr(Command, '__new__'))

    def test_stdlib_enum_new_is_its_own(self) -> 'None':
        class Coded(enum.Enum):
            """An enumeration with a ``__new__`` of its own."""

            def __new__(cls, value: 'int') -> 'Coded':
                obj = object.__new__(cls)
                obj._value_ = value
                return obj

            ONE = 1

        self.assertEqual(self.conf.read_own_enum_new(Coded, '__new__').__qualname__,
                         f'{Coded.__qualname__}.__new__')

    def test_other_names_and_enums_fall_through(self) -> 'None':
        from pcapkit.const.ftp.command import Command  # pylint: disable=import-outside-toplevel

        class Plain(enum.Enum):
            """An enumeration without a ``__new__`` of its own."""

            ONE = 1

        self.assertEqual(self.conf.read_own_enum_new(Command, 'get'), Command.get)
        self.assertIs(self.conf.read_own_enum_new(Plain, '__new__'), Plain.__new__)
        self.assertEqual(self.conf.read_own_enum_new(Plain, 'missing', 42), 42)

    def test_setup_registers_it_for_every_enum(self) -> 'None':
        from unittest import mock  # pylint: disable=import-outside-toplevel

        from sphinx.application import Sphinx  # pylint: disable=import-outside-toplevel
        app = mock.create_autospec(Sphinx, instance=True)
        self.conf.setup(app)
        app.add_autodoc_attrgetter.assert_any_call(enum.EnumMeta, self.conf.read_own_enum_new)


if __name__ == '__main__':
    unittest.main()
