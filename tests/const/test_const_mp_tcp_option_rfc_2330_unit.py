# -*- coding: utf-8 -*-
"""#2330 -- the MPTCP Option Subtypes table cites the RFC that defines it.

:class:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption` is generated from IANA's
"MPTCP Option Subtypes" registry, whose own reference is
``<xref type="rfc" data="rfc8684"/>``: RFC 8684 specifies MPTCP v1 and
obsoletes the experimental v0 of RFC 6824, which the registry's note mentions
only to point at for the v0 subtypes. Every assigned record in the registry
carries an ``rfc8684`` spec -- the ``0x9-0xe`` *Unassigned* range carries an
empty ``<spec/>`` and renders no member at all -- so every member comment the
crawler renders cites RFC 8684, with a ``#section-...`` anchor wherever the
record's spec names a section and without one for ``Reserved_for_Private_Use``
(``0xf``), whose spec is a bare ``<xref type="rfc" data="rfc8684"/>``. The
option kind that carries these subtypes cites RFC 8684 too --
:attr:`Option.Multipath_TCP <pcapkit.const.tcp.option.Option.Multipath_TCP>`,
kind 30, which is what IANA's "TCP Option Kind Numbers" registry gives for it.
The class docstring, however, cited RFC 6824, in the crawler's template
(:file:`pcapkit/vendor/tcp/mp_tcp_option.py`) and in the generated module
alike, naming an obsoleted document as the authority for a table none of whose
entries come from it.

The assertions are the invariants that defect broke, rather than the one string
that was wrong:

* the class docstring names the registry's own reference, and names nothing
  else, so the table's attribution cannot sit on a document its entries do not
  come from
  (:meth:`MPTCPOptionCitationTests.test_the_class_docstring_cites_the_registrys_rfc`);
* no citation anywhere in the generated table reaches back to the obsoleted v0
  document, which is what a partial regeneration would reintroduce
  (:meth:`MPTCPOptionCitationTests.test_the_table_cites_no_obsoleted_rfc`).
  This is deliberately not a pin on *every* role equalling RFC 8684: RFC 8684
  section 7.2 puts future assignments to this registry under Standards Action,
  "a reference to its specification" each, so a legitimate future subtype would
  add a citation to some other RFC;
* the crawler's template and the module it generates carry that citation
  identically, since the generator rewrites the module from the template and a
  fix to one alone would be undone by the next Vendor Update
  (:meth:`MPTCPOptionCitationTests.test_the_template_and_the_module_agree`);
* the parser's subtype-agnostic citations name the registry's RFC as well
  (:meth:`MPTCPOptionCitationTests.test_the_option_kind_map_cites_the_registrys_rfc`
  and
  :meth:`MPTCPOptionCitationTests.test_the_generic_mptcp_figure_cites_the_registrys_rfc`),
  for the reason the next paragraph gives.

:mod:`pcapkit.protocols.transport.tcp` carried the same defect, corrected
alongside the table: the option-kind map's comment against
``Option.Multipath_TCP``, which attributes the kind rather than any subtype's
layout, and the ``Structure of MP-TCP`` figure in ``TCP._read_mode_mp``, which
draws the subtype-agnostic option header that RFC 8684 figure 3 and RFC 6824
figure 3 draw identically. Neither states anything v0-specific, so neither had
reason to name the obsoleted document. The RFC 6824 citations that *remain* in
that module and its schemas are deliberate and out of scope: those document the
legacy v0 layouts the parsers still accept -- the ADD_ADDR ``IPVer`` nibble,
which RFC 8684 redraws as reserved bits and ``E``, and the 4-octet MP_PRIO
``AddrID`` form, which RFC 8684 section 5 removed -- which is a claim about the
wire rather than about this registry. The assertions above therefore read the
map entry and the docstring each name, never the whole module.

Every assertion here fails on the parent commit except
:meth:`MPTCPOptionCitationTests.test_the_template_and_the_module_agree`, which
passes there: the parent cites RFC 6824 in the template and in the module
consistently, so the agreement check catches only a fix applied to one side of
the pair.

The crawler is read as source rather than imported, so this runs on the legs
where the ``vendor`` extra is absent: that extra is installed by the
``project-tests`` and ``gate`` jobs, and by the ``test`` and ``integration``
jobs only on their latest-interpreter cell.

"""
from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): a citation in committed source and in a docstring, which no
#: interpreter difference can reach.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The generated table.
CONST = ROOT / 'pcapkit' / 'const' / 'tcp' / 'mp_tcp_option.py'

#: The crawler whose template renders it.
VENDOR = ROOT / 'pcapkit' / 'vendor' / 'tcp' / 'mp_tcp_option.py'

#: The parser that dispatches on these subtypes.
TRANSPORT = ROOT / 'pcapkit' / 'protocols' / 'transport' / 'tcp.py'

#: The RFC the registry gives as its reference: MPTCP v1, which obsoletes RFC 6824's v0.
REGISTRY_RFC = '8684'

#: The obsoleted document the registry's note points at for the v0 subtypes only.
OBSOLETED_RFC = '6824'

#: An :rst:role:`rfc` role's number, with or without an anchor fragment after it.
RFC_ROLE = re.compile(r':rfc:`(?P<rfc>\d+)(?:#[^`]*)?`')

#: A plain comment's bracketed attribution, as the option-kind map spells it.
RFC_BRACKET = re.compile(r'\[RFC (?P<rfc>\d+)\]')

#: The option-kind map's entry for the kind that carries the MPTCP subtypes.
KIND_ENTRY = 'Enum_Option.Multipath_TCP:'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def _class_docstring(path: 'pathlib.Path', name: 'str') -> 'str':
    """The docstring of class ``name`` in ``path``, read without importing it.

    Args:
        path: Module to parse.
        name: Name of the class whose docstring is wanted.

    Returns:
        The docstring, exactly as the source spells it.

    """
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            doc = ast.get_docstring(node, clean=False)
            if doc is None:
                raise AssertionError(f'{name} in {path} carries no docstring')
            return doc
    raise AssertionError(f'{path} defines no class {name}')


def _method_docstring(path: 'pathlib.Path', cls: 'str', name: 'str') -> 'str':
    """The docstring of ``cls.name`` in ``path``, read without importing it.

    Args:
        path: Module to parse.
        cls: Name of the class holding the method.
        name: Name of the method whose docstring is wanted.

    Returns:
        The docstring, exactly as the source spells it.

    """
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ClassDef) and node.name == cls):
            continue
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == name:
                doc = ast.get_docstring(child, clean=False)
                if doc is None:
                    raise AssertionError(f'{cls}.{name} in {path} carries no docstring')
                return doc
        raise AssertionError(f'{cls} in {path} defines no method {name}')
    raise AssertionError(f'{path} defines no class {cls}')


class MPTCPOptionCitationTests(unittest.TestCase):
    """The class, its members and its template name one RFC: the registry's."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def test_the_table_cites_no_obsoleted_rfc(self) -> 'None':
        # Nothing in the generated table may reach back to the v0 document the
        # registry's note keeps only as a pointer. Deliberately not a pin on
        # every role equalling the registry's RFC: RFC 8684 section 7.2 admits
        # future assignments here under Standards Action, each with its own
        # specification reference, so a new subtype may legitimately cite a
        # document that does not exist yet.
        source = CONST.read_text(encoding='utf-8')
        self.assertNotIn(OBSOLETED_RFC, set(RFC_ROLE.findall(source)))

    def test_the_class_docstring_cites_the_registrys_rfc(self) -> 'None':
        # The class docstring is the table's attribution, so it names the
        # registry's own reference and nothing besides -- a second citation
        # there would be a second answer to "what defines this table".
        doc = _class_docstring(CONST, 'MPTCPOption')
        self.assertEqual(set(RFC_ROLE.findall(doc)), {REGISTRY_RFC})

    def test_the_template_and_the_module_agree(self) -> 'None':
        # Vendor.__init__ reads the crawler class's own docstring as DOCS and
        # renders it as "[{NAME}] {DOCS}", so the two are one string in two
        # places: correcting either alone lets the generator put the other back.
        template = _class_docstring(VENDOR, 'MPTCPOption')
        self.assertEqual(_class_docstring(CONST, 'MPTCPOption'),
                         f'[MPTCPOption] {template}')

    def test_the_option_kind_map_cites_the_registrys_rfc(self) -> 'None':
        # The map's comment attributes the option kind, not any one subtype's
        # wire layout, so it names the document IANA gives for kind 30. The
        # v0-specific citations elsewhere in this module are left alone, which
        # is why this reads the one entry rather than the whole file.
        lines = [line for line in TRANSPORT.read_text(encoding='utf-8').splitlines()
                 if KIND_ENTRY in line]
        self.assertEqual(len(lines), 1, f'{TRANSPORT} must map {KIND_ENTRY} exactly once')
        self.assertEqual(RFC_BRACKET.findall(lines[0]), [REGISTRY_RFC])

    def test_the_generic_mptcp_figure_cites_the_registrys_rfc(self) -> 'None':
        # ``_read_mode_mp`` draws the subtype-agnostic option header, which RFC
        # 8684 figure 3 and RFC 6824 figure 3 draw identically -- so the figure
        # carries no v0-specific claim and cites the current document.
        doc = _method_docstring(TRANSPORT, 'TCP', '_read_mode_mp')
        self.assertEqual(set(RFC_ROLE.findall(doc)), {REGISTRY_RFC})

    @unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
    def test_the_imported_enums_docstring_carries_the_citation(self) -> 'None':
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption

        self.assertEqual(MPTCPOption.__doc__,
                         f'[MPTCPOption] Multipath TCP options [:rfc:`{REGISTRY_RFC}`]')


if __name__ == '__main__':
    unittest.main()
