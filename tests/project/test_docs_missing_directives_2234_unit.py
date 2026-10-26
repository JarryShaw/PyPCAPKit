# -*- coding: utf-8 -*-
"""Pins the API entries of members whose docstring no directive would otherwise render (#2234).

* ``Protocol.context`` -- a public property of every protocol, listed on the
  ``Protocol`` autoclass and in the ``ProtocolBase`` property group beside its
  siblings.
* ``IPX._next_exthdr_depth`` -- an override of the
  ``Internet._next_exthdr_depth`` hook, which ``internet.rst`` documents, so the
  override is contract too.
* ``held_body``, ``FlagsField`` and ``PACKET_FLAGS`` in
  :mod:`pcapkit.protocols.schema.misc.pcapng` -- listed beside the length
  callbacks, the option fields and the ``autodata`` constants respectively.

Each entry is checked as declared on its page and as naming a real object, the
textual precondition a plain (non-nitpicky) build would not notice losing.

"""

from __future__ import annotations

import importlib
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
API = ROOT / 'docs' / 'source' / 'pcapkit' / 'protocols'

#: The pcapng schema module, whose helpers ``pcapng.rst`` documents.
SCHEMA = 'pcapkit.protocols.schema.misc.pcapng'


def _block(text: 'str', directive: 'str') -> 'str':
    """The body of the top-level ``directive`` in ``text``, up to the next unindented line."""
    lines = text.splitlines()
    start = lines.index(directive)
    body = []
    for line in lines[start + 1:]:
        if line and not line[0].isspace():
            break
        body.append(line)
    return '\n'.join(body)


def _group(block: 'str', directive: 'str') -> 'list[str]':
    """The names of a grouped ``directive`` (e.g. ``py:property``) inside ``block``, options left out."""
    match = re.search(rf'^( *)\.\. {re.escape(directive)}:: (\S+)\n((?:\1 +[^:\s]\S*\n)*)', block + '\n', re.M)
    if match is None:
        return []
    return [match.group(2)] + match.group(3).split()


class ProtocolContextTests(unittest.TestCase):
    """``context`` is documented on ``Protocol`` and linked from ``ProtocolBase``."""

    text = (API / 'protocol.rst').read_text(encoding='utf-8')

    def test_protocol_autoclass_lists_context(self) -> 'None':
        """Listed after ``schema``, the property it follows in the class."""
        block = _block(self.text, '.. autoclass:: pcapkit.protocols.protocol.Protocol')
        self.assertIn('   .. autoproperty:: schema\n   .. autoproperty:: context\n', block)

    def test_protocolbase_group_lists_and_links_context(self) -> 'None':
        """In the property group, and linked to its ``Protocol`` entry."""
        block = _block(self.text, '.. autoclass:: pcapkit.protocols.protocol.ProtocolBase')
        self.assertIn('context', _group(block, 'py:property'))
        self.assertIn(':attr:`~Protocol.context`', block)

    def test_context_is_a_property_of_protocolbase(self) -> 'None':
        """The entry names a real property, defined where the group says."""
        from pcapkit.protocols.protocol import ProtocolBase  # pylint: disable=import-outside-toplevel
        self.assertIsInstance(ProtocolBase.__dict__.get('context'), property)


class IPXNextExthdrDepthTests(unittest.TestCase):
    """The ``_next_exthdr_depth`` override on ``IPX`` has an entry."""

    def test_ipx_autoclass_lists_the_override(self) -> 'None':
        """Listed on the ``IPX`` autoclass beside ``_make_data``."""
        text = (API / 'internet' / 'ipx.rst').read_text(encoding='utf-8')
        block = _block(text, '.. autoclass:: pcapkit.protocols.internet.ipx.IPX')
        self.assertIn('   .. automethod:: _next_exthdr_depth\n', block)

    def test_the_hook_it_overrides_is_documented(self) -> 'None':
        """The base hook has its own entry, which makes the override contract."""
        text = (API / 'internet' / 'internet.rst').read_text(encoding='utf-8')
        self.assertIn('   .. automethod:: _next_exthdr_depth\n', text)

    def test_ipx_defines_its_own_override(self) -> 'None':
        """The entry documents the method ``IPX`` defines, not an inherited one."""
        from pcapkit.protocols.internet.ipx import IPX  # pylint: disable=import-outside-toplevel
        self.assertIn('_next_exthdr_depth', IPX.__dict__)


class PCAPNGSchemaHelperTests(unittest.TestCase):
    """``held_body``, ``FlagsField`` and ``PACKET_FLAGS`` have entries on ``pcapng.rst``."""

    text = (API / 'misc' / 'pcapng.rst').read_text(encoding='utf-8')

    #: Each name, and the directive that documents it.
    ENTRIES = {
        'held_body': f'.. autofunction:: {SCHEMA}.held_body\n',
        'FlagsField': f'.. autoclass:: {SCHEMA}.FlagsField\n   :members:\n   :show-inheritance:\n',
        'PACKET_FLAGS': f'.. autodata:: {SCHEMA}.PACKET_FLAGS\n   :no-value:\n',
    }

    def test_each_entry_is_declared(self) -> 'None':
        """Each directive appears once, with the options its siblings carry."""
        for name, directive in self.ENTRIES.items():
            with self.subTest(name=name):
                self.assertEqual(self.text.count(directive), 1)

    def test_each_entry_names_a_real_object(self) -> 'None':
        """Each documented name exists in the schema module."""
        module = importlib.import_module(SCHEMA)
        for name in self.ENTRIES:
            with self.subTest(name=name):
                self.assertTrue(hasattr(module, name))


if __name__ == '__main__':
    unittest.main()
