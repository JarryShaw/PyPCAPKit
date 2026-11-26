# -*- coding: utf-8 -*-
"""An AppType member declares only what differs from its defaults (#3055).

A per-transport member gives its port alone where its service name is its own
name (``exp2 = 1022``) and adds the name only where the two differ
(``ltp_deepspace = 1113, 'ltp-deepspace'``). ``AppType.__new__`` takes the
transport from the registry's ``__transport__``, and ``_generate_next_value_``
supplies the name: aenum calls it for a member declaring fewer values than
``__new__`` requires, passing the member's name.

That hook is enum machinery, so this runs on every interpreter. Every member is
checked against its own declaration and against the declaration form.

"""
from __future__ import annotations

import ast
import inspect
import unittest

#: Test tier (#1958): exercises aenum's member-creation hooks, whose host
#: machinery differs by interpreter.
__tier__ = 'ALL'

#: The per-transport registries, by class name.
REGISTRIES = ('TCP', 'UDP', 'SCTP', 'DCCP')


def _registry(name: 'str') -> 'type':
    import pcapkit.const.reg.apptype as package

    return getattr(package, name)


def _declarations(name: 'str') -> 'list[tuple[str, tuple]]':
    """Each ``(member, literal values)`` row class ``name`` declares in its module."""
    source = inspect.getsource(inspect.getmodule(_registry(name)))
    body = next(node.body for node in ast.parse(source).body
                if isinstance(node, ast.ClassDef) and node.name == name)

    rows = []
    for node in body:
        if not isinstance(node, ast.Assign):
            continue
        elts = node.value.elts if isinstance(node.value, ast.Tuple) else [node.value]
        rows.append((node.targets[0].id, tuple(map(ast.literal_eval, elts))))
    return rows


class AppTypeMemberDefaultsTests(unittest.TestCase):
    """Every member's value, ``svc``, ``port`` and ``proto``, from the short form."""

    def test_every_member_takes_its_name_and_its_registrys_transport(self) -> None:
        for name in REGISTRIES:
            registry = _registry(name)
            rows = _declarations(name)
            self.assertNotEqual(rows, [])
            proto = registry.__transport__
            with self.subTest(registry=name):
                for key, values in rows:
                    port, svc = (values + (key,))[:2]
                    member = registry.__members__[key]
                    value = f'{svc} [{port} - {proto.name}]'
                    self.assertEqual((member.value, str.__str__(member), member.svc, member.port),
                                     (value, value, svc, port))
                    self.assertIs(member.proto, proto)

    def test_a_member_declares_neither_its_transport_nor_its_own_name(self) -> None:
        for name in REGISTRIES:
            with self.subTest(registry=name):
                for key, values in _declarations(name):
                    self.assertIsInstance(values[0], int, key)
                    self.assertLessEqual(len(values), 2, key)
                    if len(values) == 2:
                        self.assertIsInstance(values[1], str, key)
                        self.assertNotEqual(values[1], key)


if __name__ == '__main__':
    unittest.main()
