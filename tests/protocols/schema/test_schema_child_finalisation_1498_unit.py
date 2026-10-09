# -*- coding: utf-8 -*-
"""GitHub issue #1498: each non-final :class:`~pcapkit.protocols.schema.schema.Schema`
subclass is finalised on its own state, whatever was built before it.

:meth:`Schema.__new__ <pcapkit.protocols.schema.schema.Schema.__new__>` used to
read ``__finalised__`` through inheritance, so once a non-final parent had been
built its non-final children read the parent's ``BASE`` and were never
finalised. They kept the ``__excluded__`` copied at declaration, and
``to_dict()`` then included ``__map__``, ``__map_reverse__``, ``__buffer__`` and
``__updated__``. The Quick-Start option schemas of HOPOPT, IPv6-Opts and IPv4
are the shipped instances: each is a non-final subclass of a non-final
``Option``.

The defect depends on process-wide state -- which class was built first -- so
every order runs in a fresh interpreter, started from the repository root so it
imports the tree under test; the child reports ``pcapkit.__file__`` and that is
asserted too.

"""

import json
import os
import subprocess  # nosec: B404
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

#: Parent, child, and the octets each is unpacked from; ``synthetic`` is declared
#: in the script. The shipped octets are a Quick-Start option, which both the
#: generic ``Option`` and the Quick-Start schema can read.
MODELS = {
    'synthetic': ('', 'Parent', 'Child', '01', '0102'),
    'hopopt.QuickStartOption': ('pcapkit.protocols.schema.internet.hopopt', 'Option', 'QuickStartOption',
                                '2606000000000000', '2606000000000000'),
    'ipv6_opts.QuickStartOption': ('pcapkit.protocols.schema.internet.ipv6_opts', 'Option', 'QuickStartOption',
                                   '2606000000000000', '2606000000000000'),
    'ipv4.QSOption': ('pcapkit.protocols.schema.internet.ipv4', 'Option', 'QSOption',
                      '1906000000000000', '1906000000000000'),
}

SCRIPT = r'''
import importlib, json, sys
import pcapkit
from pcapkit.corekit.fields.numbers import UInt8Field
from pcapkit.protocols.schema.schema import Schema

module, parent, child, pdata, cdata, order = sys.argv[1:]
if module:
    ns = vars(importlib.import_module(module))
else:
    class Parent(Schema):
        a: 'int' = UInt8Field()
    class Child(Parent):
        b: 'int' = UInt8Field()
    ns = {'Parent': Parent, 'Child': Child}

data = {parent: bytes.fromhex(pdata), child: bytes.fromhex(cdata)}
result = {'file': pcapkit.__file__}
for name in ((parent, child) if order == 'parent-first' else (child, parent)):
    cls = ns[name]
    schema = cls.unpack(data[name])
    result[name] = {'expected': list(cls.__fields__), 'to_dict': list(schema.to_dict()),
                    'len': len(schema), 'iter': list(schema)}
print(json.dumps(result))
'''


def build(model: 'str', order: 'str') -> 'dict':
    """Build ``model``'s parent and child in ``order``, in a fresh interpreter."""
    module, parent, child, pdata, cdata = MODELS[model]
    proc = subprocess.run([sys.executable, '-c', SCRIPT, module, parent, child, pdata, cdata, order],  # nosec: B603
                          cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
    if proc.returncode:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout.splitlines()[-1])


class SchemaChildFinalisationTests(unittest.TestCase):
    """``to_dict()``, ``len()`` and iteration are right in both construction orders."""

    def test_both_orders(self) -> None:
        for model, (_, parent, child, _, _) in MODELS.items():
            for order in ('parent-first', 'child-first'):
                with self.subTest(model=model, order=order):
                    result = build(model, order)
                    self.assertEqual(os.path.dirname(os.path.dirname(result['file'])), ROOT)
                    for name in (parent, child):
                        got = result[name]
                        self.assertEqual(got['to_dict'], got['expected'], name)
                        self.assertEqual(got['iter'], got['expected'], name)
                        self.assertEqual(got['len'], len(got['expected']), name)

    def test_a_child_declared_after_its_parent_was_built(self) -> None:
        """The other side of the inheritance: declared *after* the parent's ``BASE``."""
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.infoclass import FinalisedState
        from pcapkit.protocols.schema.schema import Schema

        class Parent(Schema):
            a: 'int' = UInt8Field()

        Parent(a=1)
        self.assertEqual(Parent.__dict__.get('__finalised__'), FinalisedState.BASE)

        class Child(Parent):
            b: 'int' = UInt8Field()

            def method(self) -> 'None':
                """A name of its own, which ``__builtin__`` must also cover."""

        child = Child(1, 2)
        self.assertEqual(Child.__dict__.get('__finalised__'), FinalisedState.BASE)
        self.assertIsNot(Child.__init__, Parent.__init__)
        self.assertEqual(child.to_dict(), {'a': 1, 'b': 2})
        self.assertEqual((len(child), list(child)), (2, ['a', 'b']))
        self.assertIn('method', Child.__builtin__)

    def test_a_final_schema_under_a_base_state_ancestor_is_refused(self) -> None:
        """A bare ``@final`` no longer escapes the guard by reading ``BASE`` off its parent."""
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.infoclass import FinalisedState
        from pcapkit.protocols.schema.schema import Schema
        from pcapkit.utilities.compat import final
        from pcapkit.utilities.exceptions import SchemaError

        class Parent(Schema):
            a: 'int' = UInt8Field()

        Parent(a=1)
        self.assertEqual(Parent.__dict__.get('__finalised__'), FinalisedState.BASE)

        @final
        class Mismarked(Parent):
            pass

        self.assertIn('__final__', Mismarked.__dict__)
        self.assertNotIn('__finalised__', Mismarked.__dict__)

        with self.assertRaises(SchemaError) as caught:
            Mismarked(a=1)
        self.assertIn('Mismarked', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
