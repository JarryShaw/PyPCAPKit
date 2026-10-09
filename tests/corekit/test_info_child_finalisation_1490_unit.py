# -*- coding: utf-8 -*-
"""GitHub issue #1490: each non-final :class:`~pcapkit.corekit.infoclass.Info`
subclass is finalised on its own state, whatever was built before it.

:meth:`Info.__new__ <pcapkit.corekit.infoclass.Info.__new__>` used to read
``__finalised__`` through inheritance, so once a non-final parent had been built
its non-final children read the parent's ``BASE`` and were never finalised. They
kept the ``__excluded__`` copied at declaration, and ``to_dict()``, ``len()`` and
iteration then included ``__map__``, ``__map_reverse__`` and ``__multi__``.

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

from tests.corekit._roundtrip import skip_without_runtime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: Parent and child, by ``module:qualname``; ``synthetic`` is declared in the script.
MODELS = {
    'synthetic': ('', 'Parent', 'Child'),
    'hopopt.QuickStartOption': ('pcapkit.protocols.data.internet.hopopt', 'Option', 'QuickStartOption'),
    'hopopt.SMFDPDOption': ('pcapkit.protocols.data.internet.hopopt', 'Option', 'SMFDPDOption'),
    'ipv6_opts.QuickStartOption': ('pcapkit.protocols.data.internet.ipv6_opts', 'Option', 'QuickStartOption'),
    'ipv4.QSOption': ('pcapkit.protocols.data.internet.ipv4', 'Option', 'QSOption'),
    'tcp.MPTCPJoin': ('pcapkit.protocols.data.transport.tcp', 'MPTCP', 'MPTCPJoin'),
}

SCRIPT = r'''
import importlib, json, sys
import pcapkit
from pcapkit.corekit.infoclass import Info

module, parent, child, order = sys.argv[1:]
if module:
    ns = vars(importlib.import_module(module))
else:
    class Parent(Info):
        a: 'int'
    class Child(Parent):
        b: 'int'
    ns = {'Parent': Parent, 'Child': Child}

def keys(cls):
    out = []
    for base in reversed(cls.__mro__[:cls.__mro__.index(Info)]):
        out.extend(key for key in base.__dict__.get('__annotations__', {}) if key not in out)
    return out

result = {'file': pcapkit.__file__}
for name in ((parent, child) if order == 'parent-first' else (child, parent)):
    cls = ns[name]
    info = cls.from_dict({key: index for index, key in enumerate(keys(cls))})
    result[name] = {'expected': keys(cls), 'to_dict': list(info.to_dict()),
                    'len': len(info), 'iter': list(info)}
print(json.dumps(result))
'''


def build(model: 'str', order: 'str') -> 'dict':
    """Build ``model``'s parent and child in ``order``, in a fresh interpreter."""
    module, parent, child = MODELS[model]
    proc = subprocess.run([sys.executable, '-c', SCRIPT, module, parent, child, order],  # nosec: B603
                          cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
    if proc.returncode:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout.splitlines()[-1])


class ChildFinalisationTests(unittest.TestCase):
    """``to_dict()``, ``len()`` and iteration are right in both construction orders."""

    def setUp(self) -> None:
        skip_without_runtime(self)

    def test_both_orders(self) -> None:
        for model, (_, parent, child) in MODELS.items():
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
        from pcapkit.corekit.infoclass import FinalisedState, Info

        class Parent(Info):
            a: int

        Parent(a=1)

        class Child(Parent):
            b: int

            def method(self) -> 'None':
                """A name of its own, which ``__builtin__`` must also cover."""

        child = Child(1, 2)
        self.assertEqual(Child.__dict__.get('__finalised__'), FinalisedState.BASE)
        self.assertEqual(list(child.to_dict()), ['a', 'b'])
        self.assertEqual((len(child), list(child)), (2, ['a', 'b']))
        self.assertIn('method', Child.__builtin__)


if __name__ == '__main__':
    unittest.main()
