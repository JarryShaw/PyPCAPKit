# -*- coding: utf-8 -*-
"""GitHub issue #1842: every sentinel is a true singleton.

The owner chose to make the sentinels singletons rather than amend the
convention page to excuse them, with the shared behaviour on one abstract
base. So for ``NULL``, ``NO_VALUE``, ``NO_DEFAULT`` and ``ABSENT`` alike,
calling the type again, :func:`copy.copy`, :func:`copy.deepcopy` and every
:mod:`pickle` protocol hand back the one object.

Before the change only ``NULL`` passed all of that. ``NO_DEFAULT`` failed
pickle protocols 0 and 1, and ``NO_VALUE`` and ``ABSENT`` failed everything.

:data:`OLD_PICKLES` are pickles written by the module as it stood at
``75a9f237b``, the commit this change is based on, so they pin that a pickle
made before the change still loads. They were produced by executing
``git show 75a9f237b:pcapkit/corekit/sentinels.py`` as a module named
``pcapkit.corekit.sentinels``, registering it in :data:`sys.modules`, and
calling :func:`pickle.dumps` on each sentinel at each protocol.

"""
from __future__ import annotations

import copy
import importlib
import inspect
import pickle
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Where every sentinel is defined.
CANONICAL_MODULE = 'pcapkit.corekit.sentinels'

#: ``(object name, repr, truth value)`` for every sentinel. The repr and the truth
#: value are what the shared base must leave as they were.
SENTINELS = (
    ('NULL', '<NULL>', False),
    ('NO_VALUE', '<NO_VALUE>', False),
    ('NO_DEFAULT', '<NO_DEFAULT>', True),
    ('ABSENT', '<absent>', False),
)

#: Pickles written at ``75a9f237b``, keyed by ``(object name, protocol)``. ``NULL``
#: reduced to the module-level ``_get_null``; the others took the default reduce,
#: which is ``copyreg._reconstructor`` below protocol 2 and ``NEWOBJ`` from 2 on.
OLD_PICKLES = {
    ('NULL', 0): b'cpcapkit.corekit.sentinels\n_get_null\np0\n(tRp1\n.',
    ('NULL', 1): b'cpcapkit.corekit.sentinels\n_get_null\nq\x00)Rq\x01.',
    ('NULL', 2): b'\x80\x02cpcapkit.corekit.sentinels\n_get_null\nq\x00)Rq\x01.',
    ('NULL', 3): b'\x80\x03cpcapkit.corekit.sentinels\n_get_null\nq\x00)Rq\x01.',
    ('NULL', 4): (b'\x80\x04\x95.\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                  b'\x94\x8c\t_get_null\x94\x93\x94)R\x94.'),
    ('NULL', 5): (b'\x80\x05\x95.\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                  b'\x94\x8c\t_get_null\x94\x93\x94)R\x94.'),
    ('NO_VALUE', 0): (b'ccopy_reg\n_reconstructor\np0\n(cpcapkit.corekit.sentinels\nNoValueType\n'
                      b'p1\nc__builtin__\nobject\np2\nNtp3\nRp4\n.'),
    ('NO_VALUE', 1): (b'ccopy_reg\n_reconstructor\nq\x00(cpcapkit.corekit.sentinels\nNoValueType\n'
                      b'q\x01c__builtin__\nobject\nq\x02Ntq\x03Rq\x04.'),
    ('NO_VALUE', 2): b'\x80\x02cpcapkit.corekit.sentinels\nNoValueType\nq\x00)\x81q\x01.',
    ('NO_VALUE', 3): b'\x80\x03cpcapkit.corekit.sentinels\nNoValueType\nq\x00)\x81q\x01.',
    ('NO_VALUE', 4): (b'\x80\x04\x950\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                      b'\x94\x8c\x0bNoValueType\x94\x93\x94)\x81\x94.'),
    ('NO_VALUE', 5): (b'\x80\x05\x950\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                      b'\x94\x8c\x0bNoValueType\x94\x93\x94)\x81\x94.'),
    ('NO_DEFAULT', 0): (b'ccopy_reg\n_reconstructor\np0\n(cpcapkit.corekit.sentinels\nNoDefaultType\n'
                        b'p1\nc__builtin__\nobject\np2\nNtp3\nRp4\n.'),
    ('NO_DEFAULT', 1): (b'ccopy_reg\n_reconstructor\nq\x00(cpcapkit.corekit.sentinels\nNoDefaultType\n'
                        b'q\x01c__builtin__\nobject\nq\x02Ntq\x03Rq\x04.'),
    ('NO_DEFAULT', 2): b'\x80\x02cpcapkit.corekit.sentinels\nNoDefaultType\nq\x00)\x81q\x01.',
    ('NO_DEFAULT', 3): b'\x80\x03cpcapkit.corekit.sentinels\nNoDefaultType\nq\x00)\x81q\x01.',
    ('NO_DEFAULT', 4): (b'\x80\x04\x952\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                        b'\x94\x8c\rNoDefaultType\x94\x93\x94)\x81\x94.'),
    ('NO_DEFAULT', 5): (b'\x80\x05\x952\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                        b'\x94\x8c\rNoDefaultType\x94\x93\x94)\x81\x94.'),
    ('ABSENT', 0): (b'ccopy_reg\n_reconstructor\np0\n(cpcapkit.corekit.sentinels\nAbsentType\n'
                    b'p1\nc__builtin__\nobject\np2\nNtp3\nRp4\n.'),
    ('ABSENT', 1): (b'ccopy_reg\n_reconstructor\nq\x00(cpcapkit.corekit.sentinels\nAbsentType\n'
                    b'q\x01c__builtin__\nobject\nq\x02Ntq\x03Rq\x04.'),
    ('ABSENT', 2): b'\x80\x02cpcapkit.corekit.sentinels\nAbsentType\nq\x00)\x81q\x01.',
    ('ABSENT', 3): b'\x80\x03cpcapkit.corekit.sentinels\nAbsentType\nq\x00)\x81q\x01.',
    ('ABSENT', 4): (b'\x80\x04\x95/\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                    b'\x94\x8c\nAbsentType\x94\x93\x94)\x81\x94.'),
    ('ABSENT', 5): (b'\x80\x05\x95/\x00\x00\x00\x00\x00\x00\x00\x8c\x19pcapkit.corekit.sentinels'
                    b'\x94\x8c\nAbsentType\x94\x93\x94)\x81\x94.'),
}

#: A standalone HOPOPT header carrying one MPL option whose seed is the IPv6
#: source address. Parsed with no IPv6 header around it, ``post_process`` has no
#: address to take, so the parsed schema's ``seed`` holds ``NO_VALUE``.
MPL_HEADER = bytes.fromhex('3b006d0220070000')


def _module() -> 'Any':
    """The sentinels module that is live now (GitHub issue #1332)."""
    return importlib.import_module(CANONICAL_MODULE)


class _ReimportCase(unittest.TestCase):
    """Base: give each test class one fresh ``pcapkit`` import."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)


class SingletonTests(_ReimportCase):
    """Each way of getting a second object hands back the first.

    Failures are collected and asserted once, so a regression confined to one
    sentinel or one protocol fails the test method itself under any runner.

    """

    def test_calling_the_type_again_returns_the_sentinel(self) -> 'None':
        module = _module()
        bad = [name for name, _, _ in SENTINELS
               if type(getattr(module, name))() is not getattr(module, name)]
        self.assertEqual(bad, [])

    def test_copy_and_deepcopy_return_the_sentinel(self) -> 'None':
        module = _module()
        bad = []
        for name, _, _ in SENTINELS:
            sentinel = getattr(module, name)
            for copier in (copy.copy, copy.deepcopy):
                if copier(sentinel) is not sentinel:
                    bad.append((name, copier.__name__))
        self.assertEqual(bad, [])

    def test_every_pickle_protocol_round_trips_to_the_sentinel(self) -> 'None':
        module = _module()
        bad = []
        for name, _, _ in SENTINELS:
            sentinel = getattr(module, name)
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                if pickle.loads(pickle.dumps(sentinel, protocol=protocol)) is not sentinel:
                    bad.append((name, protocol))
        self.assertEqual(bad, [])

    def test_repr_and_truth_value_are_unchanged(self) -> 'None':
        """The shared base supplies ``__repr__``; ``__bool__`` stays per sentinel."""
        module = _module()
        for name, text, truth in SENTINELS:
            with self.subTest(sentinel=name):
                self.assertEqual(repr(getattr(module, name)), text)
                self.assertIs(bool(getattr(module, name)), truth)

    def test_the_shared_base_is_private_and_abstract(self) -> 'None':
        """Every sentinel type derives from it; it is not exported and not instantiable."""
        module = _module()
        base = module._Sentinel  # pylint: disable=protected-access

        self.assertTrue(inspect.isabstract(base))
        with self.assertRaises(TypeError):
            base()
        self.assertNotIn('_Sentinel', module.__all__)
        for name, _, _ in SENTINELS:
            with self.subTest(sentinel=name):
                self.assertTrue(issubclass(type(getattr(module, name)), base))


class OldPickleTests(_ReimportCase):
    """A pickle written before the change still loads, as the sentinel where it can."""

    def test_every_old_pickle_still_loads(self) -> 'None':
        module = _module()
        for (name, protocol), blob in OLD_PICKLES.items():
            if protocol > pickle.HIGHEST_PROTOCOL:  # pragma: no cover
                continue
            with self.subTest(sentinel=name, protocol=protocol):
                self.assertIsInstance(pickle.loads(blob), type(getattr(module, name)))

    def test_an_old_pickle_loads_as_the_sentinel(self) -> 'None':
        """``NULL`` at every protocol, the others from protocol 2 on.

        ``NULL``'s old pickles call ``_get_null``, which the module keeps for them.
        The others' old pickles from protocol 2 on rebuild through
        ``cls.__new__(cls)``, which the shared base guards.

        """
        module = _module()
        bad = []
        for (name, protocol), blob in OLD_PICKLES.items():
            if protocol > pickle.HIGHEST_PROTOCOL:  # pragma: no cover
                continue
            if name != 'NULL' and protocol < 2:
                continue
            if pickle.loads(blob) is not getattr(module, name):
                bad.append((name, protocol))
        self.assertEqual(bad, [])

    def test_an_old_default_reduce_below_protocol_2_cannot(self) -> 'None':
        """Pinned so the documented limit stays true.

        Below protocol 2 the default reduce rebuilds through
        :func:`copyreg._reconstructor`, which calls :meth:`object.__new__`
        directly. No hook on the class runs, so these load as a second instance.
        Pickles written after the change reduce to the object's own name instead.

        """
        module = _module()
        for name in ('NO_VALUE', 'NO_DEFAULT', 'ABSENT'):
            for protocol in (0, 1):
                with self.subTest(sentinel=name, protocol=protocol):
                    self.assertIsNot(pickle.loads(OLD_PICKLES[name, protocol]),
                                     getattr(module, name))


class RealObjectTests(_ReimportCase):
    """The objects #1842 measured, which hold ``NO_VALUE`` in practice."""

    def test_a_parsed_mpl_seed_keeps_its_identity(self) -> 'None':
        from pcapkit.protocols.internet.hopopt import HOPOPT

        no_value = _module().NO_VALUE
        schema = HOPOPT(MPL_HEADER, len(MPL_HEADER), extension=True).schema
        self.assertIs(schema.options[0].seed, no_value)

        bad = []
        if copy.deepcopy(schema).options[0].seed is not no_value:
            bad.append('deepcopy')
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            if pickle.loads(pickle.dumps(schema, protocol=protocol)).options[0].seed is not no_value:
                bad.append(protocol)
        self.assertEqual(bad, [])

    def test_a_deep_copied_field_keeps_its_default(self) -> 'None':
        from pcapkit.corekit.fields.strings import BytesField

        no_value = _module().NO_VALUE
        self.assertIs(copy.deepcopy(BytesField(length=4)).default, no_value)


if __name__ == '__main__':
    unittest.main()
