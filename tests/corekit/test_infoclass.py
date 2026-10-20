from __future__ import annotations

import importlib.util
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises metaclass, ABC or enum machinery, which differs by
#: interpreter.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class InfoClassTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_finalised_annotated_info_generates_init_and_warns_once_final(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.corekit.version import VersionInfo

        @info_final
        class Point(Info):
            x: int
            y: int

        point = Point(1, 2)
        self.assertEqual(point.x, 1)
        self.assertEqual(point['y'], 2)
        self.assertEqual(str(point), 'Point(x=1, y=2)')
        self.assertEqual(repr(point), '<Point x=1, y=2>')

        with mock.patch('pcapkit.corekit.infoclass.warn') as warn:
            self.assertIs(info_final(Point), Point)
        warn.assert_called_once()

        class BasePoint(Info):
            x: int

        @info_final
        class NamedPoint(BasePoint):
            x: int
            name: str

        named = NamedPoint(3, 'three')
        self.assertEqual(list(named.to_dict().items(multi=True)), [('x', 3), ('name', 'three')])

        version = VersionInfo(1, 2)
        self.assertEqual(version.version, '1.2')
        self.assertEqual(str(version), '1.2')

    def test_auto_finalised_info_mapping_update_and_builtin_key_remapping(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.utilities.exceptions import UnsupportedCall

        class Bag(Info):
            __excluded__ = ['hidden']

        bag = Bag({'items': 'conflict', 'visible': 1, 'hidden': 2}, extra=3)
        self.assertEqual(bag['items'], 'conflict')
        self.assertEqual(list(bag), ['items', 'visible', 'extra'])
        # NOTE: GitHub issue #1296 -- ``len`` counts exactly the keys
        # iteration yields, so the ``__excluded__`` ``hidden`` key and the
        # internal bookkeeping attributes are not counted.
        self.assertEqual(len(bag), 3)
        self.assertEqual(str(bag), 'Bag(items=conflict, visible=1, extra=3)')
        self.assertIn('items=', repr(bag))
        self.assertEqual(list(bag.to_dict().items(multi=True)), [('items', 'conflict'), ('visible', 1), ('extra', 3)])

        with self.assertRaises(UnsupportedCall):
            bag.visible = 9
        with self.assertRaises(UnsupportedCall):
            del bag.visible

    def test_from_dict_iterables_nested_info_and_inherited_metadata(self) -> None:
        from pcapkit.corekit.infoclass import Info

        class Base(Info):
            __additional__ = ['base_additional']
            __excluded__ = ['base_hidden']

        class Child(Base):
            __additional__ = ['child_additional']
            __excluded__ = ['child_hidden']

        self.assertIn('base_additional', Child.__additional__)
        self.assertIn('child_additional', Child.__additional__)
        self.assertIn('base_hidden', Child.__excluded__)
        self.assertIn('child_hidden', Child.__excluded__)

        inner = Info.from_dict(answer=42)
        outer = Child.from_dict([('inner', inner), ('base_hidden', 'skip')], child_hidden='skip',
                                kept='yes')
        self.assertEqual(outer['inner'], inner)
        self.assertIn('inner=Info(...)', repr(outer))
        converted = outer.to_dict()
        self.assertEqual(list(converted['inner'].items(multi=True)), [('answer', 42)])
        self.assertEqual(converted['kept'], 'yes')
        self.assertNotIn('base_hidden', converted)
        self.assertNotIn('child_hidden', converted)

        self.assertEqual(Info.from_dict({'a': 1}, b=2).to_dict().to_dict(), {'a': 1, 'b': 2})
        self.assertEqual(Info.from_dict(c=3).to_dict().to_dict(), {'c': 3})


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OwnAnnotationsTests(unittest.TestCase):
    """GitHub issue #1692: each class contributes only the annotations it declares.

    Below Python 3.10 (bpo-43901), ``cls.__annotations__`` of a class declaring
    none is its nearest base's. These pin the 3.10+ answers on every version.

    """

    #: Generated ``__init__`` signature of each class :meth:`_signatures` builds.
    EXPECTED = {
        'Bare': '(self, dict_=None, **kwargs)',
        'BareChild': '(self, dict_=None, **kwargs)',
        'Point': '(self, x, y)',
        'PointChild': '(self, x, y)',
        'Chain': '(self, a, c)',
        # NOTE: MRO ``Diamond, B, C, A``. Reading ``B.__annotations__`` gave
        # ``A``'s ``a`` ahead of ``C``'s ``c``, i.e. ``(self, c, a, d)``.
        'Diamond': '(self, a, c, d)',
    }

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _signatures() -> dict[str, str]:
        """Build fresh classes, finalise them, and return each ``__init__`` signature."""
        import inspect

        from pcapkit.corekit.infoclass import Info, info_final

        class Bare(Info):
            pass

        class BareChild(Bare):
            pass

        class Point(Info):
            x: int
            y: int

        class PointChild(Point):
            pass

        class A(Info):
            a: int

        class B(A):
            pass

        class Chain(B):
            c: int

        class C(A):
            c: int

        class Diamond(B, C):
            d: int

        signatures = {}
        for cls in (Bare, BareChild, Point, PointChild, Chain, Diamond):
            # NOTE: ``_finalised=False`` is what :meth:`Info.__new__` passes; it
            # leaves the class open, so ``BareChild`` can follow ``Bare``.
            info_final(cls, _finalised=False)
            signatures[cls.__name__] = str(inspect.signature(cls.__init__))
        return signatures

    def test_generated_signature_is_the_same_on_every_version(self) -> None:
        self.assertEqual(self._signatures(), self.EXPECTED)

        from pcapkit.corekit.infoclass import Info

        class Bare(Info):
            pass

        class BareChild(Bare):
            pass

        for cls in (Bare, BareChild):
            with self.subTest(cls=cls.__name__):
                info = cls({'a': 1}, b=2)
                self.assertEqual(list(info.items()), [('a', 1), ('b', 2)])

    def test_annotations_are_read_through_the_compat_shim(self) -> None:
        """GitHub issue #1709: one version-gated reader, from :mod:`pcapkit.utilities.compat`."""
        from pcapkit.corekit import infoclass
        from pcapkit.protocols import protocol
        from pcapkit.utilities import compat

        self.assertIs(infoclass.get_annotations, compat.get_annotations)
        self.assertIs(protocol.get_annotations, compat.get_annotations)

    def test_the_pre_3_10_reader_gives_the_same_signatures(self) -> None:
        # NOTE: a stand-in for ``compat.get_annotations`` below 3.10 -- the
        # class's own ``__dict__`` entry, as ``tests.utilities.test_compat`` pins
        # the real fallback to be -- so every leg checks that branch. It is sound
        # on 3.14 too because this module's ``from __future__ import
        # annotations`` stores a class's own annotations in its ``__dict__``
        # there as well.
        from pcapkit.corekit import infoclass

        def pre_3_10_reader(obj: type) -> dict:
            return obj.__dict__.get('__annotations__', {})

        with mock.patch.object(infoclass, 'get_annotations', pre_3_10_reader):
            self.assertEqual(self._signatures(), self.EXPECTED)

    def test_from_dict_rebuilds_a_field_inherited_by_a_field_less_subclass(self) -> None:
        from pcapkit.corekit.infoclass import Info

        class Leaf(Info):
            v: int

        class Holder(Info):
            # NOTE: an annotation is resolved in the namespace of the class
            # declaring it; ``Kind`` stands in for a base module's globals.
            # Below 3.10, ``Sub`` read ``child`` as its own and resolved it in
            # its own namespace, where ``Kind`` is unknown, so it was skipped.
            Kind = Leaf
            child: Kind

        class Sub(Holder):
            pass

        sub = Sub.from_dict(child={'v': 1})
        self.assertIsInstance(sub['child'], Leaf)
        self.assertEqual(sub['child']['v'], 1)


if __name__ == '__main__':
    unittest.main()
