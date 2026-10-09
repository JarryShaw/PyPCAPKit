# -*- coding: utf-8 -*-
"""``MultiInfo``, ``OrderedMultiInfo``, and what ``Info`` does with them.

GitHub issue #1484:

* :class:`~pcapkit.corekit.infoclass.MultiInfo` and
  :class:`~pcapkit.corekit.infoclass.OrderedMultiInfo` are immutable, read a key
  as an attribute, and keep every value of a repeated key -- the ordered one in
  order across keys;
* both are :class:`~pcapkit.corekit.infoclass.Info` subclasses that inherit
  ``from_dict`` and the finalisation rules, while the mapping protocol stays the
  multi-mapping's own;
* a finalised :class:`~pcapkit.corekit.infoclass.Info` holds every
  :class:`~pcapkit.corekit.multidict.MultiDict` value as one of them;
* :meth:`~pcapkit.corekit.infoclass.Info.to_dict` returns a plain
  :class:`~pcapkit.corekit.multidict.OrderedMultiDict` at every level, and
  :meth:`~pcapkit.corekit.infoclass.Info.from_dict` restores the ``*Info`` types.

Every case builds its own values and reads no capture. :mod:`pcapkit` is
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import copy
import enum
import itertools
import pickle  # nosec: B403 -- round-trips objects built here
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

PAIRS = [('a', 1), ('b', 2), ('a', 3)]


class Colour(enum.IntEnum):
    """An enum key, as the option lists are keyed."""

    RED = 1
    BLUE = 2


def canonical(value):  # type: ignore[no-untyped-def]
    """``value`` with every multi-mapping in it turned into its class and pairs, recursively.

    Exports are compared through this: an
    :class:`~pcapkit.corekit.multidict.OrderedMultiDict` compares its values
    with ``!=``, which for a nested one compares its internal buckets.

    """
    from pcapkit.corekit.multidict import MultiDict

    if isinstance(value, MultiDict):
        return (type(value).__qualname__, [(key, canonical(item)) for key, item in value.items(multi=True)])
    return value


class MultiInfoTests(unittest.TestCase):
    """The two classes on their own."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def classes(self):  # type: ignore[no-untyped-def]
        from pcapkit.corekit.infoclass import MultiInfo, OrderedMultiInfo
        return MultiInfo, OrderedMultiInfo

    def test_repeated_keys_are_kept_and_ordered(self) -> None:
        MultiInfo, OrderedMultiInfo = self.classes()

        ordered = OrderedMultiInfo(PAIRS)
        self.assertEqual(list(ordered.items(multi=True)), PAIRS)
        self.assertEqual(list(ordered), ['a', 'b'])

        grouped = MultiInfo(PAIRS)
        self.assertEqual(list(grouped.items(multi=True)), [('a', 1), ('a', 3), ('b', 2)])

        for info in (ordered, grouped):
            with self.subTest(cls=type(info).__name__):
                self.assertEqual(info['a'], 1)
                self.assertEqual(info.getlist('a'), [1, 3])
                self.assertEqual(len(info), 2)

    def test_keys_read_as_attributes(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        for cls in self.classes():
            with self.subTest(cls=cls.__name__):
                info = cls(PAIRS + [(Colour.BLUE, 'blue'), ('items', 'shadowed')])
                self.assertEqual((info.a, info.b), (1, 2))
                self.assertEqual(info.BLUE, 'blue')
                # A name the class defines is the method, not the key.
                self.assertTrue(callable(info.items))
                self.assertEqual(info['items'], 'shadowed')
                self.assertFalse(hasattr(info, 'missing'))
                with self.assertRaises(AttributeError) as ctx:
                    info.missing  # pylint: disable=pointless-statement
                self.assertIsInstance(ctx.exception, UnsupportedCall)

    def test_every_mutation_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        mutations = {
            'setitem': lambda info: info.__setitem__('a', 0),
            'delitem': lambda info: info.__delitem__('a'),
            'ior': lambda info: info.__ior__({'c': 4}),
            'add': lambda info: info.add('c', 4),
            'setlist': lambda info: info.setlist('a', [0]),
            'setdefault': lambda info: info.setdefault('c', 4),
            'setlistdefault': lambda info: info.setlistdefault('c', [4]),
            'update': lambda info: info.update({'c': 4}),
            'pop': lambda info: info.pop('a'),
            'popitem': lambda info: info.popitem(),
            'poplist': lambda info: info.poplist('a'),
            'popitemlist': lambda info: info.popitemlist(),
            'clear': lambda info: info.clear(),
            'setstate': lambda info: info.__setstate__([]),
            'setattr': lambda info: setattr(info, 'a', 0),
            'delattr': lambda info: delattr(info, 'a'),
        }
        for cls in self.classes():
            for name, mutate in mutations.items():
                with self.subTest(cls=cls.__name__, mutation=name):
                    info = cls(PAIRS)
                    before = list(info.items(multi=True))
                    with warnings.catch_warnings(), self.assertRaises(UnsupportedCall):
                        warnings.simplefilter('ignore')
                        mutate(info)
                    self.assertEqual(list(info.items(multi=True)), before)

    def test_copies_keep_the_type_and_every_value(self) -> None:
        for cls in self.classes():
            info = cls(PAIRS)
            for how, clone in (('copy', copy.copy(info)), ('deepcopy', copy.deepcopy(info)),
                               ('pickle', pickle.loads(pickle.dumps(info)))):  # nosec: B301
                with self.subTest(cls=cls.__name__, how=how):
                    self.assertIs(type(clone), cls)
                    self.assertEqual(list(clone.items(multi=True)), list(info.items(multi=True)))

    def test_compares_like_the_multi_dict_it_builds_on(self) -> None:
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict

        MultiInfo, OrderedMultiInfo = self.classes()
        self.assertEqual(OrderedMultiInfo(PAIRS), OrderedMultiDict(PAIRS))
        self.assertNotEqual(OrderedMultiInfo(PAIRS), OrderedMultiDict(list(reversed(PAIRS))))
        self.assertEqual(MultiInfo(PAIRS), MultiDict(PAIRS))
        self.assertIsInstance(OrderedMultiInfo(PAIRS), OrderedMultiDict)
        self.assertIsInstance(MultiInfo(PAIRS), MultiDict)


class InfoSubclassTests(unittest.TestCase):
    """The two classes as :class:`Info` subclasses -- the owner's ruling on #1484."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_both_are_info_subclasses_with_the_multi_dict_protocol(self) -> None:
        from pcapkit.corekit.infoclass import Info, MultiInfo, OrderedMultiInfo
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
        from pcapkit.protocols.data.application.httpv2 import Settings

        for cls, base in ((MultiInfo, MultiDict), (OrderedMultiInfo, OrderedMultiDict), (Settings, OrderedMultiDict)):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, Info))
                self.assertIsInstance(cls(PAIRS), Info)
                self.assertIsInstance(cls(PAIRS), base)
                # Info precedes the multi-mapping in the MRO, yet the mapping
                # protocol is the multi-mapping's own.
                mro = cls.__mro__
                self.assertLess(mro.index(Info), mro.index(base))
                for name in ('__iter__', '__len__', '__contains__', '__repr__',
                             'keys', 'values', 'get', 'getlist', 'lists', 'copy', 'deepcopy'):
                    self.assertIs(getattr(cls, name), getattr(base, name), name)
                # ``==`` is the multi-mapping's for the ordered ones, and its own
                # for MultiInfo, which defers to an ordered operand; ``!=`` is
                # never dict's, which compares the internal storage (#1484).
                if cls is MultiInfo:
                    self.assertIsNot(cls.__eq__, base.__eq__)
                else:
                    self.assertIs(cls.__eq__, base.__eq__)
                self.assertIsNot(cls.__ne__, base.__ne__)
                if cls is not Settings:  # which overrides both, for its last-value-wins reads
                    self.assertIs(cls.__getitem__, base.__getitem__)
                    self.assertIs(cls.items, base.items)
                self.assertIsNone(cls.__hash__)

    def test_from_dict_is_inherited_and_round_trips(self) -> None:
        from pcapkit.corekit.infoclass import Info, MultiInfo, OrderedMultiInfo, _OrderedMultiDict
        from pcapkit.corekit.multidict import MultiDict

        for cls, plain in ((MultiInfo, MultiDict), (OrderedMultiInfo, _OrderedMultiDict)):
            with self.subTest(cls=cls.__name__):
                self.assertIs(cls.from_dict.__func__, Info.from_dict.__func__)  # type: ignore[attr-defined]
                info = cls.from_dict(PAIRS)
                self.assertIs(type(info), cls)
                self.assertEqual(list(info.items(multi=True)), list(plain(PAIRS).items(multi=True)))

                exported = info.to_dict()
                self.assertIs(type(exported), plain)
                rebuilt = cls.from_dict(exported)
                self.assertIs(type(rebuilt), cls)
                self.assertEqual(list(rebuilt.items(multi=True)), list(info.items(multi=True)))
                self.assertEqual(rebuilt, info)

                # As the multi-mapping's own constructor does: keywords and a
                # mapping's list values add a pair each.
                self.assertEqual(list(cls.from_dict({'a': [1, 3]}, b=2).items(multi=True)),
                                 list(plain([('a', 1), ('a', 3), ('b', 2)]).items(multi=True)))
                # MultiDict's flat forms stay reachable.
                self.assertEqual(info.to_dict(flat=True), {'a': 1, 'b': 2})
                self.assertEqual(info.to_dict(flat=False), {'a': [1, 3], 'b': [2]})

    def test_the_finalisation_rules_apply(self) -> None:
        from pcapkit.corekit.infoclass import FinalisedState, OrderedMultiInfo, info_final
        from pcapkit.utilities.exceptions import InfoError

        @info_final
        class Sealed(OrderedMultiInfo):
            """A final option list."""

        # No ``__init__`` is generated: the class keeps the mapping constructor.
        self.assertNotIn('__init__', Sealed.__dict__)
        self.assertEqual(Sealed.__dict__['__finalised__'], FinalisedState.FINAL)
        self.assertEqual(list(Sealed(PAIRS).items(multi=True)), PAIRS)
        self.assertIsInstance(OrderedMultiInfo.__additional__, list)
        self.assertIsInstance(OrderedMultiInfo.__excluded__, list)
        with self.assertRaises(InfoError):
            class Derived(Sealed):  # pylint: disable=unused-variable
                """Refused: its parent is final."""

    def test_an_info_writes_its_option_lists_in_full(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.multidict import OrderedMultiDict

        info = Info.from_dict({'nested': Info(x=1), 'options': OrderedMultiDict(PAIRS)})
        self.assertEqual(repr(info), "<Info nested=Info(...), options=OrderedMultiInfo([('a', 1), ('b', 2), ('a', 3)])>")
        self.assertEqual(str(info.options), "OrderedMultiInfo([('a', 1), ('b', 2), ('a', 3)])")


class ExportComparisonTests(unittest.TestCase):
    """``to_dict()`` exports compare as mappings should -- the owner's ``__ne__`` ruling on #1484."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def info(self, last: int = 3):  # type: ignore[no-untyped-def]
        """An :class:`Info` holding a nested model, both option lists and a nested option list."""
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict

        return Info.from_dict(OrderedMultiDict([
            ('nested', Info(x=1, options=OrderedMultiDict(PAIRS))),
            ('ordered', OrderedMultiDict([('a', 1), ('b', 2), ('a', last)])),
            ('grouped', MultiDict(PAIRS)),
            ('nested', Info(x=2)),
        ]))

    def test_equal_exports_are_equal_and_not_unequal(self) -> None:
        info = self.info()
        first, second = info.to_dict(), info.to_dict()
        self.assertTrue(first == second)
        self.assertFalse(first != second)
        for ((key, one), (_, two)) in zip(first.items(multi=True), second.items(multi=True)):
            with self.subTest(key=key):
                self.assertTrue(one == two)
                self.assertFalse(one != two)
        self.assertFalse(info.ordered.to_dict() != info.ordered.to_dict())
        self.assertFalse(info.nested.options.to_dict() != info.nested.options.to_dict())

        # A real difference, however deep, still shows.
        other = self.info(last=4).to_dict()
        self.assertTrue(first != other)
        self.assertFalse(first == other)
        # As documented: an export is never equal to a plain dict.
        self.assertTrue(first['ordered'] != {'a': 1, 'b': 2})
        self.assertFalse(first['ordered'] == {'a': 1, 'b': 2})

    def test_an_option_list_is_unequal_exactly_when_it_is_not_equal(self) -> None:
        from pcapkit.corekit.infoclass import MultiInfo, OrderedMultiInfo
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
        from pcapkit.protocols.data.application.httpv2 import Settings

        swapped = [('b', 2), ('a', 1), ('a', 3)]
        for cls, plain in ((OrderedMultiInfo, OrderedMultiDict), (Settings, OrderedMultiDict), (MultiInfo, MultiDict)):
            info = cls(PAIRS)
            cases = {
                'an equal copy': (cls(PAIRS), True),
                'another order': (cls(swapped), cls is MultiInfo),  # only MultiInfo ignores the order
                f'an equal {plain.__name__}': (plain(PAIRS), True),
                f'a reordered {plain.__name__}': (plain(swapped), cls is MultiInfo),
                'a dict': ({'a': 1, 'b': 2}, False),
                'its own export': (info.to_dict(), True),
            }
            for name, (other, equal) in cases.items():
                with self.subTest(cls=cls.__name__, other=name):
                    for (one, two) in ((info, other), (other, info)):
                        self.assertIs(one == two, equal)
                        self.assertIs(one != two, not equal)

    def test_comparisons_are_symmetric_and_negated_across_every_kind(self) -> None:
        """``a == b`` is ``b == a``, and ``a != b`` is ``not a == b``, for every pair of kinds."""
        from pcapkit.corekit.infoclass import MultiInfo, OrderedMultiInfo
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
        from pcapkit.protocols.data.application.httpv2 import Settings

        reordered = [('b', 2), ('a', 1), ('a', 3)]
        kinds = {
            'MultiInfo': MultiInfo,
            'OrderedMultiInfo': OrderedMultiInfo,
            'Settings': Settings,
            'OrderedMultiInfo export': lambda pairs: OrderedMultiInfo(pairs).to_dict(),
            'MultiInfo export': lambda pairs: MultiInfo(pairs).to_dict(),
            'MultiDict': MultiDict,
            'OrderedMultiDict': OrderedMultiDict,
            'dict': lambda pairs: MultiDict(pairs).to_dict(flat=True),
        }
        ordered = {'OrderedMultiInfo', 'Settings', 'OrderedMultiInfo export', 'OrderedMultiDict'}

        def expected(left: str, right: str, same_order: bool) -> bool:
            if 'dict' in (left, right):
                return left == right
            return same_order or not (left in ordered and right in ordered)

        def verbatim_ne(one: object, two: object) -> bool:
            # NOTE: Werkzeug's OrderedMultiDict, kept verbatim in
            # pcapkit.corekit.multidict (the owner's option 3 on #1484), has no
            # ``__ne__``, so ``!=`` is dict's and compares the internal buckets.
            # Python asks it first when it is the left operand, and when it is
            # the right one of a bare MultiDict, which overrides nothing either;
            # no code outside that module is then consulted.
            return type(one) is OrderedMultiDict or (type(one) is MultiDict and type(two) is OrderedMultiDict)

        for (left, make_left), (right, make_right) in itertools.product(kinds.items(), repeat=2):
            for same_order, pairs in ((True, PAIRS), (False, reordered)):
                with self.subTest(left=left, right=right, order='same' if same_order else 'reordered'):
                    one, two = make_left(PAIRS), make_right(pairs)
                    self.assertIs(one == two, expected(left, right, same_order))
                    self.assertIs(two == one, one == two)
                    for (a, b) in ((one, two), (two, one)):
                        if not verbatim_ne(a, b):
                            self.assertIs(a != b, not a == b)

    def test_copies_of_an_export_keep_its_class(self) -> None:
        from pcapkit.corekit.multidict import OrderedMultiDict

        exported = self.info().to_dict()
        self.assertIsInstance(exported, OrderedMultiDict)
        self.assertTrue(repr(exported).startswith("OrderedMultiDict([('nested', OrderedMultiDict(["))
        for how, clone in (('copy()', exported.copy()), ('deepcopy()', exported.deepcopy()),
                           ('copy.copy', copy.copy(exported)), ('copy.deepcopy', copy.deepcopy(exported)),
                           ('pickle', pickle.loads(pickle.dumps(exported)))):  # nosec: B301
            with self.subTest(how=how):
                self.assertIs(type(clone), type(exported))
                self.assertIs(type(clone['ordered']), type(exported['ordered']))
                self.assertFalse(clone != exported)
                self.assertTrue(clone == exported)

    def test_listvalues_hands_out_copies(self) -> None:
        from pcapkit.corekit.infoclass import MultiInfo, OrderedMultiInfo

        for cls in (MultiInfo, OrderedMultiInfo):
            with self.subTest(cls=cls.__name__):
                info = cls(PAIRS)
                self.assertEqual(list(info.listvalues()), [[1, 3], [2]])
                next(iter(info.listvalues())).append(99)
                self.assertEqual(info.getlist('a'), [1, 3])
                self.assertEqual(list(info.items(multi=True)), list(cls(PAIRS).items(multi=True)))


class InfoFinalisationTests(unittest.TestCase):
    """What :class:`Info` stores, exports and restores."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_finalised_info_holds_no_mutable_multi_mapping(self) -> None:
        from pcapkit.corekit.infoclass import Info, MultiInfo, OrderedMultiInfo
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict

        source = OrderedMultiDict(PAIRS)
        info = Info.from_dict({'ordered': source, 'grouped': MultiDict(PAIRS), 'n': 1})
        self.assertIs(type(info.ordered), OrderedMultiInfo)
        self.assertIs(type(info.grouped), MultiInfo)
        self.assertEqual(list(info.ordered.items(multi=True)), PAIRS)

        # The parser's mapping is copied, so editing it afterwards does not reach the info.
        source.add('z', 9)
        self.assertEqual(list(info.ordered.items(multi=True)), PAIRS)

        # So is a value added through a MultiDict, i.e. as a repeated key.
        info.__update__(OrderedMultiDict([('ordered', OrderedMultiDict([('c', 4)]))]))
        self.assertEqual([type(value) for key, value in info.items(multi=True) if key == 'ordered'],
                         [OrderedMultiInfo, OrderedMultiInfo])

    def test_to_dict_returns_a_plain_ordered_multi_dict_at_every_level(self) -> None:
        from pcapkit.corekit.infoclass import Info, _OrderedMultiDict
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict

        info = Info.from_dict(OrderedMultiDict([
            ('nested', Info(x=1)), ('ordered', OrderedMultiDict(PAIRS)), ('grouped', MultiDict(PAIRS)),
            ('nested', Info(x=2)),
        ]))
        exported = info.to_dict()
        self.assertIs(type(exported), _OrderedMultiDict)
        self.assertIsInstance(exported, OrderedMultiDict)
        self.assertEqual([key for key, _ in exported.items(multi=True)], ['nested', 'ordered', 'grouped', 'nested'])
        self.assertEqual([type(value) for _, value in exported.items(multi=True)],
                         [_OrderedMultiDict, _OrderedMultiDict, MultiDict, _OrderedMultiDict])
        self.assertEqual([value['x'] for value in exported.getlist('nested')], [1, 2])
        self.assertEqual(list(exported['ordered'].items(multi=True)), PAIRS)

        # The export is a copy the caller may edit.
        exported['ordered'].add('z', 9)
        self.assertEqual(list(info.ordered.items(multi=True)), PAIRS)

    def test_from_dict_restores_the_info_types(self) -> None:
        from pcapkit.corekit.infoclass import Info, MultiInfo, OrderedMultiInfo, info_final
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict

        @info_final
        class Leaf(Info):
            """A nested model."""

            x: int

        @info_final
        class Node(Info):
            """A model holding both kinds of option list."""

            leaf: Leaf
            ordered: OrderedMultiInfo
            grouped: MultiInfo

        info = Node(leaf=Leaf(x=1), ordered=OrderedMultiDict(PAIRS), grouped=MultiDict(PAIRS))
        rebuilt = Node.from_dict(info.to_dict())
        self.assertEqual(rebuilt, info)
        self.assertEqual([type(value) for _, value in rebuilt.items(multi=True)], [Leaf, OrderedMultiInfo, MultiInfo])
        self.assertEqual(canonical(rebuilt.to_dict()), canonical(info.to_dict()))

    def test_from_dict_restores_an_annotated_subclass(self) -> None:
        """HTTP/2 ``Settings`` comes back as itself, last value wins and all."""
        from pcapkit.const.http.setting import Setting
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.application.httpv2 import Settings, SettingsFrame

        pairs = [(Setting.ENABLE_PUSH, 1), (Setting.ENABLE_PUSH, 0)]
        frame = SettingsFrame.from_dict({'settings': OrderedMultiDict(pairs)})
        self.assertIs(type(frame.settings), Settings)
        self.assertEqual(frame.settings[Setting.ENABLE_PUSH], 0)

        exported = frame.to_dict()
        self.assertIsInstance(exported['settings'], OrderedMultiDict)
        self.assertNotIsInstance(exported['settings'], Settings)
        rebuilt = SettingsFrame.from_dict(exported)
        self.assertIs(type(rebuilt.settings), Settings)
        self.assertEqual(list(rebuilt.settings.items(multi=True)), pairs)

    def test_parsed_options_are_frozen_and_rebuild_from_either_form(self) -> None:
        from pcapkit.corekit.infoclass import OrderedMultiInfo
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.transport.tcp import TCP

        # MSS 1460, NOP, NOP, SACK-permitted: a 28-octet header.
        options = bytes.fromhex('020405b4' '0101' '0402')
        header = struct.pack('!HHIIBBHHH', 1, 2, 0, 0, ((20 + len(options)) // 4) << 4, 0x02, 1024, 0, 0)
        raw = header + options
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            tcp = TCP(raw, len(raw))
            self.assertIs(type(tcp.info.options), OrderedMultiInfo)
            self.assertIsInstance(tcp.info.to_dict()['options'], OrderedMultiDict)
            self.assertNotIsInstance(tcp.info.to_dict()['options'], OrderedMultiInfo)
            self.assertEqual(TCP.from_data(tcp.info).data, raw)
            self.assertEqual(TCP.from_data(tcp.info.to_dict()).data, raw)
            self.assertEqual(type(tcp.info).from_dict(tcp.info.to_dict()), tcp.info)


if __name__ == '__main__':
    unittest.main()
