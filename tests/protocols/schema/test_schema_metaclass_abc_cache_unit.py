from __future__ import annotations

import importlib.util
import unittest
from collections import ChainMap
from collections.abc import Mapping

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SchemaMetaAbcCacheTests(unittest.TestCase):
    """Regression tests for GitHub issue #439.

    ``SchemaMeta.__new__`` (:mod:`pcapkit.protocols.schema.schema`) used to bypass
    :meth:`abc.ABCMeta.__new__` on Python < 3.11, to dodge a ``namespace=`` class
    keyword collision described in that module. Bypassing it also skipped
    :meth:`abc.ABCMeta.__new__`'s call to ``abc._abc_init(cls)``, so no
    :class:`~pcapkit.protocols.schema.schema.Schema` subclass ever got its own
    ``_abc_impl``. Attribute lookup then fell through the MRO to
    :class:`collections.abc.Mapping`'s ``_abc_impl`` -- the one ABC in the chain
    still built through an untouched ``ABCMeta.__new__`` -- so *every* schema
    class was reading and writing the same ``isinstance`` cache that
    ``collections.abc.Mapping`` itself uses.

    :class:`dict` is a registered virtual subclass of ``Mapping``, so asking
    ``isinstance(x, Mapping)`` for a plain :class:`dict` caches a positive answer
    keyed on ``dict`` -- and with the cache shared, ``isinstance(x, Schema)`` for
    that same ``dict`` then reads the *same* cache entry straight back, without
    ever running :class:`Schema`'s real subclass check.

    The corruption runs **both ways**, which is why two tests below ask the two
    questions in opposite orders rather than one test asking them in the
    "obvious" order. Asking ``Schema`` *first* computes a fresh (correct)
    ``False`` for ``dict`` -- but caches it in the shared object's *negative*
    cache, and since that object is ``Mapping``'s own, a plain ``dict`` then
    stops answering ``isinstance(x, Mapping)`` at all, anywhere in the process,
    until the cache token advances. Measured directly against the pre-fix code
    (not merely inferred): asking ``isinstance({}, Schema)`` and then
    ``isinstance({}, Mapping)`` returns ``False`` for the second question too.
    This is the more dangerous direction, since it breaks code with no
    connection to schemas at all -- ordinary library code such as
    :meth:`Info.from_dict <pcapkit.corekit.infoclass.Info.from_dict>` asking
    ``isinstance(dict_, (dict, collections.abc.Mapping))`` is enough to trigger
    either direction, which is why the defect only ever showed up in the full
    suite and not in a single test file run alone.

    """

    def setUp(self) -> None:
        # Fresh :mod:`pcapkit` classes *and* a freshly reset
        # :mod:`collections.abc` cache -- :func:`purge_modules` does both, and
        # both matter: a stale positive cache entry left over from an earlier
        # test in the same process would make the very first assertion below
        # true for the wrong reason.
        purge_modules(['pcapkit'])

    def tearDown(self) -> None:
        # A couple of tests below deliberately poison collections.abc's shared
        # caches (that is the point of them) -- reset them again on the way
        # out, so nothing outside this module ever reads what was left behind.
        purge_modules(['pcapkit'])

    def test_a_plain_dict_is_not_a_schema_after_mapping_is_asked_first(self) -> None:
        """The order-sensitive reproduction from GitHub issue #439 itself.

        Ask ``isinstance({}, Mapping)`` *before* ``isinstance({}, Schema)`` --
        reversing that order is the single easiest way to make this test pass on
        the broken code, so the ordering here is deliberate and load-bearing,
        not incidental.

        """
        # Ask Mapping FIRST. On the broken code this is what poisons the shared
        # cache; on the fixed code it is a completely ordinary, unrelated
        # question that leaves Schema's own cache alone.
        self.assertTrue(isinstance({}, Mapping), 'sanity: dict really is a Mapping')

        from pcapkit.protocols.schema.misc.pcapng import EndRecord, IPv4Record
        from pcapkit.protocols.schema.schema import Schema

        # THEN ask Schema. A plain dict must not test True as a Schema, nor as
        # any concrete Schema subclass, no matter what was asked about Mapping
        # a moment ago.
        self.assertFalse(isinstance({}, Schema))
        self.assertFalse(isinstance({}, EndRecord))
        self.assertFalse(isinstance({}, IPv4Record))

    def test_asking_schema_first_does_not_break_mapping_for_a_plain_dict(self) -> None:
        """The reverse direction: ``Schema`` first must not corrupt ``Mapping``.

        Before this class had its own ``_abc_impl``, asking ``isinstance({},
        Schema)`` computed a fresh (correct) ``False`` for ``dict`` and cached
        it in the *negative* cache of the object it shared with
        :class:`collections.abc.Mapping` -- after which a plain :class:`dict`
        stopped answering ``isinstance(x, Mapping)`` at all. This is the
        direction most likely to be missed: it has nothing to do with
        ``Schema`` being asked about a dict that should not match it, and
        everything to do with an *unrelated* stdlib question breaking as a
        side effect.

        """
        from pcapkit.protocols.schema.schema import Schema

        # Ask Schema FIRST this time -- the opposite order from the test above.
        self.assertFalse(isinstance({}, Schema))

        # THEN ask Mapping. A plain dict must still be reported as one.
        self.assertTrue(isinstance({}, Mapping))

    def test_schema_subclasses_have_their_own_abc_impl(self) -> None:
        """Every schema class gets its own ABCMeta registry/cache triple.

        This is the mechanism behind the test above, pinned directly: a
        :class:`Schema` subclass's ``_abc_impl`` must not be the same object as
        another subclass's, or as :class:`Schema`'s own -- and, since the
        defect's actual shape was falling through to :class:`collections.abc.
        Mapping`'s, not that one either.

        """
        from pcapkit.protocols.schema.misc.pcapng import EndRecord, IPv4Record
        from pcapkit.protocols.schema.schema import Schema

        self.assertIsNotNone(Schema._abc_impl)
        self.assertIsNot(EndRecord._abc_impl, Schema._abc_impl)
        self.assertIsNot(IPv4Record._abc_impl, Schema._abc_impl)
        self.assertIsNot(EndRecord._abc_impl, IPv4Record._abc_impl)
        self.assertIsNot(Schema._abc_impl, Mapping._abc_impl)

    def test_a_real_instance_still_isinstance_of_its_own_class(self) -> None:
        """The fix must not overcorrect into every schema object testing False.

        Giving each class its own ``_abc_impl`` must not disturb the ordinary
        case: a real instance of a schema class is still that class, even right
        after the same ``Mapping``-first probe used above.

        """
        self.assertTrue(isinstance({}, Mapping))

        from pcapkit.protocols.schema.misc.pcapng import EndRecord

        # ``__new__`` rather than the normal constructor, matching how this was
        # verified in the issue itself -- EndRecord's ``__init__`` wants field
        # values this test has no reason to know.
        instance = EndRecord.__new__(EndRecord)
        self.assertIsInstance(instance, EndRecord)
        self.assertIsInstance(instance, Mapping)
        self.assertNotIsInstance({}, EndRecord)

    @staticmethod
    def _make_shared_hierarchy() -> 'tuple[type, type]':
        """A throwaway ABC pair reproducing #439's exact shape, without pcapkit.

        Neither class is given its own ``_abc_impl``, so attribute lookup
        falls through the MRO to :class:`collections.abc.Mapping`'s -- exactly
        the shape ``SchemaMeta.__new__`` used to produce on Python < 3.11,
        confirmed below rather than assumed. Building this on plain
        ``abc.ABCMeta`` rather than ``SchemaMeta`` keeps the two tests below
        about ``abc.ABCMeta`` in general, not about this library's fix.

        """
        class _Shared(Mapping):  # pylint: disable=abstract-method
            def __getitem__(self, key: object) -> object:
                raise KeyError(key)

            def __iter__(self):
                return iter(())

            def __len__(self) -> int:
                return 0

        class _SharedChild(_Shared):
            pass

        del _Shared._abc_impl
        del _SharedChild._abc_impl
        return _Shared, _SharedChild

    def test_probing_the_same_exact_type_reproduces_439s_shape(self) -> None:
        """The general mechanism, generalised beyond :class:`dict` and ``Schema``.

        ``collections.ChainMap`` is a *separately* registered
        :class:`~collections.abc.Mapping` implementation (registered
        directly, not via real inheritance from :class:`dict`), so probing
        with it and then checking the *same* exact type exercises the same
        registered-virtual-subclass path :class:`dict` does in the real bug --
        demonstrating that #439's shape was never specific to ``dict``, only
        to *asking about the same exact type twice*.

        """
        _Shared, _SharedChild = self._make_shared_hierarchy()
        self.assertIs(_Shared._abc_impl, Mapping._abc_impl)
        self.assertIs(_SharedChild._abc_impl, Mapping._abc_impl)

        # Probe and check the SAME exact type (ChainMap, both times).
        self.assertTrue(isinstance(ChainMap(), Mapping))
        self.assertTrue(isinstance(ChainMap(), _SharedChild))

    def test_probing_a_different_exact_type_gives_a_false_negative(self) -> None:
        """A pitfall in reproducing #439: the cache is keyed by *exact* type.

        ``abc.ABCMeta.__subclasscheck__`` (see ``Lib/_py_abc.py``, which
        mirrors the C ``_abc`` accelerator) caches its answer under
        ``subclass`` -- the *exact* type asked about -- whatever rule actually
        matched. So probing with one type and then checking a *different*
        type is not a weaker version of the reproduction above, it is not a
        reproduction at all: the second question is a cache miss regardless of
        whether #439 is fixed, and comes back looking clean either way.

        A plain ``dict`` *subclass* is the probe type here, deliberately, to
        pin exactly the trap described in this issue: it has a genuine
        ``Mapping`` tie (``isinstance(x, Mapping)`` is ``True`` for it) but
        checking a *different* exact type (``ChainMap``) afterwards is
        unaffected by that -- "has a Mapping tie" is not "populates the cache
        entry the next question will read". A regression test built by
        probing with a dict subclass and asserting about anything else would
        not have caught #439; :meth:`test_probing_the_same_exact_type_reproduces_439s_shape`
        above is what actually exercises the shared cache, and it does so by
        keeping the exact type identical across both questions.

        """
        _Shared, _SharedChild = self._make_shared_hierarchy()
        self.assertIs(_SharedChild._abc_impl, Mapping._abc_impl)

        class _DictSubclass(dict):
            pass

        # Probe with one exact type (a dict subclass)...
        self.assertTrue(isinstance(_DictSubclass(), Mapping))
        # ...and check a *different* exact type (ChainMap, never asked about
        # in this process before). Clean -- not because the hierarchy above
        # is not broken (it is, by construction), but because the two
        # questions never touch the same cache entry.
        self.assertFalse(isinstance(ChainMap(), _SharedChild))
        self.assertFalse(isinstance(ChainMap(), _Shared))

    def test_the_pcapng_1248_symptom_no_longer_reproduces(self) -> None:
        """The user-facing payoff: a real ``isinstance`` call site, not a probe.

        :meth:`NameResolutionBlock.post_process
        <pcapkit.protocols.schema.misc.pcapng.NameResolutionBlock.post_process>`
        asks ``isinstance(record, (IPv4Record, IPv6Record))`` at
        :file:`pcapkit/protocols/schema/misc/pcapng.py:1248` and then reads
        ``record.names``. Before #439 was fixed, every schema class shared one
        ``_abc_impl``, so that question answered ``True`` for the block's
        *terminating* ``EndRecord`` -- which has no ``names`` -- provided
        *anything at all* had already asked whether that same ``EndRecord``
        instance was a :class:`~pcapkit.protocols.schema.schema.Schema`.

        That is a lower bar than it sounds: ``isinstance(record, Schema)`` is
        genuinely, unconditionally true for any real schema instance, via
        ordinary inheritance rather than any cache -- and every schema class
        asks it routinely (:meth:`Schema.pack`, elsewhere in this module, does
        exactly that). Measured directly (not merely inferred): on the broken
        code, asking ``isinstance(record, Schema)`` first -- correctly true,
        cached against the object every schema class shared -- made the next,
        unrelated question, ``isinstance(record, (IPv4Record, IPv6Record))``,
        answer ``True`` too, for an ``EndRecord`` that is neither. This is a
        *more* direct reproduction of the real call site than probing with a
        plain ``dict`` first (as the other tests in this class do): it needs
        no ``Mapping``/``dict`` involvement at all, only two ordinary
        ``isinstance`` questions about the very code under test, in the order
        real code already asks them.

        """
        from pcapkit.protocols.schema.misc.pcapng import EndRecord, IPv4Record, IPv6Record
        from pcapkit.protocols.schema.schema import Schema

        record = EndRecord.__new__(EndRecord)
        self.assertIs(type(record), EndRecord)

        # Ask the question every schema class asks routinely -- correctly
        # True, and on the broken code this is what poisoned the shared cache
        # for this exact object.
        self.assertTrue(isinstance(record, Schema))

        self.assertFalse(
            isinstance(record, (IPv4Record, IPv6Record)),
            "a terminating EndRecord must not test as an IPv4Record/IPv6Record -- "
            "if it does, NameResolutionBlock.post_process reads .names off a "
            "record that has none, which is the AttributeError #439 caused"
        )


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SchemaMetaReservedClassKwargsTests(unittest.TestCase):
    """Regression tests for the reserved-class-keyword guard added with #439.

    Renaming ``namespace=`` to ``ns=`` (see :mod:`pcapkit.protocols.schema.misc.
    pcapng`) fixed the one collision that was actually in use, but the
    collision class is not specific to ``namespace``: any class keyword
    spelled ``mcls``, ``name``, ``bases`` or ``namespace`` collides with a
    same-named parameter of :meth:`abc.ABCMeta.__new__` (on Python < 3.11 for
    the first three, on every version for the fourth -- see
    :attr:`~pcapkit.protocols.schema.schema.SchemaMeta._RESERVED_CLASS_KWARGS`
    for the precise reasoning), and ``cls`` collides with the implicit
    ``__init_subclass__`` classmethod binding on every version. Without a
    guard, the *next* accidental use of one of these names resurfaces as an
    opaque ``TypeError: ...__new__() got multiple values for argument '...'``
    several frames away, exactly the class of confusion that produced the
    "for unknown reason" comment #439 started from. These tests pin that the
    guard actually fires, names the offending keyword, and that ordinary class
    keywords are unaffected.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_each_reserved_keyword_raises_a_named_schema_error(self) -> None:
        """Every reserved keyword raises :exc:`SchemaError`, not a bare TypeError.

        A bare ``TypeError`` here would violate the house rule that in-library
        exceptions come from :mod:`pcapkit.utilities.exceptions` -- and would
        also be indistinguishable from the very opaque failure this guard
        exists to replace.

        """
        from pcapkit.protocols.schema.schema import Schema, SchemaMeta
        from pcapkit.utilities.exceptions import SchemaError

        for keyword in sorted(SchemaMeta._RESERVED_CLASS_KWARGS):
            with self.subTest(keyword=keyword):
                with self.assertRaises(SchemaError) as caught:
                    type(f'Reserved_{keyword}', (Schema,), {}, **{keyword: 'x'})
                self.assertIn(keyword, str(caught.exception))

    def test_an_ordinary_class_keyword_is_unaffected(self) -> None:
        """The guard must not reject a class keyword that does not collide.

        ``code=`` is the other class keyword :class:`Schema` subclasses use
        (see :meth:`EnumSchema.__init_subclass__
        <pcapkit.protocols.schema.schema.EnumSchema.__init_subclass__>`), and
        it does not appear anywhere in
        :attr:`~pcapkit.protocols.schema.schema.SchemaMeta._RESERVED_CLASS_KWARGS`,
        so it must keep working exactly as before -- as must the renamed
        ``ns=`` keyword itself.

        """
        from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
        from pcapkit.protocols.schema.misc.pcapng import Option

        class _RenamedOption(Option, ns='opt', code=Enum_OptionType.opt_comment):
            pass

        self.assertEqual(_RenamedOption.__namespace__, 'opt')


if __name__ == '__main__':
    unittest.main()
