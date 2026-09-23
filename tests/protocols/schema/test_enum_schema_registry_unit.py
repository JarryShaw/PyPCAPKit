"""Regression tests for GitHub issue #555.

:class:`~pcapkit.protocols.schema.schema.EnumSchema`'s :attr:`registry` is a
:class:`collections.defaultdict`-backed mapping of enumeration codes to schema
classes. Reading it with a bare ``registry[code]`` for a code nobody registered
used to *insert* that code -- with whatever the default factory produced -- the
same defect fixed at the protocol layer's ``__proto__`` family by GitHub issues
#421 and #425/#428. These tests cover both the auto-created
:attr:`EnumSchema.__enum__` (the shape used by
e.g. :class:`pcapkit.protocols.schema.transport.tcp.Option`) and a manually
seeded one declared directly in a subclass's own class body (the shape used by
e.g. :class:`pcapkit.protocols.schema.misc.pcapng.Option`'s outer, namespaced
mapping).
"""
from __future__ import annotations

import collections
import enum
import importlib.util
import unittest
import warnings

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EnumSchemaRegistryRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_lookup_miss_on_auto_created_registry_does_not_grow_it(self) -> None:
        """A miss on an auto-created ``__enum__`` must not be retained.

        :class:`EnumSchema` subclasses that never assign :attr:`__enum__`
        themselves get one built by :meth:`EnumSchema.__init_subclass__` --
        the shape used by e.g.
        :class:`pcapkit.protocols.schema.transport.tcp.Option`. A bare
        ``registry[code]`` for an unregistered ``code`` must keep returning
        the default schema without inserting ``code``.
        """
        from pcapkit.protocols.schema.schema import EnumSchema

        class Code(enum.IntEnum):
            registered = 1
            unassigned = 2

        class DefaultSchema:
            """Stand-in for the fallback schema."""

        class BaseSchema(EnumSchema[Code]):
            __default__ = lambda: DefaultSchema  # noqa: E731

        class RegisteredSchema(BaseSchema, code=Code.registered):
            pass

        self.assertNotIn(Code.unassigned, BaseSchema.registry)
        before = len(BaseSchema.registry)

        # the miss: a bare subscript, exactly as every schema-layer call site
        # (e.g. ``Option.registry[type]``) performs it
        result = BaseSchema.registry[Code.unassigned]

        # the fallback is preserved -- this is not a narrowing to "raise on miss"
        self.assertIs(result, DefaultSchema)

        # the miss must not be retained
        self.assertNotIn(Code.unassigned, BaseSchema.registry)
        self.assertEqual(len(BaseSchema.registry), before)

        # a second, independent miss confirms it is not a one-shot fluke
        self.assertIs(BaseSchema.registry[Code.unassigned], DefaultSchema)
        self.assertNotIn(Code.unassigned, BaseSchema.registry)

        # the registered code is unaffected by any of the above
        self.assertIs(BaseSchema.registry[Code.registered], RegisteredSchema)

    def test_lookup_miss_on_manually_declared_registry_does_not_grow_it(self) -> None:
        """A miss on a manually-declared ``__enum__`` must not be retained.

        A subclass may assign :attr:`__enum__` itself, as a plain
        :class:`collections.defaultdict`, in its own class body -- the shape
        used by e.g. :class:`pcapkit.protocols.schema.misc.pcapng.Option`'s
        outer, namespaced mapping and
        :class:`pcapkit.protocols.schema.transport.tcp.MPTCP`. This must be
        just as retention-safe as the auto-created case, even though the
        object was never touched by :meth:`EnumSchema.__init_subclass__`'s
        creation branch.
        """
        from pcapkit.protocols.schema.schema import EnumSchema

        class Code(enum.IntEnum):
            registered = 1
            unassigned = 2

        class DefaultSchema:
            """Stand-in for the fallback schema."""

        class ManualSchema(EnumSchema[Code]):
            # declared directly, bypassing the auto-creation branch in
            # ``EnumSchema.__init_subclass__`` -- pre-seeded with the
            # registered entry, just like a real protocol's schema module
            # would seed namespace defaults in its class body
            __enum__ = collections.defaultdict(lambda: DefaultSchema)

        class RegisteredSchema(ManualSchema, code=Code.registered):
            pass

        self.assertNotIn(Code.unassigned, ManualSchema.registry)
        before = len(ManualSchema.registry)

        result = ManualSchema.registry[Code.unassigned]

        self.assertIs(result, DefaultSchema)
        self.assertNotIn(Code.unassigned, ManualSchema.registry)
        self.assertEqual(len(ManualSchema.registry), before)
        self.assertIs(ManualSchema.registry[Code.registered], RegisteredSchema)

    def test_registry_identity_is_stable_across_accesses(self) -> None:
        """``.registry`` keeps returning the *same* object across accesses.

        The retention fix must not swap in a fresh wrapper on every read --
        :class:`_EnumRegistry` is the one object stored on :attr:`__enum__`,
        exactly as a plain :class:`collections.defaultdict` would have been,
        so ``is``-identity across the class-level accessor, the instance-level
        accessor and a fresh instance all hold.
        """
        from pcapkit.protocols.schema.schema import EnumSchema

        class Code(enum.IntEnum):
            one = 1

        class IdentitySchema(EnumSchema[Code]):
            pass

        self.assertIs(IdentitySchema.registry, IdentitySchema.registry)
        self.assertIs(IdentitySchema().registry, IdentitySchema.registry)

    def test_real_tcp_option_schema_registry_does_not_leak_on_miss(self) -> None:
        """The exact reproduction from GitHub issue #555.

        ``OptionNumber(156)`` is unassigned in
        :class:`pcapkit.const.tcp.option.Option`, so nothing registers it
        against :class:`pcapkit.protocols.schema.transport.tcp.Option`. A
        single bare-subscript read must not make it appear registered
        afterwards.
        """
        from pcapkit.const.tcp.option import Option as OptionNumber
        from pcapkit.protocols.schema.transport.tcp import Option, UnassignedOption

        probe = OptionNumber(156)
        self.assertNotIn(probe, Option.registry)

        schema = Option.registry[probe]

        self.assertIs(schema, UnassignedOption)
        self.assertNotIn(probe, Option.registry)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EnumSchemaRegistryOverwriteTests(unittest.TestCase):
    """The schema half of a registration reports an overwrite.

    Every public registrar in :mod:`pcapkit.foundation.registry.protocols` that
    takes a ``schema`` registers two halves of one binding: a parser class,
    through e.g. :meth:`~pcapkit.protocols.internet.ipv4.IPv4.register_option`,
    and a schema class, through :meth:`EnumSchema.register`. The parser half has
    warned on an overwrite for as long as it has existed; the schema half
    assigned bare. So one ``register_ipv4_option`` call replacing a built-in
    named the parser it displaced and said nothing about the schema -- half a
    report for one call.

    The declaration path is covered as well, because ``class MyOption(Option,
    code=...)`` reaches :attr:`EnumSchema.__enum__` without any call to
    :meth:`register`; guarding only the method would leave it silent.

    Generalises the guard GitHub issue #675 added to ``register_protocol`` in
    #681. The condition here is presence alone, as the code-keyed parser
    registries use, rather than #681's "present *and* a different class" -- that
    narrower form is licensed by a key *derived* from the value, which this
    registry's caller-supplied ``code`` is not.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _guard_registry(self, registry, key) -> None:
        """Restore ``key`` in ``registry`` on teardown, absence included.

        Mirrors the helper of the same name in
        ``tests/foundation/registry/test_protocols.py``. Every registry in this
        package is process-global and order-dependent, so a test that writes into
        one has to put back exactly what it found -- and a key that was *absent*
        has no value to restore, so writing one back would leave a stray entry
        for the next test in the process to inherit. That is the class of defect
        #674/#686 was about, hence the sentinel and the ``pop``.

        ``tests/_support.py`` deliberately offers nothing for this: its own
        ``restore_modules`` docstring notes that it restores which module object a
        name refers to, not the *contents* of one, so a registry mutated in place
        rebinds nothing and outlives the test unless undone here.

        """
        missing = object()
        previous = registry.get(key, missing)

        def restore() -> None:
            if previous is missing:
                registry.pop(key, None)
            else:
                registry[key] = previous

        self.addCleanup(restore)

    @staticmethod
    def _registry_warnings(caught, category) -> 'list[str]':
        """The messages of the captured warnings that are of ``category``.

        Filtering by category matters: the parse and import paths raise other
        warning types, and a bare count of everything captured would make an
        assertion about "no warning" pass or fail for unrelated reasons.

        """
        return [str(item.message) for item in caught
                if issubclass(item.category, category)]

    @staticmethod
    def _base_schema():
        """A fresh ``EnumSchema`` hierarchy with its own registry.

        Locally declared, so nothing here touches a process-global registry --
        :meth:`EnumSchema.__init_subclass__` builds a new ``__enum__`` for the
        first subclass in a chain.

        """
        from pcapkit.protocols.schema.schema import EnumSchema

        class Code(enum.IntEnum):
            one = 1
            two = 2
            three = 3

        class DefaultSchema:
            """Stand-in for the fallback schema."""

        class BaseSchema(EnumSchema[Code]):
            __default__ = lambda: DefaultSchema  # noqa: E731

        return Code, BaseSchema

    def test_register_warns_when_a_code_is_already_taken(self) -> None:
        """The schema half now reports what it displaced.

        Before this change the body was a bare ``cls.__enum__[code] = schema``:
        the replacement happened, the read-side fell back to the new class, and
        nothing connected that to the registration which caused it.

        """
        from pcapkit.utilities.warnings import RegistryWarning

        Code, BaseSchema = self._base_schema()

        class Incumbent(BaseSchema, code=Code.one):
            pass

        class Replacement(BaseSchema):
            pass

        # The premise: two *different* schemas, and the code really is taken.
        self.assertIsNot(Incumbent, Replacement)
        self.assertIs(BaseSchema.registry[Code.one], Incumbent)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            BaseSchema.register(Code.one, Replacement)

        # The overwrite still happens. This reports the collision, it does not
        # refuse it -- refusing would break the documented ability to replace a
        # built-in schema.
        self.assertIs(BaseSchema.registry[Code.one], Replacement)

        messages = self._registry_warnings(caught, RegistryWarning)
        self.assertEqual(len(messages), 1)

        # Naming both is the point: 'schema 1 already registered' on its own does
        # not say which schema was lost. Ordering asserted too, so the message
        # cannot name them the wrong way round.
        self.assertIn(repr(Incumbent), messages[0])
        self.assertIn(repr(Replacement), messages[0])
        self.assertLess(messages[0].index(repr(Incumbent)),
                        messages[0].index(repr(Replacement)))

    def test_register_stays_quiet_for_a_free_code(self) -> None:
        """A first registration displaces nothing and must not warn.

        Pins the other half of the guard. A registrar that warned here would
        make every legitimate ``register_*`` call noisy, and the wholesale
        ``RegistryWarning`` filter that invites is what would then hide a real
        collision.

        """
        from pcapkit.utilities.warnings import RegistryWarning

        Code, BaseSchema = self._base_schema()

        class Replacement(BaseSchema):
            pass

        self.assertNotIn(Code.two, BaseSchema.registry)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            BaseSchema.register(Code.two, Replacement)

        self.assertIs(BaseSchema.registry[Code.two], Replacement)
        self.assertEqual(self._registry_warnings(caught, RegistryWarning), [])

    def test_a_lookup_miss_still_does_not_make_a_later_register_warn(self) -> None:
        """The #555 retention fix is what makes a presence-only guard safe here.

        On a plain :class:`collections.defaultdict` a bare ``registry[code]`` for
        an unregistered code inserted the default, so parsing one packet carrying
        an unknown code would make the next legitimate registration for that code
        warn about an entry no caller ever asked for. This asserts the two fixes
        compose: read a miss, then register that code, and stay silent.

        """
        from pcapkit.utilities.warnings import RegistryWarning

        Code, BaseSchema = self._base_schema()

        class Replacement(BaseSchema):
            pass

        # The miss, exactly as every schema-layer call site performs it.
        BaseSchema.registry[Code.three]
        self.assertNotIn(Code.three, BaseSchema.registry)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            BaseSchema.register(Code.three, Replacement)

        self.assertEqual(self._registry_warnings(caught, RegistryWarning), [])

    def test_declaring_a_subclass_over_a_taken_code_warns(self) -> None:
        """The declaration path reaches the registry without calling ``register``.

        :meth:`EnumSchema.__init_subclass__` assigns ``cls.__enum__[code]``
        directly, so a guard on :meth:`register` alone would leave
        ``class MyOption(Option, code=...)`` -- the documented way to add a schema
        -- silently displacing a built-in.

        """
        from pcapkit.utilities.warnings import RegistryWarning

        Code, BaseSchema = self._base_schema()

        class Incumbent(BaseSchema, code=Code.one):
            pass

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')

            class Replacement(BaseSchema, code=Code.one):
                pass

        self.assertIs(BaseSchema.registry[Code.one], Replacement)

        messages = self._registry_warnings(caught, RegistryWarning)
        self.assertEqual(len(messages), 1)
        self.assertIn(repr(Incumbent), messages[0])
        self.assertIn(repr(Replacement), messages[0])

    def test_declaring_a_subclass_with_fresh_codes_stays_quiet(self) -> None:
        """Every ordinary schema declaration must stay silent.

        This is the case that governs whether ``import pcapkit`` is noisy: 326
        registry writes happen during import, and a guard that warned on a
        first-time declaration would fire on the great majority of them. Covers
        the iterable form of ``code`` as well, which is the branch that shares
        the guard.

        """
        from pcapkit.utilities.warnings import RegistryWarning

        Code, BaseSchema = self._base_schema()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')

            class Single(BaseSchema, code=Code.one):
                pass

            class Several(BaseSchema, code=(Code.two, Code.three)):
                pass

        self.assertEqual(self._registry_warnings(caught, RegistryWarning), [])

        # The iterable branch was restructured into a single loop to carry the
        # guard once; assert it still registers every code it was given.
        self.assertIs(BaseSchema.registry[Code.one], Single)
        self.assertIs(BaseSchema.registry[Code.two], Several)
        self.assertIs(BaseSchema.registry[Code.three], Several)

    def test_the_guard_holds_on_a_real_shipped_registry(self) -> None:
        """The same thing on :class:`...schema.transport.tcp.Option`.

        The tests above build a local hierarchy, which proves the mechanism but
        not that it is reachable on a registry the package actually ships. This
        one displaces a real built-in schema and puts it back.

        """
        from pcapkit.const.tcp.option import Option as OptionNumber
        from pcapkit.protocols.schema.transport.tcp import Option
        from pcapkit.utilities.warnings import RegistryWarning

        code = OptionNumber.Maximum_Segment_Size
        incumbent = Option.registry[code]

        # Asserted rather than assumed: if this code were somehow unregistered,
        # the warning below would not fire and the test would be vacuous.
        self.assertIn(code, Option.registry)
        self._guard_registry(Option.registry, code)

        class Replacement(Option):
            pass

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            Option.register(code, Replacement)

        self.assertIs(Option.registry[code], Replacement)

        messages = self._registry_warnings(caught, RegistryWarning)
        self.assertEqual(len(messages), 1)
        self.assertIn(repr(incumbent), messages[0])
        self.assertIn(repr(Replacement), messages[0])
