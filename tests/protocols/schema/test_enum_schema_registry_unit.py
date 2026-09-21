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
