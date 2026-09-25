# -*- coding: utf-8 -*-
"""``@final`` is a runtime rule, not only a promise to the type checker.

:func:`typing.final` records ``__final__ = True`` on the class it decorates and
stops there -- the interpreter will still derive from it happily. Both
:func:`~pcapkit.corekit.infoclass.info_final` and
:func:`~pcapkit.protocols.schema.schema.schema_final` end by applying it, so
every finalised class in the library already carried the marker and nothing read
it. Issue #778 is the ruling that it should be read, and this module is what
pins the reading.

**Four answers, one per shape, and the differences are the ruling.** In the
maintainer's terms: ``@info_final`` implies ``@final``, and ``@final`` must not
be used without ``@info_final``.

==================================== ==========================================
Shape                                Answer
==================================== ==========================================
``@info_final``                      finalise, silent
``@info_final @final`` *and*         finalise, silent -- **order must not
``@final @info_final``               matter**
``@info_final`` twice                finalise once, **warn**
``@final`` alone                     **raise** -- marked final, never finalised
==================================== ==========================================

Deriving from a finalised class raises too, which is the part #778 asked for.
The rest of the table is what :class:`DecoratorCombinationTests` covers, and the
third and fourth rows are the two that are easy to conflate: both reach
:func:`info_final` with ``__final__`` already in the class's own ``__dict__``,
so only ``__finalised__`` -- which records *that function* having run -- can
tell "already finalised" from "merely marked". Keying the re-entry check on
``__final__`` instead made row two warn and skip the generation, and that is a
defect, not a style choice: the class came back with no generated ``__init__``
and construction failed with ``TypeError: 'int' object is not iterable`` on the
:class:`Info` side, and *silently returned bookkeeping attributes* on the
:class:`~pcapkit.protocols.schema.schema.Schema` side.

What the rule costs is nothing today and everything later, which is why it needs
tests rather than a measurement. Measured at ``110381b63``: of :class:`Info`'s
488 descendants 455 carry ``__final__`` in their own ``__dict__`` and **none is
subclassed**; of :class:`~pcapkit.protocols.schema.schema.Schema`'s 445, 408 do
and none is subclassed. So the raise cannot fire on any declaration in the tree
as it stands, and the only way to know it fires at all is to make it.

Three properties are easy to get subtly wrong, and each has a test here for the
*wrong* answer as much as the right one:

:meth:`OwnDictRuleTests`
    ``__final__`` and ``__finalised__`` are both ordinary class attributes, so
    both **inherit**. A ``getattr``/``hasattr`` check on either therefore reads a
    finalised ancestor's answer off every descendant, not just off the class that
    was finalised. The test builds the one shape where the difference is
    observable -- a subclass that already existed when its parent was finalised
    -- and pins that it may still be finalised in its own right. Since
    re-finalising only warns, getting this wrong is *silent*: the class comes
    back without its generated ``__init__`` rather than with an exception, which
    is why that test checks construction rather than the markers alone.

:meth:`DecoratorCombinationTests`
    The four rows above, both families, with ``@info_final @final`` and ``@final
    @info_final`` asserted to agree rather than merely each asserted to work --
    order-independence is the property that broke, so it is the property stated.

:meth:`AncestryWalkTests`
    The check walks the whole MRO rather than ``__bases__``, so a *grandchild*
    of a finalised class is refused too. Checking the direct bases alone would
    leave a one-line way round the rule.

:meth:`VersionPortabilityTests`
    ``typing.final`` only records ``__final__`` from Python 3.11 on, and 3.10 is
    in the CI matrix. A guard reading the dunder is therefore a silent no-op on
    3.10 unless ``final`` comes from :mod:`pcapkit.utilities.compat`, whose
    shim asks ``typing_extensions`` for it below 3.11. This is the test that
    would have caught that, and the one that fails first if the import is ever
    pointed back at :mod:`typing`.

"""
from __future__ import annotations

import enum
import importlib.util
import unittest
import warnings

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class InfoFinalEnforcementTests(unittest.TestCase):
    """Deriving from, and re-finalising, a finalised :class:`Info` class."""

    def test_subclassing_a_finalised_info_class_raises(self) -> None:
        """The declaration fails, rather than producing a broken subclass.

        A finalised class carries an ``__init__`` generated from the annotations
        that were visible when the decorator ran, so a subclass declaring a
        field of its own would inherit a constructor that cannot set it -- and
        would do so silently, which is what makes this worth refusing outright.

        """
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.utilities.exceptions import InfoError

        @info_final
        class Sealed(Info):
            x: int

        with self.assertRaises(InfoError) as caught:
            class Derived(Sealed):  # pylint: disable=unused-variable
                y: int

        message = str(caught.exception)
        self.assertIn('Derived', message)
        self.assertIn('Sealed', message)
        self.assertIn('final', message)

    def test_re_finalising_the_same_info_class_only_warns(self) -> None:
        """``@info_final @info_final class X(Info)`` warns and carries on.

        The ruling on #778, in the maintainer's words: a second application to
        the *same* class "should only warn", where a *subclass* of a finalised
        class raises. The distinction is that the duplicate is redundant rather
        than wrong -- the first application already generated the ``__init__``
        and the ``__builtin__`` set, so there is nothing to refuse and nothing
        to redo. What the guard must not do is hand back a half-built class, so
        the returned class is exercised here rather than merely identified.

        """
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.utilities.warnings import InfoWarning

        @info_final
        class Sealed(Info):
            x: int

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            again = info_final(Sealed)

        emitted = [record for record in caught if issubclass(record.category, InfoWarning)]
        self.assertEqual(len(emitted), 1, [str(record.message) for record in caught])
        self.assertIn('Sealed', str(emitted[0].message))
        self.assertIn('has been finalised', str(emitted[0].message))

        self.assertIs(again, Sealed)
        self.assertEqual(again(1).to_dict(), {'x': 1})

    def test_a_base_state_info_class_is_still_subclassable(self) -> None:
        """The line the check must not cross.

        :meth:`Info.__new__` finalises an undecorated class to
        :attr:`~pcapkit.corekit.infoclass.FinalisedState.BASE` on first
        instantiation, which generates the same ``__init__`` but deliberately
        does *not* apply ``final``. Those classes are the library's own
        intermediate bases and subclassing them is ordinary use, so the marker
        rather than the state is what the guard reads.

        """
        from pcapkit.corekit.infoclass import FinalisedState, Info, info_final

        class Intermediate(Info):
            x: int

        self.assertEqual(Intermediate(x=1).x, 1)
        self.assertEqual(Intermediate.__dict__.get('__finalised__'), FinalisedState.BASE)
        self.assertNotIn('__final__', Intermediate.__dict__)

        class Extended(Intermediate):
            y: int

        self.assertIs(info_final(Extended), Extended)
        self.assertEqual(Extended(1, 2).to_dict(), {'x': 1, 'y': 2})


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SchemaFinalEnforcementTests(unittest.TestCase):
    """The same rule on the :class:`Schema` side, which is a separate hook."""

    def test_subclassing_a_finalised_schema_raises(self) -> None:
        """:class:`Schema` does not descend from :class:`Info`.

        The two families share :class:`~pcapkit.corekit.infoclass.FinalisedState`
        and nothing else, so the guard has to exist twice or one of them goes
        unenforced.

        """
        from pcapkit.corekit.infoclass import Info
        from pcapkit.protocols.schema.schema import Schema, schema_final
        from pcapkit.utilities.exceptions import SchemaError

        self.assertFalse(issubclass(Schema, Info))

        @schema_final
        class Sealed(Schema):
            pass

        with self.assertRaises(SchemaError) as caught:
            class Derived(Sealed):  # pylint: disable=unused-variable
                pass

        message = str(caught.exception)
        self.assertIn('Derived', message)
        self.assertIn('Sealed', message)
        self.assertIn('final', message)

    def test_re_finalising_the_same_schema_only_warns(self) -> None:
        """As for :func:`info_final`, and with the schema-side warning."""
        from pcapkit.protocols.schema.schema import Schema, schema_final
        from pcapkit.utilities.warnings import SchemaWarning

        @schema_final
        class Sealed(Schema):
            pass

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            again = schema_final(Sealed)

        emitted = [record for record in caught if issubclass(record.category, SchemaWarning)]
        self.assertEqual(len(emitted), 1, [str(record.message) for record in caught])
        self.assertIn('Sealed', str(emitted[0].message))
        self.assertIn('has been finalised', str(emitted[0].message))

        self.assertIs(again, Sealed)
        self.assertEqual(again().to_dict(), {})

    def test_a_base_state_schema_is_still_subclassable(self) -> None:
        """The schema-side half of the line the check must not cross."""
        from pcapkit.corekit.infoclass import FinalisedState
        from pcapkit.protocols.schema.schema import Schema, schema_final

        class Intermediate(Schema):
            pass

        Intermediate()
        self.assertEqual(Intermediate.__dict__.get('__finalised__'), FinalisedState.BASE)
        self.assertNotIn('__final__', Intermediate.__dict__)

        class Extended(Intermediate):
            pass

        self.assertIs(schema_final(Extended), Extended)

    def test_a_refused_enum_schema_declaration_leaves_the_registry_alone(self) -> None:
        """A rejected class must not have displaced a registered schema first.

        :meth:`EnumSchema.__init_subclass__` writes ``cls`` into ``__enum__``
        for every ``code`` the declaration names, and the guard it inherits is
        what refuses the declaration. Were the base hook still called at the end
        of that method rather than at its start, the raise would discard the
        class object while leaving the registry pointing at it -- so a
        declaration that failed would still have overwritten a built-in schema.

        """
        from pcapkit.protocols.schema.schema import EnumSchema, schema_final
        from pcapkit.utilities.exceptions import SchemaError

        class Code(enum.IntEnum):
            one = 1
            two = 2

        @schema_final
        class Sealed(EnumSchema[Code], code=Code.one):
            pass

        before = dict(Sealed.__enum__)

        with self.assertRaises(SchemaError):
            class Derived(Sealed, code=Code.two):  # pylint: disable=unused-variable
                pass

        self.assertEqual(dict(Sealed.__enum__), before)
        self.assertNotIn(Code.two, before)

    def test_a_refused_pcapng_option_declaration_leaves_the_registry_alone(self) -> None:
        """The same guarantee, on the one in-tree hook that did not have it.

        :meth:`~pcapkit.protocols.schema.misc.pcapng.Option.__init_subclass__`
        overrides :class:`EnumSchema`'s hook and calls
        :meth:`~pcapkit.protocols.schema.misc.pcapng.Option.register` -- which
        writes ``cls`` into :attr:`~pcapkit.protocols.schema.misc.pcapng.Option.\
        __enum__` -- before calling ``super().__init_subclass__()``, which is
        where the guard that refuses to subclass a finalised schema actually
        lives. So a refused declaration still displaced a built-in option schema
        first, exactly the failure the test above pins for the generic
        :class:`EnumSchema` hook, and this pins the same guarantee for the one
        subclass override that had grown out of step with it. A dedicated
        namespace keeps this from touching the built-in ``opt`` registry at all.

        """
        from pcapkit.const.pcapng.option_type import \
            OptionType as Enum_OptionType  # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.schema.misc.pcapng import Option
        from pcapkit.protocols.schema.schema import schema_final
        from pcapkit.utilities.exceptions import SchemaError

        # ``opt_endofopt`` -- the enum's first member -- named explicitly rather
        # than found by scanning, since a fresh namespace starts as a copy of
        # ``'opt'`` and so has no registrations of its own to collide with.
        code = Enum_OptionType.opt_endofopt
        namespace = 'test_a_refused_pcapng_option_declaration_leaves_the_registry_alone'

        @schema_final
        class Sealed(Option, ns=namespace, code=code):
            pass

        before = dict(Option.registry[namespace])
        self.assertIs(before[code], Sealed)

        with self.assertRaises(SchemaError):
            class Derived(Sealed, ns=namespace, code=code):  # pylint: disable=unused-variable
                pass

        self.assertEqual(dict(Option.registry[namespace]), before)
        self.assertIs(Option.registry[namespace][code], Sealed)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OwnDictRuleTests(unittest.TestCase):
    """``__final__`` inherits, so the check reads each class's own namespace."""

    def test_a_descendant_that_predates_the_marker_may_still_be_finalised(self) -> None:
        """The shape that tells ``__dict__`` and ``getattr`` apart.

        Declaring the subclass *before* the parent is finalised is legal -- the
        guard runs at declaration time and there was nothing to object to then.
        That leaves a class which inherits ``__final__`` without ever having
        been finalised itself, and skipping it would skip the one operation it
        still needs. A ``getattr``-keyed check would do exactly that.

        **This is the test that matters most, because its failure mode is
        silent.** Now that re-finalising only warns, a ``getattr`` here would
        not raise -- it would warn and hand back a class with no generated
        ``__init__``, whose construction then falls through to
        :meth:`Info.__update__` and takes a mapping instead of the declared
        fields. So the assertion is on the generated constructor working, not
        merely on the marker landing.

        """
        from pcapkit.corekit.infoclass import FinalisedState, Info, info_final

        class Parent(Info):
            x: int

        class Child(Parent):
            y: int

        info_final(Parent)

        # Inherited but not owned -- for *both* markers, because the re-entry
        # check keys on ``__finalised__`` and the subclass guard on ``__final__``,
        # so a ``getattr`` in either place misreads this class the same way.
        self.assertTrue(getattr(Child, '__final__', False))
        self.assertNotIn('__final__', Child.__dict__)
        self.assertEqual(getattr(Child, '__finalised__', None), FinalisedState.FINAL)
        self.assertNotIn('__finalised__', Child.__dict__)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertIs(info_final(Child), Child)

        self.assertEqual([str(record.message) for record in caught], [])
        self.assertIn('__final__', Child.__dict__)
        self.assertEqual(Child(1, 2).to_dict(), {'x': 1, 'y': 2})

    def test_an_unfinalised_descendant_is_not_mistaken_for_a_mismarked_class(self) -> None:
        """:meth:`Info.__new__`'s guard must not fire on an inherited marker.

        The same shape as above, left *unfinalised*: a class that inherits
        ``__final__`` from a parent finalised after it was declared has not been
        mismarked by anybody, so constructing it must not raise. It inherits its
        parent's generated ``__init__`` and behaves accordingly -- which is the
        pre-existing "a descendant of a finalised class is not re-finalised"
        behaviour, not something this guard is entitled to turn into an error.

        Only the guard's own property is asserted. Such a class is *imperfect*
        for the pre-existing reason -- ``__excluded__`` was never populated for
        it, so :meth:`to_dict` also returns the inherited ``__map__`` and
        ``__map_reverse__`` -- and that is deliberately left unpinned here, so
        that fixing the wart does not read as breaking this guard.

        """
        from pcapkit.corekit.infoclass import Info, info_final

        class Parent(Info):
            x: int

        class Child(Parent):
            y: int

        info_final(Parent)

        self.assertTrue(getattr(Child, '__final__', False))
        self.assertNotIn('__final__', Child.__dict__)

        # No InfoError: the marker is inherited, not owned by this class.
        self.assertEqual(Child(1).x, 1)

    def test_a_subclass_that_predates_an_unfinalised_ancestors_bare_final_is_not_blamed_for_it(self) -> None:
        """The one shape that actually tells ``__dict__`` and ``getattr`` apart
        on :meth:`Info.__new__`'s own re-entry check -- distinct from the test
        above, where the ancestor is properly finalised.

        A subclass of a *finalised* ancestor is excluded before this check is
        ever reached: it inherits ``__finalised__ == FINAL`` too, so
        :meth:`Info.__new__`'s outer ``if cls.__finalised__ ==
        FinalisedState.NONE`` is already false for it, regardless of which
        lookup the inner check uses. The shape that actually reaches the inner
        check is an ancestor marked with a *bare* ``@final`` -- never run through
        :func:`info_final` -- whose own ``__finalised__`` therefore stays
        ``NONE``. A subclass declared *before* that bare marking is legal (there
        was nothing to object to at declaration time) and inherits ``NONE`` right
        along with it, so it too reaches the inner check on construction. It owns
        neither marker: it merely inherits ``__final__`` from an ancestor that
        was never itself finalised. ``getattr`` would read that inherited marker
        and blame this class for a mismarking that is its ancestor's, not its
        own -- raising for a class with a perfectly good, freshly-generated
        ``__init__`` of its own.

        """
        from pcapkit.corekit.infoclass import FinalisedState, Info
        from pcapkit.utilities.compat import final

        class Parent(Info):
            x: int

        class Child(Parent):
            y: int

        # Bare ``@final``, not ``info_final`` -- ``Parent`` is marked but never
        # finalised, and it is marked *after* ``Child`` was already declared.
        final(Parent)

        self.assertIn('__final__', Parent.__dict__)
        self.assertEqual(Parent.__dict__.get('__finalised__'), None)
        self.assertNotIn('__final__', Child.__dict__)
        self.assertTrue(getattr(Child, '__final__', False))
        self.assertEqual(Child.__finalised__, FinalisedState.NONE)

        # No InfoError: ``Child`` itself was never marked final, only inherits
        # the marker from ``Parent``, which is not the class this constructs.
        self.assertEqual(Child(1, 2).to_dict(), {'x': 1, 'y': 2})

    def test_a_final_class_descending_from_a_base_state_ancestor_escapes_the_guard(self) -> None:
        """A documented gap, not a guarantee -- see the ``Warning`` on
        :meth:`Info.__new__`.

        ``__finalised__`` inherits, and :attr:`~FinalisedState.BASE` is no
        exception: a class marked ``@final`` while descending from a ``BASE``
        ancestor reads ``BASE`` off it, never sees its own
        :attr:`~FinalisedState.NONE`, and so never reaches the branch that reads
        its marker at all. Closing this would mean re-finalising every
        descendant of a ``BASE`` class on each subclassing, which is exactly the
        auto-finalisation behaviour
        :meth:`test_an_unfinalised_descendant_is_not_mistaken_for_a_mismarked_class`
        establishes elsewhere in this file. This test pins today's behaviour so
        that a change to it is a deliberate decision, not a silent side effect.

        """
        from pcapkit.corekit.infoclass import FinalisedState, Info
        from pcapkit.utilities.compat import final

        class Parent(Info):
            x: int

        Parent(x=1)  # bare construction auto-finalises Parent to BASE
        self.assertEqual(Parent.__dict__.get('__finalised__'), FinalisedState.BASE)
        self.assertNotIn('__final__', Parent.__dict__)

        @final
        class Escaped(Parent):
            pass

        self.assertIn('__final__', Escaped.__dict__)
        self.assertEqual(Escaped.__finalised__, FinalisedState.BASE)

        # No InfoError, despite ``Escaped`` carrying its own ``__final__`` and
        # never having been run through ``info_final``.
        self.assertEqual(Escaped(1).to_dict(), {'x': 1})


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class AncestryWalkTests(unittest.TestCase):
    """The guard walks the MRO, not just the direct bases."""

    def test_a_grandchild_of_a_finalised_class_is_refused(self) -> None:
        """Checking ``__bases__`` alone would leave a one-line bypass.

        Declare the subclass before finalising the parent -- which the test
        above establishes is legal -- and the marker then sits two levels above
        anything declared next. A direct-bases check would wave those through,
        so the finalised class would be sealed against one declaration and open
        to every one after it.

        """
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.utilities.exceptions import InfoError

        class Parent(Info):
            x: int

        class Child(Parent):
            y: int

        info_final(Parent)
        self.assertNotIn('__final__', Child.__dict__)

        with self.assertRaises(InfoError) as caught:
            class Grandchild(Child):  # pylint: disable=unused-variable
                z: int

        # Named after the class that actually carries the marker, rather than
        # after the direct base, so the message points at what to change.
        self.assertIn('Parent', str(caught.exception))

    def test_a_finalised_class_reached_through_a_second_base_is_refused(self) -> None:
        """Multiple inheritance does not dilute the rule."""
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.utilities.exceptions import InfoError

        class Mixin(Info):
            x: int

        @info_final
        class Sealed(Info):
            y: int

        with self.assertRaises(InfoError):
            class Both(Mixin, Sealed):  # pylint: disable=unused-variable
                pass


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class VersionPortabilityTests(unittest.TestCase):
    """The dunder the guard reads has to exist on every supported version."""

    def test_finalising_records_the_dunder_in_the_class_namespace(self) -> None:
        """Without this the guard is a silent no-op below Python 3.11.

        :func:`typing.final` gained the ``__final__`` side effect in 3.11
        (gh-90500); before that it returns the class untouched. 3.10 is in the
        test matrix, so a guard reading the dunder needs ``final`` to come from
        :mod:`pcapkit.utilities.compat`, which asks ``typing_extensions`` for it
        below 3.11. On 3.11 and up this assertion holds either way -- it is 3.10
        where it is load-bearing, and it is cheap enough to run everywhere.

        """
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @info_final
        class SealedInfo(Info):
            x: int

        @schema_final
        class SealedSchema(Schema):
            pass

        self.assertIs(SealedInfo.__dict__.get('__final__'), True)
        self.assertIs(SealedSchema.__dict__.get('__final__'), True)

    def test_both_modules_take_final_from_the_compat_shim(self) -> None:
        """Pinned by identity, because the failure is silent on one version only.

        Pointing either import back at :mod:`typing` would leave every test
        above passing on 3.11+ and every one of them failing on 3.10, i.e. a
        single matrix leg going red for a reason nothing in the diff explains.
        Asserting the identity says which import is the load-bearing one.

        """
        from pcapkit.corekit import infoclass
        from pcapkit.protocols.schema import schema
        from pcapkit.utilities import compat

        self.assertIs(infoclass.final, compat.final)
        self.assertIs(schema.final, compat.final)

    def test_the_shim_switches_at_the_version_that_added_the_dunder(self) -> None:
        """The boundary is 3.11, not 3.8 when the name arrived.

        The two assertions above cannot fail on this interpreter -- on 3.11 and
        up ``typing_extensions.final`` *is* ``typing.final``, so every reading of
        them is the same reading. The thing that differs between versions is
        which branch of the shim runs, and that is only visible in the source, so
        this reads the boundary out of :mod:`pcapkit.utilities.compat` rather
        than out of its behaviour. It is the one test here that fails on any
        interpreter if the shim is pointed back at :mod:`typing` below 3.11.

        Derived from the module's own ``if``, not matched against its text, so
        reformatting the guard does not fail this and moving the boundary does.

        """
        import ast
        import pathlib

        from pcapkit.utilities import compat

        source = pathlib.Path(compat.__file__).read_text(encoding='utf-8')
        boundaries = [
            ast.unparse(node.test)
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.If)
            for stmt in node.body
            if isinstance(stmt, ast.ImportFrom) and stmt.module == 'typing_extensions'
            and any(alias.name == 'final' for alias in stmt.names)
        ]
        self.assertEqual(
            boundaries, ['sys.version_info < (3, 11)'],
            'pcapkit.utilities.compat must take `final` from typing_extensions below '
            '3.11, because that is the version at which typing.final began recording '
            '__final__ -- the marker Info.__init_subclass__ and '
            'Schema.__init_subclass__ read. A lower boundary leaves both guards '
            'reading an attribute nothing set on 3.10.',
        )


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DecoratorCombinationTests(unittest.TestCase):
    """One test per row of the table in this module's docstring, both families.

    Every case exercises the **generated constructor** rather than inspecting
    markers, because that is where the defect showed: a class can carry both
    markers, report itself finalised, and still be unusable. Checking
    ``__final__`` alone would have passed on the broken code.

    """

    def assert_silently_finalised(self, cls, construct, expected) -> 'None':
        """``cls`` warns about nothing and its generated constructor works."""
        from pcapkit.corekit.infoclass import FinalisedState

        self.assertIs(cls.__dict__.get('__final__'), True)
        self.assertEqual(cls.__dict__.get('__finalised__'), FinalisedState.FINAL)
        self.assertEqual(construct(cls), expected)

    # -- row 1: the decorator on its own ---------------------------------------

    def test_info_final_alone_finalises_silently(self) -> None:
        """The baseline, so the rows below are read against something."""
        from pcapkit.corekit.infoclass import Info, info_final

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')

            @info_final
            class Sealed(Info):
                x: int

        self.assertEqual([str(record.message) for record in caught], [])
        self.assert_silently_finalised(Sealed, lambda cls: cls(1).to_dict(), {'x': 1})

    def test_schema_final_alone_finalises_silently(self) -> None:
        """The schema-side baseline.

        Fielded rather than field-less: a field-less schema's :meth:`to_dict`
        returns ``{}`` whether the generated constructor from
        :attr:`~pcapkit.protocols.schema.schema.Schema.__fields__` ran or not, so
        it cannot tell "finalised and usable" apart from "silently unfinalised" --
        which is exactly the gap #422 fell through. A real field is what makes
        the generated constructor observable.

        """
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')

            @schema_final
            class Sealed(Schema):
                x: int = UInt8Field(default=1)

        self.assertEqual([str(record.message) for record in caught], [])
        self.assert_silently_finalised(Sealed, lambda cls: cls().to_dict(), {'x': 1})

    # -- row 2: both decorators, either order ---------------------------------

    def test_info_final_and_final_agree_in_either_order(self) -> None:
        """``@info_final @final`` and ``@final @info_final`` must be the same.

        Decorators apply bottom-up, so the first spelling runs ``final`` first
        and reaches :func:`info_final` with ``__final__`` already set. Keying the
        re-entry check on that marker made this spelling warn and skip the
        generation while the other spelling did the work -- so the two are
        asserted to *agree*, not merely each asserted to pass. That is the
        property that broke, and comparing them is the only way to state it.

        """
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.utilities.compat import final

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')

            @info_final
            @final
            class BottomUp(Info):
                x: int

            @final
            @info_final
            class TopDown(Info):
                x: int

        self.assertEqual([str(record.message) for record in caught], [])
        for cls in (BottomUp, TopDown):
            with self.subTest(cls=cls.__name__):
                self.assert_silently_finalised(cls, lambda c: c(1).to_dict(), {'x': 1})

    def test_schema_final_and_final_agree_in_either_order(self) -> None:
        """The schema-side half, where the old failure was *silent*.

        Fielded rather than field-less, for the reason given in the baseline test
        above -- a field-less schema cannot distinguish "finalised and usable"
        from "silently unfinalised". With a real field, the old defect's shape is
        exactly what a field-less class could not show: an unfinalised schema has
        an empty :attr:`__excluded__`, so rather than raising it returned its own
        bookkeeping -- ``{'__map__': {}, '__map_reverse__': {}, '__buffer__': {},
        '__updated__': True}`` -- from :meth:`to_dict`, with ``x`` nowhere in it.

        """
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final
        from pcapkit.utilities.compat import final

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')

            @schema_final
            @final
            class BottomUp(Schema):
                x: int = UInt8Field(default=1)

            @final
            @schema_final
            class TopDown(Schema):
                x: int = UInt8Field(default=1)

        self.assertEqual([str(record.message) for record in caught], [])
        for cls in (BottomUp, TopDown):
            with self.subTest(cls=cls.__name__):
                self.assert_silently_finalised(cls, lambda c: c().to_dict(), {'x': 1})

    # -- row 3 lives in InfoFinalEnforcementTests /
    #    SchemaFinalEnforcementTests, as the re-finalisation warning tests.

    # -- row 4: the marker without the decorator ------------------------------

    def test_a_bare_final_info_class_is_refused_at_first_construction(self) -> None:
        """``@final`` without ``@info_final`` raises, naming the real problem.

        The guard cannot live in :meth:`Info.__init_subclass__`: ``final`` is
        applied to the class *object*, after creation, so that hook has already
        run and returned by the time the marker lands. First construction is the
        next moment this library is given control, and it is where the damage
        used to surface -- as ``TypeError: 'int' object is not iterable`` out of
        :meth:`Info.__update__`, which names neither the class nor the mistake.

        """
        from pcapkit.corekit.infoclass import Info
        from pcapkit.utilities.compat import final
        from pcapkit.utilities.exceptions import InfoError

        @final
        class Mismarked(Info):
            x: int

        with self.assertRaises(InfoError) as caught:
            Mismarked(1)

        message = str(caught.exception)
        self.assertIn('Mismarked', message)
        self.assertIn('never finalised', message)
        self.assertIn('info_final', message)

    def test_a_bare_final_schema_is_refused_at_first_construction(self) -> None:
        """The schema-side half, which used to return corrupt data instead."""
        from pcapkit.protocols.schema.schema import Schema
        from pcapkit.utilities.compat import final
        from pcapkit.utilities.exceptions import SchemaError

        @final
        class Mismarked(Schema):
            pass

        with self.assertRaises(SchemaError) as caught:
            Mismarked()

        message = str(caught.exception)
        self.assertIn('Mismarked', message)
        self.assertIn('never finalised', message)
        self.assertIn('schema_final', message)

    def test_the_refusal_repeats_rather_than_firing_once(self) -> None:
        """A guard that reports the mistake only once is worse than none.

        The raise happens *before* the auto-finalisation it guards, so
        ``__finalised__`` stays :attr:`~FinalisedState.NONE` and the next attempt
        re-enters and fails again. Were the order reversed, the first
        construction would raise and every later one would quietly succeed
        against a half-built class.

        """
        from pcapkit.corekit.infoclass import FinalisedState, Info
        from pcapkit.utilities.compat import final
        from pcapkit.utilities.exceptions import InfoError

        @final
        class Mismarked(Info):
            x: int

        for attempt in range(3):
            with self.subTest(attempt=attempt):
                with self.assertRaises(InfoError):
                    Mismarked(1)
                self.assertEqual(Mismarked.__finalised__, FinalisedState.NONE)

    def test_schema_refusal_repeats_rather_than_firing_once(self) -> None:
        """The schema-side half of the test above, which had no counterpart."""
        from pcapkit.corekit.infoclass import FinalisedState
        from pcapkit.protocols.schema.schema import Schema
        from pcapkit.utilities.compat import final
        from pcapkit.utilities.exceptions import SchemaError

        @final
        class Mismarked(Schema):
            pass

        for attempt in range(3):
            with self.subTest(attempt=attempt):
                with self.assertRaises(SchemaError):
                    Mismarked()
                self.assertEqual(Mismarked.__finalised__, FinalisedState.NONE)

    def test_a_prior_bare_info_construction_does_not_defeat_the_guard(self) -> None:
        """Order independence is the property #778's cross-review found broken.

        :meth:`Info.__new__` auto-finalises an undecorated class to
        :attr:`~FinalisedState.BASE` on its first construction -- including
        ``Info`` itself, when something constructs it bare. ``__finalised__`` is
        an ordinary class attribute and so inherits: were ``Info`` promoted to
        ``BASE`` by that bare construction, every subclass declared afterwards
        would read ``BASE`` off ``Info`` and never see its own
        ``FinalisedState.NONE`` -- silently defeating the bare-``@final`` guard
        nested inside that branch for the rest of the process. This is exactly
        what made :meth:`test_the_refusal_repeats_rather_than_firing_once` above
        order-dependent on whatever else in the suite had already bare-constructed
        ``Info()`` -- nothing in this file did, at time of writing, so it passed
        by luck rather than by guarantee. This test pins the guarantee directly
        by constructing ``Info()`` bare first, in this same process, immediately
        before declaring the mismarked class.

        """
        from pcapkit.corekit.infoclass import FinalisedState, Info
        from pcapkit.utilities.compat import final
        from pcapkit.utilities.exceptions import InfoError

        self.assertEqual(Info.__dict__.get('__finalised__'), FinalisedState.NONE)

        self.assertEqual(Info(), {})

        # ``Info`` itself must never carry its own promotion -- see the NOTE in
        # ``info_final`` -- so this must read exactly as it did before the bare
        # construction above, own-dict and all.
        self.assertEqual(Info.__dict__.get('__finalised__'), FinalisedState.NONE)

        @final
        class MismarkedAfterBareInfo(Info):
            x: int

        with self.assertRaises(InfoError) as caught:
            MismarkedAfterBareInfo(1)

        message = str(caught.exception)
        self.assertIn('MismarkedAfterBareInfo', message)
        self.assertIn('never finalised', message)

    def test_a_prior_bare_schema_construction_does_not_defeat_the_guard(self) -> None:
        """The schema-side half of the test above."""
        from pcapkit.corekit.infoclass import FinalisedState
        from pcapkit.protocols.schema.schema import Schema
        from pcapkit.utilities.compat import final
        from pcapkit.utilities.exceptions import SchemaError

        self.assertEqual(Schema.__dict__.get('__finalised__'), FinalisedState.NONE)

        self.assertEqual(Schema().to_dict(), {})
        self.assertEqual(Schema.__dict__.get('__finalised__'), FinalisedState.NONE)

        @final
        class MismarkedAfterBareSchema(Schema):
            pass

        with self.assertRaises(SchemaError) as caught:
            MismarkedAfterBareSchema()

        message = str(caught.exception)
        self.assertIn('MismarkedAfterBareSchema', message)
        self.assertIn('never finalised', message)

    def test_repeated_bare_info_construction_does_not_grow_excluded_without_bound(self) -> None:
        """The cost of the ``cls is not Info`` fix, pinned rather than assumed.

        ``Info`` never reaches :attr:`~FinalisedState.BASE` now, so a bare
        ``Info()`` would re-enter :func:`info_final` on *every* call rather than
        once, and ``cls.__excluded__.extend(cls.__builtin__)`` would append the
        same ~60 names again each time -- correctness untouched (``__excluded__``
        is only ever read for membership), but the list growing without bound,
        with the cost resurfacing at every later subclass declaration, since
        :class:`InfoMeta`'s own dedup pass is then against a base list that keeps
        growing. Fixed by short-circuiting the re-entry itself for ``Info``, via
        its own ``__base_ready__`` marker --
        :meth:`test_repeated_bare_info_construction_does_not_re_enter_the_base_setup`
        below pins that the short-circuit is what closes it, not merely that the
        length happens to stay put.

        """
        from pcapkit.corekit.infoclass import Info

        Info()  # prime it -- the first call legitimately populates __excluded__
        before = len(Info.__excluded__)

        for _ in range(50):
            Info()
        after = len(Info.__excluded__)

        self.assertEqual(after, before, 'Info.__excluded__ grew across repeated bare construction')
        self.assertEqual(len(Info.__excluded__), len(set(Info.__excluded__)))

    def test_repeated_bare_schema_construction_does_not_grow_excluded_without_bound(self) -> None:
        """The schema-side half of the test above."""
        from pcapkit.protocols.schema.schema import Schema

        Schema()  # prime it -- the first call legitimately populates __excluded__
        before = len(Schema.__excluded__)

        for _ in range(50):
            Schema()
        after = len(Schema.__excluded__)

        self.assertEqual(after, before, 'Schema.__excluded__ grew across repeated bare construction')
        self.assertEqual(len(Schema.__excluded__), len(set(Schema.__excluded__)))

    def test_repeated_bare_info_construction_does_not_re_enter_the_base_setup(self) -> None:
        """The assertion that would have caught both this round and the last.

        A dedup'd ``extend`` also keeps ``__excluded__``'s *length* bounded, but
        it does so by redoing the ``dir()``-over-the-MRO scan and rebuilding
        ``cls.__builtin__`` on every single bare call -- the previous round's
        fix, and the reason bare construction got 41x-49x slower rather than
        cheaper. ``cls.__builtin__ = set(temp)`` is a *reassignment*, so its
        identity changes every time the base setup actually reruns, even when
        the resulting set looks the same; a short-circuit that truly skips the
        work leaves that same object in place. Identity is what tells "skipped"
        apart from "did the work again and happened to get the same answer" --
        a length check alone cannot.

        A held reference, not a bare ``id()`` snapshot: comparing ``id()``
        values across separate calls is unreliable the moment the first object
        is garbage-collected, since CPython is then free to hand the very next
        ``set()`` of the same size the same address -- which is exactly what let
        this assertion pass by coincidence against the previous round's fix on
        one of the two classes. Keeping ``marker`` alive as the object itself,
        not its address, is what makes the ``is`` check below trustworthy.

        """
        from pcapkit.corekit.infoclass import Info

        Info()  # prime it
        marker = Info.__builtin__  # a live reference, not id() -- see the docstring

        for _ in range(50):
            Info()

        self.assertIs(Info.__builtin__, marker,
                       'Info.__builtin__ was rebuilt by a repeat bare construction')

    def test_repeated_bare_schema_construction_does_not_re_enter_the_base_setup(self) -> None:
        """The schema-side half of the test above."""
        from pcapkit.protocols.schema.schema import Schema

        Schema()  # prime it
        marker = Schema.__builtin__  # a live reference, not id() -- see the docstring above

        for _ in range(50):
            Schema()

        self.assertIs(Schema.__builtin__, marker,
                       'Schema.__builtin__ was rebuilt by a repeat bare construction')


if __name__ == '__main__':
    unittest.main()
