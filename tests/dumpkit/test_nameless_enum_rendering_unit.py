from __future__ import annotations

import enum
import importlib
import importlib.util
import pkgutil
import unittest
from typing import TYPE_CHECKING

from tests._support import purge_modules

if TYPE_CHECKING:
    import aenum

    #: Either enumeration library's flag class. :class:`aenum.Flag` is *not* an
    #: :class:`enum.Flag` subclass -- which is why the sweep below tests for
    #: both of them -- so neither one alone annotates a registry.
    FlagRegistry = type[enum.Flag] | type[aenum.Flag]

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class StdFlags(enum.IntFlag):
    """A stdlib replica of :class:`pcapkit.const.tcp.flags.Flags`' declared bits.

    Present so the tests can show the nameless pseudo-member is not an
    :mod:`aenum` quirk. :mod:`enum` and :mod:`aenum` spell a wholly-undeclared
    flag value the same way, so a fix that swapped enumeration libraries would
    have changed nothing.

    """

    ACK = 2048
    SYN = 16384


class AnnotatedFlags(enum.IntFlag):
    """A flag enumeration whose pseudo-members carry a public attribute.

    This exists to reach the hook's ``addon`` branch with a *nameless* member.
    That branch fires only when ``o.__dict__`` holds a key that does not begin
    with an underscore, and a pseudo-member's ``__dict__`` is just
    ``{'_value_': …, '_name_': None}`` -- so a plain composite never gets there
    and falls through to the scalar return instead. Overriding
    :meth:`~enum.Enum._missing_` to annotate the pseudo-member it builds is the
    route that does, and it is a documented extension point rather than a poke
    at the instance from outside.

    """

    ACK = 2048

    @classmethod
    def _missing_(cls, value: 'int') -> 'AnnotatedFlags | None':
        obj = super()._missing_(value)
        if obj is not None:
            obj.note = f'undeclared bits {value:#x}'
        return obj


class BaseDumper:
    """Minimal stand-in for :class:`dictdumper.dumper.Dumper`.

    Mirrors the stub in :mod:`tests.dumpkit.test_common_unit`: the hook under
    test never reaches ``super().object_hook`` for an enumeration, so nothing
    more than a terminating implementation is needed, and this avoids
    instantiating a real dumper against the filesystem.

    """

    def object_hook(self, value):  # noqa: ANN001, ANN201
        return {'base': value}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NamelessEnumRenderingTests(unittest.TestCase):
    """#648 -- a nameless flag member must not render as ``Type::None [n]``.

    :func:`~pcapkit.dumpkit.common.make_dumper`'s ``object_hook`` renders every
    enumeration member as ``Type::name [value]``, and it interpolated
    :attr:`~enum.Enum.name` unguarded at three separate places. A
    :class:`~enum.Flag` value composed entirely of undeclared bits has
    ``name is None``, so all three put the literal four characters ``None`` into
    the name half.

    The replacement is the value's own decimal spelling -- ``'Flags::0 [0]'``,
    ``'Flags::8 [8]'`` -- chosen for three reasons these tests pin:

    * It is what the enumeration libraries themselves already use for an
      undeclared residue. ``Flags(2057).name`` is ``'ACK|9'``, naming the
      declared bit and giving the leftovers as one decimal number; a
      wholly-undeclared value is that rendering with no declared bit in front.
    * It cannot be confused with a member name, because a Python identifier may
      not begin with a digit. ``'None'`` could be: ``NONE`` is a real declared
      name elsewhere in the library, so a consumer splitting the rendering on
      ``::`` had no way to tell "no flags set" from a member so named.
    * It needs no special case for zero, which matters because the defect never
      was about zero.

    The values probed are derived from each enumeration's own declared bits
    rather than written down, which is #702. This file used to sweep the literal
    ``(0, 1, 8, 9, 65536)``, and ``65536`` is ``0x10000`` -- one bit past the
    sixteen-bit field :class:`~pcapkit.const.tcp.flags.Flags` bounds its
    :meth:`~enum.Enum._missing_` to. That guard is correct, so the probe was
    what had to move: a value the registry is right to refuse cannot also be a
    value the dumper renders. Every one of the library's six flag registries
    carries such a guard, at three distinct widths, so exempting the guarded
    ones instead would have left this half of the sweep with nothing in it at
    all. (GitHub issue #808 retyped the seventh, ``TransportProtocol``, out of
    this sweep entirely -- see ``test_no_flag_registry_renders_the_literal_none``'s
    docstring below.)

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_scalar_return_renders_a_nameless_member_as_its_value(self) -> None:
        """The plain ``return`` at the end of the enumeration branch.

        Covers the nameless zero *and* every non-zero nameless value the
        registry admits, because a fix that special-cased zero would pass on
        ``Flags(0)`` alone and still emit ``'Flags::8 [8]'``'s predecessor
        ``'Flags::None [8]'``.

        Both libraries are swept from the same derivation, so this is still the
        demonstration that the rendering is not an :mod:`aenum` quirk -- stdlib
        :class:`enum.IntFlag` spells a wholly-undeclared value the same way.

        """
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.dumpkit.common import make_dumper

        dumper = make_dumper(BaseDumper)()

        for registry, library in ((Flags, 'aenum'), (StdFlags, 'enum')):
            values = _nameless_values(registry)
            # Without this the loop below could sweep nothing at all and still
            # report a pass, which is how a derived probe set rots silently
            # where a written-down one would not.
            self.assertGreater(len(values), 1, (library, values))

            for value in values:
                with self.subTest(library=library, value=value):
                    member = registry(value)
                    # The premise: there is no name to interpolate.
                    self.assertIsNone(member.name)
                    rendered = dumper.object_hook(member)
                    self.assertEqual(rendered, f'{registry.__name__}::{value} [{value}]')
                    # The defect, stated as what must no longer appear. Asserted
                    # separately from the equality above so a future change to
                    # the rendering cannot quietly reintroduce the literal.
                    self.assertNotIn('None', rendered)

    def test_named_members_are_untouched(self) -> None:
        """The control. Only the name half of a *nameless* member changes.

        ``Flags(2049)`` matters most here: its name is ``'ACK|1'``, so it was
        never broken, and it is the precedent the fallback follows. If the guard
        were written as "compose the name from the value" rather than "use the
        value when there is no name", this is the assertion that would catch it.

        """
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.dumpkit.common import make_dumper

        dumper = make_dumper(BaseDumper)()

        self.assertEqual(dumper.object_hook(Flags.ACK), 'Flags::ACK [2048]')
        self.assertEqual(dumper.object_hook(Flags.SYN | Flags.ACK), 'Flags::ACK|SYN [18432]')
        self.assertEqual(dumper.object_hook(Flags(2049)), 'Flags::ACK|1 [2049]')
        self.assertEqual(dumper.object_hook(Flags(2057)), 'Flags::ACK|9 [2057]')

        # An explicitly declared zero keeps its declared name, which is the
        # clearest demonstration that the guard keys on the *name* and not on the
        # value: this member's value is 0 and its rendering is unchanged.
        from pcapkit.const.reg.apptype import TransportProtocol

        self.assertEqual(TransportProtocol(0).name, 'undefined')
        self.assertEqual(dumper.object_hook(TransportProtocol(0)),
                         'TransportProtocol::undefined [0]')

    def test_multidict_key_path_renders_a_nameless_key(self) -> None:
        """The ``MultiDict``/``OrderedMultiDict`` *key* path.

        A second, separate interpolation of the same shape. It builds the
        dictionary key rather than the value, so a nameless key collapsed every
        undeclared flag value onto the single key ``'Flags::None [n]'`` -- and,
        for two different nameless values, onto keys distinguished only by the
        bracketed half.

        """
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
        from pcapkit.dumpkit.common import make_dumper

        dumper = make_dumper(BaseDumper)()

        multidict = MultiDict()
        multidict.add(Flags(0), 'flagless')
        multidict.add(Flags(8), 'undeclared-bit')
        multidict.add(Flags.ACK, 'acknowledged')

        converted = dumper.object_hook(multidict)
        self.assertEqual(converted['Flags::0 [0]'], ['flagless'])
        self.assertEqual(converted['Flags::8 [8]'], ['undeclared-bit'])
        self.assertEqual(converted['Flags::ACK [2048]'], ['acknowledged'])
        self.assertNotIn('Flags::None [0]', converted)
        self.assertNotIn('Flags::None [8]', converted)

        ordered = OrderedMultiDict()
        ordered.add(Flags(0), 'first')
        ordered.add(Flags(0), 'second')
        self.assertEqual(dumper.object_hook(ordered)['Flags::0 [0]'], ['first', 'second'])

    def test_addon_branch_renders_a_nameless_member(self) -> None:
        """The third interpolation -- the ``'enum'`` key of the ``addon`` mapping.

        Reached when the member carries public instance attributes, which for a
        pseudo-member takes a :meth:`~enum.Enum._missing_` override. No registry
        under :mod:`pcapkit.const` is both a flag enumeration and an annotated
        one today, so this branch is not reachable from a capture on ``main`` --
        but the interpolation was character-for-character the same as the other
        two, so it is guarded with them rather than left as the one place the
        literal ``None`` survives.

        """
        from pcapkit.dumpkit.common import make_dumper

        dumper = make_dumper(BaseDumper)()

        member = AnnotatedFlags(8)
        self.assertIsNone(member.name)

        converted = dumper.object_hook(member)
        self.assertEqual(converted['enum'], 'AnnotatedFlags::8 [8]')
        self.assertEqual(converted['note'], 'undeclared bits 0x8')

        # And the named member through the same branch, as the control.
        self.assertEqual(dumper.object_hook(AnnotatedFlags.ACK), 'AnnotatedFlags::ACK [2048]')

    def test_no_flag_registry_renders_the_literal_none(self) -> None:
        """Every flag enumeration in the library, swept rather than sampled.

        The sweep is the point: #648 was first reported against
        :class:`pcapkit.const.tcp.flags.Flags` alone, and five of the six flag
        registries turn out to be nameless at zero -- ``Flags`` plus the four
        Mobility Header flag registries. Naming them here would rot the moment
        a seventh is added, so they are discovered.

        GitHub issue #808 dropped this sweep from seven registries to six:
        :class:`~pcapkit.const.reg.apptype.TransportProtocol` was a bounded
        :class:`~aenum.IntFlag` before that issue and is a plain
        :class:`~aenum.IntEnum` after, so it no longer matches the
        ``issubclass(attribute, (enum.Flag, aenum.Flag))`` test
        :func:`_flag_registries` sweeps on. It contributed nothing to
        ``nameless`` either before or after -- it declared ``0`` as
        ``undefined`` and had no undeclared bits left in its field, the same
        shape as ``CommandType`` -- so only the registry *count* below moved.

        Since #702 the sweep is over every nameless value each registry admits
        rather than over ``registry(0)`` alone. Before that, the four Mobility
        Header registries were only ever exercised at the one value they share,
        so the sweep was broad across registries and one value deep in each.

        """
        from pcapkit.dumpkit.common import make_dumper

        dumper = make_dumper(BaseDumper)()

        registries = _flag_registries()

        # A guard on the sweep itself: an empty mapping would make every
        # assertion below vacuous, and that is how this test would rot silently.
        self.assertGreaterEqual(len(registries), 6, registries)

        nameless = []
        for label, registry in sorted(registries.items()):
            values = _nameless_values(registry)
            if values:
                nameless.append(label)

            # ``0`` is rendered whether or not it is nameless. For the one
            # registry that declares it -- ``CommandType``, the one with no
            # undeclared bits left in its field -- it is the only thing there
            # is to render, and it is the control showing the fix keys on the
            # name and not on the value.
            for value in dict.fromkeys((0, *values)):
                with self.subTest(registry=label, value=value):
                    member = registry(value)
                    rendered = dumper.object_hook(member)
                    self.assertNotIn('::None [', rendered)
                    if member.name is None:
                        # Cross-checks the derivation as well as the rendering:
                        # a nameless value the helper did not return would mean
                        # the sweep is skipping part of the field.
                        self.assertIn(value, values)
                        self.assertEqual(rendered, f'{registry.__name__}::{value} [{value}]')
                    else:
                        self.assertEqual(rendered,
                                         f'{registry.__name__}::{member.name} [{value}]')

        # Not an incidental detail: if this ever drops to zero the test above
        # stops exercising the fix at all and would pass on unfixed code.
        # Unchanged at 5 by GitHub issue #808 dropping the sweep from seven
        # registries to six -- see the class docstring above: the registry it
        # removed, TransportProtocol, was never one of the nameless five.
        self.assertGreaterEqual(len(nameless), 5, nameless)

    def test_a_value_past_the_field_is_refused_rather_than_rendered(self) -> None:
        """#702 -- the probe that was wrong, asserted the right way round.

        All six flag registries bound their :meth:`~enum.Enum._missing_` to
        the width of their own field, and the widths differ: three bits for
        :class:`~pcapkit.const.ftp.command.CommandType`, eight for three of the
        Mobility Header flags, sixteen for ``BindingUpdateFlag`` and
        :class:`~pcapkit.const.tcp.flags.Flags`. One literal therefore cannot
        mean "past the field" for all of them, which is the whole reason
        :func:`_field_mask` derives it per registry.

        This also pins the derivation without parsing anybody's source: the
        widest in-field value is accepted and the next one up is refused, which
        holds only if the mask :func:`_field_mask` computes is exactly the bound
        each registry wrote down for itself.

        Until GitHub issue #808 there were seven registries and four distinct
        widths here, the fourth being
        :class:`~pcapkit.const.reg.apptype.TransportProtocol`'s four bits --
        derived as ``max(cls.__members__.values()) * 2 - 1`` since it extended
        itself at runtime and could not hard-code a bound. #808 retyped it to a
        plain :class:`~aenum.IntEnum`, dropping it out of :func:`_flag_registries`'
        sweep entirely (see the class docstring above), which is why three
        widths remain rather than four.

        ``65536`` survives here, as the bound of the two sixteen-bit registries
        -- asserted as the rejection it always was, rather than as a value the
        dumper was expected to render. Which also keeps the ``raise`` in those
        guards covered: five of the six were never reached by any test, and the
        sixth was reached only by this file failing on it.

        """
        registries = _flag_registries()
        self.assertGreaterEqual(len(registries), 6, registries)

        widths = set()
        for label, registry in sorted(registries.items()):
            mask = _field_mask(registry)
            widths.add(mask.bit_length())

            with self.subTest(registry=label, value=mask):
                # The widest value the field holds is valid, named or not.
                self.assertEqual(registry(mask).value, mask)

            with self.subTest(registry=label, value=mask + 1):
                with self.assertRaises(ValueError) as caught:
                    registry(mask + 1)
                # ``enum`` requires ``ValueError`` from a refused lookup, and
                # #677 brought the last six divergent registries onto the bare
                # built-in the rest of :mod:`pcapkit.const` already raised, so
                # this asserts the message rather than a type of its own.
                self.assertIn(str(mask + 1), str(caught.exception))
                self.assertIn(registry.__name__, str(caught.exception))

        # The literal could not have been right for all of them, and this is the
        # measurement that says so: several distinct widths, and ``65536`` is
        # outside every single one of them. 3 rather than 4 since GitHub issue
        # #808 -- see the docstring above.
        self.assertGreaterEqual(len(widths), 3, widths)


def _const_path() -> 'list[str]':
    """The filesystem path of :mod:`pcapkit.const`, for :func:`pkgutil.walk_packages`.

    Taken from the imported package rather than built from ``__file__`` so the
    sweep reads the same tree the rest of the test imports from.

    Returns:
        A single-element search path for the ``pcapkit.const`` package.

    """
    import pcapkit.const

    return list(pcapkit.const.__path__)


def _flag_registries() -> 'dict[str, FlagRegistry]':
    """Every flag enumeration declared under :mod:`pcapkit.const`.

    Discovered rather than listed, so an eighth registry is swept the day it
    lands instead of the day somebody remembers to add it here. Keyed by
    ``<module>.<class>`` so a failing subtest names the registry it came from.

    Both libraries are matched because the two are unrelated types --
    :class:`aenum.Flag` is not an :class:`enum.Flag` subclass -- and the
    generated registries use :mod:`aenum` while the stand-ins in this file use
    the stdlib.

    Returns:
        The discovered registries, keyed by dotted path.

    """
    import aenum

    registries: 'dict[str, FlagRegistry]' = {}
    for module in pkgutil.walk_packages(_const_path(), prefix='pcapkit.const.'):
        try:
            imported = importlib.import_module(module.name)
        except ImportError:  # pragma: no cover - a registry that cannot import
            continue
        for attribute in vars(imported).values():
            if not isinstance(attribute, type) or attribute.__module__ != module.name:
                continue
            if issubclass(attribute, (enum.Flag, aenum.Flag)):
                registries[f'{module.name}.{attribute.__name__}'] = attribute
    return registries


def _declared_bits(registry: 'FlagRegistry') -> int:
    """The union of every bit *registry* declares a member for.

    Iteration over a flag enumeration yields the canonical single-bit members,
    skipping a zero member and any alias, which is what makes this the registry's
    *declared bits* rather than a member count: ``Flags`` declares twelve members
    from ``1 << 4`` upwards, so this is ``0xFFF0``.

    Args:
        registry: The flag enumeration to inspect.

    Returns:
        The bitwise OR of every member's value.

    """
    declared = 0
    for member in registry:
        declared |= member.value
    return declared


def _field_mask(registry: 'FlagRegistry') -> int:
    """The width of *registry*'s field, as an all-ones mask.

    Every flag registry in the library bounds its :meth:`~enum.Enum._missing_`
    to the field its declared bits live in, and for all six of them that bound
    is exactly the smallest all-ones mask covering every declared bit --
    ``0xFFFF`` for ``Flags``' ``1 << 4 .. 1 << 15``, ``0xFF`` for the eight-bit
    Mobility Header flags, ``0x07`` for the three-bit
    :class:`~pcapkit.const.ftp.command.CommandType`.

    A seventh registry used to belong here on the same terms:
    :class:`~pcapkit.const.reg.apptype.TransportProtocol` spelled its own bound
    as ``max(cls.__members__.values()) * 2 - 1`` because it extends itself at
    runtime and could not hard-code one. GitHub issue #808 retyped it from
    :class:`~aenum.IntFlag` to a plain :class:`~aenum.IntEnum` once nothing
    built a composite, dropping it out of :func:`_flag_registries`'s sweep
    entirely rather than merely changing its bound -- it no longer matches
    ``issubclass(attribute, (enum.Flag, aenum.Flag))``, so this function never
    sees it at all.

    Derived rather than read off the source, so it cannot drift from the guard
    and needs no table to maintain. That it does not drift is itself asserted, by
    :meth:`NamelessEnumRenderingTests.test_a_value_past_the_field_is_refused_rather_than_rendered`.

    Args:
        registry: The flag enumeration to inspect.

    Returns:
        An all-ones mask as wide as the registry's field.

    """
    return (1 << _declared_bits(registry).bit_length()) - 1


def _nameless_values(registry: 'FlagRegistry') -> 'tuple[int, ...]':
    """The in-field values of *registry* that no member names.

    A flag value made up *entirely* of bits no member declares has
    ``name is None``, which is the whole point of #648: the defect is a property
    of "no declared bits", not of the number zero, so a guard written against
    ``value == 0`` would fix the first of these and leave the rest.

    Three kinds of value come back and no more -- no bits at all, each single
    undeclared bit on its own, and every undeclared bit at once. The last is the
    multi-bit case, and it is the largest value the field admits with no declared
    bit in it, which is what the old literal's ``9`` and its out-of-range
    ``65536`` were each reaching for. Returning every subset would be exhaustive
    and is not worth 8192 subtests for :class:`StdFlags`' thirteen undeclared
    bits.

    Nothing out of range is returned, which is #702: the values are all masked
    into the registry's own field, so a registry that legitimately refuses
    ``0x10000`` is never asked to mint a pseudo-member for it.

    A registry whose declared bits fill its field has no nameless value at all
    and yields an empty tuple. :class:`~pcapkit.const.ftp.command.CommandType`
    is of that shape, declaring ``0`` as ``undefined``, which is why five of
    the six registries :func:`_flag_registries` discovers are nameless at zero
    rather than all six.
    :class:`~pcapkit.const.reg.apptype.TransportProtocol` used to be a second
    example of the same shape before GitHub issue #808 retyped it out of the
    sweep entirely -- see :func:`_field_mask`'s docstring.

    Args:
        registry: The flag enumeration to inspect.

    Returns:
        The registry's nameless values, smallest first.

    """
    undeclared = _field_mask(registry) & ~_declared_bits(registry)
    singles = [1 << index for index in range(undeclared.bit_length())
               if undeclared >> index & 1]

    candidates = [0, *singles]
    if len(singles) > 1:
        candidates.append(undeclared)

    return tuple(value for value in candidates if registry(value).name is None)


if __name__ == '__main__':
    unittest.main()
