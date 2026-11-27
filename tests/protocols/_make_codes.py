# -*- coding: utf-8 -*-
"""The checks each ``*_make_codes_2594`` module runs over its enumeration fields.

Ruled in review of #2593 (#2489) and carried across the makers by #2594: a
``make()`` field holding an enumeration takes the member or an :class:`int` code,
resolved with the enumeration's ``get``, and refuses a name; a caller holding one
resolves it first, with :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index`.
Under #2617 a code the field cannot carry, and a :obj:`bool` for a field wider than
one bit, raise :exc:`~pcapkit.utilities.exceptions.ProtocolError`.

Each module keeps its own table of fields and the refusals it pins, and gives each
field to :class:`MakeCodeChecks` as a :class:`Case`. Shared under #3148.

Nothing here imports :mod:`pcapkit` at module level, so each test module keeps its
classes' own import, after :func:`~tests._support.reimport_once_per_class`.

"""
from __future__ import annotations

import inspect
import re
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Any, Callable, Iterable, Optional, Pattern

#: The suffixes of the keywords #2594 removed from every maker.
REMOVED = ('_default', '_namespace', '_reversed')


class Case(NamedTuple):
    """One enumeration field of one maker, as a module's own table gives it."""

    #: The field, as the subtests name it.
    label: 'str'
    #: The field's width, in bits.
    bits: 'int'
    #: The member the field is built with.
    member: 'Any'
    #: The octets of a packet carrying a value in the field.
    build: 'Callable[[Any], bytes]'
    #: What a refusal says before the value: a :obj:`str` is matched literally,
    #: a compiled pattern as a regular expression, and :data:`None` is not checked.
    message: 'Optional[str | Pattern[str]]' = None
    #: The code the octets carry in the field, read back.
    read: 'Optional[Callable[[bytes], Any]]' = None
    #: The octets the maker builds without the field, which the member's must differ from.
    bare: 'Optional[Callable[[], bytes]]' = None
    #: Codes the field carries that it still refuses, past the enumeration's range.
    refused: 'tuple[int, ...]' = ()
    #: Why the member cannot be built here, if it cannot.
    skip: 'Optional[str]' = None
    #: The module's own row, for its own checks.
    row: 'Any' = None


def enumeration_arguments(func: 'Callable[..., Any]', *, keyword_only: 'bool' = False) -> 'set[str]':
    """The arguments of ``func`` annotated with an enumeration, the keyword-only ones alone if asked."""
    return {name for name, param in inspect.signature(func).parameters.items()
            if 'Enum_' in str(param.annotation) and (not keyword_only or param.kind is param.KEYWORD_ONLY)}


def removed_keywords(*classes: 'type') -> 'list[str]':
    """``Class.maker.argument`` for each argument #2594 removed that a maker of ``classes`` still takes."""
    found = []
    for cls in classes:
        for name in sorted(vars(cls)):
            func = getattr(cls, name)
            if (name == 'make' or name.startswith('_make_')) and callable(func):
                found.extend(f'{cls.__name__}.{name}.{arg}' for arg in inspect.signature(func).parameters
                             if arg.endswith(REMOVED))
    return found


class RefusalChecks:
    """:meth:`assertRefused`, for a :class:`unittest.TestCase`; a plain class, so nothing collects it."""

    def assertRefused(self, build: 'Callable[[Any], bytes]', value: 'Any',  # pylint: disable=invalid-name
                      message: 'Optional[str | Pattern[str]]' = None) -> 'None':
        """``build(value)`` raises the ``ProtocolError`` saying ``message`` and then ``value``.

        Any other outcome fails by assertion, naming what happened instead.

        """
        from pcapkit.utilities.exceptions import ProtocolError

        try:
            octets = build(value)
        except ProtocolError as error:
            if isinstance(message, str):
                self.assertEqual(str(error), f'{message}{value!r}')
            elif message is not None:
                self.assertRegex(str(error), f'^(?:{message.pattern}){re.escape(repr(value))}$')
        except Exception as error:  # pylint: disable=broad-except
            self.fail(f'{value!r} raised {type(error).__name__}, not ProtocolError: {error}')
        else:
            self.fail(f'{value!r} was accepted, building {octets.hex()}')


class MakeCodeChecks(RefusalChecks):
    """The checks a :class:`unittest.TestCase` runs over each :class:`Case` its ``cases()`` gives.

    A plain class, so that nothing collects it on its own: a module mixes it in
    ahead of :class:`unittest.TestCase` and gives :meth:`cases`.

    """

    #: Whether a negative code is among the refusals the module pins.
    NEGATIVE = False
    #: The labels of the one-bit fields, which take a :obj:`bool` as their code.
    ONE_BIT = ()  # type: tuple[str, ...]

    def cases(self) -> 'Iterable[Case]':
        """The module's fields, each as a :class:`Case`."""
        raise NotImplementedError

    def refusals(self, case: 'Case') -> 'list[Any]':
        """What ``case``'s field refuses.

        A code past its width, the module's own codes, a negative code where the
        module pins one, a :obj:`bool` for a field wider than one bit, and the
        member's name.

        """
        values = [1 << case.bits, *case.refused]  # type: list[Any]
        if self.NEGATIVE:
            values.append(-1)
        if case.bits > 1:
            values.append(True)
        return [*values, case.member.name]

    def assertFieldRefuses(self, case: 'Case', value: 'Any') -> 'None':  # pylint: disable=invalid-name
        """``case``'s field refuses ``value``."""
        self.assertRefused(case.build, value, case.message)

    def test_what_the_field_cannot_carry_is_refused(self) -> 'None':
        """Each refusal of :meth:`refusals`; a one-bit field takes :data:`True` as ``1``."""
        cases = list(self.cases())
        self.assertEqual([case.label for case in cases if case.bits == 1], list(self.ONE_BIT))
        for case in cases:
            for value in self.refusals(case):
                with self.subTest(row=case.label, value=value):
                    self.assertFieldRefuses(case, value)
            if case.bits == 1:
                with self.subTest(row=case.label, value=True):
                    octets = case.build(True)
                    self.assertEqual(octets, case.build(1))
                    if case.read is not None:
                        self.assertEqual(case.read(octets), 1)

    def test_a_member_its_code_and_its_resolved_name_build_alike(self) -> 'None':
        """The member, ``int(member)`` and the member's name through ``resolve_index`` build the same octets."""
        from pcapkit.protocols.protocol import Protocol

        for case in self.cases():
            with self.subTest(row=case.label, member=case.member):
                if case.skip is not None:
                    self.skipTest(case.skip)
                octets = case.build(case.member)
                self.assertEqual(case.build(int(case.member)).hex(), octets.hex())
                # NOTE: a member the enumeration's ``_missing_`` builds has no name to resolve.
                if case.member.name in type(case.member).__members__:
                    resolved = Protocol.resolve_index(case.member.name, namespace=type(case.member))
                    self.assertEqual(case.build(resolved).hex(), octets.hex())
                if case.read is not None:
                    self.assertEqual(case.read(octets), case.member)
                if case.bare is not None:
                    self.assertNotEqual(case.bare().hex(), octets.hex())
