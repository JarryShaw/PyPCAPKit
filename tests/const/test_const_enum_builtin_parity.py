# -*- coding: utf-8 -*-
"""Every :mod:`pcapkit.const` registry must reject an invalid value the way the built-in does.

GitHub issue #647 counted the generated range guards under :mod:`pcapkit.const`
and found that 113 of the 117 modules raise a bare :exc:`ValueError`. The issue
proposed replacing them with :class:`~pcapkit.utilities.exceptions.EnumError`;
the decision went the other way. A bare :exc:`ValueError` is exactly what
:class:`enum.IntEnum` raises for a value it does not define, mirroring the
built-in is the intent, and
:class:`~pcapkit.utilities.exceptions.EnumError` is ``(BaseError, TypeError)`` --
not a :exc:`ValueError` at all -- so swapping it in would have diverged from the
built-in *and* walked past the ``except ValueError`` in all 113 generated
``get()`` bodies, silently undoing GitHub issue #584.

What was left was the inconsistency. Six registries across four modules did
something other than raise:

* three :class:`~aenum.IntFlag` registries defined no ``_missing_`` at all, so
  ``aenum``'s :class:`~aenum.Flag` machinery composed a pseudo-member for any
  integer whatsoever. ``Flags(-1)`` returned ``65520`` -- the OR of every
  declared TCP header flag -- so a value no 16-bit wire field can hold read back
  as *every flag set at once*, and ``Flags(-65536)`` as *none set*.
* three :class:`~aenum.StrEnum` registries reached ``value.upper()`` in their
  ``_missing_`` before checking the type, so an integer raised
  :exc:`AttributeError` (``'int' object has no attribute 'upper'``) rather than
  :exc:`ValueError`.

All six now carry a guard raising a bare :exc:`ValueError`, emitted by their
templates under :mod:`pcapkit.vendor` rather than hand-written -- the tree is
generated, so a fix that is not in the template is reverted by the next crawl.

The one deliberate divergence from the built-in is preserved and pinned here:
the *mutable* registries look a value up, miss, and then **register** it with
:func:`~aenum.extend_enum` instead of raising. That is the exception the owner
named, and :class:`ConstEnumRegisterFallbackTests` exists so a future guard
cannot quietly turn a registration into a rejection -- the failure mode GitHub
issues #584 and #623 are both about.

The guard for the three flag registries delegates in-range composites to
``super()._missing_`` rather than resolving them itself, because GitHub issue
#623 established that an :class:`~aenum.IntFlag` whose ``_missing_`` re-enters
its own constructor recurses without bound.

"""
from __future__ import annotations

import ast
import collections
import enum
import importlib
import importlib.util
import inspect
import pkgutil
import re
import sys
import unittest
from typing import TYPE_CHECKING

import aenum

from tests._support import ISOLATED_PREFIXES, purge_modules, restore_modules, snapshot_modules

if TYPE_CHECKING:
    from typing import Optional

#: An integer no wire field in the library is wide enough to carry. Shared with
#: :mod:`tests.const.test_const_enum_get`, which uses the same value for the
#: same reason.
UNRESOLVABLE = 1 << 70

#: The six registries GitHub issue #647 converged, as ``(module, class name,
#: what the pre-fix lookup did with an invalid value)``. Named individually as
#: well as swept, so a regression reports *which* registry came apart rather
#: than only that the sweep shrank.
ISSUE_647_OUTLIERS = (
    ('pcapkit.const.tcp.flags', 'Flags',
     'returned 65520, the OR of every declared TCP header flag'),
    ('pcapkit.const.ftp.command', 'CommandType',
     'returned 7, the OR of A|P|S'),
    ('pcapkit.const.reg.apptype.apptype', 'TransportProtocol',
     'returned 15, the OR of tcp|udp|sctp|dccp'),
    ('pcapkit.const.ftp.command', 'Command',
     "raised AttributeError: 'int' object has no attribute 'upper'"),
    ('pcapkit.const.ftp.command', 'FEATCode',
     "raised AttributeError: 'int' object has no attribute 'upper'"),
    ('pcapkit.const.http.method', 'Method',
     "raised AttributeError: 'int' object has no attribute 'upper'"),
)

#: The registries whose ``_missing_`` ends in :func:`~aenum.extend_enum`, so an
#: unassigned value in their span is *registered* rather than rejected. This is
#: the deliberate divergence from the built-in, not an oversight: their backing
#: registries carry open "Unassigned" spans that a capture can legitimately
#: contain. They still reject a *negative* value, which no span covers.
EXPECTED_TO_REGISTER = frozenset({
    'pcapkit.const.ipv4.protection_authority.ProtectionAuthority',
    'pcapkit.const.mh.cga_type.CGAType',
})

#: The bespoke templates under :mod:`pcapkit.vendor` that carry their own copy of
#: the guard, rather than inheriting the one in :mod:`pcapkit.vendor.default`.
#: Each was rendering a registry that GitHub issue #647 found unguarded.
#:
#: Keyed to each template's own guard text rather than one literal shared by
#: all four, kept as a dict rather than collapsed back to one shared literal:
#: GitHub issue #792 moved ``pcapkit.vendor.reg.apptype.apptype``'s copy to an
#: f-string first, deliberately leaving the other three on ``%`` so its own
#: diff over a 12,391-member file stayed reviewable, and GitHub issue #798
#: swept the remaining three onto the same f-string form. All four now agree,
#: but the dict stays: a future bespoke guard is not guaranteed to match this
#: one's shape, and what #647 actually needs pinned is that each template
#: still carries *a* guard rejecting an invalid value, not that every template
#: shares one literal.
BESPOKE_TEMPLATES = {
    'pcapkit.vendor.tcp.flags': "raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')",
    'pcapkit.vendor.ftp.command': "raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')",
    'pcapkit.vendor.http.method': "raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')",
    'pcapkit.vendor.reg.apptype.apptype': "raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')",
}

#: The pair GitHub issue #804 finished, as ``(vendor module, class name, const
#: module)``. Their templates are the two of :data:`BESPOKE_TEMPLATES`' four
#: that #798 left on ``%``-formatted ``__repr__`` methods.
ISSUE_804_PAIR = (
    ('pcapkit.vendor.ftp.command', 'Command', 'pcapkit.const.ftp.command'),
    ('pcapkit.vendor.http.method', 'Method', 'pcapkit.const.http.method'),
)

#: The three GitHub issue #818 finishes, as ``(vendor module, class name,
#: const module)`` -- the same shape as :data:`ISSUE_804_PAIR`, for the
#: ``__repr__`` methods #804 deliberately left out of its own scope.
#:
#: Derived by an :mod:`ast` walk over every ``__repr__`` under
#: :mod:`pcapkit.const`, not by trusting GitHub issue #818's own headline
#: count of eight: that count includes
#: ``pcapkit.const.http.{error_code,frame,setting}``, whose ``%`` lives in
#: their ``_missing_`` guard (inherited from the *shared*
#: :mod:`pcapkit.vendor.default` template) and which the issue's own last
#: comment split back out, plus ``pcapkit.const.reg.apptype.apptype`` (already
#: an f-string since #792, and off the table anyway while GitHub issue #815
#: owns that tree). What is left with an actual ``%``-formatted ``__repr__``
#: is exactly these three -- each its own bespoke vendor template, like
#: :data:`ISSUE_804_PAIR`'s pair, so each gets a const half and a vendor half.
ISSUE_818_TRIPLE = (
    ('pcapkit.vendor.ftp.return_code', 'ReturnCode', 'pcapkit.const.ftp.return_code'),
    ('pcapkit.vendor.http.status_code', 'StatusCode', 'pcapkit.const.http.status_code'),
    ('pcapkit.vendor.pcapng.option_type', 'OptionType', 'pcapkit.const.pcapng.option_type'),
)


def percent_format_lines_in_repr(source: 'str') -> 'list[int]':
    """Every ``%``-formatting line inside a ``def __repr__`` body, and nowhere else.

    Narrower than :func:`percent_format_lines`, which the four
    :data:`BESPOKE_TEMPLATES` const modules cannot use for this: all three of
    :data:`ISSUE_818_TRIPLE` still format their ``__str__`` and ``_missing_``
    with ``%``, deliberately -- GitHub issue #818 is about ``__repr__``
    specifically, not the module-wide sweep #804 already finished for its own
    pair. Walking only the ``__repr__`` :class:`ast.FunctionDef` is what makes
    that distinction possible; a whole-module :func:`percent_format_lines`
    would report the same nonzero count before and after this fix, because
    the ``__str__`` and ``_missing_`` sites it also matches are untouched by
    it either way.

    Args:
        source: Python source text.

    Returns:
        The 1-based line numbers, sorted and deduplicated.

    """
    lines = set()  # type: set[int]
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and node.name == '__repr__':
            for inner in ast.walk(node):
                if (isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.Mod)
                        and isinstance(inner.left, ast.Constant) and isinstance(inner.left.value, str)):
                    lines.add(inner.lineno)
    return sorted(lines)


#: Known-positive and known-negative fixtures for
#: :func:`percent_format_lines_in_repr`. The positive fixture also formats
#: with ``%`` in a sibling method, the property :func:`percent_format_lines`
#: cannot distinguish from the ``__repr__`` site and this function must.
REPR_PERCENT_WALK_FIXTURES = (
    ('a %-formatted __repr__, the pre-#818 shape',
     "class C:\n    def __repr__(self):\n        return '<%s>' % self.x\n"
     "    def __str__(self):\n        return '%s' % self.x\n", 1),
    ('an f-string __repr__, the post-#818 shape',
     "class C:\n    def __repr__(self):\n        return f'<{self.x}>'\n"
     "    def __str__(self):\n        return '%s' % self.x\n", 0),
    ('no __repr__ at all', "class C:\n    def __str__(self):\n        return '%s' % self.x\n", 0),
)


def percent_format_lines(source: 'str') -> 'list[int]':
    """Every line holding a ``<str literal> % <anything>`` expression.

    An :mod:`ast` walk over ``BinOp(Constant(str) % x)`` rather than a grep,
    because a grep has to commit to a quote style and every line GitHub issue
    #804 was about is **double**-quoted: the issue's own
    ``'[^']*%[sdr]`` pattern reported ``0`` for these very files. Self-tested
    against known-positive and known-negative fixtures by
    :meth:`ConstEnumGuardTemplateTests.test_self_check_of_the_percent_format_walk`
    before it is pointed at the tree.

    Note this deliberately does *not* see ``%`` inside a string literal, which
    is what the ``__repr__`` methods look like from inside a ``vendor``
    template -- there they are template text, not expressions. The issue's
    per-file table counted them textually and so reported ``3`` and ``2`` for
    the two vendor modules where this reports ``1`` each, those being the
    generators' own ``wrap_comment`` calls.

    Args:
        source: Python source text.

    Returns:
        The 1-based line numbers, sorted and deduplicated.

    """
    return sorted({
        node.lineno for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
        and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
    })


#: Known-positive and known-negative fixtures for :func:`percent_format_lines`,
#: as ``(label, source, expected hit count)``. Both quote styles appear on the
#: positive side, since quote-blindness is the property being asserted.
PERCENT_WALK_FIXTURES = (
    ("single-quoted %s", "x = '%s bar' % y\n", 1),
    ("double-quoted %s, as all of #804's were", 'x = "<%s [%s]>" % (a, b)\n', 1),
    ('double-quoted, inside a method body',
     "def f(self):\n    return \"<%s.%s>\" % (a, b)\n", 1),
    ('f-string, the converted form', "x = f'{y} bar'\n", 0),
    ('integer modulo, not formatting', 'x = 5 % 3\n', 0),
    ('a percent sign in a comment only', '# %s in a comment\nx = 1\n', 0),
    ('a percent sign in a plain literal', "x = '100%'\n", 0),
)


class _StdIntEnum(enum.IntEnum):
    """A built-in :class:`enum.IntEnum`, as the reference for what rejection looks like."""

    A = 0


class _StdStrEnum(str, enum.Enum):
    """A built-in string enumeration.

    Spelled ``(str, enum.Enum)`` rather than :class:`enum.StrEnum`, which is
    3.11+, because the CI matrix starts at 3.10.
    """

    A = 'a'


def _iter_const_registries() -> 'list[type]':
    """Every :class:`~aenum.Enum` subclass defined under :mod:`pcapkit.const`.

    Wider than either sweep in :mod:`tests.const.test_const_enum_lookup` --
    which walks the non-flag :class:`~aenum.IntEnum` classes and the
    :class:`~aenum.IntFlag` classes in two separate passes -- and wider than the
    one in :mod:`tests.const.test_const_enum_get`, which takes both but not the
    :class:`~aenum.StrEnum` registries. Rejecting an invalid value is a contract
    all three kinds share, so all three are swept here.

    Keyed on :class:`~aenum.Enum` deliberately: ``issubclass(aenum.IntFlag,
    aenum.IntEnum)`` is :data:`False`, because an
    :class:`~aenum.IntFlag`'s MRO runs through :class:`~aenum.Flag` rather than
    :class:`~aenum.IntEnum`, so a sweep written against
    :class:`~aenum.IntEnum` silently skips every flag registry -- which is how
    GitHub issue #623 survived the sweep in
    :mod:`tests.const.test_const_enum_lookup` and how three of issue #647's six
    outliers survived the one in :mod:`tests.const.test_const_enum_get`.

    Collects only classes *defined* in the module being walked, so a
    re-exported registry is counted once.

    Returns:
        The discovered enum classes, in walk order.

    """
    import pcapkit.const as const_pkg

    classes = []  # type: list[type]
    for module_info in pkgutil.walk_packages(const_pkg.__path__, const_pkg.__name__ + '.'):
        module = importlib.import_module(module_info.name)
        for _, obj in vars(module).items():
            if (inspect.isclass(obj) and issubclass(obj, aenum.Enum)
                    and obj.__module__ == module_info.name):
                classes.append(obj)
    return classes


def _qualname(obj: 'type') -> 'str':
    """The fully qualified name used as a sweep key."""
    return f'{obj.__module__}.{obj.__qualname__}'


def _raised_by(obj: 'type', value: 'object') -> 'Optional[type]':
    """The exception type ``obj(value)`` raises, or :data:`None` if it returns.

    Args:
        obj: Enumeration class to look a value up in.
        value: Value to look up.

    Returns:
        The exception's type, or :data:`None` when the lookup resolved.

    """
    try:
        obj(value)
    except BaseException as error:  # pylint: disable=broad-except
        return type(error)
    return None


class ConstEnumBuiltinParityTests(unittest.TestCase):
    """An invalid value must be rejected with the built-in's own exception."""

    if TYPE_CHECKING:
        enums: 'list[type]'

    @classmethod
    def setUpClass(cls) -> None:
        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        cls.enums = _iter_const_registries()
        # The out-of-range probe below registers a junk member on the two
        # auto-extending registries, which are module-global classes. Restore
        # the region to what it held before this class purged it, rather than
        # purging again (as this used to do, GitHub issue #720): a second purge
        # cannot achieve "pollution cannot reach another module" -- it just
        # leaves the region empty for whoever runs next, exactly the gap #720
        # reports, whereas restoring rebinds it straight back to the pristine,
        # pre-purge modules so the polluted ones are unreachable.
        cls.addClassCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

    def test_the_sweep_size_is_pinned(self) -> None:
        """A registry added or removed needs a fresh look, not a silent pass."""
        flags = [obj for obj in self.enums if issubclass(obj, aenum.Flag)]
        strs = [obj for obj in self.enums
                if issubclass(obj, str) and not issubclass(obj, aenum.Flag)]
        ints = [obj for obj in self.enums
                if issubclass(obj, int) and not issubclass(obj, aenum.Flag)]

        # The decomposition is asserted, not just the total, so this sweep stays
        # in step with the three narrower ones it overlaps: 111 non-flag IntEnum
        # and 7 IntFlag in tests.const.test_const_enum_lookup, and 118 -- their
        # sum -- in tests.const.test_const_enum_get.
        #
        # Five of the nine string registries are the application layer one, which
        # GitHub issue #732 split into a package: the memberless
        # pcapkit.const.reg.apptype.apptype.AppType base plus one registry per
        # transport protocol. It is discovered exactly like a member-bearing
        # registry, since this sweep is structural and never looks at members.
        self.assertEqual(len(ints), 111)
        self.assertEqual(len(flags), 7)
        self.assertEqual(len(strs), 9)
        self.assertEqual(len(self.enums), 127)
        self.assertEqual(len({obj.__module__ for obj in self.enums}), 121)

    def test_every_registry_rejects_a_negative_value(self) -> None:
        """The registry-wide form of GitHub issue #647.

        No wire field the library parses is signed, so ``-1`` is invalid for
        every registry in the tree -- including the mutable ones, whose
        "Unassigned" spans are non-negative.
        """
        for obj in self.enums:
            with self.subTest(enum=_qualname(obj)):
                raised = _raised_by(obj, -1)
                self.assertIsNotNone(
                    raised, f'{_qualname(obj)}(-1) resolved instead of raising; '
                            f'see GitHub issue #647')
                self.assertIs(
                    raised, ValueError,
                    f'{_qualname(obj)}(-1) raised {raised.__name__ if raised else None} '
                    f'rather than the built-in ValueError; see GitHub issue #647')

    def test_the_exception_type_matches_the_built_in_enum(self) -> None:
        """The property GitHub issue #647 settled on, asserted directly.

        A :mod:`pcapkit.const` registry and a built-in :class:`enum.IntEnum`
        must raise the *same* exception type for the same invalid value. This is
        what rules out the in-library
        :class:`~pcapkit.utilities.exceptions.EnumError`, which is
        ``(BaseError, TypeError)``: substituting it would leave this assertion
        failing on every registry in the tree.
        """
        self.assertIs(_raised_by(_StdIntEnum, -1), ValueError)
        self.assertIs(_raised_by(_StdStrEnum, -1), ValueError)

        for obj in self.enums:
            with self.subTest(enum=_qualname(obj)):
                builtin = _StdStrEnum if issubclass(obj, str) else _StdIntEnum
                self.assertIs(_raised_by(obj, -1), _raised_by(builtin, -1))

    def test_the_exception_is_not_an_in_library_one(self) -> None:
        """Explicitly *not* ``EnumError``, and explicitly not loud.

        :class:`~pcapkit.utilities.exceptions.BaseError` logs at CRITICAL from
        its constructor, so it fires even for an exception that is caught and
        discarded -- which the ``except ValueError`` fallback in every generated
        ``get()`` does on purpose. A guard raising a
        :class:`~pcapkit.utilities.exceptions.BaseError` subclass would log once
        per discarded default.
        """
        from pcapkit.utilities.exceptions import BaseError, EnumError

        # The reason EnumError is wrong here, asserted rather than asserted-in-prose.
        self.assertTrue(issubclass(EnumError, TypeError))
        self.assertFalse(issubclass(EnumError, ValueError))

        for obj in self.enums:
            with self.subTest(enum=_qualname(obj)):
                with self.assertRaises(ValueError) as caught:
                    obj(-1)
                self.assertNotIsInstance(caught.exception, BaseError)

    def test_an_out_of_range_value_is_rejected_unless_the_registry_registers_it(self) -> None:
        """A value past the registry's own width, which the guards bound."""
        for obj in self.enums:
            qualname = _qualname(obj)
            with self.subTest(enum=qualname):
                raised = _raised_by(obj, UNRESOLVABLE)
                if qualname in EXPECTED_TO_REGISTER:
                    self.assertIsNone(
                        raised, f'{qualname} no longer registers an unassigned value; '
                                f'see GitHub issues #584 and #647')
                else:
                    self.assertIs(raised, ValueError, f'{qualname}({UNRESOLVABLE}) raised '
                                                      f'{raised.__name__ if raised else None}')

    def test_the_registries_named_in_issue_647(self) -> None:
        """The six outliers, by name, with what each used to do."""
        for module_name, class_name, before in ISSUE_647_OUTLIERS:
            with self.subTest(enum=f'{module_name}.{class_name}', before=before):
                obj = getattr(importlib.import_module(module_name), class_name)

                with self.assertRaises(ValueError) as caught:
                    obj(-1)
                self.assertIn(class_name, str(caught.exception))
                self.assertIs(type(caught.exception), ValueError)

    def test_every_new_guard_is_a_classmethod(self) -> None:
        """``_missing_`` without ``@classmethod`` raises :exc:`TypeError` for everything.

        ``aenum`` invokes a failed lookup as ``cls._missing_(value)``, so a plain
        function binds ``value`` to ``cls`` and leaves ``value`` unfilled. GitHub
        issue #492 found two registries like that and
        ``ConstMissingClassmethodTests`` in
        :mod:`tests.const.test_const_enum_lookup` pins the fix -- but its sweep
        is ``_iter_const_int_enums``, which excludes :class:`~aenum.IntFlag`, and
        it never sees a :class:`~aenum.StrEnum` either. Every guard GitHub issue
        #647 added is on one of those two kinds, so all six would have been
        outside it.
        """
        checked = 0
        offenders = []  # type: list[str]
        for obj in self.enums:
            if '_missing_' not in vars(obj):
                continue
            checked += 1
            if not isinstance(vars(obj)['_missing_'], classmethod):
                offenders.append(_qualname(obj))

        self.assertGreater(checked, 0, 'sweep found no _missing_ overrides at all')
        self.assertEqual(offenders, [],
                         f'_missing_ without @classmethod (GitHub issue #492): {offenders}')

        # The six of issue #647 specifically, since the sweep above would still
        # pass if they had no ``_missing_`` at all -- which was the defect.
        for module_name, class_name, _ in ISSUE_647_OUTLIERS:
            obj = getattr(importlib.import_module(module_name), class_name)
            with self.subTest(enum=f'{module_name}.{class_name}'):
                self.assertIn('_missing_', vars(obj),
                              f'{module_name}.{class_name} defines no _missing_; '
                              f'see GitHub issue #647')
                self.assertIsInstance(vars(obj)['_missing_'], classmethod)

    def test_a_string_registry_rejects_a_non_string_rather_than_crashing(self) -> None:
        """The three ``StrEnum`` outliers reached ``value.upper()`` unguarded."""
        from pcapkit.const.ftp.command import Command, FEATCode
        from pcapkit.const.http.method import Method

        for obj in (Command, FEATCode, Method):
            for value in (-1, 0, 1.5, b'GET', None):
                with self.subTest(enum=_qualname(obj), value=value):
                    raised = _raised_by(obj, value)
                    self.assertIs(raised, ValueError,
                                  f'{_qualname(obj)}({value!r}) raised '
                                  f'{raised.__name__ if raised else None}')


class ConstFlagCompositeTests(unittest.TestCase):
    """A bounded flag registry must still compose the values it does define.

    The guard rejects out-of-range values and hands everything else to
    ``super()._missing_``. Getting that wrong in the other direction -- a guard
    narrow enough to reject a legitimate composite -- would break parsing for
    every packet with more than one flag set, and is exactly what the
    ``FLAG = 'isinstance(value, int) and 4 <= value <= 15'`` checker in
    :mod:`pcapkit.vendor.tcp.flags` would have done had the template ever
    interpolated it: those are *bit offsets*, and the values they generate are
    ``1 << offset``.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_tcp_flag_composites_resolve(self) -> None:
        from pcapkit.const.tcp.flags import Flags

        self.assertEqual(int(Flags(0)), 0)
        for first, second in (('PSH', 'ACK'), ('SYN', 'FIN'), ('RST', 'URG')):
            composite = int(Flags[first]) | int(Flags[second])
            with self.subTest(composite=hex(composite)):
                self.assertNotIn(composite, {member.value for member in Flags})
                self.assertEqual(int(Flags(composite)), composite)
                self.assertEqual(Flags(composite), Flags[first] | Flags[second])

        # Every declared bit at once is the widest legitimate value, and it is
        # what Flags(-1) used to return.
        every = 0
        for member in Flags:
            every |= int(member)
        self.assertEqual(every, 0xFFF0)
        self.assertEqual(int(Flags(every)), every)

        # One past the 16-bit field the registry indexes bits of.
        for beyond in (0x10000, -1, -0x10000, UNRESOLVABLE):
            with self.subTest(value=beyond):
                with self.assertRaises(ValueError):
                    Flags(beyond)

        # An unassigned low bit is in range and still composes, rather than
        # being rejected: bits 0-3 of that field are the data offset.
        self.assertEqual(int(Flags(1)), 1)

    def test_the_other_two_flag_registries_compose(self) -> None:
        from pcapkit.const.ftp.command import CommandType
        from pcapkit.const.reg.apptype import TransportProtocol

        self.assertEqual(int(CommandType(0)), 0)
        self.assertEqual(CommandType(0x07), CommandType.A | CommandType.P | CommandType.S)
        with self.assertRaises(ValueError):
            CommandType(0x08)

        self.assertEqual(int(TransportProtocol(0)), 0)
        self.assertEqual(TransportProtocol(0x0F),
                         TransportProtocol.tcp | TransportProtocol.udp
                         | TransportProtocol.sctp | TransportProtocol.dccp)
        with self.assertRaises(ValueError):
            TransportProtocol(0x10)

    @unittest.skipIf(sys.version_info < (3, 11), 'enum.STRICT is 3.11+')
    def test_a_bounded_flag_matches_the_built_in_under_its_strict_boundary(self) -> None:
        """Where the built-in flag parity claim actually lands.

        :class:`enum.IntFlag` defaults to ``boundary=KEEP`` and *composes* an
        out-of-range value rather than raising, so the parity being asserted for
        the flag registries is against the built-in's own reject mode,
        ``boundary=STRICT``. The exception type is the same either way, which is
        the property GitHub issue #647 is about; this test records that the
        choice to bound the domain at all is the built-in's ``STRICT``
        behaviour and not an invention.
        """
        from pcapkit.const.tcp.flags import Flags

        strict = enum.IntFlag('strict', {'FIN': 1 << 15}, boundary=enum.STRICT)  # type: ignore[misc]
        keep = enum.IntFlag('keep', {'FIN': 1 << 15}, boundary=enum.KEEP)  # type: ignore[misc]

        self.assertIs(_raised_by(strict, -1), ValueError)
        self.assertIs(_raised_by(Flags, -1), _raised_by(strict, -1))

        # And the default the library deliberately does not follow.
        self.assertIsNone(_raised_by(keep, -1))


class ConstEnumRegisterFallbackTests(unittest.TestCase):
    """The one sanctioned divergence: look up, miss, then register.

    In the owner's words, the const enums mirror the built-in "with one
    exception: they contain the missing then register fallback (mutable enums)".
    A guard that turned a registration into a rejection would be the regression
    GitHub issues #584 and #623 are both about, so it is pinned here rather than
    left to the guard tests above to imply.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def tearDown(self) -> None:
        # Every test here registers members on module-global classes.
        purge_modules(['pcapkit'])

    def test_a_string_registry_still_registers_an_unknown_name(self) -> None:
        from pcapkit.const.ftp.command import Command, FEATCode
        from pcapkit.const.http.method import Method

        for obj, unknown in ((Method, 'FROBNICATE'), (Command, 'XYZZY'), (FEATCode, '<zzzz>')):
            with self.subTest(enum=_qualname(obj), value=unknown):
                before = len(obj.__members__)
                registered = obj(unknown)
                self.assertGreater(len(obj.__members__), before,
                                   f'{_qualname(obj)}({unknown!r}) did not register; '
                                   f'see GitHub issue #647')
                self.assertIs(obj(unknown), registered)

    def test_a_string_registry_still_matches_case_insensitively(self) -> None:
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.http.method import Method

        for obj, lowered, member in ((Method, 'get', 'GET'), (Command, 'abor', 'ABOR')):
            with self.subTest(enum=_qualname(obj), value=lowered):
                before = len(obj.__members__)
                self.assertIs(obj(lowered), obj[member])
                self.assertEqual(len(obj.__members__), before,
                                 'a case-insensitive hit must not register a new member')

    def test_the_guard_leaves_the_other_lookup_paths_alone(self) -> None:
        """``get()`` is where the guard's rejection is caught, so it is checked too.

        The string path of a generated ``get`` never reaches ``_missing_`` at all,
        and the integer path reaches it inside a ``try``. Both are exercised here
        for the four modules GitHub issue #647 touched, so a guard that had
        broken either would fail rather than merely go unmeasured.
        """
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.http.method import Method
        from pcapkit.const.reg.apptype import TransportProtocol
        from pcapkit.const.tcp.flags import Flags

        # String paths, which bypass ``_missing_``.
        self.assertIs(Flags.get('SYN'), Flags.SYN)
        self.assertIs(Command.get('abor'), Command.ABOR)
        self.assertIs(Method.get('get'), Method.GET)
        self.assertIs(TransportProtocol.get('tcp'), TransportProtocol.tcp)

        # Integer paths, which do.
        self.assertIs(TransportProtocol.get(1), TransportProtocol.tcp)
        self.assertIs(Flags.get(1 << 14), Flags.SYN)

        # And the fallback the guard's ValueError is what triggers: GitHub issue
        # #584's ``get(key, default)``, which an EnumError would have walked past.
        self.assertEqual(int(Flags.get(UNRESOLVABLE, 0)), 0)
        with self.assertRaises(ValueError):
            Flags.get(UNRESOLVABLE)

    def test_the_auto_extending_integer_registries_still_extend(self) -> None:
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.const.mh.cga_type import CGAType

        for obj in (ProtectionAuthority, CGAType):
            with self.subTest(enum=_qualname(obj)):
                before = len(obj.__members__)
                registered = obj(UNRESOLVABLE)
                self.assertGreater(len(obj.__members__), before)
                self.assertEqual(int(registered), UNRESOLVABLE)

                # ... and still reject a value no span covers.
                with self.assertRaises(ValueError):
                    obj(-1)

    def test_apptype_still_registers_an_unassigned_port(self) -> None:
        """GitHub issue #584's machinery, which runs through ``_missing_``."""
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        registered = AppType.get(65000, proto=TransportProtocol.tcp)
        self.assertEqual(int(registered), 65000)
        self.assertIs(AppType.get(65000, proto=TransportProtocol.tcp), registered)

    def test_transport_protocol_can_still_be_extended_at_runtime(self) -> None:
        """Why this registry's bound is derived rather than written down.

        ``TransportProtocol.get`` registers an unknown protocol name at
        ``max * 2``, so a literal upper bound -- the shape the Mobility Header
        flag guards use -- would reject the very member the registry had just
        grown, and every composite containing it. The guard reads the bound off
        the current members instead, and this test is what pins that: it fails
        against a hard-coded ``0x0F``.
        """
        from pcapkit.const.reg.apptype import TransportProtocol

        self.assertNotIn('quic', TransportProtocol.__members__)
        with self.assertRaises(ValueError):
            TransportProtocol(0x10)

        grown = TransportProtocol.get('quic')
        self.assertEqual(int(grown), 0x10)
        self.assertIn('quic', TransportProtocol.__members__)

        # The new member composes with the old ones, which is the assertion a
        # literal bound fails.
        self.assertEqual(int(TransportProtocol(0x11)), 0x11)
        self.assertEqual(TransportProtocol(0x11), grown | TransportProtocol.tcp)

        # And the bound moved with it rather than disappearing.
        with self.assertRaises(ValueError):
            TransportProtocol(0x20)


class ConstEnumGuardTemplateTests(unittest.TestCase):
    """A regeneration must not undo the guard.

    :mod:`pcapkit.const` is generated from :mod:`pcapkit.vendor`, so the
    committed tree passing the tests above is not evidence that the templates
    agree with it -- the next crawl would simply revert them. The four templates
    below each carry their own copy of the guard rather than inheriting the one
    in :mod:`pcapkit.vendor.default`, which is why all four had to be edited and
    why all four are checked -- each against its own guard text in
    :data:`BESPOKE_TEMPLATES`, now that GitHub issue #798 finished moving all
    four off ``%`` formatting (GitHub issue #792 did the first).
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_every_bespoke_template_carries_the_guard(self) -> None:
        for module_name, guard in BESPOKE_TEMPLATES.items():
            with self.subTest(vendor=module_name):
                source = inspect.getsource(importlib.import_module(module_name))
                self.assertIn(
                    guard, source, f'{module_name} no longer emits its guard; '
                                   f'see GitHub issue #647')

    def test_no_bespoke_const_module_still_uses_percent_formatting_for_its_guard(self) -> None:
        """The committed side of :data:`BESPOKE_TEMPLATES`, needing no ``requests``.

        GitHub issue #798: the three vendor templates the previous test's
        ``skipUnless`` can silently skip -- exactly how #792's regression
        reached seven CI legs -- so this checks the same guards through the
        committed :mod:`pcapkit.const` modules instead, which need no network
        dependency to import. Asserts the *old* ``%``-style literal is gone
        rather than merely that a guard exists, so a half-converted template
        (old and new form both present) would still fail this.
        """
        old_guard = "raise ValueError('%r is not a valid %s' % (value, cls.__name__))"
        const_modules = (
            'pcapkit.const.tcp.flags',
            'pcapkit.const.ftp.command',
            'pcapkit.const.http.method',
            'pcapkit.const.reg.apptype.apptype',
        )
        for module_name in const_modules:
            with self.subTest(const=module_name):
                source = inspect.getsource(importlib.import_module(module_name))
                self.assertNotIn(
                    old_guard, source, f'{module_name} still raises its guard with '
                                        f'%% formatting; see GitHub issue #798')

    def test_the_disable_drops_only_where_nothing_else_needs_percent_formatting(self) -> None:
        """GitHub issue #798's third part, finished by #804: the disable is earned.

        All four bespoke const modules now carry no ``%``-formatted code, so
        all four drop their module-level ``consider-using-f-string``.
        ``pcapkit.const.tcp.flags`` and ``pcapkit.const.reg.apptype.apptype``
        got there under GitHub issue #803, once their guards -- and, for the
        latter, its three dunders and its span-handling tail -- were
        converted. ``pcapkit.const.ftp.command`` and
        ``pcapkit.const.http.method`` were *not* an oversight of #798, whose
        stated scope named only the ``AppType`` template's dunders; they were
        tracked as GitHub issue #804 and finished there, two ``__repr__``
        methods in the former and one in the latter being the last ``%`` in
        either file.

        This previously asserted the opposite for that pair -- that their
        disable was retained, and why -- so it fails against any tree where
        #804's conversion is missing or half-applied, which is the point.
        Asserts the absence of ``%`` anywhere in the source rather than only
        of the disable, since a file that dropped the disable while keeping a
        ``%`` would otherwise be caught by ``make pylint`` in CI instead of
        here.
        """
        dropped = (
            'pcapkit.const.tcp.flags',
            'pcapkit.const.reg.apptype.apptype',
            'pcapkit.const.ftp.command',
            'pcapkit.const.http.method',
        )
        for module_name in dropped:
            with self.subTest(const=module_name):
                source = inspect.getsource(importlib.import_module(module_name))
                self.assertNotIn('consider-using-f-string', source)
                self.assertNotIn('%', source)

    def test_self_check_of_the_percent_format_walk(self) -> None:
        """:func:`percent_format_lines` against known-positive and known-negative fixtures.

        GitHub issue #804's third trap: the grep that surveyed these files
        used ``'[^']*%[sdr]`` and reported ``0`` for both of them, because
        every surviving ``%`` line was double-quoted. A detector is worth
        nothing until it has been shown to fire on a positive it was given on
        purpose, so this runs first.
        """
        for label, source, expected in PERCENT_WALK_FIXTURES:
            with self.subTest(fixture=label):
                self.assertEqual(len(percent_format_lines(source)), expected)

        # And the naive grep, on the same double-quoted known-positive, to pin
        # *why* it read zero rather than merely asserting that it did.
        self.assertIsNone(re.search(r"'[^']*%[sdr]", 'x = "<%s [%s]>" % (a, b)\n'))

    def test_no_percent_formatting_survives_in_the_issue_804_pair(self) -> None:
        """Neither const module nor either generator still formats with ``%``.

        The maintainer's convention from GitHub issue #783: *"id like to keep
        f-string convention across the library. only use % substitution when
        inevitable."* A ``__repr__`` is not an inevitable case, and neither is
        a ``wrap_comment`` argument.

        Covers the vendor modules as well as the const ones because the tree
        is generated: a conversion that is not in the template is reverted by
        the next crawl. Fails against stock ``55e1b756e`` reporting four
        sites -- two in :file:`pcapkit/const/ftp/command.py`, one in
        :file:`pcapkit/const/http/method.py`, and one apiece in the two
        generators' ``process`` methods.
        """
        for vendor_name, _, const_name in ISSUE_804_PAIR:
            for module_name in (const_name, vendor_name):
                with self.subTest(module=module_name):
                    source = inspect.getsource(importlib.import_module(module_name))
                    self.assertEqual(
                        percent_format_lines(source), [],
                        f'{module_name} still formats with %; see GitHub issue #804')

    def test_the_converted_reprs_render_exactly_what_percent_formatting_did(self) -> None:
        """Member by member, the ``__repr__`` output is byte-identical.

        The conversion is only safe if ``%s`` and an f-string's default
        conversion agree on every operand these three dunders interpolate.
        They do -- ``format(x, '')`` falls through to ``str(x)`` for both
        :class:`str` and :data:`None`, and ``Command.desc`` is the one
        ``Optional[str]`` among them -- but GitHub issue #796's text claimed
        an equivalence in generated output that did not hold, so this derives
        the old form's output for every member rather than assuming the two
        forms agree.
        """
        from pcapkit.const.ftp.command import Command, FEATCode
        from pcapkit.const.http.method import Method

        for member in FEATCode:
            with self.subTest(enum='FEATCode', member=member.name):
                self.assertEqual(
                    repr(member),
                    "<%s [%s]>" % (member.__class__.__name__, member._name_))  # pylint: disable=consider-using-f-string,protected-access

        for member in Command:
            with self.subTest(enum='Command', member=member.name):
                self.assertEqual(
                    repr(member),
                    "<%s.%s: %s>" % (member.__class__.__name__,  # pylint: disable=consider-using-f-string
                                     member._name_, member.desc))  # pylint: disable=protected-access

        for member in Method:
            with self.subTest(enum='Method', member=member.name):
                self.assertEqual(
                    repr(member),
                    "<%s.%s>" % (member.__class__.__name__, member._value_))  # pylint: disable=consider-using-f-string,protected-access

        # A member whose ``desc`` is None reaches the one operand that is not
        # a str, since the sweep above cannot guarantee the committed registry
        # still contains one.
        grown = Command.get('XYZZY')
        self.assertIsNone(grown.desc)
        self.assertEqual(repr(grown), '<Command.XYZZY: None>')

    def test_the_converted_generators_emit_the_same_comment_text(self) -> None:
        """The two ``wrap_comment`` arguments, run rather than inspected.

        :meth:`test_no_percent_formatting_survives_in_the_issue_804_pair`
        proves these two lines no longer use ``%`` in the *source*; this
        proves the replacement produces the same text, which the
        render-and-diff below cannot reach because it supplies the
        enumeration block ready-made instead of crawling for it.

        Built with ``cls.__new__(cls)`` and a hand-set ``record``, the bypass
        :file:`tests/vendor/test_re_sub_positional_flag_unit.py` uses, since
        :meth:`~pcapkit.vendor.default.Vendor.__init__` fetches from IANA and
        writes :file:`pcapkit/const/` as a side effect of construction. The
        rows are synthetic -- never live IANA data.
        """
        vendor_ftp = importlib.import_module('pcapkit.vendor.ftp.command')
        command = vendor_ftp.Command.__new__(vendor_ftp.Command)
        command.record = collections.Counter()
        emitted = command.process([
            'h0,h1,h2,h3,h4,h5',
            'ABOR,base,Abort a transfer,s,m,[RFC959]',
        ])
        # The old form, derived here rather than hardcoded, so this compares
        # the two expressions rather than the new one against a guess.
        expected_ftp = command.wrap_comment('%s %s' % (  # pylint: disable=consider-using-f-string
            'Abort a transfer', '[:rfc:`959`]'))
        self.assertEqual(expected_ftp, "Abort a transfer [:rfc:`959`]")
        self.assertIn(f'#: {expected_ftp}', emitted[0])

        # ``desc`` is Optional[str], and ``%s`` renders None as 'None'; the
        # f-string has to agree, so the empty-description row is exercised too.
        emitted_none = command.process([
            'h0,h1,h2,h3,h4,h5',
            'ABOR,base,,s,m,[RFC959]',
        ])
        expected_none = command.wrap_comment('%s %s' % (None, '[:rfc:`959`]'))  # pylint: disable=consider-using-f-string
        self.assertEqual(expected_none, "None [:rfc:`959`]")
        self.assertIn(f'#: {expected_none}', emitted_none[0])

        vendor_http = importlib.import_module('pcapkit.vendor.http.method')
        method = vendor_http.Method.__new__(vendor_http.Method)
        method.record = collections.Counter()
        emitted = method.process([
            'h0,h1,h2,h3',
            'GET,yes,yes,"[RFC9110, Section 9.3.1]"',
        ])
        expected_http = method.wrap_comment(re.sub(
            r'\r*\n', ' ', '%s %s' % ('GET', '[:rfc:`9110#section-9.3.1`]'),  # pylint: disable=consider-using-f-string
            flags=re.MULTILINE))
        self.assertEqual(expected_http, 'GET [:rfc:`9110#section-9.3.1`]')
        self.assertIn(f'#: {expected_http}', emitted[0])

        # And the falsy-``rfcs`` branch, whose f-string form has to keep the
        # conditional inside the replacement field. ``wrap_comment`` drops the
        # trailing space ``'%s %s'`` leaves behind, so the expectation is
        # derived from the old form rather than written as ``'GET '``.
        emitted_norfc = method.process(['h0,h1,h2,h3', 'GET,yes,yes,'])
        expected_norfc = method.wrap_comment(re.sub(
            r'\r*\n', ' ', '%s %s' % ('GET', ''), flags=re.MULTILINE))  # pylint: disable=consider-using-f-string
        self.assertEqual(expected_norfc, 'GET')
        self.assertIn(f'#: {expected_norfc}\n', emitted_norfc[0])

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_issue_804_templates_render_the_committed_modules(self) -> None:
        """The whole file, character for character, for both of #804's pair.

        The same proof shape as
        :meth:`test_the_tcp_flags_template_renders_the_committed_module`,
        which GitHub issue #803 added for the other half of
        :data:`BESPOKE_TEMPLATES`. This is what makes a half-applied
        conversion -- template edited but generated file not, or the reverse
        -- fail here rather than at the next crawl, which is the failure mode
        GitHub issue #804's first trap names. Needs no network: the crawl
        supplies only the enumeration block, which is read back out of the
        committed module.
        """
        import pathlib

        from tests.const.test_const_enum_lookup import _normalize

        for vendor_name, cls_name, const_name in ISSUE_804_PAIR:
            with self.subTest(const=const_name):
                vendor_module = importlib.import_module(vendor_name)
                vendor_class = getattr(vendor_module, cls_name)

                const_module = importlib.import_module(const_name)
                committed = pathlib.Path(
                    const_module.__file__  # type: ignore[arg-type]
                ).read_text(encoding='utf-8')

                block = re.compile(
                    rf'class {cls_name}\(StrEnum\):\n    """.*?\n\n    (#:.*?)'
                    r'\n\n    @staticmethod', re.S)
                enum_block = block.search(committed)
                self.assertIsNotNone(enum_block, f'no enumeration block in {const_name}')

                rendered = _normalize(vendor_module.LINE(
                    vendor_class.__name__, vendor_class.__doc__,
                    enum_block.group(1),  # type: ignore[union-attr]
                    vendor_name,
                ))

                self.assertIn("def __repr__(self) -> 'str':", rendered)
                self.assertNotIn('consider-using-f-string', rendered)
                self.assertEqual(rendered, committed)

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_tcp_flags_template_renders_the_committed_module(self) -> None:
        """The whole file, character for character.

        Mirrors ``test_the_vendor_templates_still_emit_the_fix`` in
        :mod:`tests.const.test_const_enum_lookup`, which does this for the four
        Mobility Header templates. Needs no network: the crawl supplies only the
        enumeration block, which is read back out of the committed module.
        """
        import pathlib

        from tests.const.test_const_enum_lookup import _normalize

        vendor_module = importlib.import_module('pcapkit.vendor.tcp.flags')
        vendor_class = vendor_module.Flags

        const_module = importlib.import_module('pcapkit.const.tcp.flags')
        committed = pathlib.Path(
            const_module.__file__  # type: ignore[arg-type]
        ).read_text(encoding='utf-8')

        block = re.compile(
            r'class \w+\(IntFlag\):\n    """.*?"""\n\n    (.*?)\n\n    @staticmethod', re.S)
        enum_block = block.search(committed)
        self.assertIsNotNone(enum_block, 'no enumeration block in pcapkit.const.tcp.flags')

        rendered = _normalize(vendor_module.LINE(
            vendor_class.__name__, vendor_class.__doc__, vendor_class.FLAG,
            enum_block.group(1),  # type: ignore[union-attr]
            'pcapkit.vendor.tcp.flags',
        ))

        self.assertIn('return super()._missing_(value)', rendered)
        self.assertEqual(rendered, committed)

    @unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                         'pcapkit.vendor needs requests')
    def test_the_tcp_flags_checker_covers_the_value_domain_not_the_bit_offsets(self) -> None:
        """The checker the template used to drop, and why it could not be kept.

        ``Flags.FLAG`` read ``4 <= value <= 15`` -- the *offsets* the IANA
        registry indexes -- while the members it generates are ``1 << offset``.
        The template never interpolated it, so it was never wrong in practice;
        interpolating it unchanged would have rejected every composite, every
        single member above bit 3, and ``Flags(0)``.
        """
        from pcapkit.vendor.tcp.flags import Flags as VendorFlags

        checker = VendorFlags.FLAG
        self.assertIn('0xFFFF', checker)

        from pcapkit.const.tcp.flags import Flags

        for member in Flags:
            value = int(member)
            with self.subTest(member=member.name):
                self.assertTrue(eval(checker, {'value': value}),  # pylint: disable=eval-used
                                f'the checker rejects its own member {member.name}={value}')
                self.assertFalse(eval('isinstance(value, int) and 4 <= value <= 15',
                                      {'value': value}),  # pylint: disable=eval-used
                                 f'the old checker accepted {member.name}={value}')

    def test_self_check_of_the_repr_percent_format_walk(self) -> None:
        """:func:`percent_format_lines_in_repr` against its own fixtures.

        Run before the walk is pointed at real modules, same discipline as
        :meth:`test_self_check_of_the_percent_format_walk`: a detector that
        has not been shown to fire on a positive on purpose, and to stay
        quiet on a sibling method's own ``%``, is not trustworthy on the real
        tree either.
        """
        for label, source, expected in REPR_PERCENT_WALK_FIXTURES:
            with self.subTest(fixture=label):
                self.assertEqual(len(percent_format_lines_in_repr(source)), expected)

    def test_no_percent_formatting_survives_in_the_issue_818_triples_repr(self) -> None:
        """None of :data:`ISSUE_818_TRIPLE`'s three ``__repr__`` methods still format with ``%``.

        Scoped to ``__repr__`` alone via :func:`percent_format_lines_in_repr`,
        because unlike :data:`ISSUE_804_PAIR`'s pair, all three of these
        modules keep formatting their ``__str__`` and ``_missing_`` guard with
        ``%`` -- that is unrelated to GitHub issue #818, which is about
        ``__repr__`` specifically, and a whole-module check would never turn
        green. Fails against stock ``75c340413`` reporting one line apiece in
        the three const modules.

        The vendor half is checked separately, by
        :meth:`test_no_percent_formatting_survives_in_the_issue_818_triples_vendor_repr_template`,
        because there the ``__repr__`` source is template *text* inside an
        f-string, invisible to an outer :mod:`ast` walk -- exactly the trap
        GitHub issue #804's own fixtures were built to catch.
        """
        for _, _, const_name in ISSUE_818_TRIPLE:
            with self.subTest(const=const_name):
                source = inspect.getsource(importlib.import_module(const_name))
                self.assertEqual(
                    percent_format_lines_in_repr(source), [],
                    f'{const_name}.__repr__ still formats with %; see GitHub issue #818')

    def test_no_percent_formatting_survives_in_the_issue_818_triples_vendor_repr_template(self) -> None:
        """The vendor half: the ``__repr__`` line the ``LINE`` template emits.

        The generator's own module is not itself executing a ``%``-formatted
        ``__repr__`` -- it holds the *text* of one, inside a ``LINE = lambda
        ...: f'''...'''`` template, so an :mod:`ast` walk over the vendor
        module sees an ordinary f-string and nothing to flag. This checks the
        template's source text directly instead, the same distinction GitHub
        issue #804's own docstring draws between "template text" and
        "expression". Fails against stock ``75c340413``, whose three
        templates still hold ``return "<%s...>" % (...)`` verbatim.
        """
        for vendor_name, _, _ in ISSUE_818_TRIPLE:
            with self.subTest(vendor=vendor_name):
                source = inspect.getsource(importlib.import_module(vendor_name))
                repr_def = source[source.index("def __repr__(self) -> 'str':"):]
                repr_line = repr_def.splitlines()[1]
                self.assertNotIn('%', repr_line,
                                  f'{vendor_name} template still emits a %-formatted __repr__; '
                                  f'see GitHub issue #818')
                self.assertIn('f\'<', repr_line)

    def test_the_issue_818_triples_reprs_render_exactly_what_percent_formatting_did(self) -> None:
        """Member by member, the ``__repr__`` output is byte-identical.

        Same proof shape as
        :meth:`test_the_converted_reprs_render_exactly_what_percent_formatting_did`,
        derived per member rather than assumed: ``%s`` and an f-string's
        default conversion agree for :class:`str` and :class:`int` operands,
        which is all three of these interpolate (``__class__.__name__``,
        ``_value_``/``opt_name``, and -- for :class:`~pcapkit.const.pcapng
        .option_type.OptionType` -- ``opt_value``, an :class:`int` that
        ``%d`` and ``str()`` render identically for every non-negative value
        these registries carry).
        """
        from pcapkit.const.ftp.return_code import ReturnCode
        from pcapkit.const.http.status_code import StatusCode
        from pcapkit.const.pcapng.option_type import OptionType

        for member in ReturnCode:
            with self.subTest(enum='ReturnCode', member=member.name):
                self.assertEqual(
                    repr(member),
                    "<%s [%s]>" % (member.__class__.__name__, member._value_))  # pylint: disable=consider-using-f-string,protected-access

        for member in StatusCode:
            with self.subTest(enum='StatusCode', member=member.name):
                self.assertEqual(
                    repr(member),
                    "<%s [%s]>" % (member.__class__.__name__, member._value_))  # pylint: disable=consider-using-f-string,protected-access

        for member in OptionType:
            with self.subTest(enum='OptionType', member=member.name):
                self.assertEqual(
                    repr(member),
                    "<%s.%s: %d>" % (  # pylint: disable=consider-using-f-string
                        member.__class__.__name__, member.opt_name, member.opt_value))


if __name__ == '__main__':
    unittest.main()
