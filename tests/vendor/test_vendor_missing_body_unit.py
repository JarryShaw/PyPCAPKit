# -*- coding: utf-8 -*-
"""A hard-coded ``_missing_`` body must end in a ``return``, and no emitted
line may re-enter ``_missing_`` for the same value.

GitHub issue #866. A vendor crawler renders the body of the generated
registry's :meth:`~enum.Enum._missing_` as a list of source lines, held in the
local ``miss``. Guards against a crawler emitting a **two**-line body whose first
line calls :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
without returning it and whose second line is ``return cls(value)``::

    cls._unregistered_member(value, 'Unassigned')
    return cls(value)

That shape is harmless only while the first line is ``extend_enum(...)``, which
*registers* the member, so the following ``cls(value)`` finds it and returns.
``_unregistered_member`` deliberately does **not** register (#861) -- so
``cls(value)`` misses again, re-enters ``_missing_``, and recurses until
``RecursionError``. #866 found :mod:`pcapkit.vendor.pcapng.record_type` and
:mod:`pcapkit.vendor.pcapng.secrets_type` emitting it.

The invariant is deliberately not "every emitted line returns": the base
crawler itself emits legitimate non-returning lines for a range-guarded body.
:meth:`pcapkit.vendor.default.Vendor.process` renders such a body as three
lines -- an ``if`` header, a ``#:`` comment, then an indented ``return`` --
and only the third of the three returns::

    miss.append(f'if {start} <= value <= {stop}:')
    miss.append(f'    #: {desc}')
    miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")

Such bodies are routine rather than a corner case: crawlers across
:mod:`pcapkit.vendor` emit these non-returning lines, and registries under
:mod:`pcapkit.const` carry exactly that shape.
A crawler hard-coding a range-guarded body as a list literal is writing
something valid, so the guard below checks only that a hard-coded body
*ends* in a ``return`` and that no emitted line re-enters ``_missing_`` for
the same value -- not that every line returns.

A statement following a ``return`` in generated output is worth noticing on
its own: it means the generator that will overwrite the file disagrees with
what the file currently does. A generated file whose first line returns hides a
dead ``return cls(value)`` behind it, so its own tests stay green, while a
regeneration from the crawler reproduces the recursing two-line body -- which
is how #866 turned :file:`tests/const/test_const_enum_lookup.py`,
:file:`tests/const/test_const_enum_no_mint.py` and
:file:`tests/protocols/misc/test_pcapng_unit.py` red, all with
``RecursionError``.

The guard here is deliberately at the **crawler** layer rather than the
generated one. ``tests/const/test_const_enum_lookup.py`` exercises every
committed registry and catches the regression once a file is regenerated; the
source a crawler *emits* needs its own check, so a fix to a generated file
cannot silently disagree with the generator that will overwrite it. This module
needs no network and no regeneration: it reads the crawlers' own ASTs.

"""
from __future__ import annotations

import ast
import pathlib
import unittest

#: Test tier (#1958): checks the vendor templates' ``_missing_`` bodies against the
#: generated lookups.
__tier__ = 'LATEST'

#: Root of the vendor crawler package, as a path rather than an import, so this
#: module reads the same tree it is checked out in regardless of which
#: ``pcapkit`` an editable install happens to resolve.
VENDOR_ROOT = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit' / 'vendor'

#: Every crawler that emits at least one *hard-coded* line into ``miss`` as a
#: string-constant list literal, sorted, one per line, so that unrelated
#: additions land on different lines (#2615). Listed so a crawler that leaves
#: this shape -- switching to ``.append()``, or dropping its unassigned range --
#: or joins it fails by name, rather than shrinking or growing the sweep below
#: silently. A crawler in any other shape is invisible to this guard; see
#: :func:`_constant_miss_lines` for which, and
#: :file:`tests/const/test_const_enum_lookup.py` for their behavioural cover.
CRAWLERS_WITH_CONSTANT_MISS_LINES = (
    'pcapkit/vendor/icmp/destination_unreachable_code.py',
    'pcapkit/vendor/icmp/parameter_problem_code.py',
    'pcapkit/vendor/icmp/time_exceeded_code.py',
    'pcapkit/vendor/icmpv6/destination_unreachable_code.py',
    'pcapkit/vendor/icmpv6/parameter_problem_code.py',
    'pcapkit/vendor/icmpv6/time_exceeded_code.py',
    'pcapkit/vendor/igmp/record_type.py',
    'pcapkit/vendor/ipv4/classification_level.py',
    'pcapkit/vendor/ipv4/option_class.py',
    'pcapkit/vendor/ipv4/option_number.py',
    'pcapkit/vendor/ipv4/protection_authority.py',
    'pcapkit/vendor/ipv4/qs_function.py',
    'pcapkit/vendor/ipv4/tos_del.py',
    'pcapkit/vendor/ipv4/tos_ecn.py',
    'pcapkit/vendor/ipv4/tos_pre.py',
    'pcapkit/vendor/ipv4/tos_rel.py',
    'pcapkit/vendor/ipv4/tos_thr.py',
    'pcapkit/vendor/ipv4/ts_flag.py',
    'pcapkit/vendor/ipv6/option.py',
    'pcapkit/vendor/ipv6/option_action.py',
    'pcapkit/vendor/ipv6/qs_function.py',
    'pcapkit/vendor/ipv6/seed_id.py',
    'pcapkit/vendor/ipv6/smf_dpd_mode.py',
    'pcapkit/vendor/ipx/packet.py',
    'pcapkit/vendor/l2tp/type.py',
    'pcapkit/vendor/linux/arphrd.py',
    'pcapkit/vendor/mh/auth_subtype.py',
    'pcapkit/vendor/mh/binding_error.py',
    'pcapkit/vendor/mh/cga_type.py',
    'pcapkit/vendor/mh/dhcp_support_mode.py',
    'pcapkit/vendor/mh/enumerating_algorithm.py',
    'pcapkit/vendor/mh/lla_code.py',
    'pcapkit/vendor/mh/option.py',
    'pcapkit/vendor/mh/packet.py',
    'pcapkit/vendor/pcapng/filter_type.py',
    'pcapkit/vendor/pcapng/hash_algorithm.py',
    'pcapkit/vendor/pcapng/option_type.py',
    'pcapkit/vendor/pcapng/record_type.py',
    'pcapkit/vendor/pcapng/secrets_type.py',
    'pcapkit/vendor/pcapng/verdict_type.py',
    'pcapkit/vendor/radiotap/field_type.py',
    'pcapkit/vendor/reg/linktype.py',
    'pcapkit/vendor/sslv2/handshake_type.py',
    'pcapkit/vendor/sslv2/version.py',
    'pcapkit/vendor/tcp/checksum.py',
    'pcapkit/vendor/vlan/priority_level.py',
)


def _constant_miss_lines() -> 'dict[str, list[str]]':
    """Collect every constant line each crawler assigns to ``miss``.

    Returns a mapping of repository-relative crawler path to the list of
    string constants in its ``miss`` list literal. A crawler that builds
    ``miss`` by ``.append()``, assigns it from a comprehension or a variable,
    names it otherwise, or never returns an ``(enum, miss)`` pair at all, is
    absent from the returned mapping entirely -- not present with an empty
    list. That is every other crawler module defining ``process()``, not just the
    examples this docstring names
    (:mod:`pcapkit.vendor.reg.ethertype`, :mod:`pcapkit.vendor.ipx.socket`);
    see :data:`CRAWLERS_WITH_CONSTANT_MISS_LINES` for the ones present.
    They are covered behaviourally, not statically, by
    :file:`tests/const/test_const_enum_lookup.py`.

    """
    found = {}  # type: dict[str, list[str]]
    for path in sorted(VENDOR_ROOT.rglob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == 'miss' for t in node.targets):
                continue
            if not isinstance(node.value, ast.List):
                continue
            lines = [elt.value for elt in node.value.elts
                     if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
            if lines:
                found[str(path.relative_to(VENDOR_ROOT.parents[1]))] = lines
    return found


class VendorMissingBodyTests(unittest.TestCase):
    """Static guards over what the crawlers render into ``_missing_``."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.miss_lines = _constant_miss_lines()  # type: ignore[attr-defined]

    def test_the_sweep_matches_the_list(self) -> None:
        """A crawler leaving or joining the sweep must be deliberate."""
        found = set(self.miss_lines)  # type: ignore[attr-defined]
        listed = set(CRAWLERS_WITH_CONSTANT_MISS_LINES)
        self.assertEqual({'joined': sorted(found - listed), 'left': sorted(listed - found)},
                         {'joined': [], 'left': []},
                         'the crawlers that emit a constant ``_missing_`` body differ '
                         'from CRAWLERS_WITH_CONSTANT_MISS_LINES, which lists each one '
                         'whose body has been checked to end in a return')

    def test_the_list_is_sorted_and_unique(self) -> None:
        """Sorted, so that unrelated additions land on different lines (#2615)."""
        self.assertEqual(list(CRAWLERS_WITH_CONSTANT_MISS_LINES),
                         sorted(set(CRAWLERS_WITH_CONSTANT_MISS_LINES)))

    def test_the_hard_coded_body_ends_in_a_return(self) -> None:
        """The invariant #866 is about, restated to the shape that is true.

        Not every emitted line has to ``return`` -- the range-guarded shape
        in :meth:`pcapkit.vendor.default.Vendor.process` legitimately emits
        an ``if`` header and a ``#:`` comment before its ``return``, and many
        crawlers do exactly that (see the module docstring). What has to be
        true is narrower: a hard-coded body must *end* on a ``return``, so
        control never falls off the end of ``miss`` into a fallthrough.

        This test does **not** catch #866 on its own: #866's body ended on
        ``return cls(value)``, which does return, so it passes this check
        either way. It is
        :meth:`test_no_crawler_emits_a_self_recursive_lookup` that catches
        the cycle -- this test only guards against a body that does not
        return at all.

        """
        for crawler, lines in sorted(self.miss_lines.items()):  # type: ignore[attr-defined]
            last = lines[-1]
            with self.subTest(crawler=crawler, line=last):
                self.assertTrue(last.lstrip().startswith('return '),
                                f'{crawler} ends its hard-coded ``_missing_`` body on '
                                f'{last!r}, which does not return; a body that falls '
                                f'through does nothing observable, see GitHub issue #866')

    def test_no_crawler_emits_a_self_recursive_lookup(self) -> None:
        """``return cls(value)`` inside ``_missing_`` is unconditionally wrong.

        Named separately from :meth:`test_the_hard_coded_body_ends_in_a_return`
        because this line *does* return and so passes that check, yet re-enters
        ``_missing_`` for the same value. It was the second half of #866's
        two-line body and is the line that actually recursed.

        """
        for crawler, lines in sorted(self.miss_lines.items()):  # type: ignore[attr-defined]
            for line in lines:
                with self.subTest(crawler=crawler, line=line):
                    self.assertNotEqual(line.replace(' ', ''), 'returncls(value)',
                                        f'{crawler} emits ``return cls(value)`` inside '
                                        f'``_missing_``, which re-enters ``_missing_`` '
                                        f'for the same value; see GitHub issue #866')

    def test_the_record_and_secrets_type_crawlers_emit_a_single_returning_line(self) -> None:
        """The specific pair from #866, pinned by name.

        Kept alongside the general sweeps because these are the crawlers #866
        was filed against, and a named test says which file to look at
        without having to read a subTest label.

        """
        for crawler in ('pcapkit/vendor/pcapng/record_type.py',
                        'pcapkit/vendor/pcapng/secrets_type.py'):
            with self.subTest(crawler=crawler):
                lines = self.miss_lines[crawler]  # type: ignore[attr-defined]
                self.assertEqual(
                    lines, ["return cls._unregistered_member(value, 'Unassigned')"],
                    f'{crawler} must emit exactly one returning line')


class RegeneratedRegistryLookupTests(unittest.TestCase):
    """The behaviour the broken body produced, pinned on the generated files.

    :file:`tests/const/test_const_enum_lookup.py` sweeps every registry and so
    already covers this; these two cases are named for #866 so the reported
    symptom is findable from the issue number.

    """

    def test_record_type_resolves_an_unassigned_value(self) -> None:
        from pcapkit.const.pcapng.record_type import RecordType

        member = RecordType(0xFFFF)
        self.assertEqual(member.name, 'Unassigned')
        self.assertEqual(int(member), 0xFFFF)
        self.assertNotIn('Unassigned', RecordType.__members__)

    def test_secrets_type_resolves_an_unassigned_value(self) -> None:
        from pcapkit.const.pcapng.secrets_type import SecretsType

        member = SecretsType(0)
        self.assertEqual(member.name, 'Unassigned')
        self.assertEqual(int(member), 0)
        self.assertNotIn('Unassigned', SecretsType.__members__)


if __name__ == '__main__':
    unittest.main()
