# -*- coding: utf-8 -*-
"""``Method.get`` must be case-sensitive, per RFC 9110 Section 9.1.

GitHub issue #896: :meth:`pcapkit.const.http.method.Method.get` used to
upper-case its ``key`` before looking it up (``name = key.upper()``, then
``name not in Method._member_map_``), so ``Method.get('get')`` resolved to
the same object as ``Method.get('GET')`` -- :attr:`Method.GET`. RFC 9110
Section 9.1 says the opposite is required::

    The method token is case-sensitive because it might be used as a gateway
    to object-based systems with case-sensitive method names. By convention,
    standardized methods are defined in all-uppercase US-ASCII letters.

so a request whose method token is the lower-case ``get`` is a distinct,
non-standardised method from the registered ``GET`` -- conflating the two
was the defect. Contrast :class:`~pcapkit.const.ftp.command.Command`'s own
equivalent override, which stays case-insensitive deliberately: RFC 959
Section 4.1 says FTP's four-letter command codes *are* to be treated
identically regardless of case, so ``Command.get`` is untouched by this
issue and is repinned below (:meth:`MethodGetCaseSensitivityTests.
test_command_get_stays_case_insensitive`) so a future change cannot quietly
fold the two together again.

**What the fix is not.** The issue's own suggested mechanism was to delete
``Method.get`` outright and let :meth:`~pcapkit.corekit.enum.EnumRegistry.get`
(the base every ``EnumRegistry`` mixin shares) handle it instead. Measured
directly against the base before doing that: for a ``str`` key that matches
neither a member name nor an already-registered value, and with no
``default`` supplied, ``EnumRegistry.get`` raises :exc:`KeyError` -- it never
builds an unregistered member the way ``Method._missing_`` does for the
*constructor* path. Confirmed on :class:`~pcapkit.const.ftp.command.FEATCode`,
which ran the base unmodified when this was measured -- GitHub issue #903's
audit has since given it a case-insensitive ``get`` of its own per
:rfc:`5797#section-2`, and the measurement still stands, because that override
delegates to the base for any key it cannot match even after folding:
``FEATCode.get('totally-unknown-thing')`` raises ``KeyError``, while
``FEATCode('totally-unknown-thing')`` -- the constructor, reaching
``_missing_`` -- resolves to an unregistered member. Deleting ``Method.get``
outright would therefore have turned ``Method.get('get')`` from "resolves to
``GET``" into "raises ``KeyError``", not into "resolves to an unregistered
member preserving ``'get'``" as the issue's own *expected behaviour* section
asks for -- and as :mod:`tests.protocols.application.test_http_unit` and
:mod:`tests.const.test_const_enum_no_mint` already require elsewhere in this
change. So the fix keeps ``Method``'s own ``get`` override -- it still needs
to build that unregistered member on a miss, which the base's ``get`` does
not do for a ``str`` key -- and only removes the ``.upper()`` folding from
the *match* it performs before falling through to that fallback. The
``_unregistered_member`` call it falls through to still canonicalises the
*name* (the identifier) to upper case, exactly as :meth:`Method._missing_`
does; only the *value* -- and now, the match against a *registered* name --
keeps the caller's exact casing.

This module also pins the crawler and the generated file against each
other, the way :mod:`tests.const.test_const_enum_get`'s own
``test_the_vendor_template_still_emits_the_fix`` does for a different
registry: :mod:`pcapkit.const` is generated from :mod:`pcapkit.vendor`, so a
fix applied only to the generated file is silently discarded by the next
crawl. Unlike that sibling test, :class:`~pcapkit.const.http.method.Method`'s
own ``get`` is rendered from a template private to
:mod:`pcapkit.vendor.http.method` itself (its own ``LINE`` lambda), not from
the shared one in :mod:`pcapkit.vendor.default` -- so the parity check here
renders that module's own template with a CSV fixture reconstructed from the
40 members the committed file already declares, offline, and compares the
result against the committed file byte for byte, rather than against a
synthetic single-member sample.

"""
from __future__ import annotations

import csv
import inspect
import io
import re
import unittest

from tests._support import reimport_once_per_class


def _reconstruct_fixture_csv() -> 'str':
    """Rebuild the IANA-shaped CSV that reproduces the committed generated
    file byte for byte, by reading the members and comments already in
    :mod:`pcapkit.const.http.method` back into ``Method Name,Safe,
    Idempotent,Reference`` rows.

    This is the offline substitute for a live crawl against
    ``https://www.iana.org/assignments/http-methods/methods.csv``, which
    this change must not perform. Faithfulness is what
    :meth:`MethodGetCaseSensitivityTests.
    test_vendor_template_matches_the_generated_module` below checks: feeding
    this fixture back through :meth:`~pcapkit.vendor.http.method.Method.
    context` must reproduce the committed generated file byte for byte, not
    merely render something self-consistent.

    Returns:
        CSV text, ``\\r\\n``-terminated, matching what
        :meth:`~pcapkit.vendor.default.Vendor.request` expects.

    """
    import pcapkit.const.http.method as const_method

    src = inspect.getsource(const_method)

    start_marker = ("    def __repr__(self) -> 'str':\n"
                     "        return f'<{self.__class__.__name__}.{self._value_}>'\n\n")
    start = src.index(start_marker) + len(start_marker)
    end_marker = "\n    @classmethod\n    def _unregistered_member"
    end = src.index(end_marker, start)
    enum_block = src[start:end]

    rows = []  # type: list[tuple[str, str, str, str]]
    for chunk in enum_block.split('\n\n'):
        lines = [line for line in chunk.split('\n') if line.strip()]
        comment_lines = [line for line in lines if line.strip().startswith('#:')]
        code_lines = [line for line in lines if not line.strip().startswith('#:')]
        if not code_lines:
            continue
        match = re.match(r"^\s*(\w+) = '([^']*)', (True|False), (True|False)$", code_lines[0])
        assert match is not None, code_lines[0]
        _name, value, safe_flag, idem_flag = match.groups()

        desc = ' '.join(line.strip()[3:] for line in comment_lines)
        assert desc.startswith(value), (desc, value)
        rest = desc[len(value):].lstrip(' ')

        rfcs = ''
        if rest:
            groups = re.findall(r'\[([^\[\]]*)\]', rest)
            assert ''.join(f'[{g}]' for g in groups) == rest, (groups, rest)
            parts = []  # type: list[str]
            for group in groups:
                rfc_match = re.match(r'^:rfc:`(\d+)(?:#([a-z0-9.\-]+))?`$', group)
                if rfc_match is None:
                    parts.append('[' + group.replace(' ', '_') + ']')
                    continue
                num, section = rfc_match.groups()
                if section is None:
                    parts.append(f'[RFC{num}]')
                else:
                    section = section[len('section'):].lstrip('-').replace('-', ' ')
                    parts.append(f'[RFC{num}, Section {section}]')
            rfcs = ''.join(parts)

        rows.append((value,
                     'yes' if safe_flag == 'True' else 'no',
                     'yes' if idem_flag == 'True' else 'no',
                     rfcs))

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator='\r\n')
    writer.writerow(['Method Name', 'Safe', 'Idempotent', 'Reference'])
    writer.writerows(rows)
    return buf.getvalue()


class MethodGetCaseSensitivityTests(unittest.TestCase):
    """The direct repro and fix for GitHub issue #896."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_get_exact_case_resolves_the_standardised_member(self) -> None:
        """The unaffected half: the registered, all-uppercase casing every
        member is actually declared under still resolves to it."""
        from pcapkit.const.http.method import Method

        self.assertIs(Method.get('GET'), Method.GET)
        self.assertTrue(Method.get('GET').safe)
        self.assertTrue(Method.get('GET').idempotent)

    def test_get_lowercase_does_not_resolve_to_the_standard_member(self) -> None:
        """The issue's own repro: ``Method.get('get')`` must stop resolving
        to :attr:`Method.GET`.

        Fails against the pre-fix override (``name = key.upper()`` folded
        into the ``_member_map_`` membership test): there,
        ``Method.get('get') is Method.GET`` is :data:`True`.
        """
        from pcapkit.const.http.method import Method

        probed = Method.get('get')
        self.assertIsNot(probed, Method.GET)
        self.assertNotEqual(probed, 'GET')

    def test_unregistered_member_preserves_the_callers_casing(self) -> None:
        """The value of the unregistered member ``get('get')`` now builds is
        exactly what the caller passed -- never upper-cased -- matching the
        convention :meth:`~pcapkit.const.http.method.Method.
        _unregistered_member` documents and :class:`~pcapkit.const.ftp.
        command.FEATCode` already follows. Only the *name* (the identifier,
        not the value) is canonicalised.
        """
        from pcapkit.const.http.method import Method

        before = len(Method.__members__)
        for key in ('get', 'Get', 'gEt', 'GeT'):
            with self.subTest(key=key):
                probed = Method.get(key)
                self.assertEqual(probed.value, key)
                self.assertEqual(str(probed), key)
                self.assertEqual(probed.name, key.upper())
                # Building the pseudo-member never registers it -- 'GET'
                # itself stays the only real member this loop's names could
                # collide with, and membership does not grow.
                self.assertEqual(len(Method.__members__), before)

        # Two calls naming the same method in different case build results
        # that are genuinely unequal -- each is exactly its own caller's
        # casing, not folded onto a shared cached member.
        self.assertNotEqual(Method.get('frob'), Method.get('FROB'))
        self.assertNotEqual(Method.get('frob'), Method.get('Frob'))

    def test_command_get_stays_case_insensitive(self) -> None:
        """The registry #896 explicitly leaves alone.

        RFC 959 Section 4.1: FTP command codes are to be treated
        identically regardless of case, so
        :meth:`~pcapkit.const.ftp.command.Command.get` keeps folding case --
        pinned here so a future edit to the sibling ``Method`` fix cannot
        silently carry the case-sensitive change over to ``Command`` too.
        It is also the only pin of GitHub issue #582 (``Command.get('abor')``
        must resolve), which
        :class:`tests.const.test_const_enum_no_mint.BespokeGetUnchangedTests`
        relies on rather than repeating.
        """
        from pcapkit.const.ftp.command import Command

        for key in ('RETR', 'retr', 'ReTr', 'rEtR'):
            with self.subTest(key=key):
                self.assertIs(Command.get(key), Command.RETR)

    def test_vendor_template_matches_the_generated_module(self) -> None:
        """A regeneration must not undo the fix, and must not have been
        needed to introduce it in the first place.

        Renders :mod:`pcapkit.vendor.http.method`'s own template with a CSV
        fixture reconstructed from the *committed* generated file (no
        network access), and requires the result to match that same file
        byte for byte -- proving the crawler template, not just the
        generated file alone, carries the fix.
        """
        import pcapkit.const.http.method as const_method
        import pcapkit.vendor.http.method as vendor_method

        csv_text = _reconstruct_fixture_csv()

        inst = object.__new__(vendor_method.Method)
        inst.NAME = 'Method'
        inst.DOCS = vendor_method.Method.__doc__
        data = inst.request(csv_text)
        rendered_ctx = inst.context(data)

        temp_ctx = []  # type: list[str]
        for line in rendered_ctx.splitlines():
            if line:
                if line.strip():
                    temp_ctx.append(line.rstrip())
            else:
                temp_ctx.append(line)
        rendered = '\n'.join(temp_ctx) + '\n'

        with open(const_method.__file__, encoding='utf-8') as handle:
            committed = handle.read()

        self.assertEqual(rendered, committed)

        # And the fix itself is actually present in both -- a byte-identical
        # comparison above already implies this, but names the exact shape
        # so a failure here is legible without a diff. GitHub issue #908
        # moved ``get`` from testing ``_member_map_`` by hand to delegating
        # to the base's own ``get`` (which also checks
        # ``_value2member_map_``), so the markers pinned here moved with it
        # -- see tests.const.test_const_method_value_lookup_908_unit for
        # that change's own dedicated coverage.
        for label, source in (('template render', rendered), ('generated module', committed)):
            with self.subTest(rendering=label):
                self.assertIn('return super().get(key)', source)
                self.assertIn(
                    'return cls._unregistered_member(default if default is not None '
                    "else key, key.upper())", source)
                self.assertNotIn('if key not in Method._member_map_', source)
                self.assertNotIn('return Method[key]', source)

    def test_regenerating_twice_is_byte_reproducible(self) -> None:
        """The same fixture fed to the same template twice must render
        identically -- the reproducibility the vendor crawler promises for
        any fixed input, checked directly rather than assumed."""
        import pcapkit.vendor.http.method as vendor_method

        csv_text = _reconstruct_fixture_csv()

        def render() -> 'str':
            inst = object.__new__(vendor_method.Method)
            inst.NAME = 'Method'
            inst.DOCS = vendor_method.Method.__doc__
            data = inst.request(csv_text)
            return inst.context(data)

        self.assertEqual(render(), render())


if __name__ == '__main__':
    unittest.main()
