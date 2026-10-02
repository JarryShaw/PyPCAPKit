# -*- coding: utf-8 -*-
"""``FEATCode.get`` must be case-insensitive, per RFC 5797 Section 2.

GitHub issue #903, the registry-wide case-sensitivity audit. Of the 127
registries under :mod:`pcapkit.const` and the 24 non-registry enumerations
elsewhere, :class:`~pcapkit.const.ftp.command.FEATCode` is the one the audit
found on the wrong side of the owner's ruling: it did no case folding at all,
so it ran the case-sensitive default, while the document defining the very
registry it is generated from states the *opposite* comparison rule outright.

RFC 5797 Section 2, describing the ``FEAT Code`` column of the IANA "FTP
Commands and Extensions" registry that
:class:`pcapkit.vendor.ftp.command.Command` crawls::

    ... but otherwise IANA maintains uniqueness of feature names (FEAT codes)
    based on case-insensitive comparison.

That is the strict limb of the criterion -- a comparison rule in the spec --
and the lenient limb holds too. RFC 2389 Section 3.2, which defines the
``FEAT`` response these codes appear in::

    The feature-label and feature-parms are nominally case sensitive, however
    the definitions of specific labels and parameters specify the precise
    interpretation, and it is to be expected that those definitions will
    usually specify the label and parameters in a case independent manner.
    Where this is done, implementations are recommended to use upper case
    letters when transmitting the feature response.

so a caller holding a line off a ``FEAT`` response holds upper case *by the
RFC's own recommendation*, while the registry spells 5 of its 15 codes in
lower case -- because RFC 5797 uses case presentationally, to tell a
registered keyword from a placeholder::

    ... defined FEAT keywords codes are listed in all uppercase, whereas
    placeholder keywords (henceforth called "pseudo FEAT codes") are listed
    in lowercase.

Measured on the live registry CSV while auditing: of 64 rows, 11 carry an
all-upper-case code (10 distinct -- ``AUTH``, ``HOST``, ``MDTM``, ``MLST``,
``PBSZ``, ``PROT``, ``REST``, ``SIZE``, ``TVFS``, ``UTF8``), 52 carry an
all-lower-case one (5 distinct -- ``base``, ``feat``, ``hist``, ``nat6``,
``secu``), 1 is blank, and **none** is mixed. So the two authorities
disagree about the casing of the same field, which is exactly the shape the
owner's ruling on this issue treats as case-insensitive. He chose the lenient
reading of the criterion, with ``TransportProtocol`` as his example: when the
RFC and IANA themselves use upper and lower case for the same field, that mix
is itself an indication of case insensitivity.

**Pre-change behaviour, measured before the fix** (throwaway process, no
probe that could mint; ``_member_map_`` and ``_value2member_map_`` both 15
entries before and after)::

    FEATCode.get('base'  ) -> <FEATCode [base]>   value='<base>'
    FEATCode.get('BASE'  ) -> KeyError: 'BASE'
    FEATCode.get('Base'  ) -> KeyError: 'Base'
    FEATCode.get('<base>') -> <FEATCode [base]>   value='<base>'
    FEATCode.get('<BASE>') -> KeyError: '<BASE>'
    FEATCode.get('AUTH'  ) -> <FEATCode [AUTH]>   value='AUTH'
    FEATCode.get('auth'  ) -> KeyError: 'auth'
    FEATCode.get('Auth'  ) -> KeyError: 'Auth'

**What the fix deliberately does not do.** It does not fold the stored members,
and it does not rename one. Every member keeps the registrar's own casing, per
the ruling on #877 that the *House Conventions* page records -- enumerations
keep the registrars' own writing, and case-insensitivity is kept for the
selected registries where it makes logical sense and/or the RFC itself treats
the values as case-insensitive -- so ``FEATCode.get('BASE').name`` is still
``'base'`` and still says *placeholder*. Nor does it fold the *value* a lookup
resolves to, which is what would have made the fold lossy. Only the inbound key
is folded, and only after an exact name-or-value match has already missed, so
:meth:`~pcapkit.corekit.enum.EnumLookup.get`'s own precedence (name before
value) and its non-minting ``str`` path both survive untouched. RFC 5797's
uniqueness rule is what makes the fold unambiguous rather than merely
convenient: a registered ``BASE`` cannot coexist with the placeholder ``base``,
so there is no second member for the fold to hide -- pinned below by
:meth:`FEATCodeCaseFoldSafetyTests.test_no_two_members_collide_when_folded`.

**Contrast, pinned so the default is not quietly widened.** The audit's other
``str``-valued registries stay case-sensitive and each has a reason:
:class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel`, whose RFC 9850
Section 4.2 registry and live IANA CSV agree on upper case in all 10 rows
with no comparison rule stated anywhere, is measured below as the witness
that the base is untouched by this change.
"""

import inspect
import unittest

from pcapkit.const.ftp.command import Command, FEATCode
from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel

#: The 5 placeholder ("pseudo FEAT code") members, registered in lower case
#: per RFC 5797 Section 2, with the ``<...>`` value form the crawler emits.
PSEUDO_CODES = ('base', 'hist', 'secu', 'feat', 'nat6')

#: The 10 genuine FEAT keywords, registered in upper case per the same section.
REAL_CODES = ('AUTH', 'HOST', 'UTF8', 'MDTM', 'MLST', 'PBSZ', 'PROT', 'REST',
              'SIZE', 'TVFS')


class FEATCodeCaseInsensitiveLookupTests(unittest.TestCase):
    """``get`` resolves a FEAT code whatever case the caller spells it in."""

    def test_a_lower_case_placeholder_resolves_from_upper_case(self) -> 'None':
        """The issue's repro. ``get('BASE')`` used to raise ``KeyError``.

        Upper case is what RFC 2389 Section 3.2 recommends implementations
        transmit, so this is the casing a caller reading a real ``FEAT``
        response is most likely to hold.

        """
        for key in ('BASE', 'Base', 'bAsE', 'base'):
            with self.subTest(key=key):
                self.assertIs(FEATCode.get(key), FEATCode.base)  # type: ignore[attr-defined]

    def test_every_placeholder_resolves_from_either_case(self) -> 'None':
        """All 5 of them, not just the one the issue names."""
        for name in PSEUDO_CODES:
            member = FEATCode[name]
            for key in (name, name.upper(), name.capitalize()):
                with self.subTest(code=name, key=key):
                    self.assertIs(FEATCode.get(key), member)

    def test_an_upper_case_keyword_resolves_from_lower_case(self) -> 'None':
        """The fold runs in both directions, not only lower -> upper."""
        for name in REAL_CODES:
            member = FEATCode[name]
            for key in (name, name.lower(), name.capitalize()):
                with self.subTest(code=name, key=key):
                    self.assertIs(FEATCode.get(key), member)

    def test_the_value_form_folds_too(self) -> 'None':
        """A placeholder's *value* carries the angle brackets, and folds.

        ``FEATCode.base`` is the member whose value is ``'<base>'`` and whose
        name is ``'base'`` -- the shape
        the *House Conventions* page uses to demonstrate the base's
        name-misses-then-value-matches fall-through. Folding has to reach the
        value side as well, or a caller holding the registry's own value
        string in the RFC's recommended casing still fails.

        """
        for key in ('<base>', '<BASE>', '<Base>'):
            with self.subTest(key=key):
                self.assertIs(FEATCode.get(key), FEATCode.base)  # type: ignore[attr-defined]

    def test_get_all_inherits_the_fold(self) -> 'None':
        """:meth:`~pcapkit.corekit.enum.EnumLookup.get_all` resolves through
        ``get``, so it gains the fold without its own override -- and still
        returns the one-entry tuple a registry mapping one key to one member
        should, rather than one entry per casing tried."""
        self.assertEqual(FEATCode.get_all('BASE'),
                         (FEATCode.base,))  # type: ignore[attr-defined]
        self.assertEqual(FEATCode.get_all('auth'),
                         (FEATCode.AUTH,))  # type: ignore[attr-defined]

    def test_exact_hits_are_unchanged_for_every_member(self) -> 'None':
        """The fold is a fallback: an exact name or value still resolves the
        way it did before, through the base, for all 15 members."""
        self.assertEqual(len(FEATCode._member_names_), 15)
        for member in FEATCode:
            with self.subTest(member=member.name):
                self.assertIs(FEATCode.get(member.name), member)
                self.assertIs(FEATCode.get(member.value), member)


class FEATCodeCaseFoldSafetyTests(unittest.TestCase):
    """The fold cannot resolve ambiguously, and cannot mint."""

    def test_no_two_members_collide_when_folded(self) -> 'None':
        """RFC 5797's uniqueness rule, checked against the generated data.

        *"IANA maintains uniqueness of feature names (FEAT codes) based on
        case-insensitive comparison."* If that ever stopped holding in the
        crawled registry, folding would start resolving one of the colliding
        pair arbitrarily -- so it is asserted rather than assumed. Measured
        across all 151 enumerations in the tree while auditing #903:
        :class:`~pcapkit.const.hip.parameter.Parameter` is the *only* one with
        a name-fold collision (``R1_Counter`` against ``R1_COUNTER``, both
        IANA-registered), and **no** enumeration anywhere has a ``str``-value
        fold collision.

        """
        names = list(FEATCode._member_map_)
        folded_names = [name.casefold() for name in names]
        self.assertEqual(len(set(folded_names)), len(set(names)))

        values = [member.value for member in FEATCode]
        folded_values = [value.casefold() for value in values]
        self.assertEqual(len(set(folded_values)), len(set(values)))

    def test_a_folded_name_never_shadows_another_members_value(self) -> 'None':
        """Name-before-value precedence is safe because the two never cross.

        The base checks a ``str`` key against member names first and member
        values second. The fold keeps that order, which would only be
        observable if one member's folded *name* equalled a *different*
        member's folded *value*. It does not, for any pair here -- so the
        fold cannot change which member a key resolves to relative to the
        exact-match path it falls back from.

        """
        by_folded_name = {name.casefold(): FEATCode._member_map_[name]
                          for name in FEATCode._member_map_}
        for member in FEATCode:
            folded_value = member.value.casefold()
            if folded_value in by_folded_name:
                with self.subTest(member=member.name):
                    self.assertIs(by_folded_name[folded_value], member)

    def test_an_unknown_code_still_raises_rather_than_minting(self) -> 'None':
        """The asymmetry the *House Conventions* page records survives.

        ``get`` never calls ``cls(key)`` for a ``str``, so a key matching no
        member -- in any casing -- raises instead of growing the registry,
        while the *constructor* still yields an unregistered member. Folding
        adds a second way to match, never a way to mint.

        """
        before_names = set(FEATCode._member_map_)
        before_values = set(FEATCode._value2member_map_)

        for key in ('ZZ-NOT-REAL', 'zz-not-real', 'Zz-Not-Real'):
            with self.subTest(key=key):
                with self.assertRaises(KeyError):
                    FEATCode.get(key)

        unregistered = FEATCode('ZZ-NOT-REAL')
        self.assertEqual(unregistered.value, 'ZZ-NOT-REAL')
        self.assertNotIn('ZZ-NOT-REAL', FEATCode._member_map_)

        self.assertEqual(set(FEATCode._member_map_), before_names)
        self.assertEqual(set(FEATCode._value2member_map_), before_values)

    def test_default_still_resolves_and_is_not_itself_folded(self) -> 'None':
        """``default`` names an already-registered value from this module.

        It is spelled by the caller against the enumeration rather than
        arriving off the wire, so it goes to the base untouched -- which also
        keeps it on the base's non-minting ``_value2member_map_`` path.

        """
        self.assertIs(FEATCode.get('ZZ-NOT-REAL', '<base>'),
                      FEATCode.base)  # type: ignore[attr-defined]
        with self.assertRaises(KeyError):
            FEATCode.get('ZZ-NOT-REAL', '<BASE>')
        with self.assertRaises(KeyError):
            FEATCode.get('ZZ-NOT-REAL', 'ALSO-NOT-REAL')

    def test_a_non_str_key_is_passed_straight_through(self) -> 'None':
        """Case cannot apply to an :obj:`int`, so the fold must not intercept
        it -- and a ``str`` registry has no member for one, so the base's
        ``ValueError`` has to reach the caller."""
        with self.assertRaises(ValueError):
            FEATCode.get(42)


class CaseSensitiveDefaultStillHoldsTests(unittest.TestCase):
    """The base, and the other audited registries, are untouched."""

    def test_tls_key_label_stays_case_sensitive(self) -> 'None':
        """The audit's witness that the default is unchanged.

        :class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel` carries no
        ``get`` of its own, so it runs
        :meth:`~pcapkit.corekit.enum.EnumLookup.get` unmodified. RFC 9850
        Section 4.2's "TLS SSLKEYLOGFILE Labels" registry lists all 10 labels
        in upper case, the live IANA CSV agrees on all 10, and neither states
        a comparison rule -- so neither limb of the criterion is met and the
        case-sensitive default is correct here.

        """
        self.assertNotIn('get', vars(TLSKeyLabel))
        self.assertIs(TLSKeyLabel.get('CLIENT_RANDOM'),
                      TLSKeyLabel.CLIENT_RANDOM)  # type: ignore[attr-defined]
        for key in ('client_random', 'Client_Random'):
            with self.subTest(key=key):
                with self.assertRaises(KeyError):
                    TLSKeyLabel.get(key)

    def test_command_keeps_its_own_rfc_959_fold(self) -> 'None':
        """:class:`~pcapkit.const.ftp.command.Command` shares this module and
        folds for a different reason -- RFC 959 Section 4.1's *"Upper and
        lower case alphabetic characters are to be treated identically"* --
        so it must be unaffected by the sibling class changing."""
        self.assertIs(Command.get('RETR'), Command.RETR)  # type: ignore[attr-defined]
        self.assertIs(Command.get('retr'), Command.RETR)  # type: ignore[attr-defined]


class VendorTemplateParityTests(unittest.TestCase):
    """The fix lives in the crawler, so a regeneration cannot undo it."""

    def test_the_crawler_template_carries_the_same_get(self) -> 'None':
        """House rule: a change to a generated registry's shape belongs in the
        crawler, never in the generated file alone.

        :class:`FEATCode` is written out longhand inside
        :data:`pcapkit.vendor.ftp.command.LINE`, so this renders that template
        and requires the generated module's own ``get`` source to appear in it
        verbatim. Importing the crawler module reads its module-level
        template only; the crawl itself is behind ``if __name__ ==
        '__main__'`` and is never run here, so this needs no network access.

        """
        from pcapkit.vendor.ftp.command import LINE

        rendered = LINE('Command', 'FTP Command', '<ENUM>', '<FEAT>',
                        'pcapkit.vendor.ftp.command')
        source = inspect.getsource(FEATCode.get.__func__)  # type: ignore[attr-defined]

        self.assertIn('IANA maintains uniqueness of feature names', source)
        self.assertIn(source.rstrip('\n'), rendered)

    def test_the_generated_module_imports_what_the_override_needs(self) -> 'None':
        """``NO_DEFAULT`` is the sentinel the override's own signature carries,
        so the template has to import it as well as emit the method.

        ``EnumLookup`` joined the same import with GitHub issue #930, which
        re-parented ``CommandType`` and ``ConformanceRequirement`` -- the last
        two of #877's non-registry enumerations -- onto it.
        """
        from pcapkit.vendor.ftp.command import LINE

        rendered = LINE('Command', 'FTP Command', '<ENUM>', '<FEAT>',
                        'pcapkit.vendor.ftp.command')
        self.assertIn('from pcapkit.corekit.enum import NO_DEFAULT, EnumLookup, EnumRegistry',
                      rendered)

        import pcapkit.const.ftp.command as generated
        self.assertIn('from pcapkit.corekit.enum import NO_DEFAULT, EnumLookup, EnumRegistry',
                      inspect.getsource(generated))


if __name__ == '__main__':
    unittest.main()
