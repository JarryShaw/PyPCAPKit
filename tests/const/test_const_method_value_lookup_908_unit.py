# -*- coding: utf-8 -*-
"""``Method.get`` must consult ``_value2member_map_``, not only ``_member_map_``.

GitHub issue #908. :class:`~pcapkit.const.http.method.Method` has 40 members,
and exactly two of them -- ``BASELINE_CONTROL`` (value ``'BASELINE-CONTROL'``)
and ``VERSION_CONTROL`` (value ``'VERSION-CONTROL'``) -- have a member *name*
that differs from their *value*, because a hyphen cannot appear in a Python
identifier. The override's own ``get`` checked only ``_member_map_`` (names)
and fell straight through to building an *unregistered* member on any miss,
so a caller spelling either method by its registered *value* got back a
freshly minted, hollowed-out member (``safe=False``, ``idempotent=False``)
instead of the real one the IANA registry describes (``idempotent=True`` for
both) -- even though the very same value already resolved correctly through
the constructor (:meth:`~pcapkit.const.http.method.Method._missing_`, which
this override never touched).

**Why a capture reaches it.** ``pcapkit/protocols/application/httpv1.py``'s
``_RE_METHOD = re.compile(rb"(?P<method>[A-Z][A-Z-]*)\\Z")`` admits a hyphen,
so a request line carrying ``BASELINE-CONTROL`` matches, reaches
``Enum_Method.get(...)`` at ``httpv1.py:434``, parses successfully, and is
reported with the wrong ``idempotent`` -- the harder kind of defect to
notice, since the parse itself never fails.
:class:`HTTPv1EndToEndTests` below pins that whole path, not just the direct
``Method.get`` call, so a fix that only patched the unit-level symptom would
not be enough.

**The fix, and the trap in the version the issue first proposed.** Delegate
to :meth:`~pcapkit.corekit.enum.EnumLookup.get` and keep the override only
for the unregistered-member fallback -- but ``Method.get`` was a
:class:`staticmethod` while the base is a :class:`classmethod`, and a
zero-argument ``super()`` inside a :class:`staticmethod` has no first
argument to bind (``RuntimeError: super(): no arguments``). So the override
had to move to :class:`classmethod` as well, following the shape
PR #913's ``FEATCode.get`` sets for the same base method.

**Two behaviours settled by earlier issues must survive unchanged**, each
pinned by its own test below rather than only implied by the others:

* Case-sensitivity, per :rfc:`9110#section-9.1` and GitHub issue #896 --
  ``Method.get('get')`` must *not* resolve to :attr:`Method.GET`.
* An unregistered member's *value* is the caller's own casing, never the
  upper-cased form -- GitHub issue #860's ruling, already exercised by
  :mod:`tests.const.test_const_method_case_sensitive_896_unit`.

**The ``default`` signature question, decided rather than assumed.** The base
``get`` is ``get(cls, key, default=NO_DEFAULT)``, where ``default`` must
already name a *registered* value (resolved through
``_value2member_map_``); this override's ``default`` has always meant
something else -- the *value* to give the freshly minted unregistered member
instead of ``key`` itself. Widening the signature to adopt ``NO_DEFAULT``
would therefore be caller-visible (a non-``None`` ``default`` on an unknown
``key`` would start resolving to an *existing* registered member instead of
minting a new one carrying that string), even though nothing in this tree
currently calls ``get`` with a non-``None`` ``default`` to notice --
confirmed by grepping every call site under ``pcapkit/`` and ``tests/``.
So the signature and the default's meaning are left exactly as they were;
:class:`DefaultSignatureTests` below pins that explicitly.

"""
from __future__ import annotations

import inspect
import unittest


class ValueLookupTests(unittest.TestCase):
    """The direct repro: the two methods whose name and value differ."""

    def test_baseline_control_resolves_via_its_value(self) -> None:
        """The issue's own first repro line."""
        from pcapkit.const.http.method import Method

        before_names = len(Method._member_map_)
        before_values = len(Method._value2member_map_)

        probed = Method.get('BASELINE-CONTROL')
        self.assertIs(probed, Method.BASELINE_CONTROL)
        self.assertIs(probed, Method('BASELINE-CONTROL'))
        self.assertFalse(probed.safe)
        self.assertTrue(probed.idempotent)

        # No minting happened to answer the lookup -- both tables are the
        # same size before and after.
        self.assertEqual(len(Method._member_map_), before_names)
        self.assertEqual(len(Method._value2member_map_), before_values)

    def test_version_control_resolves_via_its_value(self) -> None:
        """The issue's second repro line -- the only other member like it."""
        from pcapkit.const.http.method import Method

        before_names = len(Method._member_map_)
        before_values = len(Method._value2member_map_)

        probed = Method.get('VERSION-CONTROL')
        self.assertIs(probed, Method.VERSION_CONTROL)
        self.assertIs(probed, Method('VERSION-CONTROL'))
        self.assertFalse(probed.safe)
        self.assertTrue(probed.idempotent)

        self.assertEqual(len(Method._member_map_), before_names)
        self.assertEqual(len(Method._value2member_map_), before_values)

    def test_value_lookup_stays_case_sensitive(self) -> None:
        """The value side is a plain ``_value2member_map_`` lookup, not a
        casefolded one -- a lower-cased spelling of the registered value
        must not resolve to the real member either."""
        from pcapkit.const.http.method import Method

        probed = Method.get('baseline-control')
        self.assertIsNot(probed, Method.BASELINE_CONTROL)
        self.assertEqual(probed.value, 'baseline-control')

    def test_an_exact_name_match_still_wins_and_ignores_a_supplied_default(self) -> None:
        """The base's own precedence (name before value) survives the
        delegation, and ``default`` is never consulted on a hit -- matching
        the pre-#908 behaviour where a resolved ``key`` ignored ``default``
        entirely."""
        from pcapkit.const.http.method import Method

        self.assertIs(Method.get('GET', default='IGNORED'), Method.GET)
        self.assertIs(Method.get('BASELINE-CONTROL', default='IGNORED'),
                      Method.BASELINE_CONTROL)


class PreservedBehaviourTests(unittest.TestCase):
    """The two settled behaviours the fix must not disturb."""

    def test_case_sensitivity_from_896_still_holds(self) -> None:
        """RFC 9110 Section 9.1, via GitHub issue #896: a name match is
        case-**sensitive**, so ``get('get')`` must not resolve to
        :attr:`Method.GET`. Fails against a naive fix that resolves ``key``
        through ``cls(key)`` (which folds case via ``_missing_``) instead of
        through the base's own non-minting ``get``."""
        from pcapkit.const.http.method import Method

        probed = Method.get('get')
        self.assertIsNot(probed, Method.GET)
        self.assertEqual(probed.value, 'get')
        self.assertEqual(probed.name, 'GET')

    def test_unregistered_member_keeps_the_callers_own_casing(self) -> None:
        """GitHub issue #860: an unregistered member's *value* is exactly
        what the caller passed, never upper-cased -- only the *name* (the
        identifier) is canonicalised. Fails if the fallback were changed to
        build the value from ``name`` instead of the original ``key``."""
        from pcapkit.const.http.method import Method

        before = len(Method.__members__)
        probed = Method.get('frob')
        self.assertEqual(probed.value, 'frob')
        self.assertEqual(probed.name, 'FROB')
        self.assertEqual(len(Method.__members__), before)


class DefaultSignatureTests(unittest.TestCase):
    """``default`` keeps its pre-#908 meaning rather than widening to the
    base's ``NO_DEFAULT`` sentinel -- see the module docstring's reasoning."""

    def test_default_still_names_the_unregistered_members_value(self) -> None:
        """Omitted or ``None``, ``default`` uses ``key`` itself; supplied,
        it replaces the *value* of the freshly minted unregistered member --
        unchanged from before #908, and distinct from the base's own
        ``default``, which must already name a registered value."""
        from pcapkit.const.http.method import Method

        before = len(Method.__members__)

        omitted = Method.get('MixedCase-Unregistered')
        self.assertEqual(omitted.value, 'MixedCase-Unregistered')
        self.assertEqual(omitted.name, 'MIXEDCASE-UNREGISTERED')

        supplied = Method.get('MixedCase-Unregistered', default='PLACEHOLDER')
        self.assertEqual(supplied.value, 'PLACEHOLDER')
        self.assertEqual(supplied.name, 'MIXEDCASE-UNREGISTERED')

        self.assertEqual(len(Method.__members__), before)

    def test_get_is_now_a_classmethod_bound_the_same_way_for_callers(self) -> None:
        """The ``staticmethod`` -> ``classmethod`` switch GitHub issue #908's
        own correction required is invisible to a caller: ``Method.get('X')``
        binds identically either way."""
        from pcapkit.const.http.method import Method

        self.assertIsInstance(inspect.getattr_static(Method, 'get'), classmethod)
        self.assertIs(Method.get('GET'), Method.GET)


class HTTPv1EndToEndTests(unittest.TestCase):
    """The path a real capture takes, per the issue's own "why it matters"."""

    def test_a_baseline_control_request_line_reports_the_registrys_idempotent_flag(
            self) -> None:
        """``_RE_METHOD`` admits the hyphen, so this request line reaches
        ``Enum_Method.get(...)`` at ``httpv1.py:434`` and used to come back
        with ``idempotent=False`` -- the wrong answer for a parse that
        otherwise succeeds silently. Pins the whole path, not only the
        direct ``Method.get`` call above."""
        from pcapkit.const.http.method import Method
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1

        proto = object.__new__(HTTPv1)
        header, _ = proto._read_http_header(
            b'BASELINE-CONTROL /webdav/doc.txt HTTP/1.1\r\nHost: example.test')

        self.assertIs(header.method, Method.BASELINE_CONTROL)
        self.assertTrue(header.method.idempotent)
        self.assertFalse(header.method.safe)
        self.assertEqual(header.uri, '/webdav/doc.txt')

    def test_a_version_control_request_line_reports_the_registrys_idempotent_flag(
            self) -> None:
        """The issue's second repro, through the same end-to-end path."""
        from pcapkit.const.http.method import Method
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1

        proto = object.__new__(HTTPv1)
        header, _ = proto._read_http_header(
            b'VERSION-CONTROL /repo/doc.txt HTTP/1.1\r\nHost: example.test')

        self.assertIs(header.method, Method.VERSION_CONTROL)
        self.assertTrue(header.method.idempotent)


class NonStrKeyTests(unittest.TestCase):
    """The non-``str`` surface, which GitHub issue #908's fix moved.

    Delegating to the base routes a non-``str`` key through ``cls(key)`` and
    so ``_missing_``, which raises :exc:`ValueError`. The override catches
    only :exc:`KeyError` -- a failed *name* lookup -- so that
    :exc:`ValueError` reaches the caller. Pinned because it is a
    caller-visible change that the fix makes as a side effect rather than as
    its purpose, and because the ``bytes`` case moved from *returning* a
    member to raising.
    """

    def setUp(self) -> None:
        """Snapshot both lookup tables -- a probe on a minting registry is
        not a read, and these tests must not grow either table."""
        from pcapkit.const.http.method import Method

        self.before = (len(Method._member_map_), len(Method._value2member_map_))

    def tearDown(self) -> None:
        """No member may have been installed by any lookup above."""
        from pcapkit.const.http.method import Method

        self.assertEqual(
            (len(Method._member_map_), len(Method._value2member_map_)),
            self.before,
            'a non-str lookup must not mint',
        )

    def test_an_int_key_raises_value_error(self) -> None:
        """Was :exc:`AttributeError` from ``key.upper()`` before #908."""
        from pcapkit.const.http.method import Method

        with self.assertRaises(ValueError):
            Method.get(42)

    def test_a_none_key_raises_value_error(self) -> None:
        """Was :exc:`AttributeError` from ``key.upper()`` before #908."""
        from pcapkit.const.http.method import Method

        with self.assertRaises(ValueError):
            Method.get(None)  # type: ignore[arg-type]

    def test_a_bytes_key_raises_instead_of_returning_a_bytes_valued_member(self) -> None:
        """The one that changed from a *return* to a raise.

        Before #908 this handed back a member whose ``name`` and ``value``
        were both ``b'GET'``. ``bytes`` is the plausible mistake here, since
        :attr:`~pcapkit.protocols.application.httpv1.HTTP._RE_METHOD` is a
        bytes pattern and ``httpv1`` is bytes throughout -- the live call at
        ``httpv1.py:434`` is safe only because it wraps the match in
        ``self.decode(...)``.
        """
        from pcapkit.const.http.method import Method

        with self.assertRaises(ValueError):
            Method.get(b'GET')  # type: ignore[arg-type]

    def test_the_docstring_documents_the_value_error(self) -> None:
        """A caller-visible raise with no ``Raises:`` entry is the gap this
        pin exists to keep closed, in the template as well as the generated
        module."""
        from pcapkit.const.http.method import Method
        from pcapkit.vendor.http.method import LINE

        # NOTE: ``inspect.getsource(Method.get)`` rather than
        # ``Method.get.__func__``, which a ``staticmethod`` does not carry --
        # so against the pre-#908 module this would die with
        # :exc:`AttributeError` before reaching a single assertion, and would
        # be pinning ``classmethod``-ness (already pinned by
        # :class:`DefaultSignatureTests`) rather than the docstring it is
        # named for. ``getsource`` works on both descriptor kinds.
        source = inspect.getsource(Method.get)
        rendered = LINE('Method', 'HTTP Method', '<ENUM>', 'pcapkit.vendor.http.method')

        self.assertIn('Raises:', source)
        # NOTE: a distinctive sentence rather than the bare word
        # ``ValueError``, which occurs incidentally elsewhere in 4kB of
        # docstring and would make this assertion near-vacuous.
        self.assertIn('value were both the :class:`bytes` object', source)
        self.assertIn('value were both the :class:`bytes` object', rendered)


class VendorTemplateParityTests(unittest.TestCase):
    """The fix lives in the crawler template, so a regeneration cannot
    silently discard it -- following PR #913's own precedent
    (``test_the_crawler_template_carries_the_same_get``)."""

    def test_the_crawler_template_carries_the_same_get(self) -> None:
        """:class:`~pcapkit.const.http.method.Method` is written out
        longhand inside :data:`pcapkit.vendor.http.method.LINE`, so this
        renders that template and requires the generated module's own
        ``get`` source to appear in it verbatim. Importing the crawler
        module reads its module-level template only; the crawl itself is
        behind ``if __name__ == '__main__'`` and is never run here, so this
        needs no network access."""
        from pcapkit.const.http.method import Method
        from pcapkit.vendor.http.method import LINE

        rendered = LINE('Method', 'HTTP Method', '<ENUM>', 'pcapkit.vendor.http.method')
        source = inspect.getsource(Method.get.__func__)  # type: ignore[attr-defined]

        self.assertIn('GitHub issue #908', source)
        self.assertIn('return super().get(key)', source)
        self.assertIn(source.rstrip('\n'), rendered)

    def test_the_crawler_template_carries_the_missing_cross_reference_too(self) -> None:
        """The issue's own "second, related inconsistency": ``_missing_``'s
        docstring gets a pointer to ``get``'s RFC caveat so the two
        contradictory case rationales in one file are at least tied
        together."""
        from pcapkit.const.http.method import Method
        from pcapkit.vendor.http.method import LINE

        rendered = LINE('Method', 'HTTP Method', '<ENUM>', 'pcapkit.vendor.http.method')
        source = inspect.getsource(Method._missing_.__func__)  # type: ignore[attr-defined]

        self.assertIn('GitHub issue #908', source)
        self.assertIn(source.rstrip('\n'), rendered)


if __name__ == '__main__':
    unittest.main()
