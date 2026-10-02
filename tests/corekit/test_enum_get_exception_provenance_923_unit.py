# -*- coding: utf-8 -*-
"""GitHub issue #923: :meth:`~pcapkit.corekit.enum.EnumLookup.get` raises from
:mod:`pcapkit.utilities.exceptions`, in stdlib :class:`~enum.Enum`'s shape.

The owner's ruling, asked for on #921 and recorded on #923: raise whichever of
:exc:`ValueError` and :exc:`KeyError` stdlib's :class:`~enum.Enum` would raise
in the same circumstance, and raise it from :mod:`pcapkit.utilities.exceptions`
rather than as a builtin exception.

Measured on Python 3.14.7, that fixes the shape rather than leaving it open:
``E['nosuch']`` raises :exc:`KeyError` and ``E(999)`` raises :exc:`ValueError`.
The base already matched it -- a census of the 127 concrete
:class:`~pcapkit.corekit.enum.EnumLookup` subclasses found 119 answering a
string name miss with :exc:`KeyError`, 5 with :exc:`ValueError` and 3 minting --
so this issue changes **provenance only**: the bare builtin :exc:`KeyError` from
``cls._member_map_[key]`` becomes
:exc:`~pcapkit.utilities.exceptions.EnumKeyError`, and :mod:`aenum`'s own bare
:exc:`ValueError` from ``cls(key)`` becomes
:exc:`~pcapkit.utilities.exceptions.EnumValueError`.

Deriving :exc:`~pcapkit.utilities.exceptions.EnumKeyError` from :exc:`KeyError`
is what keeps the blast radius at nothing: six in-library sites catch the base's
name miss -- :meth:`~pcapkit.const.http.method.Method.get`,
:mod:`pcapkit.toolkit.scapy`, and two each in
:mod:`pcapkit.protocols.internet.hopopt` and
:mod:`pcapkit.protocols.internet.ipv6_opts` -- and ``Method.get`` catches it in
order to **mint**, so for that one a name miss is part of a *successful* call.
:class:`MethodStillMintsTests` pins that one directly.

Three call sites also changed, all of them cases of the minority shape the
ruling rejects:

* ``TransportProtocol.get`` (and its codegen twin in
  :mod:`pcapkit.vendor.reg.apptype.apptype`) dropped its ``KeyError`` ->
  ``ValueError`` conversion, keeping only the ``key.lower()`` call --
  :class:`TransportProtocolCaseFoldingTests`.
* ``Criticality.get`` was deleted outright, its body having become a pure
  pass-through -- :class:`CriticalityGetDeletionTests`.
* :class:`~pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus` and
  :class:`~pcapkit.protocols.internet.mh.IPv6AddressPrefixCode` already raised
  from :mod:`pcapkit.utilities.exceptions` on a *name* miss, but as
  ``EnumValueError`` -- the right provenance in the wrong shape --
  :class:`MobilityHeaderNameMissTests`.

On the tree before this change every test below fails at import, since
:exc:`~pcapkit.utilities.exceptions.EnumKeyError` does not exist there; with the
exception added but the base left alone, each fails on its own assertion instead.
Two are regression guards rather than defect repros and cannot fail on the
pre-#923 tree -- :meth:`TransportProtocolCaseFoldingTests.
test_upper_case_still_resolves` and the resolving half of
:class:`CriticalityGetDeletionTests` -- and they are here because they are what
the deletion and the reduction could plausibly have broken.

"""
from __future__ import annotations

import ast
import importlib
import pathlib
import re
import sys
import unittest
from typing import TYPE_CHECKING

from aenum import IntEnum, StrEnum

from pcapkit.corekit.enum import EnumLookup, EnumRegistry
from pcapkit.utilities.exceptions import EnumKeyError, EnumValueError
from pcapkit.utilities.logging import DEVMODE, logger
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any

__all__ = [
    'EnumKeyErrorClassTests', 'BaseGetProvenanceTests', 'BaseGetQuietnessTests',
    'MethodStillMintsTests', 'TransportProtocolCaseFoldingTests',
    'CriticalityGetDeletionTests', 'MobilityHeaderNameMissTests',
    'VendorTemplateParityTests', 'TRANSPORT_GET',
]

#: The region both halves of the ``TransportProtocol`` pair must spell
#: identically -- the whole ``get`` classmethod, from its decorator to its last
#: ``return``. Matched rather than sliced by line number so that neither half
#: moving keeps the check from finding it.
TRANSPORT_GET = re.compile(
    r"\n    @classmethod\n    def get\(cls, key: 'int \| str'.*?"
    r"\n        return super\(\)\.get\(key, default\)\n", re.S)


class _Closed(EnumLookup, IntEnum):
    """A closed set on the bare lookup tier, with no hooks of its own."""

    one = 1
    two = 2


class _Strings(EnumRegistry, StrEnum):
    """A ``str``-valued registry, for the name-before-value precedence."""

    plain = 'plain-value'


class _Ranged(EnumLookup, IntEnum):
    """Declares a range, so ``_validate_value`` raises in-library."""

    low = 1

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        if not (isinstance(value, int) and 0 <= value <= 8):
            raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')


class EnumKeyErrorClassTests(unittest.TestCase):
    """The class this issue adds, and why it is not
    :exc:`~pcapkit.utilities.exceptions.MissingKeyError` reused."""

    def test_it_is_a_key_error_and_an_in_library_error(self) -> 'None':
        from pcapkit.utilities.exceptions import BaseError

        self.assertTrue(issubclass(EnumKeyError, BaseError))
        self.assertTrue(issubclass(EnumKeyError, KeyError))
        self.assertFalse(issubclass(EnumKeyError, ValueError))

    def test_it_is_exported(self) -> 'None':
        import pcapkit.utilities.exceptions as exceptions

        self.assertIn('EnumKeyError', exceptions.__all__)

    def test_it_is_distinct_from_missing_key_error(self) -> 'None':
        """Deliberately a sibling rather than a reuse.

        :exc:`~pcapkit.utilities.exceptions.MissingKeyError` reports an absent
        *mapping* key -- :class:`~pcapkit.corekit.multidict.MultiDict` raises it,
        and so do both :mod:`pcapkit.toolkit` extractors for an absent packet
        field. Reusing it here would leave a caller unable to tell "this
        registry has no such member" from "this packet dict has no such field",
        which is the distinction :mod:`pcapkit.toolkit.scapy` relies on when it
        converts one into the other.
        """
        from pcapkit.utilities.exceptions import MissingKeyError

        self.assertFalse(issubclass(EnumKeyError, MissingKeyError))
        self.assertFalse(issubclass(MissingKeyError, EnumKeyError))

    def test_the_value_half_is_unchanged(self) -> 'None':
        """The pair, so that a future edit cannot quietly reshape one half."""
        from pcapkit.utilities.exceptions import BaseError

        self.assertTrue(issubclass(EnumValueError, BaseError))
        self.assertTrue(issubclass(EnumValueError, ValueError))
        self.assertFalse(issubclass(EnumValueError, KeyError))


class BaseGetProvenanceTests(unittest.TestCase):
    """:meth:`~pcapkit.corekit.enum.EnumLookup.get`'s two failure paths."""

    def test_a_name_miss_raises_the_in_library_key_error(self) -> 'None':
        with self.assertRaises(EnumKeyError) as caught:
            _Closed.get('nosuch')
        self.assertIsInstance(caught.exception, KeyError)
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertIn('nosuch', str(caught.exception))
        self.assertIn('_Closed', str(caught.exception))

    def test_a_value_miss_raises_the_in_library_value_error(self) -> 'None':
        with self.assertRaises(EnumValueError) as caught:
            _Closed.get(99)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertNotIsInstance(caught.exception, KeyError)
        self.assertIn('99', str(caught.exception))

    def test_an_unusable_default_reaches_the_same_two(self) -> 'None':
        """``default`` naming no registered value falls through to ``key``'s own
        error, so it must reach the caller as the same class -- and must not
        name the default, which is the pin GitHub issue #864 added."""
        with self.assertRaises(EnumKeyError) as caught_key:
            _Strings.get('nosuch-name', 'not-a-member')
        self.assertIn('nosuch-name', str(caught_key.exception))
        self.assertNotIn('not-a-member', str(caught_key.exception))

        with self.assertRaises(EnumValueError):
            _Closed.get(99, 98)

    def test_a_usable_default_still_raises_nothing(self) -> 'None':
        self.assertIs(_Closed.get('nosuch', 1), _Closed.one)
        self.assertIs(_Closed.get(99, 2), _Closed.two)

    def test_old_call_sites_keep_catching(self) -> 'None':
        """The whole reason the shape is preserved: the six in-library
        ``except KeyError`` sites, and any caller's own, keep working."""
        try:
            _Closed.get('nosuch')
        except KeyError as error:
            caught = error
        else:  # pragma: no cover
            self.fail('a name miss no longer raises a KeyError')
        self.assertIsInstance(caught, EnumKeyError)

        try:
            _Closed.get(99)
        except ValueError as error:
            caught_value = error  # type: ValueError
        else:  # pragma: no cover
            self.fail('a value miss no longer raises a ValueError')
        self.assertIsInstance(caught_value, EnumValueError)

    def test_an_in_library_rejection_is_passed_through_not_rewrapped(self) -> 'None':
        """A ``_validate_value`` override's own
        :exc:`~pcapkit.utilities.exceptions.EnumValueError` is what the caller
        sees, rather than a second one wrapping it -- so the override's message
        survives and the error is logged once, not twice."""
        with self.assertRaises(EnumValueError) as caught:
            _Ranged.get(99)
        self.assertIn('is not a valid _Ranged', str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

        # Still honours ``default``, as the hook's own docstring promises.
        self.assertIs(_Ranged.get(99, 1), _Ranged.low)

    def test_get_all_reports_the_same_two(self) -> 'None':
        """:meth:`~pcapkit.corekit.enum.EnumLookup.get_all` forwards to
        ``get``, so its documented ``Raises:`` has to move with it."""
        with self.assertRaises(EnumKeyError):
            _Closed.get_all('nosuch')
        with self.assertRaises(EnumValueError):
            _Closed.get_all(99)

    def test_nothing_is_minted_on_either_path(self) -> 'None':
        before_names = dict(_Strings._member_map_)
        before_values = dict(_Strings._value2member_map_)
        with self.assertRaises(EnumKeyError):
            _Strings.get('nosuch-name')
        self.assertEqual(_Strings._member_map_, before_names)
        self.assertEqual(_Strings._value2member_map_, before_values)


class BaseGetQuietnessTests(unittest.TestCase):
    """The name miss is raised with ``quiet=True``, and that is load-bearing.

    :meth:`~pcapkit.const.http.method.Method.get` catches it in order to mint,
    so a loud error there would put one :data:`logging.CRITICAL` record on the
    logger -- and set :data:`sys.tracebacklimit` to ``0`` process-wide -- for
    every *successful* ``Method.get`` call that mints. That is the GitHub issue
    #362 defect :class:`~pcapkit.utilities.exceptions.BaseError` documents
    ``quiet`` for, and :mod:`pcapkit.protocols.protocol` states the same rule
    inline: *"A pcapkit exception here would log at CRITICAL for something that
    is handled two lines later."*
    """

    def setUp(self) -> 'None':
        self._saved = getattr(sys, 'tracebacklimit', None)
        if hasattr(sys, 'tracebacklimit'):
            del sys.tracebacklimit

    def tearDown(self) -> 'None':
        if self._saved is None:
            if hasattr(sys, 'tracebacklimit'):
                del sys.tracebacklimit
        else:
            sys.tracebacklimit = self._saved

    def test_a_name_miss_logs_nothing(self) -> 'None':
        with capture(logger) as recorder:
            with self.assertRaises(EnumKeyError):
                _Closed.get('nosuch')
        self.assertEqual(recorder.messages, [])

    @unittest.skipIf(DEVMODE, 'tracebacklimit is only set outside development mode')
    def test_a_name_miss_leaves_tracebacklimit_alone(self) -> 'None':
        with capture(logger):
            with self.assertRaises(EnumKeyError):
                _Closed.get('nosuch')
        self.assertFalse(hasattr(sys, 'tracebacklimit'))

    def test_the_minting_override_stays_silent_end_to_end(self) -> 'None':
        """The call this is actually for: a ``Method.get`` that mints is a
        successful call and must emit nothing at all."""
        from pcapkit.const.http.method import Method

        with capture(logger) as recorder:
            minted = Method.get('QUIET-923-PROBE')
        self.assertEqual(recorder.messages, [])
        self.assertEqual(minted.value, 'QUIET-923-PROBE')

    def test_the_value_miss_is_loud_which_is_what_quiet_is_measured_against(self) -> 'None':
        """The control. Without it ``recorder.messages == []`` above would also
        pass if :class:`~pcapkit.utilities.exceptions.BaseError` had simply
        stopped logging, rather than this one raise being quiet."""
        with capture(logger) as recorder:
            with self.assertRaises(EnumValueError):
                _Closed.get(99)
        self.assertEqual([level for level, _ in recorder.messages], ['CRITICAL'])
        self.assertIn('EnumValueError', recorder.messages[0][1])


class MethodStillMintsTests(unittest.TestCase):
    """The sharpest call site in the blast radius.

    :meth:`~pcapkit.const.http.method.Method.get` is wired directly to the
    old contract: it catches the base's name miss *in order to* hand back an
    unregistered member. If :exc:`~pcapkit.utilities.exceptions.EnumKeyError`
    had not derived from :exc:`KeyError`, this would raise instead of minting.
    """

    def test_an_unregistered_method_token_still_mints(self) -> 'None':
        from pcapkit.const.http.method import Method

        before_names = len(Method._member_map_)
        before_values = len(Method._value2member_map_)

        minted = Method.get('FROBNICATE-923')

        self.assertEqual(minted.name, 'FROBNICATE-923')
        self.assertEqual(minted.value, 'FROBNICATE-923')
        # ``_unregistered_member`` hands back a throwaway, so neither lookup
        # table grew -- the GitHub issue #860 contract, unchanged here.
        self.assertEqual(len(Method._member_map_), before_names)
        self.assertEqual(len(Method._value2member_map_), before_values)

    def test_a_registered_method_still_resolves_by_name_and_by_value(self) -> 'None':
        from pcapkit.const.http.method import Method

        self.assertIs(Method.get('GET'), Method.GET)
        self.assertIs(Method.get('BASELINE-CONTROL'), Method.BASELINE_CONTROL)


class TransportProtocolCaseFoldingTests(unittest.TestCase):
    """``TransportProtocol.get`` survives, reduced to its ``key.lower()``.

    Case-insensitivity is not on the base and ``get('TCP')`` resolving is live
    public behaviour -- :meth:`~pcapkit.const.reg.apptype.apptype.AppType.
    _dispatch` is the one live call site and it passes ``proto.lower()``, but the
    public surface takes either casing. The exception conversion is what went.
    """

    def test_upper_case_still_resolves(self) -> 'None':
        """A regression guard, not a defect repro: it passes on the pre-#923
        tree too, and is here because reducing the override is exactly what
        could have dropped the fold along with the conversion."""
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        self.assertIs(TransportProtocol.get('TCP'), TransportProtocol.tcp)
        self.assertIs(TransportProtocol.get('Udp'), TransportProtocol.udp)
        self.assertIs(TransportProtocol.get('SCTP'), TransportProtocol.sctp)
        self.assertIs(TransportProtocol.get('tcp'), TransportProtocol.tcp)
        self.assertIs(TransportProtocol.get(1), TransportProtocol.tcp)

    def test_the_override_no_longer_converts_the_name_miss(self) -> 'None':
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        with self.assertRaises(EnumKeyError) as caught:
            TransportProtocol.get('quic')
        self.assertIsInstance(caught.exception, KeyError)
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertIn('quic', str(caught.exception))
        self.assertNotIn('quic', TransportProtocol.__members__)

    def test_the_value_miss_is_the_in_library_value_error(self) -> 'None':
        from pcapkit.const.reg.apptype.apptype import TransportProtocol

        with self.assertRaises(EnumValueError) as caught:
            TransportProtocol.get(0x20)
        self.assertIsInstance(caught.exception, ValueError)

    def test_the_override_carries_no_handler_or_raise_left(self) -> 'None':
        """Read off the source, because "reduced to the ``.lower()`` call" is a
        claim about the body and not only about what it raises. A conversion
        re-added in a different shape -- catching
        :exc:`~pcapkit.utilities.exceptions.EnumKeyError` by name, say -- would
        pass every assertion above.

        An :mod:`ast` walk rather than a substring search over the text: this
        method's body is mostly comment, and two of those comments legitimately
        contain the word *except* (``exception-compatible``) and *raise*
        (``used to raise AttributeError``), so a textual check reports a handler
        that is not there.
        """
        import pcapkit.const.reg.apptype.apptype as const_module

        committed = pathlib.Path(const_module.__file__).read_text(encoding='utf-8')
        node = None  # type: ast.FunctionDef | None
        for candidate in ast.walk(ast.parse(committed)):
            if isinstance(candidate, ast.ClassDef) and candidate.name == 'TransportProtocol':
                for inner in candidate.body:
                    if isinstance(inner, ast.FunctionDef) and inner.name == 'get':
                        node = inner
        self.assertIsNotNone(node, 'no TransportProtocol.get in the generated module')

        self.assertEqual([], [sub for sub in ast.walk(node) if isinstance(sub, ast.Try)])
        self.assertEqual([], [sub for sub in ast.walk(node) if isinstance(sub, ast.Raise)])
        region = TRANSPORT_GET.search(committed)
        self.assertIsNotNone(region, 'no TransportProtocol.get region in the generated module')
        self.assertIn('super().get(key.lower(), default)',
                      region.group(0))  # type: ignore[union-attr]


class CriticalityGetDeletionTests(unittest.TestCase):
    """``Criticality.get`` is gone, and the inherited base answers identically.

    Its body had become a pure pass-through once the ``KeyError`` ->
    ``ValueError`` conversion went, so every assertion here is about the
    *inherited* :meth:`~pcapkit.corekit.enum.EnumLookup.get`. ``default``
    handling is the one thing that could have made the deletion unsafe, so it is
    pinned in both directions.
    """

    def test_the_override_is_gone(self) -> 'None':
        from pcapkit.protocols.application.ngap import Criticality

        self.assertNotIn('get', Criticality.__dict__)

    def test_names_and_values_resolve_as_before(self) -> 'None':
        """Invariants rather than repros -- they pass on the pre-#923 tree too,
        and are the ones the deletion had to preserve."""
        from pcapkit.protocols.application.ngap import Criticality

        self.assertIs(Criticality.get('reject'), Criticality.reject)
        self.assertIs(Criticality.get('ignore'), Criticality.ignore)
        self.assertIs(Criticality.get('notify'), Criticality.notify)
        self.assertIs(Criticality.get(0), Criticality.reject)
        self.assertIs(Criticality.get(2), Criticality.notify)
        self.assertIs(Criticality.get(Criticality.reject), Criticality.reject)

    def test_a_name_miss_now_reports_in_the_stdlib_shape(self) -> 'None':
        from pcapkit.protocols.application.ngap import Criticality

        with self.assertRaises(EnumKeyError) as caught:
            Criticality.get('nosuch')
        self.assertIsInstance(caught.exception, KeyError)
        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertIn('nosuch', str(caught.exception))

    def test_a_member_valued_default_is_honoured(self) -> 'None':
        from pcapkit.protocols.application.ngap import Criticality

        self.assertIs(Criticality.get('nosuch', Criticality.reject), Criticality.reject)
        self.assertIs(Criticality.get('nosuch', Criticality.notify), Criticality.notify)

    def test_a_default_naming_no_member_is_not_honoured(self) -> 'None':
        """The other half, and the one that makes the deletion safe on a closed
        ASN.1 ``ENUMERATED``: a default resolves through
        ``_value2member_map_`` and never through the constructor, so no path
        here can mint a fourth value."""
        from pcapkit.protocols.application.ngap import Criticality

        before = len(Criticality.__members__)
        with self.assertRaises(EnumKeyError):
            Criticality.get('nosuch', 99)
        self.assertEqual(len(Criticality.__members__), before)

    def test_a_value_miss_still_goes_through_missing(self) -> 'None':
        from pcapkit.protocols.application.ngap import Criticality

        with self.assertRaises(EnumValueError) as caught:
            Criticality.get(3)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertIn('3', str(caught.exception))


class MobilityHeaderNameMissTests(unittest.TestCase):
    """The two :rfc:`5568` inline enumerations found by #923's own census.

    Both already raised from :mod:`pcapkit.utilities.exceptions` on a name miss
    -- the right provenance -- but chose ``EnumValueError`` deliberately, *"so
    the two ways of getting this wrong do not report differently"*. That is the
    conversion this ruling rejects, so the name half moves to
    :exc:`~pcapkit.utilities.exceptions.EnumKeyError` and only ``_missing_``'s
    value half stays :exc:`ValueError`-shaped.
    """

    def test_a_name_miss_is_key_shaped(self) -> 'None':
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        for enum_cls in (FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(enum=enum_cls.__name__):
                with self.assertRaises(EnumKeyError) as caught:
                    enum_cls.get('Vendor_specific')
                self.assertIsInstance(caught.exception, KeyError)
                self.assertNotIsInstance(caught.exception, ValueError)
                self.assertIn('Vendor_specific', str(caught.exception))
                self.assertIn(enum_cls.__name__, str(caught.exception))

    def test_a_value_miss_stays_value_shaped(self) -> 'None':
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        for enum_cls, unassigned in ((FastBindingAcknowledgmentStatus, 77),
                                     (IPv6AddressPrefixCode, 200)):
            with self.subTest(enum=enum_cls.__name__):
                with self.assertRaises(EnumValueError) as caught:
                    enum_cls.get(unassigned)
                self.assertIsInstance(caught.exception, ValueError)
                self.assertNotIsInstance(caught.exception, KeyError)

    def test_a_declared_name_and_value_still_resolve(self) -> 'None':
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        self.assertIs(FastBindingAcknowledgmentStatus.get('Insufficient_resources'),
                      FastBindingAcknowledgmentStatus.Insufficient_resources)
        self.assertIs(FastBindingAcknowledgmentStatus.get(130),
                      FastBindingAcknowledgmentStatus.Insufficient_resources)
        self.assertIs(IPv6AddressPrefixCode.get('NAR_Prefix'),
                      IPv6AddressPrefixCode.NAR_Prefix)
        self.assertIs(IPv6AddressPrefixCode.get(4), IPv6AddressPrefixCode.NAR_Prefix)

    def test_neither_class_grows(self) -> 'None':
        from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        for enum_cls in (FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
            with self.subTest(enum=enum_cls.__name__):
                before = len(list(enum_cls))
                with self.assertRaises(EnumKeyError):
                    enum_cls.get('nosuch_923')
                self.assertEqual(len(list(enum_cls)), before)


@unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                     'pcapkit.vendor needs requests')
class VendorTemplateParityTests(unittest.TestCase):
    """A regeneration must not undo the change.

    ``pcapkit/const/`` is generated from ``pcapkit/vendor/``, so the committed
    module passing everything above is not evidence that the template agrees
    with it -- the next crawl would simply revert it, which is the trap
    ``TransportProtocol.get`` living inside an f-string template sets. The same
    proof shape as ``test_the_tcp_flags_template_renders_the_committed_module``
    and ``test_the_vendor_templates_still_emit_the_fix``: render the template and
    compare against the committed file. Needs no network -- the crawl supplies
    only the enumeration block and the ``_missing_`` branches, neither of which
    the ``get`` region below interpolates, so placeholder arguments render it
    verbatim.
    """

    def test_the_template_renders_the_committed_get_region(self) -> 'None':
        from tests.const.test_const_enum_lookup import _normalize

        vendor_module = importlib.import_module('pcapkit.vendor.reg.apptype.apptype')
        const_module = importlib.import_module('pcapkit.const.reg.apptype.apptype')

        rendered = _normalize(vendor_module.BASE(
            'AppType', 'Application Layer Protocol Numbers [AppType]',
            '', '', '', 'pcapkit.vendor.reg.apptype.apptype',
        ))
        committed = pathlib.Path(
            const_module.__file__  # type: ignore[arg-type]
        ).read_text(encoding='utf-8')

        rendered_region = TRANSPORT_GET.search(rendered)
        committed_region = TRANSPORT_GET.search(committed)
        self.assertIsNotNone(rendered_region, 'no TransportProtocol.get in the rendered template')
        self.assertIsNotNone(committed_region, 'no TransportProtocol.get in the generated module')

        # Not vacuous: both halves have to carry the reduced body, so a template
        # that still converts cannot match a committed module that does not, and
        # a pair that agree on the *old* body fails here too.
        self.assertIn('super().get(key.lower(), default)',
                      rendered_region.group(0))  # type: ignore[union-attr]
        self.assertNotIn("raise ValueError(f'{key!r} is not a valid",
                         rendered_region.group(0))  # type: ignore[union-attr]
        self.assertEqual(rendered_region.group(0),  # type: ignore[union-attr]
                         committed_region.group(0))  # type: ignore[union-attr]


if __name__ == '__main__':
    unittest.main()
