from __future__ import annotations

import threading
import unittest

from tests._support import purge_modules, time_limit


class FieldBaseUnpackBoundsTests(unittest.TestCase):
    """Bounds checking in :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>`.

    ``length`` there is frequently wire-derived -- resolved by a
    ``_length_callback`` against the very packet under parse, or built by a
    schema selector from a value it just read off the wire -- and is thus
    attacker- or corruption-controlled. Before #554,
    ``buffer[:length].rjust(length, b'\\x00')`` zero-padded up to ``length``
    octets regardless of how little data ``buffer`` actually held, so a
    short, otherwise unremarkable capture could declare a multi-gigabyte
    field and force that allocation.

    The fix is deliberately *not* "reject any length the buffer falls short
    of": :meth:`ListField.unpack <pcapkit.corekit.fields.collections.ListField.unpack>`
    and :meth:`OptionField.unpack <pcapkit.corekit.fields.collections.OptionField.unpack>`
    depend on a short, sometimes entirely empty, tail read past a truncated
    option area decoding as zero -- that is how an over-long ``ihl``, or a
    capture cut short by the snapshot length, reads as end-of-option-list or
    ``Pad1`` instead of wedging or raising (#431). Rejecting every shortfall
    regardless of size would turn every one of those into a hard failure.

    So the guard only fires past :data:`~pcapkit.corekit.fields.field._MAX_ZERO_PAD_LENGTH`
    -- libpcap's own ``MAXIMUM_SNAPLEN`` and this package's own default
    ``snaplen`` -- which every fixed-width field ``ListField``/``OptionField``
    read past EOF is nowhere near, and which no legitimate single field is
    past either.

    :class:`~pcapkit.corekit.fields.strings.BytesField` is used throughout as
    the concrete field under test: a real, user-facing field type that goes
    through :meth:`FieldBase.unpack` unchanged, rather than a hand-rolled
    stand-in.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields import field as field_module
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.utilities.exceptions import FieldValueError

        self.BytesField = BytesField
        self.FieldValueError = FieldValueError
        self.ceiling = field_module._MAX_ZERO_PAD_LENGTH

    def test_exact_length_buffer_unpacks_unchanged(self) -> None:
        field = self.BytesField(length=4)
        self.assertEqual(field.unpack(b'\x01\x02\x03\x04', {}), b'\x01\x02\x03\x04')

    def test_buffer_with_trailing_extra_bytes_is_still_accepted(self) -> None:
        """More data than declared is fine -- only the declared prefix belongs to this field."""
        field = self.BytesField(length=4)
        self.assertEqual(field.unpack(b'\x01\x02\x03\x04\xff\xff', {}), b'\x01\x02\x03\x04')

    def test_small_field_short_by_one_octet_still_zero_pads(self) -> None:
        """A short read on an ordinary, small field is tolerated, not rejected.

        This is the #431 mechanism the option and list loops depend on: a
        type or progress-check field reading past a truncated area gets a
        short buffer and must still decode -- as zero, on the missing
        high-order octets -- rather than raise, or every capture cut short
        by its snapshot length would start failing to parse instead of
        reporting the tail as padding. This field is nowhere near
        :data:`~pcapkit.corekit.fields.field._MAX_ZERO_PAD_LENGTH`, so the
        shortfall must still be padded exactly as before #554.
        """
        field = self.BytesField(length=4)
        self.assertEqual(field.unpack(b'\x01\x02\x03', {}), b'\x00\x01\x02\x03')

    def test_small_field_over_an_entirely_empty_buffer_still_zero_pads(self) -> None:
        """The extreme case: nothing at all left to read.

        Exactly what ``OptionField.unpack`` does at the tail of a truncated
        option area -- ``file.read(field.length)`` past EOF returns ``b''``,
        and the one-octet type field it hands to :meth:`FieldBase.unpack`
        must decode that as ``0`` (end-of-option-list, or ``Pad1``) rather
        than raise.
        """
        field = self.BytesField(length=1)
        self.assertEqual(field.unpack(b'', {}), b'\x00')

    def test_field_at_the_ceiling_still_zero_pads(self) -> None:
        """Boundary: a declared length exactly at the ceiling is not rejected.

        Catches a ceiling comparison written the lenient-for-attackers way
        around (``>=`` instead of ``>``), which would reject this legitimate
        boundary value along with the genuinely oversized ones.
        """
        field = self.BytesField(length=self.ceiling)
        result = field.unpack(b'A', {})

        # rjust() right-justifies: the one real octet ends up at the end, with
        # the padding -- not the data -- at the front.
        self.assertEqual(len(result), self.ceiling)
        self.assertEqual(result[-1:], b'A')
        self.assertEqual(result[:-1], b'\x00' * (self.ceiling - 1))

    def test_field_one_past_the_ceiling_with_insufficient_buffer_is_rejected(self) -> None:
        """Boundary: one octet past the ceiling, with data missing, is rejected.

        Catches a ceiling comparison off by one in the other direction --
        e.g. a stray ``+ 1`` or ``- 1`` on the threshold -- by exercising the
        single value the exact threshold has to get right.
        """
        field = self.BytesField(length=self.ceiling + 1)
        with self.assertRaises(self.FieldValueError):
            field.unpack(b'A', {})

    def test_the_ceiling_is_262144_octets(self) -> None:
        """Pins the actual chosen figure, not just the module's own copy of it.

        262144 (``0x40_000``) is libpcap's own ``MAXIMUM_SNAPLEN`` and this
        package's own default ``snaplen``
        (:meth:`pcapkit.protocols.misc.pcap.header.Header.make`). A test that
        only ever reads the constant back from the module would still pass
        if that figure were quietly changed to something unjustified.
        """
        self.assertEqual(self.ceiling, 262144)

    def test_field_past_the_ceiling_with_a_full_buffer_is_accepted(self) -> None:
        """A field past the ceiling is rejected only when it would actually pad.

        If the buffer genuinely holds that much data there is nothing to
        zero-fill and nothing to refuse -- the guard fires on the padding
        :meth:`FieldBase.unpack` would have to perform, not merely on the
        field being large.
        """
        size = self.ceiling + 10
        field = self.BytesField(length=size)
        buffer = b'\xaa' * size

        self.assertEqual(field.unpack(buffer, {}), buffer)

    def test_rejection_message_names_the_declared_and_available_counts(self) -> None:
        field = self.BytesField(length=self.ceiling + 1)
        with self.assertRaises(self.FieldValueError) as ctx:
            field.unpack(b'A', {})

        message = str(ctx.exception)
        self.assertIn(str(self.ceiling + 1), message)
        self.assertIn('1', message)

    def test_wire_declared_length_far_larger_than_the_buffer_is_rejected_without_allocating(self) -> None:
        """The scenario #554 describes: a hostile or corrupt capture can make
        ``length`` whatever it likes.

        A ~40-octet PCAP-NG Decryption Secrets Block with a bogus inner
        length was enough to force a multi-gigabyte ``rjust()`` under the
        unfixed code. ``length`` here is set to 16 GiB -- large enough that,
        if the guard were absent, comparing against the wrong thing, or
        otherwise not actually reached, this test would try to allocate that
        much and either hang or fail with :exc:`MemoryError` rather than
        raising the expected, bounded exception. It runs under a wall-clock
        deadline rather than trusting the assertion alone to fail promptly,
        in case a future regression reintroduces the allocation instead of
        just moving the threshold.
        """
        huge_declared_length = 2 ** 34  # 16 GiB; must never actually be allocated.
        field = self.BytesField(length=huge_declared_length)

        with time_limit(5):
            with self.assertRaises(self.FieldValueError):
                field.unpack(b'AB', {})

    def test_zero_length_field_over_an_empty_buffer_is_unaffected(self) -> None:
        """A field declaring no octets at all is not a shortfall against an empty buffer."""
        field = self.BytesField(length=0)
        self.assertEqual(field.unpack(b'', {}), b'')


class FieldBaseCumulativePaddingBudgetTests(unittest.TestCase):
    """The padding budget across a whole parse, not one field at a time.

    #554's ceiling is per-field, and #573 is what that leaves behind: a packet
    holds many fields, so a declared length sitting just *under*
    :data:`~pcapkit.corekit.fields.field._MAX_ZERO_PAD_LENGTH` is honoured
    however many times it is declared, and the sum has no bound at all. Measured
    on the tree that carried only the per-field ceiling, 200 minimal PCAP-NG
    Decryption Secrets Blocks -- 4,800 wire octets, each declaring
    ``secrets_length`` of 262,142 against two supplied octets -- retained
    **50.0 MiB**, an amplification of 10,922x per block, with the ceiling never
    firing once because every single field was within it.

    :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>` now
    keeps a running ledger of octets supplied against octets synthesised, and
    refuses a shortfall *past*
    :data:`~pcapkit.corekit.fields.field._MAX_ZERO_PAD_SHORTFALL` once the total
    of those passes ``_MAX_ZERO_PAD_LENGTH + _ZERO_PAD_BUDGET_RATIO * supplied``.

    Two things these tests have to hold at once, and the second is the harder.

    The sum must be bounded. And a legitimately truncated capture must still
    parse -- the constraint that declined #571, on an executed counterexample --
    which here is not only about *whether* a shortfall is padded but about
    whether the answer is the same every time. A running budget on its own fails
    that: with one, a legitimate 54-octet frame declaring an IPv4 total length of
    65,535 (a capture of offload-sized segments cut to a 54-octet snapshot, which
    pads 65,495 octets per frame from 54 read) was measured parsing to one result
    on 37 of 40 identical calls and to a different one on calls 26, 33 and 39,
    purely because of what had been parsed before it.

    :data:`~pcapkit.corekit.fields.field._MAX_ZERO_PAD_SHORTFALL` is what removes
    that: a shortfall within the span of a 16-bit wire length is padded
    unconditionally and charged to nothing, so no shortfall a snapshot-truncated
    capture, a truncated option area or an over-long ``ihl`` can produce is ever
    refused, however many came before. Only the 32-bit band above it -- where
    #573's amplification lives -- meets the budget.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields import field as field_module
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.utilities.exceptions import FieldValueError

        self.field_module = field_module
        self.BytesField = BytesField
        self.FieldValueError = FieldValueError
        self.ceiling = field_module._MAX_ZERO_PAD_LENGTH

        # NOTE: deliberately *not* read off the module. The behavioural tests
        # below have to fail on their assertions when the budget is absent, not
        # on an :exc:`AttributeError` raised here before any of them runs -- a
        # setup that reaches for a name the unfixed code does not have turns every
        # case in the class into the same uninformative error and proves nothing
        # about behaviour. Only the two cases that exist to pin the constants
        # themselves name them.
        self.unconditional = 65536

    def pad_until_refused(self, declared: int, supplied: bytes,
                          limit: int = 200) -> 'tuple[int, int, int]':
        """Unpack the same over-long field until the budget refuses it.

        Args:
            declared: Length each field declares.
            supplied: Octets actually handed to each field.
            limit: How many fields to try before giving up.

        Returns:
            ``(padded octets in total, fields accepted, fields refused)``.

        """
        padded = accepted = refused = 0
        for _ in range(limit):
            field = self.BytesField(length=declared)
            try:
                value = field.unpack(supplied, {})
            except self.FieldValueError:
                refused += 1
                continue
            accepted += 1
            padded += len(value) - len(supplied)
        return padded, accepted, refused

    def test_many_fields_each_under_the_ceiling_are_refused_in_total(self) -> None:
        """The #573 scenario: 200 fields, every one of them within the ceiling.

        Each declares two octets short of
        :data:`~pcapkit.corekit.fields.field._MAX_ZERO_PAD_LENGTH` against two
        supplied octets, so #554's per-field guard is *correct* to let each one
        through -- and before #573 all 200 went through, retaining 50.0 MiB from
        4,800 octets of input. At least one has to be refused now, or the sum is
        still unbounded.
        """
        _, accepted, refused = self.pad_until_refused(self.ceiling - 2, b'\xaa\xbb')

        self.assertGreater(refused, 0,
                           'every one of 200 near-ceiling fields was padded: the '
                           'per-field ceiling held and the sum was not bounded at all')
        self.assertGreater(accepted, 0,
                           'not even the first field was padded, so the one-off '
                           'allowance is gone and #554 boundary behaviour has moved')

    def test_total_padding_stays_inside_the_declared_bound(self) -> None:
        """Pins the bound itself, in absolute octets, not just "some refusal happened".

        The figures are written out rather than read back off the module so that
        quietly loosening either constant fails here: 262,144 octets of one-off
        allowance plus 16 octets of padding per octet actually supplied.

        Every attempt is counted towards the octets supplied, refused ones
        included -- a refused field really did read its two octets, and charging
        it for them while denying it the credit would make the ledger a record of
        something other than what happened.
        """
        declared = self.ceiling - 2
        supplied = b'\xaa\xbb'
        attempts = 200
        padded, _, _ = self.pad_until_refused(declared, supplied, limit=attempts)

        allowance = 262144 + 16 * len(supplied) * attempts
        self.assertLessEqual(padded, allowance)

        # and the bound has to actually bite on this input, or asserting it
        # proves nothing: 200 unbounded fields would have padded 52.4 MiB.
        self.assertLess(padded, attempts * declared // 10)

    def test_the_amplification_against_wire_octets_is_bounded(self) -> None:
        """The ratio #573 is actually about: retained octets per wire octet.

        The issue measures 10,922x per block for this shape, from a minimal
        24-octet Decryption Secrets Block. Reproduced here at field level with
        the same 24 octets of notional wire cost per field, the amplification has
        to come down by at least an order of magnitude -- and this asserts on the
        ratio itself, which a smoke test for "an exception was raised" does not.
        """
        declared = self.ceiling - 2
        blocks = 200
        wire_octets = blocks * 24  # a minimal DSB is 24 octets on the wire

        padded, _, _ = self.pad_until_refused(declared, b'\xaa\xbb', limit=blocks)

        unbounded = blocks * declared / wire_octets  # 10,922x, as #573 reports
        self.assertGreater(unbounded, 10000)

        amplification = padded / wire_octets
        self.assertLess(amplification, unbounded / 100)

    def test_a_long_run_of_ordinary_short_reads_is_still_padded(self) -> None:
        """The #431 path, at scale: small short reads must not exhaust the budget.

        ``OptionField.unpack`` and ``ListField.unpack`` read a fixed-width,
        few-octet field past the end of a truncated option area and need it to
        decode as zero -- that is how an over-long ``ihl`` or a snapshot-truncated
        capture reads as end-of-option-list rather than raising. A capture holds
        very many of those, so a budget that counted them the way it counts a
        quarter-megabyte field would turn the commonest legitimate short read in
        the library into a parse failure once enough of them had happened.
        """
        field = self.BytesField(length=1)
        for _ in range(20000):
            self.assertEqual(field.unpack(b'', {}), b'\x00')

    def test_reading_real_octets_earns_allowance_for_padding_them(self) -> None:
        """A parse that actually reads data is allowed to pad in proportion to it.

        The one-off allowance covers a single large shortfall from a cold start,
        which is what a capture truncated at EOF needs. Reading real data is what
        buys a second one -- a legitimate parse of a large file has supplied the
        octets to pay for it, and a 24-octet block declaring a quarter of a
        megabyte has not.
        """
        # 1 MiB of fields that pad nothing at all.
        bulk = self.BytesField(length=4096)
        for _ in range(256):
            bulk.unpack(b'\xff' * 4096, {})

        # a 4 MiB field over one octet is past the per-field ceiling and stays
        # refused regardless of allowance -- #554's guard is not for sale.
        with self.assertRaises(self.FieldValueError):
            self.BytesField(length=4 * 1024 * 1024).unpack(b'A', {})

        # but several near-ceiling fields in a row are now affordable, where from
        # a cold start only the first was.
        padded, accepted, refused = self.pad_until_refused(self.ceiling - 2,
                                                           b'\xaa\xbb', limit=4)
        self.assertEqual((accepted, refused), (4, 0))
        self.assertEqual(padded, 4 * (self.ceiling - 4))

    def test_a_shortfall_within_a_16_bit_length_is_never_refused(self) -> None:
        """The property that makes the budget safe: the 16-bit band is unconditional.

        Every shortfall a snapshot-truncated capture can produce is one a 16-bit
        wire length declared -- an IP total length, an IPv6 payload length, a TCP
        or IPv4 option length, a PCAP-NG option length -- and the largest found
        anywhere in measurement was 65,495 octets, from a 54-octet snapshot of an
        offload-sized frame. None of those may ever depend on a budget, however
        many of them a capture holds, so this runs 400 of the largest of them back
        to back: 26.2 MiB of padding, which the budget would have refused inside
        the first two.
        """
        declared = self.unconditional  # 65,536: one past what 16 bits can declare
        field = self.BytesField(length=declared)

        for index in range(400):
            value = field.unpack(b'', {})
            self.assertEqual(len(value), declared, f'refused at field {index + 1}')
            self.assertEqual(value, b'\x00' * declared)

    def test_the_same_short_read_answers_the_same_whatever_preceded_it(self) -> None:
        """No history dependence, which a running budget alone did not give.

        Measured with a running budget and no unconditional band: the same
        legitimate 54-octet frame declaring an IPv4 total length of 65,535 parsed
        to one result on 37 of 40 identical calls and to a different one on calls
        26, 33 and 39 -- the answer moved with what had been parsed before it,
        which for a library is worse than the amplification it was bounding. The
        shortfall in that frame is 65,495 octets, so this asserts the same
        magnitude answers identically 500 times over.
        """
        field = self.BytesField(length=65495)
        first = field.unpack(b'', {})

        for index in range(500):
            self.assertEqual(field.unpack(b'', {}), first,
                             f'call {index + 1} answered differently from call 1')

    def test_the_unconditional_shortfall_is_65536_and_the_ratio_is_16(self) -> None:
        """Pins both chosen figures and the reasoning behind them.

        65,536 is the whole span of a 16-bit wire length, so no shortfall an IP
        header, an IPv6 payload, a TCP or IPv4 option or a PCAP-NG option can ask
        for is ever subject to the budget -- the measured worst legitimate single
        shortfall, 65,495, is inside it, and so is anything else 16 bits can
        express. 16 then governs only the 32-bit band above, where a legitimate
        shortfall is a once-per-file event that the one-off allowance already
        covers whole. A test that only read the constants back from the module
        would still pass if either figure were changed to something unjustified.
        """
        self.assertEqual(self.field_module._MAX_ZERO_PAD_SHORTFALL, 65536)
        self.assertEqual(2 ** 16, 65536)
        self.assertGreater(65536, 65495)  # the worst legitimate shortfall measured

        self.assertEqual(self.field_module._ZERO_PAD_BUDGET_RATIO, 16)

        # and the bands have to be the right way round, or the 32-bit band would
        # swallow the 16-bit one.
        self.assertLess(self.unconditional, self.ceiling)

    def test_the_scope_gives_a_parse_a_budget_of_its_own(self) -> None:
        """``_zero_pad_budget`` is what makes the bound per-parse rather than per-context.

        The ledger is cumulative on purpose -- a long-lived process that keeps
        reading real captures keeps earning allowance -- so a caller wanting one
        file bounded on its own has to be able to say so, and a test asserting on
        the bound has to be able to start from a known ledger.
        """
        declared = self.ceiling - 2
        attempts = 200

        with self.field_module._zero_pad_budget() as ledger:
            first, _, _ = self.pad_until_refused(declared, b'\xaa\xbb', limit=attempts)
            self.assertEqual(ledger[0], 2 * attempts)
            self.assertEqual(ledger[1], first)

        with self.field_module._zero_pad_budget() as ledger:
            self.assertEqual(ledger, [0, 0])
            second, _, _ = self.pad_until_refused(declared, b'\xaa\xbb', limit=attempts)

        self.assertEqual(first, second)

    def test_the_scope_restores_the_ledger_it_replaced(self) -> None:
        """Leaving the scope must not hand the outer parse a spent budget, or a
        fresh one."""
        outer = self.BytesField(length=8)
        outer.unpack(b'\x01', {})
        before = list(self.field_module._zero_pad_ledger.get())

        with self.field_module._zero_pad_budget():
            self.pad_until_refused(self.ceiling - 2, b'\xaa\xbb', limit=4)

        self.assertEqual(list(self.field_module._zero_pad_ledger.get()), before)

    def test_a_thread_does_not_spend_another_thread_s_budget(self) -> None:
        """Two captures parsed concurrently get a budget each.

        A plain module-level counter would make one thread's near-ceiling field
        cost the other thread its padding, which is a parse failure that depends
        on what an unrelated thread happened to be doing. A new thread runs in an
        empty :class:`~contextvars.Context`, so it installs a ledger of its own.
        """
        declared = self.ceiling - 2
        results = {}  # type: dict[str, int]

        def parse(name: str) -> None:
            _, accepted, _ = self.pad_until_refused(declared, b'\xaa\xbb', limit=4)
            results[name] = accepted

        threads = [threading.Thread(target=parse, args=(f'thread-{index}',))
                   for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(results), 4)
        self.assertEqual(set(results.values()), {min(results.values())})
        self.assertGreater(min(results.values()), 0)

    def test_the_budget_refusal_does_not_wedge_the_rest_of_the_parse(self) -> None:
        """A refused field must not stop the small short reads that follow it.

        A capture whose first block is hostile is still a capture, and the option
        and list loops after it depend on their few-octet reads decoding as zero.
        A budget that stayed exhausted for everything afterwards would turn one
        refused field into a dead parse.
        """
        self.pad_until_refused(self.ceiling - 2, b'\xaa\xbb')

        with time_limit(5):
            self.assertEqual(self.BytesField(length=1).unpack(b'', {}), b'\x00')
            self.assertEqual(self.BytesField(length=4).unpack(b'\x01\x02\x03', {}),
                             b'\x00\x01\x02\x03')

    def test_the_refusal_message_names_the_padding_the_ledger_and_the_allowance(self) -> None:
        declared = self.ceiling - 2

        with self.field_module._zero_pad_budget():
            message = ''
            for _ in range(200):
                try:
                    self.BytesField(length=declared).unpack(b'\xaa\xbb', {})
                except self.FieldValueError as exc:
                    message = str(exc)
                    break

        self.assertIn('zero-pad', message)
        self.assertIn(str(declared - 2), message)  # the padding refused
        self.assertIn('actually read', message)
        self.assertIn('allowed', message)

    def test_a_field_that_is_not_short_is_never_refused_by_the_budget(self) -> None:
        """Padding is what the budget is spent on, so a full buffer never spends any.

        A large field whose octets genuinely arrived is not amplification at all,
        and running many of them must not walk the ledger towards a refusal.
        """
        size = 4096
        buffer = b'\xcd' * size

        with self.field_module._zero_pad_budget() as ledger:
            for _ in range(500):
                self.assertEqual(self.BytesField(length=size).unpack(buffer, {}), buffer)
            self.assertEqual(ledger[1], 0)
            self.assertEqual(ledger[0], 500 * size)
