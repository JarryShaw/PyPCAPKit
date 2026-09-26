from __future__ import annotations

import struct
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
        short buffer and must still decode -- as zero, on the octets that
        were never read -- rather than raise, or every capture cut short
        by its snapshot length would start failing to parse instead of
        reporting the tail as padding. This field is nowhere near
        :data:`~pcapkit.corekit.fields.field._MAX_ZERO_PAD_LENGTH`, so the
        shortfall must still be padded exactly as before #554.

        The zeros land on the *tail*, which is where the unread octets were:
        a short read has lost the end of the buffer, not the start of it.
        Before #604 they were placed at the front instead, which corrupted
        the value rather than merely padding it -- see
        :class:`FieldBaseShortReadPaddingSideTests` below.
        """
        field = self.BytesField(length=4)
        self.assertEqual(field.unpack(b'\x01\x02\x03', {}), b'\x01\x02\x03\x00')

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

        # ljust() left-justifies: the one real octet stays where it was read,
        # at the front, and the padding fills the tail that was never read.
        # Before #604 this was the other way round.
        self.assertEqual(len(result), self.ceiling)
        self.assertEqual(result[:1], b'A')
        self.assertEqual(result[1:], b'\x00' * (self.ceiling - 1))

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
                             b'\x01\x02\x03\x00')

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


class FieldBaseShortReadPaddingSideTests(unittest.TestCase):
    """Which *side* the short-read zero padding goes on, for both byte orders.

    The two classes above are about *how much* padding
    :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>` will
    synthesise (#554, #573). This one is about where it lands, which is a
    different defect with a different symptom: it corrupts values rather than
    exhausting memory, and it does so silently -- no exception, no warning, just
    a plausible integer that is wrong.

    Before #604 the padding was applied with ``rjust()``, which places the zeros
    at the *front* of the buffer. That asserts that the octets which were never
    read were the *leading* ones. A short read asserts the opposite: the buffer
    ran out, so what is missing is whatever came *after* what was read. The zeros
    therefore belong at the end, which is ``ljust()``.

    The correction is **not** byte-order-conditional, and that is the point worth
    pinning. ``rjust()`` is wrong for a big-endian field exactly as it is for a
    little-endian one; the two merely fail in opposite directions:

    * little-endian, one octet of a four-octet ``120`` (``0x78``) --
      ``rjust()`` gives ``00 00 00 78`` read little-endian, i.e. 2,013,265,920,
      inflating the value by ``2 ** 24``. ``ljust()`` gives ``78 00 00 00``,
      i.e. 120.
    * big-endian, three octets of a four-octet ``0x01020304`` --
      ``rjust()`` gives ``00 01 02 03``, i.e. ``0x10203``, scaling the value
      *down* by 256. ``ljust()`` gives ``01 02 03 00``, i.e. ``0x1020300``.

    The big-endian direction is the dangerous one. An inflated length is loud: it
    overruns, or asks for an allocation nothing will grant. A length scaled
    *down* by a factor of 256 is a smaller, entirely plausible number that passes
    a sanity check and truncates real data instead. That asymmetry is why the
    little-endian symptom is the one that got reported and the big-endian one sat
    unnoticed -- and why a big-endian field must be tested with a value whose
    high octets are *not* zero. Given a small big-endian value such as 120, whose
    wire form is ``00 00 00 78``, ``rjust()`` restores exactly the leading zeros
    that were lost and answers correctly by accident.

    Every case here is also checked at more than one width, because a single
    width cannot distinguish "pads on the correct side" from "happens to agree
    for four octets", and the widths are what a regression would most plausibly
    get selectively wrong.

    What this must **not** change is *whether* a truncated capture parses. The
    short-read accommodation is deliberate (#431), the budget above is built
    around preserving it, and third-party PR #571 was declined for breaking it.
    So the cases that the option and list loops depend on -- above all a read
    against an entirely empty buffer, which pads to all zeros either way -- are
    asserted here too, unchanged.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields.numbers import (Int32Field, UInt16Field, UInt32Field,
                                                    UInt64Field)
        from pcapkit.corekit.fields.strings import BytesField

        self.BytesField = BytesField
        self.Int32Field = Int32Field
        self.UInt16Field = UInt16Field
        self.UInt32Field = UInt32Field
        self.UInt64Field = UInt64Field

    def truncate(self, value: int, width: int, byteorder: str, kept: int) -> bytes:
        """The first ``kept`` octets of ``value`` as it appears on the wire.

        Args:
            value: The value the capture actually held.
            width: Field width, in octets.
            byteorder: ``'big'`` or ``'little'``.
            kept: How many octets of the field were captured.

        Returns:
            The octets a short read would be handed.

        Truncation cuts the *end* of a buffer, so this is a prefix of the wire
        form -- which is what makes the missing octets the trailing ones whatever
        the byte order is.

        """
        return value.to_bytes(width, byteorder)[:kept]  # type: ignore[arg-type]

    def expected(self, value: int, width: int, byteorder: str, kept: int) -> int:
        """What a short read of ``kept`` octets should report.

        The unread octets are unknown and assumed zero, so the answer is the
        truncated wire form zero-filled back to ``width`` and decoded. Derived
        from the wire form rather than written out, so it states the property
        under test instead of restating the implementation's arithmetic.
        """
        wire = self.truncate(value, width, byteorder, kept).ljust(width, b'\x00')
        return int.from_bytes(wire, byteorder)  # type: ignore[arg-type]

    def test_the_issue_s_little_endian_figure(self) -> None:
        """Exactly the case #604 reports, pinned as a literal.

        One octet of a four-octet little-endian 120. ``rjust()`` answered
        2,013,265,920 -- wrong by seven orders of magnitude, with no exception
        and no warning. The literals are written out rather than computed so that
        this test states the issue's own measured figures and cannot drift with a
        helper.
        """
        field = self.UInt32Field(byteorder='little')

        self.assertEqual(field.unpack(b'\x78', {}), 120)
        self.assertNotEqual(field.unpack(b'\x78', {}), 2013265920)

    def test_the_issue_s_big_endian_figure(self) -> None:
        """The other half of #604, which the issue title understated.

        Three octets of a four-octet big-endian ``0x01020304``. ``rjust()``
        answered ``0x10203``, scaling the value down by 256 -- the direction that
        passes a sanity check, which is why it went unnoticed. ``ljust()``
        answers ``0x1020300``: the three octets that were read, in place, with
        the one that was not assumed zero.
        """
        field = self.UInt32Field(byteorder='big')

        self.assertEqual(field.unpack(b'\x01\x02\x03', {}), 0x1020300)
        self.assertNotEqual(field.unpack(b'\x01\x02\x03', {}), 0x10203)

    def test_a_short_read_is_value_preserving_at_every_width_and_order(self) -> None:
        """The property, rather than a table of expected numbers.

        For every width, both byte orders, and every possible shortfall, a short
        read must report the octets it was given *in the positions they occupy on
        the wire*, with the octets it was not given assumed zero. That is one
        statement covering 2-, 4- and 8-octet fields at every truncation point,
        and it is the statement ``rjust()`` violates.

        The value is chosen so that no octet is zero and every octet differs, so
        a padding side that is wrong -- or a width read with the wrong endianness
        -- cannot coincide with the right answer.
        """
        cases = [
            (2, self.UInt16Field, 0x0102),
            (4, self.UInt32Field, 0x01020304),
            (8, self.UInt64Field, 0x0102030405060708),
        ]

        for width, cls, value in cases:
            for byteorder in ('big', 'little'):
                field = cls(byteorder=byteorder)  # type: ignore[call-arg]
                for kept in range(width + 1):
                    buffer = self.truncate(value, width, byteorder, kept)
                    with self.subTest(width=width, byteorder=byteorder, kept=kept):
                        self.assertEqual(
                            field.unpack(buffer, {}),
                            self.expected(value, width, byteorder, kept),
                        )

    def test_a_full_read_is_untouched_at_every_width_and_order(self) -> None:
        """The regression guard: nothing about a complete field may move.

        The padding side is only ever consulted when the buffer falls short, so a
        field that got all its octets must answer exactly as it did before #604 --
        for a big-endian field especially, since that is the one whose short-read
        behaviour this change alters and whose full-read behaviour must not.
        """
        cases = [
            (2, self.UInt16Field, 0x0102),
            (4, self.UInt32Field, 0x01020304),
            (8, self.UInt64Field, 0x0102030405060708),
        ]

        for width, cls, value in cases:
            for byteorder in ('big', 'little'):
                field = cls(byteorder=byteorder)  # type: ignore[call-arg]
                wire = value.to_bytes(width, byteorder)  # type: ignore[arg-type]
                with self.subTest(width=width, byteorder=byteorder):
                    self.assertEqual(field.unpack(wire, {}), value)
                    # and trailing octets beyond the field are not this field's
                    self.assertEqual(field.unpack(wire + b'\xff\xff', {}), value)

    def test_a_little_endian_short_read_is_never_inflated(self) -> None:
        """The little-endian failure direction, stated as an inequality.

        ``rjust()`` on a little-endian field moves every octet read into a
        *higher* position than it occupies on the wire, so the reported value
        exceeds the truth -- by ``2 ** 24`` in the reported case. Whatever the
        width or shortfall, a short read can only ever drop information, so it
        must never report more than the value actually held.
        """
        for width, cls, value in ((2, self.UInt16Field, 0x0102),
                                  (4, self.UInt32Field, 0x01020304),
                                  (8, self.UInt64Field, 0x0102030405060708)):
            field = cls(byteorder='little')  # type: ignore[call-arg]
            for kept in range(width):
                buffer = self.truncate(value, width, 'little', kept)
                with self.subTest(width=width, kept=kept):
                    self.assertLessEqual(field.unpack(buffer, {}), value)

    def test_a_big_endian_short_read_keeps_the_octets_it_read_in_place(self) -> None:
        """The big-endian failure direction: the octets must not slide down.

        ``rjust()`` shifted every octet read towards the low end, dividing the
        value by 256 per missing octet -- so ``0x01020304`` truncated to three
        octets read as ``0x10203`` rather than ``0x1020300``. Asserting the
        leading octets survive at full magnitude is what catches that: the value
        read must still be at least the truth with the unread octets zeroed,
        which for a big-endian field means the most significant ones are intact.
        """
        for width, cls, value in ((2, self.UInt16Field, 0x0102),
                                  (4, self.UInt32Field, 0x01020304),
                                  (8, self.UInt64Field, 0x0102030405060708)):
            field = cls(byteorder='big')  # type: ignore[call-arg]
            for kept in range(1, width):
                buffer = self.truncate(value, width, 'big', kept)
                read = field.unpack(buffer, {})
                with self.subTest(width=width, kept=kept):
                    # the octets read are the high ones and keep their magnitude
                    self.assertEqual(read >> (8 * (width - kept)),
                                     value >> (8 * (width - kept)))
                    # which the rjust() answer, scaled down by the shortfall,
                    # was not
                    self.assertNotEqual(read, value >> (8 * (width - kept)))

    def test_a_signed_field_pads_on_the_same_side(self) -> None:
        """Signedness is orthogonal to the padding side, and must stay so.

        The sign lives in the most significant octet, so on a big-endian field it
        is read first and survives a short read; on a little-endian one it is the
        last octet and is exactly what a truncated capture loses. Under
        ``rjust()`` a truncated little-endian negative value silently became a
        small positive one, because the octet carrying the sign was synthesised
        as zero *and* the octets that were read were moved into its place.
        """
        value = -2  # 0xfffffffe
        for byteorder in ('big', 'little'):
            field = self.Int32Field(byteorder=byteorder)  # type: ignore[call-arg]
            wire = value.to_bytes(4, byteorder, signed=True)  # type: ignore[arg-type]

            with self.subTest(byteorder=byteorder, kept=4):
                self.assertEqual(field.unpack(wire, {}), value)

            for kept in range(1, 4):
                expected = int.from_bytes(
                    wire[:kept].ljust(4, b'\x00'), byteorder, signed=True  # type: ignore[arg-type]
                )
                with self.subTest(byteorder=byteorder, kept=kept):
                    self.assertEqual(field.unpack(wire[:kept], {}), expected)

    def test_a_byte_string_field_keeps_its_octets_at_the_front(self) -> None:
        """A truncated blob loses its tail, so the zeros go on the tail.

        :class:`~pcapkit.corekit.fields.strings.BytesField` unpacks through the
        same line with an ``Ns`` template, so the padding side decides where the
        real octets sit in the value handed to the caller. ``rjust()`` returned
        ``b'\\x00\\x01\\x02\\x03'`` for three octets of a four-octet field,
        which claims a leading zero octet that was never on the wire and hides
        the fact that the tail is what is missing.
        """
        for width in (2, 4, 8):
            data = bytes(range(1, width + 1))
            for kept in range(width + 1):
                field = self.BytesField(length=width)
                with self.subTest(width=width, kept=kept):
                    self.assertEqual(field.unpack(data[:kept], {}),
                                     data[:kept] + b'\x00' * (width - kept))

    def test_an_entirely_empty_buffer_still_reads_as_zero(self) -> None:
        """The #431 invariant, which this change must not disturb.

        ``OptionField.unpack`` and ``ListField.unpack`` read a fixed-width,
        few-octet field past the end of a truncated option area and need it to
        decode as ``0`` -- that is how an over-long ``ihl`` or a capture cut
        short by its snapshot length reads as end-of-option-list or ``Pad1``
        rather than raising. With nothing at all in the buffer the whole field is
        padding, so both ``rjust()`` and ``ljust()`` produce all zeros and the
        answer is the same before and after #604. Asserted explicitly, because it
        is the property a fix to the padding side could most easily have broken
        and the one that declined #571.
        """
        for byteorder in ('big', 'little'):
            for cls in (self.UInt16Field, self.UInt32Field, self.UInt64Field):
                field = cls(byteorder=byteorder)  # type: ignore[call-arg]
                with self.subTest(byteorder=byteorder, field=cls.__name__):
                    self.assertEqual(field.unpack(b'', {}), 0)

        for width in (1, 4, 16):
            with self.subTest(bytes_width=width):
                self.assertEqual(self.BytesField(length=width).unpack(b'', {}),
                                 b'\x00' * width)

    def test_a_short_read_round_trips_back_to_the_padded_wire_form(self) -> None:
        """``pack`` of what ``unpack`` reported must reproduce the padded buffer.

        :meth:`FieldBase.pack <pcapkit.corekit.fields.field.FieldBase.pack>`
        writes the field's full width, so the only wire form a short read's value
        can legitimately correspond to is the octets that were read followed by
        the zeros that were synthesised for the ones that were not. Under
        ``rjust()`` it did not: the value packed back to the *padding* in front of
        the data, so an unpack/pack cycle moved the real octets. This is the
        cheapest statement that the reported value and the buffer agree about
        which octets were missing.
        """
        cases = [
            (2, self.UInt16Field, 0x0102),
            (4, self.UInt32Field, 0x01020304),
            (8, self.UInt64Field, 0x0102030405060708),
        ]

        for width, cls, value in cases:
            for byteorder in ('big', 'little'):
                field = cls(byteorder=byteorder)  # type: ignore[call-arg]
                for kept in range(width + 1):
                    buffer = self.truncate(value, width, byteorder, kept)
                    read = field.unpack(buffer, {})
                    with self.subTest(width=width, byteorder=byteorder, kept=kept):
                        self.assertEqual(field.pack(read, {}),
                                         buffer.ljust(width, b'\x00'))


class FieldBaseLengthNegativeResolvedLengthTests(unittest.TestCase):
    """:attr:`FieldBase.length <pcapkit.corekit.fields.field.FieldBase.length>`
    on a negative resolved length.

    A ``length=lambda pkt: pkt['__length__']``-style callback is
    attacker/corruption-controlled the same way :attr:`FieldBase.unpack`'s
    ``length`` argument is (see the class above): :meth:`Schema.unpack
    <pcapkit.protocols.schema.schema.Schema.unpack>` decrements
    ``packet['__length__']`` by each field's nominal width regardless of how
    many octets the buffer actually held, and a subsequent field's callback
    can resolve to that negative remainder. :class:`~pcapkit.corekit.fields.
    strings._TextField.__call__` then builds a template such as ``'-5s'``
    from it with no lower bound, and :func:`struct.calcsize` cannot size
    that -- pre-fix this surfaced as a bare, uncatchable :exc:`struct.error`
    (GitHub issue #805).

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields.numbers import NumberField
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.utilities.exceptions import ProtocolError

        self.BytesField = BytesField
        self.NumberField = NumberField
        self.ProtocolError = ProtocolError

    def test_a_negative_resolved_length_raises_protocolerror_not_structerror(self) -> None:
        """The crash reproduction from #805, isolated to the field property.

        Pre-fix, ``struct.error: bad char in struct format`` -- a bare
        stdlib exception, not even a :exc:`ValueError`, uncatchable by
        ordinary caller code -- escaped here. This is the exact shape
        HTTP/2's ``GoawayFrame.debug``/``PushPromiseFrame.fragment`` fields
        hit once their fixed-width siblings have already driven
        ``pkt['__length__']`` negative.
        """
        field = self.BytesField(length=lambda pkt: pkt['__length__'])({'__length__': -5})

        self.assertEqual(field.template, '-5s')
        with self.assertRaises(self.ProtocolError) as ctx:
            field.length  # noqa: B018 -- property access is the point

        # must not be a bare struct.error: ProtocolError is a ValueError
        # subclass in this library's hierarchy, never struct.error itself.
        self.assertIsInstance(ctx.exception, ValueError)
        self.assertNotIsInstance(ctx.exception, struct.error)

    def test_a_zero_or_positive_resolved_length_is_unaffected(self) -> None:
        """The fix must not change the answer for any non-negative length.

        The property is a thin ``try/except`` around the same
        :func:`struct.calcsize` call as before; a resolved length that never
        raises must return exactly what it always returned.
        """
        for resolved in (0, 1, 5, 1024):
            with self.subTest(resolved=resolved):
                field = self.BytesField(length=lambda pkt: pkt['__length__'])(
                    {'__length__': resolved})
                self.assertEqual(field.length, resolved)

    def test_a_malformed_template_raises_protocolerror_naming_the_template(self) -> None:
        """A typo'd template is a category error, not a negative length (#825).

        :func:`struct.calcsize` raises the identical bare :exc:`struct.error`
        -- ``bad char in struct format`` -- for a malformed template as it
        does for a negative one (measured on 3.14.7: ``calcsize('-1s')`` and
        ``calcsize('Xs')`` both raise it). Pre-fix, :attr:`FieldBase.length
        <pcapkit.corekit.fields.field.FieldBase.length>` caught that blanket
        and always reported "resolved to a negative length", which would have
        misdiagnosed this case. The template here (``'Xs'``) never matches
        the leading-minus-sign shape a resolved negative count takes, so it
        must fall to the distinct, template-naming message instead.
        """
        field = self.BytesField(length=4)
        field.name = 'weird'
        field._template = 'Xs'  # a typo, not a resolved negative count

        with self.assertRaises(self.ProtocolError) as ctx:
            field.length  # noqa: B018 -- property access is the point

        message = str(ctx.exception)
        self.assertIn('Xs', message)
        self.assertNotIn('negative length', message)

        # must not be a bare struct.error, and must still chain to the real
        # one struct.calcsize actually raised.
        self.assertNotIsInstance(ctx.exception, struct.error)
        self.assertIsInstance(ctx.exception.__cause__, struct.error)

    def test_a_byte_order_prefixed_negative_length_is_still_reported_as_negative(self) -> None:
        """A prefixed negative template must not be misdiagnosed as malformed (#827).

        :class:`~pcapkit.corekit.fields.numbers.NumberField` builds its
        template as ``f'{endian}{struct_fmt}'``
        (:meth:`NumberField.__init__ <pcapkit.corekit.fields.numbers.
        NumberField.__init__>`) over the same ``f'{length}s'`` fall-through
        every other field uses (:meth:`NumberField.build_template
        <pcapkit.corekit.fields.numbers.NumberField.build_template>`'s
        ``else`` arm) -- so a negative resolved length comes out prefixed,
        e.g. ``'>-1s'``, not bare ``'-1s'``. Uses the real ``NumberField``
        construction path rather than hand-setting ``_template``, so this
        would catch a future change to how templates are assembled, not
        just to the regex.
        """
        field = self.NumberField(length=-1)
        field.name = 'number'

        self.assertEqual(field.template, '>-1s')
        with self.assertRaises(self.ProtocolError) as ctx:
            field.length  # noqa: B018 -- property access is the point

        message = str(ctx.exception)
        self.assertIn('negative length', message)
        self.assertNotIn('malformed', message)
        self.assertNotIsInstance(ctx.exception, struct.error)
        self.assertIsInstance(ctx.exception.__cause__, struct.error)

    def test_negative_and_malformed_templates_are_reported_distinctly(self) -> None:
        """The two categories never trade messages, and neither leaks a bare
        :exc:`struct.error` -- across both, not just one.
        """
        cases = {
            'negative': (self.BytesField(length=lambda pkt: pkt['__length__'])(
                {'__length__': -1}), None),
            'malformed': (self.BytesField(length=4), 'Xs'),
        }
        for label, (field, forced_template) in cases.items():
            with self.subTest(case=label):
                field.name = 'field'
                if forced_template is not None:
                    field._template = forced_template

                with self.assertRaises(self.ProtocolError) as ctx:
                    field.length  # noqa: B018 -- property access is the point

                message = str(ctx.exception)
                if label == 'negative':
                    self.assertIn('negative length', message)
                else:
                    self.assertNotIn('negative length', message)
                    self.assertIn(field.template, message)

                self.assertNotIsInstance(ctx.exception, struct.error)
                self.assertIsInstance(ctx.exception.__cause__, struct.error)


if __name__ == '__main__':
    unittest.main()
