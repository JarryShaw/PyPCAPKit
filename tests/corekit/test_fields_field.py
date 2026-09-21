from __future__ import annotations

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
