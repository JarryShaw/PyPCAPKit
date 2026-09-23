# -*- coding: utf-8 -*-
"""HTTP/2 payload lengths, asserted against the octets that went onto the wire.

GitHub issue #668. Three payload length callbacks in
:mod:`pcapkit.protocols.schema.application.httpv2` put the conditional
expression in the wrong place, so an **unpadded** ``DATA``, ``HEADERS`` or
``PUSH_PROMISE`` frame parsed with its whole payload silently discarded.

What the grouping did
---------------------

A conditional expression binds looser than ``-``, so::

    length=lambda pkt: pkt['__length__'] - pkt['pad_len'] if pkt['flags']['bit_3'] else 0

groups as ``(pkt['__length__'] - pkt['pad_len']) if pkt['flags']['bit_3'] else 0``
-- the whole subtraction is the ``if`` arm and the ``else`` arm is a bare ``0``.
``0`` reaches :class:`~pcapkit.corekit.fields.strings.BytesField` as "read no
octets at all", so every frame *without* the ``PADDED`` flag read its payload as
``b''``. The intent was to subtract nothing rather than to read nothing::

    length=lambda pkt: pkt['__length__'] - (pkt['pad_len'] if pkt['flags']['bit_3'] else 0)

``__length__`` is the *remaining* declared length at the field, so the unpadded
arm wants ``__length__`` itself, which is what subtracting a zero padding length
gives. Padding is rare in HTTP/2, so the broken arm was the common one: nothing
raised, nothing warned, and ``info.data`` was simply empty.

Why the arithmetic comes out
----------------------------

:meth:`~pcapkit.protocols.schema.schema.Schema.unpack` decrements
``packet['__length__']`` by every field's width as it goes, so at the payload
field ``__length__`` is whatever the preceding fields left. For a padded
``DATA`` frame whose declared payload is ``1 + len(data) + pad_len``, the
one-octet ``pad_len`` field has already been consumed, leaving
``len(data) + pad_len``; subtracting ``pad_len`` gives ``len(data)``. For the
unpadded frame nothing precedes the payload, so ``__length__`` *is*
``len(data)``. Both arms are therefore exact, and the padded arm has no
off-by-one -- which #668 asked to be checked separately rather than assumed.
:class:`HTTPv2DataFramePayloadLengthUnitTests` and its siblings assert both.

Note also that the two expressions are *equal whenever ``PADDED`` is set*
(``(A - B) if T else 0`` and ``A - (B if T else 0)`` are both ``A - B`` for
truthy ``T``), so only the unpadded arm could ever have changed. The padded
cases below are here to prove that from behaviour rather than from the shape of
the conditional, and to catch a "fix" that repairs the unpadded arm by breaking
the padded one.

It broke construction as well as parsing
---------------------------------------

:class:`~pcapkit.corekit.fields.strings.BytesField` consults its ``length``
callback on the *pack* path too, so the ``else 0`` arm did not merely discard a
payload on read -- it declined to write one. Measured pre-fix,
``bytes(HTTP(type=Frame.DATA, sid=1, frame={'data': DATA_PAYLOAD}))`` packed
``000015000000000001``: nine octets of header whose length field declares
**21**, with the body absent. A reader walking a stream by that length field is
handed a frame twelve octets shorter than it claims, which desynchronises
everything after it. #668 is filed as a parse-side defect and the construct side
needed no code change, so
:class:`HTTPv2ConstructedFrameDeclaresWhatItWritesUnitTests` asserts that half
rather than leaving it implied.

Why the assertions are on bytes and not on lengths
--------------------------------------------------

``self.assertEqual(len(info.data), 12)`` passes under a fix that reads the right
*number* of octets from the wrong offset, and under one that drops the
subtraction entirely if the payload and the padding happen to add up. So every
assertion here names the octets. The padding in each padded case is a
distinctive non-zero pattern (:data:`PADDING`) rather than the zeros
:rfc:`9113#section-6.1` tells a sender to use, precisely so that a fix which
forgets to subtract it shows up as ``PAYLOAD + PADDING`` -- a different byte
string -- rather than as a coincidentally equal length. pcapkit does not police
padding content, so this is input its parser has to handle either way.

Why the zero-length payload cases are here
------------------------------------------

Each of the three frames has a "frame of only padding" case, where ``pad_len``
accounts for the whole payload area and the payload is legitimately empty. Those
are not padding of the test matrix: a cross-review on a second model found that
with only the ``DATA`` one present -- every other fixture carrying a non-empty
payload -- the module was satisfied by a wrong fix returning
``max(computed, 1)`` for the two ``fragment`` fields, which passed all fifteen
tests while leaking a padding octet into the fragment and swallowing a
``SchemaWarning: packet length < 0: -1``. ``0`` is a legitimate answer from
these callbacks and has to be asserted as one, at the wire and at the callback
both; :meth:`HTTPv2PayloadLengthCallbackUnitTests.\
test_the_padded_arm_reaches_zero_and_is_not_clamped` is the latter.

The clean controls
------------------

:attr:`~pcapkit.protocols.schema.application.httpv2.ContinuationFrame.fragment`,
:attr:`~pcapkit.protocols.schema.application.httpv2.UnassignedFrame.data` and
:attr:`~pcapkit.protocols.schema.application.httpv2.GoawayFrame.debug` use the
plain ``length=lambda pkt: pkt['__length__']`` with no conditional, and all
three carried their payload correctly the whole time.
:class:`HTTPv2PlainLengthFormControlUnitTests` asserts them, because they are
what shows the field machinery was never at fault -- it was the conditional's
grouping alone.

Why the round-trip suite could not see it
----------------------------------------

:mod:`tests.protocols.test_option_roundtrip_unit` drives every HTTP/2 frame
type, but through ``make`` -> parse -> ``make``, and ``make`` writes the length
field from ``HTTP._make_http_length``. Both sides therefore agreed on an empty
payload and the octets matched. Its generator also passes no ``data`` or
``fragment`` argument for these three frames (measured: ``kwargs={}`` for
``httpv2-frame/DATA``, ``/HEADERS`` and ``/PUSH_PROMISE``), so the payload it
round-trips is ``b''`` and there was nothing for the callback to lose.
:meth:`tests.protocols.application.test_http_unit.HTTPUnitTests.test_httpv2_frame_readers_cover_successful_frames`
drives the readers with hand-built schema stubs rather than wire bytes, so the
length callback never ran there at all. This module reads wire octets, which is
the gap -- and asserts the packed octets too, which no existing test did either.

This module is unit tier: it builds its own octets and reads no capture.

"""

from __future__ import annotations

import importlib.util
import io
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A ``DATA`` frame payload. Twelve octets, no repeated substring, and not equal
#: in length to any other constant here, so a read at the wrong offset or of the
#: wrong width changes the octets rather than just the count.
DATA_PAYLOAD = b'{"ok":true}\n'

#: A ``HEADERS``/``PUSH_PROMISE`` header block fragment. The HPACK encoding of
#: ``:method: GET``, ``:scheme: http``, ``:path: /`` and a literal
#: ``:authority: www.example.com``, from :rfc:`7541` appendix C.4.1 -- a real
#: fragment rather than filler, so that "this is what HPACK would have been
#: handed" is literally true.
FRAGMENT = b'\x82\x86\x84\x41\x0fwww.example.com'

#: Padding octets for the padded cases. Deliberately **not** zero: see the
#: module docstring. :rfc:`9113#section-6.1` tells a sender to pad with zeros and
#: lets a receiver treat non-zero padding as a protocol error, but pcapkit does
#: not check it, and non-zero padding is what makes a byte assertion able to tell
#: "subtracted the padding" from "read the padding as payload".
PADDING = b'\xde\xad\xbe\xef'

#: A ``GOAWAY`` frame's additional debug data.
DEBUG_DATA = b'\x10too_many_streams\x11'

#: Stream dependency for the ``PRIORITY``-flagged ``HEADERS`` cases: exclusive
#: bit set, stream 2.
STREAM_DEP = (0x80000002).to_bytes(4, 'big')

#: Weight octet for the ``PRIORITY``-flagged ``HEADERS`` cases. The reader
#: reports ``weight + 1``, so 15 on the wire is 16 in the data object.
WEIGHT = 15


def http2_frame_bytes(type_: 'int', flags: 'int', sid: 'int', payload: 'bytes') -> 'bytes':
    """Build the wire octets of one HTTP/2 frame.

    The length field counts the *whole* frame, header included -- this library's
    convention rather than :rfc:`9113#section-4.1`'s, which counts the payload
    alone. ``HTTP.make`` writes ``payload + 9`` and the readers recover the
    payload as ``length - 9``.

    Duplicated from
    :func:`tests.protocols.application.test_http_unit.http2_frame_bytes` rather
    than imported: importing it would execute that module, which purges
    ``pcapkit`` out of :data:`sys.modules` in its own ``setUp``, and a small
    builder is cheaper to repeat than that coupling is to reason about. The two
    must stay in step.

    Args:
        type_: Frame type octet.
        flags: Frame flags octet.
        sid: Stream identifier.
        payload: The frame payload, header excluded.

    Returns:
        The packed frame.

    """
    return (
        (len(payload) + 9).to_bytes(3, 'big')
        + bytes([type_, flags])
        + sid.to_bytes(4, 'big')
        + payload
    )


class FramePayloadMixin:
    """Parse one frame off the wire and hand back its data object."""

    def parse(self, raw: 'bytes') -> 'Any':
        """Parse ``raw`` through the public path and assert nothing warned.

        A :class:`~pcapkit.utilities.warnings.SchemaWarning` is how
        :meth:`~pcapkit.protocols.schema.schema.Schema.unpack` reports
        ``__length__`` having gone negative, i.e. a field having read past the
        declared payload. Requiring silence makes that an assertion rather than
        something a reader has to notice in the captured output.

        Args:
            raw: The whole frame, header included.

        Returns:
            The parsed data object, i.e. ``HTTP(...).info``.

        """
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            info = HTTPv2(io.BytesIO(raw), len(raw)).info

        self.assertEqual(  # type: ignore[attr-defined]
            [str(entry.message) for entry in caught], [],
            'parsing a well-formed frame must not warn; a warning here means a '
            'field read past the declared payload length'
        )
        return info


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2DataFramePayloadLengthUnitTests(FramePayloadMixin, unittest.TestCase):
    """``DATA`` -- ``pcapkit/protocols/schema/application/httpv2.py:210``."""

    #: ``DATA``, :rfc:`9113#section-6.1`.
    TYPE = 0x00
    #: ``END_STREAM``.
    END_STREAM = 0x01
    #: ``PADDED``.
    PADDED = 0x08

    def test_unpadded_data_frame_keeps_its_whole_payload(self) -> None:
        """An unpadded ``DATA`` frame's payload survives the parse.

        This is #668's headline case. Pre-fix the callback returned ``0`` here
        and ``info.data`` came back ``b''`` -- measured on the octets this test
        builds, which declare twelve payload octets and carried them.

        """
        raw = http2_frame_bytes(self.TYPE, self.END_STREAM, 1, DATA_PAYLOAD)
        info = self.parse(raw)

        self.assertEqual(info.data, DATA_PAYLOAD)
        self.assertEqual(info.pad_len, 0)
        self.assertTrue(info.flags.END_STREAM)
        self.assertFalse(info.flags.PADDED)

    def test_padded_data_frame_keeps_its_payload_and_drops_its_padding(self) -> None:
        """A padded ``DATA`` frame's payload survives, padding excluded.

        The arm that already worked, asserted so that a fix cannot repair the
        unpadded case by breaking this one. :data:`PADDING` is non-zero, so a
        callback that stopped subtracting it would hand back
        ``DATA_PAYLOAD + PADDING`` and be caught here rather than pass on an
        equal length.

        """
        payload = bytes([len(PADDING)]) + DATA_PAYLOAD + PADDING
        raw = http2_frame_bytes(self.TYPE, self.END_STREAM | self.PADDED, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.data, DATA_PAYLOAD)
        self.assertNotIn(PADDING, info.data,
                         'the padding octets must not reach the payload')
        self.assertEqual(info.pad_len, len(PADDING))
        self.assertTrue(info.flags.PADDED)

    def test_a_padded_data_frame_of_only_padding_reads_an_empty_payload(self) -> None:
        """``pad_len`` accounting for the whole payload leaves ``data`` empty.

        The boundary of the padded arm: here ``__length__ - pad_len`` is exactly
        ``0``, which is the one input for which the pre-fix and post-fix
        expressions agree on an empty payload -- and the only shape under which
        ``b''`` is the right answer.

        """
        payload = bytes([len(PADDING)]) + PADDING
        raw = http2_frame_bytes(self.TYPE, self.PADDED, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.data, b'')
        self.assertEqual(info.pad_len, len(PADDING))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2HeadersFramePayloadLengthUnitTests(FramePayloadMixin, unittest.TestCase):
    """``HEADERS`` -- ``pcapkit/protocols/schema/application/httpv2.py:260``."""

    #: ``HEADERS``, :rfc:`9113#section-6.2`.
    TYPE = 0x01
    #: ``END_HEADERS``.
    END_HEADERS = 0x04
    #: ``PADDED``.
    PADDED = 0x08
    #: ``PRIORITY``.
    PRIORITY = 0x20

    def test_unpadded_headers_frame_keeps_its_header_block_fragment(self) -> None:
        """An unpadded ``HEADERS`` frame's fragment survives the parse.

        Pre-fix ``info.fragment`` came back ``b''``, which is what an HPACK
        decoder would have been handed in place of the header block.

        """
        raw = http2_frame_bytes(self.TYPE, self.END_HEADERS, 1, FRAGMENT)
        info = self.parse(raw)

        self.assertEqual(info.fragment, FRAGMENT)
        self.assertEqual(info.pad_len, 0)
        self.assertTrue(info.flags.END_HEADERS)

    def test_padded_headers_frame_keeps_its_fragment_and_drops_its_padding(self) -> None:
        """A padded ``HEADERS`` frame's fragment survives, padding excluded."""
        payload = bytes([len(PADDING)]) + FRAGMENT + PADDING
        raw = http2_frame_bytes(self.TYPE, self.END_HEADERS | self.PADDED, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.fragment, FRAGMENT)
        self.assertNotIn(PADDING, info.fragment,
                         'the padding octets must not reach the fragment')
        self.assertEqual(info.pad_len, len(PADDING))

    def test_unpadded_headers_frame_with_priority_keeps_its_fragment(self) -> None:
        """``PRIORITY`` moves the fragment five octets in, and it still survives.

        The five octets of stream dependency and weight are consumed by fields
        of their own, so ``__length__`` has already been decremented by them by
        the time the fragment's callback runs. Asserting the priority values as
        well as the fragment is what shows the fragment was read from *after*
        them rather than over them.

        """
        payload = STREAM_DEP + bytes([WEIGHT]) + FRAGMENT
        raw = http2_frame_bytes(self.TYPE, self.END_HEADERS | self.PRIORITY, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.fragment, FRAGMENT)
        self.assertTrue(info.excl_dependency)
        self.assertEqual(info.stream_dependency, 2)
        self.assertEqual(info.weight, WEIGHT + 1)
        self.assertEqual(info.pad_len, 0)

    def test_padded_headers_frame_with_priority_keeps_its_fragment(self) -> None:
        """Both conditionals at once: padding subtracted, priority skipped past."""
        payload = (bytes([len(PADDING)]) + STREAM_DEP + bytes([WEIGHT])
                   + FRAGMENT + PADDING)
        raw = http2_frame_bytes(
            self.TYPE, self.END_HEADERS | self.PADDED | self.PRIORITY, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.fragment, FRAGMENT)
        self.assertNotIn(PADDING, info.fragment)
        self.assertEqual(info.pad_len, len(PADDING))
        self.assertEqual(info.weight, WEIGHT + 1)

    def test_a_padded_headers_frame_of_only_padding_reads_an_empty_fragment(self) -> None:
        """``pad_len`` accounting for the whole area leaves ``fragment`` empty.

        The zero-length boundary, and it is load-bearing rather than decorative.
        A cross-review on a second model found that without this case -- and its
        ``PUSH_PROMISE`` and ``PRIORITY`` counterparts below -- the module was
        satisfied by a wrong fix returning ``max(computed, 1)`` for these two
        fields, since every other fixture here has a non-empty fragment and so
        never asks the callback for ``0``. Measured under that mutation: this
        frame's ``fragment`` came back ``b'\\xde'`` -- one padding octet leaked in
        -- alongside a swallowed ``SchemaWarning: packet length < 0: -1``, and all
        15 of the other tests still passed. :meth:`FramePayloadMixin.parse`
        requiring silence is what turns that warning into a failure.

        """
        payload = bytes([len(PADDING)]) + PADDING
        raw = http2_frame_bytes(self.TYPE, self.END_HEADERS | self.PADDED, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.fragment, b'')
        self.assertEqual(info.pad_len, len(PADDING))

    def test_a_padded_priority_headers_frame_of_only_padding_is_empty_too(self) -> None:
        """The same boundary with ``PRIORITY`` also consuming five octets.

        Here three fields have already decremented ``__length__`` -- ``pad_len``,
        the stream dependency and the weight -- before the fragment's callback
        runs, and what is left is exactly the padding. The arithmetic has to
        arrive at ``0`` rather than at something clamped above it.

        """
        payload = (bytes([len(PADDING)]) + STREAM_DEP + bytes([WEIGHT]) + PADDING)
        raw = http2_frame_bytes(
            self.TYPE, self.END_HEADERS | self.PADDED | self.PRIORITY, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.fragment, b'')
        self.assertEqual(info.pad_len, len(PADDING))
        self.assertEqual(info.weight, WEIGHT + 1)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2PushPromiseFramePayloadLengthUnitTests(FramePayloadMixin, unittest.TestCase):
    """``PUSH_PROMISE`` -- ``pcapkit/protocols/schema/application/httpv2.py:357``."""

    #: ``PUSH_PROMISE``, :rfc:`9113#section-6.6`.
    TYPE = 0x05
    #: ``END_HEADERS``.
    END_HEADERS = 0x04
    #: ``PADDED``.
    PADDED = 0x08
    #: The promised stream identifier these cases use.
    PROMISED_SID = 7

    def test_unpadded_push_promise_frame_keeps_its_fragment(self) -> None:
        """An unpadded ``PUSH_PROMISE`` frame's fragment survives the parse.

        The promised stream identifier is asserted too: it sits between
        ``pad_len`` and the fragment, so reading it correctly and the fragment
        as ``b''`` is exactly the pre-fix behaviour, and asserting only the
        fragment would not show that the four octets before it were accounted
        for.

        """
        payload = self.PROMISED_SID.to_bytes(4, 'big') + FRAGMENT
        raw = http2_frame_bytes(self.TYPE, self.END_HEADERS, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.fragment, FRAGMENT)
        self.assertEqual(info.promised_sid, self.PROMISED_SID)
        self.assertEqual(info.pad_len, 0)

    def test_padded_push_promise_frame_keeps_its_fragment_and_drops_padding(self) -> None:
        """A padded ``PUSH_PROMISE`` frame's fragment survives, padding excluded."""
        payload = (bytes([len(PADDING)]) + self.PROMISED_SID.to_bytes(4, 'big')
                   + FRAGMENT + PADDING)
        raw = http2_frame_bytes(self.TYPE, self.END_HEADERS | self.PADDED, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.fragment, FRAGMENT)
        self.assertNotIn(PADDING, info.fragment,
                         'the padding octets must not reach the fragment')
        self.assertEqual(info.promised_sid, self.PROMISED_SID)
        self.assertEqual(info.pad_len, len(PADDING))

    def test_a_padded_push_promise_frame_of_only_padding_is_empty(self) -> None:
        """``pad_len`` accounting for the whole area leaves ``fragment`` empty.

        The zero-length boundary for this frame -- see
        :meth:`HTTPv2HeadersFramePayloadLengthUnitTests.\
test_a_padded_headers_frame_of_only_padding_reads_an_empty_fragment`
        for the wrong fix that passed the module before this case existed. The
        promised stream identifier is asserted as well, since it is the field
        immediately ahead of the fragment and the one an offset error would
        borrow from.

        """
        payload = (bytes([len(PADDING)]) + self.PROMISED_SID.to_bytes(4, 'big')
                   + PADDING)
        raw = http2_frame_bytes(self.TYPE, self.END_HEADERS | self.PADDED, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.fragment, b'')
        self.assertEqual(info.promised_sid, self.PROMISED_SID)
        self.assertEqual(info.pad_len, len(PADDING))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2PlainLengthFormControlUnitTests(FramePayloadMixin, unittest.TestCase):
    """The three frames whose payload length has no conditional at all.

    ``ContinuationFrame.fragment``, ``UnassignedFrame.data`` and
    ``GoawayFrame.debug`` are written ``length=lambda pkt: pkt['__length__']``,
    and all three carried their payload correctly before #668 was fixed as well
    as after. That is what localises the defect to the conditional's grouping
    rather than to :class:`~pcapkit.corekit.fields.strings.BytesField`,
    ``__length__``'s bookkeeping, or the frame dispatch -- all of which these
    frames use identically.

    """

    def test_continuation_frame_carries_its_fragment(self) -> None:
        """``CONTINUATION`` -- ``httpv2.py:426``, the plain form."""
        raw = http2_frame_bytes(0x09, 0x04, 1, FRAGMENT)
        info = self.parse(raw)

        self.assertEqual(info.fragment, FRAGMENT)

    def test_goaway_frame_carries_its_debug_data(self) -> None:
        """``GOAWAY`` -- ``httpv2.py:397``, the plain form."""
        from pcapkit.const.http.error_code import ErrorCode

        payload = ((5).to_bytes(4, 'big')
                   + int(ErrorCode.ENHANCE_YOUR_CALM).to_bytes(4, 'big')
                   + DEBUG_DATA)
        raw = http2_frame_bytes(0x07, 0x00, 1, payload)
        info = self.parse(raw)

        self.assertEqual(info.debug_data, DEBUG_DATA)
        self.assertEqual(info.last_sid, 5)
        self.assertEqual(info.error, ErrorCode.ENHANCE_YOUR_CALM)

    def test_unassigned_frame_carries_its_data(self) -> None:
        """An unregistered frame type -- ``httpv2.py:174``, the plain form.

        ``0xF0`` is in the range :rfc:`9113#section-5.5` leaves for extensions,
        so this is expected traffic; the reader warns about it, which is why the
        warning is suppressed rather than asserted absent as elsewhere here.

        """
        raw = http2_frame_bytes(0xF0, 0x00, 1, DATA_PAYLOAD)

        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        registry = HTTPv2.__dict__['__frame__']
        try:
            with mock.patch('pcapkit.protocols.application.httpv2.warn'):
                info = HTTPv2(io.BytesIO(raw), len(raw)).info
            self.assertEqual(info.data, DATA_PAYLOAD)
        finally:
            registry.pop(Frame(0xF0), None)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2PayloadLengthCallbackUnitTests(unittest.TestCase):
    """The three callbacks, called directly, on the arm that was broken.

    The wire tests above are the ones that matter, but they can only show the
    *consequence*. These call each length callback with a synthetic ``packet``
    and assert the number it returns, which is where the defect actually lived
    and which names the expected value rather than leaving it to be inferred
    from a byte string.

    """

    #: The remaining declared length the synthetic packets claim.
    REMAINING = 12
    #: The padding length the padded synthetic packet claims.
    PAD_LEN = 4

    def fields(self) -> 'list[tuple[str, Any, str]]':
        """The three fields under test, as ``(label, schema, attribute)``.

        Returns:
            One entry per mis-parenthesised site.

        """
        from pcapkit.protocols.schema.application.httpv2 import (DataFrame, HeadersFrame,
                                                                 PushPromiseFrame)
        return [
            ('DataFrame.data', DataFrame, 'data'),
            ('HeadersFrame.fragment', HeadersFrame, 'fragment'),
            ('PushPromiseFrame.fragment', PushPromiseFrame, 'fragment'),
        ]

    def packet(self, *, padded: 'bool') -> 'dict[str, Any]':
        """A synthetic ``packet`` mapping for a length callback.

        ``pad_len`` is :data:`~pcapkit.corekit.fields.field.NoValue` in the
        unpadded mapping because that is what the
        :class:`~pcapkit.corekit.fields.misc.ConditionalField` ahead of the
        payload actually leaves behind when ``PADDED`` is clear -- see
        :meth:`~pcapkit.protocols.schema.schema.Schema.unpack`.

        Args:
            padded: Whether to set the ``PADDED`` flag bit.

        Returns:
            The mapping to hand the callback.

        """
        from pcapkit.corekit.fields.field import NoValue

        flags = {f'bit_{bit}': 0 for bit in range(8)}
        if padded:
            flags['bit_3'] = 1
        return {
            '__length__': self.REMAINING,
            'pad_len': self.PAD_LEN if padded else NoValue,
            'flags': flags,
        }

    def test_the_unpadded_arm_returns_the_remaining_length(self) -> None:
        """With ``PADDED`` clear the callback returns ``__length__``, not ``0``.

        This is #668 stated as a number: pre-fix all three returned ``0`` here,
        which is why an unpadded frame's payload was dropped.

        """
        packet = self.packet(padded=False)
        for label, schema, attribute in self.fields():
            with self.subTest(field=label):
                length = schema.__fields__[attribute](packet).length
                self.assertEqual(
                    length, self.REMAINING,
                    f'{label}: with PADDED clear the payload occupies the whole '
                    f'remaining declared length; returning 0 reads no payload at all'
                )

    def test_the_unpadded_arm_does_not_consult_pad_len(self) -> None:
        """The unpadded arm must not evaluate ``pad_len``.

        ``pad_len`` is :data:`~pcapkit.corekit.fields.field.NoValue` when
        ``PADDED`` is clear, so the conditional has to short-circuit around it.
        It does so in the fixed form because the conditional *is* the right
        operand of the subtraction. This does not discriminate the fix from the
        defect -- the broken grouping short-circuited too, just around the wrong
        thing -- but it does pin the shape against a rewrite that reaches for
        ``pad_len`` unconditionally, e.g. ``__length__ - int(pkt['pad_len'] or 0)``,
        which raises on the value the field machinery actually supplies.

        """
        from pcapkit.corekit.fields.field import NoValue

        packet = self.packet(padded=False)
        self.assertIs(packet['pad_len'], NoValue)

        for label, schema, attribute in self.fields():
            with self.subTest(field=label):
                schema.__fields__[attribute](packet).length  # must not raise

    def test_the_padded_arm_subtracts_exactly_the_padding_length(self) -> None:
        """With ``PADDED`` set the callback returns ``__length__ - pad_len``.

        The arm that always worked, pinned at the level of the number so that a
        change to the unpadded arm cannot quietly move this one. ``pad_len``'s
        own octet is *not* subtracted here, because the field that read it has
        already decremented ``__length__`` by one.

        """
        packet = self.packet(padded=True)
        for label, schema, attribute in self.fields():
            with self.subTest(field=label):
                length = schema.__fields__[attribute](packet).length
                self.assertEqual(
                    length, self.REMAINING - self.PAD_LEN,
                    f'{label}: with PADDED set the payload is the remaining '
                    f'declared length less the padding'
                )

    def test_the_padded_arm_reaches_zero_and_is_not_clamped(self) -> None:
        """``__length__ == pad_len`` must give ``0``, not a floor above it.

        ``0`` is a legitimate answer -- a frame whose padding fills its whole
        payload area has a zero-length payload -- so the callback must be able to
        return it. Pinned as a number because a clamp is the shape of wrong fix
        the wire tests above could not see until their zero-length cases were
        added: ``max(computed, 1)`` satisfies every non-empty fixture and only
        shows up here and at that boundary.

        """
        from pcapkit.corekit.fields.field import NoValue

        packet = {
            '__length__': self.PAD_LEN,
            'pad_len': self.PAD_LEN,
            'flags': {**{f'bit_{bit}': 0 for bit in range(8)}, 'bit_3': 1},
        }
        self.assertIsNot(packet['pad_len'], NoValue)

        for label, schema, attribute in self.fields():
            with self.subTest(field=label):
                length = schema.__fields__[attribute](packet).length
                self.assertEqual(
                    length, 0,
                    f'{label}: padding filling the whole payload area leaves a '
                    f'zero-length payload; the callback must return 0 rather '
                    f'than a clamped minimum'
                )


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2ConstructedFrameDeclaresWhatItWritesUnitTests(unittest.TestCase):
    """The same callback governs ``pack()``, so #668 was a wire-format defect too.

    :class:`~pcapkit.corekit.fields.strings.BytesField` consults its ``length``
    callback on the construct path as well as the parse path, so the ``else 0``
    arm did not merely discard a payload on read -- it declined to *write* one.
    Measured pre-fix: ``bytes(HTTP(type=Frame.DATA, sid=1, frame={'data': body}))``
    packed ``000015000000000001``, nine octets of header whose length field
    declares **21**, with the twelve octets of body absent. Any reader walking a
    stream by that length field is handed a frame that is twelve octets shorter
    than it claims, which desynchronises everything after it.

    The issue frames #668 as a parse-side defect and the construct side needed no
    code change, so this is asserted here rather than left implied by the parse
    tests -- it is the half of the defect that reaches other people's tooling.

    """

    def build(self, **kwargs: 'Any') -> 'bytes':
        """Construct one frame through the public API and pack it.

        Args:
            **kwargs: Forwarded to :class:`~pcapkit.protocols.application.httpv2.HTTP`.

        Returns:
            The packed frame.

        """
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            raw = bytes(HTTPv2(**kwargs))

        self.assertEqual([str(entry.message) for entry in caught], [],
                         'constructing a well-formed frame must not warn')
        return raw

    def assertDeclaresWhatItWrites(self, raw: 'bytes', payload: 'bytes') -> 'None':  # noqa: N802
        """Assert the length field matches the octets packed, and carries ``payload``.

        Args:
            raw: The packed frame.
            payload: The payload octets it must contain.

        """
        self.assertEqual(
            int.from_bytes(raw[:3], 'big'), len(raw),
            'the declared length must match the octets actually written -- this '
            'library counts the whole frame, header included'
        )
        self.assertIn(payload, raw, 'the payload octets must reach the wire')

    def test_an_unpadded_data_frame_writes_the_body_it_declares(self) -> None:
        """``DATA`` -- packed nine octets against a declared 21 pre-fix."""
        raw = self.build(type=0x00, sid=1, frame={'data': DATA_PAYLOAD})
        self.assertDeclaresWhatItWrites(raw, DATA_PAYLOAD)

    def test_an_unpadded_headers_frame_writes_the_fragment_it_declares(self) -> None:
        """``HEADERS`` -- packed nine octets against a declared 29 pre-fix."""
        raw = self.build(type=0x01, sid=1, frame={'fragment': FRAGMENT})
        self.assertDeclaresWhatItWrites(raw, FRAGMENT)

    def test_an_unpadded_push_promise_frame_writes_the_fragment_it_declares(self) -> None:
        """``PUSH_PROMISE`` -- packed thirteen octets against a declared 33 pre-fix.

        Thirteen rather than nine because the promised stream identifier sits
        ahead of the fragment and was written; it is asserted here so that a
        regression cannot lose the fragment while keeping the frame's length
        field self-consistent.

        """
        raw = self.build(type=0x05, sid=1,
                         frame={'promised_sid': 7, 'fragment': FRAGMENT})
        self.assertDeclaresWhatItWrites(raw, FRAGMENT)
        self.assertIn((7).to_bytes(4, 'big'), raw)

    def test_an_unpadded_continuation_frame_is_the_control(self) -> None:
        """``CONTINUATION`` packed its fragment correctly pre-fix as well.

        The plain-form control for the construct path, matching
        :class:`HTTPv2PlainLengthFormControlUnitTests` on the parse path: it
        declared 29 and wrote 29 throughout, which is what shows the construct
        machinery was never the problem either.

        """
        raw = self.build(type=0x09, sid=1, frame={'fragment': FRAGMENT})
        self.assertDeclaresWhatItWrites(raw, FRAGMENT)


if __name__ == '__main__':
    unittest.main()
