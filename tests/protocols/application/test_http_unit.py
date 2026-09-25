from __future__ import annotations

import importlib.util
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__


def http2_header(length: int, type_: object, flags: int = 0, sid: int = 1) -> SimpleNamespace:
    return SimpleNamespace(
        length=length,
        type=type_,
        flags={f'bit_{bit}': (flags & (1 << bit)) >> bit for bit in range(8)},
        stream={'sid': sid},
    )


def http2_schema(**kwargs: object) -> SimpleNamespace:
    flags = kwargs.pop('__flags__', 0)
    schema = SimpleNamespace(**kwargs)
    setattr(schema, '__flags__', flags)
    return schema


def http2_frame_bytes(type_: int, flags: int, sid: int, payload: bytes) -> bytes:
    """Build the wire bytes of one HTTP/2 frame.

    The length field counts the *whole* frame, header included -- this
    library's convention rather than :rfc:`9113#section-4.1`'s, as the NOTE in
    :meth:`test_unregistered_frame_type_does_not_mutate_the_class_registry`
    spells out. ``make`` writes ``payload + 9`` and the readers recover the
    payload as ``length - 9``.

    """
    return (
        (len(payload) + 9).to_bytes(3, 'big')
        + bytes([type_, flags])
        + sid.to_bytes(4, 'big')
        + payload
    )


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_http_read_rejects_unknown_version_selector(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        http = object.__new__(HTTP)

        with self.assertRaises(ProtocolError):
            HTTP.read(http, length=0, version=3)

    def test_http_make_rejects_unknown_version_selector(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        http = object.__new__(HTTP)

        with self.assertRaises(ProtocolError):
            HTTP.make(http, version=3)

    def test_http_make_data_rejects_unknown_version_selector(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            HTTP._make_data({'version': 9})

    def test_http_base_id_and_cached_properties_are_stable(self) -> None:
        from pcapkit.protocols.application.http import HTTP

        http = object.__new__(HTTP)
        http._version = '1.1'
        http._length = 42

        self.assertEqual(HTTP.id(), ('HTTP', 'HTTPv1', 'HTTPv2'))
        self.assertEqual(http.name, 'Hypertext Transfer Protocol')
        self.assertEqual(http.alias, 'HTTP/1.1')
        self.assertEqual(http.version, '1.1')
        self.assertEqual(http.length, 42)

    def test_http_read_make_and_guess_version_delegation_paths(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        class FakeHTTPv1:
            version = '1.1'
            length = 11
            info = 'v1-info'

            def __init__(self, file, length, **kwargs):
                self.file = file
                self.init_length = length
                self.kwargs = kwargs

            @staticmethod
            def make(**kwargs):
                return ('v1-made', kwargs)

        class FakeHTTPv2:
            version = '2'
            length = 22
            info = 'v2-info'

            def __init__(self, file, length, **kwargs):
                self.file = file
                self.init_length = length
                self.kwargs = kwargs

            @staticmethod
            def make(**kwargs):
                return ('v2-made', kwargs)

        http = object.__new__(HTTP)
        http._data = b'GET / HTTP/1.1\r\n\r\n'
        http._file = object()
        http.__cached__ = {}

        with mock.patch('pcapkit.protocols.application.httpv1.HTTP', FakeHTTPv1):
            self.assertEqual(http.read(version=1, marker=True), 'v1-info')
        self.assertEqual(http.version, '1.1')
        self.assertEqual(http.length, 11)

        with mock.patch('pcapkit.protocols.application.httpv2.HTTP', FakeHTTPv2):
            self.assertEqual(http.read(length=9, version=2), 'v2-info')
        self.assertEqual(http.version, '2')
        self.assertEqual(http.length, 22)

        guessed = SimpleNamespace(version='1.1', length=11, info='v1-info')
        with mock.patch.object(HTTP, '_guess_version', return_value=guessed) as guess:
            self.assertEqual(http.read(), 'v1-info')
        guess.assert_called_once_with(len(http._data))

        with mock.patch('pcapkit.protocols.application.httpv1.HTTP', FakeHTTPv1):
            self.assertEqual(http.make(version=1, path='/'), ('v1-made', {'path': '/'}))
        with mock.patch('pcapkit.protocols.application.httpv2.HTTP', FakeHTTPv2):
            self.assertEqual(http.make(version=2, sid=1), ('v2-made', {'sid': 1}))

        with mock.patch('pcapkit.protocols.application.httpv1.HTTP',
                        mock.Mock(side_effect=ProtocolError('bad v1'))), \
                mock.patch('pcapkit.protocols.application.httpv2.HTTP', FakeHTTPv2):
            self.assertIsInstance(HTTP._guess_version(http, 9), FakeHTTPv2)
        with mock.patch('pcapkit.protocols.application.httpv1.HTTP', FakeHTTPv1):
            self.assertIsInstance(HTTP._guess_version(http, 9), FakeHTTPv1)
        with mock.patch('pcapkit.protocols.application.httpv1.HTTP',
                        mock.Mock(side_effect=ProtocolError('bad v1'))), \
                mock.patch('pcapkit.protocols.application.httpv2.HTTP',
                           mock.Mock(side_effect=ProtocolError('bad v2'))):
            with self.assertRaises(ProtocolError):
                HTTP._guess_version(http, 9)

    def test_http_make_dispatches_to_real_versioned_classes(self) -> None:
        """Regression test for GH-452.

        ``HTTP.make`` used to dispatch with ``protocol.make(**kwargs)``, where
        ``protocol`` is the imported *class* -- an unbound call, since neither
        ``HTTPv1.make`` nor ``HTTPv2.make`` is declared ``staticmethod`` or
        ``classmethod`` on the real class (both are plain ``def make(self,
        ...)``, matching the abstract ``ProtocolBase.make``). Every real call
        therefore raised ``TypeError: make() missing 1 required positional
        argument: 'self'``.

        This deliberately exercises the **real** ``HTTPv1``/``HTTPv2``
        classes rather than a fake with a ``staticmethod`` ``make`` --
        ``test_http_read_make_and_guess_version_delegation_paths`` above uses
        exactly such a fake, which is what let the original defect through:
        a ``staticmethod`` absorbs an unbound call the same as a bound one,
        so a fake-based assertion passes whether or not ``self`` is actually
        threaded through.
        """
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.schema.application.httpv1 import HTTP as Schema_HTTPv1
        from pcapkit.protocols.schema.application.httpv2 import HTTP as Schema_HTTPv2

        http = object.__new__(HTTP)

        schema_v1 = http.make(version=1, method='GET', uri='/index.html')
        self.assertIsInstance(schema_v1, Schema_HTTPv1)
        self.assertIn(b'GET /index.html HTTP/1.1\r\n', schema_v1.data)

        schema_v2 = http.make(version=2, sid=1, frame=b'payload')
        self.assertIsInstance(schema_v2, Schema_HTTPv2)
        self.assertEqual(schema_v2.stream['sid'], 1)
        self.assertEqual(schema_v2.frame, b'payload')

    def test_http_construction_reaches_the_versioned_make_callee(self) -> None:
        """Regression test for GH-452, using the corrected reproduction.

        The issue's original reproduction called ``HTTP.make(version=1,
        ...)`` directly on the class -- but the *outer* ``HTTP.make`` is
        itself an ordinary instance method, so that call fails at the outer
        method and never demonstrates anything about the inner
        ``protocol.make(**kwargs)`` dispatch this issue is actually about.

        The real, supported entry point is construction:
        :meth:`ProtocolBase.__init__` (``protocol.py:519``, the ``**kwargs``-
        only overload at ``:517``) calls ``self.pack(**kwargs)`` when built
        with no ``file``, and :meth:`ProtocolBase.pack` (``protocol.py:284``)
        is ``self.__header__ = self.make(**kwargs)`` -- a *bound* call on the
        outer ``HTTP`` instance, which is what actually reaches the inner,
        previously-unbound ``protocol.make(**kwargs)``. So the reachable
        reproduction is ``HTTP(version=1, ...)``, not ``HTTP.make(...)``:

        - on the unfixed code, this raises ``TypeError: HTTP.make() missing
          1 required positional argument: 'self'`` -- the *same* exception
          text as the wrong reproduction, but reached legitimately this time.
        - on the fixed code, the constructed packet is read back and rejected,
          as ``ProtocolError: HTTP: invalid format`` -- proving the callee was
          actually reached, which "no ``TypeError``" alone would not.

        The asserted message was ``'HTTP/1: invalid format'`` until #787.
        Nothing about *this* regression test changed: the exception type, and
        the fact that reaching it at all proves the versioned ``make`` ran, are
        as they were. What moved is which line raises. ``httpv1.HTTP`` now
        reports a malformed message as ``ProtocolError`` itself, so
        ``HTTP.read``'s ``except ProtocolError: raise`` re-raises it unchanged
        instead of ``except ValueError`` re-labelling it with the version it had
        dispatched on. The bare message is also what this path *already* gave
        whenever ``_read_http_header`` rejected a start line it could not
        recognise, so #787 makes one message of two rather than introducing a
        new one.

        Worth recording, since the docstring above used to claim otherwise: the
        rejection is not ``HTTPv1.make`` refusing these keywords. ``make``
        accepts them and builds ``b'GET / HTTP/1.1\\r\\n\\r\\n'``; it is the
        read-back of that packet which fails, because ``_read_http_header``
        requires a header field section and a field-less request has none. That
        a valid minimal HTTP/1 request cannot be re-read is a defect in its own
        right, and not one #787 set out to fix.
        """
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            HTTP(version=1, http_version='1.1', method='GET', uri='/')
        self.assertEqual(str(ctx.exception), 'HTTP: invalid format')

    def test_http_read_explicit_version_uses_same_buffer_as_guess(self) -> None:
        """Regression test for GH-447.

        The explicit ``version=`` path passed ``self._file`` -- already
        drained by the outer read -- instead of ``self._data``, so it built
        the sub-protocol from a short or empty buffer while
        ``_guess_version``, built from the same bytes, worked fine. This pins
        the fix by asserting *which* buffer object reaches the sub-protocol
        constructor, for both ``version=1`` and ``version=2``, rather than
        merely that a call succeeds.
        """
        from pcapkit.protocols.application.http import HTTP

        class RecordingHTTP:
            version = '1.1'
            length = 5
            info = 'recorded-info'

            def __init__(self, file: object, length: int, **kwargs: object) -> None:
                self.received = file

        http = object.__new__(HTTP)
        http._data = b'GET / HTTP/1.1\r\n\r\n'
        # Stands in for a stream already advanced by the outer read; passing
        # this instead of ``_data`` is exactly the GH-447 defect.
        http._file = object()
        http.__cached__ = {}

        with mock.patch('pcapkit.protocols.application.httpv1.HTTP', RecordingHTTP):
            http.read(version=1)
        self.assertIs(http._http.received, http._data)

        with mock.patch('pcapkit.protocols.application.httpv2.HTTP', RecordingHTTP):
            http.read(version=2)
        self.assertIs(http._http.received, http._data)

    def test_http_read_explicit_version_1_matches_guess_on_real_bytes(self) -> None:
        """The literal GH-447 reproduction: a real HTTP/1.1 request parses
        identically whether the version is guessed or given explicitly."""
        import io

        from pcapkit.protocols.application.http import HTTP

        raw = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'

        guessed = HTTP(io.BytesIO(raw), len(raw))
        explicit = HTTP(io.BytesIO(raw), len(raw), version=1)

        self.assertEqual(guessed.alias, 'HTTP/1.1')
        self.assertEqual(explicit.alias, 'HTTP/1.1')
        self.assertEqual(explicit.length, guessed.length)
        self.assertEqual(explicit.info, guessed.info)

    def test_http_read_explicit_version_wraps_malformed_payload(self) -> None:
        """The second half of GH-447: a payload that fails to parse on the
        explicit path must surface as a chained :class:`ProtocolError`, not a
        bare :class:`ValueError` a caller cannot catch as a protocol error."""
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        bad = b'not a valid http request at all'

        with self.assertRaises(ProtocolError) as ctx:
            HTTP(io.BytesIO(bad), len(bad), version=1)
        self.assertIsInstance(ctx.exception.__cause__, ValueError)

    def test_http_read_explicit_version_still_wraps_a_bare_value_error(self) -> None:
        """``HTTP.read``'s ``except ValueError`` net stays, and is pinned here.

        #787 stops ``httpv1.HTTP`` from raising a bare :class:`ValueError` at
        all, and that wrapper is what used to catch it -- so after the fix no
        real payload reaches it, and the test above that used to cover it
        (``..._wraps_malformed_payload``) now gets its chained ``__cause__`` from
        ``httpv1.HTTP`` instead. Left in place rather than deleted, because the
        guarantee is the explicit path's and not one delegate's: a
        :class:`ValueError` out of *either* versioned class, from any site #787
        did not touch, must still reach the caller as a
        :class:`~pcapkit.utilities.exceptions.ProtocolError`. Pinned with a
        stand-in that raises one, since nothing in the library does any more --
        an untested branch is how a net like this comes to look redundant and
        gets removed.

        """
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        http = object.__new__(HTTP)
        http._data = b'irrelevant'
        http.__cached__ = {}

        for version, module in ((1, 'httpv1'), (2, 'httpv2')):
            with self.subTest(version=version):
                with mock.patch(f'pcapkit.protocols.application.{module}.HTTP',
                                mock.Mock(side_effect=ValueError('boom'))):
                    with self.assertRaises(ProtocolError) as ctx:
                        http.read(version=version)

                self.assertEqual(str(ctx.exception), f'HTTP/{version}: invalid format')
                self.assertIsInstance(ctx.exception.__cause__, ValueError)

        # A ``ProtocolError`` from the delegate is re-raised as it is, not
        # re-labelled -- which is why #787's normalisation changes the message
        # the two tests named in its commit assert.
        with mock.patch('pcapkit.protocols.application.httpv1.HTTP',
                        mock.Mock(side_effect=ProtocolError('HTTP: invalid format'))):
            with self.assertRaises(ProtocolError) as ctx:
                http.read(version=1)
        self.assertEqual(str(ctx.exception), 'HTTP: invalid format')
        self.assertIsNone(ctx.exception.__cause__)

    def test_http_make_data_delegates_to_httpv1(self) -> None:
        from pcapkit.const.http.method import Method
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.http import HTTP

        data = DummyData(
            version=1,
            receipt=SimpleNamespace(version='1.1', method=Method.GET, uri='/index.html'),
            header=OrderedMultiDict([('Host', 'example.test')]),
            body=b'body',
        )

        values = HTTP._make_data(data)
        self.assertEqual(values['http_version'], '1.1')
        self.assertEqual(values['method'], Method.GET)
        self.assertEqual(values['uri'], '/index.html')
        self.assertEqual(values['headers']['Host'], 'example.test')
        self.assertEqual(values['body'], b'body')

    def test_http_make_data_delegates_to_httpv2(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.http import HTTP

        flags = SimpleNamespace(__value__=0x01)
        data = DummyData(
            version=2,
            length=13,
            type=Frame.DATA,
            flags=flags,
            sid=1,
            __next_type__=None,
        )

        values = HTTP._make_data(data)
        self.assertEqual(values['length'], 13)
        self.assertEqual(values['type'], Frame.DATA)
        self.assertEqual(values['flags'], 0x01)
        self.assertEqual(values['sid'], 1)
        self.assertIs(values['frame'], data)

    def test_http_guess_version_falls_through_to_the_http2_arm(self) -> None:
        """``_guess_version`` must reach its second arm, which it never did (#787).

        This test used to be ``..._propagates_malformed_payload_value_error``
        and asserted the opposite -- that these bytes raise :class:`ValueError`
        -- because that is what the unfixed code did: ``httpv1.HTTP`` failed
        with a bare :class:`ValueError`, which ``contextlib.suppress(
        ProtocolError)`` does not catch, so the exception left ``_guess_version``
        from the *first* arm and the HTTP/2 arm below it was dead code.

        The expectation is inverted rather than deleted because the old one
        pinned the defect as though it were the contract. Note the assertion
        would still have *passed* untouched --
        :class:`~pcapkit.utilities.exceptions.ProtocolError` is a
        :class:`ValueError` subclass, so ``assertRaises(ValueError)`` cannot tell
        a normalised protocol error from a stray stdlib one -- had these
        particular bytes still raised at all.

        What is asserted is that the second arm was *entered*, not the answer it
        gave -- and, as of #799, the answer for *these* bytes is itself
        ``ProtocolError`` rather than ``version='2'``. An earlier revision of
        this test pinned ``version == '2'`` here and #799's review caught that
        as exactly the trap this docstring already warned against: "not"'s
        three octets read as a 24-bit declared length of 7,237,492, wildly past
        the fifteen actually available, and #799 now requires the declared
        length to be consistent with the buffer -- so arm 2 is entered
        (dead-code-ness stays fixed) but correctly declines this payload too,
        and both arms failing is what drives ``_guess_version`` to its own
        ``ProtocolError``. Real HTTP/2 wire bytes -- self-consistently declared
        -- are pinned to ``version == '2'`` by
        ``test_guess_version_reaches_http2_on_the_connection_preface``, which is
        where that assertion belongs.

        """
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        http = object.__new__(HTTP)
        http._data = b'not http at all'

        entered = []  # type: list[str]
        real_v1 = importlib.import_module('pcapkit.protocols.application.httpv1').HTTP
        real_v2 = importlib.import_module('pcapkit.protocols.application.httpv2').HTTP

        def record(name: str, real: object) -> object:
            def spy(*args: object, **kwargs: object) -> object:
                entered.append(name)
                return real(*args, **kwargs)  # type: ignore[operator]
            return spy

        with mock.patch('pcapkit.protocols.application.httpv1.HTTP',
                        record('httpv1', real_v1)), \
             mock.patch('pcapkit.protocols.application.httpv2.HTTP',
                        record('httpv2', real_v2)):
            with self.assertRaises(ProtocolError):
                HTTP._guess_version(http, len(http._data))

        # Both arms ran, in order: the first was tried and failed, and the
        # second was reached -- which is exactly what it never used to be --
        # even though it goes on to decline these particular bytes too.
        self.assertEqual(entered, ['httpv1', 'httpv2'])

    def test_guess_version_reaches_http2_on_the_connection_preface(self) -> None:
        """The literal #787 reproduction: the HTTP/2 connection preface.

        ``b'PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n'`` plus a SETTINGS frame is
        what an HTTP/2 connection opens with, and ``httpv2.HTTP`` parses the
        *frame* (on its own) and reports ``version='2'``. Through the proxy it
        raised ``ValueError: not enough values to unpack (expected 2, got 1)``
        instead, from ``httpv1.HTTP`` -- so the guess could not reach the answer
        its own second arm already had.

        Asserted against the explicit ``version=2`` path rather than on its own,
        because "``read()`` and ``read(version=2)`` agree" is the property #787
        is about: the explicit path worked throughout, and only the guess did
        not.

        The preface itself is asserted separately, and *not* prepended to the
        frame in one buffer as the original #787 reproduction did. That
        construction only ever "worked" by exploiting the exact defect #799
        fixes: ``httpv2.HTTP`` has no notion of the preface at all, so it read
        the preface's own ASCII octets as a frame header -- ``b'PRI'`` as a
        23-bit-plus declared length of 5,265,993 -- and pre-#799 the guard
        never checked that against the real buffer, so it "succeeded" reporting
        a length backed by nothing. #799's ``schema.length > length`` check
        rejects that inconsistency on both the guess and the explicit path
        alike, which is correct: recognising the preface and skipping past it
        is a real gap (tracked as #800), but reading it as if it were binary
        framing was never a fix for that gap, only an accident #799 closes.

        #800 has since closed that gap, so the one-buffer construction is
        asserted here on the *explicit* path only: ``read(version=2)`` still has
        no notion of the preface and must still refuse to read it as framing,
        while the guess path now identifies the preface by prefix compare and
        parses the frame after it. That half moved to
        ``test_guess_version_identifies_the_http2_connection_preface`` below.

        """
        import io
        import warnings

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.warnings import ProtocolWarning

        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        settings = http2_frame_bytes(0x04, 0x00, 0, b'')

        guessed = HTTP(io.BytesIO(settings), len(settings))
        explicit = HTTP(io.BytesIO(settings), len(settings), version=2)

        self.assertEqual(guessed.version, '2')
        self.assertEqual(guessed.alias, 'HTTP/2')
        self.assertEqual(guessed.length, explicit.length)
        self.assertEqual(guessed.info, explicit.info)

        # The frame alone, with no unassigned frame type in it, parses clean.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            clean = HTTP(io.BytesIO(settings), len(settings))
        self.assertEqual(clean.version, '2')
        self.assertEqual([w for w in caught if issubclass(w.category, ProtocolWarning)], [])

        # The preface prepended to the frame, read as one buffer, is still
        # refused on the *explicit* path: ``read(version=2)`` hands the whole
        # buffer to ``httpv2.HTTP``, which has no notion of the preface and must
        # not read its ASCII as framing. The guess path identifies it instead --
        # see ``test_guess_version_identifies_the_http2_connection_preface``.
        raw = preface + settings
        with self.assertRaises(ProtocolError):
            HTTP(io.BytesIO(raw), len(raw), version=2)

    def test_guess_version_identifies_the_http2_connection_preface(self) -> None:
        """The preface is identified by prefix compare, not by a parse (#800).

        ``b'PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n'`` followed by a SETTINGS
        frame is what every HTTP/2 connection opens with
        (:rfc:`9113#section-3.4`), and before this change the dispatcher had no
        notion of it: the HTTP/1 arm declined it and the HTTP/2 arm read the
        preface's own ASCII as a frame header, ``b'PRI'`` becoming a declared
        length of 5,265,993. #799/#802 then made that inconsistency a refusal,
        which was right in itself but left a real HTTP/2 connection opening
        reported as not-HTTP at all -- measured on ``f046b38f8``/``4530424df``,
        both the bare preface and preface-plus-SETTINGS raised ``unknown HTTP
        version``.

        Three things are asserted, because "it answers 2" alone would also be
        true of the accident this replaces:

        * the answer is ``version='2'``;
        * the parsed frame is *the SETTINGS frame*, byte-identical to reading
          that frame on its own -- which is what proves the preface was skipped
          rather than consumed as framing;
        * the reported declared length is the frame's real 9, not a number the
          preface's ASCII happens to spell.

        """
        import io
        import warnings

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.warnings import ProtocolWarning

        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        settings = http2_frame_bytes(0x04, 0x00, 0, b'')
        raw = preface + settings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            guessed = HTTP(io.BytesIO(raw), len(raw))
        frame_only = HTTP(io.BytesIO(settings), len(settings), version=2)

        self.assertEqual(guessed.version, '2')
        self.assertEqual(guessed.alias, 'HTTP/2')
        # The preface is header rather than payload, so it counts towards
        # ``length`` -- without that, ``__init__``'s ``packet=self.packet.payload``
        # injection slices from octet 9 of a buffer whose frame starts at 24 and
        # reports the tail of the preface as this packet's payload, which is what
        # ``info`` equality below would otherwise catch.
        self.assertEqual(guessed.length, len(preface) + frame_only.length)
        self.assertEqual(guessed.info, frame_only.info)
        self.assertEqual(guessed.info.packet, b'')
        self.assertEqual(guessed.info.length, 9)
        self.assertNotEqual(guessed.info.length, 5265993)
        self.assertEqual([w for w in caught if issubclass(w.category, ProtocolWarning)], [])

        # The frame after the preface is parsed for real, not assumed: a padded
        # SETTINGS payload comes back as its own settings, and a frame the
        # parser refuses is refused rather than answered by the identification.
        settings_2 = http2_frame_bytes(0x04, 0x00, 0, b'\x00\x03\x00\x00\x00d')
        guessed_2 = HTTP(io.BytesIO(preface + settings_2), len(preface) + len(settings_2))
        self.assertEqual(guessed_2.version, '2')
        self.assertEqual(guessed_2.info, HTTP(io.BytesIO(settings_2), len(settings_2),
                                              version=2).info)

    def test_guess_version_reports_a_preface_with_no_frame_as_such(self) -> None:
        """A preface with nothing after it is HTTP/2, but carries no frame.

        :rfc:`9113#section-3.4` requires the preface to be followed immediately
        by a SETTINGS frame, so a payload that is *exactly* the 24 preface octets
        is either truncated or cut at a segment boundary. It is still positively
        identified as HTTP/2 -- but this library's HTTP/2 data model is one frame
        per packet and has no representation for a frameless segment, so there is
        nothing to return and the payload is refused.

        What the fix buys here is the *diagnosis*, which is why the message is
        asserted rather than merely the exception type: on ``4530424df`` this
        answered ``unknown HTTP version``, indistinguishable from genuine
        garbage, and it now says which of the two it was. Reporting a version
        with no data would be the dishonest alternative.

        """
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        self.assertEqual(len(preface), 24)

        with self.assertRaises(ProtocolError) as ctx:
            HTTP(io.BytesIO(preface), len(preface))
        self.assertEqual(str(ctx.exception), 'HTTP/2: connection preface with no frame')

        # A preface followed by something too short to be a frame is refused by
        # the HTTP/2 parser itself -- identification commits to the version, it
        # does not excuse the frame.
        raw = preface + b'\x00\x00\x09\x04'
        with self.assertRaises(ProtocolError) as ctx:
            HTTP(io.BytesIO(raw), len(raw))
        self.assertIn('9-octet frame header', str(ctx.exception))

        # And a preface followed by a frame that trips the #805 residual -- a
        # sixteen-octet GOAWAY, whose fixed ``stream`` and ``error`` fields alone
        # want eight octets after the header -- must come back catchable. The
        # identified HTTP/2 route normalises that, because the trial-parse arm it
        # replaces for this input used to suppress :exc:`struct.error` and answer
        # ``unknown HTTP version``; without the conversion the bare stdlib error
        # would now escape a dispatcher documented to raise ``ProtocolError``.
        import struct

        from pcapkit.utilities.exceptions import BaseError

        goaway = b'\x00\x00\x15\x07\x00\x00\x00\x00\x00' + b'\xff' * 7
        self.assertEqual(len(goaway), 16)
        raw = preface + goaway
        with self.assertRaises(ProtocolError) as ctx:
            HTTP(io.BytesIO(raw), len(raw))
        self.assertEqual(str(ctx.exception), 'HTTP/2: invalid format')
        self.assertIsInstance(ctx.exception, BaseError)
        self.assertNotIsInstance(ctx.exception, struct.error)
        self.assertIsInstance(ctx.exception.__cause__, struct.error)

    def test_guess_version_does_not_classify_text_as_http2(self) -> None:
        """Garbage text must never come back HTTP/2.

        ``b'foo bar baz\\r\\nX: y\\r\\n\\r\\n'`` answered ``version='2'`` on
        ``main`` before #802 -- the headline wrong answer of #800 -- because the
        HTTP/2 arm accepted any buffer of nine octets or more and ``b'foo'`` read
        as a declared length of 6,712,175 that nothing checked.

        Honest about what closed it: #802's ``schema.length > length`` check
        already refuses this, so this case passes on ``4530424df`` too and is a
        *regression guard* rather than a fix demonstration. It is worth pinning
        here all the same, because after #800 the answer no longer depends on
        that guard at all: text does not match the preface and does not match an
        HTTP/1 start line, so it is never positively identified as anything, and
        the fall-through is the only route left to it. Both defences are asserted
        so that loosening either one is noticed.

        """
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv1 import _test_start_line
        from pcapkit.utilities.exceptions import ProtocolError

        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        cases = (
            ('lowercase start line', b'foo bar baz\r\nX: y\r\n\r\n'),
            ('no start line at all', b'not http at all'),
            ('prose', b'the quick brown fox jumps over the lazy dog\r\n\r\n'),
            ('almost a method', b'Get /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'),
        )

        for label, raw in cases:
            with self.subTest(case=label):
                # Neither identification claims it ...
                self.assertFalse(raw.startswith(preface))
                self.assertFalse(_test_start_line(raw))
                # ... and the fall-through refuses it rather than guessing.
                with self.assertRaises(ProtocolError):
                    HTTP(io.BytesIO(raw), len(raw))

    def test_guess_version_commits_to_http1_once_the_start_line_says_so(self) -> None:
        """An identified HTTP/1 message is not re-tried as HTTP/2 (#800).

        This is the direction that matters for #682, which is about to route 231
        real HTTP/1 frames through this dispatcher. Before the fix, an HTTP/1
        message the HTTP/1 parser refused was handed to the HTTP/2 arm, which
        accepts any self-consistent buffer of nine octets or more -- so the
        answer for a malformed HTTP/1 message depended on what its first three
        ASCII octets happened to spell as a 24-bit length. Now the start line
        decides the version and the HTTP/1 parser's own verdict is the answer.

        Asserted on the message, because the exception *type* is
        ``ProtocolError`` either way: on ``4530424df`` these payloads came back
        ``unknown HTTP version`` (both arms having declined), and they now come
        back ``HTTP: invalid format`` from the version that was actually
        identified.

        """
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv1 import _test_start_line
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            ('field line with no colon', b'GET / HTTP/1.1\r\nbadfield\r\n\r\n'),
            ('first field line folded', b'GET / HTTP/1.1\r\n Host: example.com\r\n\r\n'),
            ('status line, no colon', b'HTTP/1.1 200 OK\r\nbadfield\r\n\r\n'),
        )

        for label, raw in cases:
            with self.subTest(case=label):
                self.assertTrue(_test_start_line(raw))
                with self.assertRaises(ProtocolError) as ctx:
                    HTTP(io.BytesIO(raw), len(raw))
                self.assertEqual(str(ctx.exception), 'HTTP: invalid format')

    def test_start_line_predicate_agrees_with_the_httpv1_parser(self) -> None:
        """``_test_start_line`` must accept exactly what ``httpv1.HTTP`` accepts.

        The predicate classifies and the parser parses, and they are two
        statements of the same rule -- which is why the predicate lives beside
        ``_RE_METHOD``/``_RE_VERSION``/``_RE_STATUS`` in ``httpv1.py`` rather
        than in the dispatcher. Drift either way is a defect: a predicate looser
        than the parser classifies payloads the parser then refuses, and a
        tighter one hands real HTTP/1 to a later arm, which is the mislabel #787
        and #800 are both about.

        Pinned by construction rather than by inspection -- each payload is run
        through ``httpv1.HTTP`` as well as through the predicate, so the two
        cannot be edited apart without this failing.

        """
        import io

        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.protocols.application.httpv1 import _test_start_line
        from pcapkit.utilities.exceptions import ProtocolError

        accepted = (
            ('request', b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'),
            ('request, extra spaces', b'GET  /  HTTP/1.0\r\nHost: example.com\r\n\r\n'),
            ('response', b'HTTP/1.1 200 OK\r\nServer: example\r\n\r\nbody'),
            ('response, no message', b'HTTP/1.0 404 -\r\nServer: example\r\n\r\n'),
            ('hyphenated method', b'M-SEARCH * HTTP/1.1\r\nHost: example.com\r\n\r\n'),
        )
        refused = (
            # Rejected by the anchored patterns themselves.
            ('lowercase method', b'Get / HTTP/1.1\r\nHost: example.com\r\n\r\n'),
            ('four-digit status', b'HTTP/1.1 2000 OK\r\nServer: example\r\n\r\n'),
            ('no version token', b'GET / FTP/1.1\r\nHost: example.com\r\n\r\n'),
            # Rejected by the unpackings ``_read_http_header`` performs first.
            ('two-token start line', b'GET /\r\nHost: example.com\r\n\r\n'),
            ('no CRLF at all', b'GET / HTTP/1.1'),
            ('the HTTP/2 preface', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),
            ('not http at all', b'not http at all'),
        )

        for label, raw in accepted:
            with self.subTest(accepted=label):
                self.assertTrue(_test_start_line(raw))
                # The parser agrees: it reads this without raising.
                self.assertIn(HTTPv1(io.BytesIO(raw), len(raw)).version, ('1.0', '1.1'))

        for label, raw in refused:
            with self.subTest(refused=label):
                self.assertFalse(_test_start_line(raw))
                # The parser agrees: it refuses this at the start line.
                with self.assertRaises(ProtocolError):
                    HTTPv1(io.BytesIO(raw), len(raw))

    def test_guess_version_leaves_a_mid_stream_frame_to_the_fall_through(self) -> None:
        """A bare frame carries no preface and no start line, and is undecidable.

        Identification cannot answer for a mid-stream segment, and #800
        deliberately adds no heuristic for one -- no "frame type at most 9,
        reserved bit clear" test, because that is what misfires on binary HTTP/1
        bodies. So a bare frame falls through to the trial parse, where the
        HTTP/2 parser's own length and type consistency rules decide: a
        self-consistent frame is read as HTTP/2 (unchanged behaviour, pinned so
        the new identification step is not mistaken for a replacement of the
        fall-through), and one whose declared length its buffer does not back is
        refused rather than answered.

        """
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv1 import _test_start_line
        from pcapkit.utilities.exceptions import ProtocolError

        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        settings = http2_frame_bytes(0x04, 0x00, 0, b'')

        # Neither identification fires, so this reaches the fall-through.
        self.assertFalse(settings.startswith(preface))
        self.assertFalse(_test_start_line(settings))

        guessed = HTTP(io.BytesIO(settings), len(settings))
        self.assertEqual(guessed.version, '2')
        self.assertEqual(guessed.info,
                         HTTP(io.BytesIO(settings), len(settings), version=2).info)

        # A nine-octet header declaring 16777215 is not backed by its buffer.
        inconsistent = b'\xff\xff\xff\x04\x00\x00\x00\x00\x00'
        with self.assertRaises(ProtocolError):
            HTTP(io.BytesIO(inconsistent), len(inconsistent))

    def test_guess_version_keeps_an_upgrade_h2c_exchange_on_http1(self) -> None:
        """An ``Upgrade: h2c`` exchange stays HTTP/1.1, and that is correct.

        :rfc:`7540#section-3.2`'s upgrade -- deprecated by
        :rfc:`9113#section-3.1` but not removed -- is explicitly out of #800's
        scope, and not because it was awkward: on the wire the upgrade request
        and its ``101 Switching Protocols`` response *are* HTTP/1.1 messages, and
        HTTP/1.1 is the right answer for both. The switch takes effect only after
        the ``101``, so classifying later segments of the same connection as
        HTTP/2 needs per-connection state keyed on the 4-tuple, and
        ``_guess_version`` is handed one payload with no flow context.
        Recognising the field is possible; acting on it is not, so it is left
        alone rather than half-implemented.

        Pinned so that a later attempt to "support h2c" by sniffing the header
        has to change a test that says why it must not.

        """
        import io

        from pcapkit.protocols.application.http import HTTP

        request = (b'GET / HTTP/1.1\r\n'
                   b'Host: example.com\r\n'
                   b'Connection: Upgrade, HTTP2-Settings\r\n'
                   b'Upgrade: h2c\r\n'
                   b'HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n')
        response = (b'HTTP/1.1 101 Switching Protocols\r\n'
                    b'Connection: Upgrade\r\n'
                    b'Upgrade: h2c\r\n\r\n')

        for label, raw in (('upgrade request', request), ('101 response', response)):
            with self.subTest(case=label):
                guessed = HTTP(io.BytesIO(raw), len(raw))
                explicit = HTTP(io.BytesIO(raw), len(raw), version=1)

                self.assertEqual(guessed.version, '1.1')
                self.assertEqual(guessed.alias, 'HTTP/1.1')
                self.assertEqual(guessed.info, explicit.info)

        # The field is visible in the parsed message -- it is simply not acted
        # on, which is the distinction this test exists to record.
        upgraded = HTTP(io.BytesIO(request), len(request))
        self.assertEqual(upgraded.info.header['Upgrade'], 'h2c')

    def test_guess_version_still_prefers_http1_for_http1_bytes(self) -> None:
        """HTTP/1 is tried first and must still win, request and response alike.

        The arms are ordered, so making the second reachable is only safe if the
        first still claims everything it used to -- which is what stops #787's
        fix from relabelling ordinary HTTP/1 traffic as HTTP/2.

        """
        import io

        from pcapkit.protocols.application.http import HTTP

        cases = (
            ('request', b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n', '1.1'),
            ('response', b'HTTP/1.1 200 OK\r\nServer: example\r\n\r\nbody', '1.1'),
            ('response 1.0', b'HTTP/1.0 404 Not Found\r\nServer: example\r\n\r\n', '1.0'),
        )

        for label, raw, version in cases:
            with self.subTest(case=label):
                guessed = HTTP(io.BytesIO(raw), len(raw))
                explicit = HTTP(io.BytesIO(raw), len(raw), version=1)

                self.assertEqual(guessed.version, version)
                self.assertEqual(guessed.alias, f'HTTP/{version}')
                self.assertEqual(guessed.info, explicit.info)

    def test_guess_version_still_reports_an_unknown_http_version(self) -> None:
        """Bytes neither arm accepts must still raise ``unknown HTTP version``.

        ``_guess_version``'s closing ``raise`` is only reachable when *both*
        arms fail with :class:`~pcapkit.utilities.exceptions.ProtocolError`, so
        it needs a payload that ``httpv2.HTTP`` rejects too -- a frame whose
        declared length contradicts its type. A PING frame carries eight octets
        of opaque data and so must declare 17 by this library's whole-frame
        convention; 9 is refused by ``_read_http_ping``.

        A frame is used as the probe rather than short garbage because it
        exercises the intended route: both arms declining with
        ``ProtocolError``. Short garbage now arrives here too, by way of the
        :exc:`struct.error` that ``_guess_version`` suppresses alongside
        ``ProtocolError``, and
        ``test_guess_version_reports_unknown_version_for_a_short_payload``
        covers that separately -- it used to escape uncaught, which is the second
        leak of #787's shape.

        """
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        raw = http2_frame_bytes(0x06, 0x00, 0, b'')  # PING, declared length 9

        with self.assertRaises(ProtocolError) as ctx:
            HTTP(io.BytesIO(raw), len(raw))
        self.assertEqual(str(ctx.exception), 'unknown HTTP version')

    def test_guess_version_reports_unknown_version_for_a_short_payload(self) -> None:
        """A payload too short for an HTTP/2 frame header must not leak :exc:`struct.error`.

        Making the HTTP/2 arm reachable routed a class of payload that used to
        stop at the HTTP/1 arm into ``httpv2.HTTP`` for the first time, and under
        nine octets that class fails *inside* the schema machinery rather than in
        ``read``: ``FieldBase.length`` hands :func:`struct.calcsize` a template
        built from a negative length, and the resulting :exc:`struct.error`
        derives straight from :exc:`Exception`. It is therefore not a
        ``ProtocolError``, not a :exc:`ValueError`, and not
        :exc:`~pcapkit.utilities.exceptions.StructError`, so none of
        ``_guess_version``'s suppression, ``read``'s ``except ValueError`` net,
        nor a caller's ``except BaseError`` saw it -- it left the proxy bare.

        Asserted on all three of those nets, because "it raises something" is not
        the property that was missing; "a caller who catches protocol errors
        catches this" is.

        The underlying defect is ``httpv2.HTTP``'s, and predates #787: the same
        :exc:`struct.error` comes out of ``HTTPv2`` constructed directly and out
        of ``HTTP(..., version=2)``, on the base revision as much as on this one.
        What #787 changed is that the *guess* path reaches it, so the fix belongs
        at this dispatcher's boundary, where both routes into a versioned parser
        already normalise their failures. Both routes are pinned here for that
        reason.

        """
        import io
        import struct

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import BaseError, ProtocolError

        # Eight octets: one short of the nine an HTTP/2 frame header needs, and
        # with no CRLF pair, so the HTTP/1 arm declines it as well.
        raw = b'\x00' * 8

        for label, kwargs in (('guessed', {}), ('explicit version=2', {'version': 2})):
            with self.subTest(path=label):
                with self.assertRaises(ProtocolError) as ctx:
                    HTTP(io.BytesIO(raw), len(raw), **kwargs)

                # The nets that used to miss it.
                self.assertIsInstance(ctx.exception, ValueError)
                self.assertIsInstance(ctx.exception, BaseError)
                self.assertNotIsInstance(ctx.exception, struct.error)

        # Every length below the frame header size behaves the same way, so the
        # fix is not pinned to one convenient payload.
        for size in range(0, 9):
            with self.subTest(size=size):
                short = b'\x00' * size
                with self.assertRaises(ProtocolError):
                    HTTP(io.BytesIO(short), len(short))

    def test_httpv1_read_raises_protocol_error_for_a_malformed_message(self) -> None:
        """The chosen #787 fix, at its source: ``httpv1.HTTP`` raises ``ProtocolError``.

        Both of the unpackings that a non-HTTP/1 payload lands short on are
        covered -- the header/body separator in ``read``, and the start line in
        ``_read_http_header`` -- since either alone leaves the other leaking a
        bare :class:`ValueError`, and the reproduction only reaches the second.

        Asserted on ``httpv1.HTTP`` directly rather than through the proxy
        because that is the difference between the two candidate fixes: the
        contract now holds for every caller, including
        ``Transport._decode_next_layer``, which dispatches TCP ports 80 and 8080
        straight to this class and never passes through ``_guess_version`` at
        all.

        ``__cause__`` is asserted because the chain is what keeps the underlying
        unpacking error reportable, and what keeps
        ``test_http_read_explicit_version_wraps_malformed_payload`` true of the
        explicit path.

        """
        import io

        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            # No header/body separator at all -- ``read``'s own unpacking.
            ('no separator', b'not http at all'),
            # A header with no CRLF in it -- the HTTP/2 preface is exactly this
            # once the separator has been split off.
            ('preface start line', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),
            # A start line of fewer than three whitespace-separated tokens.
            ('two-token start line', b'GET /\r\nHost: example.com\r\n\r\n'),
            ('one-token start line', b'PRI\r\nHost: example.com\r\n\r\n'),
        )

        for label, raw in cases:
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError) as ctx:
                    HTTPv1(io.BytesIO(raw), len(raw))
                self.assertEqual(str(ctx.exception), 'HTTP: invalid format')
                self.assertIsInstance(ctx.exception.__cause__, ValueError)
                self.assertNotIsInstance(ctx.exception.__cause__, ProtocolError)

    def test_httpv1_refuses_a_field_line_with_no_colon(self) -> None:
        """A colon-less field line must raise ``ProtocolError``, not :exc:`IndexError`.

        ``re.split(rb'\\s*:\\s*', field, maxsplit=1)`` returns a *one*-element
        list for a field line with no colon in it, so ``item[1]`` raised
        :exc:`IndexError`. That is the same defect #787 is about, one loop
        further on and wearing a different exception type: an :exc:`IndexError`
        is neither a :exc:`ValueError` nor a ``ProtocolError``, so it escaped
        ``HTTP._guess_version``'s suppression exactly as the bare
        :exc:`ValueError` did and left the HTTP/2 arm dead for this whole class
        of input as well.

        Refused rather than skipped: dropping the line would hand back a message
        whose header fields are quietly not the ones on the wire, which is worse
        than declining to parse it.

        """
        import io

        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            ('no colon at all', b'GET / HTTP/1.1\r\nNoColonHere\r\nHost: e\r\n\r\n'),
            ('no colon, last field', b'GET / HTTP/1.1\r\nHost: e\r\nNoColonHere\r\n\r\n'),
            # A continuation line with nothing before it to continue: an
            # ``obs-fold`` is only meaningful after a field line.
            ('orphan continuation', b'GET / HTTP/1.1\r\n   orphan\r\nHost: e\r\n\r\n'),
        )

        for label, raw in cases:
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError) as ctx:
                    HTTPv1(io.BytesIO(raw), len(raw))
                self.assertEqual(str(ctx.exception), 'HTTP: invalid format')

    def test_httpv1_unfolds_an_obs_fold_continuation_line(self) -> None:
        """A folded field line is legal HTTP/1 and must parse to the field it carries.

        :rfc:`9112#section-5.2` allows a field value to continue on the next line
        when that line begins with SP or HTAB, and prescribes replacing each such
        ``obs-fold`` with a space before interpreting the value. Deprecated, but
        present in real captures, and both of the ways it used to come out were
        wrong:

        * a continuation carrying no colon reached ``item[1]`` and raised
          :exc:`IndexError` -- so an ordinary, legal HTTP/1.1 request aborted the
          guess and, once refused, would have been relabelled HTTP/2;
        * a continuation that happened to contain a colon was *worse*: it parsed
          silently into a spurious extra field, so ``X-Long: a`` folded over
          ``b: c`` yielded two fields rather than one value of ``a b: c``, with
          nothing raised to say so.

        The second is the reason this is unfolded rather than merely refused.
        Detecting the continuation is what both answers need, and having detected
        it, parsing the message correctly costs one line more than declining it
        -- while declining it would leave a legal request falling through to the
        HTTP/2 arm, which is the mislabelling #787 exists to stop.

        """
        import io

        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1

        cases = (
            ('space continuation', b'GET / HTTP/1.1\r\nX-Long: a\r\n   b\r\nHost: e\r\n\r\n'),
            ('tab continuation', b'GET / HTTP/1.1\r\nX-Long: a\r\n\tb\r\nHost: e\r\n\r\n'),
            ('two continuations', b'GET / HTTP/1.1\r\nX-Long: a\r\n b\r\n\tc\r\nHost: e\r\n\r\n'),
        )
        expected = (
            ('space continuation', [('X-Long', 'a b'), ('Host', 'e')]),
            ('tab continuation', [('X-Long', 'a b'), ('Host', 'e')]),
            ('two continuations', [('X-Long', 'a b c'), ('Host', 'e')]),
        )

        for (label, raw), (_, fields) in zip(cases, expected):
            with self.subTest(case=label):
                proto = HTTPv1(io.BytesIO(raw), len(raw))
                self.assertEqual(list(proto.info.header.items()), fields)

        # The colon-bearing continuation, which used to mis-parse in silence.
        raw = b'GET / HTTP/1.1\r\nX-Long: a\r\n   b: c\r\nHost: e\r\n\r\n'
        proto = HTTPv1(io.BytesIO(raw), len(raw))
        self.assertEqual(list(proto.info.header.items()),
                         [('X-Long', 'a b: c'), ('Host', 'e')])

    def test_httpv1_unfold_replaces_the_whole_obs_fold_including_the_ows(self) -> None:
        """A folded message must agree with its literal equivalent, OWS and all.

        The production is ``obs-fold = OWS CRLF RWS`` (:rfc:`9112#section-5.2`)
        and a recipient replaces *the whole* obs-fold with one or more SP -- so
        the optional whitespace before the CRLF belongs to the fold, not to the
        field value. Right-stripping only the continuation left that OWS behind:
        ``X: a \\t`` folded over ``\\tb`` unfolded to ``'a \\t  b'`` where the
        literal ``X: a b`` gives ``'a b'``, four of the five pairs below
        disagreed, and a HTAB survived inside the value where the RFC prescribes
        SP.

        Asserted as agreement between each folded message and the literal message
        it is *defined to mean*, rather than against a hand-written expected
        value, because that equivalence is the whole content of the RFC's remedy
        -- and pinning it on one input, as this test first did, is what let the
        trailing-OWS forms through.

        """
        import io

        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1

        def fields(raw: bytes) -> object:
            return list(HTTPv1(io.BytesIO(raw), len(raw)).info.header.items())

        pairs = (
            ('no trailing OWS',
             b'GET / HTTP/1.1\r\nX: a\r\n b\r\nHost: e\r\n\r\n',
             b'GET / HTTP/1.1\r\nX: a b\r\nHost: e\r\n\r\n'),
            ('trailing SP',
             b'GET / HTTP/1.1\r\nX: a   \r\n b\r\nHost: e\r\n\r\n',
             b'GET / HTTP/1.1\r\nX: a b\r\nHost: e\r\n\r\n'),
            ('trailing HTAB',
             b'GET / HTTP/1.1\r\nX: a\t\r\n b\r\nHost: e\r\n\r\n',
             b'GET / HTTP/1.1\r\nX: a b\r\nHost: e\r\n\r\n'),
            ('mixed trailing OWS',
             b'GET / HTTP/1.1\r\nX: a \t \r\n\tb\r\nHost: e\r\n\r\n',
             b'GET / HTTP/1.1\r\nX: a b\r\nHost: e\r\n\r\n'),
            ('two folds, both with trailing OWS',
             b'GET / HTTP/1.1\r\nX: a \r\n b \r\n c\r\nHost: e\r\n\r\n',
             b'GET / HTTP/1.1\r\nX: a b c\r\nHost: e\r\n\r\n'),
            # A continuation that is *only* whitespace: ``line.strip()`` is empty,
            # so the branch appends a bare separator and must still land on the
            # same value as the literal form.
            ('OWS-only continuation',
             b'GET / HTTP/1.1\r\nX: a\r\n \t \r\nHost: e\r\n\r\n',
             b'GET / HTTP/1.1\r\nX: a\r\nHost: e\r\n\r\n'),
            # A *response* start line takes the other classification branch, so
            # the unfold is exercised independently of request parsing.
            ('response fold',
             b'HTTP/1.1 200 OK\r\nX: a \r\n b\r\nServer: s\r\n\r\n',
             b'HTTP/1.1 200 OK\r\nX: a b\r\nServer: s\r\n\r\n'),
        )

        for label, folded, literal in pairs:
            with self.subTest(case=label):
                self.assertEqual(fields(folded), fields(literal))

        # No unfolded value may carry a HTAB: the fold is replaced by SP, and a
        # surviving HTAB is the signature of the OWS that was not stripped.
        for label, folded, _ in pairs:
            with self.subTest(case=label, check='no HTAB survives'):
                values = [value for _, value in fields(folded)]  # type: ignore[misc]
                self.assertEqual([v for v in values if '\t' in v], [])

    def test_httpv1_never_lets_a_bare_exception_escape(self) -> None:
        """The invariant behind #787: ``httpv1.HTTP`` fails only as ``ProtocolError``.

        This is what makes the set of payloads whose proxy answer changed
        *derivable* rather than something to enumerate by example. That set is
        exactly

            {payloads ``httpv1`` refused with a bare exception on base}
            INTERSECT {payloads ``httpv2`` accepts}
            INTERSECT {payloads ``httpv1`` still refuses}

        and the bare-exception sites were precisely four: the missing
        ``\\r\\n\\r\\n`` in ``read``, a header with no CRLF, a start line of fewer
        than three whitespace-separated tokens, and ``item[1]`` on a colon-less
        field line. A fifth such site would add a fifth class nobody predicted,
        which is how that count grew by one on each review round while it was
        being found by search.

        So rather than pin the classes, this pins the property that bounds them:
        over a battery spanning every branch of ``read`` and
        ``_read_http_header`` -- including the four converted sites and the four
        classes that already raised ``ProtocolError`` before the fix -- nothing
        escapes that is not a ``ProtocolError``. A new bare-raising site fails
        here, and no consequence table has to be re-derived by hand.

        """
        import io

        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        payloads = (
            # The four converted sites.
            ('read: no CRLFCRLF', b'not http at all'),
            ('read: no CRLFCRLF, long', b'abcdefghijklmnopqrstuvwxyz0123456789'),
            ('header: no CRLF (preface)', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),
            ('header: no CRLF (field-less request)', b'GET / HTTP/1.0\r\n\r\n'),
            ('header: no CRLF (field-less response)', b'HTTP/1.1 200 OK\r\n\r\n'),
            ('start line: two tokens', b'GET /\r\nHost: e\r\n\r\n'),
            ('start line: one token', b'PRI\r\nHost: e\r\n\r\n'),
            ('field line: no colon', b'GET / HTTP/1.1\r\nNoColonHere\r\n\r\n'),
            ('field line: orphan continuation', b'GET / HTTP/1.1\r\n orphan\r\n\r\n'),
            # Already ``ProtocolError`` before the fix -- these must stay so.
            ('start line: unrecognised 3 tokens', b'FOO BAR BAZ\r\nHost: e\r\n\r\n'),
            ('start line: non-numeric status', b'HTTP/1.1 XXX OK\r\nHost: e\r\n\r\n'),
            ('start line: four-digit status', b'HTTP/1.1 2000 OK\r\nHost: e\r\n\r\n'),
            ('start line: lowercase method', b'get / HTTP/1.1\r\nHost: e\r\n\r\n'),
            ('start line: bad version token', b'GET / HTTP/x.y\r\nHost: e\r\n\r\n'),
            # Empty and near-empty buffers.
            ('empty', b''),
            ('bare CRLFCRLF', b'\r\n\r\n'),
            ('CRLFCRLF then body', b'\r\n\r\nbody'),
            # Valid, to keep the battery honest about what it is asserting.
            ('valid request', b'GET / HTTP/1.1\r\nHost: e\r\n\r\n'),
            ('valid response', b'HTTP/1.1 200 OK\r\nServer: s\r\n\r\n'),
            ('valid folded request', b'GET / HTTP/1.1\r\nX: a\r\n b\r\nHost: e\r\n\r\n'),
        )

        for label, raw in payloads:
            with self.subTest(case=label):
                try:
                    HTTPv1(io.BytesIO(raw), len(raw))
                except ProtocolError:
                    pass  # the only permitted failure
                except BaseException as exc:  # noqa: B036 # pragma: no cover
                    self.fail(f'{label}: bare {type(exc).__module__}.'
                              f'{type(exc).__qualname__} escaped httpv1.HTTP: {exc}')

    def test_httpv1_passes_maxsplit_to_re_split_by_keyword(self) -> None:
        """``re.split``'s ``maxsplit`` must be a keyword, or #787 recurs verbatim.

        Passing it positionally is a :exc:`DeprecationWarning` from Python 3.13
        and is documented to become a :exc:`TypeError`. A :exc:`TypeError` is
        neither a :exc:`ValueError` nor a ``ProtocolError``, so on the release
        that makes the change it would escape ``HTTP._guess_version``'s
        suppression and kill the HTTP/2 arm again -- the same defect as #787, from
        a different exception type, which is why it is pinned rather than left to
        a linter.

        Asserted on a real parse rather than by reading the source, so that a new
        positional ``re.split`` anywhere on this path is caught too.

        """
        import io
        import warnings

        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1

        raw = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-A: b\r\n\r\nbody'

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            HTTPv1(io.BytesIO(raw), len(raw))

        offenders = [
            f'{w.filename}:{w.lineno}: {w.message}' for w in caught
            if issubclass(w.category, DeprecationWarning) and 'maxsplit' in str(w.message)
        ]
        self.assertEqual(offenders, [])

    def test_guess_version_does_not_suppress_struct_error_on_the_http1_arm(self) -> None:
        """Only the *last* arm may suppress :exc:`struct.error`. Arm 1 must not.

        The sub-nine-octet leak is worked around by suppressing
        :exc:`struct.error` alongside ``ProtocolError``, and it is tempting to
        apply that to both arms for symmetry. It must not be: an arm that is
        not the last one hands the payload *onward* when it swallows an error,
        and the HTTP/2 arm accepts any payload of at least nine octets -- so a
        swallowed error on arm 1 becomes a confident ``version='2'`` for a
        message that is plainly HTTP/1, which is the mislabel #787 exists to
        stop rather than a tidier failure. ``unknown HTTP version`` is only the
        best case, needing arm 2 to decline as well.

        #799 closed the *outer*-header slice of the class this suppression
        exists for (``httpv2.HTTP.unpack`` now rejects a buffer under nine
        octets before the schema layer runs), and #805 closed the *inner*
        slice (a resolved field length going negative now raises
        ``ProtocolError`` rather than a bare :exc:`struct.error`), but neither
        retired the suppression: it stays as defence in depth for any
        ``__length__``-keyed field #805 did not individually verify, across
        the ten schema modules that share the pattern. See
        ``test_guess_version_reports_unknown_version_for_a_short_payload`` for
        the outer-header case #799 closed, and
        ``test_guess_version_no_longer_leaks_a_bare_struct_error_for_an_inner_field_shortfall``
        below for the inner one #805 closed.

        It is also unnecessary: nothing reaches a :exc:`struct.error` through
        ``httpv1.HTTP``. Nine byte patterns over lengths 0-24, on both the direct
        route and ``read(version=1)``, answered ``ProtocolError`` 450 times out of
        450.

        :class:`~pcapkit.utilities.exceptions.StructError` is included because it
        *subclasses* :exc:`struct.error`, so a widened arm 1 would swallow
        pcapkit's own signal too -- along with ``StructError.eof``, which
        ``NoPayload`` handling reads -- where letting it escape reaches
        ``beholder`` and becomes ``Raw``.

        """
        import io
        import struct

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import StructError

        # Unambiguously HTTP/1.1, and long enough that arm 2 would accept it.
        raw = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n'

        # Control: unpatched, this is HTTP/1.1 on the guess path.
        self.assertEqual(HTTP(io.BytesIO(raw), len(raw)).version, '1.1')

        faults = (
            ('stdlib struct.error', struct.error('injected')),
            ('pcapkit StructError', StructError('injected')),
            ('pcapkit StructError, eof', StructError('injected', eof=True)),
        )

        for label, error in faults:
            with self.subTest(fault=label):
                with mock.patch('pcapkit.protocols.application.httpv1.HTTP',
                                mock.Mock(side_effect=error)):
                    # It must propagate, not be swallowed into an HTTP/2 answer.
                    with self.assertRaises(struct.error):
                        HTTP(io.BytesIO(raw), len(raw))

    def test_guess_version_no_longer_leaks_a_bare_struct_error_for_an_inner_field_shortfall(self) -> None:
        """A buffer that clears nine octets used to still crash one field further in.

        #799's ``httpv2.HTTP.unpack`` guard only protects the fixed nine-octet
        *outer* header. A ``GOAWAY`` frame's own fixed ``stream`` (4 octets) and
        ``error`` (4 octets) fields consume eight more octets before ``debug``
        is even reached, so a sixteen-octet buffer -- nine for the header, seven
        for the rest -- drives ``pkt['__length__']`` to ``-1`` at ``debug``.
        Pre-#805, that raised a bare :exc:`struct.error` straight through
        ``httpv2.HTTP``; #805 closed the actual root, generic
        ``FieldBase.length`` (``struct.calcsize`` on a negative-count template),
        shared by at least ten schema modules, not something httpv2-specific --
        so direct construction now raises :exc:`ProtocolError` too.

        ``_guess_version``'s last arm keeps suppressing :exc:`struct.error`
        alongside ``ProtocolError`` regardless: narrowing it, as an earlier
        revision of this fix did, regressed the direct ``HTTP()`` guess path
        for a *different* input class (the sub-nine-octet outer-header one),
        and #805 does not touch every ``__length__``-keyed field in every one
        of those ten modules, so the suppression stays as defence in depth.
        This test drives real wire bytes through the actual guess path -- no
        ``mock.patch`` -- specifically because a mocked fault cannot see a
        regression in the *un-mocked* route the fault is meant to stand in for.

        """
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import BaseError, ProtocolError

        # GOAWAY (type 0x07), sid 0, declared length 0x15 (21, this library's
        # whole-frame convention) -- but only sixteen octets actually follow.
        raw = b'\x00\x00\x15\x07\x00\x00\x00\x00\x00' + b'\xff' * 7
        self.assertEqual(len(raw), 16)

        # Direct construction now raises ProtocolError, not a bare
        # struct.error -- #805's fix, pinned here so a regression is noticed.
        import struct
        with self.assertRaises(ProtocolError) as direct_ctx:
            HTTPv2(io.BytesIO(raw), len(raw))
        self.assertNotIsInstance(direct_ctx.exception, struct.error)

        # The guess path must answer the same way: _guess_version's arm 2
        # suppresses struct.error/ProtocolError precisely so this comes back
        # catchable either way.
        for label, kwargs in (('guessed', {}), ('explicit version=2', {'version': 2})):
            with self.subTest(path=label):
                with self.assertRaises(ProtocolError) as ctx:
                    HTTP(io.BytesIO(raw), len(raw), **kwargs)
                self.assertIsInstance(ctx.exception, BaseError)
                self.assertIsInstance(ctx.exception, ValueError)
                self.assertNotIsInstance(ctx.exception, struct.error)

    def test_guess_version_keeps_http1_for_a_folded_http1_request(self) -> None:
        """The #787 claim, for the input class finding the colon-less line exposed.

        A folded request is legal HTTP/1, so the *right* outcome is that the
        HTTP/1 arm still claims it -- not that the HTTP/2 arm becomes reachable
        for it. Pinned through the proxy because that is where the mislabel would
        appear: ``UDP`` dispatches ports 80 and 8080 to this dispatcher, so a
        refused HTTP/1 request reads as ``UDP:HTTP/2`` in ``pcapkit.extract``
        output rather than merely failing.

        """
        import io

        from pcapkit.protocols.application.http import HTTP

        raw = b'GET / HTTP/1.1\r\nX-Long: a\r\n   b\r\nHost: e\r\n\r\n'

        guessed = HTTP(io.BytesIO(raw), len(raw))
        explicit = HTTP(io.BytesIO(raw), len(raw), version=1)

        self.assertEqual(guessed.version, '1.1')
        self.assertEqual(guessed.alias, 'HTTP/1.1')
        self.assertEqual(guessed.info, explicit.info)

    def test_httpv1_id_make_data_and_request_construction(self) -> None:
        from pcapkit.const.http.method import Method
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.protocols.schema.application.httpv1 import HTTP as Schema_HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv1)
        proto._info = SimpleNamespace(receipt=SimpleNamespace(version='1.0'))
        headers = OrderedMultiDict([('Host', 'example.test')])
        schema = proto.make(method='GET', uri='/index.html', headers=headers, body=b'body')
        bytes_schema = proto.make(method=b'POST', uri=b'/submit')
        enum_schema = proto.make(method=Method.HEAD, uri='/head')
        object_schema = proto.make(method=SimpleNamespace(value='TRACE'), uri='/trace')
        data = DummyData(
            receipt=SimpleNamespace(version='1.1', method=Method.GET, uri='/index.html'),
            header=headers,
            body=b'body',
        )

        self.assertEqual(HTTPv1.id(), ('HTTP', 'HTTPv1'))
        self.assertEqual(proto.version, '1.0')
        self.assertEqual(proto.alias, 'HTTP/1.0')
        self.assertIn(b'GET /index.html HTTP/1.1\r\n', schema.data)
        self.assertIn(b'Host: example.test\r\n', schema.data)
        self.assertTrue(schema.data.endswith(b'\r\nbody'))
        self.assertIn(b'POST /submit HTTP/1.1\r\n', bytes_schema.data)
        self.assertIn(b'HEAD /head HTTP/1.1\r\n', enum_schema.data)
        self.assertIn(b'TRACE /trace HTTP/1.1\r\n', object_schema.data)
        self.assertEqual(HTTPv1._make_data(data)['uri'], '/index.html')

        proto.__header__ = Schema_HTTP(data=b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\nbody')
        proto._data = proto.__header__.data
        proto.__cached__ = {}
        parsed = proto.read()
        self.assertEqual(parsed.receipt.version, '1.1')
        self.assertEqual(parsed.body, b'body')

        proto.__header__ = Schema_HTTP(data=b'HTTP/1.1 404 Not Found\r\nServer: example\r\n\r\nbody')
        response = proto.read()
        self.assertEqual(response.receipt.status, 404)
        self.assertEqual(response.receipt.message, 'Not Found')
        self.assertEqual(response.header['Server'], 'example')
        with self.assertRaises(ProtocolError):
            proto._read_http_header(b'BAD nope nope\r\nHost: example')

    def test_method_get_is_case_insensitive(self) -> None:
        """``Method.get`` tested the raw key and registered the upper-cased one,
        so a mixed-case method raised ``TypeError`` -- #583, item 1.

        The same mismatch as #582 in :mod:`pcapkit.const.ftp.command`. Resolving
        to the existing member matters beyond not crashing: a duplicate
        registered alongside ``GET`` would carry neither its ``safe`` nor its
        ``idempotent`` attribute.
        """
        from pcapkit.const.http.method import Method

        for key in ('GET', 'Get', 'get', 'gEt'):
            with self.subTest(key=key):
                self.assertIs(Method.get(key), Method.GET)

        self.assertIs(Method('Get'), Method.GET)
        self.assertTrue(Method.get('Get').safe)
        self.assertEqual([name for name in Method._member_map_
                          if name.upper() == 'GET'], ['GET'])

        unknown = Method.get('frob')
        self.assertEqual(unknown._name_, 'FROB')
        self.assertIs(Method.get('FROB'), unknown)

    def test_httpv1_method_regex_is_anchored(self) -> None:
        """``_RE_METHOD`` was unanchored and :func:`re.match` anchors only at the
        start, so it prefix-matched ``b'Get'`` down to ``b'G'`` -- #583, item 2.

        Method tokens are case-sensitive per :rfc:`9110#section-9.1`, so ``Get``
        is not ``GET`` and must not be accepted as one.
        """
        import re

        from pcapkit.protocols.application.httpv1 import _RE_METHOD

        for probe, expected in ((b'GET', b'GET'),
                                (b'POST', b'POST'),
                                (b'BASELINE-CONTROL', b'BASELINE-CONTROL'),
                                (b'Get', None),
                                (b'get', None),
                                (b'GET ', None)):
            with self.subTest(probe=probe):
                match = re.match(_RE_METHOD, probe)
                self.assertEqual(match.group('method') if match else None, expected)

    def test_httpv1_read_header_uses_the_captured_method(self) -> None:
        """``httpv1.py`` handed the whole ``para1`` to ``Method.get`` rather than
        the captured group, so a prefix match let a bad token through -- #583.

        Both halves are asserted together because either alone still gives a
        wrong answer: normalising ``Method.get`` alone would parse ``b'Get'`` as
        ``GET`` off a one-character match, and passing the captured group alone
        would parse it as a method named ``G``.
        """
        from pcapkit.const.http.method import Method
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv1)

        header, _ = proto._read_http_header(b'GET /index.html HTTP/1.1\r\nHost: example.test')
        self.assertIs(header.method, Method.GET)
        self.assertEqual(header.uri, '/index.html')

        # A mixed- or lower-case token is not a registered method and no longer
        # masquerades as a prefix of one; it is a malformed request line.
        for raw in (b'Get / HTTP/1.1\r\nHost: example.test',
                    b'get / HTTP/1.1\r\nHost: example.test'):
            with self.subTest(raw=raw):
                with self.assertRaises(ProtocolError):
                    proto._read_http_header(raw)

        # No case-variant member was registered on the way through.
        self.assertEqual([name for name in Method._member_map_
                          if name.upper() == 'GET'], ['GET'])

        # The response path is untouched.
        response, _ = proto._read_http_header(b'HTTP/1.1 404 Not Found\r\nServer: example')
        self.assertEqual(response.status, 404)

    def test_httpv1_status_regex_is_anchored(self) -> None:
        """``_RE_STATUS`` carried the same unanchored-prefix defect as
        ``_RE_METHOD``, and it escaped as the wrong exception type.

        Found while auditing ``_RE_METHOD``'s siblings for #583. The pattern is
        only a guard -- the value comes from ``int(para2)`` on the *raw* token --
        so a prefix match let a malformed status past the guard and then out of
        ``int()`` as a bare ``ValueError``, where ``_read_http_header`` documents
        ``ProtocolError``. :rfc:`9112#section-4` gives ``status-code = 3DIGIT``,
        exactly three, so anchoring is what the grammar says.

        The citation is RFC 9112, not RFC 9110: the production belongs to
        HTTP/1.1's ``status-line = HTTP-version SP status-code SP
        [ reason-phrase ]``, and :rfc:`9110#section-15` covers what the codes
        *mean* plus the IANA registry. RFC 9112 section 4 says so itself --
        "HTTP's core status codes are defined in Section 15 of [HTTP]". A
        cross-review caught the first draft citing 9110 for the grammar.

        Measured before the fix:
        ``b'HTTP/1.1 200x OK'`` -> ``ValueError: invalid literal for int() with
        base 10: b'200x'``, and ``b'HTTP/1.1 2000 OK'`` -> ``ValueError: 2000 is
        not a valid StatusCode``.
        """
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv1)

        good, _ = proto._read_http_header(b'HTTP/1.1 200 OK\r\nServer: example')
        self.assertEqual(good.status, 200)

        for raw in (b'HTTP/1.1 200x OK\r\nServer: example',
                    b'HTTP/1.1 2000 OK\r\nServer: example',
                    b'HTTP/1.1 20 OK\r\nServer: example'):
            with self.subTest(raw=raw):
                # ProtocolError, not ValueError: a malformed start line is a
                # protocol error, which is what the method documents.
                with self.assertRaises(ProtocolError):
                    proto._read_http_header(raw)

    def test_httpv1_response_construction_and_missing_request_uri_error(self) -> None:
        from pcapkit.const.http.status_code import StatusCode
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv1)
        schema = proto.make(status=StatusCode.CODE_200, message='OK')
        default_message = proto.make(status=StatusCode.CODE_404)

        self.assertIn(b'HTTP/1.1 200 OK\r\n\r\n', schema.data)
        self.assertIn(b'HTTP/1.1 404 Not Found\r\n\r\n', default_message.data)
        with self.assertRaises(ProtocolError):
            proto.make(method='GET')
        with self.assertRaises(ProtocolError):
            proto.make()
        with self.assertRaises(ProtocolError):
            proto.make(method='GET', uri='/', status=StatusCode.CODE_200)

    def test_httpv2_id_length_make_bytes_and_register_frame_warning(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        proto = object.__new__(HTTPv2)
        original = HTTPv2.__dict__['__frame__'][Frame.DATA]
        try:
            schema = proto.make(type=Frame.DATA, flags=0x01, sid=3, frame=b'data')
            with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
                HTTPv2.register_frame(Frame.DATA, 'data')

            self.assertEqual(HTTPv2.id(), ('HTTP', 'HTTPv2'))
            self.assertEqual(proto.alias, 'HTTP/2')
            self.assertEqual(proto.version, '2')
            self.assertEqual(proto.length, 9)
            self.assertEqual(proto.__length_hint__(), 9)
            self.assertEqual(schema.length, 13)
            self.assertEqual(schema.type, Frame.DATA)
            self.assertEqual(schema.flags['bit_0'], 1)
            self.assertEqual(schema.stream['sid'], 3)
            self.assertEqual(schema.frame, b'data')
            warn.assert_called_once()
        finally:
            HTTPv2.__dict__['__frame__'][Frame.DATA] = original

    def test_unregistered_frame_type_does_not_mutate_the_class_registry(self) -> None:
        """Parsing must not write to the shared ``HTTPv2.__frame__``.

        #425's defect on HTTP/2 frame dispatch. ``__frame__`` is a
        :class:`collections.defaultdict` on a class attribute shared by every
        :class:`~pcapkit.protocols.application.httpv2.HTTP` instance in the
        process, so ``__frame__[type]`` inserted every frame type it missed --
        and the value it inserted was ``'none'``, which the default factory
        returns anyway.

        Frame type ``0xF0`` sits in the range :rfc:`9113` leaves for extensions,
        so an unrecognised frame type is expected traffic rather than a
        malformed frame -- HTTP/2 requires an endpoint to ignore one.

        """
        import io

        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        # Length 13, type 0xF0, no flags, stream 1, then four octets of payload.
        #
        # 13 is the *whole* frame, header included, which is this library's
        # convention rather than :rfc:`9113#section-4.1`'s -- that one counts the
        # payload alone, so a real frame with four octets of payload declares 4.
        # ``make`` writes ``payload + 9`` (httpv2.py:292) and the readers recover
        # the payload as ``length - 9`` (httpv2.py:658,668), and ``read`` rejects
        # anything under 9 outright, so a wire-accurate 4 raises here. Declaring
        # 13 is what reaches the registry lookup; the mismatch with the RFC is a
        # separate defect and not this test's to assert.
        packet = bytes.fromhex('00000d' 'f0' '00' '00000001' '61626364')
        self.assertEqual(int.from_bytes(packet[:3], 'big'), len(packet))

        registry = HTTPv2.__dict__['__frame__']
        before = set(registry)
        self.assertNotIn(Frame(0xF0), before)

        try:
            with mock.patch('pcapkit.protocols.application.httpv2.warn'):
                proto = HTTPv2(io.BytesIO(packet), len(packet))

            # The frame is still parsed, by the fallback the registry declares.
            self.assertEqual(proto.info.data, b'abcd')
            self.assertEqual(set(registry), before)

            with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
                HTTPv2.register_frame(Frame(0xF0), 'none')
            self.assertEqual(warn.call_count, 0)
        finally:
            registry.pop(Frame(0xF0), None)

    def test_httpv2_frame_readers_cover_successful_frames(self) -> None:
        from pcapkit.const.http.error_code import ErrorCode
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        proto = object.__new__(HTTPv2)

        with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
            none = proto._read_http_none(
                http2_schema(data=b'unknown'),
                header=http2_header(10, 250, flags=0x01, sid=3),
            )
        self.assertEqual(none.to_dict()['data'], b'unknown')
        self.assertIsNone(none.flags)
        warn.assert_called_once()

        with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
            none_clean = proto._read_http_none(
                http2_schema(data=b'clean'),
                header=SimpleNamespace(length=9, type=251, flags={}, stream={'sid': 4}),
            )
        self.assertEqual(none_clean.data, b'clean')
        warn.assert_not_called()

        data = proto._read_http_data(
            http2_schema(pad_len=2, data=b'data', __flags__=0x09),
            header=http2_header(16, Frame.DATA, flags=0x09, sid=1),
        )
        self.assertTrue(data.flags.to_dict()['END_STREAM'])
        self.assertTrue(data.flags.to_dict()['PADDED'])
        self.assertEqual(data.to_dict()['pad_len'], 2)
        self.assertEqual(data.to_dict()['data'], b'data')

        headers = proto._read_http_headers(
            http2_schema(
                pad_len=1,
                stream_dep={'exclusive': 1, 'sid': 7},
                weight=4,
                fragment=b'headers',
                __flags__=0x2D,
            ),
            header=http2_header(22, Frame.HEADERS, flags=0x2D, sid=1),
        )
        self.assertTrue(headers.flags.to_dict()['END_STREAM'])
        self.assertTrue(headers.flags.to_dict()['END_HEADERS'])
        self.assertTrue(headers.flags.to_dict()['PADDED'])
        self.assertTrue(headers.flags.to_dict()['PRIORITY'])
        self.assertEqual(headers.to_dict()['stream_dependency'], 7)
        self.assertEqual(headers.to_dict()['weight'], 5)
        self.assertEqual(headers.to_dict()['fragment'], b'headers')

        priority = proto._read_http_priority(
            http2_schema(stream={'exclusive': 1, 'sid': 5}, weight=9),
            header=http2_header(9, Frame.PRIORITY, sid=1),
        )
        self.assertTrue(priority.to_dict()['excl_dependency'])
        self.assertEqual(priority.to_dict()['stream_dependency'], 5)
        self.assertEqual(priority.to_dict()['weight'], 10)

        rst = proto._read_http_rst_stream(
            http2_schema(error=ErrorCode.NO_ERROR),
            header=http2_header(13, Frame.RST_STREAM, sid=1),
        )
        self.assertEqual(rst.to_dict()['error'], ErrorCode.NO_ERROR)

        settings = proto._read_http_settings(
            http2_schema(settings=[
                SimpleNamespace(id=Setting.HEADER_TABLE_SIZE, value=4096),
                SimpleNamespace(id=Setting.ENABLE_PUSH, value=0),
            ], __flags__=0),
            header=http2_header(21, Frame.SETTINGS, sid=0),
        )
        self.assertFalse(settings.flags.to_dict()['ACK'])
        self.assertEqual(settings.settings[Setting.HEADER_TABLE_SIZE], 4096)
        self.assertEqual(settings.settings[Setting.ENABLE_PUSH], 0)

        push = proto._read_http_push_promise(
            http2_schema(pad_len=1, stream={'sid': 11}, fragment=b'push', __flags__=0x0C),
            header=http2_header(18, Frame.PUSH_PROMISE, flags=0x0C, sid=1),
        )
        self.assertTrue(push.flags.to_dict()['END_HEADERS'])
        self.assertTrue(push.flags.to_dict()['PADDED'])
        self.assertEqual(push.to_dict()['promised_sid'], 11)
        self.assertEqual(push.to_dict()['fragment'], b'push')

        ping = proto._read_http_ping(
            http2_schema(data=b'12345678', __flags__=0x01),
            header=http2_header(17, Frame.PING, flags=0x01, sid=0),
        )
        self.assertTrue(ping.flags.to_dict()['ACK'])
        self.assertEqual(ping.to_dict()['data'], b'12345678')

        goaway = proto._read_http_goaway(
            http2_schema(stream={'sid': 13}, error=ErrorCode.NO_ERROR, debug=b'bye'),
            header=http2_header(20, Frame.GOAWAY, sid=0),
        )
        self.assertEqual(goaway.to_dict()['last_sid'], 13)
        self.assertEqual(goaway.to_dict()['debug_data'], b'bye')

        window = proto._read_http_window_update(
            http2_schema(size={'incr': 65535}),
            header=http2_header(13, Frame.WINDOW_UPDATE, sid=1),
        )
        self.assertEqual(window.to_dict()['increment'], 65535)

        continuation = proto._read_http_continuation(
            http2_schema(fragment=b'cont', __flags__=0x04),
            header=http2_header(13, Frame.CONTINUATION, flags=0x04, sid=1),
        )
        self.assertTrue(continuation.flags.to_dict()['END_HEADERS'])
        self.assertEqual(continuation.to_dict()['fragment'], b'cont')

    def test_httpv2_frame_readers_reject_malformed_lengths(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv2)

        with self.assertRaises(ProtocolError):
            proto._read_http_priority(http2_schema(stream={'exclusive': 0, 'sid': 1}, weight=1),
                                      header=http2_header(10, Frame.PRIORITY))
        with self.assertRaises(ProtocolError):
            proto._read_http_rst_stream(http2_schema(error=0),
                                        header=http2_header(12, Frame.RST_STREAM))
        with self.assertRaises(ProtocolError):
            proto._read_http_settings(http2_schema(settings=[], __flags__=0),
                                      header=http2_header(14, Frame.SETTINGS, sid=0))
        with self.assertRaises(ProtocolError):
            proto._read_http_settings(http2_schema(settings=[], __flags__=0x01),
                                      header=http2_header(15, Frame.SETTINGS, flags=0x01, sid=0))
        with self.assertRaises(ProtocolError):
            proto._read_http_push_promise(http2_schema(pad_len=0, stream={'sid': 1}, fragment=b''),
                                          header=http2_header(12, Frame.PUSH_PROMISE))
        with self.assertRaises(ProtocolError):
            proto._read_http_ping(http2_schema(data=b'bad', __flags__=0),
                                  header=http2_header(16, Frame.PING, sid=0))
        with self.assertRaises(ProtocolError):
            proto._read_http_window_update(http2_schema(size={'incr': 1}),
                                           header=http2_header(12, Frame.WINDOW_UPDATE))

    def test_httpv2_read_validates_common_frame_header_rules(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv2)

        proto.__header__ = http2_header(8, Frame.DATA, sid=1)
        with self.assertRaises(ProtocolError):
            proto.read(length=8)

        proto.__header__ = http2_header(17, Frame.PING, sid=1)
        with self.assertRaises(ProtocolError):
            proto.read(length=17)

        proto.__header__ = http2_header(9, Frame.DATA, sid=1)
        proto.__header__.frame = http2_schema(pad_len=0, data=b'', __flags__=0)
        self.assertEqual(proto.read(length=9).to_dict()['type'], Frame.DATA)
        proto._data = b'\x00' * 9
        proto.__cached__ = {}
        self.assertEqual(proto.read().to_dict()['type'], Frame.DATA)

        # #799: a well-formed *declared* length (9, i.e. clears the header-only
        # guard on its own) must still be refused if the *available* buffer
        # does not also clear nine -- ``read``'s guard now checks both.
        proto.__header__ = http2_header(9, Frame.DATA, sid=1)
        proto.__header__.frame = http2_schema(pad_len=0, data=b'', __flags__=0)
        with self.assertRaises(ProtocolError):
            proto.read(length=8)

        # #799 blocker 2: a declared length that clears nine on its own must
        # still be refused if it exceeds what the buffer actually holds --
        # otherwise a frame can declare far more than the capture contains and
        # have that declared, attacker-controlled value reported as fact.
        proto.__header__ = http2_header(16777215, Frame.DATA, sid=1)
        proto.__header__.frame = http2_schema(pad_len=0, data=b'', __flags__=0)
        with self.assertRaises(ProtocolError):
            proto.read(length=9)

    def test_httpv2_truncated_frame_is_rejected_uniformly_regardless_of_declared_length(self) -> None:
        """#799: a buffer of four real octets must refuse *every* declared length.

        ``httpv2.py:223`` used to read ``if schema.length < 9:`` -- the declared
        24-bit length off the wire, never the buffer's -- so a frame whose real
        buffer held only four octets still parsed whenever the declared value
        happened to clear nine and (for ``SETTINGS``) land on a multiple of six
        past it. Measured pre-fix, sweeping the declared length against exactly
        this four-octet ``SETTINGS`` buffer::

            declared=0    -> ProtocolError   declared=9        -> PARSED length=9
            declared=5    -> ProtocolError   declared=15       -> PARSED length=15
            declared=8    -> ProtocolError   declared=65535    -> PARSED length=65535
            declared=10   -> ProtocolError   declared=16777215 -> PARSED length=16777215
            declared=100  -> ProtocolError

        Non-monotone in the declared value alone: 9 parsed, 10 did not, 15 did.
        The parses are exactly the declared lengths congruent to 3 (mod 6) --
        i.e. ``(declared - 9) % 6 == 0`` -- which is ``_read_http_settings``'s own
        *unrelated* structural check on the declared value, not evidence the
        buffer held what was declared. Every one of the nine cases below must
        now come back ``ProtocolError`` uniformly.

        """
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        def truncated_settings_frame(declared: int) -> bytes:
            # The *whole* wire buffer is four octets: the three-octet declared
            # length plus a one-octet SETTINGS type. Nothing else -- not even
            # the flags octet or the stream identifier -- is actually present,
            # so the frame's real buffer never backs what it declares.
            return declared.to_bytes(3, 'big') + bytes([0x04])

        for declared in (0, 5, 8, 9, 10, 15, 100, 65535, 16777215):
            with self.subTest(declared=declared):
                raw = truncated_settings_frame(declared)
                with self.assertRaises(ProtocolError):
                    HTTP(io.BytesIO(raw), len(raw))

    def test_httpv2_truncated_frame_is_rejected_across_frame_types_and_buffer_lengths(self) -> None:
        """The uniformity holds for other frame types and other buffer sizes too.

        The ``SETTINGS``-specific sweep above shows the exact reported shape,
        but the guard fix (``schema.length < 9 or length < 9 or schema.length
        > length``) is general: it must reject a too-short buffer for *any*
        frame type, and at every buffer length under nine, not only four.

        """
        import io

        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        def truncated_frame(declared: int, type_: int, buflen: int) -> bytes:
            header = declared.to_bytes(3, 'big') + bytes([type_])
            if len(header) < buflen:
                return header + b'\x00' * (buflen - len(header))
            return header[:buflen]

        declares = (0, 9, 10, 15, 100, 65535, 16777215)
        buflens = (0, 1, 4, 8)
        types = (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)  # every registered frame type

        for type_ in types:
            for declared in declares:
                for buflen in buflens:
                    with self.subTest(type=type_, declared=declared, buflen=buflen):
                        raw = truncated_frame(declared, type_, buflen)
                        with self.assertRaises(ProtocolError):
                            HTTP(io.BytesIO(raw), len(raw))

    def test_httpv2_declared_length_exceeding_the_buffer_is_rejected(self) -> None:
        """#799 blocker 2: a declared length beyond the buffer must not parse.

        Before this check, a frame whose declared length cleared nine on its
        own -- regardless of how far past the real buffer it reached -- still
        passed the guard and reported the declared, attacker-controlled value
        as if the capture actually contained it. Measured pre-fix, identical on
        base and the first revision of this PR: a nine-octet buffer declaring
        16777215 parsed and reported ``length=16777215``, overstated by
        16,777,206 octets, at every one of these buffer sizes.

        """
        import io

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        def frame(declared: int, buflen: int, type_: int = 0x00) -> bytes:
            header = (declared.to_bytes(3, 'big') + bytes([type_, 0x00])
                     + (0).to_bytes(4, 'big'))
            if len(header) < buflen:
                return header + b'\x00' * (buflen - len(header))
            return header[:buflen]

        for buflen in (9, 10, 12, 16, 24):
            with self.subTest(buflen=buflen):
                raw = frame(16777215, buflen)
                with self.assertRaises(ProtocolError):
                    HTTPv2(io.BytesIO(raw), len(raw))

        # The boundary itself: declared exactly equal to the buffer is fine
        # (covered by other tests too), one octet past it is not.
        exact = frame(9, 9)
        HTTPv2(io.BytesIO(exact), len(exact))  # must not raise

        one_over = frame(10, 9)
        with self.assertRaises(ProtocolError):
            HTTPv2(io.BytesIO(one_over), len(one_over))

    def test_httpv2_boundary_buffer_exactly_nine_octets(self) -> None:
        """The boundary itself: a buffer of exactly nine octets must parse.

        Nine is the header's own size, so a ``DATA`` frame declaring nine (an
        empty payload) backed by exactly nine real octets is the smallest
        legitimate HTTP/2 frame there is. One octet short of that must still be
        refused -- pinning that the fix's ``>= 9`` is not an off-by-one ``> 9``.

        """
        import io

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        exactly_nine = http2_frame_bytes(0x00, 0x00, 1, b'')
        self.assertEqual(len(exactly_nine), 9)
        info = HTTPv2(io.BytesIO(exactly_nine), len(exactly_nine)).info
        self.assertEqual(info.length, 9)
        self.assertEqual(info.data, b'')

        one_short = exactly_nine[:8]
        with self.assertRaises(ProtocolError):
            HTTPv2(io.BytesIO(one_short), len(one_short))

    def test_httpv2_well_formed_frame_still_parses(self) -> None:
        """The fix must not refuse a frame whose buffer backs its declared length.

        A ``DATA`` frame declaring 21 (nine octets of header plus twelve of
        payload) backed by all 21 real octets is exactly the well-formed case
        the guard must keep accepting.

        """
        import io

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        payload = b'{"ok":true}\n'
        raw = http2_frame_bytes(0x00, 0x00, 1, payload)

        info = HTTPv2(io.BytesIO(raw), len(raw)).info
        self.assertEqual(info.length, len(raw))
        self.assertEqual(info.data, payload)

    def test_httpv2_unpack_rejects_a_short_buffer_before_the_schema_layer_crashes(self) -> None:
        """A buffer under nine octets must not reach :func:`struct.calcsize`.

        Before this guard existed at ``unpack``, a buffer too short to hold the
        fixed nine-octet header sent ``Schema.unpack`` into arithmetic that
        builds a *negative*-length struct template for a frame's payload field
        (``pkt['__length__']`` is decremented by each field's nominal width
        regardless of how many octets the buffer actually had), and
        :func:`struct.calcsize` raised a bare :exc:`struct.error` for it --
        neither a ``ProtocolError`` nor caught by anything downstream. Pinned
        directly on ``HTTP.unpack`` rather than only on ``read``, since ``read``
        never runs for these buffers: the crash happened one call earlier.

        """
        import io

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for size in range(0, 9):
            with self.subTest(size=size):
                short = b'\x00' * size
                with self.assertRaises(ProtocolError):
                    HTTPv2(io.BytesIO(short), len(short))

    def test_httpv2_unpack_rejects_an_implicit_short_buffer_but_not_an_empty_one(self) -> None:
        """The ``length=None`` path: non-empty short is rejected, empty is not.

        ``unpack`` resolves ``length`` from ``len(self)`` only when the caller
        leaves it ``None`` -- exercised nowhere else in this module, since
        every other case above passes an explicit ``length``. A *non-empty*
        buffer under nine octets is malformed regardless of how ``length``
        arrived, so it is still rejected here. A *genuinely empty* one is not:
        that is :meth:`Schema.unpack`'s own "no more packets" signal
        (:exc:`StreamEOFError`), and forwarding a resolved ``0`` in its place --
        rather than the original ``None`` -- would misreport that signal as a
        malformed packet instead of preserving it.

        """
        import io

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError, StreamEOFError

        for size in range(1, 9):
            with self.subTest(size=size):
                short = b'\x00' * size
                with self.assertRaises(ProtocolError):
                    HTTPv2(io.BytesIO(short))  # no explicit length

        with self.assertRaises(StreamEOFError):
            HTTPv2(io.BytesIO(b''))  # no explicit length, genuinely exhausted

    def test_httpv2_frame_constructors_cover_all_frame_types_and_branches(self) -> None:
        from pcapkit.const.http.error_code import ErrorCode
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.protocols.data.application.httpv2 import PingFrame, PingFrameFlags
        from pcapkit.protocols.schema.application import httpv2 as schema_httpv2
        from pcapkit.protocols.schema.application.httpv2 import DataFrame, SettingPair
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv2)

        none_schema, none_flags = proto._make_http_none(SimpleNamespace(data=b'unknown'))
        self.assertEqual(none_schema.data, b'unknown')
        self.assertEqual(none_flags, 0)
        none_direct_schema, none_direct_flags = proto._make_http_none(data=b'direct')
        self.assertEqual(none_direct_schema.data, b'direct')
        self.assertEqual(none_direct_flags, 0)

        data_schema, data_flags = proto._make_http_data(end_stream=True, pad_len=2, data=b'data')
        self.assertTrue(data_flags & DataFrame.Flags.END_STREAM)
        self.assertTrue(data_flags & DataFrame.Flags.PADDED)
        self.assertEqual(data_schema.pad_len, 2)
        data_plain_schema, data_plain_flags = proto._make_http_data(data=b'plain')
        self.assertEqual(data_plain_schema.data, b'plain')
        self.assertEqual(data_plain_flags, 0)
        # ``_make_http_data`` reads ``frame.flags.END_STREAM`` back (#652), so
        # this stub carries a ``flags`` namespace in the same shape the
        # ``_make_http_headers`` stub below already used.
        frame_schema, frame_flags = proto._make_http_data(SimpleNamespace(
            flags=SimpleNamespace(END_STREAM=True, PADDED=False),
            pad_len=3,
            data=b'from-frame',
        ))
        self.assertEqual(frame_schema.data, b'from-frame')
        self.assertTrue(frame_flags & DataFrame.Flags.PADDED)
        self.assertTrue(frame_flags & DataFrame.Flags.END_STREAM)

        headers_schema, headers_flags = proto._make_http_headers(
            end_stream=True,
            end_headers=True,
            pad_len=1,
            excl_dep=True,
            sid_dep=7,
            weight=5,
            fragment=b'headers',
        )
        self.assertEqual(headers_schema.stream_dep['sid'], 7)
        self.assertEqual(headers_schema.weight, 4)
        self.assertEqual(headers_flags, 0x2D)
        headers_frame_schema, headers_frame_flags = proto._make_http_headers(SimpleNamespace(
            flags=SimpleNamespace(PRIORITY=True, END_HEADERS=True, END_STREAM=False),
            pad_len=0,
            excl_dependency=False,
            stream_dependency=9,
            weight=1,
            fragment=b'from-frame',
        ))
        self.assertEqual(headers_frame_schema.fragment, b'from-frame')
        self.assertEqual(headers_frame_flags, 0x24)
        headers_plain_schema, headers_plain_flags = proto._make_http_headers(fragment=b'plain')
        self.assertEqual(headers_plain_schema.fragment, b'plain')
        self.assertEqual(headers_plain_flags, 0)

        priority_schema, _ = proto._make_http_priority(sid_dep=3, excl_dep=True, weight=10)
        self.assertEqual(priority_schema.stream['sid'], 3)
        self.assertEqual(priority_schema.weight, 9)
        priority_frame_schema, _ = proto._make_http_priority(SimpleNamespace(
            excl_dependency=False,
            stream_dependency=4,
            weight=1,
        ))
        self.assertEqual(priority_frame_schema.stream['sid'], 4)

        rst_schema, _ = proto._make_http_rst_stream(error=ErrorCode.CANCEL)
        self.assertEqual(rst_schema.error, ErrorCode.CANCEL)
        rst_frame_schema, _ = proto._make_http_rst_stream(SimpleNamespace(error=ErrorCode.NO_ERROR))
        self.assertEqual(rst_frame_schema.error, ErrorCode.NO_ERROR)

        settings_list_schema, settings_list_flags = proto._make_http_settings(
            ack=True,
            settings=[
                SettingPair(id=Setting.HEADER_TABLE_SIZE, value=4096),
                (Setting.ENABLE_PUSH, 0),
            ],
        )
        self.assertEqual(settings_list_flags, 0x01)
        self.assertEqual([item.id for item in settings_list_schema.settings],
                         [Setting.HEADER_TABLE_SIZE, Setting.ENABLE_PUSH])
        settings_bytes_schema, _ = proto._make_http_settings(settings=b'\x00\x01\x00\x00\x10\x00')
        self.assertEqual(settings_bytes_schema.settings, b'\x00\x01\x00\x00\x10\x00')
        settings_dict_schema, _ = proto._make_http_settings(
            SimpleNamespace(flags=SimpleNamespace(ACK=False),
                            settings=OrderedMultiDict([(Setting.MAX_FRAME_SIZE, 16384)])),
        )
        self.assertEqual(settings_dict_schema.settings[0].id, Setting.MAX_FRAME_SIZE)
        with self.assertRaises(ProtocolError):
            proto._make_http_settings(settings=None)

        push_schema, push_flags = proto._make_http_push_promise(
            end_headers=True,
            pad_len=1,
            promised_sid=11,
            fragment=b'push',
        )
        self.assertEqual(push_schema.stream['sid'], 11)
        self.assertEqual(push_flags, 0x0C)
        push_frame_schema, push_frame_flags = proto._make_http_push_promise(SimpleNamespace(
            flags=SimpleNamespace(END_HEADERS=False),
            pad_len=2,
            promised_sid=12,
            fragment=b'from-frame',
        ))
        self.assertEqual(push_frame_schema.stream['sid'], 12)
        self.assertEqual(push_frame_flags, 0x08)
        push_plain_schema, push_plain_flags = proto._make_http_push_promise(
            promised_sid=13,
            fragment=b'plain',
        )
        self.assertEqual(push_plain_schema.stream['sid'], 13)
        self.assertEqual(push_plain_flags, 0)

        ping_schema, ping_flags = proto._make_http_ping(ack=True, opaque_data=b'12345678')
        self.assertEqual(ping_schema.data, b'12345678')
        self.assertEqual(ping_flags, 0x01)
        ping_frame_schema, ping_frame_flags = proto._make_http_ping(SimpleNamespace(
            flags=SimpleNamespace(ACK=False),
            data=b'abcdefgh',
        ))
        self.assertEqual(ping_frame_schema.data, b'abcdefgh')
        self.assertEqual(ping_frame_flags, 0)

        goaway_schema, _ = proto._make_http_goaway(
            last_sid=13,
            error=ErrorCode.NO_ERROR,
            debug_data=b'bye',
        )
        self.assertEqual(goaway_schema.stream['sid'], 13)
        self.assertEqual(goaway_schema.debug, b'bye')
        goaway_frame_schema, _ = proto._make_http_goaway(SimpleNamespace(
            last_sid=14,
            error=ErrorCode.PROTOCOL_ERROR,
            debug_data=b'frame',
        ))
        self.assertEqual(goaway_frame_schema.stream['sid'], 14)

        window_schema, _ = proto._make_http_window_update(incr=65535)
        self.assertEqual(window_schema.size['incr'], 65535)
        window_frame_schema, _ = proto._make_http_window_update(SimpleNamespace(increment=7))
        self.assertEqual(window_frame_schema.size['incr'], 7)

        continuation_schema, continuation_flags = proto._make_http_continuation(
            end_headers=True,
            fragment=b'cont',
        )
        self.assertEqual(continuation_schema.fragment, b'cont')
        self.assertEqual(continuation_flags, 0x04)
        continuation_frame_schema, continuation_frame_flags = proto._make_http_continuation(SimpleNamespace(
            flags=SimpleNamespace(END_HEADERS=False),
            fragment=b'from-frame',
        ))
        self.assertEqual(continuation_frame_schema.fragment, b'from-frame')
        self.assertEqual(continuation_frame_flags, 0)

        made_from_dict = proto.make(type=Frame.HEADERS, sid=1, frame={
            'end_headers': True,
            'sid_dep': 0,
            'fragment': b'h',
        })
        self.assertEqual(made_from_dict.type, Frame.HEADERS)
        self.assertEqual(made_from_dict.flags['bit_2'], 1)
        made_from_bytes = proto.make(type=Frame.DATA, sid=1, frame=b'raw')
        self.assertEqual(made_from_bytes.length, 12)
        self.assertEqual(made_from_bytes.frame, b'raw')
        made_from_schema = proto.make(type=Frame.DATA, sid=1,
                                      frame=schema_httpv2.UnassignedFrame(data=b'schema'))
        self.assertEqual(made_from_schema.length, 15)
        ping_data = PingFrame(
            length=17,
            type=Frame.PING,
            flags=PingFrameFlags(ACK=True),
            sid=0,
            data=b'12345678',
        )
        ping_data.flags.__update__({'__value__': 0x01})
        made_from_data = proto.make(type=Frame.PING, sid=0, frame=ping_data)
        self.assertEqual(made_from_data.type, Frame.PING)
        self.assertEqual(made_from_data.flags['bit_0'], 1)
        self.assertEqual(proto._make_http_length(schema_httpv2.UnassignedFrame(data=b'xx'), 0), 2)
        self.assertEqual(proto._make_http_length(data_schema, data_flags), 7)
        self.assertEqual(proto._make_http_length(headers_schema, headers_flags), 14)
        self.assertEqual(proto._make_http_length(priority_schema, 0), 5)
        self.assertEqual(proto._make_http_length(rst_schema, 0), 4)
        self.assertEqual(proto._make_http_length(settings_list_schema, settings_list_flags), 12)
        self.assertEqual(proto._make_http_length(settings_bytes_schema, 0), 6)
        self.assertEqual(proto._make_http_length(push_schema, push_flags), 10)
        self.assertEqual(proto._make_http_length(ping_schema, ping_flags), 8)
        self.assertEqual(proto._make_http_length(goaway_schema, 0), 11)
        self.assertEqual(proto._make_http_length(window_schema, 0), 4)
        self.assertEqual(proto._make_http_length(continuation_schema, continuation_flags), 4)
        self.assertEqual(proto._make_http_length(SimpleNamespace(pack=lambda: b'abc'), 0), 3)
        with self.assertRaises(ProtocolError):
            proto.make(type=Frame.DATA, frame=object())

    def test_settings_frame_settings_field_wraps_item_schema(self) -> None:
        """Regression test for GH-459.

        ``SettingsFrame.settings`` used to pass the bare ``SettingPair``
        *class* as ``ListField``'s ``item_type``, where every sibling
        (``tcp.py``'s ``SACK.sack``, ``hip.py``, ``mh.py``'s
        ``CGAParametersOption.parameters``, ``sctp.py``'s
        ``gap_blocks``/``dup_tsn``) wraps its schema item in a
        :class:`~pcapkit.corekit.fields.misc.SchemaField`. A bare
        ``SchemaMeta`` is not a field instance, so ``ListField.unpack``'s
        schema branch -- ``field = self._item_type(packet)`` -- constructed a
        ``SettingPair`` from the packet *dict* instead of configuring a
        per-item field, and the ``isinstance(self._item_type, SchemaField)``
        check that picks the schema branch was ``False`` for a bare class in
        the first place, so it fell through to the plain-field branch and
        failed there instead: ``field.length`` does not exist on a
        ``SettingPair`` instance.

        This is a unit-level check on the field wiring, not an end-to-end
        ``HTTPv2`` round trip: the SETTINGS frame's pack path still dies
        earlier on ``KeyError: 'flags'``, raised by ``FrameType.post_process``
        at ``schema/application/httpv2.py:144`` where it reaches the enclosing
        header's ``flags`` field through a nested packet context that cannot
        see it (GH-445, fixed by the still-open PR #457), so a real
        ``SettingsFrame.pack()``/``HTTPv2(...).make()`` round trip through this
        field remains unreachable until that lands. The
        ``httpv2-frame/SETTINGS`` entry in ``EXPECTED_FAILURES`` records that
        same ``KeyError: 'flags'``.
        """
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.protocols.schema.application.httpv2 import SettingPair, SettingsFrame

        field = SettingsFrame.__fields__['settings']

        # The type-check the ``# type: ignore[arg-type]`` used to silence:
        # ``item_type`` must be a field instance, not the schema class itself.
        self.assertIsInstance(field._item_type, SchemaField)
        self.assertIs(field._item_type.schema, SettingPair)

        # Two SETTINGS pairs, 6 octets each: HEADER_TABLE_SIZE=4096,
        # ENABLE_PUSH=0.
        raw = (1).to_bytes(2, 'big') + (4096).to_bytes(4, 'big') \
            + (2).to_bytes(2, 'big') + (0).to_bytes(4, 'big')
        packet = {'__length__': len(raw)}

        settings = field(packet).unpack(raw, packet)

        self.assertEqual(len(settings), 2)
        self.assertIsInstance(settings[0], SettingPair)
        self.assertIsInstance(settings[1], SettingPair)
        self.assertEqual(settings[0].id, 1)
        self.assertEqual(settings[0].value, 4096)
        self.assertEqual(settings[1].id, 2)
        self.assertEqual(settings[1].value, 0)

    def test_httpv2_callable_frame_registry_paths(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.protocols.schema.application import httpv2 as schema_httpv2

        custom = Frame.get(250)
        frame_registry = HTTPv2.__dict__['__frame__']
        original = frame_registry.get(custom)

        def read_frame(frame, *, header):
            return SimpleNamespace(type=header.type, length=header.length,
                                   sid=header.stream['sid'], data=frame.data)

        def make_frame(frame=None, *, data=b''):
            if frame is not None:
                data = frame.data
            return schema_httpv2.UnassignedFrame(data=data), 0

        proto = object.__new__(HTTPv2)
        try:
            with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
                HTTPv2.register_frame(custom, (read_frame, make_frame))
            warn.assert_not_called()

            proto.__header__ = http2_header(9, custom, sid=3)
            proto.__header__.frame = SimpleNamespace(data=b'read')
            parsed = proto.read(length=9)
            self.assertEqual(parsed.data, b'read')
            self.assertEqual(parsed.sid, 3)

            made = proto.make(type=custom, sid=3, frame={'data': b'made'})
            self.assertEqual(made.frame.data, b'made')
            self.assertEqual(made.length, 13)
        finally:
            if original is None:
                frame_registry.pop(custom, None)
            else:
                frame_registry[custom] = original

    def test_httpv2_schema_selector_and_frame_post_process_flags(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.schema.application import httpv2 as schema_httpv2
        from pcapkit.protocols.schema.application.httpv2 import DataFrame

        field = schema_httpv2.http_frame_selector({
            'type': Frame.DATA,
            '__length__': 4,
        })
        self.assertIs(field.schema, DataFrame)
        self.assertEqual(field.length, 4)

        frame = DataFrame(pad_len=0, data=b'data')
        frame.post_process({
            'flags': {
                'bit_0': 1,
                'bit_1': 0,
                'bit_2': 0,
                'bit_3': 1,
                'bit_4': 0,
                'bit_5': 0,
                'bit_6': 0,
                'bit_7': 0,
            },
        })

        self.assertTrue(frame.__flags__ & DataFrame.Flags.END_STREAM)
        self.assertTrue(frame.__flags__ & DataFrame.Flags.PADDED)

        plain = DataFrame(pad_len=0, data=b'plain')
        plain.post_process({
            'flags': {f'bit_{bit}': 0 for bit in range(8)},
        })
        self.assertEqual(plain.__flags__, 0)
        # ``IntFlag`` compares equal to ``int``, so the assertion above passes
        # for both a plain ``0`` and a ``Flags(0)``. Pin the type too -- that is
        # the whole of #650.
        self.assertIs(type(plain.__flags__), DataFrame.Flags)

    def test_make_http_data_restores_end_stream_from_the_frame(self) -> None:
        """``_make_http_data`` must read ``END_STREAM`` back off ``frame.flags``.

        It was the only one of the six ``_make_http_*`` methods that never
        looked at ``frame.flags``, so a DATA frame parsed with ``END_STREAM``
        set rebuilt with the bit clear and a parse -> reconstruct round trip
        lost it silently (#652). ``PADDED`` survived only because it is
        re-derived from ``pad_len``.

        """
        import io

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.protocols.schema.application.httpv2 import DataFrame

        for end_stream, flags_octet in ((False, 0x00), (True, 0x01)):
            with self.subTest(end_stream=end_stream):
                raw = http2_frame_bytes(0x00, flags_octet, 1, b'hello')
                proto = HTTPv2(io.BytesIO(raw), len(raw))
                info = proto.read()

                # The bit is present on the parse ...
                self.assertIs(info.flags.END_STREAM, end_stream)

                # ... and must still be present on the rebuild.
                _, rebuilt = proto._make_http_data(info)
                self.assertEqual(
                    bool(rebuilt & DataFrame.Flags.END_STREAM), end_stream)

                # It must reach the constructed header's flags octet, which is
                # what a round trip actually writes to the wire.
                header = proto.make(**proto._make_data(info))
                self.assertEqual(header.flags['bit_0'], int(end_stream))
                self.assertEqual(header.pack()[4], flags_octet)

    def test_a_flagless_frame_seeds_its_flags_as_an_enum(self) -> None:
        """A flags octet of ``0x00`` must still yield a ``Flags``, not an ``int``.

        ``FrameType.post_process`` seeded its accumulator with a bare ``0`` and
        ``|=`` promoted it only as a side effect, so a frame with no bit set --
        routine in HTTP/2, not an edge case -- left ``__flags__`` a plain
        ``int`` where the schema and the data model both declare a ``Flags``,
        and a membership test against it raised ``TypeError`` (#650, the #616
        shape).

        """
        import io

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.protocols.schema.application.httpv2 import (DataFrame, FrameType,
                                                                 UnassignedFrame)

        for label, flags_octet in (('none set', 0x00), ('END_STREAM', 0x01)):
            with self.subTest(flags=label):
                raw = http2_frame_bytes(0x00, flags_octet, 1, b'hello')
                info = HTTPv2(io.BytesIO(raw), len(raw)).read()

                value = info.flags.__value__
                self.assertIs(type(value), DataFrame.Flags)
                self.assertEqual(value, flags_octet)

                # The #616 symptom: this raised ``TypeError: argument of type
                # 'int' is not a container or iterable`` for the 0x00 case.
                self.assertEqual(DataFrame.Flags.END_STREAM in value,
                                 bool(flags_octet & 0x01))

        # ``FrameType.Flags`` declares no members, which is the predicate
        # ``post_process`` guards its seed on -- pinned here so the guard
        # cannot be simplified away without this failing first.
        self.assertEqual(len(FrameType.Flags.__members__), 0)

        # What makes the guard *necessary* is version-dependent, so it is
        # asserted as such rather than unconditionally. The 3.11 enum rewrite
        # made a memberless ``enum.Flag`` subclass refuse ``Flags(0)``
        # outright, where earlier interpreters handed back a pseudo-member --
        # ``Enum.__new__`` gained ``if not cls._member_map_: raise TypeError``
        # (3.11's ``enum.py:1117``), which runs *before* the ``_missing_`` hook
        # that used to manufacture one. Measured either side of the boundary
        # rather than taken from a changelog:
        #
        #   3.8.20   Flags(0) -> OK <Flags.0: 0>
        #   3.9.25   Flags(0) -> OK <Flags.0: 0>
        #   3.10.21  Flags(0) -> OK <Flags.0: 0>
        #   3.11.15  Flags(0) -> TypeError: <flag 'Flags'> has no members defined
        #   3.12.13  Flags(0) -> TypeError: ... has no members; specify `names=()` ...
        #   3.14.7   Flags(0) -> TypeError: ... has no members; specify `names=()` ...
        #
        # 3.12 only reworded the message; the refusal itself starts at 3.11.
        # The guard keys on the memberless-ness above rather than on this, so
        # it is correct on every supported interpreter either way.
        if sys.version_info >= (3, 11):
            with self.assertRaises(TypeError):
                FrameType.Flags(0)

        # The five frame schemas that inherit that memberless enum therefore
        # keep the plain ``int`` -- and must not raise on the way.
        unassigned = UnassignedFrame(data=b'x')
        unassigned.post_process({
            'flags': {f'bit_{bit}': 0 for bit in range(8)},
        })
        self.assertIs(type(unassigned.__flags__), int)
        self.assertEqual(unassigned.__flags__, 0)

    def test_application_base_rejects_next_layer_operations(self) -> None:
        from pcapkit.protocols.application.application import Application
        from pcapkit.utilities.exceptions import IntError, UnsupportedCall

        class DemoApplication(Application):
            @property
            def name(self) -> str:
                return 'Demo Application'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

        app = object.__new__(DemoApplication)

        with self.assertRaises(IntError):
            DemoApplication.__index__()
        with self.assertRaises(UnsupportedCall):
            DemoApplication._decode_next_layer(app, object())
        with self.assertRaises(UnsupportedCall):
            DemoApplication._import_next_layer(app, 80)


if __name__ == '__main__':
    unittest.main()
