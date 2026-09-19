from __future__ import annotations

import io
import unittest

from tests._support import bootstrap_core_modules, install_fake_payload_protocols, purge_modules


class DecoratorTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        modules = bootstrap_core_modules()
        self.decorators = modules['decorators']
        self.exceptions = modules['exceptions']

    def test_seekset_restores_original_offset(self) -> None:
        class DemoProtocol:
            def __init__(self) -> None:
                self._file = io.BytesIO(b'abcdef')
                self._seekset = 2

            @self.decorators.seekset
            def read_two(self) -> bytes:
                return self._file.read(2)

        protocol = DemoProtocol()
        protocol._file.seek(5)

        self.assertEqual(protocol.read_two(), b'cd')
        self.assertEqual(protocol._file.tell(), 5)

    def test_prepare_converts_bytes_and_populates_packet_metadata(self) -> None:
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet: dict[str, object]) -> None:
                packet['prepped'] = True

            def __init__(self, data: bytes) -> None:
                self.data = data

            def post_process(self, packet: dict[str, object]) -> dict[str, object]:
                packet['data'] = self.data
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls(data.read())

        packet = DemoSchema.unpack(b'payload', None, None)

        self.assertEqual(packet['__length__'], 7)
        self.assertTrue(packet['prepped'])
        self.assertEqual(packet['data'], b'payload')

    def test_prepare_infers_length_for_stream_and_preserves_packet(self) -> None:
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet: dict[str, object]) -> None:
                packet['prepped'] = True

            def __init__(self, data: bytes) -> None:
                self.data = data

            def post_process(self, packet: dict[str, object]) -> dict[str, object]:
                packet['data'] = self.data
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls(data.read(length))

        stream = io.BytesIO(b'xxpayload')
        stream.seek(2)
        packet = {'existing': True}
        result = DemoSchema.unpack(stream, None, packet)

        self.assertEqual(result['__length__'], 7)
        self.assertTrue(result['existing'])
        self.assertTrue(result['prepped'])
        self.assertEqual(result['data'], b'payload')

        stream = io.BytesIO(b'payload-extra')
        result = DemoSchema.unpack(stream, 7, None)
        self.assertEqual(result['__length__'], 7)
        self.assertEqual(result['data'], b'payload')

    def _demo_schema_for_call_shapes(self):
        """A ``DemoSchema`` whose ``unpack`` records what ``prepare`` bound.

        Shared by the five call-shape tests below, one per row of `#444
        <https://github.com/JarryShaw/PyPCAPKit/issues/444>`__'s reproduction
        table: ``prepare`` used to subscript ``args[2]``/``args[3]``
        unconditionally, so only the three-positional shape worked and every
        shorter or keyword call raised ``IndexError`` instead of falling back
        to the documented ``length=None, packet=None`` defaults.

        """
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet: dict[str, object]) -> None:
                packet['prepped'] = True

            def __init__(self, data: bytes) -> None:
                self.data = data

            def post_process(self, packet: dict[str, object]) -> dict[str, object]:
                packet['data'] = self.data
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls(data.read())

        return DemoSchema

    def _assert_call_shape_result(self, packet: dict[str, object]) -> None:
        self.assertEqual(packet['__length__'], 7)
        self.assertTrue(packet['prepped'])
        self.assertEqual(packet['data'], b'payload')

    def test_prepare_accepts_data_only(self) -> None:
        """``unpack(data)`` -- length and packet both omitted."""
        DemoSchema = self._demo_schema_for_call_shapes()
        self._assert_call_shape_result(DemoSchema.unpack(b'payload'))

    def test_prepare_accepts_data_and_positional_length(self) -> None:
        """``unpack(data, length)`` -- packet omitted."""
        DemoSchema = self._demo_schema_for_call_shapes()
        self._assert_call_shape_result(DemoSchema.unpack(b'payload', 7))

    def test_prepare_accepts_data_length_and_packet_positionally(self) -> None:
        """``unpack(data, length, packet)`` -- the one shape that already worked."""
        DemoSchema = self._demo_schema_for_call_shapes()
        self._assert_call_shape_result(DemoSchema.unpack(b'payload', 7, {}))

    def test_prepare_accepts_keyword_length(self) -> None:
        """``unpack(data, length=2)`` -- length by keyword, packet omitted."""
        DemoSchema = self._demo_schema_for_call_shapes()
        self._assert_call_shape_result(DemoSchema.unpack(b'payload', length=7))

    def test_prepare_accepts_keyword_length_and_packet(self) -> None:
        """``unpack(data, length=2, packet={})`` -- both trailing args by keyword."""
        DemoSchema = self._demo_schema_for_call_shapes()
        self._assert_call_shape_result(DemoSchema.unpack(b'payload', length=7, packet={}))

    def test_prepare_raises_typeerror_for_extra_positional_and_keyword_arguments(self) -> None:
        """Extras used to vanish silently instead of being forwarded; see #454.

        ``prepare``'s own docstring promised the decorated function receives
        ``*args, **kwargs``, but the wrapper never populated either --
        reproduced from the issue::

            Probe.unpack(b'\\x07\\x08', 2, {}, 'EXTRA_POSITIONAL', extra_kw='EXTRA_KW')
            -> a=7 b=8      # both extras silently gone, no error

        The chosen fix removes the promise (nothing in the tree ever passed
        extras, and ``@prepare`` decorates exactly one function, whose real
        signature never had room for them) and rejects extras instead of
        forwarding them, so a misspelled or unsupported argument is a
        ``TypeError`` rather than a parse that silently ignored it.

        """
        DemoSchema = self._demo_schema_for_call_shapes()

        with self.assertRaises(TypeError):
            DemoSchema.unpack(b'payload', 7, {}, 'EXTRA_POSITIONAL', extra_kw='EXTRA_KW')

    def test_prepare_raises_typeerror_for_length_given_both_positionally_and_by_keyword(self) -> None:
        """The narrower case #454 calls out.

        Passing ``length`` both positionally and by keyword used to silently
        keep the positional value and drop the keyword one -- the keyword
        never reached ``kwargs.pop``, since that branch only runs when the
        positional slot was *not* supplied. It is now a caller error like any
        other unconsumed argument.

        """
        DemoSchema = self._demo_schema_for_call_shapes()

        with self.assertRaises(TypeError):
            DemoSchema.unpack(b'payload', 7, {}, length=2)

    def test_prepare_raises_eof_for_empty_payloads(self) -> None:
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet):
                return None

            def post_process(self, packet):
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls()

        with self.assertRaises(EOFError):
            DemoSchema.unpack(b'', None, None)

    def test_prepare_raises_stream_eof_error_not_a_bare_eof_error(self) -> None:
        """The genuinely-exhausted case now raises an in-library exception.

        A caller could not previously tell a truncated capture apart from any
        other ``EOFError``. ``StreamEOFError`` still *is* an ``EOFError`` --
        so ``pcapkit.foundation.extraction.Extractor``'s existing ``except
        (EOFError, StopIteration)`` keeps working unchanged -- but it can now
        be caught specifically via
        :class:`pcapkit.utilities.exceptions.StreamEOFError`.

        """
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet):
                return None

            def post_process(self, packet):
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls()

        with self.assertRaises(self.exceptions.StreamEOFError):
            DemoSchema.unpack(b'', None, None)

    def test_prepare_still_raises_eof_for_a_truncated_stream(self) -> None:
        """A file-like stream already exhausted, with no declared length, is
        the frame reader's genuine end-of-capture case and must still raise --
        confirming the #458 fix only changes the *declared*-zero case below,
        not this one.

        """
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet):
                return None

            def post_process(self, packet):
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls()

        stream = io.BytesIO(b'')
        with self.assertRaises(self.exceptions.StreamEOFError):
            DemoSchema.unpack(stream, None, None)

    def test_prepare_accepts_a_declared_zero_length_schema(self) -> None:
        """A nested, or otherwise genuinely empty, schema sized zero *by the
        caller* must unpack rather than raise. Reproduced from #458::

            @schema_final
            class Empty(Schema):
                pass
            Empty.unpack(b'', 0, {})
            -> EOFError: EOFError()     # before the fix

        Distinguishing this from the truncated-stream case above is what
        ``length is not None`` (a *declared* length, even zero) checks for.

        """
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet: dict[str, object]) -> None:
                packet['prepped'] = True

            def __init__(self, data: bytes) -> None:
                self.data = data

            def post_process(self, packet: dict[str, object]) -> dict[str, object]:
                packet['data'] = self.data
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls(data.read())

        packet = DemoSchema.unpack(b'', 0, {})

        self.assertEqual(packet['__length__'], 0)
        self.assertTrue(packet['prepped'])
        self.assertEqual(packet['data'], b'')

    def test_prepare_leaves_the_schema_clean_after_post_process(self) -> None:
        """``post_process``'s revisions must not mark the schema as needing a re-pack.

        ``Schema.unpack`` clears ``__updated__`` before returning, but
        ``post_process`` runs after it and every field it assigns sets the flag
        again. The schema was therefore left dirty, and the next
        ``bytes(schema)`` re-packed it -- which calls ``post_process`` a second
        time with a packet context rebuilt from the schema's own fields, so any
        value ``post_process`` had derived from the *enclosing* layer's context
        was overwritten with the fallback. ``Schema.pack`` clears the flag after
        ``post_process``, and this asserts the unpacking path now matches it.

        """
        class DemoSchema:
            def __init__(self) -> None:
                self.__updated__ = False

            @classmethod
            def pre_unpack(cls, packet) -> None:
                return None

            def post_process(self, packet):
                # stand-in for a field assignment, which is what sets the flag
                self.value = packet.get('src', 'fallback')
                self.__updated__ = True
                return self

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls()

        schema = DemoSchema.unpack(b'payload', None, {'src': 'outer-source'})

        self.assertEqual(schema.value, 'outer-source')
        self.assertFalse(schema.__updated__)

    def test_prepare_tolerates_a_post_process_that_returns_no_schema(self) -> None:
        """``post_process`` need not return a schema, so the flag reset is guarded.

        An implementation may hand back a nested schema instead of ``self`` --
        ``pcapkit.protocols.schema.internet.hopopt._SMFDPDOption`` returns
        ``self.data`` -- and the stand-ins above return the packet mapping.
        Neither may raise from the reset.

        """
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet) -> None:
                packet['prepped'] = True

            def post_process(self, packet):
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls()

        returned = DemoSchema.unpack(b'payload', None, None)

        self.assertIsInstance(returned, dict)
        self.assertTrue(returned['prepped'])

    ##########################################################################
    # beholder.
    #
    # The stand-in protocols below carry a ``_get_payload`` that delegates to
    # ``self.__header__.get_payload()``, because that is what
    # ``ProtocolBase._get_payload`` is -- a wrapper over the schema's accessor.
    # ``beholder`` goes through the wrapper rather than the schema directly, so
    # that the two protocols which override it (SCTP, PCAP-NG) recover from a
    # next-layer failure at all; see
    # ``test_beholder_uses_the_protocol_payload_accessor_not_the_schema``.
    ##########################################################################

    @staticmethod
    def _payload_stand_ins():
        """``Raw`` and ``NoPayload`` stand-ins recording what they were handed."""
        class NoPayload:
            def __init__(self, file_, length, error=None, alias=None) -> None:
                self.file = file_
                self.length = length
                self.error = error
                self.alias = alias

        class Raw(NoPayload):
            pass

        install_fake_payload_protocols(Raw, NoPayload)
        return Raw, NoPayload

    @staticmethod
    def _demo_protocol_class(decorator, payload: bytes, raises, drop_length=False):
        """A protocol whose next-layer decode always raises ``raises``."""
        class Header:
            def get_payload(self) -> bytes:
                return payload

        class DemoProtocol:
            __header__ = Header()

            def _get_payload(self) -> bytes:
                return self.__header__.get_payload()

            if drop_length:
                @decorator
                def decode(self, proto):
                    raise raises
            else:
                @decorator
                def decode(self, proto, length=None):
                    raise raises

        return DemoProtocol

    def test_beholder_wraps_struct_eof_with_no_payload(self) -> None:
        Raw, NoPayload = self._payload_stand_ins()
        DemoProtocol = self._demo_protocol_class(
            self.decorators.beholder, b'payload-bytes',
            self.exceptions.StructError('unexpected eof', eof=True))

        result = DemoProtocol().decode(1, 10)

        self.assertIsInstance(result, NoPayload)
        self.assertEqual(result.file, b'payload-bytes')
        self.assertEqual(result.length, 10)
        self.assertEqual(result.error, 'unexpected eof')

    def test_beholder_wraps_other_errors_with_raw(self) -> None:
        Raw, _ = self._payload_stand_ins()
        DemoProtocol = self._demo_protocol_class(
            self.decorators.beholder, b'raw-bytes', ValueError('broken parser'))

        result = DemoProtocol().decode(1, 3)

        self.assertIsInstance(result, Raw)
        self.assertEqual(result.file, b'raw-bytes')
        self.assertEqual(result.length, 3)
        self.assertEqual(result.error, 'broken parser')

    def test_beholder_forwards_the_protocol_number_as_an_alias(self) -> None:
        """A failed payload keeps the number it arrived with.

        The success path in ``_import_next_layer`` passes ``alias=proto``, so a
        payload that reached :class:`Raw` because nothing was registered on its
        number is still labelled with that number. Omitting it from the failure
        path made *registering* a protocol produce less informative output than
        leaving the number unregistered.

        """
        Raw, _ = self._payload_stand_ins()
        DemoProtocol = self._demo_protocol_class(
            self.decorators.beholder, b'raw-bytes', ValueError('broken parser'))

        self.assertEqual(DemoProtocol().decode(60, 3).alias, 60)
        # No ``proto`` argument at all -- the decorator must not raise.
        DemoProtocol = self._demo_protocol_class(
            self.decorators.beholder, b'raw-bytes', ValueError('broken parser'),
            drop_length=True)
        self.assertEqual(DemoProtocol().decode(66).alias, 66)

    def test_beholder_uses_the_protocol_payload_accessor_not_the_schema(self) -> None:
        """An overridden ``_get_payload`` is what the recovery path reads.

        SCTP carries user data inside a DATA chunk and PCAP-NG inside a block,
        so neither header schema has a ``payload`` field: reaching for the schema
        raises ``ProtocolUnbound('unknown field: payload')`` *from the recovery
        path*, turning a next-layer failure that should have degraded to
        :class:`Raw` into a crash. It was unreachable until something was
        registered on an SCTP payload protocol identifier, which NGAP now is.

        """
        exceptions = self.exceptions
        Raw, _ = self._payload_stand_ins()

        class Header:
            def get_payload(self) -> bytes:
                raise exceptions.ProtocolUnbound("unknown field: 'payload'")

        class DemoProtocol:
            __header__ = Header()

            def _get_payload(self) -> bytes:
                return b'chunk-user-data'

            @self.decorators.beholder
            def decode(self, proto, length=None):
                raise ValueError('broken parser')

        result = DemoProtocol().decode(60, 15)

        self.assertIsInstance(result, Raw)
        self.assertEqual(result.file, b'chunk-user-data')

    def test_beholder_verbose_mode_prints_traceback(self) -> None:
        Raw, _ = self._payload_stand_ins()
        DemoProtocol = self._demo_protocol_class(
            self.decorators.beholder, b'raw-bytes', ValueError('broken parser'))

        from unittest import mock

        with mock.patch.object(self.decorators, 'VERBOSE', True):
            with mock.patch.object(self.decorators.traceback, 'print_exc') as print_exc:
                result = DemoProtocol().decode(1, 3)

        self.assertIsInstance(result, Raw)
        print_exc.assert_called_once()

    def test_beholder_defaults_length_when_argument_is_missing(self) -> None:
        Raw, _ = self._payload_stand_ins()
        DemoProtocol = self._demo_protocol_class(
            self.decorators.beholder, b'raw-bytes', ValueError('broken parser'),
            drop_length=True)

        result = DemoProtocol().decode(1)

        self.assertIsInstance(result, Raw)
        self.assertIsNone(result.length)


if __name__ == '__main__':
    unittest.main()
