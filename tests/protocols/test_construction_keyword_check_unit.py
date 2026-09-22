# -*- coding: utf-8 -*-
"""A construction keyword no signature declares is refused, not discarded.

Every ``make`` in the tree ends its signature with ``**kwargs: 'Any'`` and reads
nothing out of it, so until issue #617 a keyword it did not declare was accepted,
dropped, and the field it named kept its default. That is the worst shape a defect
can take in a packet library: the octets are wrong, nothing says so, and the
mapping that produced them reads correctly.

The cost is not hypothetical. Issue #602 was
:data:`examples.generators.options.TCP_BASE` asking for ``seq=1`` where
:meth:`TCP.make <pcapkit.protocols.transport.tcp.TCP.make>` spells the parameter
``seq_no``. Measured on the tree before this fix::

    declared seq = 1   built info.seq = 0
    warnings captured: []

Twenty-five generated fixture frames carried sequence number ``0`` while the
generator said ``1``, one octet per frame, and the only reason anybody found out
was that somebody read the mapping against the signature. Issues #541 and #556
were the same family of silence.

The schema layer has never been so permissive: :meth:`Schema.__update__
<pcapkit.protocols.schema.schema.Schema.__update__>` warns
:exc:`~pcapkit.utilities.warnings.UnknownFieldWarning` for a field it does not
know (:file:`pcapkit/protocols/schema/schema.py`). The asymmetry between the two
is what #617 is about, and
:meth:`AsymmetryTests.test_the_schema_layer_still_warns_where_construction_now_raises`
pins both halves of it in one place.

What is checked, and what is deliberately not
---------------------------------------------

The check runs in :meth:`ProtocolBase.__init__
<pcapkit.protocols.protocol.ProtocolBase.__init__>` rather than in ``make``,
because ``make`` is not the only consumer of the keywords it is handed:
:meth:`ProtocolBase.__post_init__
<pcapkit.protocols.protocol.ProtocolBase.__post_init__>` passes one ``**kwargs``
to the construction *and* to the parse of what it has just constructed, so a
keyword declared only by ``read`` travels through ``make`` as well.
:class:`~pcapkit.protocols.internet.hip.HIP` is the live example and
:class:`ForwardedKeywordTests` is where it is pinned; rejecting on ``make``'s
signature alone would reject correct code.

Two things are left alone on purpose, and each has a test saying so:

:meth:`ScopeTests.test_the_parse_path_is_unaffected`
    Parsing. There the keywords are not field values but whatever the engines and
    the four ``_import_next_layer`` implementations forward -- ``alias``,
    ``packet``, and the parse limits -- and a protocol cannot know which of its
    ancestors' keywords its parent chose to pass on. Nothing was ever lost that
    way either: a dropped parse keyword changes how a packet is read, not what
    the octets say.

:meth:`ScopeTests.test_out_of_band_keywords_are_accepted_while_constructing`
    The out-of-band keywords, which configure the call rather than naming a
    field and are consumed before any ``make`` sees them.

And one thing is softened rather than left alone, in :class:`ReconstructionTests`:
:meth:`ProtocolBase.from_data <pcapkit.protocols.protocol.ProtocolBase.from_data>`
warns where a caller would be raised at, because the keywords it spreads came out
of :meth:`ProtocolBase._make_data
<pcapkit.protocols.protocol.ProtocolBase._make_data>` rather than out of anybody's
editor. Three protocols have a mismatch of exactly that kind today and have been
losing a field to it in silence; they are recorded there.

This module is unit tier: it constructs its own octets and reads no capture, so
it runs on a fresh checkout with nothing generated.

"""

from __future__ import annotations

import collections
import importlib.util
import inspect
import io
import unittest
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A correct TCP header, spelled the way :meth:`TCP.make
#: <pcapkit.protocols.transport.tcp.TCP.make>` declares it. The baseline every
#: rejection below is a single-keyword departure from, so that a test failing
#: says "this keyword" rather than "something in here".
GOOD_HEADER = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'syn': True, 'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
}

#: The three misspellings of #602, as ``(wrong spelling, the parameter meant)``.
MISSPELLINGS = (
    ('seq', 'seq_no'),
    ('ack_flag', 'ack'),
    ('urgent_pointer', 'urgent'),
)


def _protocol_class(**namespace: 'Any') -> 'Any':
    """Build a minimal :class:`~pcapkit.protocols.protocol.Protocol` subclass.

    Purpose-built rather than borrowed from a real protocol, because the shapes
    under test here -- a ``read`` that declares what ``make`` does not, a class
    that names a keyword in ``__keywords__`` -- have to be varied one at a time,
    and no single real protocol offers all of them. The real protocols are pinned
    by signature instead, in :class:`ForwardedKeywordTests`.

    Args:
        **namespace: Extra class attributes, e.g. an overriding ``read`` or a
            ``__keywords__``.

    Returns:
        The protocol class, whose ``make`` declares ``spam`` and nothing else.

    """
    from pcapkit.corekit.fields.misc import PayloadField
    from pcapkit.corekit.infoclass import info_final
    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.data import Data
    from pcapkit.protocols.protocol import Protocol
    from pcapkit.protocols.schema.schema import Schema, schema_final

    @info_final
    class DummyData(Data):
        value: int = 0

    @schema_final
    class DummySchema(Schema):
        payload: bytes = PayloadField(length=lambda packet: packet['__length__'], default=b'')

    # NOTE: A ``class`` statement rather than a ``type()`` call with a namespace
    # dict, on both counts: a generic base needs ``__mro_entries__`` resolution
    # that ``type()`` does not do, and ``read``/``make`` have to be *in* the body
    # because :class:`abc.ABCMeta` computes ``__abstractmethods__`` at class
    # creation and assigning them afterwards leaves the class abstract.
    class DummyProtocol(Protocol[DummyData, DummySchema],
                        schema=DummySchema, data=DummyData):
        __layer__ = 'Internet'
        __proto__ = collections.defaultdict(lambda: None)

        @property
        def name(self) -> 'str':
            return 'Dummy Protocol'

        @property
        def length(self) -> 'int':
            return 2

        def read(self, length: 'int | None' = None, **kwargs: 'Any') -> 'DummyData':
            from pcapkit.protocols.misc.null import NoPayload

            self._next = NoPayload()
            self._protos = ProtoChain(type(self), self.alias, basis=self._next.protochain)
            return DummyData(value=0)

        def make(self, spam: 'bytes' = b'ab', **kwargs: 'Any') -> 'DummySchema':
            return DummySchema(payload=spam)

        @classmethod
        def __index__(cls) -> 'int':  # type: ignore[override]
            return 250

    # Overriding a method that is already concrete, so this does not reopen
    # ``__abstractmethods__``. Nothing reads the signatures until the first
    # construction, so a later assignment is still seen by the check.
    for attribute, value in namespace.items():
        setattr(DummyProtocol, attribute, value)

    return DummyProtocol


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RejectionTests(unittest.TestCase):
    """An undeclared construction keyword raises rather than vanishing."""

    def test_the_three_misspellings_of_the_defect_are_each_refused(self) -> None:
        """Each key of #602, put back one at a time, raises and is named.

        ``TCP_BASE`` is correct today, so reproducing the report means
        reintroducing the misspelling. Before the fix each of these built a
        segment whose field kept its default -- ``seq=1`` giving ``info.seq == 0``
        -- and captured no warning at all.

        """
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import UnsupportedCall

        for wrong, right in MISSPELLINGS:
            keywords = dict(GOOD_HEADER)
            keywords[wrong] = keywords.pop(right, 0)

            with self.subTest(keyword=wrong):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    with self.assertRaises(UnsupportedCall) as context:
                        TCP(**keywords)

                message = str(context.exception)
                self.assertIn('TCP', message)
                self.assertIn(repr(wrong), message)
                # The exception is the whole signal; nothing is also warned.
                self.assertEqual([str(item.message) for item in caught], [])

    def test_the_correct_spelling_still_builds_the_segment_it_describes(self) -> None:
        """The check rejects only what it should.

        A rejection test on its own is satisfied by a check that rejects
        everything, which would be a far worse defect than the one being fixed.
        This is the other half: the same header, spelled correctly, still
        produces the octets :rfc:`9293` puts at those offsets.

        """
        from pcapkit.protocols.transport.tcp import TCP

        segment = TCP(**GOOD_HEADER)
        octets = bytes(segment)

        self.assertEqual(segment.info.seq, 1)
        self.assertEqual(octets[0:2], (50000).to_bytes(2, 'big'))
        self.assertEqual(octets[4:8], (1).to_bytes(4, 'big'))
        self.assertTrue(octets[13] & 0x02)

    def test_every_keyword_the_signature_declares_is_accepted(self) -> None:
        """No declared parameter of a real ``make`` is refused.

        Derived from :func:`inspect.signature` rather than from a list, so a
        parameter added to ``TCP.make`` tomorrow is covered without an edit here.
        A hand-written list is exactly the thing that would let the check drift
        into rejecting a legitimate keyword.

        """
        from pcapkit.protocols.protocol import _declared_keywords
        from pcapkit.protocols.transport.tcp import TCP

        accepted = _declared_keywords(TCP)
        for name, parameter in inspect.signature(TCP.make).parameters.items():
            # ``self`` is a parameter of the unbound function and never a keyword
            # a caller may pass, so the accepted set excludes it on purpose.
            if name == 'self' or parameter.kind not in (parameter.POSITIONAL_OR_KEYWORD,
                                                        parameter.KEYWORD_ONLY):
                continue
            with self.subTest(keyword=name):
                self.assertIn(name, accepted)

    def test_several_unexpected_keywords_are_all_reported(self) -> None:
        """The message names every offender, not just the first.

        A caller who has misspelled two keywords should learn both in one run,
        rather than fixing one and rediscovering the other.

        """
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall) as context:
            TCP(srcport=1, dstport=2, zzz_second=2, aaa_first=1)

        message = str(context.exception)
        self.assertIn(repr('aaa_first'), message)
        self.assertIn(repr('zzz_second'), message)
        # Sorted, so the message is the same however the caller ordered them.
        self.assertLess(message.index('aaa_first'), message.index('zzz_second'))

    def test_a_near_miss_is_named_in_the_message(self) -> None:
        """A misspelling one edit from a real parameter suggests it.

        The whole population this check exists for is typists, so the message
        carries the neighbour rather than making the caller open the signature.
        ``seq`` for ``seq_no`` is the exact case that cost #602 its fixture bytes.

        """
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall) as context:
            TCP(**{**GOOD_HEADER, 'seq': GOOD_HEADER['seq_no']})

        self.assertIn("did you mean 'seq_no'?", str(context.exception))

    def test_the_exception_is_the_one_the_library_already_uses(self) -> None:
        """``UnsupportedCall``, as for an unexpected *class* keyword.

        Not a new exception type: the library already answers "you passed a
        keyword I do not accept" with
        :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`, in five places with
        this exact message shape -- ``protocol.py:1064``,
        ``dumpkit/common.py:142``, ``foundation/reassembly/reassembly.py:580``,
        ``foundation/engines/engine.py:313`` and
        ``foundation/traceflow/traceflow.py:514``. Reusing it keeps one answer to
        one question rather than adding a second.

        The honest caveat, recorded so it is a decision rather than an oversight:
        all five of those reject a *class* keyword at ``__init_subclass__`` time,
        which is a narrower kind of "unexpected keyword" than a field value passed
        to a constructor. And ``UnsupportedCall`` carries :exc:`AttributeError`,
        where a reader expecting the stdlib's ``unexpected keyword argument`` would
        reach for :exc:`TypeError` -- and where an ``except AttributeError`` written
        for duck-typing could swallow this. Consistency with the five precedents was
        preferred to a sixth spelling of the same idea, but the trade is real.

        """
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import BaseError, UnsupportedCall

        with self.assertRaises(UnsupportedCall) as context:
            TCP(srcport=1, no_such_tcp_field=1)

        self.assertIsInstance(context.exception, BaseError)
        self.assertIsInstance(context.exception, AttributeError)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ForwardedKeywordTests(unittest.TestCase):
    """A keyword declared downstream of ``make`` is still accepted."""

    def test_hip_declares_extension_on_read_and_not_on_make(self) -> None:
        """The real asymmetry the check has to tolerate.

        :meth:`HIP.read <pcapkit.protocols.internet.hip.HIP.read>` declares
        ``extension``, :meth:`HIP.make <pcapkit.protocols.internet.hip.HIP.make>`
        does not, and :meth:`HIP.__post_init__
        <pcapkit.protocols.internet.hip.HIP.__post_init__>` forwards it to both --
        so ``examples/generators/options.py``'s ``_hip_build`` passing
        ``extension=True`` on the construction path is correct code that a check
        against ``make`` alone would have broken. Asserted from the signatures, so
        it fails if either side of the asymmetry moves.

        """
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.protocol import _declared_keywords

        def keywords(method: 'Any') -> 'set[str]':
            return {
                name for name, parameter in inspect.signature(method).parameters.items()
                if parameter.kind in (parameter.POSITIONAL_OR_KEYWORD,
                                      parameter.KEYWORD_ONLY)
            }

        self.assertIn('extension', keywords(HIP.read))
        self.assertNotIn('extension', keywords(HIP.make))
        self.assertIn('extension', _declared_keywords(HIP))

    def test_a_keyword_only_read_declares_is_accepted_end_to_end(self) -> None:
        """The same shape, constructed rather than inspected.

        HIP's own construction needs a valid parameter set and a matching
        version, which is a statement about HIP rather than about this check, so
        the end-to-end half is done on a protocol built for it. ``eggs`` is
        declared by ``read`` only, and the construction has to survive it.

        """
        def read(self, length: 'int | None' = None, *, eggs: 'int' = 0,
                 **kwargs: 'Any') -> 'Any':
            from pcapkit.corekit.protochain import ProtoChain
            from pcapkit.protocols.misc.null import NoPayload

            self._next = NoPayload()
            self._protos = ProtoChain(type(self), self.alias, basis=self._next.protochain)
            self.seen_eggs = eggs
            return type(self).__data__(value=eggs)

        protocol = _protocol_class(read=read)
        instance = protocol(spam=b'ab', eggs=7)

        self.assertEqual(instance.seen_eggs, 7)
        self.assertEqual(bytes(instance), b'ab')

    def test_keywords_declared_by_a_class_attribute_are_accepted(self) -> None:
        """``__keywords__`` covers a name read out of ``**kwargs``.

        Signatures cannot show a keyword a method reads with
        ``kwargs.get('spam')`` -- which :meth:`ESP.read
        <pcapkit.protocols.internet.esp.ESP.read>` does with ``packet``, and which
        a third-party protocol may do with anything. Such a protocol names the
        keyword on the class instead, so the check has an answer other than
        "break it". Opt-in per class, so it can only exempt a name whose author
        wrote it down.

        """
        def read(self, length: 'int | None' = None, **kwargs: 'Any') -> 'Any':
            from pcapkit.corekit.protochain import ProtoChain
            from pcapkit.protocols.misc.null import NoPayload

            self._next = NoPayload()
            self._protos = ProtoChain(type(self), self.alias, basis=self._next.protochain)
            self.seen_eggs = kwargs.get('eggs')
            return type(self).__data__(value=0)

        from pcapkit.utilities.exceptions import UnsupportedCall

        undeclared = _protocol_class(read=read)
        with self.assertRaises(UnsupportedCall):
            undeclared(spam=b'ab', eggs=7)

        declared = _protocol_class(read=read, __keywords__=frozenset({'eggs'}))
        self.assertEqual(declared(spam=b'ab', eggs=7).seen_eggs, 7)

    def test_a_subclass_inherits_the_declarations_of_its_parents(self) -> None:
        """The accepted set is the union over the MRO, not the most derived.

        A subclass that declares its own keyword and forwards the rest must not
        make its parent's keywords unreachable, and a subclass that declares
        nothing must not lose its parent's ``__keywords__``.

        """
        from pcapkit.protocols.protocol import _declared_keywords

        parent = _protocol_class(__keywords__=frozenset({'eggs'}))

        class Child(parent):  # type: ignore[misc,valid-type]
            __keywords__ = frozenset({'beans'})

            def make(self, ham: 'bytes' = b'ab', **kwargs: 'Any') -> 'Any':
                return type(self).__schema__(payload=ham)

        accepted = _declared_keywords(Child)
        for name in ('eggs', 'beans', 'ham', 'spam'):
            with self.subTest(keyword=name):
                self.assertIn(name, accepted)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ScopeTests(unittest.TestCase):
    """What the check deliberately leaves alone."""

    def test_the_parse_path_is_unaffected(self) -> None:
        """Dissection still tolerates a keyword nothing declares.

        The engines and every ``_import_next_layer`` forward ``alias``,
        ``packet`` and the parse limits down a chain whose members cannot know
        what their parents chose to pass on, so rejecting there would break
        dissection rather than catch a misspelling -- and nothing is lost either
        way, because a dropped parse keyword changes how a packet is read, not
        what its octets say.

        """
        from pcapkit.protocols.transport.tcp import TCP

        octets = bytes(TCP(**GOOD_HEADER))
        parsed = TCP(io.BytesIO(octets), len(octets),
                     no_such_field=1, alias='whatever')

        self.assertEqual(parsed.info.seq, 1)
        self.assertEqual(parsed.info.srcport.port, 50000)

    def test_a_direct_make_call_is_not_checked(self) -> None:
        """The limitation, recorded rather than left to be discovered.

        The check sits in :meth:`ProtocolBase.__init__
        <pcapkit.protocols.protocol.ProtocolBase.__init__>`, where every producer's
        keywords converge, so ``SomeProtocol(...)`` is covered and a *direct*
        ``SomeProtocol.make(...)`` is not: it still absorbs an undeclared keyword
        and discards it. ``object.__new__(cls).make(**kwargs)`` is the idiom that
        reaches it -- used by several modules of this suite, and by
        :meth:`HTTP.make <pcapkit.protocols.application.http.HTTP.make>` itself to
        reach its versioned implementation.

        Closing it would mean interposing on each of the thirty ``make``
        implementations rather than on the one place their keywords meet, which is
        a larger change than #617. Written down here because the alternative is
        somebody inferring from the docstrings that ``make`` validates, and because
        if the gap is ever closed this test goes red and gets deleted.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4

        bare = object.__new__(IPv4)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            schema = bare.make(offst=5, protocl=6, payload=b'\xaa' * 8)

        # Both keywords are misspellings -- ``offset`` and ``protocol`` -- and both
        # go the way they always did: absorbed, dropped, nothing said.
        self.assertFalse(hasattr(schema, 'offst'))
        self.assertEqual([str(item.message) for item in caught], [])

    def test_out_of_band_keywords_are_accepted_while_constructing(self) -> None:
        """The keywords that configure the call rather than naming a field.

        ``_layer``, ``_protocol``, ``__context__`` and ``__packet__`` are
        consumed by :meth:`ProtocolBase.__init__
        <pcapkit.protocols.protocol.ProtocolBase.__init__>` or by the schema
        layer, so no ``make`` declares them and the check has to know them by
        name. A regression here would refuse a caller that is setting a parse
        limit on something it is constructing.

        ``packet`` is the fifth, and is there for a different reason -- see
        :meth:`test_from_data_survives_the_injected_packet_keyword`.

        """
        from pcapkit.protocols.protocol import OUT_OF_BAND_KEYWORDS
        from pcapkit.protocols.transport.tcp import TCP

        segment = TCP(**GOOD_HEADER, _layer='Internet', _protocol='tcp',
                      __context__=None, __packet__={})

        self.assertEqual(segment.info.seq, 1)
        self.assertEqual(segment._exlayer, 'Internet')
        self.assertEqual(
            OUT_OF_BAND_KEYWORDS,
            frozenset({'_layer', '_protocol', '__context__', '__packet__', 'packet'}))

    def test_from_data_survives_the_injected_packet_keyword(self) -> None:
        """Rebuilding a parsed packet is not a caller misspelling something.

        :meth:`ProtocolBase.__init__ <pcapkit.protocols.protocol.ProtocolBase.__init__>`
        injects ``packet=self.packet.payload`` into every parsed ``_info``, and the
        default :meth:`ProtocolBase._make_data
        <pcapkit.protocols.protocol.ProtocolBase._make_data>` is ``data.to_dict()``
        -- so ``from_data`` hands ``packet`` to a ``make`` that very often does not
        declare it. :class:`~pcapkit.protocols.misc.null.NoPayload` is the case
        that matters, because :meth:`ProtocolBase._make_payload
        <pcapkit.protocols.protocol.ProtocolBase._make_payload>` reaches it for the
        innermost layer of every packet: refusing ``packet`` broke ``from_data``
        for all of them. Measured before ``packet`` was made out-of-band::

            UnsupportedCall: NoPayload: unexpected keyword(s): 'packet'

        What is asserted is that the rebuild happens at all. Whether it reproduces
        the original octets is a separate question about ``from_data``'s fidelity,
        which this change neither improves nor worsens.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4

        octets = bytes(IPv4(src='127.0.0.1', dst='127.0.0.2'))
        parsed = IPv4(io.BytesIO(octets), len(octets))
        rebuilt = IPv4.from_data(parsed.info)

        self.assertIsInstance(rebuilt, IPv4)
        self.assertEqual(rebuilt.info.src, parsed.info.src)
        self.assertEqual(rebuilt.info.dst, parsed.info.dst)

    def test_a_dispatcher_may_decline_the_check(self) -> None:
        """``__keywords__ = None`` skips it, for a protocol that cannot enumerate.

        :meth:`HTTP.make <pcapkit.protocols.application.http.HTTP.make>` declares
        only ``version`` and forwards every other keyword to
        :class:`HTTPv1 <pcapkit.protocols.application.httpv1.HTTP>` or
        :class:`HTTPv2 <pcapkit.protocols.application.httpv2.HTTP>` according to
        that value, so no fixed set of names is correct for it. Measured before the
        opt-out existed::

            UnsupportedCall: HTTP: unexpected keyword(s): 'http_version', 'method', 'uri'

        Asserted through the real class rather than a dummy, because the point is
        that this one protocol declines and the rest do not. The construction still
        fails, with :exc:`~pcapkit.utilities.exceptions.ProtocolError` from
        ``HTTPv1.make`` itself -- which is the outcome
        :meth:`HTTPUnitTests.test_http_construction_reaches_the_versioned_make_callee`
        already pins, and is the proof that the keywords reached the delegate
        rather than being refused on the way.

        """
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.protocols.protocol import _declared_keywords
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        self.assertIsNone(_declared_keywords(HTTP))
        self.assertIsNotNone(_declared_keywords(TCP))

        # The opt-out is not inherited. Both versioned classes declare their
        # keywords in full, and exempting them along with their base would forgo
        # the check on the only two HTTP classes that can carry it -- which is what
        # happened on the first attempt at this, measured before the ``klass is
        # cls`` guard: every HTTP subclass came back unchecked.
        for versioned, keyword in ((HTTPv1, 'http_version'), (HTTPv2, 'sid')):
            with self.subTest(protocol=versioned.__module__):
                accepted = _declared_keywords(versioned)
                self.assertIsNotNone(accepted)
                self.assertIn(keyword, accepted)

        with self.assertRaises(ProtocolError) as context:
            HTTP(version=1, http_version='1.1', method='GET', uri='/')
        self.assertEqual(str(context.exception), 'HTTP/1: invalid format')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ReconstructionTests(unittest.TestCase):
    """``from_data`` warns where a caller would be raised at, and why."""

    def test_from_data_warns_instead_of_raising(self) -> None:
        """A ``_make_data`` key the signature does not take is audible, not fatal.

        :meth:`ProtocolBase.from_data <pcapkit.protocols.protocol.ProtocolBase.from_data>`
        spreads whatever :meth:`ProtocolBase._make_data
        <pcapkit.protocols.protocol.ProtocolBase._make_data>` returned into
        ``__init__``, so nobody typed those keywords: a mismatch is a defect in the
        protocol's own pair of mappings, and the caller who meets it cannot fix it.
        Raising there would also convert three latent defects of that shape into a
        broken ``from_data`` -- see
        :meth:`test_the_three_known_make_data_mismatches_are_recorded`.

        ``L2TPv2`` is used because it is one of the three and therefore exercises
        the real path rather than a contrived one. When its ``_make_data`` is fixed
        this test goes red, which is the point: the entry is then deleted.

        """
        from pcapkit.protocols.link.l2tpv2 import L2TPv2
        from pcapkit.utilities.warnings import UnknownFieldWarning

        octets = bytes(L2TPv2(version=2, tunnel_id=1, session_id=2, payload=b'ab'))
        parsed = L2TPv2(io.BytesIO(octets), len(octets))

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            rebuilt = L2TPv2.from_data(parsed.info)

        self.assertIsInstance(rebuilt, L2TPv2)
        messages = [item for item in caught
                    if isinstance(item.message, UnknownFieldWarning)]
        self.assertEqual(len(messages), 1, [str(item.message) for item in caught])
        self.assertIn("'prio'", str(messages[0].message))
        self.assertIn('_make_data', str(messages[0].message))

    def test_the_three_known_make_data_mismatches_are_recorded(self) -> None:
        """The latent defects this check made visible, named so they can be fixed.

        Each of these has ``_make_data`` returning a key that no signature of the
        same protocol declares, so :meth:`ProtocolBase.from_data
        <pcapkit.protocols.protocol.ProtocolBase.from_data>` has been dropping that
        field in silence -- a frame's timestamp, an L2TPv2 priority bit, and a
        capture's byte order. They are recorded rather than fixed here because each
        is a defect in its own protocol rather than in this mechanism, and because
        two of them need a decision about what ``make`` should be called rather than
        a rename.

        Written as an expected-failure table for the reason the round-trip module
        writes its own that way: fixing one of these turns this red and the entry
        gets deleted, where a silent skip would leave the defect recorded forever.

        """
        from pcapkit.protocols.link.l2tpv2 import L2TPv2
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.protocols.protocol import _declared_keywords

        # protocol -> the ``_make_data`` key it returns that nothing declares
        recorded = {Frame: 'ts_src', L2TPv2: 'prio', Header: 'magic_number'}

        for protocol, key in recorded.items():
            with self.subTest(protocol=protocol.__name__):
                accepted = _declared_keywords(protocol)
                self.assertIsNotNone(accepted)
                self.assertNotIn(key, accepted, (
                    f'{protocol.__name__} now declares {key!r}, so its _make_data '
                    f'mismatch is fixed -- delete this entry'
                ))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class AsymmetryTests(unittest.TestCase):
    """The two layers, and what each now does with a name it does not know."""

    def test_the_schema_layer_still_warns_where_construction_now_raises(self) -> None:
        """One unknown name, two layers, both of them audible.

        This is the asymmetry #617 reported, asserted from both ends so that it
        cannot drift apart again unnoticed. The schema keeps warning rather than
        raising: :meth:`Schema.__update__
        <pcapkit.protocols.schema.schema.Schema.__update__>` is the constructor of
        every schema in the tree and runs on the parse path too, so tightening it
        is a separate change with a far wider blast radius -- deliberately out of
        scope here, and recorded as such.

        """
        from pcapkit.protocols.schema.transport.tcp import TCP as Schema_TCP
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import UnsupportedCall
        from pcapkit.utilities.warnings import UnknownFieldWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            Schema_TCP(srcport=1, dstport=2, no_such_field=3)

        self.assertEqual([type(item.message) for item in caught], [UnknownFieldWarning])
        self.assertIn('not a valid field name', str(caught[0].message))

        with self.assertRaises(UnsupportedCall):
            TCP(srcport=1, dstport=2, no_such_field=3)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SentinelTests(unittest.TestCase):
    """The absent-key marker is an instance of a named class, not a bare object.

    :func:`~pcapkit.protocols.protocol._declared_keywords` has to tell three
    answers apart when it reads ``__keywords__`` out of a class
    :attr:`~object.__dict__`: a set of names, the :obj:`None` that declines the
    check, and the key not being there at all. :obj:`None` is taken by the second
    of those -- :attr:`ProtocolBase.__keywords__
    <pcapkit.protocols.protocol.ProtocolBase.__keywords__>` is typed
    ``Optional[frozenset[str]]`` and :class:`~pcapkit.protocols.application.http.HTTP`
    sets it -- so the third needs a marker of its own.

    That marker is :data:`~pcapkit.protocols.protocol._Absent`, an instance of
    :class:`~pcapkit.protocols.protocol._AbsentType` following
    :class:`~pcapkit.corekit.fields.field.NoValueType`, which is how this library
    already spells a singleton marker. It was a bare ``object()`` when #640 was
    first raised; a bare ``object()`` has no name in a traceback, no informative
    :func:`repr`, and no type a checker can hold anyone to.

    The four tests here split two and two, and the split is worth knowing before
    reading them:

    :meth:`test_the_absent_marker_is_an_instance_of_its_own_type` and
    :meth:`test_the_absent_marker_cannot_be_confused_with_another_singleton`
        pin the marker's *shape*. Both name ``_Absent``, so on the bare
        ``object()`` they fail at the import -- which makes them a check that the
        rename happened, with the substance behind the gate.

    :meth:`test_the_absent_marker_never_reaches_the_accepted_names` and
    :meth:`test_the_three_answers_stay_distinct_across_the_swap`
        pin the *behaviour*, and **both pass on the bare** ``object()`` **too**.
        That is the point of them rather than a weakness: they are the evidence
        that the swap changed nothing, which a shape assertion cannot give. What
        they catch is the mistake this kind of swap actually makes -- comparing
        against a second instance of the right class, which reads correctly and
        typechecks -- measured by mutating the ``.get`` default to a fresh
        ``_AbsentType()``, at which point both fail with ``TypeError:
        '_AbsentType' object is not iterable`` from ``names.update(keywords)``
        while both shape tests pass through the mutation unharmed.

    So neither pair is sufficient alone: the first pair cannot tell a correct
    marker from a correctly-named broken one, and the second cannot tell
    ``object()`` from a typed singleton.

    """

    def test_the_absent_marker_is_an_instance_of_its_own_type(self) -> None:
        """It has a type of its own, and the falsiness the convention carries."""
        from pcapkit.corekit.fields.field import NoValue, NoValueType
        from pcapkit.protocols.protocol import _Absent, _AbsentType

        self.assertIsInstance(_Absent, _AbsentType)

        # The point of #640's review comment: ``type(object())`` is ``object``,
        # which says nothing about what the value is for.
        self.assertIsNot(type(_Absent), object)

        # Falsy, exactly as ``NoValue`` is.
        self.assertFalse(_Absent)
        self.assertFalse(NoValue)

        # And ``@final``. ``typing.final`` only records ``__final__`` on the
        # decorated class from 3.11 on, and 3.10 is in the CI matrix, so the two
        # cases are spelled out rather than folded into one ``getattr`` comparison
        # of two defaults -- that form reads as an assertion but degrades to
        # ``None == None`` below 3.11, passing whether or not either class is
        # decorated at all. ``NoValueType`` is the probe for which case this is,
        # so the two classes cannot drift apart either way.
        if hasattr(NoValueType, '__final__'):
            self.assertIs(_AbsentType.__final__, True)  # type: ignore[attr-defined]
        else:  # pragma: no cover
            self.assertFalse(hasattr(_AbsentType, '__final__'))

        # A bare ``object()`` reads as ``<object object at 0x...>``.
        self.assertEqual(repr(_Absent), '<absent>')

    def test_the_absent_marker_cannot_be_confused_with_another_singleton(self) -> None:
        """No other singleton in the library answers an ``is`` against it.

        :data:`~pcapkit.corekit.fields.field.NoValue` is the near neighbour and
        the one deliberately *not* reused here: it is documented as the default
        value of :attr:`FieldBase.default
        <pcapkit.corekit.fields.field.FieldBase.default>` and means "no value was
        given", where this one means "this key is not here". Sharing an instance
        between the two would make either site's marker satisfy the other's test.

        """
        from pcapkit.corekit.fields.field import NoValue, NoValueType
        from pcapkit.protocols.protocol import _Absent, _AbsentType

        self.assertIsNot(_Absent, NoValue)
        self.assertNotIsInstance(_Absent, NoValueType)
        self.assertNotIsInstance(NoValue, _AbsentType)

        # Nor does it compare *equal* to any of them: neither class defines
        # ``__eq__``, so identity is the only way either is ever true, and this
        # says so rather than leaving it to be assumed.
        for other in (None, NotImplemented, Ellipsis, NoValue, object(), frozenset(), ''):
            with self.subTest(other=type(other).__name__):
                self.assertIsNot(_Absent, other)
                self.assertFalse(_Absent == other)

    def test_the_absent_marker_never_reaches_the_accepted_names(self) -> None:
        """A class with no ``__keywords__`` anywhere in its MRO still reads clean.

        The failure mode this pins is an identity comparison against the wrong
        singleton: the marker then falls through to ``names.update(keywords)``,
        which raises :exc:`TypeError` because it is not iterable, or -- worse, if
        it ever were -- lands in the accepted set as a member that is not a
        keyword name at all. Asserted against a plain class rather than a
        protocol, because :class:`~pcapkit.protocols.protocol.ProtocolBase`
        declares ``__keywords__`` itself, so no protocol ever reaches the branch
        with the whole MRO silent.

        """
        from pcapkit.protocols.protocol import OUT_OF_BAND_KEYWORDS, _declared_keywords

        class Bare:
            """No ``__keywords__``, so every class in the MRO takes the absent branch."""

            def make(self, spam: 'int' = 0, **kwargs: 'Any') -> 'None':
                """Declare one keyword, so the result is not merely empty."""

        self.assertNotIn('__keywords__', Bare.__dict__)
        self.assertNotIn('__keywords__', object.__dict__)

        declared = _declared_keywords(Bare)

        self.assertIsNotNone(declared)
        self.assertIn('spam', declared)
        self.assertTrue(OUT_OF_BAND_KEYWORDS <= declared)
        self.assertEqual([name for name in declared if not isinstance(name, str)], [])

    def test_the_three_answers_stay_distinct_across_the_swap(self) -> None:
        """Absent, :obj:`None`, and a declared set are still three outcomes.

        A marker that is falsy -- which this one is, following the convention --
        would be read as an opt-out by any ``if not keywords`` written later, and
        an empty ``frozenset()`` is the value that makes the two
        indistinguishable under truthiness while staying distinct under ``is``.
        So the empty set is checked alongside the populated one.

        """
        from pcapkit.protocols.protocol import _declared_keywords

        # Declined: the class names ``None`` itself.
        self.assertIsNone(_declared_keywords(_protocol_class(__keywords__=None)))

        # Declared, and falsy. Still checked, and ``spam`` still comes off ``make``.
        empty = _declared_keywords(_protocol_class(__keywords__=frozenset()))
        self.assertIsNotNone(empty)
        self.assertIn('spam', empty)

        # Declared and populated, and inherited from neither of the above.
        named = _declared_keywords(_protocol_class(__keywords__=frozenset({'ham'})))
        self.assertIsNotNone(named)
        self.assertIn('ham', named)
        self.assertIn('spam', named)

        # Absent: nothing of its own, so it takes ``ProtocolBase``'s empty set.
        absent = _declared_keywords(_protocol_class())
        self.assertIsNotNone(absent)
        self.assertNotIn('ham', absent)
        self.assertIn('spam', absent)


if __name__ == '__main__':
    unittest.main()
