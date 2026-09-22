# -*- coding: utf-8 -*-
"""``TCP_BASE`` builds the segment it describes.

Every frame in :file:`examples/captures/options-tcp.pcap` is a TCP segment whose
header comes from :data:`examples.generators.options.TCP_BASE` and whose only
per-case difference is the one option it carries. So that mapping is the
description of twenty-five fixture frames, and a key it spells wrongly is a
description that does not match the octets.

Nothing warned when one did. :meth:`TCP.make
<pcapkit.protocols.transport.tcp.TCP.make>` ends its signature with
``**kwargs: 'Any'`` and never reads anything out of it, so a keyword it does not
declare is accepted, discarded, and the parameter it was meant to set keeps its
default. GitHub issue #602 is three such keys:

* ``'seq': 1`` for ``seq_no``, so every generated frame carried sequence number
  ``0`` while the table read as ``1``;
* ``'urgent_pointer': 0`` for ``urgent``, whose requested value and unused
  default happened to coincide;
* ``'ack_flag': False`` for ``ack`` -- while ``'ack': 0`` bound to ``ack``,
  which is the acknowledgement *flag*, not the acknowledgement number
  ``ack_no``. The pair was the wrong way round, and neither half said so.

Why the expected header is written out here
-------------------------------------------

:data:`EXPECTED_HEADER` repeats ``TCP_BASE``, which looks like duplication and
is the point. A test that reads its own expectations out of the mapping under
test cannot fail on a misspelled key -- it fails with :exc:`KeyError`, or worse
agrees with whatever the mapping happens to say. Spelling the intended header
out independently is what makes the failure read ``0 != 1``, which is the defect,
rather than ``KeyError: 'seq_no'``, which is a symptom of it.

It also gives the twenty-five fixture frames a stated contract. Changing
``TCP_BASE``'s values changes the bytes of ``options-tcp.pcap``, so it should
take two edits and a moment's thought, not one.

What each check is for
----------------------

:meth:`TCPBaseKeywordTests.test_every_key_is_a_parameter_make_declares`
    The check that generalises. It compares the keys against
    :func:`inspect.signature`, so it fails for a *fourth* misspelling nobody
    has made yet -- which a per-field assertion would not.

:meth:`TCPBaseHeaderTests.test_the_header_fields_are_the_ones_expected` and
:meth:`TCPBaseHeaderTests.test_the_header_octets_are_the_ones_expected`
    The data model and the wire, separately. The data model is what ``make``
    packed and :meth:`ProtocolBase.__post_init__
    <pcapkit.protocols.protocol.ProtocolBase.__post_init__>` parsed straight
    back, so a field wrong in both directions round-trips through it
    unnoticed; the octets are what the capture actually holds.

:meth:`TCPBaseHeaderTests.test_the_acknowledgement_flag_and_number_are_distinct`
    ``ack`` and ``ack_no`` are one letter apart, adjacent in the signature, and
    both falsy in ``TCP_BASE``, so swapping them back would change nothing
    anything else here could see. This sets them to values that cannot be
    confused.

This module is unit tier: it constructs its own octets and reads no capture, so
it runs on a fresh checkout with nothing generated.

"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import types
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The header every frame of :file:`examples/captures/options-tcp.pcap` has to
#: carry, keyed by the name :meth:`TCP.make
#: <pcapkit.protocols.transport.tcp.TCP.make>` declares for it. A SYN-only
#: segment from port 50000 to port 80, sequence number 1, everything else at
#: zero. Written out rather than read from ``TCP_BASE`` -- see the module
#: docstring for why that is deliberate.
EXPECTED_HEADER = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack': False,
    'psh': False, 'rst': False, 'syn': True, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}

#: Each integer header field, as ``(keyword, octet offset, octet width)`` within
#: a TCP header. :rfc:`9293` section 3.1.
WIRE_INTEGERS = (
    ('srcport', 0, 2),
    ('dstport', 2, 2),
    ('seq_no', 4, 4),
    ('ack_no', 8, 4),
    ('window', 14, 2),
    ('urgent', 18, 2),
)

#: Offset and width of the checksum, which is the one header field ``TCP_BASE``
#: gives as :obj:`bytes` rather than as an :obj:`int`.
CHECKSUM_OFFSET, CHECKSUM_WIDTH = 16, 2

#: Each flag ``make`` takes, as ``(keyword, octet offset, bit mask)``. From
#: :rfc:`9293` section 3.1 and :rfc:`3540` section 4: octet 12 is the four-bit
#: data offset, three reserved bits and then ``NS``, so the nonce bit is the
#: *low* bit of that octet rather than a ninth bit of octet 13.
FLAG_BITS = (
    ('ns', 12, 0x01),
    ('cwr', 13, 0x80),
    ('ece', 13, 0x40),
    ('urg', 13, 0x20),
    ('ack', 13, 0x10),
    ('psh', 13, 0x08),
    ('rst', 13, 0x04),
    ('syn', 13, 0x02),
    ('fin', 13, 0x01),
)

#: ``make`` keyword -> the attribute the parsed data model reports it as, for
#: the fields whose two names differ.
DATA_MODEL_NAMES = {
    'seq_no': 'seq',
    'ack_no': 'ack',
    'window': 'window_size',
    'urgent': 'urgent_pointer',
}


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/options.py` by path.

    That directory is not a package and its module names are too generic to put
    on :data:`sys.path`, which is why :file:`examples/generators/make_samples.py`
    and :file:`tests/protocols/test_option_roundtrip_unit.py` both load it by
    path. This follows them, under a module name of its own so that loading it
    here does not displace the copy either of those holds.

    Returns:
        The generator module, which exposes ``TCP_BASE``.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'options.py'
    spec = importlib.util.spec_from_file_location(
        'pcapkit_samples_options_tcp_base', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the option generator from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPBaseKeywordTests(unittest.TestCase):
    """``TCP_BASE``'s keys, against the signature that has to accept them."""

    def test_every_key_is_a_parameter_make_declares(self) -> None:
        """No key relies on ``**kwargs`` swallowing it.

        The invariant with no judgement in it: a key that is not a declared
        parameter is a key whose value is discarded, because ``make`` reads
        nothing out of ``kwargs``. Deriving the expected set from
        :func:`inspect.signature` rather than listing it is what makes this
        catch a misspelling introduced tomorrow.

        """
        from pcapkit.protocols.transport.tcp import TCP

        options = _load_generator()
        signature = inspect.signature(TCP.make)
        declared = {
            name for name, parameter in signature.parameters.items()
            if parameter.kind in (parameter.POSITIONAL_OR_KEYWORD,
                                  parameter.KEYWORD_ONLY)
        }

        undeclared = sorted(set(options.TCP_BASE) - declared)
        self.assertEqual(undeclared, [], (
            f'TCP_BASE passes {undeclared} to TCP.make, which does not declare '
            f'them; they are absorbed by **kwargs and silently dropped, so the '
            f'fields they name keep their defaults'
        ))

    def test_nothing_downstream_of_make_could_have_read_the_leftovers(self) -> None:
        """``TCP``'s parse path declares no header keyword either.

        The check above would be too strict for a protocol that legitimately
        forwards a keyword through ``**kwargs`` to something that *does* declare
        it -- which this library does, and documents: the same generator hands
        ``extension=True`` to ``HIP``, where :meth:`HIP.read
        <pcapkit.protocols.internet.hip.HIP.read>` declares it even though
        ``HIP.make`` does not. ``TCP`` is not such a protocol. ``TCP.read`` takes
        ``length`` and ``**kwargs`` and reads nothing out of the latter, so for
        ``TCP`` a keyword ``make`` does not declare is a keyword nothing at all
        consumes, and the rule above is exactly right rather than merely tidy.

        """
        from pcapkit.protocols.transport.tcp import TCP

        declared = {
            name for name, parameter in inspect.signature(TCP.read).parameters.items()
            if parameter.kind in (parameter.POSITIONAL_OR_KEYWORD,
                                 parameter.KEYWORD_ONLY)
        }

        self.assertEqual(declared - {'self'}, {'length'})

    def test_tcp_base_is_the_expected_header(self) -> None:
        """The mapping is the header this module says the fixtures carry.

        The two are maintained side by side on purpose. This is the assertion
        that fails when somebody edits one of them, which is the reminder that
        twenty-five captured frames change with it.

        """
        options = _load_generator()
        self.assertEqual(dict(options.TCP_BASE), EXPECTED_HEADER)

    def test_make_still_has_the_kwargs_that_hid_the_defect(self) -> None:
        """``make`` really does absorb an undeclared keyword without complaint.

        Without this, the check above looks like a style rule. It is not: the
        reason a misspelling cost twenty-five wrong fixture frames instead of a
        :exc:`TypeError` is the ``**kwargs`` at the end of the signature, and
        that nothing ever inspects it. Recording the behaviour here means a
        change to it -- ``make`` starting to reject or warn about the leftovers,
        as :class:`~pcapkit.protocols.schema.schema.Schema` construction already
        warns about an unknown field -- turns this red rather than passing
        silently.

        """
        from pcapkit.protocols.transport.tcp import TCP

        signature = inspect.signature(TCP.make)
        self.assertTrue(
            any(parameter.kind is parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()),
            'TCP.make no longer takes **kwargs, so an undeclared keyword would '
            'raise instead of being dropped',
        )

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            TCP(srcport=50000, dstport=80, no_such_tcp_field=12345)

        self.assertEqual([str(warning.message) for warning in caught], [])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPBaseHeaderTests(unittest.TestCase):
    """The segment ``TCP_BASE`` builds carries the header it states."""

    #: The generator module, loaded once for the class.
    options = None  # type: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.options = _load_generator()

    def _build(self, **overrides: 'Any') -> 'Any':
        """A TCP segment from ``TCP_BASE``, with ``overrides`` merged over it.

        Args:
            **overrides: Header keywords replacing the ones in ``TCP_BASE``.

        Returns:
            The constructed :class:`~pcapkit.protocols.transport.tcp.TCP`.

        """
        from pcapkit.protocols.transport.tcp import TCP

        return TCP(**{**self.options.TCP_BASE, **overrides})

    def test_the_header_fields_are_the_ones_expected(self) -> None:
        """Every value the mapping states reaches the field it names.

        ``seq`` is the one that moved: the mapping read as ``1`` and the segment
        reported ``0``. The rest are asserted alongside it because a fixture
        header nobody has checked is a fixture header that could differ
        anywhere.

        """
        info = self._build().info
        flags = {name for name, _, _ in FLAG_BITS}

        for keyword, value in EXPECTED_HEADER.items():
            # The flags are checked on the wire instead, since ``ns`` is not in
            # the data model; ``payload`` is the segment's contents rather than
            # a header field, and is empty here.
            if keyword in flags or keyword == 'payload':
                continue
            attribute = DATA_MODEL_NAMES.get(keyword, keyword)
            with self.subTest(field=keyword):
                reported = getattr(info, attribute)
                if keyword in ('srcport', 'dstport'):
                    # Reported as an ``AppType`` member, whose ``value`` is the
                    # rendered service string -- the port number is ``port``.
                    reported = reported.port
                self.assertEqual(reported, value)

    def test_the_header_octets_are_the_ones_expected(self) -> None:
        """The octets a fixture frame is built from carry the stated header.

        The check above reads the data model, which is what ``make`` packed and
        ``__post_init__`` parsed straight back -- so a field wrong in both
        directions survives it. This reads the offsets :rfc:`9293` puts each
        field at.

        """
        octets = bytes(self._build())

        for keyword, offset, width in WIRE_INTEGERS:
            with self.subTest(field=keyword):
                self.assertEqual(
                    octets[offset:offset + width],
                    int(EXPECTED_HEADER[keyword]).to_bytes(width, 'big'))

        self.assertEqual(
            octets[CHECKSUM_OFFSET:CHECKSUM_OFFSET + CHECKSUM_WIDTH],
            EXPECTED_HEADER['checksum'])

    def test_the_flag_bits_are_the_ones_expected(self) -> None:
        """Each flag keyword reaches the flag of that name.

        ``syn`` is the only one set, so the interesting half of this is the
        eight that are not: a flag keyword bound to the wrong field would leave
        ``syn`` right and one of the others wrong.

        The bits are read off the octets rather than off ``info.flags`` because
        ``ns`` is not in the data model at all --
        :class:`~pcapkit.protocols.data.transport.tcp.Flags` has its ``ns``
        declaration commented out, and the schema keeps the bit in ``offset``
        rather than beside the other eight. Going to the wire covers all nine
        without depending on that split.

        """
        octets = bytes(self._build())

        for keyword, offset, mask in FLAG_BITS:
            with self.subTest(flag=keyword):
                self.assertEqual(bool(octets[offset] & mask),
                                 EXPECTED_HEADER[keyword])

    def test_the_data_model_agrees_with_the_wire_on_the_flags_it_has(self) -> None:
        """The eight flags the data model does carry match the octets.

        Cheap, and it stops the check above from being the only statement about
        the flags: were the wire bits right and the accessors wrong, the fixture
        would still be a segment nothing could read back correctly.

        """
        segment = self._build()
        octets = bytes(segment)
        flags = segment.info.flags

        for keyword, offset, mask in FLAG_BITS:
            if keyword == 'ns':
                continue
            with self.subTest(flag=keyword):
                self.assertEqual(bool(getattr(flags, keyword)),
                                 bool(octets[offset] & mask))

    def test_the_acknowledgement_flag_and_number_are_distinct(self) -> None:
        """``ack`` is the flag and ``ack_no`` is the number, not the reverse.

        Both are falsy in ``TCP_BASE``, so nothing else here would notice them
        swapped back. Setting them to values that cannot be confused is what
        pins which is which.

        """
        segment = self._build(ack=True, ack_no=0xDEADBEEF)
        octets = bytes(segment)

        self.assertTrue(segment.info.flags.ack)
        self.assertEqual(segment.info.ack, 0xDEADBEEF)
        self.assertEqual(octets[8:12], b'\xde\xad\xbe\xef')
        self.assertTrue(octets[13] & 0x10)


if __name__ == '__main__':
    unittest.main()
