# -*- coding: utf-8 -*-
"""Byte-identity proof for GitHub issue #730, across the classic-PCAP sample captures.

:mod:`tests.corekit.test_fields_copy_dispatch_unit` proves the *mechanism* the
issue asked about: every field ``__call__`` now reaches
:meth:`~pcapkit.corekit.fields.field.FieldBase.__copy__` directly instead of
going through :func:`copy.copy`. This module proves the thing that actually
matters -- that swapping the dispatch did not move a single byte of what
:func:`~pcapkit.interface.core.extract` produces.

Every field of every protocol is copied through one of the eight call sites
#730 named, once per field per packet, so a mistake in any of them is not
confined to one protocol -- it is exactly the kind of change that wants a
broad, mechanical check rather than a handful of hand-picked assertions. Each
capture below is walked record by record using the classic-PCAP framing
itself -- a 24-octet global header, then any number of 16-octet record
headers each followed by ``incl_len`` octets of captured data -- and every
record's repack, ``bytes(frame)``, is compared against the *original file's
own bytes* at that exact offset. There is no golden/expected value baked into
this module to fall out of step with anything: the ground truth is the sample
capture itself, read directly with :func:`open`, independently of whatever
:func:`~pcapkit.interface.core.extract` makes of it.

PCAP-NG is deliberately out of scope here: its block framing is not a fixed
16-octet record header, so the same offset walk does not apply, and its own
round-trip fidelity is already covered by
:mod:`tests.protocols.test_pcapng_regression`. The field ``__call__`` change
this module guards is format-agnostic -- every field, in every schema, of
every protocol, in every container format, goes through one of the same eight
call sites -- so classic PCAP alone already exercises the mechanism; a
passing run of the existing PCAP-NG suite (unaffected by this change) is the
rest of the proof.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Every classic-PCAP sample capture this module checks. ``in.pcap`` is the one
#: git tracks; the rest are built by :file:`examples/generators/make_samples.py`
#: and read through :func:`~tests._support.sample_path`, which is why this
#: module is a ``_runtime.py`` -- the fixture-dependent tier that may read them
#: freely, rather than the unit tier that may not (see :mod:`tests._tiers`).
#: ``http.pcap`` is #730's own reproduction capture; the rest span the other
#: byte orders, timestamp resolutions and protocol families the library reads.
CLASSIC_PCAP_CAPTURES = (
    'in.pcap',
    'http.pcap',
    'arp.pcap',
    'tcp.pcap',
    'ipv4.pcap',
    'ipv6.pcap',
    'stream.pcap',
    'test.pcap',
    'http6.cap',
    'big_endian.pcap',
    'little_endian.pcap',
    'big_endian_nanosecond.pcap',
    'options-internet.pcap',
    'options-ipv4.pcap',
    'options-ipv6.pcap',
    'options-tcp.pcap',
    'options-transport.pcap',
)

#: Octets in a classic-PCAP global header, before the first record.
_GLOBAL_HEADER_LENGTH = 24
#: Octets in a classic-PCAP record header, before that record's captured data.
_RECORD_HEADER_LENGTH = 16


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FieldCopyDispatchByteIdentityTests(unittest.TestCase):
    """``bytes(frame) == <the file's own bytes at that offset>``, for every record.

    Deliberately does not re-derive ``incl_len`` independently -- that is
    exactly what :mod:`tests.protocols.misc.pcap.test_frame_endian_runtime`
    already does, by unpacking the record header with :mod:`struct` ahead of
    the parser and comparing. Here each record's own reported ``incl_len``
    both selects the slice it is compared against *and* advances to the next
    record, so a field that misreports its own length is caught the same way
    a field that mis-repacks its value is: either way, the walk stops lining
    up with the file's real record boundaries and the running-total assertion
    at the end of :meth:`assertCaptureRoundTripsByteForByte` catches it.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def assertCaptureRoundTripsByteForByte(self, name: str) -> None:
        """Walk every record of ``name`` and compare its repack to the file's own bytes.

        Args:
            name: Bare sample-capture file name, resolved through
                :func:`~tests._support.sample_path`.

        """
        from pcapkit.interface import extract

        path = sample_path(name)
        with open(path, 'rb') as stream:
            raw = stream.read()

        extractor = extract(fin=path, store=True, nofile=True, engine='default')
        frames = list(extractor.frame)

        self.assertGreater(len(frames), 0, f'{name} produced no frames at all')

        offset = _GLOBAL_HEADER_LENGTH
        for frame in frames:
            with self.subTest(capture=name, frame=frame.info.number):
                incl_len = frame.info.frame_info.incl_len
                record_end = offset + _RECORD_HEADER_LENGTH + incl_len

                self.assertEqual(
                    bytes(frame), raw[offset:record_end],
                    f'{name} frame {frame.info.number} repacked differently from the '
                    f'capture\'s own bytes at offset {offset} -- see GitHub issue #730')
                offset = record_end

        # Every record accounted the whole file's own record-header-declared
        # length, not just some prefix of it -- a length a field under-reports
        # would still pass every per-frame comparison above and only show up
        # here, as bytes of the file no frame ever claimed.
        self.assertEqual(
            offset, len(raw),
            f'{name}: frames covered {offset} of {len(raw)} octets -- the last records '
            f'were never compared at all')

    def test_every_classic_pcap_sample_round_trips_byte_for_byte(self) -> None:
        for name in CLASSIC_PCAP_CAPTURES:
            with self.subTest(capture=name):
                try:
                    self.assertCaptureRoundTripsByteForByte(name)
                except FileNotFoundError as exc:
                    self.skipTest(str(exc))


if __name__ == '__main__':
    unittest.main()
