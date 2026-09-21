# -*- coding: utf-8 -*-
"""The TCP SACK option's length constraint, which was documented but not checked.

GitHub issue #519 counted :meth:`TCP._read_mode_sack
<pcapkit.protocols.transport.tcp.TCP._read_mode_sack>` among its phantom
``Raises:`` clauses: the docstring promised ``ProtocolError: If length is
**NOT** multiply of 8 plus 2`` and the body contained no such check. The
tempting reading is that the clause was stale and should be deleted, which is
what the other five phantoms in that issue needed.

It was the opposite. The clause was right and the check was missing, and three
pieces of evidence settle it:

* :rfc:`2018` gives the SACK option a 2-octet header followed by 8-octet
  left/right edge pairs, so a well-formed option's length really is ``8n + 2``.
* The sibling readers validate their own lengths rather than delegating it.
  :meth:`TCP._read_mode_sackpmt
  <pcapkit.protocols.transport.tcp.TCP._read_mode_sackpmt>` -- the method
  immediately above this one -- raises on ``schema.length != 2``, and
  :meth:`TCP._read_mode_echo <pcapkit.protocols.transport.tcp.TCP._read_mode_echo>`
  on ``schema.length != 6``, both with the same message. ``_read_mode_sack``
  was the one option reader documenting a length rule it never enforced.
* Nothing upstream enforced it either. A segment carrying ``kind=5,
  length=11`` parsed clean before the fix: the schema field is
  ``ListField(length=lambda pkt: pkt['length'] - 2,
  item_type=SchemaField(length=8, schema=SACKBlock))``, and a remainder is
  simply not noticed. That is what :meth:`SACKLengthTests
  .test_invalid_sack_length_is_rejected` pins.

So this module is the behavioural half of the #519 work. The other half is
:file:`tests/test_docstring_contract.py`, which stops a docstring from drifting
away from the code again; this one stops the code from drifting away from
*this* docstring, which is the direction that actually lets a malformed packet
through.

:meth:`SACKLengthTests.test_invalid_sack_length_is_rejected` used to accept
either :exc:`~pcapkit.utilities.exceptions.ProtocolError` or
:exc:`~pcapkit.utilities.exceptions.FieldValueError`, because which one arrived
depended on process state rather than on the packet -- filed as #525. The root
cause was :meth:`ListField.unpack
<pcapkit.corekit.fields.collections.ListField.unpack>` resolving
:class:`~pcapkit.corekit.fields.misc.SchemaField` through a *function-local*
import on every call, instead of once at module load: ordinarily a cheap
:data:`sys.modules` hit, but a class that has been popped from
:data:`sys.modules` since this field was built (which is exactly what the
``#439`` ABC-cache regression tests do, in every case's ``setUp``/``tearDown``,
to get a clean cache between them) comes back as a second, distinct class on
the next call. ``isinstance(self._item_type, SchemaField)`` then answers
:data:`False` for an item that plainly is one, ``ListField.unpack`` bills it by
its declared length instead of by what it actually consumed, and *that* is what
let the length check go negative and raise
:exc:`~pcapkit.utilities.exceptions.FieldValueError` from
:mod:`pcapkit.corekit.fields.collections` before ``_read_mode_sack`` was ever
reached. Hoisting the import to module level in that fix closed it: the
exception is now always :exc:`~pcapkit.utilities.exceptions.ProtocolError`,
regardless of what ran earlier in the process, and the assertion below is
narrowed to match.
:meth:`SACKLengthTests.test_sack_exception_type_survives_a_sys_modules_purge`
pins the mechanism directly, by reproducing the exact
:data:`sys.modules` manipulation that used to flip it.

One deliberate limit, so a later reader does not think it an oversight: the
check implements exactly the rule the docstring states, ``(length - 2) % 8 ==
0``. :rfc:`2018` also wants at least one block and at most four, so ``length=2``
is degenerate and ``length=42`` is too long, and neither is rejected here.
Tightening past the documented contract would change what the parser accepts on
the strength of a test rather than of the specification it cites, so it is
recorded in :meth:`SACKLengthTests.test_documented_rule_is_the_implemented_rule`
instead of being quietly added.

Every case builds its own octets in memory and reads no capture under
:file:`examples/captures/`, so this belongs to the unit tier.

"""
from __future__ import annotations

import io
import sys
import unittest

from pcapkit.protocols.transport.tcp import TCP
from pcapkit.utilities.exceptions import ProtocolError

#: TCP option kind for SACK, per :rfc:`2018`.
SACK = 5
#: TCP option kind for a single-octet no-op, used to pad the options area out
#: to a 4-octet boundary so the data offset stays legal.
NOP = 1


def sack_option(length: 'int', payload: 'int') -> 'bytes':
    """A SACK option declaring ``length`` and carrying ``payload`` data octets.

    ``length`` and ``payload`` are set independently on purpose: the defect
    being pinned is a *declared* length that does not match the 8-octet block
    structure, so the test has to be able to declare one thing and supply
    another.

    """
    return bytes([SACK, length]) + bytes(payload)


def segment(option: 'bytes') -> 'bytes':
    """A minimal ACK segment whose options area is ``option``, NOP-padded."""
    while len(option) % 4:
        option += bytes([NOP])
    offset = (20 + len(option)) // 4
    header = (
        (1234).to_bytes(2, 'big')     # source port
        + (80).to_bytes(2, 'big')     # destination port
        + (0).to_bytes(4, 'big')      # sequence number
        + (0).to_bytes(4, 'big')      # acknowledgement number
        + bytes([offset << 4, 0x10])  # data offset, and ACK set
        + (8192).to_bytes(2, 'big')   # window
        + (0).to_bytes(2, 'big')      # checksum
        + (0).to_bytes(2, 'big')      # urgent pointer
    )
    return header + option


def parse(option: 'bytes') -> 'TCP':
    """Parse a segment carrying ``option``."""
    raw = segment(option)
    return TCP(io.BytesIO(raw), len(raw))


class SACKLengthTests(unittest.TestCase):
    """A SACK option's declared length against its block structure."""

    def test_valid_sack_lengths_are_accepted(self) -> 'None':
        """``8n + 2`` parses, for one through four blocks.

        The companion to the rejection test: a length rule enforced too
        eagerly would break every real SACK-bearing segment, so the accepted
        cases are pinned as tightly as the rejected ones.

        """
        for blocks in range(1, 5):
            length = 2 + 8 * blocks
            with self.subTest(blocks=blocks, length=length):
                tcp = parse(sack_option(length, 8 * blocks))
                self.assertIn(SACK, [int(key) for key in tcp.info['options']])

    def test_invalid_sack_length_is_rejected(self) -> 'None':
        """A length that is not ``8n + 2`` is rejected.

        Every one of these parsed without complaint before the #519 check was
        added, which is the whole point of the case. ``11`` and ``14`` are the
        interesting ones -- a remainder of 1 and of 4 -- because the block list
        happily consumes as many whole 8-octet items as it can find and
        silently ignores the tail.

        This used to accept either :exc:`~pcapkit.utilities.exceptions.ProtocolError`
        or :exc:`~pcapkit.utilities.exceptions.FieldValueError`, since which one
        arrived depended on unrelated process state rather than on the packet
        -- #525. That is now fixed at the root (see the module docstring and
        :meth:`test_sack_exception_type_survives_a_sys_modules_purge` below),
        so the exception is pinned to the single documented type:
        :exc:`~pcapkit.utilities.exceptions.ProtocolError` from
        :meth:`TCP._read_mode_sack
        <pcapkit.protocols.transport.tcp.TCP._read_mode_sack>`, which is the
        check this module exists for.

        """
        for length in (3, 11, 14, 17, 19, 25):
            with self.subTest(length=length):
                with self.assertRaises(ProtocolError) as caught:
                    parse(sack_option(length, length + 8))
                self.assertRegex(str(caught.exception), 'invalid format')

    def test_sack_exception_type_survives_a_sys_modules_purge(self) -> 'None':
        """The exception type does not depend on :data:`sys.modules` state.

        This pins the actual mechanism behind #525, rather than merely
        recording the symptom. :meth:`ListField.unpack
        <pcapkit.corekit.fields.collections.ListField.unpack>` used to resolve
        :class:`~pcapkit.corekit.fields.misc.SchemaField` through a
        function-local import, re-run on every call. That is an ordinary
        :data:`sys.modules` cache hit almost always -- except when something
        has popped :mod:`pcapkit.corekit.fields.misc` out of
        :data:`sys.modules` since this ``ListField`` was built, which is
        exactly what the ``#439`` ABC-cache regression tests do in every
        case's ``setUp``/``tearDown`` (see
        :mod:`tests.protocols.schema.test_schema_metaclass_abc_cache_unit`) to
        get a clean cache between cases. The next call then re-executes
        :mod:`pcapkit.corekit.fields.misc` from scratch and mints a *second*,
        distinct ``SchemaField`` class, while the ``sack`` field's
        ``item_type`` -- built long before, from the first one -- is still an
        instance of the original. ``isinstance`` against the new class then
        answers :data:`False` for an item that plainly is a ``SchemaField``,
        and ``ListField.unpack`` takes its other branch, which bills each item
        by its *declared* length unconditionally instead of by what it
        actually consumed -- letting the length check go negative and raise
        :exc:`~pcapkit.utilities.exceptions.FieldValueError` from
        :mod:`pcapkit.corekit.fields.collections` before
        ``_read_mode_sack`` is ever reached.

        Reproducing that does not need the schema test suite at all -- the
        :data:`sys.modules` manipulation alone is sufficient, and doing just
        that is what makes this a targeted regression test rather than a
        repeat of the same "run some other tests first" guess #525 opened
        with. Before the fix, this exact removal made
        :meth:`ListField.unpack <pcapkit.corekit.fields.collections.ListField.unpack>`
        re-import :mod:`pcapkit.corekit.fields.misc` on its next call and mint
        the mismatched second ``SchemaField`` class described above; asserting
        that :mod:`pcapkit.corekit.fields.misc` is *not* back in
        :data:`sys.modules` immediately after ``parse()`` returns is what
        confirms the fix (a module-level import, resolved once) rather than
        just a passing assertion for the wrong reason.

        """
        self.assertIn(
            'pcapkit.corekit.fields.misc', sys.modules,
            'test setup expects pcapkit to already be imported',
        )
        removed = sys.modules.pop('pcapkit.corekit.fields.misc')
        try:
            with self.assertRaises(ProtocolError) as caught:
                parse(sack_option(11, 11 + 8))
            self.assertRegex(str(caught.exception), 'invalid format')

            # The fix hoisted the import to module level, so nothing during
            # ``parse()`` re-triggers it: the module stays absent from
            # ``sys.modules`` until this test restores it below. Before the
            # fix, ``ListField.unpack``'s function-local import would have put
            # it right back.
            self.assertNotIn('pcapkit.corekit.fields.misc', sys.modules)
        finally:
            # NOTE: restore, rather than leave the module state disturbed for
            # whatever the test runner collects next.
            sys.modules['pcapkit.corekit.fields.misc'] = removed

    def test_documented_rule_is_the_implemented_rule(self) -> 'None':
        """The check is exactly ``(length - 2) % 8 == 0``, no more.

        :rfc:`2018` also bounds the block count at one to four, and the
        implementation deliberately does not reach past its own docstring to
        enforce that. Only one such case is actually reachable, though, and
        working out why is what makes the missing bound harmless:

        * ``length=2`` -- no blocks at all. Satisfies the modulo rule, is not
          well formed under :rfc:`2018`, and parses. This is the one real gap,
          recorded here as a decision rather than left silent.
        * five blocks or more cannot be expressed at all, which is why
          :rfc:`2018` stops at four. The TCP data offset is four bits, so a
          header is at most ``15 * 4 == 60`` octets and the options area at
          most 40. A five-block SACK needs ``2 + 40 == 42`` octets of option,
          and 44 once padded, which no legal data offset can describe --
          :func:`segment` cannot even build one. The upper bound is therefore
          enforced by the header format rather than by a check, and adding one
          would be unreachable code.

        So if a lower bound is ever added, this test is what should fail and be
        rewritten.

        """
        tcp = parse(sack_option(2, 0))
        self.assertIn(SACK, [int(key) for key in tcp.info['options']])

        # five blocks: 2 + 8*5 == 42 octets, 44 padded, needing a data offset
        # of 16 where the field holds a maximum of 15.
        with self.assertRaises(ValueError):
            segment(sack_option(42, 40))


if __name__ == '__main__':
    unittest.main()
