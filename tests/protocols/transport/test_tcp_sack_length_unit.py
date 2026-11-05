# -*- coding: utf-8 -*-
"""The TCP SACK option's length constraint, documented and checked.

GitHub issue #519 counted :meth:`TCP._read_mode_sack
<pcapkit.protocols.transport.tcp.protocol.TCP._read_mode_sack>` among its phantom
``Raises:`` clauses: the docstring promised ``ProtocolError: If length is
**NOT** multiply of 8 plus 2`` and the body had no such check. Unlike the other
phantoms there, the clause is right and the check belongs in the body:

* :rfc:`2018` gives the SACK option a 2-octet header followed by 8-octet
  left/right edge pairs, so a well-formed length is ``8n + 2``.
* The sibling readers validate their own lengths, with the same message:
  :meth:`TCP._read_mode_sackpmt
  <pcapkit.protocols.transport.tcp.protocol.TCP._read_mode_sackpmt>` raises on
  ``schema.length != 2`` and
  :meth:`TCP._read_mode_echo <pcapkit.protocols.transport.tcp.protocol.TCP._read_mode_echo>`
  on ``schema.length != 6``.
* Nothing upstream enforces it. The schema field is
  ``ListField(length=lambda pkt: pkt['length'] - 2,
  item_type=SchemaField(length=8, schema=SACKBlock))``, which ignores a remainder,
  so without the check ``kind=5, length=11`` parses clean, as
  :meth:`SACKLengthTests.test_invalid_sack_length_is_rejected` pins.

This is the behavioural half of #519. :file:`tests/test_docstring_contract.py` stops a
docstring drifting from the code; this module stops the code drifting from *this*
docstring, the direction that lets a malformed packet through.

The exception is :exc:`~pcapkit.utilities.exceptions.ProtocolError` whatever ran earlier
in the process (#525). That relies on :meth:`ListField.unpack
<pcapkit.corekit.fields.collections.ListField.unpack>` resolving
:class:`~pcapkit.corekit.fields.misc.SchemaField` at module load, not through a
function-local import per call: the ``#439`` ABC-cache tests pop classes from
:data:`sys.modules` in every ``setUp``/``tearDown``, so such an import would return a
second, distinct class. ``isinstance(self._item_type, SchemaField)`` would then be
:data:`False`, ``ListField.unpack`` would bill the item by its declared length rather
than what it consumed, and the length check would go negative and raise
:exc:`~pcapkit.utilities.exceptions.FieldValueError` from
:mod:`pcapkit.corekit.fields.collections` before ``_read_mode_sack`` is reached.
:meth:`SACKLengthTests.test_sack_exception_type_survives_a_sys_modules_purge`
reproduces that purge.

A deliberate limit: the check is exactly the documented rule, ``(length - 2) % 8 == 0``.
:rfc:`2018` also wants one to four blocks; tightening past the documented contract would
change what the parser accepts on a test's say rather than the specification's, so
:meth:`SACKLengthTests.test_documented_rule_is_the_implemented_rule` records the gap
instead.

Unit tier: every case builds its own octets and reads no capture.

"""
from __future__ import annotations

import io
import sys
import unittest

from pcapkit.protocols.transport.tcp.protocol import TCP
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

        Every one of these parses without complaint unless the #519 check is
        in place, which is the whole point of the case. ``11`` and ``14`` are the
        interesting ones -- a remainder of 1 and of 4 -- because the block list
        happily consumes as many whole 8-octet items as it can find and
        silently ignores the tail.

        The exception is pinned to the single documented type, independent of
        unrelated process state -- #525, see the module docstring and
        :meth:`test_sack_exception_type_survives_a_sys_modules_purge` below:
        :exc:`~pcapkit.utilities.exceptions.ProtocolError` from
        :meth:`TCP._read_mode_sack
        <pcapkit.protocols.transport.tcp.protocol.TCP._read_mode_sack>`, which is the
        check this module exists for.

        """
        for length in (3, 11, 14, 17, 19, 25):
            with self.subTest(length=length):
                with self.assertRaises(ProtocolError) as caught:
                    parse(sack_option(length, length + 8))
                self.assertRegex(str(caught.exception), 'invalid format')

    def test_sack_exception_type_survives_a_sys_modules_purge(self) -> 'None':
        """The exception type does not depend on :data:`sys.modules` state.

        Pins the mechanism behind #525, not just its symptom. A function-local
        import of :class:`~pcapkit.corekit.fields.misc.SchemaField` in
        :meth:`ListField.unpack <pcapkit.corekit.fields.collections.ListField.unpack>`
        would, once :mod:`pcapkit.corekit.fields.misc` is popped from
        :data:`sys.modules` (as the ``#439`` ABC-cache tests in
        :mod:`tests.protocols.schema.test_schema_metaclass_abc_cache_unit` do in
        every ``setUp``/``tearDown``), re-execute it and mint a second, distinct
        ``SchemaField``. The ``sack`` field's ``item_type``, built from the first,
        then fails ``isinstance``, and ``ListField.unpack`` bills each item by its
        *declared* length, so the length check goes negative and raises
        :exc:`~pcapkit.utilities.exceptions.FieldValueError` from
        :mod:`pcapkit.corekit.fields.collections` before ``_read_mode_sack`` is
        reached.

        The :data:`sys.modules` removal alone reproduces it, without the schema
        suite or the "run some other tests first" guess #525 opened with.
        Asserting the module is *not* back in :data:`sys.modules` after
        ``parse()`` confirms the import is module-level, so the test does not
        pass for the wrong reason.

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

            # The import is at module level, so nothing during ``parse()``
            # re-triggers it: the module stays absent from ``sys.modules``
            # until this test restores it below. A function-local import in
            # ``ListField.unpack`` would put it right back.
            self.assertNotIn('pcapkit.corekit.fields.misc', sys.modules)
        finally:
            # NOTE: restore, rather than leave the module state disturbed for
            # whatever the test runner collects next.
            sys.modules['pcapkit.corekit.fields.misc'] = removed

    def test_documented_rule_is_the_implemented_rule(self) -> 'None':
        """The check is exactly ``(length - 2) % 8 == 0``, no more.

        :rfc:`2018` also bounds the block count at one to four, which the
        implementation deliberately does not enforce past its own docstring. Only
        one violation is reachable:

        * ``length=2``, no blocks: satisfies the modulo rule, is malformed under
          :rfc:`2018`, and parses. This gap is a recorded decision.
        * five or more blocks cannot be expressed. The four-bit data offset caps
          the header at ``15 * 4 == 60`` octets and the options area at 40; a
          five-block SACK needs ``2 + 40 == 42`` octets, 44 padded, which
          :func:`segment` cannot build. The header format enforces the upper
          bound, so a check would be unreachable.

        If a lower bound is ever added, this test should fail and be rewritten.


        """
        tcp = parse(sack_option(2, 0))
        self.assertIn(SACK, [int(key) for key in tcp.info['options']])

        # five blocks: 2 + 8*5 == 42 octets, 44 padded, needing a data offset
        # of 16 where the field holds a maximum of 15.
        with self.assertRaises(ValueError):
            segment(sack_option(42, 40))


if __name__ == '__main__':
    unittest.main()
