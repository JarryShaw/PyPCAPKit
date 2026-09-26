"""A :class:`~pcapkit.corekit.fields.numbers.NumberField` whose resolved ``length`` is negative.

GitHub issue #828. :meth:`~pcapkit.corekit.fields.numbers.NumberField.__call__`
caches ``self._bit_length`` from the resolved ``length`` whenever ``bit_length``
was not supplied, and shifts by it immediately: ``1 << (length * 8)``. A
resolved length below zero -- the real shape is
``pcapkit/protocols/schema/internet/hip.py``'s
``NumberField(length=lambda pkt: pkt['len'] - 4, signed=False)``, which goes
negative for any wire ``len`` under ``4`` -- therefore raised a bare
:exc:`ValueError` (``negative shift count``): not one of
:mod:`pcapkit.utilities.exceptions`, so a caller could not tell it from a bug
of its own, and raised *before* :attr:`~pcapkit.corekit.fields.field.
FieldBase.length`'s own :exc:`ProtocolError` guard (#805, refined by #811 and
#827) ever got a chance to see the value -- that guard fires only once a
:attr:`~pcapkit.corekit.fields.field.FieldBase.template` already exists to
call :func:`struct.calcsize` on, and this method crashes several lines before
building one.

Every negative case here is run twice: once via a literal negative ``length``
and once via the real ``lambda pkt: pkt['len'] - 4`` callable shape with a
``packet`` dict, so a fix that only special-cased a literal int would still
fail here.
"""

from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NegativeResolvedLengthTests(unittest.TestCase):
    """The reported defect: a resolved ``length`` below zero, and the two
    boundaries either side of it that must keep working.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_a_literal_negative_length_raises_protocolerror(self) -> None:
        """The narrowest reproduction: ``length=-1`` supplied directly.

        No callback is involved at all -- ``Field.__init__`` accepts any
        :obj:`int`, so a negative one reaches
        :meth:`~pcapkit.corekit.fields.numbers.NumberField.__call__`'s eager
        ``1 << (length * 8)`` exactly as a callable resolving to the same
        value would.

        """
        from pcapkit.corekit.fields.numbers import NumberField
        from pcapkit.utilities.exceptions import ProtocolError

        field = NumberField(length=-1, signed=False)

        with self.assertRaises(ProtocolError) as ctx:
            field(dict())

        self.assertIn('resolved to a negative length', str(ctx.exception))
        self.assertIn('-1', str(ctx.exception))

    def test_protocolerror_is_a_baseerror_unlike_the_stock_valueerror(self) -> None:
        """The defect in one assertion: catchable as a pcapkit error.

        On stock ``21e9588af`` this raises a bare :class:`builtins.ValueError`
        (``negative shift count``), which is *not* an instance of
        :class:`~pcapkit.utilities.exceptions.BaseError` and so cannot be
        caught as one -- measured directly below, since that is the whole
        point of the regression.

        """
        from pcapkit.corekit.fields.numbers import NumberField
        from pcapkit.utilities.exceptions import BaseError

        field = NumberField(length=-4, signed=False)

        with self.assertRaises(BaseError) as ctx:
            field(dict())

        self.assertNotIsInstance(ctx.exception, type(None))  # sanity: an exception was raised
        self.assertIsInstance(ctx.exception, BaseError)

    def test_the_real_callable_shape_from_hip_py_also_raises_protocolerror(self) -> None:
        """``lambda pkt: pkt['len'] - 4`` against a truncated ``len``, verbatim.

        This is the exact shape at ``pcapkit/protocols/schema/internet/
        hip.py``'s ``PuzzleParameter.random`` field (line 734 as of
        ``21e9588af``): a wire ``len`` of ``3`` -- one octet short of the
        4-octet header this parameter always carries -- resolves the
        remaining ``random`` payload to ``-1`` octets, negative because the
        packet is malformed rather than because anyone asked for a negative
        width.

        """
        from pcapkit.corekit.fields.numbers import NumberField
        from pcapkit.utilities.exceptions import BaseError, ProtocolError

        field = NumberField(length=lambda pkt: pkt['len'] - 4, signed=False)

        with self.assertRaises(ProtocolError) as ctx:
            field({'len': 3})

        self.assertIsInstance(ctx.exception, BaseError)
        self.assertIn('resolved to a negative length', str(ctx.exception))
        self.assertIn('-1', str(ctx.exception))

    def test_a_more_negative_resolution_also_raises_protocolerror(self) -> None:
        """A wire ``len`` of ``0`` resolves to ``-4``, not just ``-1``.

        Pinned separately from the ``-1`` case so a fix that only checks
        ``length == -1`` -- rather than ``length < 0`` -- fails here.

        """
        from pcapkit.corekit.fields.numbers import NumberField
        from pcapkit.utilities.exceptions import BaseError, ProtocolError

        field = NumberField(length=lambda pkt: pkt['len'] - 4, signed=False)

        with self.assertRaises(ProtocolError) as ctx:
            field({'len': 0})

        self.assertIsInstance(ctx.exception, BaseError)
        self.assertIn('-4', str(ctx.exception))

    def test_a_resolved_length_of_exactly_zero_still_succeeds(self) -> None:
        """The boundary the fix must not break: zero is not negative.

        The same ``lambda pkt: pkt['len'] - 4`` shape with ``len=4`` resolves
        to exactly ``0`` -- a legitimate empty field, not a malformed packet --
        and issue #828 is explicit that this must keep working. Checked via
        both the literal and the callable shape, matching the negative cases
        above.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        literal = NumberField(length=0, signed=False)(dict())
        self.assertEqual(literal._length, 0)
        self.assertEqual(literal.template, '>0s')
        self.assertEqual(literal.length, 0)

        callable_ = NumberField(length=lambda pkt: pkt['len'] - 4, signed=False)
        resolved = callable_({'len': 4})
        self.assertEqual(resolved._length, 0)
        self.assertEqual(resolved.template, '>0s')
        self.assertEqual(resolved.length, 0)

    def test_a_positive_resolved_length_is_unaffected(self) -> None:
        """The control: a well-formed packet is not touched by this guard.

        The same ``hip.py`` shape with a ``len`` of ``8`` -- a well-formed
        ``PUZZLE`` parameter, header plus four octets of random data --
        resolves to ``4`` and packs exactly as a static ``length=4`` field
        would.

        """
        from pcapkit.corekit.fields.numbers import NumberField

        field = NumberField(length=lambda pkt: pkt['len'] - 4, signed=False)
        resolved = field({'len': 8})

        self.assertEqual(resolved._length, 4)
        self.assertEqual(resolved.template, '>I')
        self.assertEqual(resolved.length, 4)

        static = NumberField(length=4, signed=False)(dict())
        self.assertEqual(resolved.pack(0xdeadbeef, dict()),
                          static.pack(0xdeadbeef, dict()))


if __name__ == '__main__':
    unittest.main()
