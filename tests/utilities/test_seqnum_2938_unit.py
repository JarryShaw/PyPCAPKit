# -*- coding: utf-8 -*-
"""A 32-bit sequence number unwraps to the integer within ``2 ** 31`` of its reference (#2938).

:func:`pcapkit.utilities.seqnum.unwrap` is the comparison of RFC 9293, section 3.4, that
TCP and TLS reassembly share.

"""

import unittest

#: Test tier (#1958): ``int`` arithmetic at the edges of the 32-bit space.
__tier__ = 'ALL'


class UnwrapTests(unittest.TestCase):
    """Each case is a wire value, a reference, and the unwrapped value."""

    CASES = (
        ('at the reference', 1000, 1000, 1000),
        ('just ahead', 1500, 1000, 1500),
        ('just behind', 500, 1000, 500),
        ('ahead across 2 ** 32', 10, 2 ** 32 - 10, 2 ** 32 + 10),
        ('behind across 2 ** 32', 2 ** 32 - 10, 2 ** 32 + 10, 2 ** 32 - 10),
        ('behind across zero', 2 ** 32 - 10, 10, -10),
        ('half the space ahead wraps behind', 2 ** 31, 0, -(2 ** 31)),
        ('one short of half ahead', 2 ** 31 - 1, 0, 2 ** 31 - 1),
        ('a later wrap', 5, 3 * 2 ** 32 + 2 ** 32 - 5, 4 * 2 ** 32 + 5),
    )

    def test_unwrap(self) -> None:
        from pcapkit.utilities.seqnum import unwrap

        for (name, seq, ref, expected) in self.CASES:
            with self.subTest(case=name):
                self.assertEqual(unwrap(seq, ref), expected)
                self.assertEqual(unwrap(seq, ref) % 2 ** 32, seq)


if __name__ == '__main__':
    unittest.main()
