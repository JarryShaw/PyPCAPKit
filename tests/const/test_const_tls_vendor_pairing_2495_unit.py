# -*- coding: utf-8 -*-
"""``ContentType``/``HandshakeType`` after pairing with their crawler.

GitHub issue #2495. Regenerating both modules from the new
:mod:`pcapkit.vendor.tls.content_type` and
:mod:`pcapkit.vendor.tls.handshake_type` crawlers (:pr:`2503`) fixed a real
behaviour bug the hand-maintained modules had drifted into: ``ContentType``
resolved values 32-63 to ``Unassigned`` via a flat ``_missing_`` fallback,
where IANA's registry -- and the crawler -- call that band ``Reserved``
(:rfc:`9147`). It also dropped ``ContentType.invalid``, which had no IANA
counterpart and no reference anywhere in the codebase, and it means
``HandshakeType`` now names its two single-row ``Unassigned`` entries
(values 7 and 255) as explicit members instead of leaving them to
``_missing_``.

"""
import unittest


class ContentTypeReservedBandTests(unittest.TestCase):
    """Values 32-63 resolve to ``Reserved``, not ``Unassigned`` (:rfc:`9147`)."""

    def test_32_resolves_to_reserved(self) -> 'None':
        from pcapkit.const.tls.content_type import ContentType

        self.assertEqual(ContentType(32).name, 'Reserved')

    def test_63_resolves_to_reserved(self) -> 'None':
        from pcapkit.const.tls.content_type import ContentType

        self.assertEqual(ContentType(63).name, 'Reserved')

    def test_bands_either_side_of_32_63_still_resolve_to_unassigned(self) -> 'None':
        from pcapkit.const.tls.content_type import ContentType

        for value in (19, 28, 31, 64, 255):
            with self.subTest(value=value):
                self.assertEqual(ContentType(value).name, 'Unassigned')

    def test_invalid_member_is_gone(self) -> 'None':
        from pcapkit.const.tls.content_type import ContentType

        self.assertFalse(hasattr(ContentType, 'invalid'))
        self.assertNotIn('invalid', ContentType.__members__)
        # Value 0 still resolves -- to the 0-19 Unassigned band, by
        # _missing_, rather than to a dedicated sentinel member.
        self.assertEqual(ContentType(0).name, 'Unassigned')


class HandshakeTypeUnassignedMembersTests(unittest.TestCase):
    """IANA's single-row ``Unassigned`` entries are named members."""

    def test_value_7_is_a_named_unassigned_member(self) -> 'None':
        from pcapkit.const.tls.handshake_type import HandshakeType

        self.assertIn('unassigned_7', HandshakeType.__members__)
        self.assertEqual(HandshakeType.unassigned_7, 7)
        self.assertEqual(HandshakeType(7).name, 'unassigned_7')

    def test_value_255_is_a_named_unassigned_member(self) -> 'None':
        from pcapkit.const.tls.handshake_type import HandshakeType

        self.assertIn('unassigned_255', HandshakeType.__members__)
        self.assertEqual(HandshakeType.unassigned_255, 255)
        self.assertEqual(HandshakeType(255).name, 'unassigned_255')

    def test_other_unassigned_values_still_fall_through_to_missing(self) -> 'None':
        from pcapkit.const.tls.handshake_type import HandshakeType

        for value in (18, 19, 27, 253):
            with self.subTest(value=value):
                self.assertEqual(HandshakeType(value).name, 'Unassigned')


if __name__ == '__main__':
    unittest.main()
