# -*- coding: utf-8 -*-
"""GitHub issue #2411: the ESP read path and one warning missed the ``ESP:`` prefix.

#2366 (fixing #2297) put the house ``ESP: <lowercase description>`` prefix on
:meth:`ESP.make <pcapkit.protocols.internet.esp.ESP.make>`'s
:exc:`~pcapkit.utilities.exceptions.ProtocolError` messages and on
:meth:`SecurityAssociation.unavailable
<pcapkit.protocols.internet.esp.SecurityAssociation.unavailable>`, but eight
sites were outside its checklist and kept the bare wording -- so the *same*
condition read two different ways depending on which direction it was hit from
(``ESP: no security association for SPI 0x...`` from ``make``, and
``no security association for SPI 0x...`` from ``read``).

The eight, as #2411 enumerates them:

* three diagnostics returned by :meth:`ESP._read_trailer
  <pcapkit.protocols.internet.esp.ESP._read_trailer>` -- the one for a
  plaintext too short to hold a trailer, the one for a pad length the
  plaintext cannot hold, and the padding-pattern one, which is both returned
  and warned with (:class:`ReadTrailerMessages`);
* four built inline in :meth:`ESP.read
  <pcapkit.protocols.internet.esp.ESP.read>` and surfaced as
  :attr:`esp.error <pcapkit.protocols.data.internet.esp.ESP.error>`
  (:class:`ReadErrorMessages`);
* the integrity-key warning in :meth:`SecurityAssociation.__init__
  <pcapkit.protocols.internet.esp.SecurityAssociation.__init__>`
  (:class:`IntegrityKeyWarning`). :func:`~pcapkit.utilities.warnings.warn`
  blames the caller's frame rather than the protocol, so the message text is
  the only thing that names ESP at all -- it needs the prefix more than the
  exceptions do, not less.

Every message is pinned **whole**, not by substring: the existing tests in
``tests/protocols/internet/test_esp_unit.py`` match fragments and so pass with
or without a prefix, which is exactly why the omission survived #2366. This
follows the pinning style of
``tests/protocols/test_maker_invalid_format_messages_2296_unit.py`` and its
#2406 companion.

Nothing here needs |cryptography|_ bar
:meth:`ReadErrorMessages.test_aead_tag_mismatch_names_the_protocol`: an
``ENCR_NULL`` SA exercises the trailer and the separate-integrity paths on
:mod:`hmac` and :mod:`hashlib` alone.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_CRYPTO = importlib.util.find_spec('cryptography') is not None

#: The SPI every message below names, and its ``{spi:#010x}`` rendering.
SPI = 0x4321
SPI_TEXT = '0x00004321'


def esp_packet(payload: bytes, *, spi: int = SPI, seq: int = 1) -> bytes:
    """An ESP packet: the 8-octet header, then ``payload`` verbatim."""
    return struct.pack('!II', spi, seq) + payload


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ESPMessageTestCase(unittest.TestCase):
    """Re-import :mod:`pcapkit` once per class, as the suite's convention asks."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def sa(self, **kwargs: 'Any') -> 'Any':
        """A Security Association for :data:`SPI`, ``ENCR_NULL`` unless told otherwise.

        ``ENCR_NULL`` returns the payload as its own plaintext and needs no
        |cryptography|_, so it reaches the trailer and separate-integrity
        paths that carry the messages under test without a cipher in the way.

        """
        from pcapkit.protocols.internet.esp import SecurityAssociation

        kwargs.setdefault('spi', SPI)
        return SecurityAssociation(**kwargs)

    def parse(self, packet: bytes, *associations: 'Any') -> 'Any':
        """Parse ``packet`` with ``associations`` in context, swallowing warnings.

        Returns:
            The parsed data model, i.e. ``esp.info``.

        """
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import ESP, ESPContext

        registry = ContextRegistry.make(ESPContext(*associations)) if associations else None
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            if registry is None:
                return ESP(packet, len(packet)).info
            return ESP(packet, len(packet), __context__=registry).info


class ReadTrailerMessages(ESPMessageTestCase):
    """``ESP._read_trailer``'s three diagnostics name the protocol.

    ``_read_trailer`` is a :func:`staticmethod`, so it has no ``self.alias`` to
    read and spells the prefix literally -- the same way every site in
    :class:`~pcapkit.protocols.internet.esp.SecurityAssociation` does.

    """

    def trailer(self, plaintext: bytes, **kwargs: 'Any') -> 'Any':
        """``_read_trailer`` over ``plaintext``, for an SA built from ``kwargs``."""
        from pcapkit.protocols.internet.esp import ESP

        return ESP._read_trailer(plaintext, self.sa(**kwargs), SPI)

    def test_plaintext_too_short_for_a_trailer(self) -> None:
        # one octet cannot hold both the pad length and the next header, which
        # are the last two octets of the plaintext
        self.assertEqual(
            self.trailer(b'\x06'),
            f'ESP: decrypted payload too short: SPI {SPI_TEXT} decrypts to 1 octets, '
            f'too short to hold a pad length and next header')

    def test_an_empty_plaintext_too(self) -> None:
        self.assertEqual(
            self.trailer(b''),
            f'ESP: decrypted payload too short: SPI {SPI_TEXT} decrypts to 0 octets, '
            f'too short to hold a pad length and next header')

    def test_pad_length_beyond_the_plaintext(self) -> None:
        # pad length 255 over a 5-octet plaintext: 3 octets remain once the
        # trailer's own two are taken off
        self.assertEqual(
            self.trailer(b'abc' + bytes([255, 6])),
            f'ESP: invalid pad length: the decrypted payload for SPI {SPI_TEXT} declares '
            f'255 octets of padding but holds only 3; the encryption key is most likely wrong')

    def test_padding_pattern_is_decisive_when_nothing_authenticated_it(self) -> None:
        # zero padding where RFC 4303 s2.4 asks for 1, 2, ...; a strict SA with
        # no integrity has the pattern as its only wrong-key signal, so the
        # mismatch is returned rather than warned about
        self.assertEqual(
            self.trailer(b'payload' + bytes(2) + bytes([2, 6])),
            f'ESP: invalid padding: the decrypted payload for SPI {SPI_TEXT} does not follow '
            f'the monotonically increasing sequence of RFC 4303 s2.4; the encryption key is '
            f'most likely wrong')

    def test_a_lenient_sa_warns_with_the_same_prefixed_text(self) -> None:
        from pcapkit.utilities.warnings import ProtocolWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            trailer = self.trailer(b'payload' + bytes(2) + bytes([2, 6]), strict=False)

        # accepted, so the trailer comes back parsed rather than as a reason
        self.assertEqual(trailer, (b'payload', bytes(2), 2, 6))
        messages = [str(w.message) for w in caught
                    if issubclass(w.category, ProtocolWarning)]
        self.assertEqual(
            messages,
            [f'ESP: invalid padding: the decrypted payload for SPI {SPI_TEXT} does not follow '
             f'the monotonically increasing sequence of RFC 4303 s2.4'])

    def test_a_consistent_trailer_is_still_read(self) -> None:
        # the guards have not widened: padding 01 02, pad length 2, next 6 (TCP)
        self.assertEqual(self.trailer(b'payload' + bytes([1, 2]) + bytes([2, 6])),
                         (b'payload', bytes([1, 2]), 2, 6))


class ReadErrorMessages(ESPMessageTestCase):
    """``ESP.read``'s four inline diagnostics name the protocol.

    ``read`` is an instance method, so it spells the prefix ``{self.alias}:``,
    as ``ESP.make``'s messages do.

    """

    def test_no_security_association_names_the_protocol(self) -> None:
        from pcapkit.protocols.internet.esp import ESPStatus

        info = self.parse(esp_packet(b'opaque-ciphertext'))
        self.assertIs(info.status, ESPStatus.NO_SA)
        self.assertEqual(info.error, f'ESP: no security association for SPI {SPI_TEXT}')

    def test_a_payload_shorter_than_the_declared_icv(self) -> None:
        from pcapkit.protocols.internet.esp import ESPStatus

        # the ICV length comes from the SA, so declaring 16 octets over a
        # 4-octet payload is reported as TRUNCATED with no cipher involved
        info = self.parse(esp_packet(b'tiny'), self.sa(icv_length=16))
        self.assertIs(info.status, ESPStatus.TRUNCATED)
        self.assertEqual(
            info.error,
            'ESP: payload too short: 4 octets, shorter than the 16-octet ICV the '
            'security association declares')

    def test_an_icv_that_does_not_verify(self) -> None:
        from pcapkit.protocols.internet.esp import ESPStatus, Integrity

        sa = self.sa(integrity=Integrity.HMAC_SHA2_256_128, integrity_key=bytes(32))
        # a 16-octet ICV that is not the one the key computes
        packet = esp_packet(b'payload' + bytes([1, 2]) + bytes([2, 6]) + bytes(16), seq=7)
        info = self.parse(packet, sa)

        self.assertIs(info.status, ESPStatus.AUTH_FAILED)
        self.assertEqual(
            info.error,
            f'ESP: integrity check value does not verify for SPI {SPI_TEXT} sequence 7')

    def test_the_right_icv_still_verifies(self) -> None:
        from pcapkit.protocols.internet.esp import ESPStatus, Integrity

        key = bytes(range(32))
        sa = self.sa(integrity=Integrity.HMAC_SHA2_256_128, integrity_key=key)
        body = b'payload' + bytes([1, 2]) + bytes([2, 6])
        icv = hmac.new(key, struct.pack('!II', SPI, 7) + body, hashlib.sha256).digest()[:16]
        info = self.parse(esp_packet(body + icv, seq=7), sa)

        self.assertIs(info.status, ESPStatus.DECRYPTED)
        self.assertIsNone(info.error)

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_aead_tag_mismatch_names_the_protocol(self) -> None:
        from pcapkit.protocols.internet.esp import Cipher, ESPStatus

        # a combined-mode SA verifies its own tag inside decryption, so the
        # wrong key surfaces as the library's InvalidTag rather than as a
        # ProtocolError -- the one message here that needs |cryptography|_
        sa = self.sa(encryption=Cipher.AES_GCM_16, encryption_key=bytes(16) + b'salt')
        packet = esp_packet(bytes(8) + bytes(16) + bytes(16), seq=3)
        info = self.parse(packet, sa)

        self.assertIs(info.status, ESPStatus.AUTH_FAILED)
        self.assertEqual(
            info.error,
            f'ESP: authentication tag does not verify for SPI {SPI_TEXT} sequence 3; '
            f'the encryption key is most likely wrong')


class IntegrityKeyWarning(ESPMessageTestCase):
    """``SecurityAssociation.__init__``'s integrity-key warning names the protocol.

    :func:`~pcapkit.utilities.warnings.warn` reports the *caller's* frame, so
    without the prefix the text is all a reader has to go on -- there is no
    ``pcapkit/protocols/internet/esp.py`` in the location it prints.

    """

    def test_a_short_integrity_key_warns_by_name(self) -> None:
        from pcapkit.protocols.internet.esp import Integrity
        from pcapkit.utilities.warnings import ProtocolWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.sa(integrity=Integrity.HMAC_SHA2_256_128, integrity_key=bytes(16))

        messages = [str(w.message) for w in caught
                    if issubclass(w.category, ProtocolWarning)]
        self.assertEqual(
            messages,
            ['ESP: invalid integrity key: AUTH_HMAC_SHA2_256_128 expects a 32-octet key, '
             'got 16 octets; the ICV will very likely fail to verify'])

    def test_a_key_of_the_right_size_does_not_warn(self) -> None:
        from pcapkit.protocols.internet.esp import Integrity
        from pcapkit.utilities.warnings import ProtocolWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.sa(integrity=Integrity.HMAC_SHA2_256_128, integrity_key=bytes(32))

        self.assertEqual([str(w.message) for w in caught
                          if issubclass(w.category, ProtocolWarning)], [])


if __name__ == '__main__':
    unittest.main()
