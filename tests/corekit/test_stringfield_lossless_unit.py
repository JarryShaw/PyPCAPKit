# -*- coding: utf-8 -*-
"""StringField packs back exactly the octets it unpacked.

GitHub issue #1293: :class:`~pcapkit.corekit.fields.strings.StringField` was
lossy three ways. Without an ``encoding`` it decoded with the charset
:func:`~pcapkit.utilities.chardet.detect` guessed and packed the text back as
UTF-8; an octet the charset could not decode became U+FFFD and was packed as
U+FFFD's own three octets; and a length of ``-1`` was taken from the *character*
count, so multi-octet text lost its tail.

The octets are now remembered by a :class:`DecodedString
<pcapkit.corekit.fields.strings.DecodedString>` and packed verbatim, while the
decoded text is left exactly as it was -- U+FFFD and all. That the text is
unchanged is load-bearing rather than incidental, so
:class:`TestStringFieldDumpers` runs the real ``plist`` and ``tree`` dumpers over
an undecodable octet: a lone surrogate there instead of U+FFFD raises
``UnicodeEncodeError`` inside :mod:`dictdumper`, which is a crash on arbitrary
capture bytes.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import copy
import os
import pickle
import tempfile
import unittest

from tests._support import reimport_once_per_class

#: Charsets whose codecs reject a ``'surrogateescape'`` error handler, so that a
#: fallback through one would raise where ``'replace'`` does not.
NO_SURROGATE_CHARSETS = ('utf-16', 'utf-16-le', 'utf-16-be', 'utf-32', 'utf-7')


def pcapng(comment: bytes) -> bytes:
    """A minimal pcapng: SHB, IDB and one EPB, the first two carrying ``comment``.

    Args:
        comment: Octets to write as the ``opt_comment`` of the SHB and the IDB.

    Returns:
        The capture file's octets.

    """
    opts = (b'\x01\x00' + len(comment).to_bytes(2, 'little')
            + comment + bytes((-len(comment)) % 4) + b'\x00\x00\x00\x00')

    shb_body = bytes.fromhex('4d3c2b1a') + b'\x01\x00\x00\x00' + b'\xff' * 8 + opts
    shb_len = (12 + len(shb_body)).to_bytes(4, 'little')
    shb = bytes.fromhex('0a0d0d0a') + shb_len + shb_body + shb_len

    idb_body = b'\x01\x00\x00\x00' + (0x40000).to_bytes(4, 'little') + opts
    idb_len = (12 + len(idb_body)).to_bytes(4, 'little')
    idb = b'\x01\x00\x00\x00' + idb_len + idb_body + idb_len

    packet = bytes.fromhex('ffffffffffff' '000000000001' '0800') + bytes(34)
    epb_body = (bytes(12) + len(packet).to_bytes(4, 'little')
                + len(packet).to_bytes(4, 'little') + packet)
    epb_len = (12 + len(epb_body)).to_bytes(4, 'little')
    epb = b'\x06\x00\x00\x00' + epb_len + epb_body + epb_len

    return shb + idb + epb


class TestStringFieldLossless(unittest.TestCase):
    """Pin ``pack(unpack(octets)) == octets`` for :class:`StringField`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def roundtrip(self, octets: bytes, **kwargs: object) -> 'tuple[str, bytes]':
        """Unpack ``octets`` through a field of their own width, then pack it back."""
        from pcapkit.corekit.fields.strings import StringField

        field = StringField(length=len(octets), **kwargs)  # type: ignore[arg-type]
        value = field.unpack(octets, {})
        return value, field.pack(value, {})

    def test_detected_charset_is_reused_on_pack(self) -> None:
        value, packed = self.roundtrip(bytes.fromhex('e974e9'))
        self.assertEqual(packed.hex(), 'e974e9')
        self.assertEqual(value, 'été')

    def test_undecodable_octet_round_trips_as_replacement_text(self) -> None:
        value, packed = self.roundtrip(b'caf\xe9', encoding='utf-8')
        self.assertEqual(packed, b'caf\xe9')
        self.assertEqual(value, 'caf�')  # the text main decoded, unchanged

    def test_lossy_errors_scheme_still_round_trips(self) -> None:
        for errors in ('replace', 'ignore'):
            with self.subTest(errors=errors):
                _, packed = self.roundtrip(b'a\xffb', encoding='utf-8', errors=errors)
                self.assertEqual(packed, b'a\xffb')

    def test_decoded_text_never_holds_a_lone_surrogate(self) -> None:
        for octets in (b'\xff\xfe', b'caf\xe9', b'\x80', bytes(range(128, 160)),
                       bytes.fromhex('e974e9'), b'\xed\xa0\x80'):
            for kwargs in ({}, {'encoding': 'utf-8'}, {'unquote': True}):
                with self.subTest(octets=octets, kwargs=tuple(sorted(kwargs))):
                    value, packed = self.roundtrip(octets, **kwargs)  # type: ignore[arg-type]
                    self.assertEqual(packed, octets)
                    self.assertFalse([char for char in value if 0xD800 <= ord(char) <= 0xDFFF])

    def test_charsets_without_surrogateescape_do_not_raise(self) -> None:
        for charset in NO_SURROGATE_CHARSETS:
            with self.subTest(charset=charset):
                _, packed = self.roundtrip(b'\xff\xfe\x41', encoding=charset)
                self.assertEqual(packed, b'\xff\xfe\x41')

    def test_valid_text_decodes_to_a_plain_str(self) -> None:
        value, packed = self.roundtrip('héllo'.encode())
        self.assertIs(type(value), str)
        self.assertEqual(value, 'héllo')
        self.assertEqual(packed, 'héllo'.encode())

    def test_unquote_keeps_the_original_quoting(self) -> None:
        value, packed = self.roundtrip(b'a%2fb%2F', unquote=True)
        self.assertEqual(value, 'a/b/')
        self.assertEqual(packed, b'a%2fb%2F')

    def test_variable_length_counts_encoded_octets(self) -> None:
        from pcapkit.corekit.fields.strings import StringField

        self.assertEqual(StringField(length=-1).pack('héllo', {}), 'héllo'.encode())

    def test_edited_value_packs_with_the_field_encoding(self) -> None:
        from pcapkit.corekit.fields.strings import StringField

        field = StringField(length=-1)
        value = StringField(length=3).unpack(bytes.fromhex('e974e9'), {})
        self.assertEqual(field.pack(value.upper(), {}), 'ÉTÉ'.encode())

    def test_decoded_string_survives_copy_and_pickle(self) -> None:
        from pcapkit.corekit.fields.strings import StringField

        field = StringField(length=3)
        value = field.unpack(bytes.fromhex('e974e9'), {})
        for clone in (copy.copy(value), copy.deepcopy(value), pickle.loads(pickle.dumps(value))):
            with self.subTest(clone=type(clone).__name__):
                self.assertEqual(clone, 'été')
                self.assertEqual(field.pack(clone, {}).hex(), 'e974e9')

    def test_decoded_string_compares_and_hashes_as_its_text(self) -> None:
        from pcapkit.corekit.fields.strings import DecodedString

        value = DecodedString('été', b'\xe9t\xe9')
        self.assertEqual(value, 'été')
        self.assertEqual(hash(value), hash('été'))
        self.assertEqual({value: 1}['été'], 1)


class TestStringFieldDumpers(unittest.TestCase):
    """The dumpers render an undecodable octet rather than failing on it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_plist_and_tree_dump_an_undecodable_comment(self) -> None:
        import pcapkit

        for comment in (b'\xff\xfe', b'caf\xe9'):
            for fmt, suffix in (('plist', '.plist'), ('tree', '.txt'), ('json', '.json')):
                with self.subTest(comment=comment, format=fmt):
                    with tempfile.TemporaryDirectory() as tmp:
                        fin = os.path.join(tmp, 'in.pcapng')
                        fout = os.path.join(tmp, 'out' + suffix)
                        with open(fin, 'wb') as file:
                            file.write(pcapng(comment))

                        pcapkit.extract(fin=fin, fout=fout, format=fmt,
                                        store=False, engine='default')
                        with open(fout, 'rb') as file:
                            dumped = file.read()
                    # The dump is readable UTF-8 -- a lone surrogate would have
                    # raised in the writer rather than reaching the file -- and the
                    # comment is in it, as U+FFFD or as the escape ``json`` writes.
                    text = dumped.decode('utf-8')
                    self.assertTrue('�' in text or '\\ufffd' in text)

    def test_the_dumped_comment_still_packs_back_to_its_octets(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        whole = pcapng(b'caf\xe9')
        shb = whole[:int.from_bytes(whole[4:8], 'little')]

        parsed = PCAPNG(shb, len(shb), num=1, sct=1, ctx=None)
        self.assertEqual(parsed.info.options[1].comment, 'caf�')
        self.assertEqual(PCAPNG.from_data(parsed.info, num=1, sct=1, ctx=None).data, shb)


if __name__ == '__main__':
    unittest.main()
