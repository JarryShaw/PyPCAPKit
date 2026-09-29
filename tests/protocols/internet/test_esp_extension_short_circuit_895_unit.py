"""``ESP`` short-circuits on ``extension=True``, like its seven siblings.

GitHub issue #895 reported that ``extension=`` was accepted by
:class:`~pcapkit.protocols.internet.esp.ESP` and then silently ignored. #924
discharged the substantive half: :attr:`ESP._extf` became load-bearing, so
``payload``, ``protochain`` and ``protocol`` all consult it. What #924 left was
the *other* half, and the maintainer ruled it in scope here:

    i say the short-circuit must be done in ``ESP`` cause it's part of the IPv6
    extension headers.

The seven other extension headers end ``read`` with ``if extension: return
<data>`` before calling :meth:`~pcapkit.protocols.internet.internet.Internet
._decode_next_layer`, because when the header is one link in an IPv6 chain it
is :meth:`IPv6._decode_next_layer
<pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>` that walks the rest
of that chain. Decoding the payload again from inside the header produces a
result nobody reads.

**``ESP`` needs the guard in two places, not one.** The decrypted path returns
at the tail of :meth:`~pcapkit.protocols.internet.esp.ESP.read`, but every
*undecrypted* path -- no security association, wrong key, malformed trailer --
returns through :meth:`ESP._make_opaque
<pcapkit.protocols.internet.esp.ESP._make_opaque>` instead. Guarding only
``read``'s tail would leave the common case unfixed: a capture taken without
keys is the expected case, not the rare one, and that is precisely the path
that reaches ``_make_opaque``. ``_make_opaque`` has no ``extension``
parameter, so it consults :attr:`self._extf`, which
:meth:`~pcapkit.protocols.internet.esp.ESP.__post_init__` assigns *before* it
hands off to ``read``.

These tests count calls into ``Internet._decode_next_layer`` rather than
asserting on parsed output, because the whole point of the change is work *not*
done -- and the output is identical either way for the fields a caller reads
through the chain walk. Patching is done on the class that actually defines the
method: it is resolved on :class:`~pcapkit.protocols.internet.internet.Internet`,
not on :class:`~pcapkit.protocols.protocol.ProtocolBase`, so patching the latter
silently intercepts nothing and every count reads zero.

"""
from __future__ import annotations

import io
import unittest
import warnings

#: An ESP header with no matching security association, so parsing takes the
#: ``_make_opaque`` path: 4 octets of SPI, 4 of sequence number, then opaque
#: payload. No keys are registered anywhere in these tests, by design.
ESP_NO_KEYS = bytes.fromhex('00000001' '00000002') + b'\xaa' * 24

#: An AH header, as the control. ``AH`` is the closest analogue to ``ESP`` --
#: both are IPsec *and* IPv6 extension headers, both double-inherit
#: ``IPsec`` + ``IPv6_Ext`` -- and it already had the short-circuit, so it shows
#: the shape ``ESP`` is being brought into line with rather than a new invention.
AH_HEADER = bytes.fromhex('3b' '04' '0000' '00000001' '00000002') + b'\xbb' * 12


def _decode_calls(klass: 'type', raw: 'bytes', *, extension: 'bool') -> 'int':
    """How many times parsing ``raw`` as ``klass`` enters ``_decode_next_layer``.

    Counted on the defining class rather than on the instance, and restored in a
    ``finally`` so a failing assertion cannot leak the patch into another test.

    """
    from pcapkit.protocols.internet.internet import Internet

    owner = next(cls for cls in klass.__mro__ if '_decode_next_layer' in cls.__dict__)
    assert owner is Internet, f'expected Internet to define it, found {owner.__name__}'

    calls = []
    original = owner.__dict__['_decode_next_layer']

    def counting(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(type(self).__name__)
        return original(self, *args, **kwargs)

    setattr(owner, '_decode_next_layer', counting)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            protocol = klass(io.BytesIO(raw), len(raw), version=6, extension=extension)
            _ = protocol.info
    finally:
        setattr(owner, '_decode_next_layer', original)
    return calls.count(klass.__name__)


class ESPShortCircuitTests(unittest.TestCase):
    """The guard fires on the undecrypted path, which is the common one."""

    def test_extension_true_does_not_decode_the_next_layer(self) -> 'None':
        """This is the assertion that fails without the fix."""
        from pcapkit.protocols.internet.esp import ESP

        self.assertEqual(_decode_calls(ESP, ESP_NO_KEYS, extension=True), 0)

    def test_extension_false_still_decodes_it(self) -> 'None':
        """The guard must be conditional, not a removal.

        Without this, deleting the ``_decode_next_layer`` call outright would
        also satisfy the test above.

        """
        from pcapkit.protocols.internet.esp import ESP

        self.assertEqual(_decode_calls(ESP, ESP_NO_KEYS, extension=False), 1)

    def test_the_parsed_header_is_unchanged_either_way(self) -> 'None':
        """The short-circuit skips work, it does not change what was parsed."""
        from pcapkit.protocols.internet.esp import ESP

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            as_ext = ESP(io.BytesIO(ESP_NO_KEYS), len(ESP_NO_KEYS), version=6, extension=True)
            standalone = ESP(io.BytesIO(ESP_NO_KEYS), len(ESP_NO_KEYS), version=6, extension=False)

        for field in ('spi', 'seq', 'length', 'status'):
            with self.subTest(field=field):
                self.assertEqual(getattr(as_ext.info, field), getattr(standalone.info, field))


class ESPMatchesItsSiblingsTests(unittest.TestCase):
    """``AH`` as the control: ``ESP`` is being aligned, not special-cased."""

    def test_ah_already_behaves_this_way(self) -> 'None':
        """If this ever fails, the invariant moved rather than ``ESP`` regressing."""
        from pcapkit.protocols.internet.ah import AH

        self.assertEqual(_decode_calls(AH, AH_HEADER, extension=True), 0)
        self.assertEqual(_decode_calls(AH, AH_HEADER, extension=False), 1)

    def test_every_decode_next_layer_return_is_guarded(self) -> 'None':
        """Source-level sweep over the whole family.

        Asserted against the source rather than at runtime because several of
        the eight need a well-formed body to parse at all, and a fixture per
        header would pin those bodies rather than this invariant.

        **The guard must sit immediately before the return it guards.** A
        first draft of this test merely looked for ``if extension:`` or ``if
        self._extf:`` anywhere in the file, and passed on unfixed ``ESP`` --
        because ``ESP.protocol`` already consults ``self._extf`` for an
        unrelated reason. That version asserted something true and useless. This
        one pairs each ``return self._decode_next_layer(`` with the line above
        it, which is what actually distinguishes a guarded return from an
        unguarded one. ``ESP`` is allowed ``self._extf`` in place of the
        ``extension`` parameter, since ``_make_opaque`` does not take one.

        """
        import pathlib
        import re

        import pcapkit.protocols.internet as package

        root = pathlib.Path(package.__file__).parent
        family = ('hopopt', 'ipv6_route', 'ipv6_frag', 'ipv6_opts', 'mh', 'hip', 'ah', 'esp')
        guard = re.compile(r'^\s+if (?:extension|self\._extf):$')

        for module in family:
            with self.subTest(module=module):
                lines = (root / f'{module}.py').read_text(encoding='utf-8').splitlines()
                returns = [n for n, line in enumerate(lines)
                           if 'return self._decode_next_layer(' in line]
                self.assertTrue(returns, f'{module}.py never calls _decode_next_layer')

                for n in returns:
                    # the guard is `if …:` / `return <data>` / `return self._decode…`
                    window = lines[max(0, n - 2):n]
                    self.assertTrue(
                        any(guard.match(line) for line in window),
                        f'{module}.py:{n + 1} returns _decode_next_layer with no '
                        f'`if extension:` / `if self._extf:` guard in the two lines above '
                        f'it -- every IPv6 extension header must stop before decoding the '
                        f'next layer when parsed as one link of a chain (GitHub issue #895)',
                    )


if __name__ == '__main__':
    unittest.main()
