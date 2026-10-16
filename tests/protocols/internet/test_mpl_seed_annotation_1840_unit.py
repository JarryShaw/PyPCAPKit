# -*- coding: utf-8 -*-
"""The MPL option schemas annotate ``seed`` as the values it actually holds.

GitHub issue #1840: ``MPLOption.seed`` in the HOPOPT and IPv6-Opts schemas was
annotated ``'int'``, and its ``__init__`` stub's ``seed`` ``'Optional[int]'``.
When ``S`` is 0 (:rfc:`7731#section-6.1`) the seed is the IPv6 source address,
which ``post_process`` stores as an :class:`~ipaddress.IPv6Address`; the data
models already say ``Optional[int | IPv6Address]``.

The annotations are string literals naming ``TYPE_CHECKING``-only imports, so
they are checked by the names they use rather than evaluated. The ``__init__``
stub exists only under ``TYPE_CHECKING``, so it is read from the module source.
The runtime cases build their octets in memory and read no capture, as in
:mod:`tests.protocols.internet.test_mpl_seed_rebuild_unit`.

"""

import ast
import ipaddress
import pathlib
import struct
import unittest

from tests._support import reimport_once_per_class

#: Extension headers carrying one MPL option (type 0x6D), next header 59, one
#: per seed-id kind. Flags ``M`` set, sequence 7. The 64- and 128-bit seeds are
#: 5, so only the ``S`` field sets their width.
HEADERS = {
    0: bytes.fromhex('3b006d0220070000'),
    1: bytes.fromhex('3b006d046007beef'),
    2: bytes.fromhex('3b016d0aa007' '0000000000000005' '0000'),
    3: bytes.fromhex('3b026d12e007' '00000000000000000000000000000005' '0000'),
}

#: Integer seed each non-address kind carries in :data:`HEADERS`.
INT_SEEDS = {1: 0xBEEF, 2: 5, 3: 5}

SRC = ipaddress.IPv6Address('2001:db8::1')
DST = ipaddress.IPv6Address('2001:db8::2')


def _names(annotation: 'str') -> 'set[str]':
    """Return every name a string annotation uses."""
    tree = ast.parse(annotation, mode='eval')
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}


def _schemas() -> 'dict[str, tuple[object, int]]':
    from pcapkit.const.ipv6.extension_header import ExtensionHeader
    from pcapkit.protocols.schema.internet import hopopt, ipv6_opts
    return {
        'HOPOPT': (hopopt, ExtensionHeader.HOPOPT),
        'IPv6_Opts': (ipv6_opts, ExtensionHeader.IPv6_Opts),
    }


def _init_stub_seed(module: 'object') -> 'str':
    """Return the ``seed`` annotation of ``MPLOption.__init__`` in ``module``'s source."""
    tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding='utf-8'))  # type: ignore[attr-defined]
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef) and cls.name == 'MPLOption':
            for node in ast.walk(cls):
                if isinstance(node, ast.FunctionDef) and node.name == '__init__':
                    for arg in node.args.args:
                        if arg.arg == 'seed':
                            return ast.literal_eval(arg.annotation)  # type: ignore[arg-type]
    raise AssertionError('MPLOption.__init__ stub has no seed parameter')


class TestMPLSeedAnnotation(unittest.TestCase):
    """Pin the ``seed`` annotations and the runtime types they describe."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_seed_field_annotation_names_ipv6address(self) -> None:
        for name, (module, _) in _schemas().items():
            with self.subTest(proto=name):
                annotation = module.MPLOption.__annotations__['seed']  # type: ignore[attr-defined]
                self.assertEqual(_names(annotation), {'int', 'IPv6Address'})

    def test_init_stub_seed_annotation_names_ipv6address(self) -> None:
        for name, (module, _) in _schemas().items():
            with self.subTest(proto=name):
                self.assertEqual(_names(_init_stub_seed(module)), {'Optional', 'int', 'IPv6Address'})

    def test_seed_types_inside_ipv6(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        for name, (module, code) in _schemas().items():
            for kind, octets in HEADERS.items():
                with self.subTest(proto=name, S=kind):
                    packet = (struct.pack('!IHBB', 6 << 28, len(octets), int(code), 64)
                              + SRC.packed + DST.packed + octets)
                    exthdrs = IPv6(packet, len(packet)).extension_headers
                    self.assertEqual(list(exthdrs.keys()), [code])
                    options = list(exthdrs.values())[0].schema.options
                    mpl = [opt for opt in options if isinstance(opt, module.MPLOption)]  # type: ignore[attr-defined]
                    self.assertEqual(len(mpl), 1)
                    seed = mpl[0].seed
                    if kind == 0:
                        self.assertIsInstance(seed, ipaddress.IPv6Address)
                        self.assertEqual(seed, SRC)
                    else:
                        self.assertIs(type(seed), int)
                        self.assertEqual(seed, INT_SEEDS[kind])


if __name__ == '__main__':
    unittest.main()
