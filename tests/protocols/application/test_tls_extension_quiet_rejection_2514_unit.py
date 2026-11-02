# -*- coding: utf-8 -*-
"""A TLS extension body its decoder rejects is kept raw, quietly (#2514).

``SSL._read_tls_extensions`` catches the decoder's ``ProtocolError`` and keeps
the octets, so the error is control flow: it logs nothing and leaves
``sys.excepthook`` and ``threading.excepthook`` alone. That holds for a shipped
decoder, which raises an ordinary loud error, and for a registered one.

"""
from __future__ import annotations

import sys
import threading
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): checks that the exception hooks are left alone.
__tier__ = 'ALL'


def _ext(code: int, data: bytes) -> bytes:
    return code.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def _vec(data: bytes, width: int = 2) -> bytes:
    return len(data).to_bytes(width, 'big') + data


def _client_hello(*extensions: bytes) -> bytes:
    body = (b'\x03\x03' + bytes(32) + b'\x00' + _vec(b'\x13\x01') + _vec(b'\x00', 1)
            + _vec(b''.join(extensions)))
    fragment = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + len(fragment).to_bytes(2, 'big') + fragment


class QuietRejectionTests(unittest.TestCase):
    """A rejected body keeps its octets, logs nothing and installs no hook."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        saved_sys, saved_threading = sys.excepthook, threading.excepthook

        def _restore() -> None:
            sys.excepthook = saved_sys
            threading.excepthook = saved_threading

        self.addCleanup(_restore)

        def _sys_sentinel(*args: 'Any') -> None:
            saved_sys(*args)

        def _threading_sentinel(args: 'Any') -> None:
            saved_threading(args)

        self.sys_sentinel, self.threading_sentinel = _sys_sentinel, _threading_sentinel
        sys.excepthook, threading.excepthook = _sys_sentinel, _threading_sentinel

    def _parse_quietly(self, wire: bytes) -> 'tuple':
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities import exceptions
        from pcapkit.utilities.logging import logger

        with capture(logger) as package, capture(exceptions.logger) as module:
            parsed = TLS(wire, len(wire))
        self.assertEqual(package.messages, [])
        self.assertEqual(module.messages, [])
        self.assertIs(sys.excepthook, self.sys_sentinel)
        self.assertIs(threading.excepthook, self.threading_sentinel)
        self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())
        return parsed.info.content[0].body.extensions

    def test_a_shipped_decoders_rejection_is_quiet(self) -> None:
        for name, extension in {
                'alpn list length mismatch': _ext(16, b'\x00\x09\x02h2'),
                'supported_groups odd length': _ext(10, _vec(b'\x00\x1d\x00')),
                'supported_versions odd length': _ext(43, _vec(b'\x03\x04\x03', 1)),
        }.items():
            with self.subTest(case=name):
                ext, = self._parse_quietly(_client_hello(extension))
                self.assertEqual(ext.data, extension[4:])

    def test_a_registered_decoders_loud_rejection_is_quiet(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.foundation.registry.protocols import register_tls_extension
        from pcapkit.protocols.application.ssl import SSL
        from pcapkit.utilities import exceptions
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.logging import logger

        def parser(ext_type: object, data: bytes, *, msg_type: object) -> bytes:  # pylint: disable=unused-argument
            raise ProtocolError('padding: rejected')

        def constructor(ext_type: object, data: object = None, *, msg_type: object,  # pylint: disable=unused-argument
                        **kwargs: object) -> bytes:
            return b''

        # The same error, constructed outside the parse, is loud.
        with capture(logger) as package, capture(exceptions.logger) as module:
            ProtocolError('padding: rejected')
        self.assertIn(('CRITICAL', 'ProtocolError: padding: rejected'), package.messages + module.messages)
        sys.excepthook, threading.excepthook = self.sys_sentinel, self.threading_sentinel

        shipped = dict(SSL.__extension__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                register_tls_extension(ExtensionType.padding, (parser, constructor))
            ext, = self._parse_quietly(_client_hello(_ext(21, bytes(3))))
            self.assertEqual(ext.data, bytes(3))
        finally:
            SSL.__extension__.clear()
            SSL.__extension__.update(shipped)


if __name__ == '__main__':
    unittest.main()
