from __future__ import annotations

import importlib.util
from types import SimpleNamespace
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FTPUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_ftp_length_is_unsupported(self) -> None:
        from pcapkit.protocols.application.application import Application
        from pcapkit.protocols.application.ftp import FTP
        from pcapkit.utilities.exceptions import UnsupportedCall

        ftp = object.__new__(FTP)

        self.assertEqual(ftp.layer, 'Application')
        self.assertEqual(Application.layer.__get__(ftp), 'Application')
        self.assertEqual(ftp.name, 'File Transfer Protocol')
        with self.assertRaises(UnsupportedCall):
            _ = ftp.length

    def test_ftp_read_parses_request_response_and_rejects_invalid(self) -> None:
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.ftp.return_code import ReturnCode
        from pcapkit.protocols.application.ftp import FTP, Type
        from pcapkit.utilities.exceptions import ProtocolError

        ftp = object.__new__(FTP)
        ftp.__cached__ = {}

        ftp._data = b'USER guest\r\n'
        ftp.__header__ = SimpleNamespace(data=b'USER guest\r\n')
        self.assertEqual(ftp.read().args, 'guest')

        ftp.__header__ = SimpleNamespace(data=b'USER anonymous\r\n')
        request = ftp.read(length=16)
        self.assertEqual(request.type, Type.REQUEST)
        self.assertEqual(request.cmmd, Command.USER)
        self.assertEqual(request.args, 'anonymous')

        ftp.__header__ = SimpleNamespace(data=b'220- Ready\r\n')
        response = ftp.read(length=12)
        self.assertEqual(response.type, Type.RESPONSE)
        self.assertEqual(response.code, ReturnCode.CODE_220)
        self.assertTrue(response.more)
        self.assertEqual(response.args, 'Ready')

        ftp.__header__ = SimpleNamespace(data=b'!!\r\n')
        with self.assertRaises(ProtocolError):
            ftp.read(length=4)

    def test_command_get_is_case_insensitive(self) -> None:
        """``Command.get`` normalised the key it registered but not the key it
        looked up, so the first lowercase command raised ``TypeError`` instead
        of resolving -- #582.

        :rfc:`959#section-5.3` makes FTP commands case-insensitive -- "Upper and
        lower case alphabetic characters are to be treated identically. Thus, any
        of the following may represent the retrieve command: ``RETR Retr retr
        ReTr rETr``" -- so every casing of a registered command has to resolve to
        the *same* member rather than to a second one registered alongside it.

        The citation is section 5.3 (COMMANDS, which gives the command syntax),
        not section 4.1 (FTP COMMANDS, which only lists the per-command
        semantics); #582 cited 4.1 and a cross-review caught it. Verified against
        the RFC text: the sentence sits between the 5.3 and 5.4 headings. The
        ``:rfc:`959#section-4.1``` citations in
        :mod:`pcapkit.const.ftp.command` are a different claim -- the command
        *kind* (access control, transfer parameter, service) -- and are correct.
        """
        from pcapkit.const.ftp.command import Command

        for key in ('RETR', 'retr', 'ReTr', 'rEtR'):
            with self.subTest(key=key):
                self.assertIs(Command.get(key), Command.RETR)

        # ``_missing_`` carried the identical mismatch, so the value-lookup
        # form raised too.
        self.assertIs(Command('retr'), Command.RETR)

        # A genuinely unknown command still registers, under its canonical
        # upper-case name, and does not create a case-variant duplicate.
        unknown = Command.get('xyzw')
        self.assertEqual(unknown._name_, 'XYZW')
        self.assertIs(Command.get('XYZW'), unknown)
        self.assertEqual([name for name in Command._member_map_
                          if name.upper() == 'RETR'], ['RETR'])

    def test_ftp_read_parses_a_lowercase_request(self) -> None:
        """The case-insensitivity is reachable from wire data: ``ftp.py``
        compiles ``FTP_REQUEST`` with :data:`re.I` and passes the match
        verbatim, so a lowercase request used to crash the parse -- #582.
        """
        from pcapkit.const.ftp.command import Command
        from pcapkit.protocols.application.ftp import FTP, Type

        ftp = object.__new__(FTP)
        ftp.__cached__ = {}

        for raw, command, args in ((b'retr file.txt\r\n', Command.RETR, 'file.txt'),
                                   (b'Retr file.txt\r\n', Command.RETR, 'file.txt'),
                                   (b'user guest\r\n', Command.USER, 'guest'),
                                   (b'RETR file.txt\r\n', Command.RETR, 'file.txt')):
            with self.subTest(raw=raw):
                ftp.__header__ = SimpleNamespace(data=raw)
                ftp._data = raw
                request = ftp.read(length=len(raw))
                self.assertEqual(request.type, Type.REQUEST)
                self.assertIs(request.cmmd, command)
                self.assertEqual(request.args, args)

    def test_ftp_make_builds_request_and_response_packets(self) -> None:
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.ftp.return_code import ReturnCode
        from pcapkit.protocols.application.ftp import FTP

        ftp = object.__new__(FTP)
        request = ftp.make(cmmd=Command.USER, args='anonymous')
        request_bytes = ftp.make(cmmd=b'NOOP')
        request_value = ftp.make(cmmd=SimpleNamespace(value=b'PWD'))
        response = ftp.make(code=ReturnCode.CODE_220, args='Ready', more=True)
        response_bytes = ftp.make(code=b'230', args=b'Logged in')

        self.assertEqual(request.data, b'USER anonymous')
        self.assertEqual(request_bytes.data, b'NOOP ')
        self.assertEqual(request_value.data, b'PWD ')
        self.assertEqual(response.data, b'220- Ready')
        self.assertEqual(response_bytes.data, b'230 Logged in')

    def test_ftp_make_rejects_ambiguous_packet_type(self) -> None:
        from pcapkit.protocols.application.ftp import FTP
        from pcapkit.utilities.exceptions import ProtocolError

        ftp = object.__new__(FTP)

        with self.assertRaises(ProtocolError):
            ftp.make()
        with self.assertRaises(ProtocolError):
            ftp.make(cmmd='USER', code=220)

    def test_ftp_make_data_preserves_request_and_response_fields(self) -> None:
        from pcapkit.const.ftp.command import Command
        from pcapkit.const.ftp.return_code import ReturnCode
        from pcapkit.protocols.application.ftp import FTP

        request = DummyData(cmmd=Command.USER, code=None, args='anonymous', more=False)
        response = DummyData(cmmd=None, code=ReturnCode.CODE_220, args='Ready', more=True)

        self.assertEqual(
            FTP._make_data(request),
            {'cmmd': Command.USER, 'code': None, 'args': 'anonymous', 'more': False},
        )
        self.assertEqual(
            FTP._make_data(response),
            {'cmmd': None, 'code': ReturnCode.CODE_220, 'args': 'Ready', 'more': True},
        )

    def test_ftp_data_channel_name_is_stable(self) -> None:
        from pcapkit.protocols.application.ftp import FTP_DATA

        ftp_data = object.__new__(FTP_DATA)

        self.assertEqual(ftp_data.name, 'FTP_DATA')

    def test_application_base_post_init_and_unsupported_hooks(self) -> None:
        from pcapkit.protocols.application.application import Application
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.utilities.exceptions import IntError, UnsupportedCall

        class DummyApplication(Application):
            @property
            def name(self) -> str:
                return 'Dummy Application'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

        app = object.__new__(DummyApplication)

        with mock.patch.object(ProtocolBase, '__post_init__', return_value=None) as post_init:
            app.__post_init__(custom=True)
        post_init.assert_called_once()
        self.assertIn('DummyApplication', str(app._protos))

        with self.assertRaises(IntError):
            DummyApplication.__index__()
        with self.assertRaises(UnsupportedCall):
            app._decode_next_layer({}, None, None)
        with self.assertRaises(UnsupportedCall):
            app._import_next_layer(0)


if __name__ == '__main__':
    unittest.main()
