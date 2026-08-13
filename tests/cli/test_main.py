from __future__ import annotations

import importlib.util
import io
import pathlib
import sys
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]


class CLIMainTests(unittest.TestCase):
    def _load_cli_module(self, *, emoji_module=Ellipsis):
        for name in list(sys.modules):
            if name == 'pcapkit' or name.startswith('pcapkit.') or name == 'emoji':
                sys.modules.pop(name, None)

        pcapkit_pkg = types.ModuleType('pcapkit')
        pcapkit_pkg.__version__ = '9.9.9'
        pcapkit_pkg.__path__ = [str(ROOT / 'pcapkit')]
        sys.modules['pcapkit'] = pcapkit_pkg

        foundation_pkg = types.ModuleType('pcapkit.foundation')
        foundation_pkg.__path__ = []
        sys.modules['pcapkit.foundation'] = foundation_pkg

        extraction_module = types.ModuleType('pcapkit.foundation.extraction')

        class Extractor:
            created = []

            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.input = kwargs['fin']
                self.output = kwargs['fout']
                type(self).created.append(self)

            def __iter__(self):
                return iter([1, 2])

        extraction_module.Extractor = Extractor
        sys.modules['pcapkit.foundation.extraction'] = extraction_module

        interface_module = types.ModuleType('pcapkit.interface')
        interface_module.JSON = 'JSON'
        interface_module.PLIST = 'PLIST'
        interface_module.TREE = 'TREE'
        sys.modules['pcapkit.interface'] = interface_module

        compat_module = types.ModuleType('pcapkit.utilities.compat')
        compat_module.ModuleNotFoundError = ModuleNotFoundError
        sys.modules['pcapkit.utilities.compat'] = compat_module

        exceptions_module = types.ModuleType('pcapkit.utilities.exceptions')
        exceptions_module.stacklevel = lambda: 1
        sys.modules['pcapkit.utilities.exceptions'] = exceptions_module

        warnings_module = types.ModuleType('pcapkit.utilities.warnings')
        warnings_module.EmojiWarning = type('EmojiWarning', (Warning,), {})
        warnings_module.warn = mock.Mock()
        sys.modules['pcapkit.utilities.warnings'] = warnings_module

        if emoji_module is not Ellipsis:
            if emoji_module is None:
                sys.modules.pop('emoji', None)
            else:
                sys.modules['emoji'] = emoji_module

        spec = importlib.util.spec_from_file_location('pcapkit.__main__', ROOT / 'pcapkit' / '__main__.py')
        module = importlib.util.module_from_spec(spec)
        assert spec is not None and spec.loader is not None
        sys.modules['pcapkit.__main__'] = module
        spec.loader.exec_module(module)
        return module, extraction_module.Extractor, warnings_module.warn

    def test_get_parser_parses_expected_arguments(self) -> None:
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, _, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()
        args = parser.parse_args(['input.pcap', '-o', 'out.json', '-j', '-F'])

        self.assertEqual(args.fin, 'input.pcap')
        self.assertEqual(args.fout, 'out.json')
        self.assertTrue(args.json)
        self.assertTrue(args.files)

    def test_main_uses_json_format_and_stdin_when_requested(self) -> None:
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, extractor_cls, _ = self._load_cli_module(emoji_module=emoji)

        fake_stdin = types.SimpleNamespace(buffer=io.BytesIO(b'data'))
        with mock.patch.object(sys, 'argv', ['pcapkit-cli', '-', '--json', '--buffer-save']), \
             mock.patch.object(sys, 'stdin', fake_stdin):
            result = module.main()

        self.assertEqual(result, 0)
        created = extractor_cls.created[-1]
        self.assertIs(created.kwargs['fin'], fake_stdin.buffer)
        self.assertEqual(created.kwargs['format'], 'JSON')
        self.assertTrue(created.kwargs['no_eof'])
        self.assertTrue(created.kwargs['buffer_save'])

    def test_main_verbose_mode_prints_fallback_when_emojize_fails(self) -> None:
        class BrokenEmoji:
            @staticmethod
            def emojize(text):
                raise UnicodeEncodeError('utf-8', 'x', 0, 1, 'boom')

        module, extractor_cls, _ = self._load_cli_module(emoji_module=BrokenEmoji())

        fake_stdout = io.StringIO()
        with mock.patch.object(sys, 'argv', ['pcapkit-cli', 'capture.pcap', '--tree', '--verbose']), \
             mock.patch('sys.stdout', fake_stdout):
            result = module.main()

        self.assertEqual(result, 0)
        created = extractor_cls.created[-1]
        self.assertEqual(created.kwargs['format'], 'TREE')
        output = fake_stdout.getvalue()
        self.assertIn("[*] Loading file 'capture.pcap'", output)
        self.assertIn('[*] Report file stored in None', output)


if __name__ == '__main__':
    unittest.main()
