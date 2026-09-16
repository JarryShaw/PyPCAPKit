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

    def test_layer_and_protocol_reach_the_extractor(self) -> None:
        """``-L``/``-P`` are forwarded under the names ``Extractor`` reads.

        The CLI half of GH-356. The forwarding was always correct -- it is the
        core that dropped the limits -- so this pins the contract that made it
        correct: ``Extractor`` takes ``layer=`` and ``protocol=``, and the CLI
        must not invent its own spelling for either.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, extractor_cls, _ = self._load_cli_module(emoji_module=emoji)

        with mock.patch.object(sys, 'argv', ['pcapkit-cli', 'capture.pcap',
                                            '-L', 'internet', '-P', 'TCP']):
            self.assertEqual(module.main(), 0)

        created = extractor_cls.created[-1]
        self.assertEqual(created.kwargs['layer'], 'internet')
        self.assertEqual(created.kwargs['protocol'], 'TCP')

    def test_layer_defaults_to_none_and_is_case_insensitive(self) -> None:
        """An omitted ``-L``/``-P`` forwards :data:`None`, not a sentinel string.

        ``Extractor.__init__`` substitutes its own ``'none'``/``'null'`` for an
        omitted value, so the CLI has nothing to substitute. It used to pass the
        strings ``'None'`` and ``'null'``, which only worked because
        ``Extractor`` happened to lowercase the former into the sentinel it
        wanted.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, _, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()

        bare = parser.parse_args(['input.pcap'])
        self.assertIsNone(bare.layer)
        self.assertIsNone(bare.protocol)

        # ``-L Internet`` still works: the value is lowercased before it is
        # matched against the layer names.
        self.assertEqual(parser.parse_args(['input.pcap', '-L', 'Internet']).layer, 'internet')
        self.assertEqual(parser.parse_args(['input.pcap', '--layer', 'LINK']).layer, 'link')

    def test_layer_rejects_a_name_that_is_not_a_layer(self) -> None:
        """A misspelled ``-L`` fails loudly rather than being ignored.

        The layer names are a closed set and nothing downstream validates them:
        an unknown name simply never matches a protocol's ``__layer__``, so the
        parse runs to the top of the stack and the user is given a full report
        they did not ask for -- silently, which is the failure GH-356 was about.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, _, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()

        with mock.patch('sys.stderr', io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(['input.pcap', '-L', 'nonsense'])

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
