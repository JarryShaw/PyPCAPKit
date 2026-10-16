# -*- coding: utf-8 -*-
""":mod:`pcapkit.__main__`, against stand-ins for everything it imports.

The command line tool is tested without the library behind it: :mod:`pcapkit`,
:mod:`pcapkit.foundation.extraction`, :mod:`pcapkit.interface`, three
:mod:`pcapkit.utilities` modules and :mod:`emoji` are all replaced with
stand-ins, so what is under test is the argument wiring and nothing else. The
real thing runs in :mod:`tests.integration.test_cli_subprocess`.

:data:`sys.modules` is process-global, so binding a stand-in over a real module
name is a write that outlives the test unless something undoes it -- and these
stand-ins are *emptier* than what they replace, which is the quiet kind. Issue
#688: this file wrote nine names and put none of them back -- the seven stand-ins
above, the bare ``pcapkit.foundation`` parent they hang from, and
``pcapkit.__main__`` itself. Pairing it with :mod:`tests.project.test_public_api`
gave ten errors: nine ``ImportError: cannot import name 'show_flag_values' from
'pcapkit.utilities.compat'`` and one for ``SeekError``, because the real library's
next import found a ``pcapkit.utilities.compat`` carrying exactly one name.

That is the same defect as issues #660 and #674, and it is fixed the same way:
:func:`tests._support.isolate_modules` in ``setUp``, which purges the region on
the way in and restores it exactly on the way out. What this file used to do
instead was roll its own purge loop, which protects this file from whatever ran
before it and promises nothing to whatever runs after -- see
:func:`tests._support.purge_modules` for why restoration is owed by the code that
binds.

:func:`tests.conftest.restore_module_table` masked the symptom under
:program:`pytest` throughout, which is why it took an audit to find: it surfaces
only under ``--noconftest``, under the stdlib :mod:`unittest` runner, or on any
route that does not load that conftest.
:meth:`CLIMainTests.assert_module_table_restored` is checked in a cleanup
registered *before* the isolation, so it runs after the restore and is not
masked by that fixture -- a regression here fails under a plain
:program:`pytest` run rather than waiting for someone to try another runner.

"""
from __future__ import annotations

import importlib.util
import io
import pathlib
import re
import sys
import types
import unittest
from unittest import mock

from tests._support import ISOLATED_PREFIXES, isolate_modules, snapshot_modules

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The :data:`sys.modules` region this file stands things in for, and therefore
#: the region it has to put back.
#:
#: Wider than :data:`tests._support.ISOLATED_PREFIXES` by ``'emoji'``, which is
#: the one stand-in here that is not part of :mod:`pcapkit`.
#: :func:`tests.conftest.restore_module_table` covers only the default prefixes,
#: so the faked ``emoji`` was not merely unrestored but *unmasked* as well: it
#: survived even a normal :program:`pytest` run, leaving whatever imported
#: :mod:`emoji` next with a :class:`~types.SimpleNamespace` carrying nothing but
#: ``emojize`` -- or, from the last test here, a class whose ``emojize`` raises
#: :exc:`UnicodeEncodeError`.
ISOLATED = ISOLATED_PREFIXES + ('emoji',)

#: How many module names :func:`summarise_names` spells out before it starts
#: counting instead. Bounded because the interesting list is long: on a warm
#: module table the :mod:`pcapkit` region holds some three hundred names, so an
#: unbounded report of what a leak did to it is twelve kilobytes of failure
#: message that nobody reads -- measured, at 12089 characters.
NAMES_IN_FAILURE_MESSAGE = 8


def summarise_names(label: str, names: 'list[str]') -> str:
    """``label``, how many of ``names`` there are, and the first few of them.

    Args:
        label: What went wrong with these names -- ``'added'`` and its siblings.
        names: The names, already sorted.

    Returns:
        A one-line summary, or the empty string when ``names`` is empty, so that
        the caller can drop the directions that are fine.

    """
    if not names:
        return ''
    shown = ', '.join(names[:NAMES_IN_FAILURE_MESSAGE])
    extra = len(names) - NAMES_IN_FAILURE_MESSAGE
    return f'{label} {len(names)} ({shown}{f", +{extra} more" if extra > 0 else ""})'


class CLIMainTests(unittest.TestCase):
    def setUp(self) -> None:
        # Registered *before* ``isolate_modules`` and deliberately so: cleanups
        # run last-in-first-out, so this one runs after the restore that
        # ``isolate_modules`` registers and can check that the restore actually
        # happened. Registered the other way round it would run first, see the
        # stand-ins still bound, and fail every test.
        self.addCleanup(self.assert_module_table_restored, snapshot_modules(ISOLATED))

        # ``isolate_modules`` rather than a purge loop of this file's own: the
        # stand-ins below are bound over real module names, and purging protects
        # only this test while restoring is what the *next* one needs (#688).
        isolate_modules(self, ISOLATED)

    def assert_module_table_restored(self, before: 'dict[str, types.ModuleType]') -> None:
        """The :data:`ISOLATED` region of :data:`sys.modules` is as it was found.

        The regression assertion for issue #688, and exact in all three
        directions a restore can be wrong: a name this test added, a name it
        dropped, and a name it rebound to something else. Absence matters as much
        as presence -- ``pcapkit.utilities.compat`` did not exist before a test
        here ran on a cold table, so it must not exist after one either, and a
        check written as a :meth:`dict.update` of the snapshot would have missed
        exactly that.

        Args:
            before: The snapshot taken in ``setUp``, before anything was purged
                or bound.

        """
        after = snapshot_modules(ISOLATED)
        problems = [summary for summary in (
            summarise_names('added', sorted(set(after) - set(before))),
            summarise_names('removed', sorted(set(before) - set(after))),
            summarise_names('rebound', sorted(name for name in set(before) & set(after)
                                              if after[name] is not before[name])),
        ) if summary]

        self.assertEqual(
            problems, [],
            f'this test left the {ISOLATED} region of sys.modules different from how it '
            f'found it -- {"; ".join(problems)}. The stand-ins bound here are emptier '
            f'than the modules they replace, so whatever imports the real library next '
            f'gets a package with almost no attributes rather than an error naming this '
            f'file. See issue #688.')

    def _load_cli_module(self, *, emoji_module=Ellipsis):
        # No purge here: ``setUp``'s ``isolate_modules`` has already emptied the
        # region, and it is the half that also puts it back afterwards.
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
                # A no-op since the isolation covers ``'emoji'`` -- the name is
                # already gone. Kept as the explicit spelling of "leave nothing
                # bound", so the caller reads the same either way.
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

    def test_output_help_describes_the_output_file(self) -> None:
        """``-o``'s help names the output report, not the input capture.

        Issue #1796: the help was copied from the positional ``input-file-name``
        and read "The name of input pcap file", so ``--help`` said ``-o`` named
        the file being *read*. It also said the extension is always appended,
        but :func:`~pcapkit.__main__.main` forwards ``-a``/``--auto-extension``
        as ``Extractor(extension=...)``, which is off by default.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, _, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()
        action = next(action for action in parser._actions  # pylint: disable=protected-access
                      if action.dest == 'fout')
        self.assertEqual(action.option_strings, ['-o', '--output'])

        text = action.help.lower()
        self.assertIn('output', text)
        self.assertNotIn('input', text)
        # ``Extractor.__init__`` substitutes "out" for an omitted ``fout``.
        self.assertIn('"out"', text)
        # The extension depends on ``-a``, and ``-F`` makes ``fout`` a directory.
        self.assertIn('--auto-extension', text)
        self.assertIn('--files', text)

    def test_input_help_ties_the_pcap_extension_to_auto_extension(self) -> None:
        """``input-file-name``'s help appends ``.pcap`` only under ``-a``.

        Issue #1796: the help said ".pcap" is always appended when omitted, but
        :meth:`~pcapkit.foundation.extraction.Extractor.make_name` appends it
        only with ``extension=True`` -- ``-a`` -- and then unless the name
        already ends in one of ``Extractor.PCAP_EXT``. Without ``-a``,
        ``pcapkit-cli in`` fails with ``FileNotFound`` for ``in``.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, _, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()
        action = next(action for action in parser._actions  # pylint: disable=protected-access
                      if action.dest == 'fin')

        text = action.help.lower()
        self.assertIn('--auto-extension', text)
        self.assertNotIn('automatically appended', text)
        # ``Extractor.PCAP_EXT``: a name already ending in one is left alone.
        self.assertIn('".cap"', text)
        self.assertIn('".pcapng"', text)

    def test_auto_extension_help_covers_input_and_output(self) -> None:
        """``-a``'s help names the input extension as well as the output one.

        Issue #1796: the help mentioned only the output file, but ``-a`` is
        forwarded as ``Extractor(extension=...)``, which
        :meth:`~pcapkit.foundation.extraction.Extractor.make_name` applies to
        the input name too -- and not to ``fout`` under ``-F``, where it is a
        directory.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, _, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()
        action = next(action for action in parser._actions  # pylint: disable=protected-access
                      if action.dest == 'auto_extension')

        text = action.help.lower()
        self.assertIn('input', text)
        self.assertIn('".pcap"', text)
        self.assertIn('--files', text)

    @staticmethod
    def _named_options(pattern: str, text: str) -> 'set[str]':
        """The backquoted options in the clause of ``text`` that ``pattern`` finds.

        Args:
            pattern: A regular expression whose first group is the clause.
            text: A help string.

        Returns:
            The options named in the clause, such as ``'--json'``, or an empty
            set when ``text`` has no such clause.

        """
        match = re.search(pattern, text)
        return set(re.findall(r'`(--[a-z-]+)`', match.group(1))) if match else set()

    def _forwarded_format(self, module, extractor_cls, *argv: str):
        """The ``format=`` that :func:`main` hands ``Extractor`` for ``argv``."""
        with mock.patch.object(sys, 'argv', ['pcapkit-cli', 'capture.pcap', *argv]):
            self.assertEqual(module.main(), 0)
        return extractor_cls.created[-1].kwargs['format']

    def test_format_switch_help_names_what_overrides_it(self) -> None:
        """``-j``, ``-p`` and ``-t`` each name exactly the options that beat them.

        Issue #1796: each of them said "This option overrides all other
        options", which cannot hold for all of them at once, and holds for none:
        :func:`~pcapkit.__main__.main` tests ``--format`` first, then
        ``--json``, then ``--plist``, then ``--tree``. So each help's "Ignored
        if ... is given" clause is checked against what ``main`` forwards when
        the switch is given together with each other format option.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, extractor_cls, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()
        helps = {action.dest: action.help for action in parser._actions}  # pylint: disable=protected-access
        # ``pcap`` is no stand-in constant, so a ``--format`` win is visible.
        options = {'--format': ('--format', 'pcap'), '--json': ('--json',),
                   '--plist': ('--plist',), '--tree': ('--tree',)}

        for switch in ('--json', '--plist', '--tree'):
            with self.subTest(switch=switch):
                text = helps[switch[2:]]
                alone = self._forwarded_format(module, extractor_cls, switch)
                winners = {other for other, argv in options.items() if other != switch
                           and self._forwarded_format(module, extractor_cls, switch, *argv) != alone}
                self.assertNotIn('overrides all other options', text)
                self.assertEqual(self._named_options(r'Ignored if (.+?) (?:is|are) given', text),
                                 winners)

    def test_format_help_names_the_switches_it_overrides(self) -> None:
        """``-f``'s help lists the real formats and the switches it beats.

        Issue #1796: it said "Available are all formats supported by
        dictdumper", but the formats are the keys of ``Extractor.__output__``,
        which include ``pcap``, a :mod:`pcapkit.dumpkit` writer, and it said
        nothing of ``-j``/``-p``/``-t``, which :func:`~pcapkit.__main__.main`
        consults only when ``--format`` is not given. With no format option at
        all ``main`` forwards :data:`None`, and ``Extractor.__init__``
        substitutes ``tree``.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, extractor_cls, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()
        text = next(action.help for action in parser._actions  # pylint: disable=protected-access
                    if action.dest == 'format')
        beaten = {switch for switch in ('--json', '--plist', '--tree')
                  if self._forwarded_format(module, extractor_cls, '--format', 'pcap', switch) == 'pcap'}

        self.assertNotIn('dictdumper', text)
        self.assertIn('"pcap"', text)
        self.assertIn('no format option, "tree" is used', text)
        self.assertEqual(self._named_options(r'precedence over (.+?)\.', text), beaten)

    def test_help_strings_have_no_known_slips(self) -> None:
        """No help string keeps a slip the rendered-docs proofread found.

        Issue #1796, from the #1103 proofread: "a extraction", "if ... omits"
        for "is omitted", "Indicate if store buffer", and the unbalanced
        quotes of ``stdin'``.

        """
        emoji = types.SimpleNamespace(emojize=lambda text: text)
        module, _, _ = self._load_cli_module(emoji_module=emoji)

        parser = module.get_parser()
        slips = ('a extraction', 'omits', 'Indicate if', "`stdin'")
        found = [(action.dest, slip) for action in parser._actions  # pylint: disable=protected-access
                 for slip in slips if slip in (action.help or '')]
        self.assertEqual(found, [])

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
