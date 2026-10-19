# -*- coding: utf-8 -*-
"""Command Line Tool
=======================

.. module:: pcapkit.__main__

.. important::

   The |emoji|_ package is optional. Without it, importing this module
   warns :class:`~pcapkit.utilities.warnings.EmojiWarning` and the verbose
   messages print as plain text.

:mod:`pcapkit.__main__` was originally the module file of
|jspcapy|_, which is deprecated and merged with :mod:`pcapkit`.

"""
import argparse
import sys
from typing import TYPE_CHECKING

from pcapkit import __version__
from pcapkit.foundation.extraction import Extractor
from pcapkit.interface import JSON, PLIST, TREE
from pcapkit.utilities.compat import ModuleNotFoundError  # pylint: disable=redefined-builtin
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import EmojiWarning, warn

try:
    import emoji
except ModuleNotFoundError:
    warn("dependency package 'emoji' not found",
         EmojiWarning, stacklevel=stacklevel())

__all__ = ['main']

if TYPE_CHECKING:
    from argparse import ArgumentParser


def get_parser() -> 'ArgumentParser':
    """CLI argument parser."""
    parser = argparse.ArgumentParser(prog='pcapkit-cli',
                                     description='PCAP file extractor and formatted dumper')
    parser.add_argument('-V', '--version', action='version', version=__version__)
    parser.add_argument('fin', metavar='input-file-name',
                        help=('The name of the input PCAP or PCAP-NG file. With '
                              '`--auto-extension`, ".pcap" is appended unless its '
                              'extension is already ".pcap", ".cap" or ".pcapng". '
                              'Use "-" to read from standard input.'))
    parser.add_argument('-o', '--output', action='store', metavar='file-name', dest='fout',
                        help=('The name of the output report file. If it is omitted, '
                              '"out" is used. With `--auto-extension`, the extension '
                              'of the output format (e.g. ".json") is appended if '
                              'absent. With `--files`, the directory each frame\'s '
                              'report is written to.'))
    parser.add_argument('-f', '--format', action='store', metavar='format', dest='format',
                        help=('The format of the report: "json", "plist" (or "xml"), '
                              '"tree" (or "text", "txt") or "pcap" (or "cap"). Takes '
                              'precedence over `--json`, `--plist` and `--tree`. With '
                              'no format option, "tree" is used.'))
    parser.add_argument('-j', '--json', action='store_true', default=False,
                        help=('Write the report as JSON, as `--format json` does. '
                              'Ignored if `--format` is given.'))
    parser.add_argument('-p', '--plist', action='store_true', default=False,
                        help=('Write the report as a macOS property list, as '
                              '`--format plist` does. Ignored if `--format` or '
                              '`--json` is given.'))
    parser.add_argument('-t', '--tree', action='store_true', default=False,
                        help=('Write the report as tree view text, as `--format tree` '
                              'does; this is the default. Ignored if `--format`, '
                              '`--json` or `--plist` is given.'))
    parser.add_argument('-a', '--auto-extension', action='store_true', default=False,
                        help=('Append missing file extensions: ".pcap" to the input '
                              'file name, and the extension of the output format '
                              '(e.g. ".json") to the output file name unless `--files` '
                              'is set.'))
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help=('Print the input name, the protocol chain of each '
                              'frame, and where the report is stored.'))
    parser.add_argument('-F', '--files', action='store_true', default=False,
                        help=('Write a report file per frame, in the directory named '
                              'by `--output`.'))
    parser.add_argument('-E', '--engine', action='store', dest='engine', default='default', metavar='PKG',
                        help=('The extraction engine, case-insensitive: "default" (or '
                              '"pcapkit"), or a third-party one such as "dpkt" or '
                              '"scapy", which needs its package installed. An unknown '
                              'or unavailable engine falls back to "default".'))
    parser.add_argument('-P', '--protocol', action='store', dest='protocol', default=None, metavar='PROTOCOL',
                        help=('Stop dissecting each frame after this protocol, e.g. '
                              '"IPv4" (case-insensitive); the rest of the frame is '
                              'kept as raw data. Third-party engines ignore it.'))
    # NOTE: ``choices`` rather than a free-form string, because the layer names
    # are a closed set (``pcapkit.foundation.extraction.Layers``) and a name
    # outside it is not rejected anywhere downstream -- it simply never matches a
    # protocol's ``__layer__`` and the parse silently runs to the top of the
    # stack, which is the failure mode GH-356 was about. ``type=str.lower`` keeps
    # ``-L Internet`` accepted, matching ``Extractor.__init__``, which lowercases
    # the value anyway.
    #
    # The defaults are :data:`None` and not the ``'None'``/``'null'`` strings:
    # ``Extractor.__init__`` substitutes its own sentinels for an
    # omitted value, so passing the strings would only work because it happens to
    # lowercase ``'None'`` into the sentinel it wants.
    parser.add_argument('-L', '--layer', action='store', dest='layer', default=None, metavar='LAYER',
                        type=str.lower, choices=['link', 'internet', 'transport', 'application', 'none'],
                        help=('Stop dissecting each frame after its protocol in this '
                              'layer: "link", "internet", "transport" or "application" '
                              '(case-insensitive); "none", the default, sets no limit. '
                              'Third-party engines ignore it.'))
    parser.add_argument('-B', '--buffer-save', action='store_true', default=False,
                        help=('Save a copy of the input to a file as it is read. Only '
                              'an input that is not seekable, such as a pipe on '
                              'standard input, is saved.'))
    parser.add_argument('-O', '--buffer-path', action='store', metavar='file-name', dest='buffer_path',
                        help=('The name of the file `--buffer-save` writes. If it is '
                              'omitted, a temporary file is used and then deleted.'))
    return parser


def main() -> 'int':
    """Entrypoint."""
    parser = get_parser()
    args = parser.parse_args()

    if args.format:
        fmt = args.format
    elif args.json:
        fmt = JSON
    elif args.plist:
        fmt = PLIST
    elif args.tree:
        fmt = TREE
    else:
        fmt = None

    no_eof = args.fin == '-'
    if args.fin == '-':
        args.fin = sys.stdin.buffer

    extractor = Extractor(store=False, auto=not args.verbose,
                          fin=args.fin, fout=args.fout,
                          files=args.files, format=fmt,
                          layer=args.layer, protocol=args.protocol,
                          engine=args.engine, extension=args.auto_extension,
                          verbose=args.verbose, buffer_save=args.buffer_save,
                          no_eof=no_eof, buffer_path=args.buffer_path)  # type: ignore[var-annotated]

    if args.verbose:
        try:
            print(emoji.emojize(f":police_car_light: Loading file {extractor.input!r}"))
        except (UnicodeEncodeError, NameError):  # may trigger if emoji not installed
            print(f"[*] Loading file {extractor.input!r}")

        for _ in extractor:
            pass

        try:
            print(emoji.emojize(f":beer_mug: Report file{'s' if args.files else ''} stored in {extractor.output!r}"))
        except (UnicodeEncodeError, NameError):  # may trigger if emoji not installed
            print(f"[*] Report file{'s' if args.files else ''} stored in {extractor.output!r}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
