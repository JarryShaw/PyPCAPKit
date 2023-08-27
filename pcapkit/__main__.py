# -*- coding: utf-8 -*-
"""Command Line Tool
=======================

.. module:: pcapkit.__main__

.. important::

   This module requires ``emoji`` package to be installed.

:mod:`pcapkit.__main__` was originally the module file of
|jspcapy|_, which is now deprecated and merged with :mod:`pcapkit`.

.. |jspcapy| replace:: ``jspcapy``
.. _jspcapy: https://github.com/JarryShaw/jspcapy

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
                        help=('The name of input pcap file. If ".pcap" omits, '
                              'it will be automatically appended. Use "-" to indicate '
                              'reading from `stdin\'.'))
    parser.add_argument('-o', '--output', action='store', metavar='file-name', dest='fout',
                        help=('The name of input pcap file. If format extension '
                              'omits, it will be automatically appended.'))
    parser.add_argument('-f', '--format', action='store', metavar='format', dest='format',
                        help=('Print a extraction report in the specified output '
                              'format. Available are all formats supported by '
                              'dictdumper, e.g.: json, plist, and tree.'))
    parser.add_argument('-j', '--json', action='store_true', default=False,
                        help=('Display extraction report as json. This will yield '
                              '"raw" output that may be used by external tools. '
                              'This option overrides all other options.'))
    parser.add_argument('-p', '--plist', action='store_true', default=False,
                        help=('Display extraction report as macOS Property List '
                              '(plist). This will yield "raw" output that may be '
                              'used by external tools. This option overrides all '
                              'other options.'))
    parser.add_argument('-t', '--tree', action='store_true', default=False,
                        help=('Display extraction report as tree view text. This '
                              'will yield "raw" output that may be used by external '
                              'tools. This option overrides all other options.'))
    parser.add_argument('-a', '--auto-extension', action='store_true', default=False,
                        help='If output file extension omits, append automatically.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Show more information.')
    parser.add_argument('-F', '--files', action='store_true', default=False,
                        help='Split each frame into different files.')
    parser.add_argument('-E', '--engine', action='store', dest='engine', default='default', metavar='PKG',
                        help=('Indicate extraction engine. Note that except '
                              'default or pcapkit engine, all other engines '
                              'need support of corresponding packages.'))
    parser.add_argument('-P', '--protocol', action='store', dest='protocol', default='null', metavar='PROTOCOL',
                        help='Indicate extraction stops after which protocol.')
    parser.add_argument('-L', '--layer', action='store', dest='layer', default='None', metavar='LAYER',
                        help='Indicate extract frames until which layer.')
    parser.add_argument('-B', '--buffer-save', action='store_true', default=False,
                        help='Indicate if store buffer to file when reading from stdin.')
    parser.add_argument('-O', '--buffer-path', action='store', metavar='file-name', dest='buffer_path',
                        help=('The name of buffer storage file. If `--buffer-save` is set and this '
                              'omits, it will be automatically assigned.'))
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
        except UnicodeEncodeError:
            print(f"[*] Loading file {extractor.input!r}")

        for _ in extractor:
            pass

        try:
            print(emoji.emojize(f":beer_mug: Report file{'s' if args.files else ''} stored in {extractor.output!r}"))
        except UnicodeEncodeError:
            print(f"[*] Report file{'s' if args.files else ''} stored in {extractor.output!r}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
