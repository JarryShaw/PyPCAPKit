# -*- coding: utf-8 -*-
"""command line tool

:mod:`pcapkit.__main__` was originally the module file of
|jspcapy|_, which is now deprecated and merged with :mod:`pcapkit`.

"""
import argparse
import sys
import warnings

import emoji

from pcapkit.foundation.extraction import Extractor
from pcapkit.interface import JSON, PLIST, TREE

#: version number
__version__ = '0.15.5'


def get_parser():
    """CLI argument parser.

    Returns:
        argparse.ArgumentParser: Argument parser.

    """
    parser = argparse.ArgumentParser(prog='pcapkit-cli',
                                     description='PCAP file extractor and formatted dumper')
    parser.add_argument('-V', '--version', action='version', version=__version__)
    parser.add_argument('fin', metavar='input-file-name',
                        help=('The name of input pcap file. If ".pcap" omits, '
                              'it will be automatically appended.'))
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
    parser.add_argument('-v', '--verbose', action='store_false', default=True,
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
    return parser


def main():
    """Entrypoint."""
    parser = get_parser()
    args = parser.parse_args()
    warnings.simplefilter('ignore')

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

    extractor = Extractor(store=False, format=fmt,
                          fin=args.fin, fout=args.fout,
                          auto=args.verbose, files=args.files,
                          layer=args.layer, protocol=args.protocol,
                          engine=args.engine, extension=args.auto_extension)

    if not args.verbose:
        try:
            print(emoji.emojize(f":police_car_light: Loading file {extractor.input!r}"))
        except UnicodeEncodeError:
            print(f"[*] Loading file {extractor.input!r}")
        for _ in extractor:
            print(f' - Frame {extractor.length:>3d}: {extractor.protocol}')
        try:
            print(emoji.emojize(f":beer_mug: Report file{'s' if args.files else ''} stored in {extractor.output!r}"))
        except UnicodeEncodeError:
            print(f"[*] Report file{'s' if args.files else ''} stored in {extractor.output!r}")


if __name__ == '__main__':
    sys.exit(main())
