# -*- coding: utf-8 -*-


import argparse
import os
import sys


# original module of jspcapy
# command line tool for jspcap


from jspcap.interface import extract


# version number
__version__ = '0.4.0'


def get_parser():
    parser = argparse.ArgumentParser(prog='jspcapy', description=(
        'PCAP file extractor and formatted exporter'
    ))
    parser.add_argument('-V', '--version', action='version', version=f'{__version__}')
    parser.add_argument('fin', metavar='input-file-name',
                        help=(
                            'The name of input pcap file. If ".pcap" omits, '
                            'it will be automatically appended.'
                        ))
    parser.add_argument('-o', '--output', action='store', metavar='file-name',
                        dest='fout', help=(
                            'The name of input pcap file. If format extension '
                            'omits, it will be automatically appended.'
                        ))
    parser.add_argument('-f', '--format', action='store', metavar='format',
                        dest='format', help=(
                            'Print a extraction report in the specified output '
                            'format. Available are all formats supported by '
                            'jsformat, e.g.: json, plist, and tree.'
                        ))
    parser.add_argument('-j', '--json', action='store_true', default=False,
                        help=(
                            'Display extraction report as json. This will yield '
                            '"raw" output that may be used by external tools. '
                            'This option overrides all other options.'
                        ))
    parser.add_argument('-p', '--plist', action='store_true', default=False,
                        help=(
                            'Display extraction report as macOS Property List '
                            '(plist). This will yield "raw" output that may be '
                            'used by external tools. This option overrides all '
                            'other options.'
                        ))
    parser.add_argument('-t', '--tree', action='store_true', default=False,
                        help=(
                            'Display extraction report as tree view text. This '
                            'will yield "raw" output that may be used by external '
                            'tools. This option overrides all other options.'
                        ))
    parser.add_argument('-a', '--auto-extension', action='store_true', default=False,
                        help=(
                            'If output file extension omits, append automatically.'
                        ))
    parser.add_argument('-F', '--files', action='store_true', default=False,
                        help=(
                            'Split each frame into different files.'
                        ))
    parser.add_argument('-v', '--verbose', action='store_false', default=True,
                        help=(
                            'Show more information.'
                        ))
    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()

    if args.format:     fmt = args.format
    elif args.json:     fmt = 'json'
    elif args.plist:    fmt = 'plist'
    elif args.tree:     fmt = 'tree'
    else:               fmt = None

    extractor = extract(
                    fin=args.fin, fout=args.fout, format=fmt,
                    auto=args.verbose, files=args.files,
                    store=False, extension=args.auto_extension,
                )

    if not args.verbose:
        print(f"🚨 Loading file '{extractor.input}'")
        for frame in extractor:
            print(f' - Frame {extractor.length:>3d}: {extractor.protocol}')
        print(f"🍺 Report file{'s' if args.files else ''} stored in '{extractor.output}'")


if __name__ == '__main__':
    sys.exit(main())
