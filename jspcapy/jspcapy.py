#!/usr/bin/python3
# -*- coding: utf-8 -*-


import argparse
import os


# main module of jspcapy
# command line tool for jspcap


from jspcap.exceptions import FileError, FormatError
from jspcap.extractor import Extractor


# version number
__version__ = '0.0.1'

# extracting label
NUMB = lambda number, protocol: ' - Frame {:>3d}: {}'.format(number, protocol)


def get_parser():
    parser = argparse.ArgumentParser(description=(
        'PCAP file extractor and formatted exporter'
    ))
    parser.add_argument('-v', '--version', action='version',
                        version='{0}'.format(__version__))
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
                            'jsformat, e.g.: json, plist, tree, xml.'
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
    parser.add_argument('-V', '--verbose', action='store_false', default=True,
                        help=(
                            'Show more information.'
                        ))
    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()

    if args.format:
        fmt = args.format
    elif args.json:
        fmt = 'json'
    elif args.plist:
        fmt = 'plist'
    elif args.tree:
        fmt = 'tree'
    else:
        fmt = None

    print(args.verbose)

    try:
        ext = Extractor(fin=args.fin, fout=args.fout, fmt=fmt,
                        auto=args.verbose, extension=args.auto_extension)
    except FormatError:
        try:
            ext = Extractor(fin=args.fin, fout=args.fout, fmt=fmt,
                            auto=args.verbose, extension=args.auto_extension)
        except FileError:
            fin, fout, fmt = Extractor.make_name(args.fin, args.fout, args.format, args.auto_extension)
            print("UnsupportedFile: Unsupported file '{}'".format(fin))
            os.remove(fout)
            return
    except FileError:
        fin, fout, fmt = Extractor.make_name(args.fin, args.fout, args.format, args.auto_extension)
        print("UnsupportedFile: Unsupported file '{}'".format(fin))
        os.remove(fout)
        return
    except FileNotFoundError:
        fin, fout, fmt = Extractor.make_name(args.fin, args.fout, args.format, args.auto_extension)
        print("FileNotFoundError: No such file or directory: '{}'".format(fin))
        os.remove(fout)
        return

    if not args.verbose:
        print("🚨Loading file '{}'".format(ext.input))
        for frame in ext:
            content = NUMB(ext.length, ext.protocol)
            print(content)
        print("🍺Report file stored in '{}'".format(ext.output))


if __name__ == '__main__':
    main()
