# -*- coding: utf-8 -*-
"""CLI for web crawlers."""

import argparse
import importlib
import multiprocessing
import sys
import warnings

import pcapkit.vendor as vendor_module
from pcapkit.utilities.warnings import InvalidVendorWarning, VendorRuntimeWarning
from pcapkit.vendor import __all__ as vendor_all

# version string
__version__ = '0.14.5'


def get_parser():
    parser = argparse.ArgumentParser(prog='pcapkit-vendor',
                                     description='update constant enumerations')
    parser.add_argument('-V', '--version', action='version', version=__version__)
    parser.add_argument('target', action='store', nargs=argparse.REMAINDER,
                        help='update targets, supply none to update all')
    return parser


def run(vendor):
    print(vendor.__doc__)
    try:
        vendor()
    except Exception as error:
        warnings.warn(error, VendorRuntimeWarning)


def main():
    parser = get_parser()
    args = parser.parse_args()

    target_list = list()
    for target in args.target:
        try:
            module = importlib.import_module(f'pcapkit.vendor.{target}')
            target_list.extend(getattr(module, name) for name in module.__all__)
        except ImportError:
            warn = warnings.formatwarning(f'invalid vendor updater: {target}', InvalidVendorWarning,
                                          __file__, 0, ' '.join(sys.argv))
            print(warn, file=sys.stderr)

    if not target_list:
        target_list.extend(getattr(vendor_module, name) for name in vendor_all)

    with multiprocessing.Pool() as pool:
        pool.map(run, target_list)


if __name__ == "__main__":
    sys.exit(main())
