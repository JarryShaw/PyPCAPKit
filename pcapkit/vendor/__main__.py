# -*- coding: utf-8 -*-
"""CLI for web crawlers."""

import argparse
import importlib
import sys
import warnings

import pcapkit.vendor as vendor_module
from pcapkit.utilities.warnings import InvalidVendorWarning, VendorRuntimeWarning
from pcapkit.vendor import __all__ as vendor_all

#: version string
__version__ = '0.15.5'


def get_parser():
    """CLI argument parser.

    Returns:
        argparse.ArgumentParser: Argument parser.

    """
    parser = argparse.ArgumentParser(prog='pcapkit-vendor',
                                     description='update constant enumerations')
    parser.add_argument('-V', '--version', action='version', version=__version__)
    parser.add_argument('target', action='store', nargs=argparse.REMAINDER,
                        help='update targets, supply none to update all')
    return parser


def run(vendor):
    """Script runner.

    Args:
        vendor (Type[Vendor]): Subclass of :class:`~pcapkit.vendor.default.Vendor` from :mod:`pcapkit.vendor`.

    Warns:
        VendorRuntimeWarning: If failed to initiate the ``vendor`` class.

    """
    print(f'{vendor.__module__}.{vendor.__name__}: {vendor.__doc__}')
    try:
        vendor()
    except Exception as error:
        warnings.warn(f'{vendor.__module__}.{vendor.__name__} <{error!r}>', VendorRuntimeWarning, stacklevel=2)


def main():
    """Entrypoint.

    Warns:
        InvalidVendorWarning: If vendor target not found in :mod:`pcapkit.vendor` module.

    """
    parser = get_parser()
    args = parser.parse_args()

    target_list = list()
    for target in args.target:
        try:
            module = importlib.import_module(f'pcapkit.vendor.{target}')
            target_list.extend(getattr(module, name) for name in module.__all__)
        except ImportError:
            warnings.showwarning(f'invalid vendor updater: {target}', InvalidVendorWarning,
                                 filename=__file__, lineno=0, line=' '.join(sys.argv))

    if not target_list:
        if args.target:
            parser.error('missing valid targets')
        target_list.extend(getattr(vendor_module, name) for name in vendor_all)

    # with multiprocessing.Pool() as pool:
    #     pool.map(run, target_list)
    [run(vendor) for vendor in target_list]  # pylint: disable=expression-not-assigned


if __name__ == "__main__":
    sys.exit(main())
