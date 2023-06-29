# -*- coding: utf-8 -*-
"""Command Line Tool
=======================

.. module:: pcapkit.vendor.__main__

:mod:`pcapkit.vendor.__main__` is a command line tool for updating
constant enumerations.

"""

import argparse
import importlib
import sys
import traceback
import warnings
from typing import TYPE_CHECKING

from pcapkit import __version__
from pcapkit import vendor as vendor_module
from pcapkit.utilities.logging import VERBOSE, logger
from pcapkit.utilities.warnings import InvalidVendorWarning, VendorRuntimeWarning, warn

if TYPE_CHECKING:
    from argparse import ArgumentParser
    from typing import Type

    from pcapkit.vendor.default import Vendor


def get_parser() -> 'ArgumentParser':
    """CLI argument parser."""
    parser = argparse.ArgumentParser(prog='pcapkit-vendor',
                                     description='update constant enumerations')
    parser.add_argument('-V', '--version', action='version', version=__version__)
    parser.add_argument('target', action='store', nargs=argparse.REMAINDER,
                        help='update targets, supply none to update all')
    return parser


def run(vendor: 'Type[Vendor]') -> 'None':
    """Script runner.

    Args:
        vendor: Subclass of :class:`~pcapkit.vendor.default.Vendor` from :mod:`pcapkit.vendor`.

    Warns:
        VendorRuntimeWarning: If failed to initiate the ``vendor`` class.

    """
    logger.info(f'{vendor.__module__}.{vendor.__name__}: {vendor.__doc__}')
    try:
        vendor()
    except Exception as error:
        if VERBOSE:
            traceback.print_exc()
        warn(f'{vendor.__module__}.{vendor.__name__} <{error!r}>', VendorRuntimeWarning, stacklevel=2)


def main() -> 'int':
    """Entrypoint.

    Warns:
        InvalidVendorWarning: If vendor target not found in :mod:`pcapkit.vendor` module.

    """
    parser = get_parser()
    args = parser.parse_args()

    target_list = []  # type: list[Type[Vendor]]
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
        target_list.extend(getattr(vendor_module, name) for name in vendor_module.__all__)

    # with multiprocessing.Pool() as pool:
    #     pool.map(run, target_list)
    for vendor in target_list:
        run(vendor)
    return 0


if __name__ == '__main__':
    sys.exit(main())
