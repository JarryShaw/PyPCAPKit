# -*- coding: utf-8 -*-
"""Command Line Tool
=======================

.. module:: pcapkit.vendor.__main__

:mod:`pcapkit.vendor.__main__` is a command line tool for updating
constant enumerations.

"""

import argparse
import contextlib
import importlib
import os
import shutil
import sys
import tempfile
import traceback
import warnings
from typing import TYPE_CHECKING

from pcapkit import __version__
from pcapkit import vendor as vendor_module
from pcapkit.utilities.logging import VERBOSE, get_logger
from pcapkit.utilities.warnings import InvalidVendorWarning, VendorRuntimeWarning, warn

if TYPE_CHECKING:
    from argparse import ArgumentParser
    from typing import Iterator, Type

    from pcapkit.vendor.default import Vendor


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


def get_parser() -> 'ArgumentParser':
    """CLI argument parser."""
    parser = argparse.ArgumentParser(prog='pcapkit-vendor',
                                     description='update constant enumerations')
    parser.add_argument('-V', '--version', action='version', version=__version__)
    parser.add_argument('target', action='store', nargs=argparse.REMAINDER,
                        help='update targets, supply none to update all')
    return parser


@contextlib.contextmanager
def _snapshot_and_restore(vendor: 'Type[Vendor]') -> 'Iterator[None]':
    """Copy a target's const file aside before it runs; restore it if it raises.

    A ruling given in review of the work for #872 settled how a failed target
    is undone: keep a copy of its const file before running the sub-vendor and
    revert if anything failed, rather than making the write itself atomic.
    This is that -- at the per-target boundary :func:`run` already owns, which
    is also exactly where the earlier ruling on the same work wants the
    discarding to happen: only a non-zero sub-vendor's changes are discarded,
    and a zero-exited one's are kept.

    It is a *wider* guarantee than protecting the single
    ``open``/``print`` pair :meth:`~pcapkit.vendor.default.Vendor.__init__`
    happens to write through would give: it covers any way a crawler's own
    code could end up touching its const file, not only that one write.

    The destination is resolved via
    :meth:`~pcapkit.vendor.default.Vendor._dest_path` -- a classmethod for
    exactly this reason -- called on ``vendor`` itself, *before*
    :meth:`Vendor.__init__` ever runs its fetch, its render and its write.
    If that resolution fails -- a crawler outside the real
    :mod:`pcapkit.vendor` tree, such as a test double, or one whose
    ``_dest_path`` genuinely cannot be resolved without instance state --
    the snapshot is skipped and ``vendor()`` runs unprotected, exactly as it
    always did; not being able to *name* the file is not itself a reason to
    fail the target. The two triggers diverge from there. A crawler outside
    the real tree fails loudly anyway: :meth:`Vendor.__init__` calls the
    exact same ``_dest_path`` on itself and hits the exact same resolution
    failure, so nothing is lost by skipping the snapshot. An instance-method
    override that needs ``self`` does not fail the same way twice --
    ``vendor._dest_path()`` raises :exc:`TypeError` on the *class* call this
    function makes (no ``self`` to bind), but the *instance* call inside
    ``__init__`` binds ``self`` correctly and resolves fine, so that crawler
    runs to completion unprotected and **succeeds silently**: ``run()``
    returns :data:`True`, the file is replaced, and nothing warns that no
    snapshot was ever taken.

    That is one of two ways this function can decline to protect a target,
    and the two are not symmetric. The other is :func:`tempfile.mkstemp`
    failing to create the backup file -- most commonly a destination
    directory with no write permission, which needs a *directory*-level
    operation this function performs (creating a new entry) that
    :meth:`Vendor.__init__`'s own ``open(const_file, 'w')`` never needed (a
    *file*-level operation on a file that already exists). Unlike a
    ``_dest_path`` failure, this one is **not** swallowed: it happens before
    ``vendor()`` is ever called, so it propagates straight out of this
    function and fails the target outright, with the previous file
    untouched because nothing was ever attempted. So: a path that cannot be
    named lets the target proceed unprotected; a path that can be named but
    not backed up stops the target before it starts. Both leave the
    previous file exactly as it was, for different reasons.

    A symlinked destination has a related divergence from the pre-#872
    behaviour -- documented against the write path by rounds 4-8 (deleted
    along with ``_write_atomic``, though the underlying behaviour persists
    here instead): ``open(const_file, 'w')`` writes *through* a symlink,
    into whatever file it points at, leaving the link itself untouched.
    ``os.replace(backup, const_file)`` on restore instead replaces the *link
    itself* with a regular file. Measured, for ``link.py`` symlinked to
    ``real.py``: after a failure and restore, ``real.py`` is left however
    the crawler's failed write left it (truncated, in this case -- nothing
    here restores the file a symlink used to point at), ``link.py`` is now a
    regular file holding the backup's content, and
    ``os.path.islink(link.py)`` is :data:`False`. ``find pcapkit/const
    -type l`` is still empty, so this remains latent.

    Nothing is copied at all when the destination does not exist yet: there
    is no previous file for a failure to discard, so there is nothing this
    context manager needs to do beyond letting the body run.

    Args:
        vendor: Subclass of :class:`~pcapkit.vendor.default.Vendor` about to
            be run.

    Yields:
        Nothing; the caller's ``vendor()`` call belongs inside the ``with``.

    """
    try:
        const_file = vendor._dest_path()  # pylint: disable=protected-access
    except Exception:
        yield
        return

    if not os.path.isfile(const_file):
        yield
        return

    fd, backup = tempfile.mkstemp(dir=os.path.dirname(const_file),
                                  prefix=f'.{os.path.basename(const_file)}.',
                                  suffix='.bak')
    os.close(fd)
    shutil.copy2(const_file, backup)
    try:  # pylint: disable=no-else-raise
        yield
    except BaseException:
        # os.replace() disposes of the backup by moving it back onto
        # const_file -- but only once it succeeds. If it does not, the
        # original exception is masked (it survives only as __context__ on
        # whatever os.replace raises) and the backup is left orphaned; ``raise``
        # is unconditional here on purpose, since a failed restore is still a
        # failure the target must report, not a success to fall through to.
        #
        # The `else:` below is deliberate, not a style default pylint would
        # pick: collapsing it into an unindented statement after this whole
        # `try` (as an earlier round of this same PR did) makes "cleanup
        # only runs on success" a fact that has to be re-derived from
        # "`raise` never falls through", rather than one the structure
        # states directly -- and it silently stopped being true the moment
        # someone deleted that `raise`.  A mutation test proved it: with the
        # `raise` gone, the unindented `os.remove(backup)` still ran, after
        # `os.replace` had already renamed the backup away, so it raised
        # FileNotFoundError instead of the crawler's real error -- and every
        # existing test still passed, because run() catches that too.
        os.replace(backup, const_file)
        raise
    else:
        # contextlib, per the owner's stated preference over a hand-rolled
        # try/finally: a failure to remove the backup after a *successful*
        # run must not itself turn that success into run() -> False.
        with contextlib.suppress(OSError):
            os.remove(backup)


def run(vendor: 'Type[Vendor]') -> 'bool':
    """Script runner.

    Args:
        vendor: Subclass of :class:`~pcapkit.vendor.default.Vendor` from :mod:`pcapkit.vendor`.

    Returns:
        :data:`True` if ``vendor`` ran to completion, :data:`False` if it raised --
        this is what lets :func:`main` turn a crawler failure into a non-zero exit
        code instead of a silently-ignored no-op.

    Warns:
        VendorRuntimeWarning: If failed to initiate the ``vendor`` class.

    """
    logger.info(f'{vendor.__module__}.{vendor.__name__}: {vendor.__doc__}')
    try:
        with _snapshot_and_restore(vendor):
            vendor()
    except Exception as error:
        if VERBOSE:
            traceback.print_exc()
        # Unconditional, unlike the warning below: VendorRuntimeWarning is
        # filterable and VERBOSE defaults false, so without a plain print a CI
        # log that ignores warnings would show nothing at all about which
        # target broke or why -- exactly the failure mode this fix exists for.
        print(f'{vendor.__module__}.{vendor.__name__} failed: {error!r}', file=sys.stderr)
        warn(f'{vendor.__module__}.{vendor.__name__} <{error!r}>', VendorRuntimeWarning, stacklevel=2)
        return False
    return True


def main() -> 'int':
    """Entrypoint.

    Every target is attempted regardless of earlier failures -- a crawler that
    is down should not block regeneration of everything else -- but the exit
    code reflects whether *all* of them succeeded, so a no-op regeneration
    (crawler raised, previous const file left untouched) is distinguishable
    from a real one at the process boundary, which is what CI actually checks.

    Returns:
        ``0`` if every target ran to completion, ``1`` if any target raised.

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
    success = True
    for vendor in target_list:
        if not run(vendor):
            success = False
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
