# -*- coding: utf-8 -*-
"""The weekly Conda Update moves each platform pin up, and each pin has a review-by date (#1851).

* :func:`conda_vendor.installs` and :func:`conda_vendor.newest_wheel` find the
  newest release with a wheel every conda Python installs on a platform, on
  PyPI's JSON for cryptography as recorded here: ``abi3`` from an older
  CPython, ``universal2`` on either Mac, and not a free-threaded, arm64-only,
  musllinux, yanked or pre-release file.
* :func:`conda_vendor.refresh` moves a pin up to that release with a fresh
  review-by date, drops it once it reaches the installed release or if it
  already pins it, and leaves it, with a warning, when PyPI cannot be read or
  when no release has a wheel for every conda Python, naming the Pythons no
  release has one for (#2025), or when the pinned release has lost the wheel an
  older release still has, naming the Pythons it lacks (#2028).
  ``--refresh-pins`` rewrites :file:`conda/platform-pins.toml` only on a change.
* :func:`conda_vendor._fetch` reads PyPI through :mod:`requests`, a stand-in
  here, and raises each of its errors as :class:`OSError`. It imports requests
  itself, so the script loads, and ``--smoke`` passes, without it.
* The table is not one of :file:`util/verdict_covers_checkout.py`'s bot-managed
  paths, so a commit moving a pin waits for its own ``Unit Tests`` run.
* ``--check`` fails on a pin past its review-by date, and passes on one in date,
  without reading the network.
* :file:`conda/platform-pins.toml` is in the form the job writes, and
  ``conda-update`` in :file:`.github/workflows/cron-conda.yml` installs
  requests and runs ``--refresh-pins`` between installing ``.[all]`` and
  writing the requirements, read with :func:`tests._workflows.load`.
* Every test reaches the script through :func:`load_vendor`, which skips without
  :mod:`tomllib`, so none fails on the 3.8 to 3.10 legs (#1898).

"""

from __future__ import annotations

import bz2
import contextlib
import datetime
import importlib.util
import io
import json
import pathlib
import re
import shlex
import sys
import tarfile
import tempfile
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): drives util/conda_vendor.py, which runs on one interpreter.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'cron-conda.yml'
#: The conda Pythons the stand-ins are built for; the matcher takes any list.
PYTHONS = ('3.11', '3.12', '3.13', '3.14', '3.15')
#: The day the stand-in runs happen on.
TODAY = datetime.date(2026, 10, 17)
#: What every file of the recorded releases says of the Python it needs.
REQUIRES = '!=3.9.0,!=3.9.1,>=3.9'

_MODULE = []  # type: list[Any]


def load_vendor(name: 'str' = 'conda_vendor') -> 'Any':
    """:file:`util/conda_vendor.py`, loaded afresh as ``name``; skipped without :mod:`tomllib`, which it imports.

    Every test reaches the script through here, so none fails on the 3.8 to 3.10
    legs, which lack :mod:`tomllib` (#1898): :class:`TomllibGuardTests`.

    """
    if tomllib is None:  # pragma: no cover
        raise unittest.SkipTest('tomllib, which util/conda_vendor.py imports, needs Python 3.11+')
    spec = importlib.util.spec_from_file_location(name, ROOT / 'util' / 'conda_vendor.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def vendor() -> 'Any':
    """:file:`util/conda_vendor.py`, loaded once through :func:`load_vendor`."""
    if not _MODULE:
        _MODULE.append(load_vendor())
    return _MODULE[0]


def files(version: 'str', *tags: 'str', yanked: 'bool' = False,
          requires_python: 'str' = REQUIRES) -> 'list[dict[str, Any]]':
    """A release's files as PyPI's JSON lists them, cut to the fields :func:`newest_wheel` reads.

    Each of ``tags`` is a wheel's ``{python}-{abi}-{platform}``; the sdist comes last.

    """
    found = [{'filename': f'cryptography-{version}-{tag}.whl', 'packagetype': 'bdist_wheel',
              'requires_python': requires_python, 'yanked': yanked} for tag in tags]
    found.append({'filename': f'cryptography-{version}.tar.gz', 'packagetype': 'sdist',
                  'requires_python': requires_python, 'yanked': yanked})
    return found


def recorded(**more: 'list[dict[str, Any]]') -> 'dict[str, Any]':
    """PyPI's JSON for cryptography, with ``more`` releases besides.

    Recorded from https://pypi.org/pypi/cryptography/json on 2026-10-16, cut to
    some of its releases and of their files. 45.0.0 is yanked whole; 48.0.1 is the
    newest with a universal2 wheel, which #1827 pins osx-64 to; 49.0.0 and 50.0.2
    have arm64 macOS wheels alone.

    """
    releases = {
        '45.0.0': files('45.0.0', 'cp311-abi3-macosx_10_9_universal2', 'cp311-abi3-manylinux_2_34_x86_64',
                        'cp37-abi3-macosx_10_9_universal2', yanked=True,
                        requires_python='!=3.9.0,!=3.9.1,>=3.7'),
        '48.0.1': files('48.0.1', 'cp311-abi3-macosx_10_9_universal2', 'cp311-abi3-manylinux_2_34_x86_64',
                        'cp311-abi3-musllinux_1_2_x86_64', 'cp311-abi3-win_amd64',
                        'cp314-cp314t-macosx_10_9_universal2', 'cp39-abi3-macosx_10_9_universal2'),
        '49.0.0': files('49.0.0', 'cp311-abi3-macosx_11_0_arm64', 'cp311-abi3-manylinux_2_34_x86_64',
                        'cp311-abi3-musllinux_1_2_x86_64', 'cp314-cp314t-macosx_11_0_arm64',
                        'cp39-abi3-macosx_11_0_arm64'),
        '50.0.2': files('50.0.2', 'cp311-abi3-macosx_11_0_arm64',
                        'cp311-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64',
                        'cp311-abi3-musllinux_1_2_x86_64', 'cp315-abi3.abi3t-macosx_11_0_arm64',
                        'cp39-abi3-macosx_11_0_arm64'),
    }
    releases.update(more)
    return {'info': {'name': 'cryptography', 'version': '50.0.2'}, 'releases': releases}


#: A later release with an Intel macOS wheel again, as the stand-in for upstream shipping one.
INTEL_AGAIN = files('51.0.0', 'cp311-abi3-macosx_10_9_universal2', 'cp311-abi3-manylinux_2_34_x86_64')


def lost_wheel() -> 'dict[str, Any]':
    """The recording with 48.0.1's cp311 osx-64 wheel yanked, and 47.0.0 still serving every Python (#2028).

    48.0.1 keeps a cp312 ``abi3`` universal2 wheel, so it lacks cp311 alone.

    """
    yanked = files('48.0.1', 'cp311-abi3-macosx_10_9_universal2', yanked=True)[:1]
    return recorded(**{'47.0.0': files('47.0.0', 'cp311-abi3-macosx_10_9_universal2'),
                       '48.0.1': yanked + files('48.0.1', 'cp312-abi3-macosx_10_9_universal2')})


def table(version: 'str' = '48.0.1', review_by: 'datetime.date' = datetime.date(2026, 12, 1),
          ) -> 'dict[str, dict[str, Any]]':
    """A ``PLATFORM_PINS`` pinning cryptography to ``version`` on osx-64."""
    return {'cryptography': {'osx-64': vendor().Pin(version, review_by, 'no Intel wheel (#1827)')}}


def stand_in_requests(payload: 'Any' = None, *, error: 'Optional[str]' = None, status: 'Optional[str]' = None,
                      undecodable: 'bool' = False) -> 'tuple[types.ModuleType, list[tuple[str, dict[str, Any]]]]':
    """A stand-in :mod:`requests` whose ``get`` answers ``payload``, and the ``get`` calls it is asked.

    ``error`` fails the request itself, ``status`` its ``raise_for_status``, and
    ``undecodable`` its ``json``. Its ``RequestException`` derives from
    :class:`Exception` alone, unlike requests' own, so :func:`conda_vendor._fetch`
    has to catch it by name for :func:`conda_vendor.refresh` to catch it at all.

    """
    calls = []  # type: list[tuple[str, dict[str, Any]]]
    fake = types.ModuleType('requests')

    class RequestException(Exception):
        """requests' base error, here not an :class:`OSError`."""

    class Response:
        """A reply, which fails as the arguments say."""

        def raise_for_status(self) -> None:
            if status is not None:
                raise RequestException(status)

        def json(self) -> 'Any':
            if undecodable:
                raise RequestException('Expecting value: line 1 column 1 (char 0)')
            return payload

    def get(url: 'str', **kwargs: 'Any') -> 'Response':
        calls.append((url, kwargs))
        if error is not None:
            raise RequestException(error)
        return Response()

    fake.RequestException = RequestException  # type: ignore[attr-defined]
    fake.get = get  # type: ignore[attr-defined]
    return fake, calls


def no_urllib() -> 'Any':
    """:func:`urllib.request.urlopen` patched to fail, so a test reading PyPI some other way never reaches it."""
    return mock.patch('urllib.request.urlopen', side_effect=AssertionError('PyPI was read through urllib'))


#: A built conda package's files, as --smoke passes them: pcapkit's _extern shim
#: and one vendored distribution.
SMOKE_FILES = {
    'pcapkit/__init__.py': ("import os, sys\n_extern = os.path.join(os.path.dirname(os.path.realpath(__file__)), "
                            "'_extern')\nif os.path.exists(_extern):\n    sys.path.append(_extern)\n"),
    'pcapkit/_extern/bundle/__init__.py': '',
    'pcapkit/_extern/bundle-1.0.dist-info/METADATA': 'Name: bundle\n',
    'pcapkit/_extern/bundle-1.0.dist-info/RECORD':
        'bundle/__init__.py,,\nbundle-1.0.dist-info/METADATA,,\nbundle-1.0.dist-info/RECORD,,\n',
}


def smoke_package(module: 'Any', directory: 'pathlib.Path') -> 'pathlib.Path':
    """A ``.tar.bz2`` conda package of :data:`SMOKE_FILES` for this runner, in ``directory``."""
    runner = module.runner_platform()
    if runner is None:  # pragma: no cover
        raise unittest.SkipTest('this machine is none of the platforms the conda legs build on')
    site = f'lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/'
    members = {site + name: text for name, text in SMOKE_FILES.items()}
    members['info/index.json'] = json.dumps({'name': 'pypcapkit', 'subdir': runner})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, text in members.items():
            data = text.encode('utf-8')
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    path = directory / 'pypcapkit-0-py_0.tar.bz2'
    path.write_bytes(bz2.compress(buffer.getvalue()))
    return path


class TagMatcherTests(unittest.TestCase):
    """:func:`installs` on single wheels, and :func:`newest_wheel` on the recording."""

    def test_abi3_installs_on_its_own_and_every_later_python(self) -> None:
        installs = vendor().installs
        wheel = 'cryptography-48.0.1-cp311-abi3-macosx_10_9_universal2.whl'
        for python in PYTHONS:
            with self.subTest(python=python):
                self.assertTrue(installs(wheel, 'osx-64', python, REQUIRES))
        self.assertFalse(installs(wheel, 'osx-64', '3.10', REQUIRES))

    def test_universal2_installs_on_either_mac_and_not_on_linux(self) -> None:
        installs = vendor().installs
        wheel = 'cryptography-48.0.1-cp311-abi3-macosx_10_9_universal2.whl'
        self.assertTrue(installs(wheel, 'osx-64', '3.12'))
        self.assertTrue(installs(wheel, 'osx-arm64', '3.12'))
        self.assertFalse(installs(wheel, 'linux-64', '3.12'))

    def test_an_arm64_wheel_does_not_install_on_intel(self) -> None:
        installs = vendor().installs
        wheel = 'cryptography-49.0.0-cp311-abi3-macosx_11_0_arm64.whl'
        self.assertFalse(installs(wheel, 'osx-64', '3.12'))
        self.assertTrue(installs(wheel, 'osx-arm64', '3.12'))

    def test_an_own_abi_wheel_installs_on_its_own_python_alone(self) -> None:
        installs = vendor().installs
        wheel = 'cryptography-51.0.0-cp312-cp312-macosx_10_13_x86_64.whl'
        self.assertEqual([python for python in PYTHONS if installs(wheel, 'osx-64', python)], ['3.12'])
        self.assertFalse(installs('cryptography-48.0.1-cp314-cp314t-macosx_10_9_universal2.whl', 'osx-64', '3.14'))

    def test_manylinux_installs_on_linux_and_musllinux_nowhere(self) -> None:
        installs = vendor().installs
        for wheel, subdir, expected in (
                ('cryptography-48.0.1-cp311-abi3-manylinux_2_34_x86_64.whl', 'linux-64', True),
                ('cryptography-50.0.2-cp311-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl', 'linux-64', True),
                ('cryptography-48.0.1-cp311-abi3-musllinux_1_2_x86_64.whl', 'linux-64', False),
                ('cryptography-48.0.1-cp311-abi3-manylinux_2_34_x86_64.whl', 'osx-64', False),
                ('cryptography-48.0.1-cp311-abi3-win_amd64.whl', 'osx-64', False),
                ('cryptography-51.0.0-py3-none-any.whl', 'linux-64', True),
                ('cryptography-51.0.0-py3-none-any.whl', 'osx-64', True)):
            with self.subTest(wheel=wheel, subdir=subdir):
                self.assertEqual(installs(wheel, subdir, '3.12'), expected)

    def test_an_sdist_and_an_excluded_python_install_nowhere(self) -> None:
        installs = vendor().installs
        self.assertFalse(installs('cryptography-48.0.1.tar.gz', 'osx-64', '3.12'))
        wheel = 'cryptography-51.0.0-cp311-abi3-macosx_10_9_universal2.whl'
        self.assertFalse(installs(wheel, 'osx-64', '3.11', '>=3.12'))
        self.assertTrue(installs(wheel, 'osx-64', '3.12', '>=3.12'))

    def test_the_recording_has_osx_64_wheels_up_to_48_0_1(self) -> None:
        newest = vendor().newest_wheel
        self.assertEqual(newest(recorded(), 'osx-64', PYTHONS), '48.0.1')
        self.assertEqual(newest(recorded(), 'osx-arm64', PYTHONS), '50.0.2')
        self.assertEqual(newest(recorded(), 'linux-64', PYTHONS), '50.0.2')
        self.assertEqual(newest(recorded(), 'linux-64', PYTHONS, ceiling='49.0.0'), '49.0.0')

    def test_no_matching_wheel_is_none(self) -> None:
        newest = vendor().newest_wheel
        # 45.0.0's universal2 wheels are yanked, so nothing up to 47 has one.
        self.assertIsNone(newest(recorded(), 'osx-64', PYTHONS, ceiling='47.0.0'))
        self.assertIsNone(newest({'releases': {}}, 'osx-64', PYTHONS))

    def test_every_python_needs_a_wheel(self) -> None:
        newest = vendor().newest_wheel
        project = recorded(**{'51.0.0': files('51.0.0', 'cp312-cp312-macosx_10_13_x86_64')})
        self.assertEqual(newest(project, 'osx-64', PYTHONS), '48.0.1')
        self.assertEqual(newest(project, 'osx-64', ['3.12']), '51.0.0')

    def test_a_pre_release_and_a_yanked_wheel_are_passed_over(self) -> None:
        newest = vendor().newest_wheel
        project = recorded(**{'52.0.0rc1': files('52.0.0rc1', 'cp311-abi3-macosx_10_9_universal2'),
                              '51.0.0': files('51.0.0', 'cp311-abi3-macosx_10_9_universal2', yanked=True)})
        self.assertEqual(newest(project, 'osx-64', PYTHONS), '48.0.1')
        self.assertEqual(newest(recorded(**{'51.0.0': INTEL_AGAIN}), 'osx-64', PYTHONS), '51.0.0')

    def test_json_without_releases_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            vendor().newest_wheel({'info': {}}, 'osx-64', PYTHONS)


class BumpTests(unittest.TestCase):
    """:func:`refresh` on stand-in pins, the recording and stand-in installed versions."""

    def refresh(self, project: 'Any', installed: 'Any' = '52.0.0', pins: 'Any' = None) -> 'Any':
        def fetch(name: 'str') -> 'Any':
            if isinstance(project, BaseException):
                raise project
            return project
        return vendor().refresh(table() if pins is None else pins, fetch,
                                lambda name: installed, PYTHONS, TODAY)

    def test_a_newer_wheel_moves_the_pin_and_renews_its_date(self) -> None:
        module = vendor()
        result, notes = self.refresh(recorded(**{'51.0.0': INTEL_AGAIN}))
        self.assertEqual(result, {'cryptography': {'osx-64': module.Pin(
            '51.0.0', TODAY + module.REVIEW_HORIZON, 'no Intel wheel (#1827)')}})
        self.assertEqual(TODAY + module.REVIEW_HORIZON, datetime.date(2027, 1, 16))
        self.assertEqual(notes, [('notice', 'cryptography on osx-64 moves from 48.0.1 to 51.0.0, the newest '
                                            'release with a wheel there; due for review by 2027-01-16')])

    def test_the_installed_release_with_a_wheel_drops_the_pin(self) -> None:
        result, notes = self.refresh(recorded(**{'51.0.0': INTEL_AGAIN}), installed='51.0.0')
        self.assertEqual(result, {})
        self.assertEqual(notes, [('notice', 'cryptography 51.0.0, the installed release, has a wheel for '
                                            'osx-64, so its 48.0.1 pin there is dropped')])

    def test_a_pin_already_at_the_installed_release_is_dropped(self) -> None:
        for project, version in ((recorded(), '50.0.2'), (recorded(**{'51.0.0': INTEL_AGAIN}), '51.0.0')):
            with self.subTest(pin=version, wheel=version == '51.0.0'):
                result, notes = self.refresh(project, installed=version, pins=table(version))
                self.assertEqual(result, {})
                self.assertEqual(notes, [('notice', f'cryptography {version} on osx-64 is the installed '
                                                    'release itself, so the pin is dropped')])

    def test_a_pin_with_no_newer_wheel_keeps_its_version_and_date(self) -> None:
        self.assertEqual(self.refresh(recorded(), installed='50.0.2'), (table(), []))

    def test_a_pin_never_passes_the_installed_release(self) -> None:
        self.assertEqual(self.refresh(recorded(**{'51.0.0': INTEL_AGAIN}), installed='50.0.2'), (table(), []))

    def test_a_pin_on_a_platform_no_leg_builds_is_left_alone(self) -> None:
        pins = {'cryptography': {'linux-aarch64': vendor().Pin('1.0', TODAY, 'a stand-in')}}
        result, notes = self.refresh(recorded(**{'51.0.0': INTEL_AGAIN}), pins=pins)
        self.assertEqual(result, pins)
        self.assertEqual([level for level, _ in notes], ['warning'])

    def test_pypi_failing_leaves_the_pin_and_warns(self) -> None:
        # What _fetch raises: OSError for a failed request (FetchTests), and
        # ValueError for a reply an older requests cannot decode.
        for error in (OSError('503 Server Error: Service Unavailable'), TimeoutError('timed out'),
                      ValueError('Expecting value: line 1 column 1')):
            with self.subTest(error=type(error).__name__):
                result, notes = self.refresh(error)
                self.assertEqual(result, table())
                self.assertEqual(len(notes), 1, notes)
                self.assertEqual(notes[0][0], 'warning')
                self.assertTrue(notes[0][1].startswith('PyPI could not be read for cryptography ('), notes)
                self.assertTrue(notes[0][1].endswith('), so its pins stay as they are'), notes)

    def test_json_without_releases_leaves_the_pin_and_warns(self) -> None:
        result, notes = self.refresh({'message': 'Not Found'})
        self.assertEqual(result, table())
        self.assertEqual(notes, [('warning', "cryptography 48.0.1 on osx-64 stays as it is: "
                                             "PyPI's JSON has no releases")])

    def test_a_pin_no_release_can_move_to_warns_with_the_missing_tags(self) -> None:
        # #2025: no release has a cp38 wheel, so the pin used to stay without a word.
        result, notes = vendor().refresh(table(), lambda name: recorded(), lambda name: '50.0.2',
                                         ('3.8', *PYTHONS), TODAY)
        self.assertEqual(result, table())
        self.assertEqual(notes, [('warning', 'cryptography 48.0.1 on osx-64 stays as it is, and may no longer '
                                             'hold: no release up to 50.0.2 has a wheel for cp38 on osx-64')])

    def test_a_pin_no_single_release_serves_warns_for_every_tag(self) -> None:
        # #2025: each Python has an osx-64 wheel in some release, but none has all of them.
        project = {'releases': {'1.0': files('1.0', 'cp311-cp311-macosx_10_9_x86_64'),
                                '2.0': files('2.0', 'cp312-cp312-macosx_10_9_x86_64')}}
        pins = {'cryptography': {'osx-64': vendor().Pin('1.0', TODAY, 'a stand-in')}}
        result, notes = vendor().refresh(pins, lambda name: project, lambda name: '3.0', ['3.11', '3.12'], TODAY)
        self.assertEqual(result, pins)
        self.assertEqual(notes, [('warning', 'cryptography 1.0 on osx-64 stays as it is, and may no longer '
                                             'hold: no release up to 3.0 has wheels for all of cp311, cp312 '
                                             'on osx-64 at once')])

    def test_a_pin_whose_release_lost_a_wheel_warns_with_the_tag_it_lacks(self) -> None:
        # #2028: 47.0.0 still has every wheel, so the 48.0.1 pin used to stay without a word.
        result, notes = self.refresh(lost_wheel())
        self.assertEqual(result, table())
        self.assertEqual(notes, [('warning', 'cryptography 48.0.1 on osx-64 stays as it is, and may no longer '
                                             'hold: 48.0.1 has no wheel for cp311 on osx-64, and the newest '
                                             'release up to 52.0.0 with wheels for all of cp311, cp312, cp313, '
                                             'cp314, cp315 there is 47.0.0')])

    def test_a_pin_whose_release_lost_every_wheel_warns_for_every_tag(self) -> None:
        # #2028: 49.0.0 has arm64 macOS wheels alone, and 48.0.1 has universal2 ones.
        result, notes = self.refresh(recorded(), pins=table('49.0.0'))
        self.assertEqual(result, table('49.0.0'))
        self.assertEqual(notes, [('warning', 'cryptography 49.0.0 on osx-64 stays as it is, and may no longer '
                                             'hold: 49.0.0 has no wheel for cp311, cp312, cp313, cp314, cp315 '
                                             'on osx-64, and the newest release up to 52.0.0 with wheels for '
                                             'all of cp311, cp312, cp313, cp314, cp315 there is 48.0.1')])

    def test_a_pin_pypi_no_longer_lists_warns(self) -> None:
        # #2028: a pinned release gone from PyPI, or a pre-release, is not one newest_wheel weighs.
        for version in ('48.5.0', '49.0.0rc1'):
            with self.subTest(pin=version):
                result, notes = self.refresh(recorded(**{'49.0.0rc1': INTEL_AGAIN}), pins=table(version))
                self.assertEqual(result, table(version))
                self.assertEqual(notes, [('warning', f'cryptography {version} on osx-64 stays as it is, and may no '
                                                     f'longer hold: PyPI lists no stable release {version}, and '
                                                     'the newest release up to 52.0.0 with wheels for all of '
                                                     'cp311, cp312, cp313, cp314, cp315 there is 48.0.1')])

    def test_a_pin_above_the_installed_release_is_not_called_lost(self) -> None:
        # #2028: 49.0.0 is above the installed 48.5.0, so newest_wheel never weighed it.
        self.assertEqual(self.refresh(recorded(), installed='48.5.0', pins=table('49.0.0')), (table('49.0.0'), []))

    def test_a_package_not_installed_leaves_the_pin_and_warns(self) -> None:
        result, notes = self.refresh(recorded(**{'51.0.0': INTEL_AGAIN}), installed=None)
        self.assertEqual(result, table())
        self.assertEqual(notes, [('warning', 'cryptography is not installed here, so its pins stay as they are')])


class FetchTests(unittest.TestCase):
    """``_fetch`` reads PyPI through :mod:`requests`, imported only then, and raises its errors as OSError."""

    HEADERS = {'User-Agent': 'PyPCAPKit conda-update (#1851)', 'Accept': 'application/json'}

    def fetch(self, fake: 'types.ModuleType') -> 'Any':
        with no_urllib(), mock.patch.dict(sys.modules, {'requests': fake}):
            return vendor()._fetch('cryptography')

    def test_pypi_is_read_through_requests(self) -> None:
        fake, calls = stand_in_requests(recorded())
        self.assertEqual(self.fetch(fake), recorded())
        self.assertEqual(calls, [('https://pypi.org/pypi/cryptography/json',
                                  {'headers': self.HEADERS, 'timeout': 60})])

    def test_each_requests_error_is_raised_as_one_refresh_catches(self) -> None:
        module = vendor()
        for failure, message in (({'error': 'Name or service not known'}, 'Name or service not known'),
                                 ({'status': '503 Server Error: Service Unavailable'},
                                  '503 Server Error: Service Unavailable'),
                                 ({'undecodable': True}, 'Expecting value: line 1 column 1 (char 0)')):
            with self.subTest(**failure):
                fake, _ = stand_in_requests(recorded(), **failure)
                self.assertFalse(issubclass(fake.RequestException, OSError))  # type: ignore[attr-defined]
                with self.assertRaises(OSError) as raised:
                    self.fetch(fake)
                self.assertIsInstance(raised.exception, module.UNREADABLE)
                self.assertEqual(str(raised.exception), message)
                self.assertIsInstance(raised.exception.__cause__, fake.RequestException)  # type: ignore[attr-defined]

    def test_without_requests_only_the_request_fails(self) -> None:
        """The script loads, and ``--smoke`` passes, with :mod:`requests` unimportable.

        ``conda-dist`` and Create Release's ``conda`` legs run ``--smoke`` with
        pip, setuptools and wheel alone installed (#1854).

        """
        with no_urllib(), mock.patch.dict(sys.modules, {'requests': None}):
            fresh = load_vendor('conda_vendor_without_requests')
            with self.assertRaises(ImportError):
                fresh._fetch('cryptography')
            with tempfile.TemporaryDirectory() as temp:
                package = smoke_package(fresh, pathlib.Path(temp))
                self.assertEqual(fresh.main(['--smoke', str(package)]), 0)


class Scratch:
    """``util/conda_vendor.py``'s files and hooks pointed into a temporary tree, for :func:`main`."""

    def __init__(self, pins: 'dict[str, dict[str, Any]]') -> None:
        self.pins = pins

    def __enter__(self) -> 'Scratch':
        module = vendor()
        self.temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temp.name)
        (root / 'conda').mkdir()
        self.file, self.table = root / 'conda' / 'requirements.txt', root / 'conda' / 'platform-pins.toml'
        self.table.write_text(module.render_pins(self.pins), encoding='utf-8')
        self.saved = {name: getattr(module, name) for name in (
            'ROOT', 'FILE', 'PINS', 'PLATFORM_PINS', '_requires', '_version', '_installed', '_fetch', '_today')}
        module.ROOT, module.FILE, module.PINS, module.PLATFORM_PINS = root, self.file, self.table, self.pins
        module._requires = lambda name: []
        module._version = module._installed = lambda name: '52.0.0'
        module._today = lambda: TODAY
        module._fetch = self.offline
        return self

    @staticmethod
    def offline(name: 'str') -> 'Any':
        raise AssertionError(f'PyPI was asked for {name}')

    def __exit__(self, *exc_info: 'Any') -> None:
        module = vendor()
        for name, value in self.saved.items():
            setattr(module, name, value)
        self.temp.cleanup()

    def main(self, *argv: 'str') -> 'tuple[int, str]':
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = vendor().main(list(argv))
        return status, output.getvalue()


class RefreshCommandTests(unittest.TestCase):
    """``--refresh-pins`` end to end, on a scratch table and a stand-in PyPI."""

    def test_a_moved_pin_is_written_with_its_new_date(self) -> None:
        module = vendor()
        with Scratch(table()) as scratch:
            module._fetch = lambda name: recorded(**{'51.0.0': INTEL_AGAIN})
            status, output = scratch.main('--refresh-pins')
            written = scratch.table.read_text(encoding='utf-8')
        self.assertEqual(status, 0)
        self.assertEqual(written, module.render_pins(table('51.0.0', datetime.date(2027, 1, 16))))
        self.assertIn('review-by = 2027-01-16\n', written)
        self.assertEqual(output, '::notice title=Platform pins::cryptography on osx-64 moves from 48.0.1 to '
                                 '51.0.0, the newest release with a wheel there; due for review by 2027-01-16\n')

    def test_a_pin_at_the_installed_release_is_written_out(self) -> None:
        module = vendor()
        with Scratch(table('52.0.0')) as scratch:
            module._fetch = lambda name: recorded()
            status, output = scratch.main('--refresh-pins')
            written = scratch.table.read_text(encoding='utf-8')
        self.assertEqual(status, 0)
        self.assertEqual(written, module.render_pins({}))
        self.assertEqual(output, '::notice title=Platform pins::cryptography 52.0.0 on osx-64 is the installed '
                                 'release itself, so the pin is dropped\n')

    def test_a_network_failure_writes_nothing_and_passes(self) -> None:
        module = vendor()
        fake, calls = stand_in_requests(error='Name or service not known')
        with Scratch(table()) as scratch, no_urllib(), mock.patch.dict(sys.modules, {'requests': fake}):
            before = scratch.table.read_bytes()
            module._fetch = scratch.saved['_fetch']
            status, output = scratch.main('--refresh-pins')
            after = scratch.table.read_bytes()
        self.assertEqual(status, 0)
        self.assertEqual(after, before)
        self.assertEqual([url for url, _ in calls], ['https://pypi.org/pypi/cryptography/json'])
        self.assertEqual(output, '::warning title=Platform pins::PyPI could not be read for cryptography '
                                 '(Name or service not known), so its pins stay as they are\n')

    def test_an_overdue_pin_left_where_it_is_is_warned_about(self) -> None:
        module = vendor()
        with Scratch(table(review_by=TODAY - datetime.timedelta(days=1))) as scratch:
            module._fetch = lambda name: recorded()
            status, output = scratch.main('--refresh-pins')
        self.assertEqual(status, 0)
        self.assertEqual(output.splitlines(), [
            '::warning title=Platform pins::overdue: cryptography is pinned to 48.0.1 on osx-64, and was due for '
            'review by 2026-10-16; check the pin still holds, then set a new review-by date, such as 2027-01-16'])

    def test_a_stuck_pin_is_warned_about_and_passes(self) -> None:
        # #2025: the step stays green, as the workflow's non-blocking rule has it, but says so.
        module = vendor()
        with Scratch(table()) as scratch:
            before = scratch.table.read_bytes()
            module._fetch = lambda name: recorded()
            with mock.patch.object(module, 'conda_pythons', lambda: ['3.8', *PYTHONS]):
                status, output = scratch.main('--refresh-pins')
            after = scratch.table.read_bytes()
        self.assertEqual(status, 0)
        self.assertEqual(after, before)
        self.assertEqual(output, '::warning title=Platform pins::cryptography 48.0.1 on osx-64 stays as it is, '
                                 'and may no longer hold: no release up to 52.0.0 has a wheel for cp38 '
                                 'on osx-64\n')

    def test_a_pin_whose_release_lost_a_wheel_is_warned_about_and_passes(self) -> None:
        # #2028: the step stays green, as the workflow's non-blocking rule has it, but says so.
        module = vendor()
        with Scratch(table()) as scratch:
            before = scratch.table.read_bytes()
            module._fetch = lambda name: lost_wheel()
            with mock.patch.object(module, 'conda_pythons', lambda: list(PYTHONS)):
                status, output = scratch.main('--refresh-pins')
            after = scratch.table.read_bytes()
        self.assertEqual(status, 0)
        self.assertEqual(after, before)
        self.assertEqual(output, '::warning title=Platform pins::cryptography 48.0.1 on osx-64 stays as it is, '
                                 'and may no longer hold: 48.0.1 has no wheel for cp311 on osx-64, and the newest '
                                 'release up to 52.0.0 with wheels for all of cp311, cp312, cp313, cp314, cp315 '
                                 'there is 47.0.0\n')

    def test_a_pin_still_the_newest_to_qualify_passes_silently(self) -> None:
        # #2028: 48.0.1 is the newest release with an osx-64 wheel for every Python, so it is not lost.
        module = vendor()
        with Scratch(table()) as scratch:
            before = scratch.table.read_bytes()
            module._fetch = lambda name: recorded(**{'47.0.0': files('47.0.0', 'cp311-abi3-macosx_10_9_universal2')})
            with mock.patch.object(module, 'conda_pythons', lambda: list(PYTHONS)):
                status, output = scratch.main('--refresh-pins')
            after = scratch.table.read_bytes()
        self.assertEqual(status, 0)
        self.assertEqual(after, before)
        self.assertEqual(output, '')


class CheckTests(unittest.TestCase):
    """``--check`` on a pin in date and past it, never reading the network."""

    def test_review_reports_a_pin_past_its_date_only(self) -> None:
        review = vendor().review
        due = datetime.date(2026, 12, 1)
        self.assertEqual(review(table(review_by=due), due - datetime.timedelta(days=1)), [])
        self.assertEqual(review(table(review_by=due), due), [])
        self.assertEqual(review(table(review_by=due), due + datetime.timedelta(days=1)), [
            'overdue: cryptography is pinned to 48.0.1 on osx-64, and was due for review by 2026-12-01; '
            'check the pin still holds, then set a new review-by date, such as 2027-03-03'])

    def test_check_passes_on_a_pin_in_date(self) -> None:
        with Scratch(table(review_by=TODAY)) as scratch, mock.patch.dict(sys.modules, {'requests': None}):
            self.assertEqual(scratch.main(), (0, ''))
            self.assertEqual(scratch.main('--check'), (0, ''))

    def test_check_fails_on_a_pin_past_its_date(self) -> None:
        with Scratch(table(review_by=TODAY - datetime.timedelta(days=1))) as scratch, \
                mock.patch.dict(sys.modules, {'requests': None}):
            self.assertEqual(scratch.main(), (0, ''))
            status, output = scratch.main('--check')
        self.assertEqual(status, 1)
        self.assertEqual(output, 'conda/platform-pins.toml: overdue: cryptography is pinned to 48.0.1 on osx-64, '
                                 'and was due for review by 2026-10-16; check the pin still holds, then set a new '
                                 'review-by date, such as 2027-01-16\n')


class TableFileTests(unittest.TestCase):
    """:file:`conda/platform-pins.toml` as committed, and as :func:`render_pins` writes it."""

    def test_the_committed_table_is_in_the_form_the_job_writes(self) -> None:
        module = vendor()
        text = module.PINS.read_text(encoding='utf-8')
        self.assertEqual(module.load_pins(text), module.PLATFORM_PINS)
        self.assertEqual(module.render_pins(module.PLATFORM_PINS), text)

    def test_every_committed_pin_says_why(self) -> None:
        for name, platforms in vendor().PLATFORM_PINS.items():
            for subdir, pin in platforms.items():
                with self.subTest(package=name, subdir=subdir):
                    self.assertTrue(pin.reason.strip())

    def test_a_table_reads_back_as_written(self) -> None:
        module = vendor()
        pins = {'cryptography': {'osx-64': module.Pin('48.0.1', TODAY, 'say "why" \\ here\n\x7f, é')},
                'lxml': {'linux-64': module.Pin('6.0', TODAY, ''), 'osx-arm64': module.Pin('6.1', TODAY, 'b')}}
        self.assertEqual(module.load_pins(module.render_pins(pins)), pins)
        self.assertEqual(module.load_pins(module.render_pins({})), {})

    def test_a_malformed_pin_is_refused(self) -> None:
        load = vendor().load_pins
        for text in ('[cryptography.osx-64]\nversion = "48.0.1"\nreason = "r"\n',
                     '[cryptography.osx-64]\nversion = "48.0.1"\nreview-by = "2027-01-15"\nreason = "r"\n',
                     '[cryptography.osx-64]\nversion = "48.0.1"\nreview-by = 2027-01-15T00:00:00\nreason = "r"\n',
                     '[cryptography.osx-64]\nversion = 48\nreview-by = 2027-01-15\nreason = "r"\n',
                     '[cryptography.osx-64]\nversion = "48.0.1"\nreview-by = 2027-01-15\nreason = "r"\nnote = 1\n',
                     'cryptography = "48.0.1"\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                load(text)


class VerdictTests(unittest.TestCase):
    """A commit moving a pin is not built under its parent's ``Unit Tests`` verdict (#1643)."""

    def test_the_table_is_not_a_bot_managed_path(self) -> None:
        """:file:`util/verdict_covers_checkout.py` must not wave the table's commits through.

        :file:`util/conda_vendor.py` reads the table on import, so every test of
        that script does, and a moved pin changes what those tests expect of
        :file:`conda/requirements.txt`. A bot commit to the table therefore waits
        for its own ``Unit Tests`` run instead of being covered by its parent's.

        """
        spec = importlib.util.spec_from_file_location('verdict_covers_checkout',
                                                      ROOT / 'util' / 'verdict_covers_checkout.py')
        assert spec is not None and spec.loader is not None
        verdict = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verdict)  # type: ignore[union-attr]
        self.assertEqual(vendor().PINS, ROOT / 'conda' / 'platform-pins.toml')
        self.assertNotIn('conda/platform-pins.toml', verdict.BOT_MANAGED_PATHS)


#: A requirement's project name, at the start of a requirement specifier.
REQUIREMENT_NAME = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?')


def pip_installs(line: 'str') -> 'list[str]':
    """The projects a ``python -m pip install`` shell line names, normalised; none for any other line.

    Split as the shell would, so nothing after a ``#`` counts (#1902), and each
    requirement read for its project name, so ``requests[socks]`` and
    ``requests>=2`` are both :mod:`requests`. Options, and an argument that is
    not a project name, such as ``.[all]``, name nothing.

    """
    # Checked before the split, which raises on a quote another line closes.
    if line.split()[:4] != ['python', '-m', 'pip', 'install']:
        return []
    names = []  # type: list[str]
    for word in shlex.split(line, comments=True)[4:]:
        match = None if word.startswith('-') else REQUIREMENT_NAME.match(word)
        if match is not None:
            names.append(re.sub(r'[-_.]+', '-', match.group()).lower())
    return names


class PipInstallsTests(unittest.TestCase):
    """:func:`pip_installs` reads an install line for the projects it installs, as pip would."""

    def test_a_requirement_is_read_for_its_name(self) -> None:
        for line, expected in (
                ('python -m pip install -U pip requests', ['pip', 'requests']),
                ('python -m pip install requests[socks]', ['requests']),
                ("python -m pip install 'requests>=2'", ['requests']),
                ('python -m pip install Requests_Toolbelt', ['requests-toolbelt']),
                ('python -m pip install -e .[all]', []),
                ('python util/conda_vendor.py requests', []),
                ("echo 'requests", []),
        ):
            with self.subTest(line=line):
                self.assertEqual(pip_installs(line), expected)

    def test_a_name_after_a_comment_is_not_installed(self) -> None:
        # #1902: split without comment handling, ``requests`` here read as installed.
        self.assertEqual(pip_installs('python -m pip install -e .[all]  # requests comes later'), [])
        self.assertEqual(pip_installs('python -m pip install pip # requests'), ['pip'])


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
class WorkflowTests(unittest.TestCase):
    """``conda-update`` refreshes the pins after installing ``.[all]`` and before writing the requirements."""

    def setUp(self) -> None:
        self.jobs = _workflows.load(WORKFLOW)['jobs']
        self.steps = self.jobs['conda-update']['steps']

    def index(self, found: 'Any') -> 'int':
        """The index of the one ``conda-update`` step ``found`` holds for."""
        hits = [index for index, step in enumerate(self.steps) if found(step)]
        self.assertEqual(len(hits), 1, hits)
        return hits[0]

    @staticmethod
    def runs(step: 'dict[str, Any]') -> 'list[str]':
        return [line.strip() for line in str(step.get('run', '')).splitlines()
                if line.strip() and not line.strip().startswith('#')]

    def refreshes(self, step: 'dict[str, Any]') -> 'bool':
        """Whether ``step`` runs the refresh, its log kept for the run report (#2030)."""
        return self.runs(step) == ['set -o pipefail', 'python util/conda_vendor.py --refresh-pins | '
                                                      'tee "$RUNNER_TEMP/platform-pins.log"']

    def test_the_refresh_runs_between_the_install_and_the_writer(self) -> None:
        refresh = self.index(self.refreshes)
        install = self.index(lambda step: "python -m pip install -e '.[all]'" in self.runs(step))
        writer = self.index(lambda step: 'python util/conda_vendor.py' in self.runs(step))
        changed = self.index(lambda step: step.get('id') == 'verify-changed-files')
        self.assertLess(install, refresh)
        self.assertLess(refresh, writer)
        self.assertLess(writer, changed)
        for key in ('if', 'continue-on-error'):
            with self.subTest(key=key):
                self.assertNotIn(key, self.steps[refresh])

    def test_the_job_installs_requests_before_the_refresh(self) -> None:
        """``.[all]`` does not bring :mod:`requests`, which ``--refresh-pins`` reads PyPI with."""
        refresh = self.index(self.refreshes)
        installs = [index for index, step in enumerate(self.steps) for line in self.runs(step)
                    if 'requests' in pip_installs(line)]
        self.assertTrue(installs, 'no step of conda-update installs requests')
        self.assertLess(min(installs), refresh)

    def test_the_commit_takes_the_rewritten_table(self) -> None:
        commit = self.index(lambda step: step.get('name') == 'Commit Changes')
        self.assertIn('git commit -am', str(self.steps[commit]['run']))

    def test_no_other_job_reads_pypi_for_the_pins(self) -> None:
        for job_id, job in self.jobs.items():
            if job_id == 'conda-update':
                continue
            for step in job.get('steps', ()):
                with self.subTest(job=job_id, step=step.get('name')):
                    self.assertNotIn('--refresh-pins', str(step.get('run', '')))


class TomllibGuardTests(unittest.TestCase):
    """Without :mod:`tomllib`, as on the 3.8 to 3.10 legs, every other test here passes or skips (#1898).

    Those legs read green even when a test fails (#1679), so a test reaching the
    script's module-level ``import tomllib`` other than through :func:`load_vendor`
    shows only in their annotations. This runs the rest of the module with
    :mod:`tomllib` gone instead, on any interpreter.

    """

    def test_every_other_test_passes_or_skips_without_tomllib(self) -> None:
        module = sys.modules[__name__]
        loader = unittest.defaultTestLoader
        suite = unittest.TestSuite(
            loader.loadTestsFromTestCase(case) for case in vars(module).values()
            if isinstance(case, type) and issubclass(case, unittest.TestCase)
            and case.__module__ == __name__ and case is not type(self))
        result = unittest.TestResult()
        with mock.patch.dict(sys.modules, {'tomllib': None}), mock.patch.object(module, 'tomllib', None), \
                mock.patch.object(module, '_MODULE', []):
            suite.run(result)
        self.assertEqual([f'{test.id()}: {trace.strip().splitlines()[-1]}'
                          for test, trace in result.errors + result.failures], [])
        skipped = {test.id().rpartition('.')[2] for test, reason in result.skipped if 'tomllib' in reason}
        self.assertIn('test_without_requests_only_the_request_fails', skipped)


if __name__ == '__main__':
    unittest.main()
