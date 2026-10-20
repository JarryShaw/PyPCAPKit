# -*- coding: utf-8 -*-
"""The :mod:`pcapkit.vendor` crawlers read their own variables.

GitHub issue #1726: #1743 moved ``pcapkit.vendor.default.MAX_RETRY`` and
``CI_MODE``, and the proxy lookups, into :mod:`pcapkit.utilities.config`; the
issue then settled that the crawlers keep their variables in
:mod:`pcapkit.vendor`. So :mod:`pcapkit.vendor.default` reads
:envvar:`PCAPKIT_VENDOR_RETRY` and :envvar:`PCAPKIT_CI_MODE` itself, through the
public :func:`~pcapkit.utilities.config.read_limit` and
:func:`~pcapkit.utilities.config.read_flag`, so a bad value still warns with a
:exc:`~pcapkit.utilities.warnings.ConfigWarning` and falls back; and
:func:`~pcapkit.vendor.default.get_proxies` reads the proxy variables itself, on
every call.

Nothing here makes a network call: ``requests.get`` is replaced for the whole of
each case. The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture.

"""
from __future__ import annotations

import ast
import collections
import importlib
import importlib.util
import os
import pathlib
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises pcapkit.vendor, which users run on any supported
#: interpreter.
__tier__ = 'ALL'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The module under test, read as text.
SOURCE = ROOT / 'pcapkit' / 'vendor' / 'default.py'

#: Every distribution importing :mod:`pcapkit.vendor` needs, as
#: :file:`tests/vendor/test_user_agent_unit.py` explains.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: The crawlers' variables, all documented with :mod:`pcapkit.vendor.default`.
VARIABLES = ('PCAPKIT_VENDOR_RETRY', 'PCAPKIT_CI_MODE', 'PCAPKIT_HTTP_PROXY', 'PCAPKIT_HTTPS_PROXY')


class _VendorCase(unittest.TestCase):
    """A fresh import of :mod:`pcapkit.vendor.default` from this checkout."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        import pcapkit.vendor.default as default
        from pcapkit.utilities.warnings import ConfigWarning

        resolved = pathlib.Path(default.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{default.__name__} was imported from {resolved}, which is outside {ROOT}')
        self.default = default
        self.ConfigWarning = ConfigWarning


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class DeclarationTests(_VendorCase):
    """``MAX_RETRY`` and ``CI_MODE``: each one's variable, default and minimum."""

    def load(self, name: str, text: 'str | None') -> 'tuple[object, list[str]]':
        """``default.<name>`` with only its variable set, to ``text``, and the ConfigWarnings given."""
        variable = {'MAX_RETRY': 'PCAPKIT_VENDOR_RETRY', 'CI_MODE': 'PCAPKIT_CI_MODE'}[name]
        env = {key: value for key, value in os.environ.items() if not key.startswith('PCAPKIT_')}
        if text is not None:
            env[variable] = text
        try:
            with mock.patch.dict(os.environ, env, clear=True), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                importlib.reload(self.default)
            return getattr(self.default, name), [str(item.message) for item in caught
                                                 if issubclass(item.category, self.ConfigWarning)]
        finally:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                importlib.reload(self.default)

    def test_the_names_are_back(self) -> None:
        self.assertIsInstance(self.default.MAX_RETRY, int)
        self.assertIsInstance(self.default.CI_MODE, bool)

    def test_max_retry_reads_pcapkit_vendor_retry(self) -> None:
        self.assertEqual(self.load('MAX_RETRY', '4'), (4, []))
        # Above the default is taken silently: there is no risk to report, and
        # .github/workflows/cron-vendor.yml sets 10.
        self.assertEqual(self.load('MAX_RETRY', '10'), (10, []))

    def test_max_retry_defaults_to_five(self) -> None:
        self.assertEqual(self.load('MAX_RETRY', None), (5, []))

    def test_max_retry_takes_one_and_refuses_anything_below(self) -> None:
        self.assertEqual(self.load('MAX_RETRY', '1'), (1, []))
        # 0 was read as 1 before #1726, and -1 is no limit only where a limit
        # has a risk to name; here both are refused, as is a non-integer, which
        # crashed the import.
        for text in ('0', '-1', 'lots'):
            with self.subTest(text=text):
                value, messages = self.load('MAX_RETRY', text)
                self.assertEqual((value, len(messages)), (5, 1), messages)
                self.assertEqual(messages[0], f'PCAPKIT_VENDOR_RETRY={text!r} is not an integer '
                                              'of at least 1; using the default, 5')

    def test_ci_mode_reads_pcapkit_ci_mode(self) -> None:
        # 1 is what .github/workflows/cron-vendor.yml sets.
        for text in ('1', 'yes', ' On '):
            with self.subTest(text=text):
                self.assertEqual(self.load('CI_MODE', text), (True, []))
        self.assertEqual(self.load('CI_MODE', 'off'), (False, []))

    def test_ci_mode_defaults_to_off(self) -> None:
        self.assertEqual(self.load('CI_MODE', None), (False, []))

    def test_a_bad_ci_mode_warns_and_falls_back_to_off(self) -> None:
        value, messages = self.load('CI_MODE', 'maybe')
        self.assertEqual((value, len(messages)), (False, 1), messages)
        self.assertTrue(messages[0].startswith("PCAPKIT_CI_MODE='maybe' is not one of "), messages[0])
        self.assertTrue(messages[0].endswith('; using the default, False'), messages[0])


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class ReaderTests(_VendorCase):
    """``Vendor._request`` and ``get_proxies`` read the variables of this module."""

    def fetch(self, retry: int, proxies: 'dict[str, str]') -> 'tuple[list[object], list[str]]':
        """The proxies of every request a failing crawl makes, and its retry notices.

        ``MAX_RETRY`` is patched to ``retry``, and ``CI_MODE`` on, so the crawl
        fails rather than prompting once both loops are spent.

        """
        import requests

        default = self.default

        class Crawler(default.Vendor):
            FLAG = 'isinstance(value, int)'
            LINK = 'https://example.invalid/registry'

            def count(self, data: object) -> 'collections.Counter[str]':
                return collections.Counter()

            def process(self, data: object) -> 'tuple[list[str], list[str]]':
                return [], []

        fetched = []  # type: list[object]

        def fail(url: object, **kwargs: object) -> object:
            fetched.append(kwargs.get('proxies'))
            return mock.Mock(ok=False, text='')

        with mock.patch.object(requests, 'get', fail), \
                mock.patch.object(default, 'get_proxies', return_value=proxies), \
                mock.patch.object(default, 'CI_MODE', True), \
                mock.patch.object(default, 'MAX_RETRY', retry), \
                warnings.catch_warnings(record=True) as caught, \
                self.assertRaises(requests.RequestException):
            warnings.simplefilter('always')
            Crawler.__new__(Crawler)._request()  # pylint: disable=protected-access
        notices = [str(item.message) for item in caught]
        return fetched, [text for text in notices if text.startswith((
            'Connection failed; retry for ', 'Connection failed; retry with proxy for '))]

    def test_max_retry_in_the_direct_loop(self) -> None:
        for retry in (2, 3):
            with self.subTest(retry=retry):
                fetched, notices = self.fetch(retry, {})
                self.assertEqual(fetched, [None] * retry)
                # The notice counts against the configured retry, not the default 5.
                self.assertEqual(notices, [f'Connection failed; retry for {count}/{retry}...'
                                           for count in range(1, retry + 1)])

    def test_max_retry_in_the_proxy_loop(self) -> None:
        proxies = {'http': 'http://proxy.invalid'}
        for retry in (2, 3):
            with self.subTest(retry=retry):
                fetched, notices = self.fetch(retry, proxies)
                self.assertEqual(fetched, [None] * retry + [proxies] * retry)
                self.assertEqual(notices, [f'Connection failed; retry for {count}/{retry}...'
                                           for count in range(1, retry + 1)]
                                 + [f'Connection failed; retry with proxy for {count}/{retry}...'
                                    for count in range(1, retry + 1)])

    def test_proxies_are_read_on_every_call(self) -> None:
        # Set after the import: the variables are read on every call, as
        # get_proxies always read them.
        with mock.patch.dict(os.environ, {'PCAPKIT_HTTP_PROXY': 'http://late'}):
            os.environ.pop('PCAPKIT_HTTPS_PROXY', None)
            self.assertEqual(self.default.get_proxies(), {'http': 'http://late'})
        with mock.patch.dict(os.environ, {'PCAPKIT_HTTPS_PROXY': 'http://later'}):
            os.environ.pop('PCAPKIT_HTTP_PROXY', None)
            self.assertEqual(self.default.get_proxies(), {'https': 'http://later'})
        with mock.patch.dict(os.environ, {'PCAPKIT_HTTP_PROXY': 'http://a', 'PCAPKIT_HTTPS_PROXY': 'http://b'}):
            self.assertEqual(self.default.get_proxies(), {'http': 'http://a', 'https': 'http://b'})


class LayoutTests(unittest.TestCase):
    """Where the variables are read and documented; read as text, so no extra is needed."""

    def test_only_the_public_readers_of_config_are_used(self) -> None:
        used = {node.attr for node in ast.walk(ast.parse(SOURCE.read_text(encoding='utf-8')))
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == 'config'}
        self.assertEqual(used, {'read_limit', 'read_flag'})

    def test_every_variable_is_documented_with_the_crawlers(self) -> None:
        docs = ROOT / 'docs' / 'source' / 'pcapkit'
        vendor = (docs / 'vendor' / 'default.rst').read_text(encoding='utf-8')
        config = (docs / 'utilities' / 'config.rst').read_text(encoding='utf-8')
        for variable in VARIABLES:
            with self.subTest(variable=variable):
                self.assertIn(f'.. envvar:: {variable}\n', vendor)
                self.assertNotIn(f'.. envvar:: {variable}\n', config)
                self.assertIn(f':envvar:`{variable}`', config)
        for name in ('MAX_RETRY', 'CI_MODE'):
            with self.subTest(name=name):
                self.assertIn(f'.. autodata:: pcapkit.vendor.default.{name}\n', vendor)

    def test_no_removal_notice_is_left(self) -> None:
        docs = ROOT / 'docs' / 'source' / 'pcapkit' / 'vendor' / 'default.rst'
        for path in (SOURCE, docs):
            with self.subTest(path=path.name):
                self.assertNotIn('versionremoved', path.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
