# -*- coding: utf-8 -*-
"""Regression tests for the ``User-Agent`` the vendor crawlers send.

GitHub issue #518: :meth:`pcapkit.vendor.default.Vendor._request` used to call
``requests.get(self.LINK)`` with no headers at all, in both its direct and its
proxy branch. Wikimedia rejects |requests|_' default ``python-requests/<version>``
agent outright -- measured 2026-09-19 as HTTP 403 and 126 bytes of robot-policy
text, against 200 for a descriptive agent, reproduced on four separate articles
with nothing but the header changing -- so four crawlers could not fetch their
registry at all, and burned ``MAX_RETRY`` attempts against a refusal that no
amount of retrying lifts.

.. |requests| replace:: ``requests``
.. _requests: https://requests.readthedocs.io

What is worth pinning is narrower than "a header is sent", and there are three
parts to it:

* **Both** call sites send it. The proxy branch is the one that gets forgotten,
  because it only runs when the direct fetch has already raised, so a test that
  exercises only the happy path would have passed on the unfixed code's sibling
  bug. :meth:`test_the_proxy_branch_sends_it_too` drives that branch deliberately.
* The agent is **descriptive, not a browser spoof**. Wikimedia's policy asks for
  an agent that identifies the tool and offers a contact address; sending
  ``Mozilla/5.0 …`` would satisfy the 403 and misrepresent the client, so
  :meth:`test_the_agent_is_not_a_browser_spoof` fails on browser tokens.
* It is **composed from package metadata**, so it tracks
  :data:`pcapkit.__version__` instead of going stale as a literal that nobody
  remembers to bump.

No test here makes a network call: ``requests.get`` is replaced by a recorder for
the whole of each case, and :meth:`test_no_request_goes_out_without_the_header`
asserts that every call it saw carried one.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture.

"""
from __future__ import annotations

import contextlib
import importlib.util
import os
import pathlib
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs. ``requests`` is the
#: obvious one -- ``pcapkit.vendor.default`` imports it at module scope -- but it
#: is not sufficient: importing ``pcapkit.vendor.default`` imports the
#: ``pcapkit.vendor`` package first, and its :file:`__init__.py` pulls in all
#: seventeen subpackages, seven of which ``import bs4`` at module scope. So a
#: guard on ``requests`` alone lets the suite error instead of skipping on a
#: machine that happens to have ``requests`` and not ``beautifulsoup4``.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all. They ship in the ``vendor`` extra
#: (:file:`pyproject.toml`), not ``test`` -- so these tests skip on the ``test``
#: and ``gate`` jobs of :file:`.github/workflows/unit-tests.yml`, which never
#: install ``vendor``, but run for real on ``engine-tests``, which does (#738).
#: Guarded the same way
#: :file:`tests/protocols/test_dispatch_registry_unit.py` guards its own optional
#: runtime dependencies, rather than making the whole unit tier depend on the
#: crawlers' requirements. See #518.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Tokens that only appear in a browser's ``User-Agent``. The point of the fix is
#: an agent that says what the client actually is, so any of these appearing in
#: it means the fix has been replaced by a spoof. ``Gecko`` covers both the real
#: token and the ``like Gecko`` every Chromium agent carries.
BROWSER_TOKENS = ('Mozilla', 'AppleWebKit', 'Chrome', 'Chromium', 'Safari',
                  'Gecko', 'Edg/', 'OPR/', 'Opera', 'Trident', 'Firefox')


#: Repository URL the faked metadata advertises. Deliberately unlike
#: :data:`pcapkit.vendor.default.PROJECT_URL`, so that a ``get_user_agent`` which
#: silently fell back to the constant is distinguishable from one that read the
#: metadata it was given.
_MOVED_URL = 'https://example.invalid/moved-repo'

#: Homepage URL the faked metadata also advertises, listed *before* the repository
#: one. Picking this up would mean the label match had degenerated into "first
#: Project-URL wins".
_HOMEPAGE_URL = 'https://example.invalid/home'


class _Response:
    """The parts of :class:`requests.Response` that ``_request`` looks at."""

    def __init__(self, text: 'str' = '<html><body>ok</body></html>',
                 ok: 'bool' = True) -> 'None':
        self.ok = ok
        self.text = text


class _FakeMetadata:
    """The parts of :class:`importlib.metadata.PackageMetadata` the agent reads.

    Args:
        name: Value to return for the ``Name`` field.
        repository_label: Label to file :data:`_MOVED_URL` under. The whole point
            of the parameter is that the caller chooses its *case*, which no real
            installed distribution lets a test vary.

    """

    def __init__(self, name: 'str', repository_label: 'str') -> 'None':
        self.name = name
        self.repository_label = repository_label

    def get(self, key: 'str', default: 'Any' = None) -> 'Any':
        return {'Name': self.name}.get(key, default)

    def get_all(self, key: 'str') -> 'Any':
        if key != 'Project-URL':
            return []
        # ``homepage`` first, so that order alone cannot produce a pass.
        return [f'homepage, {_HOMEPAGE_URL}',
                f'{self.repository_label}, {_MOVED_URL}',
                'changelog, https://example.invalid/changes']


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class VendorUserAgentTests(unittest.TestCase):
    """The descriptive agent, and that both fetch paths actually send it."""

    if TYPE_CHECKING:
        default: 'Any'
        requests: 'Any'

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        import requests

        import pcapkit
        import pcapkit.vendor.default as default

        # The module has to come from this checkout for the assertions to mean
        # anything: a copy imported from an installed distribution elsewhere
        # would be tested instead of the one being changed. That is an
        # environment mismatch rather than a defect, hence a skip.
        resolved = pathlib.Path(default.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{default.__name__} was imported from {resolved}, which is outside '
                          f'{ROOT}; install this checkout with `pip install -e .` to run this '
                          f'suite against it')

        self.default = default
        self.requests = requests
        self.pcapkit = pcapkit

    def _crawler(self, link: 'str' = 'https://example.invalid/registry') -> 'Any':
        """A throwaway crawler with a ``LINK``, built without touching the disk.

        ``Vendor.__init__`` fetches *and writes a constant file* as a side effect
        of construction, which a test has no business doing to the working tree,
        so the two attributes it sets that ``_request`` needs are set by hand.
        ``request`` is reduced to the identity so that the fetched text comes
        straight back and can be asserted on.

        """
        class _Crawler(self.default.Vendor):  # type: ignore[name-defined,misc]
            FLAG = 'isinstance(value, int)'
            LINK = link

            def count(self, data: 'Any') -> 'Any':
                import collections
                return collections.Counter()

            def request(self, text: 'str') -> 'str':  # type: ignore[override]
                return text

            def process(self, data: 'Any') -> 'Any':
                return [], []

        crawler = _Crawler.__new__(_Crawler)
        crawler.NAME = _Crawler.__name__
        crawler.DOCS = 'throwaway'
        return crawler

    def _agent_from_metadata(self, metadata: 'Any') -> 'str':
        """Build the agent as if the distribution metadata were ``metadata``.

        ``get_user_agent`` is :func:`~functools.lru_cache`\\ d, so the cache is
        cleared on both sides of the call: once so the faked metadata is actually
        consulted rather than a cached real answer returned, and once afterwards so
        the fake does not leak into any later case.

        """
        import importlib.metadata as md

        self.default.get_user_agent.cache_clear()
        try:
            with mock.patch.object(md, 'metadata', return_value=metadata):
                return self.default.get_user_agent()
        finally:
            self.default.get_user_agent.cache_clear()

    @contextlib.contextmanager
    def _recording_get(self, *responses: 'Any') -> 'Iterator[list[tuple[Any, Any]]]':
        """Replace ``requests.get`` with a recorder, and hand back its log.

        Each element of ``responses`` is returned by the corresponding call, or
        raised if it is an exception. Running out of them is an error rather than
        a silent repeat, so a test that provokes more fetches than it accounted
        for fails here instead of hanging in ``_request``'s retry loop.

        """
        calls = []  # type: list[tuple[Any, Any]]
        queue = list(responses)

        def fake_get(url: 'Any' = None, **kwargs: 'Any') -> 'Any':
            calls.append((url, kwargs))
            if not queue:
                raise AssertionError(f'unexpected fetch #{len(calls)} of {url!r}')
            reply = queue.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply

        original = self.requests.get
        self.requests.get = fake_get
        try:
            yield calls
        finally:
            self.requests.get = original

    # -- the agent itself ---------------------------------------------------

    def test_agent_names_the_package_its_version_and_a_contact_url(self) -> None:
        agent = self.default.get_user_agent()

        self.assertIsInstance(agent, str)
        self.assertIn(self.pcapkit.__version__, agent,
                      'the agent must carry the package version, so it tracks releases')
        self.assertIn('https://', agent,
                      "Wikimedia's policy asks for a contact address in the agent")
        self.assertIn(self.default.PROJECT_URL.rstrip('/').rsplit('/', 1)[-1], agent,
                      'the agent must name the project, so an operator can be identified')

    def test_the_agent_is_not_a_browser_spoof(self) -> None:
        # Wikimedia asks to be told what the client is. Passing the 403 by
        # pretending to be a browser would work and would be a lie, so it is
        # pinned against rather than left to judgement.
        agent = self.default.get_user_agent()
        for token in BROWSER_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token, agent)

    def test_agent_is_composed_from_metadata_not_hardcoded(self) -> None:
        # The version has to come from pcapkit.__version__ rather than a literal:
        # pointing that name at something else must move the agent with it.
        with mock.patch.object(self.default, '__version__', '99.98.97'):
            self.default.get_user_agent.cache_clear()
            try:
                self.assertIn('99.98.97', self.default.get_user_agent())
            finally:
                self.default.get_user_agent.cache_clear()

    def test_agent_survives_missing_distribution_metadata(self) -> None:
        # Running from a source checkout that was never installed must not raise;
        # the fallback constants stand in for the metadata.
        import importlib.metadata as md

        self.default.get_user_agent.cache_clear()
        with mock.patch.object(md, 'metadata', side_effect=md.PackageNotFoundError):
            try:
                agent = self.default.get_user_agent()
            finally:
                self.default.get_user_agent.cache_clear()
        self.assertIn(self.default.DISTRIBUTION, agent)
        self.assertIn(self.default.PROJECT_URL, agent)
        self.assertIn(self.pcapkit.__version__, agent)

    def test_metadata_is_actually_read_rather_than_hardcoded(self) -> None:
        # The installed metadata happens to agree with DISTRIBUTION and
        # PROJECT_URL, so a get_user_agent() that ignored the metadata entirely
        # would produce the identical string and pass every other case here.
        # Faking it to disagree is the only way to tell the two apart.
        agent = self._agent_from_metadata(_FakeMetadata('RenamedDist', 'repository'))

        self.assertIn('RenamedDist/', agent)
        self.assertIn(_MOVED_URL, agent)
        self.assertNotIn(_HOMEPAGE_URL, agent,
                         'homepage was picked up instead of repository')

    def test_project_url_label_is_matched_case_insensitively(self) -> None:
        # ``get_user_agent`` lowercases the label before comparing it, and the
        # docstring promises as much -- but every real distribution writes
        # ``repository`` in lower case already, so dropping the ``.casefold()``
        # breaks nothing that the installed metadata can reveal. Core metadata
        # does not constrain the case of a Project-URL label, and a wheel built
        # from a ``pyproject.toml`` that spells it ``Repository`` is perfectly
        # legal, so the promise is pinned here with labels that exercise it.
        for label in ('Repository', 'REPOSITORY', 'RePoSiToRy'):
            with self.subTest(label=label):
                agent = self._agent_from_metadata(_FakeMetadata('RenamedDist', label))
                self.assertIn(_MOVED_URL, agent,
                              f'a Project-URL labelled {label!r} was not recognised; '
                              f'the label comparison is case-sensitive')
                self.assertNotIn(self.default.PROJECT_URL, agent,
                                 'fell back to PROJECT_URL rather than reading the metadata')

    def test_unrelated_project_url_labels_are_ignored(self) -> None:
        # The flip side: matching must stay anchored to ``repository`` rather than
        # becoming "any label that looks close enough".
        agent = self._agent_from_metadata(_FakeMetadata('RenamedDist', 'repository-mirror'))

        self.assertNotIn(_MOVED_URL, agent)
        self.assertIn(self.default.PROJECT_URL, agent,
                      'no label matched, so the fallback URL should have been used')

    # -- that it is actually sent -------------------------------------------

    def test_direct_branch_sends_the_user_agent(self) -> None:
        crawler = self._crawler()
        with self._recording_get(_Response()) as calls:
            crawler._request()  # pylint: disable=protected-access

        self.assertEqual(len(calls), 1)
        _, kwargs = calls[0]
        self.assertIn('headers', kwargs, 'the direct fetch sent no headers at all')
        self.assertEqual(kwargs['headers'].get('User-Agent'),
                         self.default.get_user_agent())

    def test_the_proxy_branch_sends_it_too(self) -> None:
        # The bug this guards is sending the header on one path and not the
        # other. Make the direct fetch raise so the proxy branch runs, and give
        # get_proxies() something to find so it is not skipped.
        crawler = self._crawler()
        boom = self.requests.exceptions.RequestException('no route')

        with mock.patch.dict(os.environ, {'PCAPKIT_HTTP_PROXY': 'http://127.0.0.1:9',
                                          'PCAPKIT_HTTPS_PROXY': 'http://127.0.0.1:9'}):
            with self._recording_get(boom, _Response()) as calls:
                with self.assertWarns(Warning):
                    crawler._request()  # pylint: disable=protected-access

        self.assertEqual(len(calls), 2, 'expected a direct attempt then a proxied one')
        _, proxied = calls[1]
        self.assertIn('proxies', proxied, 'the second call was not the proxy branch')
        self.assertIn('headers', proxied, 'the proxy fetch sent no headers at all')
        self.assertEqual(proxied['headers'].get('User-Agent'),
                         self.default.get_user_agent())

    def test_no_request_goes_out_without_the_header(self) -> None:
        # Belt and braces over the two cases above: whatever path _request takes,
        # every fetch it makes carries the agent. Driven through a retry so that
        # the loop's second and third attempts are covered too, not just the
        # first -- a header computed inside the loop could regress on one of them.
        crawler = self._crawler()
        with self._recording_get(_Response(ok=False), _Response(text=''), _Response()) as calls:
            with self.assertWarns(Warning):
                crawler._request()  # pylint: disable=protected-access

        self.assertEqual(len(calls), 3)
        for index, (_, kwargs) in enumerate(calls):
            with self.subTest(fetch=index):
                self.assertEqual(kwargs.get('headers', {}).get('User-Agent'),
                                 self.default.get_user_agent())

    def test_link_none_still_short_circuits(self) -> None:
        # The retired crawlers (#507, #518) rely on this: no LINK means
        # Vendor.request() is called directly and nothing is fetched. Adding the
        # header must not have moved the short-circuit.
        crawler = self._crawler()
        type(crawler).LINK = None

        sentinel = object()
        with mock.patch.object(type(crawler), 'request', return_value=sentinel):
            with self._recording_get() as calls:
                self.assertIs(crawler._request(), sentinel)  # pylint: disable=protected-access
        self.assertEqual(calls, [], 'a crawler with no LINK must not fetch anything')


if __name__ == '__main__':
    unittest.main()
