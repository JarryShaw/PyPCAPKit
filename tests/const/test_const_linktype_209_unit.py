# -*- coding: utf-8 -*-
"""``LinkType(209)`` must resolve to the current name, not the legacy one.

GitHub issue #844: :mod:`pcapkit.const.reg.linktype` declared two members for
value ``209`` -- ``IPMB_LINUX`` first, ``I2C_LINUX`` second -- so
:class:`~aenum.IntEnum`'s "first member defined for a value is canonical" rule
made ``LinkType(209).name`` resolve to ``'IPMB_LINUX'``, the name tcpdump's own
registry (and the generated comment above it) labels "Legacy names (do not
use)". Traced to commit ``cfdf2ab5c7`` (2024-05-04): a regeneration inserted
the legacy row above the current one, because tcpdump's
``http://www.tcpdump.org/linktypes.html`` table lists them in exactly that
order -- ``LINKTYPE_IPMB_LINUX`` (209, marked legacy in its notes column)
ahead of ``LINKTYPE_I2C_LINUX`` (209, the current name). 209 is the *only*
value the table double-assigns, and that legacy note is the only occurrence of
the word "legacy" anywhere in it (measured directly against a live fetch while
fixing this).

The fix is in the generator, :mod:`pcapkit.vendor.reg.linktype`, not in the
generated file: :meth:`~pcapkit.vendor.reg.linktype.LinkType.process` now
sinks any row whose notes column mentions "legacy" into a bucket appended
*after* every other row, so the current name is always the first one defined
for a shared value regardless of the source table's own row order.

This module pins both the symptom and the root cause:

- :class:`LinkType209ConstResolutionTests` -- against the committed, generated
  :class:`pcapkit.const.reg.linktype.LinkType`, the same lookup the issue
  reported.
- :class:`LinkTypeGeneratorLegacyOrderingTests` -- against
  :meth:`~pcapkit.vendor.reg.linktype.LinkType.process` directly, fed a
  two-row fixture reproducing tcpdump's own HTML for value 209 byte-for-byte
  (captured from a live fetch while diagnosing this issue). Needs no network:
  the fixture *is* the table row, not a fetch of it, so this stays reliable in
  CI while still exercising the exact code path a real crawl runs. A
  regeneration that drops the fix reintroduces the wrong order here before it
  ever reaches the committed const file.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules

#: The crawler dependencies :class:`LinkTypeGeneratorLegacyOrderingTests` needs to
#: parse its fixture. Spelled exactly as
#: :data:`tests.vendor.test_request_prompt_unit.VENDOR_DEPS` so this file reaches
#: the **existing** ``HAS_VENDOR_DEPS`` dependency gate rather than minting a new
#: one -- ``tests/_dependency_gates.py:315`` already accounts for that gate, with
#: ``dark={'test': ('html5lib',), 'gate': ('html5lib',)}``, and ``engine-tests``
#: closes it by installing the ``vendor`` extra.
#:
#: ``html5lib`` is the one that is actually missing on ``test``: ``requests`` and
#: ``bs4`` have shipped in the ``test`` extra since #507, but only
#: ``beautifulsoup4[html5lib]`` -- the ``vendor`` and ``all`` extras -- provides a
#: parser (``pyproject.toml:203``, and the note at ``:256-263`` saying so
#: deliberately).
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether all of :data:`VENDOR_DEPS` are importable. Guarded the way
#: :file:`tests/vendor/test_request_prompt_unit.py` guards the same dependencies,
#: rather than making the whole unit tier depend on the crawlers'.
#:
#: Consequence worth knowing: :class:`LinkTypeGeneratorLegacyOrderingTests` is the
#: root-cause pin, and it runs only where the ``vendor`` extra is installed --
#: ``engine-tests`` per-PR, and locally. :class:`LinkType209ConstResolutionTests`
#: needs no parser and so still guards the reported symptom everywhere.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: tcpdump's own two rows for value 209, captured verbatim (modulo
#: whitespace) from a live fetch of ``http://www.tcpdump.org/linktypes.html``
#: on 2026-09-27 -- legacy ``IPMB_LINUX`` first, current ``I2C_LINUX`` second,
#: exactly the order the registry itself lists them in.
LINKTYPE_209_TABLE_HTML = """
<table class="linktypedlt">
<tr><th>header row, skipped by request()</th></tr>
<tr>
<td class="symbol">LINKTYPE_IPMB_LINUX</td>
<td class="number">209</td>
<td class="symbol">DLT_IPMB_LINUX</td>
<td>
Legacy names (do not use) for Linux I2C below.
</td>
</tr>
<tr>
<td class="symbol">LINKTYPE_I2C_LINUX</td>
<td class="number">209</td>
<td class="symbol">DLT_I2C_LINUX</td>
<td>
<a href="linktypes/LINKTYPE_I2C_LINUX.html">Linux I2C packets</a>.
</td>
</tr>
</table>
"""


class LinkType209ConstResolutionTests(unittest.TestCase):
    """Against the generated, committed :class:`~pcapkit.const.reg.linktype.LinkType`."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_value_209_resolves_to_the_current_name(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        self.assertEqual(LinkType(209).name, 'I2C_LINUX',
                         "LinkType(209).name resolved to the legacy "
                         "'IPMB_LINUX' name instead of the current "
                         "'I2C_LINUX' one; see GitHub issue #844")

    def test_the_legacy_name_is_still_reachable_as_an_alias(self) -> None:
        # The fix reorders which name is canonical for 209; it does not take
        # the legacy name away -- both still name the same member by value.
        from pcapkit.const.reg.linktype import LinkType

        self.assertEqual(LinkType['IPMB_LINUX'], LinkType['I2C_LINUX'])
        self.assertEqual(LinkType['IPMB_LINUX'].value, 209)
        self.assertEqual(LinkType['IPMB_LINUX'].name, 'I2C_LINUX')


@unittest.skipUnless(HAS_VENDOR_DEPS, 'requests, bs4 and/or html5lib not installed')
class LinkTypeGeneratorLegacyOrderingTests(unittest.TestCase):
    """Against the generator's own ``process()``, root cause rather than symptom."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    @staticmethod
    def _process_fixture() -> 'list[str]':
        """Run :meth:`LinkType.process` over the value-209 fixture rows.

        Builds the instance with ``object.__new__`` rather than calling
        ``LinkType()`` directly: the real constructor
        (:meth:`pcapkit.vendor.default.Vendor.__init__`) fetches the live
        registry and writes the generated const file as a side effect, and
        this test needs neither -- only the pure :meth:`process` step that
        turns registry rows into rendered enum members.
        """
        import bs4

        from pcapkit.vendor.reg.linktype import LinkType

        soup = bs4.BeautifulSoup(LINKTYPE_209_TABLE_HTML, 'html5lib')
        rows = soup.select('table.linktypedlt tr')[1:]

        inst = object.__new__(LinkType)
        enum, _miss = inst.process(rows)
        return enum

    def test_current_name_is_emitted_before_the_legacy_one(self) -> None:
        enum = self._process_fixture()

        self.assertEqual(len(enum), 2, f'expected exactly 2 rendered members, got: {enum!r}')

        first_name = enum[0].splitlines()[1].split(' = ', 1)[0].strip()
        second_name = enum[1].splitlines()[1].split(' = ', 1)[0].strip()

        self.assertEqual(first_name, 'I2C_LINUX',
                         f'the current name must be emitted first so it is '
                         f'canonical for value 209; got order {[first_name, second_name]!r}')
        self.assertEqual(second_name, 'IPMB_LINUX')

    def test_both_rows_still_render_with_their_own_comment(self) -> None:
        # Reordering must not lose either row or swap their bodies.
        enum = self._process_fixture()
        rendered = '\n'.join(enum)

        self.assertIn('I2C_LINUX = 209', rendered)
        self.assertIn('IPMB_LINUX = 209', rendered)
        self.assertIn('Linux I2C packets', rendered)
        self.assertIn('Legacy names (do not use) for Linux I2C below.', rendered)


if __name__ == '__main__':
    unittest.main()
