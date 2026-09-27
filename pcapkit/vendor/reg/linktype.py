# -*- coding: utf-8 -*-
"""Link-Layer Header Type Values
===================================

.. module:: pcapkit.vendor.reg.linktype

This module contains the vendor crawler for **Link-Layer Header Type Values**,
which is automatically generating :class:`pcapkit.const.reg.linktype.LinkType`.

"""

import collections
import re
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

    from bs4.element import Tag

__all__ = ['LinkType']


class LinkType(Vendor):
    """Link-Layer Header Type Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF'
    #: Link to registry.
    LINK = 'http://www.tcpdump.org/linktypes.html'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records."""
        return collections.Counter()

    def request(self, text: 'str') -> 'list[Tag]':  # type: ignore[override] # pylint: disable=signature-differs
        """Fetch registry table.

        Args:
            text: Context from :attr:`~LinkType.LINK`.

        Returns:
            Rows (``tr``) from registry table (``table``).

        """
        soup = bs4.BeautifulSoup(text, 'html5lib')
        table = soup.select('table.linktypedlt')[0]
        return table.select('tr')[1:]

    def process(self, data: 'list[Tag]') -> 'tuple[list[str], list[str]]':
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        legacy = []  # type: list[str]
        miss = [
            "return extend_enum(cls, 'Unassigned_%d' % value, value)",
        ]

        # Value-aware guard for the ``sink`` decision below (GitHub issue #852,
        # a follow-up to #848/#844). A row's notes mentioning "legacy" is
        # tcpdump's only textual signal for *which* member of a duplicated
        # value is the deprecated one, but that word can appear in a row's
        # notes for an unrelated reason -- e.g. referencing some other,
        # differently-valued code as "the legacy DLT_FOO". Computing which
        # values are genuinely duplicated in this table upfront, independent
        # of row order, stops the sink from firing on a value that has no
        # duplicate to disambiguate in the first place. It does not, on its
        # own, guarantee which member of a *genuine* duplicate pair is
        # correct if tcpdump's own wording is attached to the wrong one of
        # the two -- that residual case still relies on the wording being
        # trustworthy.
        #
        # A range row (``DLT_USER0``..``DLT_USER15``) is never itself routed
        # through ``sink`` (see item 2 in #852), but its *expanded* values
        # still have to count here: a single-value row can legitimately
        # duplicate one of the values a range expands to, and missing that
        # would silently under-count the duplicate the same way the
        # word-only rule did before #852.
        #
        # The single-value branch accepts whatever ``int()`` accepts --
        # a leading sign, PEP 515 underscores -- rather than the narrower
        # ``str.isdigit()``, so it recognises exactly the same values the
        # main loop's own ``int(temp)`` below does. A signed or underscored
        # value is not reachable in tcpdump's live table today (every
        # committed member matches a plain unsigned decimal), but a
        # narrower recognition set here than in the main loop would be the
        # same class of silent under-count this pre-scan exists to close
        # for ranges: a legacy row's value would go uncounted, so its alias
        # would stop being sunk without anything failing loudly.
        def _expand(temp: 'str') -> 'list[int]':
            try:
                return [int(temp)]
            except ValueError:
                pass
            if '–' in temp:  # en dash, not a hyphen -- see the ``except ValueError`` below
                try:
                    start, stop = map(int, temp.split('–'))
                except ValueError:
                    return []
                return list(range(start, stop + 1))
            return []

        value_counts = collections.Counter(
            value
            for temp in (content.select('td.number')[0].text.strip() for content in data)
            for value in _expand(temp)
        )  # type: Counter[int]
        dup_values = {value for value, count in value_counts.items() if count > 1}

        for content in data:
            name = content.select('td.symbol')[0].text.strip()[9:].strip()
            temp = content.select('td.number')[0].text.strip()
            desc = content.select('td.symbol')[1].text.strip()
            cmmt = re.sub(r'\s+', ' ', content.select('td')[3].text.strip()).replace("''", '``').replace('_', r'\_')

            if not name:
                name = desc[4:]

            try:
                code, code_int = temp, int(temp)
                if not name:
                    name = f'Unassigned_{code}'

                pres = f"{name} = {code}"
                if desc:
                    sufs = "#: %s" % self.wrap_comment(f"[``{desc}``] {cmmt}")  # pylint: disable=consider-using-f-string
                else:
                    sufs = "#: %s" % self.wrap_comment(cmmt)

                # if len(pres) > 74:
                #     sufs = f"\n{' '*80}{sufs}"

                # enum.append(f'{pres.ljust(76)}{sufs}')

                # Sink this row after every current entry only when its value
                # is a genuine duplicate (``dup_values`` above) *and* its own
                # notes mention "legacy", so the current name -- not the
                # legacy one -- is the first member defined for that value
                # and therefore wins ``LinkType(value).name``.
                sink = legacy if (code_int in dup_values and 'legacy' in cmmt.lower()) else enum
                sink.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = map(int, temp.split('–'))
                for code in range(start, stop+1):
                    name = f'USER{code-start}'
                    desc = f'DLT_USER{code-start}'

                    pres = f"{name} = {code}"
                    sufs = "#: %s" % self.wrap_comment(f"[``{desc}``] {cmmt}")  # pylint: disable=consider-using-f-string

                    # if len(pres) > 74:
                    #     sufs = f"\n{' '*80}{sufs}"

                    # enum.append(f'{pres.ljust(76)}{sufs}')

                    # Range rows are generic, user-definable placeholders,
                    # never a deprecated/current pair -- so every expanded
                    # member always lands in ``enum`` unconditionally,
                    # rather than through the per-row ``sink`` above.
                    # Otherwise one range row whose notes happened to mention
                    # "legacy" would sink all sixteen expanded members at
                    # once instead of just itself (item 2 in #852).
                    enum.append(f'{sufs}\n    {pres}')

        if legacy:
            # A reader scanning the generated file by value will find these
            # members out of numeric order: sinking appends them here, after
            # every current entry, rather than leaving them at their
            # original position in tcpdump's table (item 4 in #852). Say so
            # once, right where they are emitted -- as a plain ``#`` comment,
            # deliberately, not a ``#:`` one: a ``#:`` line immediately above
            # an attribute becomes that attribute's rendered Sphinx docstring,
            # and this note is about the generator's own source layout, not
            # about what ``IPMB_LINUX`` (or whichever name is sunk here) means
            # to a caller.
            legacy[0] = (
                "# The following legacy alias(es) are emitted here, after every\n"
                "    # current entry above, instead of at their original numeric\n"
                "    # position -- see pcapkit.vendor.reg.linktype.LinkType.process\n"
                "    # for why.\n"
                "    " + legacy[0]
            )
        return enum + legacy, miss


if __name__ == '__main__':
    sys.exit(LinkType())  # type: ignore[arg-type]
