# -*- coding: utf-8 -*-
"""Block Types
=================

.. module:: pcapkit.vendor.pcapng.block_type

This module contains the vendor crawler for **Block Types**,
which is automatically generating :class:`pcapkit.const.pcapng.block_type.BlockType`.

"""

import collections
import sys
from typing import TYPE_CHECKING

import bs4

from pcapkit.vendor.default import Vendor

__all__ = ['BlockType']

if TYPE_CHECKING:
    from collections import Counter

    from bs4.element import Tag

###############################################################################
# NOTE: on the registry URL, which this module and its two siblings
# (:mod:`~pcapkit.vendor.pcapng.option_type`,
# :mod:`~pcapkit.vendor.pcapng.record_type`) share. Why all three read ``-03`` is
# stated for readers in the note in ``docs/source/pcapkit/vendor/pcapng.rst``,
# which renders; what follows is the measurement detail behind it. See #518.
#
# The dead ``-02`` URL,
# https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html, serves a
# 77968-byte HTML error page rather than a clean refusal, so ``Vendor._request``
# rejects it on ``page.ok`` and retries MAX_RETRY times against a page that will
# never come back. On ``-02`` the registries are ASCII art inside ``<pre>`` and
# the only HTML ``<table>`` is the running-header one, so
# ``soup.select('table#table-9')`` below finds nothing and raises ``IndexError``.
# Measured across every published revision, ``-03`` is the only one that
# reproduces all three committed constant files byte for byte.
#
# Two renderings of ``-03`` were compared, and both reproduce the three constant
# files byte-identically, so the choice is about exposure rather than data:
#
#   * https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html
#     -- 254640 bytes, 11 ``<table>`` (the header one plus ``table-1``..``-10``),
#     ``Last-Modified: Thu, 24 Jun 2021 01:24:12 GMT``. This is the immutable
#     I-D archive: a static file, frozen at publication.
#   * https://datatracker.ietf.org/doc/html/draft-tuexen-opsawg-pcapng-03
#     -- 272271 bytes, 13 ``<table>``, no ``Last-Modified``. Rendered per
#     request, and the extra ~17 KB is datatracker chrome: a version selector, a
#     "Compare versions" control and a metadata table, plus ten more ``<link>``
#     and two more ``<nav>``.
#
# The archive wins. Selecting tables by id out of a document that gains three
# unrelated ``<table>`` elements from a navigation template, which can change
# whenever the service is redeployed, is gratuitous risk for no gain.
#
# NOTE: the draft has since moved to the OPSAWG working group as
# ``draft-ietf-opsawg-pcapng``, currently at ``-05``. Tracking it is a separate
# change, not a URL swap: the newer revisions alter the registries, and from
# ``draft-ietf-opsawg-pcapng-03`` onwards ``process()`` below dies with
# ``ValueError: invalid literal for int() with base 16: '0x0A0D0AXX'`` on a
# wildcard row it has no handling for.
###############################################################################


class BlockType(Vendor):
    """Block Types"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 0xFFFFFFFF'
    #: Link to registry.
    LINK = 'https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html'

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
        table = soup.select('table#table-9')[0]
        return table.select('tr')[1:]

    def process(self, data: 'list[Tag]') -> 'tuple[list[str], list[str]]':
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for content in data:
            temp = content.select('td')[0].text.strip()
            desc = ' '.join(content.select('td')[1].stripped_strings)

            if 'Reserved' in desc:
                name = 'Reserved'
            else:
                name = self.safe_name(desc.split('.', maxsplit=1)[0].split('(', maxsplit=1)[0].strip())

            try:
                code = int(temp, base=16)
                if name == 'Reserved':
                    name = f'Reserved_0x{code:08x}'

                pref = f'{name} = 0x{code:08x}'
                sufs = self.wrap_comment(desc)

                enum.append(f'#: {sufs}\n    {pref}')
            except ValueError:
                start, stop = map(lambda x: int(x, base=16), temp.split('-'))

                miss.append(f'if 0x{start:08x} <= value <= 0x{stop:08x}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_%08x' % value, value)")
        return enum, miss


if __name__ == '__main__':
    sys.exit(BlockType())  # type: ignore[arg-type]
