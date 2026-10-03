# -*- coding: utf-8 -*-
"""IPv6 Extension Header Types
=================================

.. module:: pcapkit.vendor.ipv6.extension_header

This module contains the vendor crawler for **IPv6 Extension Header Types**,
which is automatically generating :class:`pcapkit.const.ipv6.extension_header.ExtensionHeader`.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter
    from typing import Callable

__all__ = ['ExtensionHeader']

LINE = lambda NAME, DOCS, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['{NAME}']


class {NAME}(EnumRegistry, IntEnum):
    """[{NAME}] {DOCS}"""

    {ENUM}
'''  # type: Callable[[str, str, str, str], str]


class ExtensionHeader(Vendor):
    """IPv6 Extension Header Types"""

    #: Keyword-style names carried over from this crawler's *previous* data
    #: source, keyed by protocol number. The Protocol Numbers registry
    #: (``protocol-numbers-1.csv``, this crawler's :attr:`LINK` before GitHub
    #: issue :issue:`925`) paired each of these headers with a short ``Keyword``
    #: column value, e.g. ``IPv6-Route`` for header 43. The registry
    #: :attr:`LINK` now points at -- IANA's authoritative *IPv6 Extension
    #: Header Types* registry -- has no such column, only a verbose
    #: ``Description`` (``Routing Header for IPv6`` for the same header), so
    #: deriving names the same way :meth:`process` does for every other
    #: 3-column registry (see e.g. :class:`~pcapkit.vendor.ipv6.router_alert.
    #: RouterAlert`) would silently rename these members. This mapping keeps
    #: the existing, shorter names instead; any header not listed here still
    #: falls back to a name derived from its description, same as always.
    NAMES = {
        0: 'HOPOPT',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        50: 'ESP',
        51: 'AH',
        60: 'IPv6-Opts',
        139: 'HIP',
        140: 'Shim6',
    }  # type: dict[int, str]

    #: Link to registry.
    #:
    #: .. note::
    #:
    #:    Until GitHub issue :issue:`925`, this pointed at the *Protocol Numbers*
    #:    registry (``protocol-numbers/protocol-numbers-1.csv``), filtered on
    #:    its ``IPv6 Extension Header`` column -- a derived signal, not the
    #:    registry :rfc:`8200#section-4` names as authoritative for this
    #:    enumeration. That registry disagreed with this one on header 147
    #:    (``BIT-EMU``): it flagged 147 as an IPv6 extension header, citing
    #:    :rfc:`9801`, while this registry omits 147 entirely -- see the issue
    #:    for the reading of :rfc:`9801` that makes the omission look
    #:    intentional rather than an erratum. Fixing :attr:`LINK` also let
    #:    :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` drop
    #:    ``BIT_EMU``: :attr:`pcapkit.protocols.internet.ipv6.IPv6
    #:    ._decode_next_layer`'s walk used to rely on ``ExtensionHeader(147)``
    #:    resolving, but its own test (``tests.protocols.internet
    #:    .test_ipv6_ext_unit.IPv6ExtUnitTests
    #:    .test_unimplemented_terminal_code_stops_the_walk_not_the_packet``)
    #:    now exercises the identical code path on 253 -- a code this
    #:    registry *does* list -- so nothing outside this package depends on
    #:    147 resolving any more.
    LINK = 'https://www.iana.org/assignments/ipv6-parameters/extension-header.csv'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(
            map(lambda item: self.safe_name(self.NAMES.get(int(item[0]), item[1])),
                filter(lambda item: len(item[0].split('-')) != 2, reader)))

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        miss = []  # type: list[str]
        for item in reader:
            code_str = item[0]
            desc = item[1]
            rfcs = item[2]

            keyword = self.NAMES.get(int(code_str)) if code_str.isdigit() else None
            name = keyword or desc

            temp = []  # type: list[str]
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            name_part = f'{keyword}, {desc}' if keyword else desc
            comment = self.wrap_comment(re.sub(r'\r*\n', ' ', '%s %s' % (  # pylint: disable=consider-using-f-string
                name_part, ''.join(temp) if rfcs else '',
            ), flags=re.MULTILINE))

            try:
                code, _ = code_str, int(code_str)
                renm = self.rename(name, code, original=keyword)

                pres = f"{renm} = {code}"
                sufs = f"#: {comment}"

                #if len(pres) > 74:
                #    sufs = f"\n{' '*80}{sufs}"

                #enum.append(f'{pres.ljust(76)}{sufs}')
                enum.append(f'{sufs}\n    {pres}')
            except ValueError:
                start, stop = code_str.split('-')

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {comment}')
                miss.append(f"    return extend_enum(cls, '{self.safe_name(name)}_%d' % value, value)")
        return enum, miss

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        enum, _ = self.process(data)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum))
        return LINE(self.NAME, self.DOCS, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(ExtensionHeader())  # type: ignore[arg-type]
