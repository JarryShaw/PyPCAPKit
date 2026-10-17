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

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['{NAME}']


class {NAME}(EnumRegistry, IntEnum):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it fits the 8-bit Next Header field.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` so
        that :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses a
        value no extension header can carry, as
        :meth:`~pcapkit.corekit.enum.EnumLookup.get` does, in the same words
        (:issue:`1816`). There is no ``_missing_`` here to take a range from
        -- the constructor refuses every value no member carries -- so the
        range is that of the Next Header field an extension header type is
        sent in (:rfc:`8200#section-3`), and an unassigned type within it may
        still be minted.

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` is not an :class:`int` in
                ``0``-``255``. A :exc:`ValueError`, so an ``except
                ValueError`` caller is unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))
'''  # type: Callable[[str, str, str, str], str]


class ExtensionHeader(Vendor):
    """IPv6 Extension Header Types"""

    #: Keyword-style names carried over from this crawler's *previous* data
    #: source, keyed by protocol number. The Protocol Numbers registry
    #: (``protocol-numbers-1.csv``, this crawler's :attr:`LINK` before GitHub
    #: issue :issue:`925`) paired each of these headers with a short ``Keyword``
    #: column value, e.g. ``IPv6-Route`` for header 43. The registry
    #: :attr:`LINK` points at -- IANA's authoritative *IPv6 Extension
    #: Header Types* registry -- has no such column, only a verbose
    #: ``Description`` (``Routing Header for IPv6`` for the same header), so
    #: deriving names the same way :meth:`process` does for every other
    #: 3-column registry (see e.g.
    #: :class:`~pcapkit.vendor.ipv6.router_alert.RouterAlert`)
    #: would silently rename these members. This mapping keeps
    #: the shorter names instead; any header not listed here falls back to a
    #: name derived from its description.
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
    #:    This is the registry :rfc:`8200#section-4` names as authoritative for
    #:    this enumeration, rather than the *Protocol Numbers* registry
    #:    (``protocol-numbers/protocol-numbers-1.csv``) filtered on its ``IPv6
    #:    Extension Header`` column, which is a derived signal (GitHub issue
    #:    :issue:`925`). The two disagree on header 147 (``BIT-EMU``): the
    #:    Protocol Numbers registry flags 147 as an IPv6 extension header,
    #:    citing :rfc:`9801`, while this registry omits 147 entirely -- see the
    #:    issue for the reading of :rfc:`9801` that makes the omission look
    #:    intentional rather than an erratum. So
    #:    :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` has no
    #:    ``BIT_EMU``, and the walk in :meth:`IPv6._decode_next_layer
    #:    <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>` does not
    #:    depend on ``ExtensionHeader(147)`` resolving: its test
    #:    (``tests.protocols.internet.test_ipv6_ext_unit.IPv6ExtUnitTests
    #:    .test_unimplemented_terminal_code_stops_the_walk_not_the_packet``)
    #:    exercises that code path on 253, a code this registry *does* list.
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
            for rfc in self.split_references(rfcs):
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
