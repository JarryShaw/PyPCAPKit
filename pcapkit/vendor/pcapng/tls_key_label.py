# -*- coding: utf-8 -*-
"""TLS Key Log Labels
========================

.. module:: pcapkit.vendor.pcapng.tls_key_label

This module contains the vendor crawler for **TLS Key Log Labels**,
which is automatically generating :class:`pcapkit.const.pcapng.tls_key_label.TLSKeyLabel`.

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

__all__ = ['TLSKeyLabel']

#: Hand-carried comment for the ``RSA`` member, copied verbatim from the text
#: GitHub issue :issue:`882` gave it in
#: :class:`pcapkit.protocols.misc.pcapng.TLSKeyLabel` -- ``RSA`` has no row in
#: :attr:`TLSKeyLabel.LINK`'s registry to generate a comment from (``grep -c
#: RSA`` on the fetched CSV is 0), so it is carried across rather than
#: derived, per GitHub issue :issue:`886`'s first constraint. The embedded
#: ``\n    #: `` continuations match every other multi-line member comment
#: this crawler (and its siblings) emit, so the rendered class body indents
#: correctly once :meth:`TLSKeyLabel.context` joins it in.
RSA_COMMENT = ('NSS-historical: not a registered label of :rfc:`9850#section-4.2`\'s "TLS\n'
               '    #: SSLKEYLOGFILE Labels" registry. Defined by the Mozilla NSS\n'
               '    #: ``SSLKEYLOGFILE`` convention and removed in NSS 3.34; kept here only so\n'
               '    #: that key logs predating :rfc:`9850` still read.')

LINE = lambda NAME, DOCS, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from aenum import StrEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['{NAME}']


class {NAME}(EnumRegistry, StrEnum):
    """[{NAME}] {DOCS}"""

    {ENUM}
'''  # type: Callable[[str, str, str, str], str]


class TLSKeyLabel(Vendor):
    """TLS Key Log Labels"""

    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/tls-parameters/tls-sslkeylogfile-labels.csv'

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[0]), reader))

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields. ``RSA`` is prepended by
            hand -- see :data:`RSA_COMMENT` -- since it has no row in the
            registry itself. The second element is always empty: this
            registry does not mint an ``_missing_`` (see
            :class:`pcapkit.const.pcapng.tls_key_label.TLSKeyLabel`'s own
            docstring for why), so there is nothing to render there.

        """
        enum = [
            f"#: {RSA_COMMENT}\n    RSA = 'RSA'",
        ]  # type: list[str]

        reader = csv.reader(data)
        next(reader)  # header
        for item in reader:
            label, desc, ref = item[0].strip(), item[1].strip(), item[2].strip()

            # NOTE: fails loudly rather than guessing. A silent fallback to
            # '9850' here would mis-cite a future row referenced by anything
            # other than a bare ``[RFCnnnn]``, and blindly appending
            # ``#section-4.2`` below to whatever number *did* match would
            # mis-cite a row citing a different RFC entirely -- section 4.2 is
            # specifically RFC 9850's own "TLS SSLKEYLOGFILE Labels" registry
            # section, not a fact about any other RFC's structure. All ten
            # rows fetched as of 2026-09-28 are ``[RFC9850]``, so this always
            # takes the ``rfc == '9850'`` branch today; a future registry
            # change either still fits it or raises here for a human to look
            # at, rather than rendering a citation nobody checked.
            match = re.match(r'\[RFC(\d+)\]\Z', ref)
            if match is None:
                raise ValueError(
                    f'{label!r} cites {ref!r}, which this crawler does not know how to '
                    f'render as an RFC citation -- extend the parsing rather than letting '
                    f'it guess')
            rfc = match.group(1)
            section = '#section-4.2' if rfc == '9850' else ''

            renm = self.safe_name(label)
            sufs = self.wrap_comment(f'{desc}, c.f., :rfc:`{rfc}{section}`.')

            pref = f"{renm} = '{label}'"
            # NOTE: mirrors the ``# nosec B105`` bandit suppression every
            # such member already carries in
            # :class:`pcapkit.protocols.misc.pcapng.TLSKeyLabel` as of #882 --
            # bandit's B105 (hardcoded password string) flags a string
            # constant assigned to a name containing ``SECRET``, which eight
            # of these ten labels' names do.
            if 'SECRET' in label:
                pref += '  # nosec B105'

            enum.append(f'#: {sufs}\n    {pref}')
        return enum, []

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        enum, _ = self.process(data)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum)).strip()
        return LINE(self.NAME, self.DOCS, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(TLSKeyLabel())  # type: ignore[arg-type]
