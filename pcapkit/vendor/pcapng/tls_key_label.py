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
#: the hand-written ``pcapkit.protocols.misc.pcapng.TLSKeyLabel`` -- ``RSA`` has no row in
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

from typing import TYPE_CHECKING

from aenum import StrEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['{NAME}']


class {NAME}(EnumRegistry, StrEnum):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it is a :class:`str`, this registry's member type.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` so
        that :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses a
        value :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`). There is no ``_missing_`` here to take a
        range from -- the constructor refuses every value no member carries --
        so the member type is the whole check, and any :class:`str` label may
        still be minted.

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` is not a :class:`str`. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not isinstance(value, str):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))
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
            registry itself. The second element is always empty: the
            generated :class:`pcapkit.const.pcapng.tls_key_label.TLSKeyLabel`
            has no ``_missing_`` -- its constructor refuses every value no
            member carries -- so there is nothing to render there.

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
            # rows fetched on 2026-09-28 are ``[RFC9850]``, so each takes the
            # ``rfc == '9850'`` branch; a future registry
            # change either still fits it or raises here for a human to look
            # at, rather than rendering a citation nobody checked. IANA has
            # spelt it ``[RFC 9850]`` since 2026-10-13, which fits too (#1664).
            match = re.fullmatch(r'\[RFC\s*(\d+)\]', ref)
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
            # NOTE: mirrors the ``nosec B105`` bandit suppression every
            # such member carried in the hand-written
            # ``pcapkit.protocols.misc.pcapng.TLSKeyLabel`` (#882) --
            # bandit's B105 (hardcoded password string) flags a string
            # constant assigned to a name containing ``SECRET``, which most
            # of these labels' names do.
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
