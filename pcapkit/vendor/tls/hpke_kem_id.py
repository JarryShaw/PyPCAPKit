# -*- coding: utf-8 -*-
"""HPKE KEM Identifiers
==========================

.. module:: pcapkit.vendor.tls.hpke_kem_id

This module contains the vendor crawler for **HPKE KEM Identifiers**,
which is automatically generating :class:`pcapkit.const.tls.hpke_kem_id.HpkeKemId`.

The registry is IANA's ``HPKE KEM Identifiers`` table, an eight-column CSV --
``Value, KEM, Nsecret, Nenc, Npk, Nsk, Auth, Reference``. Its rows are the
``kem_id`` an ``encrypted_client_hello`` ``ECHConfig`` carries
(:rfc:`9849#section-4`, :rfc:`9180#section-7.1`).

The crawlers of the HPKE KDF and AEAD identifiers subclass this one, naming the
column of their own CSVs in :attr:`~HpkeKemId.REFERENCE`. IANA writes each value
in hex, and the members keep it. A name keeps its parenthetical, so
``DHKEM(X25519, HKDF-SHA256)`` is ``DHKEM_X25519_HKDF_SHA256``: dropping it, as
:meth:`~pcapkit.vendor.default.Vendor.safe_name` does, would name every DHKEM
``DHKEM``.

"""

import collections
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['HpkeKemId']


def hexlify(code: 'int') -> 'str':
    """Convert code to hex form."""
    return f'0x{code:04X}'


class HpkeKemId(Vendor):
    """HPKE KEM Identifiers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/hpke/hpke-kem-ids.csv'

    #: Column of the ``Reference`` cell.
    REFERENCE = 7

    def safe_name(self, name: 'str') -> 'str':
        """Convert an IANA name cell to a member identifier.

        Args:
            name: Verbatim name cell.

        Returns:
            What :meth:`~pcapkit.vendor.default.Vendor.safe_name` gives for the
            name with its parentheses as spaces, so their content is kept.

        """
        return super().safe_name(re.sub(r'[()]', ' ', name))

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records.

        Args:
            data: CSV data.

        Returns:
            Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(self.safe_name(item[1]) for item in reader if len(item[0].split('-')) != 2)

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
            name = item[1]
            rfcs = item[self.REFERENCE]

            temp = []  # type: list[str]
            for rfc in self.split_references(rfcs):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            body = '%s %s' % (name, ''.join(temp) if rfcs else '')  # pylint: disable=consider-using-f-string
            desc = self.wrap_comment(re.sub(r'\r*\n\s*', ' ', body, flags=re.MULTILINE))

            if len(item[0].split('-')) != 2:
                code = hexlify(int(item[0], base=16))
                renm = self.rename(name, code)

                enum.append(f'#: {desc}\n    {renm} = {code}')
            else:
                start, stop = map(lambda s: hexlify(int(s, base=16)), item[0].split('-'))

                miss.append(f'if {start} <= value <= {stop}:')
                miss.append(f'    #: {desc}')
                miss.append(f"    return cls._unregistered_member(value, '{self.safe_name(name)}')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(HpkeKemId())  # type: ignore[arg-type]
