# -*- coding: utf-8 -*-
"""NGAP Protocol IE Identifiers
==================================

.. module:: pcapkit.vendor.ngap.protocol_ie

This module contains the vendor crawler for **NGAP Protocol IE Identifiers**,
which is automatically generating
:class:`pcapkit.const.ngap.protocol_ie.ProtocolIE`.

See :mod:`pcapkit.vendor.ngap.procedure_code`'s module docstring for why this
crawler's source is |pycrate|_'s already-installed, compiled NGAP
specification rather than a network registry, and why an in-range value it has
not seen answers through :meth:`~pcapkit.corekit.enum.EnumRegistry.
_unregistered_member` rather than raising or minting a permanent, shared-value
member -- the same GitHub issue :issue:`880` ruling, applied to the sibling registry.

.. |pycrate| replace:: ``pycrate``
.. _pycrate: https://github.com/pycrate-org/pycrate

"""
import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter
    from typing import Callable

__all__ = ['ProtocolIE']

#: The ``NGAP-CommonDataTypes`` open type this crawler claims. Matched against
#: each ``NGAP_Constants`` value object's own ``_typeref.called`` -- see
#: :meth:`pcapkit.vendor.ngap.procedure_code.ProcedureCode._request` for why
#: the private attribute is read directly rather than through a public
#: accessor.
_TYPEREF = ('NGAP-CommonDataTypes', 'ProtocolIE-ID')

#: Default constant template of enumerate registry, sourced from pycrate
#: rather than an IANA CSV -- see :mod:`pcapkit.vendor.ngap.procedure_code`.
LINE = lambda NAME, DOCS, FLAG, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
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

    @classmethod
    def _missing_(cls, value: 'int') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
'''.strip()  # type: Callable[[str, str, str, str, str], str]


class ProtocolIE(Vendor):
    """NGAP protocol IE identifiers, 3GPP TS 38.413."""

    #: Value limit checker, matching ``pycrate_asn1dir.NGAP``'s own
    #: ``ProtocolIE_ID._const_val`` (``ASN1RangeInt(lb=0, ub=65535)``): a
    #: ``ProtocolIE-ID`` is encoded as one aligned-PER 16-bit field.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'

    # No network registry to link to -- see
    # :mod:`pcapkit.vendor.ngap.procedure_code`'s module docstring. Left
    # unset rather than assigned ``None`` explicitly -- see that module's
    # own ``ProcedureCode`` for why.

    def _request(self) -> 'list[tuple[str, int]]':  # type: ignore[override]
        """Read the assignment from |pycrate|_'s compiled NGAP specification.

        See :meth:`pcapkit.vendor.ngap.procedure_code.ProcedureCode._request`
        for why the three private attributes read here (``_typeref``,
        ``_name``, ``_val``) have no surviving public equivalent.

        Returns:
            One ``(python_identifier, value)`` pair per ``ProtocolIE-ID``
            assignment, in the compiled specification's own declaration
            order -- already ascending by value, measured against pycrate
            0.8.1.

        Raises:
            ImportError: If the optional ``pycrate`` dependency is not
                installed.

        """
        try:
            from pycrate_asn1dir.NGAP import NGAP_Constants
        except ImportError as error:
            raise ImportError(
                "pcapkit.vendor.ngap.protocol_ie needs the optional 'pycrate' "
                "dependency installed to source NGAP's ProtocolIE-ID assignments "
                "from pycrate_asn1dir.NGAP (pip install pypcapkit[NGAP]); see "
                'GitHub issue #880') from error

        entries = []  # type: list[tuple[str, int]]
        for obj in NGAP_Constants._all_:  # pylint: disable=protected-access
            typeref = obj._typeref  # pylint: disable=protected-access
            if typeref is None or typeref.called != _TYPEREF:
                continue

            raw_name = obj._name  # pylint: disable=protected-access
            if not raw_name.startswith('id-'):
                continue
            name = raw_name[3:].replace('-', '_')

            entries.append((name, obj._val))  # pylint: disable=protected-access
        return entries

    def count(self, data: 'list[tuple[str, int]]') -> 'Counter[str]':  # type: ignore[override]
        """No duplicate-name bookkeeping needed.

        See :meth:`pcapkit.vendor.ngap.procedure_code.ProcedureCode.count` --
        measured, zero duplicate names and zero duplicate values across all
        438.

        """
        return collections.Counter()

    def process(self, data: 'list[tuple[str, int]]') -> 'list[str]':  # type: ignore[override]
        """Render each assignment as a member declaration.

        Args:
            data: The ``(name, value)`` pairs :meth:`_request` read from
                |pycrate|_.

        Returns:
            One ``NAME = VALUE`` source line per assignment.

        """
        return [f'{name} = {value}' for name, value in data]

    def context(self, data: 'list[tuple[str, int]]') -> 'str':  # type: ignore[override]
        """Generate constant context.

        Args:
            data: The ``(name, value)`` pairs :meth:`_request` read from
                |pycrate|_.

        Returns:
            Constant context.

        """
        ENUM = '\n\n    '.join(self.process(data)).strip()
        return LINE(self.NAME, self.DOCS, self.FLAG, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(ProtocolIE())  # type: ignore[arg-type]
