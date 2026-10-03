# -*- coding: utf-8 -*-
"""NGAP Elementary Procedure Codes
=====================================

.. module:: pcapkit.vendor.ngap.procedure_code

This module contains the vendor crawler for **NGAP Elementary Procedure
Codes**, which is automatically generating
:class:`pcapkit.const.ngap.procedure_code.ProcedureCode`.

GitHub issue :issue:`880`'s owner ruling: unlike every other crawler in this package,
the source of truth here is not a network registry :mod:`requests` can fetch
-- 3GPP publishes TS 38.413 as a PDF, with no CSV or HTML IANA-style registry
kept in step with it. |pycrate|_ already carries the up-to-date assignment as
compiled ASN.1, at ``pycrate_asn1dir/NGAP.py``'s ``NGAP_Constants`` class (one
``INT`` value object per ``id-<Name>`` constant, tagged with the ``ProcedureCode``
or ``ProtocolIE-ID`` open type it belongs to) -- and it is the very same
dependency :mod:`pcapkit.protocols.application.ngap` already needs installed to
decode NGAP at all. So this crawler reads that already-installed package
directly instead of fetching anything over the network: :attr:`~ProcedureCode.LINK`
is :obj:`None` and :meth:`ProcedureCode._request` imports ``pycrate_asn1dir.NGAP``
in place of :meth:`~pcapkit.vendor.default.Vendor._request`'s HTTP round trip.
No network access happens at generation time -- only, if at all, whenever
``pip install pypcapkit[NGAP]`` last ran.

:class:`~pcapkit.const.ngap.procedure_code.ProcedureCode` is a genuinely open
registry -- 3GPP keeps assigning new elementary procedures to TS 38.413 -- so,
unlike the closed :mod:`pcapkit.protocols.internet.mh` enums GitHub issue :issue:`877`
ruled on, an in-range value this crawler has not (yet) seen is not a bug to
raise on: :meth:`~pcapkit.const.ngap.procedure_code.ProcedureCode._missing_`
answers it with a throwaway, non-registering member instead (see
:meth:`pcapkit.corekit.enum.EnumRegistry._unregistered_member`), which is what
stops two different unrecognised keys from aliasing onto the same member --
the defect GitHub issue :issue:`880` exists to fix.

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

__all__ = ['ProcedureCode']

#: The ``NGAP-CommonDataTypes`` open type this crawler claims. Matched against
#: each ``NGAP_Constants`` value object's own ``_typeref.called`` -- see
#: :meth:`ProcedureCode._request` for why the private attribute is read
#: directly rather than through a public accessor.
_TYPEREF = ('NGAP-CommonDataTypes', 'ProcedureCode')

#: Default constant template of enumerate registry, sourced from pycrate
#: rather than an IANA CSV -- see the module docstring.
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


class ProcedureCode(Vendor):
    """NGAP elementary procedure codes, 3GPP TS 38.413."""

    #: Value limit checker, matching ``pycrate_asn1dir.NGAP``'s own
    #: ``ProcedureCode._const_val`` (``ASN1RangeInt(lb=0, ub=255)``): a
    #: ``ProcedureCode`` is encoded as one aligned-PER octet.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'

    # No network registry to link to -- see the module docstring. Left
    # unset rather than assigned ``None`` explicitly: ``Vendor.LINK`` already
    # defaults to :obj:`None`, and a fresh assignment here would need the
    # same ``# type: ignore[assignment]`` the base class's own declaration
    # carries, for narrowing a ``str``-annotated attribute to ``None`` again.

    def _request(self) -> 'list[tuple[str, int]]':  # type: ignore[override]
        """Read the assignment from |pycrate|_'s compiled NGAP specification.

        Every ``NGAP_Constants`` value object carries a private ``_typeref``
        naming which ``NGAP-CommonDataTypes`` open type it belongs to (``.called``,
        a ``(module, type)`` pair), a private ``_name`` holding the ASN.1
        identifier verbatim (``'id-AMFConfigurationUpdate'``), and a private
        ``_val`` holding the assigned integer. None of the three has a public
        accessor that survives this far: :meth:`~pycrate_asn1rt.asnobj.ASN1Obj.
        get_typeref` resolves to the *referenced type object* rather than its
        ``(module, name)`` pair, and that object's own :meth:`get_name` reads
        :obj:`None` here despite :func:`repr` showing the name -- measured
        against pycrate 0.8.1. Reading the private attributes directly is
        therefore the only way to recover what this crawler needs, which is a
        property of parsing pycrate's own compiled representation rather than
        a shortcut around a public API this package should have used instead.

        Returns:
            One ``(python_identifier, value)`` pair per ``ProcedureCode``
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
                "pcapkit.vendor.ngap.procedure_code needs the optional 'pycrate' "
                "dependency installed to source NGAP's ProcedureCode assignments "
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

        Unlike a hand-scraped CSV, |pycrate|_'s compiled specification names
        each assignment once -- measured, zero duplicate names and zero
        duplicate values across all 81 -- so :meth:`~pcapkit.vendor.default.
        Vendor.rename`'s per-name counter has nothing to disambiguate and this
        crawler never calls it.

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
    sys.exit(ProcedureCode())  # type: ignore[arg-type]
