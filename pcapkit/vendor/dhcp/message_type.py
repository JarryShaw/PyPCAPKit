# -*- coding: utf-8 -*-
"""DHCP Message Type 53 Values
=================================

.. module:: pcapkit.vendor.dhcp.message_type

This module contains the vendor crawler for **DHCP Message Type 53 Values**,
which is automatically generating
:class:`pcapkit.const.dhcp.message_type.MessageType`.

The registry is IANA's ``DHCP Message Type 53 Values`` table, in the ``Value,
Message Type, Reference`` shape :meth:`~pcapkit.vendor.default.Vendor.process`
reads. It lists no unassigned range: a value of the one-octet option it does
not list resolves as ``Unassigned``.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['MessageType']


class MessageType(Vendor):
    """DHCP Message Type 53 Values"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/bootp-dhcp-parameters/message-type-53.csv'

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields and missing fields, the latter resolving every
            value the registry does not list.

        """
        enum, miss = super().process(data)
        miss.append("return cls._unregistered_member(value, 'Unassigned')")
        return enum, miss


if __name__ == '__main__':
    sys.exit(MessageType())  # type: ignore[arg-type]
