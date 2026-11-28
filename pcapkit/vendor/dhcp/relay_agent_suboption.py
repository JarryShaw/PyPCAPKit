# -*- coding: utf-8 -*-
"""DHCP Relay Agent Sub-Option Codes
=======================================

.. module:: pcapkit.vendor.dhcp.relay_agent_suboption

This module contains the vendor crawler for **DHCP Relay Agent Sub-Option
Codes**, which is automatically generating
:class:`pcapkit.const.dhcp.relay_agent_suboption.RelayAgentSubOption`.

The registry is IANA's ``DHCP Relay Agent Sub-Option Codes`` table, in the
``Code, Sub-Option Description, Reference`` shape
:meth:`~pcapkit.vendor.default.Vendor.process` reads. Sub-option 3 carries a
sentence rather than a name, saying it is reserved, so it takes the name
``Reserved_3``, as a reserved code of another registry would; the sentence is its
comment, on one line. A code of the one-octet field the registry does not list,
``0`` among them, resolves as ``Unassigned``.

"""

import re
import sys

from pcapkit.vendor.default import Vendor

__all__ = ['RelayAgentSubOption']

#: A description saying the sub-option is reserved rather than naming it.
RESERVED = re.compile(r'\ASub-option (\d+) is reserved\b')


class RelayAgentSubOption(Vendor):
    """DHCP Relay Agent Sub-Option Codes"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 255'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/bootp-dhcp-parameters/relay-agent-sub-options.csv'

    def safe_name(self, name: 'str') -> 'str':
        """Convert a ``Sub-Option Description`` cell to a member identifier.

        Args:
            name: Verbatim description cell.

        Returns:
            ``Reserved_<code>`` for a description saying the sub-option is
            reserved, or what :meth:`~pcapkit.vendor.default.Vendor.safe_name`
            gives.

        """
        match = RESERVED.match(name)
        if match is not None:
            return f'Reserved_{match.group(1)}'
        return super().safe_name(name)

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

    @staticmethod
    def wrap_comment(text: 'str') -> 'str':
        """Wrap ``text`` as :meth:`~pcapkit.vendor.default.Vendor.wrap_comment`
        does, once its runs of whitespace are single spaces.

        Args:
            text: Source text.

        Returns:
            Wrapped comments.

        """
        return Vendor.wrap_comment(re.sub(r'\s+', ' ', text))


if __name__ == '__main__':
    sys.exit(RelayAgentSubOption())  # type: ignore[arg-type]
