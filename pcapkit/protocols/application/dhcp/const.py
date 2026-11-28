# -*- coding: utf-8 -*-
"""constants for the BOOTP and DHCP family

.. versionadded:: 1.10.0

"""

from pcapkit.const.dhcp.option import Option as Enum_Option

__all__ = ['HEADER_LENGTH', 'MAGIC_COOKIE', 'SNAME_LENGTH', 'FILE_LENGTH', 'CHADDR_LENGTH', 'MINIMUMS']

#: Length of the fixed header, ``op`` through ``file`` (:rfc:`2131#section-2`).
HEADER_LENGTH = 236
#: Length of the ``chaddr`` field.
CHADDR_LENGTH = 16
#: Length of the ``sname`` field.
SNAME_LENGTH = 64
#: Length of the ``file`` field.
FILE_LENGTH = 128
#: The magic cookie, 99.130.83.99, opening an option area
#: (:rfc:`2132#section-2`).
MAGIC_COOKIE = b'\x63\x82\x53\x63'


#: The least value an integer option takes, where :rfc:`2132` gives one.
MINIMUMS = {
    Enum_Option.Max_DG_Assembly: 576,    # [RFC 2132, section 4.4]
    Enum_Option.Default_IP_TTL: 1,       # [RFC 2132, section 4.5]
    Enum_Option.MTU_Interface: 68,       # [RFC 2132, section 5.1]
    Enum_Option.Default_TCP_TTL: 1,      # [RFC 2132, section 7.1]
    Enum_Option.DHCP_Max_Msg_Size: 576,  # [RFC 2132, section 9.10]
}
