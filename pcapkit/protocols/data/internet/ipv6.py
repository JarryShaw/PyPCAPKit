# -*- coding: utf-8 -*-
"""data model for Internet Protocol version 6"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from typing import Any
    from ipaddress import IPv6Address

    from typing_extensions import Literal

    from pcapkit.const.reg.transtype import TransType

__all__ = [
    'IPv6',

]


class IPv6(Info):
    """Data model for Internet Protocol version 6.

    .. attribute:: class
       :type: int

       Traffic class.

       .. note::

          This field is conflict with ``class`` keyword. To access this field,
          directly use :func:`getattr` instead.

    """

    #: Version.
    version: 'Literal[6]'
    #: Traffic class.
    #class: 'int'
    #: Flow label.
    label: 'int'
    #: Payload length.
    payload: 'int'
    #: Next header.
    next: 'TransType'
    #: Hop limit.
    limit: 'int'
    #: Source address.
    src: 'IPv6Address'
    #: Destination address.
    dst: 'IPv6Address'

    if TYPE_CHECKING:
        fragment: 'Info'

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'IPv6':
        self = super().__new__(*args, **kwargs)

        # NOTE: We cannot define ``class`` due to preserved keyword conflict.
        # Thus, we directly inject the information into the annotations.
        self.__annotations__['class'] = int  # pylint: disable=no-member

        return self  # type: ignore[return-value]
