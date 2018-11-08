# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class DI_TYPE(IntEnum):
    """Enumeration class for DI_TYPE."""
    _ignore_ = 'DI_TYPE _'
    DI_TYPE = vars()

    # DI-Types
    DI_TYPE['none included'] = 0                                                # [RFC 7401]
    DI_TYPE['FQDN'] = 1                                                         # [RFC 7401]
    DI_TYPE['NAI'] = 2                                                          # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return DI_TYPE(key)
        if key not in DI_TYPE._member_map_:
            extend_enum(DI_TYPE, key, default)
        return DI_TYPE[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 15:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
