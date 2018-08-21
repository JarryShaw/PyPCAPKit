# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class GroupID(IntEnum):
    """Enumeration class for GroupID."""
    _ignore_ = 'GroupID _'
    GroupID = vars()

    # Group IDs
    GroupID['Reserved'] = 0                                                     # [RFC 7401]
    GroupID['384-bit group'] = 1                                                # [RFC 5201] DEPRECATED
    GroupID['OAKLEY well known group 1'] = 2                                    # [RFC 5201] DEPRECATED
    GroupID['1536-bit MODP group'] = 3                                          # [RFC 7401]
    GroupID['3072-bit MODP group'] = 4                                          # [RFC 7401]
    GroupID['6144-bit MODP group'] = 5                                          # [RFC 5201] DEPRECATED
    GroupID['8192-bit MODP group'] = 6                                          # [RFC 5201] DEPRECATED
    GroupID['NIST P-256'] = 7                                                   # [RFC 7401]
    GroupID['NIST P-384'] = 8                                                   # [RFC 7401]
    GroupID['NIST P-521'] = 9                                                   # [RFC 7401]
    GroupID['SECP160R1'] = 10                                                   # [RFC 7401]
    GroupID['2048-bit MODP group'] = 11                                         # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return GroupID(key)
        if key not in GroupID._member_map_:
            extend_enum(GroupID, key, default)
        return GroupID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 12 <= value <= 255:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
