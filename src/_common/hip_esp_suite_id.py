# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class ESP_SuiteID(IntEnum):
    """Enumeration class for ESP_SuiteID."""
    _ignore_ = 'ESP_SuiteID _'
    ESP_SuiteID = vars()

    # ESP Transform Suite IDs
    ESP_SuiteID['RESERVED'] = 0                                                 # [RFC 7402]
    ESP_SuiteID['AES-128-CBC with HMAC-SHA1'] = 1                               # [RFC 3602][RFC 2404]
    ESP_SuiteID['DEPRECATED [2]'] = 2                                           # [RFC 7402]
    ESP_SuiteID['DEPRECATED [3]'] = 3                                           # [RFC 7402]
    ESP_SuiteID['DEPRECATED [4]'] = 4                                           # [RFC 7402]
    ESP_SuiteID['DEPRECATED [5]'] = 5                                           # [RFC 7402]
    ESP_SuiteID['DEPRECATED [6]'] = 6                                           # [RFC 7402]
    ESP_SuiteID['NULL with HMAC-SHA-256'] = 7                                   # [RFC 2410][RFC 4868]
    ESP_SuiteID['AES-128-CBC with HMAC-SHA-256'] = 8                            # [RFC 3602][RFC 4868]
    ESP_SuiteID['AES-256-CBC with HMAC-SHA-256'] = 9                            # [RFC 3602][RFC 4868]
    ESP_SuiteID['AES-CCM-8'] = 10                                               # [RFC 4309]
    ESP_SuiteID['AES-CCM-16'] = 11                                              # [RFC 4309]
    ESP_SuiteID['AES-GCM with an 8 octet ICV'] = 12                             # [RFC 4106]
    ESP_SuiteID['AES-GCM with a 16 octet ICV'] = 13                             # [RFC 4106]
    ESP_SuiteID['AES-CMAC-96'] = 14                                             # [RFC 4493][RFC 4494]
    ESP_SuiteID['AES-GMAC'] = 15                                                # [RFC 4543]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ESP_SuiteID(key)
        if key not in ESP_SuiteID._member_map_:
            extend_enum(ESP_SuiteID, key, default)
        return ESP_SuiteID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 16 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
