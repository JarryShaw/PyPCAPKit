# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class HrdType(IntEnum):
    """Enumeration class for HrdType."""
    _ignore_ = 'HrdType _'
    HrdType = vars()

    # Hardware Types [RFC 826][RFC 5494]
    HrdType['Reserved [0]'] = 0                                                 # [RFC 5494]
    HrdType['Ethernet (10Mb)'] = 1                                              # [Jon_Postel]
    HrdType['Experimental Ethernet (3Mb)'] = 2                                  # [Jon_Postel]
    HrdType['Amateur Radio AX.25'] = 3                                          # [Philip_Koch]
    HrdType['Proteon ProNET Token Ring'] = 4                                    # [Avri_Doria]
    HrdType['Chaos'] = 5                                                        # [Gill_Pratt]
    HrdType['IEEE 802 Networks'] = 6                                            # [Jon_Postel]
    HrdType['ARCNET'] = 7                                                       # [RFC 1201]
    HrdType['Hyperchannel'] = 8                                                 # [Jon_Postel]
    HrdType['Lanstar'] = 9                                                      # [Tom_Unger]
    HrdType['Autonet Short Address'] = 10                                       # [Mike_Burrows]
    HrdType['LocalTalk'] = 11                                                   # [Joyce_K_Reynolds]
    HrdType['LocalNet (IBM PCNet or SYTEK LocalNET)'] = 12                      # [Joseph Murdock]
    HrdType['Ultra link'] = 13                                                  # [Rajiv_Dhingra]
    HrdType['SMDS'] = 14                                                        # [George_Clapp]
    HrdType['Frame Relay'] = 15                                                 # [Andy_Malis]
    HrdType['Asynchronous Transmission Mode (ATM) [16]'] = 16                   # [JXB2]
    HrdType['HDLC'] = 17                                                        # [Jon_Postel]
    HrdType['Fibre Channel'] = 18                                               # [RFC 4338]
    HrdType['Asynchronous Transmission Mode (ATM) [19]'] = 19                   # [RFC 2225]
    HrdType['Serial Line'] = 20                                                 # [Jon_Postel]
    HrdType['Asynchronous Transmission Mode (ATM) [21]'] = 21                   # [Mike_Burrows]
    HrdType['MIL-STD-188-220'] = 22                                             # [Herb_Jensen]
    HrdType['Metricom'] = 23                                                    # [Jonathan_Stone]
    HrdType['IEEE 1394.1995'] = 24                                              # [Myron_Hattig]
    HrdType['MAPOS'] = 25                                                       # [Mitsuru_Maruyama][RFC 2176]
    HrdType['Twinaxial'] = 26                                                   # [Marion_Pitts]
    HrdType['EUI-64'] = 27                                                      # [Kenji_Fujisawa]
    HrdType['HIPARP'] = 28                                                      # [Jean_Michel_Pittet]
    HrdType['IP and ARP over ISO 7816-3'] = 29                                  # [Scott_Guthery]
    HrdType['ARPSec'] = 30                                                      # [Jerome_Etienne]
    HrdType['IPsec tunnel'] = 31                                                # [RFC 3456]
    HrdType['InfiniBand (TM)'] = 32                                             # [RFC 4391]
    HrdType['TIA-102 Project 25 Common Air Interface (CAI)'] = 33               # [Jeff Anderson, Telecommunications Industry of America (TIA) TR-8.5 Formulating Group, <cja015&motorola.com>, June 2004]
    HrdType['Wiegand Interface'] = 34                                           # [Scott_Guthery_2]
    HrdType['Pure IP'] = 35                                                     # [Inaky_Perez-Gonzalez]
    HrdType['HW_EXP1'] = 36                                                     # [RFC 5494]
    HrdType['HFI'] = 37                                                         # [Tseng-Hui_Lin]
    HrdType['HW_EXP2'] = 256                                                    # [RFC 5494]
    HrdType['AEthernet'] = 257                                                  # [Geoffroy_Gramaize]
    HrdType['Reserved [65535]'] = 65535                                         # [RFC 5494]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return HrdType(key)
        if key not in HrdType._member_map_:
            extend_enum(HrdType, key, default)
        return HrdType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 38 <= value <= 255:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 258 <= value <= 65534:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
