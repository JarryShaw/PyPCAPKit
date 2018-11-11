# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Hardware(IntEnum):
    """Enumeration class for Hardware."""
    _ignore_ = 'Hardware _'
    Hardware = vars()

    # Hardware Types [RFC 826][RFC 5494]
    Hardware['Reserved [0]'] = 0                                                # [RFC 5494]
    Hardware['Ethernet (10Mb)'] = 1                                             # [Jon_Postel]
    Hardware['Experimental Ethernet (3Mb)'] = 2                                 # [Jon_Postel]
    Hardware['Amateur Radio AX.25'] = 3                                         # [Philip_Koch]
    Hardware['Proteon ProNET Token Ring'] = 4                                   # [Avri_Doria]
    Hardware['Chaos'] = 5                                                       # [Gill_Pratt]
    Hardware['IEEE 802 Networks'] = 6                                           # [Jon_Postel]
    Hardware['ARCNET'] = 7                                                      # [RFC 1201]
    Hardware['Hyperchannel'] = 8                                                # [Jon_Postel]
    Hardware['Lanstar'] = 9                                                     # [Tom_Unger]
    Hardware['Autonet Short Address'] = 10                                      # [Mike_Burrows]
    Hardware['LocalTalk'] = 11                                                  # [Joyce_K_Reynolds]
    Hardware['LocalNet (IBM PCNet or SYTEK LocalNET)'] = 12                     # [Joseph Murdock]
    Hardware['Ultra link'] = 13                                                 # [Rajiv_Dhingra]
    Hardware['SMDS'] = 14                                                       # [George_Clapp]
    Hardware['Frame Relay'] = 15                                                # [Andy_Malis]
    Hardware['Asynchronous Transmission Mode (ATM) [16]'] = 16                  # [JXB2]
    Hardware['HDLC'] = 17                                                       # [Jon_Postel]
    Hardware['Fibre Channel'] = 18                                              # [RFC 4338]
    Hardware['Asynchronous Transmission Mode (ATM) [19]'] = 19                  # [RFC 2225]
    Hardware['Serial Line'] = 20                                                # [Jon_Postel]
    Hardware['Asynchronous Transmission Mode (ATM) [21]'] = 21                  # [Mike_Burrows]
    Hardware['MIL-STD-188-220'] = 22                                            # [Herb_Jensen]
    Hardware['Metricom'] = 23                                                   # [Jonathan_Stone]
    Hardware['IEEE 1394.1995'] = 24                                             # [Myron_Hattig]
    Hardware['MAPOS'] = 25                                                      # [Mitsuru_Maruyama][RFC 2176]
    Hardware['Twinaxial'] = 26                                                  # [Marion_Pitts]
    Hardware['EUI-64'] = 27                                                     # [Kenji_Fujisawa]
    Hardware['HIPARP'] = 28                                                     # [Jean_Michel_Pittet]
    Hardware['IP and ARP over ISO 7816-3'] = 29                                 # [Scott_Guthery]
    Hardware['ARPSec'] = 30                                                     # [Jerome_Etienne]
    Hardware['IPsec tunnel'] = 31                                               # [RFC 3456]
    Hardware['InfiniBand (TM)'] = 32                                            # [RFC 4391]
    Hardware['TIA-102 Project 25 Common Air Interface (CAI)'] = 33              # [Jeff Anderson, Telecommunications Industry of America (TIA) TR-8.5 Formulating Group, <cja015&motorola.com>, June 2004]
    Hardware['Wiegand Interface'] = 34                                          # [Scott_Guthery_2]
    Hardware['Pure IP'] = 35                                                    # [Inaky_Perez-Gonzalez]
    Hardware['HW_EXP1'] = 36                                                    # [RFC 5494]
    Hardware['HFI'] = 37                                                        # [Tseng-Hui_Lin]
    Hardware['HW_EXP2'] = 256                                                   # [RFC 5494]
    Hardware['AEthernet'] = 257                                                 # [Geoffroy_Gramaize]
    Hardware['Reserved [65535]'] = 65535                                        # [RFC 5494]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Hardware(key)
        if key not in Hardware._member_map_:
            extend_enum(Hardware, key, default)
        return Hardware[key]

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
