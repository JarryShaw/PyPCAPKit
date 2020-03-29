# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Hardware Types [:rfc:`826`][:rfc:`5494`]"""

from aenum import IntEnum, extend_enum

__all__ = ['Hardware']


class Hardware(IntEnum):
    """[Hardware] Hardware Types [:rfc:`826`][:rfc:`5494`]"""

    _ignore_ = 'Hardware _'
    Hardware = vars()

    #: [:rfc:`5494`]
    Hardware['Reserved [0]'] = 0

    #: [Jon Postel]
    Hardware['Ethernet (10Mb)'] = 1

    #: [Jon Postel]
    Hardware['Experimental Ethernet (3Mb)'] = 2

    #: [Philip Koch]
    Hardware['Amateur Radio AX.25'] = 3

    #: [Avri Doria]
    Hardware['Proteon ProNET Token Ring'] = 4

    #: [Gill Pratt]
    Hardware['Chaos'] = 5

    #: [Jon Postel]
    Hardware['IEEE 802 Networks'] = 6

    #: [:rfc:`1201`]
    Hardware['ARCNET'] = 7

    #: [Jon Postel]
    Hardware['Hyperchannel'] = 8

    #: [Tom Unger]
    Hardware['Lanstar'] = 9

    #: [Mike Burrows]
    Hardware['Autonet Short Address'] = 10

    #: [Joyce K Reynolds]
    Hardware['LocalTalk'] = 11

    #: [Joseph Murdock]
    Hardware['LocalNet (IBM PCNet or SYTEK LocalNET)'] = 12

    #: [Rajiv Dhingra]
    Hardware['Ultra link'] = 13

    #: [George Clapp]
    Hardware['SMDS'] = 14

    #: [Andy Malis]
    Hardware['Frame Relay'] = 15

    #: [JXB2]
    Hardware['Asynchronous Transmission Mode (ATM) [16]'] = 16

    #: [Jon Postel]
    Hardware['HDLC'] = 17

    #: [:rfc:`4338`]
    Hardware['Fibre Channel'] = 18

    #: [:rfc:`2225`]
    Hardware['Asynchronous Transmission Mode (ATM) [19]'] = 19

    #: [Jon Postel]
    Hardware['Serial Line'] = 20

    #: [Mike Burrows]
    Hardware['Asynchronous Transmission Mode (ATM) [21]'] = 21

    #: [Herb Jensen]
    Hardware['MIL-STD-188-220'] = 22

    #: [Jonathan Stone]
    Hardware['Metricom'] = 23

    #: [Myron Hattig]
    Hardware['IEEE 1394.1995'] = 24

    #: [Mitsuru Maruyama][:rfc:`2176`]
    Hardware['MAPOS'] = 25

    #: [Marion Pitts]
    Hardware['Twinaxial'] = 26

    #: [Kenji Fujisawa]
    Hardware['EUI-64'] = 27

    #: [Jean Michel Pittet]
    Hardware['HIPARP'] = 28

    #: [Scott Guthery]
    Hardware['IP and ARP over ISO 7816-3'] = 29

    #: [Jerome Etienne]
    Hardware['ARPSec'] = 30

    #: [:rfc:`3456`]
    Hardware['IPsec tunnel'] = 31

    #: [:rfc:`4391`]
    Hardware['InfiniBand (TM)'] = 32

    #: [Jeff Anderson, Telecommunications Industry of America (TIA) TR-8.5 Formulating Group, <cja015&motorola.com>, June 2004]
    Hardware['TIA-102 Project 25 Common Air Interface (CAI)'] = 33

    #: [Scott Guthery 2]
    Hardware['Wiegand Interface'] = 34

    #: [Inaky Perez-Gonzalez]
    Hardware['Pure IP'] = 35

    #: [:rfc:`5494`]
    Hardware['HW_EXP1'] = 36

    #: [Tseng-Hui Lin]
    Hardware['HFI'] = 37

    #: [:rfc:`5494`]
    Hardware['HW_EXP2'] = 256

    #: [Geoffroy Gramaize]
    Hardware['AEthernet'] = 257

    #: [:rfc:`5494`]
    Hardware['Reserved [65535]'] = 65535

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Hardware(key)
        if key not in Hardware._member_map_:  # pylint: disable=no-member
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
        return super()._missing_(value)
