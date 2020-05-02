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
    Hardware['Reserved_0'] = 0

    #: [Jon Postel]
    Hardware['Ethernet'] = 1

    #: [Jon Postel]
    Hardware['Experimental_Ethernet'] = 2

    #: [Philip Koch]
    Hardware['Amateur_Radio_AX_25'] = 3

    #: [Avri Doria]
    Hardware['Proteon_ProNET_Token_Ring'] = 4

    #: [Gill Pratt]
    Hardware['Chaos'] = 5

    #: [Jon Postel]
    Hardware['IEEE_802_Networks'] = 6

    #: [:rfc:`1201`]
    Hardware['ARCNET'] = 7

    #: [Jon Postel]
    Hardware['Hyperchannel'] = 8

    #: [Tom Unger]
    Hardware['Lanstar'] = 9

    #: [Mike Burrows]
    Hardware['Autonet_Short_Address'] = 10

    #: [Joyce K Reynolds]
    Hardware['LocalTalk'] = 11

    #: [Joseph Murdock]
    Hardware['LocalNet'] = 12

    #: [Rajiv Dhingra]
    Hardware['Ultra_Link'] = 13

    #: [George Clapp]
    Hardware['SMDS'] = 14

    #: [Andy Malis]
    Hardware['Frame_Relay'] = 15

    #: [JXB2]
    Hardware['Asynchronous_Transmission_Mode_16'] = 16

    #: [Jon Postel]
    Hardware['HDLC'] = 17

    #: [:rfc:`4338`]
    Hardware['Fibre_Channel'] = 18

    #: [:rfc:`2225`]
    Hardware['Asynchronous_Transmission_Mode_19'] = 19

    #: [Jon Postel]
    Hardware['Serial_Line'] = 20

    #: [Mike Burrows]
    Hardware['Asynchronous_Transmission_Mode_21'] = 21

    #: [Herb Jensen]
    Hardware['MIL_STD_188_220'] = 22

    #: [Jonathan Stone]
    Hardware['Metricom'] = 23

    #: [Myron Hattig]
    Hardware['IEEE_1394_1995'] = 24

    #: [Mitsuru Maruyama][:rfc:`2176`]
    Hardware['MAPOS'] = 25

    #: [Marion Pitts]
    Hardware['Twinaxial'] = 26

    #: [Kenji Fujisawa]
    Hardware['EUI_64'] = 27

    #: [Jean Michel Pittet]
    Hardware['HIPARP'] = 28

    #: [Scott Guthery]
    Hardware['IP_And_ARP_Over_ISO_7816_3'] = 29

    #: [Jerome Etienne]
    Hardware['ARPSec'] = 30

    #: [:rfc:`3456`]
    Hardware['IPsec_Tunnel'] = 31

    #: [:rfc:`4391`]
    Hardware['InfiniBand'] = 32

    #: [Jeff Anderson, Telecommunications Industry of America (TIA) TR-8.5 Formulating Group, <cja015&motorola.com>, June 2004]
    Hardware['TIA_102_Project_25_Common_Air_Interface'] = 33

    #: [Scott Guthery 2]
    Hardware['Wiegand_Interface'] = 34

    #: [Inaky Perez-Gonzalez]
    Hardware['Pure_IP'] = 35

    #: [:rfc:`5494`]
    Hardware['HW_EXP1'] = 36

    #: [Tseng-Hui Lin]
    Hardware['HFI'] = 37

    #: [:rfc:`5494`]
    Hardware['HW_EXP2'] = 256

    #: [Geoffroy Gramaize]
    Hardware['AEthernet'] = 257

    #: [:rfc:`5494`]
    Hardware['Reserved_65535'] = 65535

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
