# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Hardware Types [:rfc:`826`][:rfc:`5494`]"""

from aenum import IntEnum, extend_enum

__all__ = ['Hardware']


class Hardware(IntEnum):
    """[Hardware] Hardware Types [:rfc:`826`][:rfc:`5494`]"""

    #: Reserved [:rfc:`5494`]
    Reserved_0 = 0

    #: Ethernet (10Mb) [Jon Postel]
    Ethernet = 1

    #: Experimental Ethernet (3Mb) [Jon Postel]
    Experimental_Ethernet = 2

    #: Amateur Radio AX.25 [Philip Koch]
    Amateur_Radio_AX_25 = 3

    #: Proteon ProNET Token Ring [Avri Doria]
    Proteon_ProNET_Token_Ring = 4

    #: Chaos [Gill Pratt]
    Chaos = 5

    #: IEEE 802 Networks [Jon Postel]
    IEEE_802_Networks = 6

    #: ARCNET [:rfc:`1201`]
    ARCNET = 7

    #: Hyperchannel [Jon Postel]
    Hyperchannel = 8

    #: Lanstar [Tom Unger]
    Lanstar = 9

    #: Autonet Short Address [Mike Burrows]
    Autonet_Short_Address = 10

    #: LocalTalk [Joyce K Reynolds]
    LocalTalk = 11

    #: LocalNet (IBM PCNet or SYTEK LocalNET) [Joseph Murdock]
    LocalNet = 12

    #: Ultra link [Rajiv Dhingra]
    Ultra_link = 13

    #: SMDS [George Clapp]
    SMDS = 14

    #: Frame Relay [Andy Malis]
    Frame_Relay = 15

    #: Asynchronous Transmission Mode (ATM) [JXB2]
    Asynchronous_Transmission_Mode_16 = 16

    #: HDLC [Jon Postel]
    HDLC = 17

    #: Fibre Channel [:rfc:`4338`]
    Fibre_Channel = 18

    #: Asynchronous Transmission Mode (ATM) [:rfc:`2225`]
    Asynchronous_Transmission_Mode_19 = 19

    #: Serial Line [Jon Postel]
    Serial_Line = 20

    #: Asynchronous Transmission Mode (ATM) [Mike Burrows]
    Asynchronous_Transmission_Mode_21 = 21

    #: MIL-STD-188-220 [Herb Jensen]
    MIL_STD_188_220 = 22

    #: Metricom [Jonathan Stone]
    Metricom = 23

    #: IEEE 1394.1995 [Myron Hattig]
    IEEE_1394_1995 = 24

    #: MAPOS [Mitsuru Maruyama][:rfc:`2176`]
    MAPOS = 25

    #: Twinaxial [Marion Pitts]
    Twinaxial = 26

    #: EUI-64 [Kenji Fujisawa]
    EUI_64 = 27

    #: HIPARP [Jean Michel Pittet]
    HIPARP = 28

    #: IP and ARP over ISO 7816-3 [Scott Guthery]
    IP_and_ARP_over_ISO_7816_3 = 29

    #: ARPSec [Jerome Etienne]
    ARPSec = 30

    #: IPsec tunnel [:rfc:`3456`]
    IPsec_tunnel = 31

    #: InfiniBand (TM) [:rfc:`4391`]
    InfiniBand = 32

    #: TIA-102 Project 25 Common Air Interface (CAI) [Jeff Anderson,
    #: Telecommunications Industry of America (TIA) TR-8.5 Formulating Group,
    #: <cja015&motorola.com>, June 2004]
    TIA_102_Project_25_Common_Air_Interface = 33

    #: Wiegand Interface [Scott Guthery 2]
    Wiegand_Interface = 34

    #: Pure IP [Inaky Perez-Gonzalez]
    Pure_IP = 35

    #: HW_EXP1 [:rfc:`5494`]
    HW_EXP1 = 36

    #: HFI [Tseng-Hui Lin]
    HFI = 37

    #: HW_EXP2 [:rfc:`5494`]
    HW_EXP2 = 256

    #: AEthernet [Geoffroy Gramaize]
    AEthernet = 257

    #: Reserved [:rfc:`5494`]
    Reserved_65535 = 65535

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
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 258 <= value <= 65534:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
