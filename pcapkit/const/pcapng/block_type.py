# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Block Types
=================

.. module:: pcapkit.const.pcapng.block_type

This module contains the constant enumeration for **Block Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.block_type.BlockType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['BlockType']


class BlockType(IntEnum):
    """[BlockType] Block Types"""

    #: Reserved ???
    Reserved_0x00000000 = 0x00000000

    #: Interface Description Block ( Section 4.2 )
    Interface_Description_Block = 0x00000001

    #: Packet Block ( Appendix A )
    Packet_Block = 0x00000002

    #: Simple Packet Block ( Section 4.4 )
    Simple_Packet_Block = 0x00000003

    #: Name Resolution Block ( Section 4.5 )
    Name_Resolution_Block = 0x00000004

    #: Interface Statistics Block ( Section 4.6 )
    Interface_Statistics_Block = 0x00000005

    #: Enhanced Packet Block ( Section 4.3 )
    Enhanced_Packet_Block = 0x00000006

    #: IRIG Timestamp Block (requested by Gianluca Varenni
    #: <gianluca.varenni@cacetech.com>, CACE Technologies LLC); code also used for
    #: Socket Aggregation Event Block
    IRIG_Timestamp_Block = 0x00000007

    #: ARINC 429 in AFDX Encapsulation Information Block (requested by Gianluca
    #: Varenni <gianluca.varenni@cacetech.com>, CACE Technologies LLC)
    ARINC_429_in_AFDX_Encapsulation_Information_Block = 0x00000008

    #: systemd Journal Export Block ( Section 4.7 )
    systemd_Journal_Export_Block = 0x00000009

    #: Decryption Secrets Block ( Section 4.8 )
    Decryption_Secrets_Block = 0x0000000a

    #: Hone Project Machine Info Block (see also Google version )
    Hone_Project_Machine_Info_Block = 0x00000101

    #: Hone Project Connection Event Block (see also Google version )
    Hone_Project_Connection_Event_Block = 0x00000102

    #: Sysdig Machine Info Block
    Sysdig_Machine_Info_Block = 0x00000201

    #: Sysdig Process Info Block, version 1
    Sysdig_Process_Info_Block_version_1 = 0x00000202

    #: Sysdig FD List Block
    Sysdig_FD_List_Block = 0x00000203

    #: Sysdig Event Block
    Sysdig_Event_Block = 0x00000204

    #: Sysdig Interface List Block
    Sysdig_Interface_List_Block = 0x00000205

    #: Sysdig User List Block
    Sysdig_User_List_Block = 0x00000206

    #: Sysdig Process Info Block, version 2
    Sysdig_Process_Info_Block_version_2 = 0x00000207

    #: Sysdig Event Block with flags
    Sysdig_Event_Block_with_flags = 0x00000208

    #: Sysdig Process Info Block, version 3
    Sysdig_Process_Info_Block_version_3 = 0x00000209

    #: Sysdig Process Info Block, version 4
    Sysdig_Process_Info_Block_version_4 = 0x00000210

    #: Sysdig Process Info Block, version 5
    Sysdig_Process_Info_Block_version_5 = 0x00000211

    #: Sysdig Process Info Block, version 6
    Sysdig_Process_Info_Block_version_6 = 0x00000212

    #: Sysdig Process Info Block, version 7
    Sysdig_Process_Info_Block_version_7 = 0x00000213

    #: Custom Block that rewriters can copy into new files ( Section 4.9 )
    Custom_Block_that_rewriters_can_copy_into_new_files = 0x00000bad

    #: Custom Block that rewriters should not copy into new files ( Section 4.9 )
    Custom_Block_that_rewriters_should_not_copy_into_new_files = 0x40000bad

    #: Section Header Block ( Section 4.1 )
    Section_Header_Block = 0x0a0d0d0a

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'BlockType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return BlockType(key)
        if key not in BlockType._member_map_:  # pylint: disable=no-member
            return extend_enum(BlockType, key, default)
        return BlockType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'BlockType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0a0d0a00 <= value <= 0x0a0d0aff:
            #: Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
            return extend_enum(cls, 'Reserved_%08x' % value, value)
        if 0x000a0d0a <= value <= 0xff0a0d0a:
            #: Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
            return extend_enum(cls, 'Reserved_%08x' % value, value)
        if 0x000a0d0d <= value <= 0xff0a0d0d:
            #: Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
            return extend_enum(cls, 'Reserved_%08x' % value, value)
        if 0x0d0d0a00 <= value <= 0x0d0d0aff:
            #: Reserved. Used to detect trace files corrupted because of file transfers using the FTP protocol in text mode.
            return extend_enum(cls, 'Reserved_%08x' % value, value)
        if 0x80000000 <= value <= 0xffffffff:
            #: Reserved for local use.
            return extend_enum(cls, 'Reserved_%08x' % value, value)
        return super()._missing_(value)
