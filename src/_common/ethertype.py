# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class EtherType(IntEnum):
    """Enumeration class for EtherType."""
    _ignore_ = 'EtherType _'
    EtherType = vars()

    # Ethertype IEEE 802 Numbers
    EtherType['XEROX PUP (see 0A00)'] = 0x0200                                  # [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, "PUP: An Internetwork Architecture", XEROX Palo Alto Research Center, CSL-79-10, July 1979; also in IEEE Transactions on Communication, Volume COM-28, Number 4, April 1980.][Neil_Sembower]
    EtherType['PUP Addr Trans (see 0A01)'] = 0x0201                             # [Neil_Sembower]
    EtherType['Nixdorf'] = 0x0400                                               # [Neil_Sembower]
    EtherType['XEROX NS IDP'] = 0x0600                                          # ["The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", AA-K759B-TK, Digital Equipment Corporation, Maynard, MA. Also as: "The Ethernet - A Local Area Network", Version 1.0, Digital Equipment Corporation, Intel Corporation, Xerox Corporation, September 1980. And: "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specifications", Digital, Intel and Xerox, November 1982. And: XEROX, "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", X3T51/80-50, Xerox Corporation, Stamford, CT., October 1980.][Neil_Sembower]
    EtherType['DLOG [0x0660]'] = 0x0660                                         # [Neil_Sembower]
    EtherType['DLOG [0x0661]'] = 0x0661                                         # [Neil_Sembower]
    EtherType['Internet Protocol version 4 (IPv4)'] = 0x0800                    # [RFC 7042]
    EtherType['X.75 Internet'] = 0x0801                                         # [Neil_Sembower]
    EtherType['NBS Internet'] = 0x0802                                          # [Neil_Sembower]
    EtherType['ECMA Internet'] = 0x0803                                         # [Neil_Sembower]
    EtherType['Chaosnet'] = 0x0804                                              # [Neil_Sembower]
    EtherType['X.25 Level 3'] = 0x0805                                          # [Neil_Sembower]
    EtherType['Address Resolution Protocol (ARP)'] = 0x0806                     # [RFC 7042]
    EtherType['XNS Compatability'] = 0x0807                                     # [Neil_Sembower]
    EtherType['Frame Relay ARP'] = 0x0808                                       # [RFC 1701]
    EtherType['Symbolics Private'] = 0x081C                                     # [David_Plummer]
    EtherType['Ungermann-Bass net debugr'] = 0x0900                             # [Neil_Sembower]
    EtherType['Xerox IEEE802.3 PUP'] = 0x0A00                                   # [Neil_Sembower]
    EtherType['PUP Addr Trans'] = 0x0A01                                        # [Neil_Sembower]
    EtherType['Banyan VINES'] = 0x0BAD                                          # [Neil_Sembower]
    EtherType['VINES Loopback'] = 0x0BAE                                        # [RFC 1701]
    EtherType['VINES Echo'] = 0x0BAF                                            # [RFC 1701]
    EtherType['Berkeley Trailer nego'] = 0x1000                                 # [Neil_Sembower]
    EtherType['Valid Systems'] = 0x1600                                         # [Neil_Sembower]
    EtherType['TRILL'] = 0x22F3                                                 # [RFC 6325]
    EtherType['L2-IS-IS'] = 0x22F4                                              # [RFC 6325]
    EtherType['PCS Basic Block Protocol'] = 0x4242                              # [Neil_Sembower]
    EtherType['BBN Simnet'] = 0x5208                                            # [Neil_Sembower]
    EtherType['DEC Unassigned (Exp.)'] = 0x6000                                 # [Neil_Sembower]
    EtherType['DEC MOP Dump/Load'] = 0x6001                                     # [Neil_Sembower]
    EtherType['DEC MOP Remote Console'] = 0x6002                                # [Neil_Sembower]
    EtherType['DEC DECNET Phase IV Route'] = 0x6003                             # [Neil_Sembower]
    EtherType['DEC LAT'] = 0x6004                                               # [Neil_Sembower]
    EtherType['DEC Diagnostic Protocol'] = 0x6005                               # [Neil_Sembower]
    EtherType['DEC Customer Protocol'] = 0x6006                                 # [Neil_Sembower]
    EtherType['DEC LAVC, SCA'] = 0x6007                                         # [Neil_Sembower]
    EtherType['Trans Ether Bridging'] = 0x6558                                  # [RFC 1701]
    EtherType['Raw Frame Relay'] = 0x6559                                       # [RFC 1701]
    EtherType['Ungermann-Bass download'] = 0x7000                               # [Neil_Sembower]
    EtherType['Ungermann-Bass dia/loop'] = 0x7002                               # [Neil_Sembower]
    EtherType['Proteon'] = 0x7030                                               # [Neil_Sembower]
    EtherType['Cabletron'] = 0x7034                                             # [Neil_Sembower]
    EtherType['Cronus VLN'] = 0x8003                                            # [RFC 824][Daniel_Tappan]
    EtherType['Cronus Direct'] = 0x8004                                         # [RFC 824][Daniel_Tappan]
    EtherType['HP Probe'] = 0x8005                                              # [Neil_Sembower]
    EtherType['Nestar'] = 0x8006                                                # [Neil_Sembower]
    EtherType['AT&T [0x8008]'] = 0x8008                                         # [Neil_Sembower]
    EtherType['Excelan'] = 0x8010                                               # [Neil_Sembower]
    EtherType['SGI diagnostics'] = 0x8013                                       # [Andrew_Cherenson]
    EtherType['SGI network games'] = 0x8014                                     # [Andrew_Cherenson]
    EtherType['SGI reserved'] = 0x8015                                          # [Andrew_Cherenson]
    EtherType['SGI bounce server'] = 0x8016                                     # [Andrew_Cherenson]
    EtherType['Apollo Domain'] = 0x8019                                         # [Neil_Sembower]
    EtherType['Tymshare'] = 0x802E                                              # [Neil_Sembower]
    EtherType['Tigan, Inc.'] = 0x802F                                           # [Neil_Sembower]
    EtherType['Reverse Address Resolution Protocol (RARP)'] = 0x8035            # [RFC 903][Joseph_Murdock]
    EtherType['Aeonic Systems'] = 0x8036                                        # [Neil_Sembower]
    EtherType['DEC LANBridge'] = 0x8038                                         # [Neil_Sembower]
    EtherType['DEC Ethernet Encryption'] = 0x803D                               # [Neil_Sembower]
    EtherType['DEC Unassigned'] = 0x803E                                        # [Neil_Sembower]
    EtherType['DEC LAN Traffic Monitor'] = 0x803F                               # [Neil_Sembower]
    EtherType['Planning Research Corp.'] = 0x8044                               # [Neil_Sembower]
    EtherType['AT&T [0x8046]'] = 0x8046                                         # [Neil_Sembower]
    EtherType['AT&T [0x8047]'] = 0x8047                                         # [Neil_Sembower]
    EtherType['ExperData'] = 0x8049                                             # [Neil_Sembower]
    EtherType['Stanford V Kernel exp.'] = 0x805B                                # [Neil_Sembower]
    EtherType['Stanford V Kernel prod.'] = 0x805C                               # [Neil_Sembower]
    EtherType['Evans & Sutherland'] = 0x805D                                    # [Neil_Sembower]
    EtherType['Little Machines'] = 0x8060                                       # [Neil_Sembower]
    EtherType['Counterpoint Computers'] = 0x8062                                # [Neil_Sembower]
    EtherType['Univ. of Mass. @ Amherst [0x8065]'] = 0x8065                     # [Neil_Sembower]
    EtherType['Univ. of Mass. @ Amherst [0x8066]'] = 0x8066                     # [Neil_Sembower]
    EtherType['Veeco Integrated Auto.'] = 0x8067                                # [Neil_Sembower]
    EtherType['General Dynamics'] = 0x8068                                      # [Neil_Sembower]
    EtherType['AT&T [0x8069]'] = 0x8069                                         # [Neil_Sembower]
    EtherType['Autophon'] = 0x806A                                              # [Neil_Sembower]
    EtherType['ComDesign'] = 0x806C                                             # [Neil_Sembower]
    EtherType['Computgraphic Corp.'] = 0x806D                                   # [Neil_Sembower]
    EtherType['Matra'] = 0x807A                                                 # [Neil_Sembower]
    EtherType['Dansk Data Elektronik'] = 0x807B                                 # [Neil_Sembower]
    EtherType['Merit Internodal'] = 0x807C                                      # [Hans_Werner_Braun]
    EtherType['Vitalink TransLAN III'] = 0x8080                                 # [Neil_Sembower]
    EtherType['Appletalk'] = 0x809B                                             # [Neil_Sembower]
    EtherType['Spider Systems Ltd.'] = 0x809F                                   # [Neil_Sembower]
    EtherType['Nixdorf Computers'] = 0x80A3                                     # [Neil_Sembower]
    EtherType['Banyan Systems [0x80C4]'] = 0x80C4                               # [Neil_Sembower]
    EtherType['Banyan Systems [0x80C5]'] = 0x80C5                               # [Neil_Sembower]
    EtherType['Pacer Software'] = 0x80C6                                        # [Neil_Sembower]
    EtherType['Applitek Corporation'] = 0x80C7                                  # [Neil_Sembower]
    EtherType['IBM SNA Service on Ether'] = 0x80D5                              # [Neil_Sembower]
    EtherType['Varian Associates'] = 0x80DD                                     # [Neil_Sembower]
    EtherType['Retix'] = 0x80F2                                                 # [Neil_Sembower]
    EtherType['AppleTalk AARP (Kinetics)'] = 0x80F3                             # [Neil_Sembower]
    EtherType['Apollo Computer'] = 0x80F7                                       # [Neil_Sembower]
    EtherType['Wellfleet Communications'] = 0x80FF                              # [Neil_Sembower]
    EtherType['Customer VLAN Tag Type (C-Tag, formerly called the Q-Tag) (initially Wellfleet)'] = 0x8100
                                                                                # [RFC 7042]
    EtherType['Hayes Microcomputers'] = 0x8130                                  # [Neil_Sembower]
    EtherType['VG Laboratory Systems'] = 0x8131                                 # [Neil_Sembower]
    EtherType['Logicraft'] = 0x8148                                             # [Neil_Sembower]
    EtherType['Network Computing Devices'] = 0x8149                             # [Neil_Sembower]
    EtherType['Alpha Micro'] = 0x814A                                           # [Neil_Sembower]
    EtherType['SNMP'] = 0x814C                                                  # [Joyce_K_Reynolds]
    EtherType['BIIN [0x814D]'] = 0x814D                                         # [Neil_Sembower]
    EtherType['BIIN [0x814E]'] = 0x814E                                         # [Neil_Sembower]
    EtherType['Technically Elite Concept'] = 0x814F                             # [Neil_Sembower]
    EtherType['Rational Corp'] = 0x8150                                         # [Neil_Sembower]
    EtherType['XTP'] = 0x817D                                                   # [Neil_Sembower]
    EtherType['SGI/Time Warner prop.'] = 0x817E                                 # [Neil_Sembower]
    EtherType['HIPPI-FP encapsulation'] = 0x8180                                # [Neil_Sembower]
    EtherType['STP, HIPPI-ST'] = 0x8181                                         # [Neil_Sembower]
    EtherType['Reserved for HIPPI-6400 [0x8182]'] = 0x8182                      # [Neil_Sembower]
    EtherType['Reserved for HIPPI-6400 [0x8183]'] = 0x8183                      # [Neil_Sembower]
    EtherType['Motorola Computer'] = 0x818D                                     # [Neil_Sembower]
    EtherType['ARAI Bunkichi'] = 0x81A4                                         # [Neil_Sembower]
    EtherType['SECTRA'] = 0x86DB                                                # [Neil_Sembower]
    EtherType['Delta Controls'] = 0x86DE                                        # [Neil_Sembower]
    EtherType['Internet Protocol version 6 (IPv6)'] = 0x86DD                    # [RFC 7042]
    EtherType['ATOMIC'] = 0x86DF                                                # [Joe_Touch]
    EtherType['TCP/IP Compression'] = 0x876B                                    # [RFC 1144][RFC 1701]
    EtherType['IP Autonomous Systems'] = 0x876C                                 # [RFC 1701]
    EtherType['Secure Data'] = 0x876D                                           # [RFC 1701]
    EtherType['IEEE Std 802.3 - Ethernet Passive Optical Network (EPON)'] = 0x8808# [EPON][RFC 7042]
    EtherType['Point-to-Point Protocol (PPP)'] = 0x880B                         # [RFC 7042]
    EtherType['General Switch Management Protocol (GSMP)'] = 0x880C             # [RFC 7042]
    EtherType['MPLS'] = 0x8847                                                  # [RFC 5332]
    EtherType['MPLS with upstream-assigned label'] = 0x8848                     # [RFC 5332]
    EtherType['Multicast Channel Allocation Protocol (MCAP)'] = 0x8861          # [RFC 7042]
    EtherType['PPP over Ethernet (PPPoE) Discovery Stage'] = 0x8863             # [RFC 2516]
    EtherType['PPP over Ethernet (PPPoE) Session Stage'] = 0x8864               # [RFC 2516]
    EtherType['IEEE Std 802.1X - Port-based network access control'] = 0x888E   # [IEEE]
    EtherType['IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)'] = 0x88A8 # [IEEE]
    EtherType['IEEE Std 802 - Local Experimental Ethertype [0x88B5]'] = 0x88B5  # [IEEE]
    EtherType['IEEE Std 802 - Local Experimental Ethertype [0x88B6]'] = 0x88B6  # [IEEE]
    EtherType['IEEE Std 802 - OUI Extended Ethertype'] = 0x88B7                 # [IEEE]
    EtherType['IEEE Std 802.11 - Pre-Authentication (802.11i)'] = 0x88C7        # [IEEE]
    EtherType['IEEE Std 802.1AB - Link Layer Discovery Protocol (LLDP)'] = 0x88CC# [IEEE]
    EtherType['IEEE Std 802.1AE - Media Access Control Security'] = 0x88E5      # [IEEE]
    EtherType['Provider Backbone Bridging Instance tag'] = 0x88E7               # [IEEE Std 802.1Q-2014]
    EtherType['IEEE Std 802.1Q - Multiple VLAN Registration Protocol (MVRP)'] = 0x88F5
                                                                                # [IEEE]
    EtherType['IEEE Std 802.1Q - Multiple Multicast Registration Protocol (MMRP)'] = 0x88F6
                                                                                # [IEEE]
    EtherType['IEEE Std 802.11 - Fast Roaming Remote Request (802.11r)'] = 0x890D# [IEEE]
    EtherType['IEEE Std 802.21 - Media Independent Handover Protocol'] = 0x8917 # [IEEE]
    EtherType['IEEE Std 802.1Qbe - Multiple I-SID Registration Protocol'] = 0x8929# [IEEE]
    EtherType['TRILL Fine Grained Labeling (FGL)'] = 0x893B                     # [RFC 7172]
    EtherType['IEEE Std 802.1Qbg - ECP Protocol (also used in 802.1BR)'] = 0x8940# [IEEE]
    EtherType['TRILL RBridge Channel'] = 0x8946                                 # [RFC 7178]
    EtherType['GeoNetworking as defined in ETSI EN 302 636-4-1'] = 0x8947       # [IEEE]
    EtherType['NSH (Network Service Header)'] = 0x894F                          # [RFC 8300]
    EtherType['Loopback'] = 0x9000                                              # [Neil_Sembower]
    EtherType['3Com(Bridge) XNS Sys Mgmt'] = 0x9001                             # [Neil_Sembower]
    EtherType['3Com(Bridge) TCP-IP Sys'] = 0x9002                               # [Neil_Sembower]
    EtherType['3Com(Bridge) loop detect'] = 0x9003                              # [Neil_Sembower]
    EtherType['Multi-Topology'] = 0x9A22                                        # [RFC -ietf-trill-multi-topology-06]
    EtherType['LoWPAN encapsulation'] = 0xA0ED                                  # [RFC 7973]
    EtherType['The Ethertype will be used to identify a "Channel" in which control messages are encapsulated as payload of GRE packets. When a GRE packet tagged with the Ethertype is received, the payload will be handed to the network processor for processing.'] = 0xB7EA
                                                                                # [RFC 8157]
    EtherType['BBN VITAL-LanBridge cache'] = 0xFF00                             # [Neil_Sembower]
    EtherType['Reserved'] = 0xFFFF                                              # [RFC 1701]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return EtherType(key)
        if key not in EtherType._member_map_:
            extend_enum(EtherType, key, default)
        return EtherType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000 <= value <= 0x05DC:
            # [Neil_Sembower]
            extend_enum(cls, 'IEEE802.3 Length Field [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0101 <= value <= 0x01FF:
            # [Neil_Sembower]
            extend_enum(cls, 'Experimental [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0888 <= value <= 0x088A:
            # [Neil_Sembower]
            extend_enum(cls, 'Xyplex [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x1001 <= value <= 0x100F:
            # [Neil_Sembower]
            extend_enum(cls, 'Berkeley Trailer encap/IP [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x6008 <= value <= 0x6009:
            # [Neil_Sembower]
            extend_enum(cls, 'DEC Unassigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x6010 <= value <= 0x6014:
            # [Neil_Sembower]
            extend_enum(cls, '3Com Corporation [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x7020 <= value <= 0x7029:
            # [Neil_Sembower]
            extend_enum(cls, 'LRT [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8039 <= value <= 0x803C:
            # [Neil_Sembower]
            extend_enum(cls, 'DEC Unassigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8040 <= value <= 0x8042:
            # [Neil_Sembower]
            extend_enum(cls, 'DEC Unassigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x806E <= value <= 0x8077:
            # [Neil_Sembower]
            extend_enum(cls, 'Landmark Graphics Corp. [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x807D <= value <= 0x807F:
            # [Neil_Sembower]
            extend_enum(cls, 'Vitalink Communications [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8081 <= value <= 0x8083:
            # [Neil_Sembower]
            extend_enum(cls, 'Counterpoint Computers [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x809C <= value <= 0x809E:
            # [Neil_Sembower]
            extend_enum(cls, 'Datability [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80A4 <= value <= 0x80B3:
            # [Neil_Sembower]
            extend_enum(cls, 'Siemens Gammasonics Inc. [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80C0 <= value <= 0x80C3:
            # [Neil_Sembower]
            extend_enum(cls, 'DCA Data Exchange Cluster [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80C8 <= value <= 0x80CC:
            # [Neil_Sembower]
            extend_enum(cls, 'Intergraph Corporation [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80CD <= value <= 0x80CE:
            # [Neil_Sembower]
            extend_enum(cls, 'Harris Corporation [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80CF <= value <= 0x80D2:
            # [Neil_Sembower]
            extend_enum(cls, 'Taylor Instrument [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80D3 <= value <= 0x80D4:
            # [Neil_Sembower]
            extend_enum(cls, 'Rosemount Corporation [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80DE <= value <= 0x80DF:
            # [Neil_Sembower]
            extend_enum(cls, 'Integrated Solutions TRFS [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80E0 <= value <= 0x80E3:
            # [Neil_Sembower]
            extend_enum(cls, 'Allen-Bradley [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80E4 <= value <= 0x80F0:
            # [Neil_Sembower]
            extend_enum(cls, 'Datability [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80F4 <= value <= 0x80F5:
            # [Neil_Sembower]
            extend_enum(cls, 'Kinetics [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8101 <= value <= 0x8103:
            # [Neil_Sembower]
            extend_enum(cls, 'Wellfleet Communications [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8107 <= value <= 0x8109:
            # [Neil_Sembower]
            extend_enum(cls, 'Symbolics Private [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8132 <= value <= 0x8136:
            # [Neil_Sembower]
            extend_enum(cls, 'Bridge Communications [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8137 <= value <= 0x8138:
            # [Neil_Sembower]
            extend_enum(cls, 'Novell, Inc. [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8139 <= value <= 0x813D:
            # [Neil_Sembower]
            extend_enum(cls, 'KTI [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8151 <= value <= 0x8153:
            # [Neil_Sembower]
            extend_enum(cls, 'Qualcomm [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x815C <= value <= 0x815E:
            # [Neil_Sembower]
            extend_enum(cls, 'Computer Protocol Pty Ltd [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8164 <= value <= 0x8166:
            # [Neil_Sembower]
            extend_enum(cls, 'Charles River Data System [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8184 <= value <= 0x818C:
            # [Neil_Sembower]
            extend_enum(cls, 'Silicon Graphics prop. [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x819A <= value <= 0x81A3:
            # [Neil_Sembower]
            extend_enum(cls, 'Qualcomm [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81A5 <= value <= 0x81AE:
            # [Neil_Sembower]
            extend_enum(cls, 'RAD Network Devices [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81B7 <= value <= 0x81B9:
            # [Neil_Sembower]
            extend_enum(cls, 'Xyplex [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81CC <= value <= 0x81D5:
            # [Neil_Sembower]
            extend_enum(cls, 'Apricot Computers [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81D6 <= value <= 0x81DD:
            # [Neil_Sembower]
            extend_enum(cls, 'Artisoft [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81E6 <= value <= 0x81EF:
            # [Neil_Sembower]
            extend_enum(cls, 'Polygon [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F0 <= value <= 0x81F2:
            # [Neil_Sembower]
            extend_enum(cls, 'Comsat Labs [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F3 <= value <= 0x81F5:
            # [Neil_Sembower]
            extend_enum(cls, 'SAIC [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F6 <= value <= 0x81F8:
            # [Neil_Sembower]
            extend_enum(cls, 'VG Analytical [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8203 <= value <= 0x8205:
            # [Neil_Sembower]
            extend_enum(cls, 'Quantum Software [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8221 <= value <= 0x8222:
            # [Neil_Sembower]
            extend_enum(cls, 'Ascom Banking Systems [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x823E <= value <= 0x8240:
            # [Neil_Sembower]
            extend_enum(cls, 'Advanced Encryption Syste [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x827F <= value <= 0x8282:
            # [Neil_Sembower]
            extend_enum(cls, 'Athena Programming [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8263 <= value <= 0x826A:
            # [Neil_Sembower]
            extend_enum(cls, 'Charles River Data System [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x829A <= value <= 0x829B:
            # [Neil_Sembower]
            extend_enum(cls, 'Inst Ind Info Tech [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x829C <= value <= 0x82AB:
            # [Neil_Sembower]
            extend_enum(cls, 'Taurus Controls [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x82AC <= value <= 0x8693:
            # [Neil_Sembower]
            extend_enum(cls, 'Walker Richer & Quinn [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8694 <= value <= 0x869D:
            # [Neil_Sembower]
            extend_enum(cls, 'Idea Courier [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x869E <= value <= 0x86A1:
            # [Neil_Sembower]
            extend_enum(cls, 'Computer Network Tech [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x86A3 <= value <= 0x86AC:
            # [Neil_Sembower]
            extend_enum(cls, 'Gateway Communications [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x86E0 <= value <= 0x86EF:
            # [Neil_Sembower]
            extend_enum(cls, 'Landis & Gyr Powers [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8700 <= value <= 0x8710:
            # [Neil_Sembower]
            extend_enum(cls, 'Motorola [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8A96 <= value <= 0x8A97:
            # [Neil_Sembower]
            extend_enum(cls, 'Invisible Software [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0xFF00 <= value <= 0xFF0F:
            # [Neil_Sembower]
            extend_enum(cls, 'ISC Bunker Ramo [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        super()._missing_(value)
