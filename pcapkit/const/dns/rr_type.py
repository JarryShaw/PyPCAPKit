# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DNS Resource Record (RR) TYPEs
====================================

.. module:: pcapkit.const.dns.rr_type

This module contains the constant enumeration for **DNS Resource Record (RR) TYPEs**,
which is automatically generated from :class:`pcapkit.vendor.dns.rr_type.RRType`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['RRType']


class RRType(EnumRegistry, IntEnum):
    """[RRType] DNS Resource Record (RR) TYPEs"""

    #: Reserved [:rfc:`6895`]
    Reserved_0 = 0

    #: A -- a host address [:rfc:`1035`]
    A = 1

    #: NS -- an authoritative name server [:rfc:`1035`]
    NS = 2

    #: MD -- a mail destination (OBSOLETE - use MX) [:rfc:`1035`]
    MD = 3

    #: MF -- a mail forwarder (OBSOLETE - use MX) [:rfc:`1035`]
    MF = 4

    #: CNAME -- the canonical name for an alias [:rfc:`1035`]
    CNAME = 5

    #: SOA -- marks the start of a zone of authority [:rfc:`1035`]
    SOA = 6

    #: MB -- a mailbox domain name (EXPERIMENTAL) [:rfc:`1035`]
    MB = 7

    #: MG -- a mail group member (EXPERIMENTAL) [:rfc:`1035`]
    MG = 8

    #: MR -- a mail rename domain name (EXPERIMENTAL) [:rfc:`1035`]
    MR = 9

    #: NULL -- a null RR (EXPERIMENTAL) [:rfc:`1035`]
    NULL = 10

    #: WKS -- a well known service description [:rfc:`1035`]
    WKS = 11

    #: PTR -- a domain name pointer [:rfc:`1035`]
    PTR = 12

    #: HINFO -- host information [:rfc:`1035`]
    HINFO = 13

    #: MINFO -- mailbox or mail list information [:rfc:`1035`]
    MINFO = 14

    #: MX -- mail exchange [:rfc:`1035`]
    MX = 15

    #: TXT -- text strings [:rfc:`1035`]
    TXT = 16

    #: RP -- for Responsible Person [:rfc:`1183`]
    RP = 17

    #: AFSDB -- for AFS Data Base location [:rfc:`1183`][:rfc:`5864`]
    AFSDB = 18

    #: X25 -- for X.25 PSDN address [:rfc:`1183`]
    X25 = 19

    #: ISDN -- for ISDN address [:rfc:`1183`]
    ISDN = 20

    #: RT -- for Route Through [:rfc:`1183`]
    RT = 21

    #: NSAP -- for NSAP address, NSAP style A record (DEPRECATED)
    #: [:rfc:`1706`][Moving TPC.INT and NSAP.INT infrastructure domains to
    #: historic]
    NSAP = 22

    #: NSAP-PTR -- for domain name pointer, NSAP style (DEPRECATED)
    #: [:rfc:`1706`][Moving TPC.INT and NSAP.INT infrastructure domains to
    #: historic]
    NSAP_PTR = 23

    #: SIG -- for security signature
    #: [:rfc:`2536`][:rfc:`2931`][:rfc:`3110`][:rfc:`4034`]
    SIG = 24

    #: KEY -- for security key [:rfc:`2536`][:rfc:`2539`][:rfc:`3110`][:rfc:`4034`]
    KEY = 25

    #: PX -- X.400 mail mapping information [:rfc:`2163`]
    PX = 26

    #: GPOS -- Geographical Position [:rfc:`1712`]
    GPOS = 27

    #: AAAA -- IP6 Address [:rfc:`3596`]
    AAAA = 28

    #: LOC -- Location Information [:rfc:`1876`]
    LOC = 29

    #: NXT -- Next Domain (OBSOLETE) [:rfc:`2535`][:rfc:`3755`]
    NXT = 30

    #: EID -- Endpoint Identifier [Michael
    #: Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]
    EID = 31

    #: NIMLOC -- Nimrod Locator [1][Michael
    #: Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]
    NIMLOC = 32

    #: SRV -- Server Selection [1][:rfc:`2782`]
    SRV = 33

    #: ATMA -- ATM Address [ ATM Forum Technical Committee, "ATM Name System,
    #: V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in
    #: escrow by IANA.]
    ATMA = 34

    #: NAPTR -- Naming Authority Pointer [:rfc:`3403`]
    NAPTR = 35

    #: KX -- Key Exchanger [:rfc:`2230`]
    KX = 36

    #: CERT -- CERT [:rfc:`4398`]
    CERT = 37

    #: A6 -- A6 (OBSOLETE - use AAAA) [:rfc:`2874`][:rfc:`3226`][:rfc:`6563`]
    A6 = 38

    #: DNAME -- DNAME [:rfc:`6672`]
    DNAME = 39

    #: SINK -- SINK [Donald E Eastlake][draft-eastlake-kitchen-sink-02]
    SINK = 40

    #: OPT -- OPT [:rfc:`3225`][:rfc:`6891`]
    OPT = 41

    #: APL -- APL [:rfc:`3123`]
    APL = 42

    #: DS -- Delegation Signer [:rfc:`4034`]
    DS = 43

    #: SSHFP -- SSH Key Fingerprint [:rfc:`4255`]
    SSHFP = 44

    #: IPSECKEY -- IPSECKEY [:rfc:`4025`]
    IPSECKEY = 45

    #: RRSIG -- RRSIG [:rfc:`4034`]
    RRSIG = 46

    #: NSEC -- NSEC [:rfc:`4034`][:rfc:`9077`]
    NSEC = 47

    #: DNSKEY -- DNSKEY [:rfc:`4034`]
    DNSKEY = 48

    #: DHCID -- DHCID [:rfc:`4701`]
    DHCID = 49

    #: NSEC3 -- NSEC3 [:rfc:`5155`][:rfc:`9077`]
    NSEC3 = 50

    #: NSEC3PARAM -- NSEC3PARAM [:rfc:`5155`]
    NSEC3PARAM = 51

    #: TLSA -- TLSA [:rfc:`6698`]
    TLSA = 52

    #: SMIMEA -- S/MIME cert association [:rfc:`8162`]
    SMIMEA = 53

    #: DELEGPARAM -- Extensible Delegation Indirection (TEMPORARY - registered
    #: 2026-10-16, expires 2027-10-16) [draft-ietf-deleg-12]
    DELEGPARAM = 54

    #: HIP -- Host Identity Protocol [:rfc:`8005`]
    HIP = 55

    #: NINFO -- NINFO [Jim Reid]
    NINFO = 56

    #: RKEY -- RKEY [Jim Reid]
    RKEY = 57

    #: TALINK -- Trust Anchor LINK [Wouter Wijngaards]
    TALINK = 58

    #: CDS -- Child DS [:rfc:`7344`]
    CDS = 59

    #: CDNSKEY -- DNSKEY(s) the Child wants reflected in DS [:rfc:`7344`]
    CDNSKEY = 60

    #: OPENPGPKEY -- OpenPGP Key [:rfc:`7929`]
    OPENPGPKEY = 61

    #: CSYNC -- Child-To-Parent Synchronization [:rfc:`7477`]
    CSYNC = 62

    #: ZONEMD -- Message Digest Over Zone Data [:rfc:`8976`]
    ZONEMD = 63

    #: SVCB -- General-purpose service binding [:rfc:`9460`]
    SVCB = 64

    #: HTTPS -- SVCB-compatible type for use with HTTP [:rfc:`9460`]
    HTTPS = 65

    #: DSYNC -- Endpoint discovery for delegation synchronization [:rfc:`9859`]
    DSYNC = 66

    #: HHIT -- Hierarchical Host Identity Tag [:rfc:`9886`]
    HHIT = 67

    #: BRID -- UAS Broadcast Remote Identification [:rfc:`9886`]
    BRID = 68

    #: UNECE -- Value coded per a UNECE Recommendation
    #: [draft-woodcock-faltstrom-external-registry-rrtypes-00]
    UNECE = 69

    #: ISO -- Value coded per an ISO standard
    #: [draft-woodcock-faltstrom-external-registry-rrtypes-00]
    ISO = 70

    #: SPF [:rfc:`7208`]
    SPF = 99

    #: UINFO [IANA-Reserved]
    UINFO = 100

    #: UID [IANA-Reserved]
    UID = 101

    #: GID [IANA-Reserved]
    GID = 102

    #: UNSPEC [IANA-Reserved]
    UNSPEC = 103

    #: NID [:rfc:`6742`]
    NID = 104

    #: L32 [:rfc:`6742`]
    L32 = 105

    #: L64 [:rfc:`6742`]
    L64 = 106

    #: LP [:rfc:`6742`]
    LP = 107

    #: EUI48 -- an EUI-48 address [:rfc:`7043`]
    EUI48 = 108

    #: EUI64 -- an EUI-64 address [:rfc:`7043`]
    EUI64 = 109

    #: NXNAME -- NXDOMAIN indicator for Compact Denial of Existence [:rfc:`9824`]
    NXNAME = 128

    #: TKEY -- Transaction Key [:rfc:`2930`]
    TKEY = 249

    #: TSIG -- Transaction Signature [:rfc:`8945`]
    TSIG = 250

    #: IXFR -- incremental transfer [:rfc:`1995`]
    IXFR = 251

    #: AXFR -- transfer of an entire zone [:rfc:`1035`][:rfc:`5936`]
    AXFR = 252

    #: MAILB -- mailbox-related RRs (MB, MG or MR) [:rfc:`1035`]
    MAILB = 253

    #: MAILA -- mail agent RRs (OBSOLETE - see MX) [:rfc:`1035`]
    MAILA = 254

    #: \* -- A request for some or all records the server has available
    #: [:rfc:`1035`][:rfc:`6895`][:rfc:`8482`]
    ANY = 255

    #: URI -- URI [:rfc:`7553`]
    URI = 256

    #: CAA -- Certification Authority Restriction [:rfc:`8659`]
    CAA = 257

    #: AVC -- Application Visibility and Control [Wolfgang Riedel]
    AVC = 258

    #: DOA -- Digital Object Architecture [draft-durand-doa-over-dns-02]
    DOA = 259

    #: AMTRELAY -- Automatic Multicast Tunneling Relay [:rfc:`8777`]
    AMTRELAY = 260

    #: RESINFO -- Resolver Information as Key/Value Pairs [:rfc:`9606`]
    RESINFO = 261

    #: WALLET -- Public wallet address [Paul Hoffman]
    WALLET = 262

    #: CLA -- BP Convergence Layer Adapter [draft-johnson-dns-ipn-cla-07]
    CLA = 263

    #: IPN -- BP Node Number [draft-johnson-dns-ipn-cla-07]
    IPN = 264

    #: TA -- DNSSEC Trust Authorities [Sam Weiler][ Deploying DNSSEC Without a
    #: Signed Root.  Technical Report 1999-19, Information Networking Institute,
    #: Carnegie Mellon University, April 2004.]
    TA = 32768

    #: DLV -- DNSSEC Lookaside Validation (OBSOLETE) [:rfc:`8749`][:rfc:`4431`]
    DLV = 32769

    #: DELEG -- Extensible Delegation (TEMPORARY - registered 2026-10-16, expires
    #: 2027-10-16) [draft-ietf-deleg-12]
    DELEG = 61440

    #: Reserved
    Reserved_65535 = 65535

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'RRType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 71 <= value <= 98:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 110 <= value <= 127:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 129 <= value <= 248:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 265 <= value <= 32767:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 32770 <= value <= 61439:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 61441 <= value <= 65279:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 65280 <= value <= 65534:
            #: Private use
            return cls._unregistered_member(value, 'Private_use')
        return super()._missing_(value)
