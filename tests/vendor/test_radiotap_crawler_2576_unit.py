# -*- coding: utf-8 -*-
"""GitHub issue #2576: the radiotap crawlers.

:mod:`pcapkit.vendor.radiotap.field_type` scrapes radiotap.org's *Defined
Fields* table and two rows of its *Unofficially Used Fields* one, and each flag
crawler the table on its field's page. Regenerating each constant module from
the fixtures below, the tables as radiotap.org served them on 2026-11-01, is a
no-op against the committed file, so a crawler edit that was never regenerated
fails here.

**The fixtures are built inline and parsed with the same** ``html5lib`` **the
crawlers use**, rather than fetched, as in ``test_ftp_return_code_unit.py``:
the unit tier makes no network call.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture and makes
no network call.

"""
from __future__ import annotations

import html
import importlib
import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders the constant modules from recorded data and compares them
#: with the committed files, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The distributions importing :mod:`pcapkit.vendor` with its crawlers needs, as
#: ``test_ipx_packet_unit.py`` names them.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all; see ``test_ipx_packet_unit.py``.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Each row of the *Defined Fields* table, as ``(bit number, field, page)``.
ROWS = (
    (0, 'TSFT', 'TSFT'), (1, 'Flags', 'Flags'), (2, 'Rate', 'Rate'), (3, 'Channel', 'Channel'),
    (4, 'FHSS', 'FHSS'), (5, 'Antenna signal', 'Antenna%20signal'),
    (6, 'Antenna noise', 'Antenna%20noise'), (7, 'Lock quality', 'Lock%20quality'),
    (8, 'TX attenuation', 'TX%20attenuation'), (9, 'dB TX attenuation', 'dB%20TX%20attenuation'),
    (10, 'dBm TX power', 'dBm%20TX%20power'), (11, 'Antenna', 'Antenna'),
    (12, 'dB antenna signal', 'dB%20antenna%20signal'), (13, 'dB antenna noise', 'dB%20antenna%20noise'),
    (14, 'RX flags', 'RX%20flags'), (15, 'TX flags', 'TX%20flags'), (19, 'MCS', 'MCS'),
    (20, 'A-MPDU status', 'A-MPDU%20status'), (21, 'VHT', 'VHT'), (22, 'timestamp', 'timestamp'),
    (23, 'HE', 'HE'), (24, 'HE-MU', 'HE-MU'), (25, 'HE-MU-other-user', 'HE-MU-other-user'),
    (26, '0-length-PSDU', '0-length-PSDU'), (27, 'L-SIG', 'L-SIG'),
    (28, 'TLV fields in radiotap', 'TLV'), (29, 'Radiotap Namespace', 'Radiotap%20Namespace'),
    (30, 'Vendor Namespace', 'Vendor%20Namespace'), (32, 'S1G', 'S1G'), (33, 'U-SIG', 'U-SIG'),
    (34, 'EHT', 'EHT'),
)

#: Each row of the *Unofficially Used Fields* table, as ``(bit number, field,
#: page, generators, parsers)``.
UNOFFICIAL_ROWS = (
    (14, 'FCS in header', 'FCS%20in%20header', 'OpenBSD', 'wireshark'),
    (16, 'RSSI', 'RSSI', 'OpenBSD', ''),
    (16, 'RTS retries', 'RTS%20retries', 'Linux (only libertas driver), NetBSD (?)', ''),
    (17, 'data retries', 'data%20retries', 'Linux (mac80211)', 'wireshark'),
    (18, 'XChannel', 'XChannel', 'FreeBSD, OS X', 'wireshark (partial)'),
)

#: The *Defined Fields* page, in the shape the live one has: a header row of bold
#: cells, then one row per field, the name linked to its page.
FIXTURE = ''.join((
    '<!DOCTYPE html><html><head><title>Radiotap - Defined Fields</title></head><body>',
    '<h1>Defined Fields</h1><p><p>The following fields are defined:</p><table><tbody>',
    '<tr><td><strong>bit number</strong></td><td><strong>field</strong></td></tr>',
    *(f'<tr><td>{bit}</td><td><a href="/fields/{page}.html">{name}</a></td></tr>' for bit, name, page in ROWS),
    '</tbody></table></p></body></html>',
))

#: The *Unofficially Used Fields* page, in the same shape.
UNOFFICIAL = ''.join((
    '<!DOCTYPE html><html><head><title>Radiotap - Unofficially Used Fields</title></head><body>',
    '<h1>Unofficially Used Fields</h1><table><tbody><tr><td><strong>bit number</strong></td>',
    '<td><strong>field</strong></td><td><strong>generators/OS(es)</strong></td>',
    '<td><strong>parser(s)</strong></td></tr>',
    *(f'<tr><td>{bit}</td><td><a href="/fields/{page}.html">{name}</a></td><td>{generators}</td>'
      f'<td>{parsers}</td></tr>' for bit, name, page, generators, parsers in UNOFFICIAL_ROWS),
    '</tbody></table></body></html>',
))

#: Each flag crawler's page, as ``(module, class, page)``.
FLAG_CRAWLERS = (
    ('flags', 'Flags', 'Flags'), ('channel_flags', 'ChannelFlags', 'Channel'),
    ('rx_flags', 'RXFlags', 'RX flags'), ('tx_flags', 'TXFlags', 'TX flags'),
    ('mcs_known', 'MCSKnown', 'MCS'), ('ampdu_flags', 'AMPDUFlags', 'A-MPDU status'),
    ('vht_known', 'VHTKnown', 'VHT'), ('vht_flags', 'VHTFlags', 'VHT'), ('vht_coding', 'VHTCoding', 'VHT'),
    ('timestamp_flags', 'TimestampFlags', 'timestamp'),
    ('he_mu_other_user_known', 'HEMUOtherUserKnown', 'HE-MU-other-user'),
    ('lsig_data1', 'LSIGData1', 'L-SIG'), ('s1g_known', 'S1GKnown', 'S1G'), ('eht_known', 'EHTKnown', 'EHT'),
)

#: Prefixes the name maps' macros carry, which the member names drop.
PREFIXES = ('IEEE80211_RADIOTAP_', 'IEEE80211_')

#: The tables of each field page, and the one after them where a page holds
#: more, which no crawler takes: ``(heading, paragraph, subfield, rows)``, the
#: heading and subfield :obj:`None` where the page has none. Cell texts are kept
#: as served, ``«BR»`` included.
PAGES = {'A-MPDU status': ((None,
                    'The following flags are defined:',
                    None,
                    (('0x0001', 'driver reports 0-length subframes'),
                     ('0x0002', 'frame is 0-length subframe (valid only if 0x0001 is set)'),
                     ('0x0004', 'last subframe is known (should be set for all subframes in an A-MPDU)'),
                     ('0x0008', 'this frame is the last subframe'),
                     ('0x0010', 'delimiter CRC error'),
                     ('0x0020', 'delimiter CRC value known: the delimiter CRC value field is valid'),
                     ('0x0040', 'EOF value'),
                     ('0x0080', 'EOF value known'),
                     ('0xff00', 'reserved'))),),
 'Channel': ((None,
              'Currently, the following flags are defined:',
              None,
              (('Mask', 'Meaning'),
               ('0x0001', 'S1G 700MHz spectrum channel'),
               ('0x0002', 'S1G 800MHz spectrum channel'),
               ('0x0004', 'S1G 900MHz spectrum channel'),
               ('0x0010', 'Turbo Channel'),
               ('0x0020', 'CCK channel'),
               ('0x0040', 'OFDM channel'),
               ('0x0080', '2 GHz spectrum channel'),
               ('0x0100', '5 GHz spectrum channel'),
               ('0x0200', 'Only passive scan allowed'),
               ('0x0400', 'Dynamic CCK-OFDM channel'),
               ('0x0800', 'GFSK channel (FHSS PHY)'))),),
 'EHT': (('known',
          'Note that for trigger-based (TB) PPDUs, the EHT-SIG isn’t present over the air as all the '
          'information for each station is provided in the trigger frame. Sniffer should - where possible - '
          'provide a subset of the OFDMA related fields to simplify understanding of the resulting capture '
          '(i.e. to be able to read it without having to go back to the prior trigger frame.)',
          'known',
          (('bits', 'OFDMA (including TB)', 'MU-MIMO', 'EHT sounding'),
           ('0x00000001', '(reserved)', '(reserved)', '(reserved)'),
           ('0x00000002', 'Spatial Reuse Known', '(same)', '(same)'),
           ('0x00000004', 'GI (Guard Interval) Known', '(same)', '(same)'),
           ('0x00000008', '(reserved)', '(reserved)', '(reserved)'),
           ('0x00000010', 'number of LTF symbols Known', '(same)', '(same)'),
           ('0x00000020', 'LDPC Extra Symbol Segment Known', '(same)', '(reserved)'),
           ('0x00000040', 'Pre-FEC Padding Factor Known', '(same)', '(reserved)'),
           ('0x00000080', 'PE Disambiguity Known', '(same)', '(reserved)'),
           ('0x00000100', 'Disregard Known', '(same)', '(reserved)'),
           ('0x00000200', '(reserved)', '(reserved)', 'Disregard Known'),
           ('0x00001c00', '(reserved)', '(reserved)', '(reserved)'),
           ('0x00002000', 'CRC1 Known', '(same)', '(same)'),
           ('0x00004000', 'Tail1 Known', '(same)', '(same)'),
           ('0x00008000', 'CRC2 Known', '(reserved)', '(reserved)'),
           ('0x00010000', 'Tail2 Known', '(reserved)', '(reserved)'),
           ('0x00020000', '(reserved)', '(reserved)', 'NSS Known'),
           ('0x00040000', '(reserved)', '(reserved)', 'Beamformed Known'),
           ('0x00080000', '(reserved)', 'Number Of Non-OFDMA Users Known', '(reserved)'),
           ('0x00100000', '(reserved)', 'User Encoding Block CRC Known', '(reserved)'),
           ('0x00200000', '(reserved)', 'User Encoding Block Tail Known', '(reserved)'),
           ('0x00400000', 'RU/MRU Size Known', '(same)', '(reserved)'),
           ('0x00800000', 'RU/MRU Index Known', '(same)', '(reserved)'),
           ('0x01000000', 'RU Allocation (TB format) Known', '(same)', '(reserved)'),
           ('0x02000000', 'Primary 80 MHz Channel Position known', '(same)', '(same)'),
           ('0xfc000000', '(reserved)', '(reserved)', '(reserved)'))),
         ('data[0]',
          'data[0]',
          'data[0]',
          (('bits', 'meaning'),
           ('0x00000007', '(reserved)'),
           ('0x00000078', 'Spatial Reuse'),
           ('0x00000180', 'GI (0=0.8us, 1=1.6us, 2=3.2us, 3=reserved)'),
           ('0x00000600', 'LTF symbol size (0=unknown, 1=1x, 2=2x, 3=4x)'),
           ('0x00003800', 'number of LTF symbols (0=1x, 1=2x, 2=4x, 3=6x, 4=8x, 5-7=reserved)'),
           ('0x00004000', 'LDPC extra symbol segment'),
           ('0x00018000', 'Pre-FEC padding factor'),
           ('0x00020000', 'PE Disambiguity'),
           ('0x000c0000', 'Disregard (EHT sounding)'),
           ('0x00300000', '(reserved) (EHT sounding)'),
           ('0x003c0000', 'Disregard (non EHT sounding)'),
           ('0x03c00000', 'CRC1 (OFDMA: B0-16+9N, EHT sounding: B0-15, non-OFDMA: B0-41)'),
           ('0xfc000000', 'Tail1')))),
 'Flags': ((None,
            'Currently, the following flags are defined:',
            None,
            (('Mask', 'Meaning'),
             ('0x01', 'sent/received during CFP'),
             ('0x02', 'sent/received with short preamble'),
             ('0x04', 'sent/received with WEP encryption'),
             ('0x08', 'sent/received with fragmentation'),
             ('0x10', 'frame includes FCS'),
             ('0x20', 'frame has padding between 802.11 header and payload (to 32-bit boundary)'),
             ('0x40', 'frame failed FCS check'))),
           (None,
            'Currently unspecified but used:',
            None,
            (('Mask', 'Meaning'), ('0x80', 'frame used short guard interval (HT)')))),
 'HE-MU-other-user': (('per_user_1',
                       'per_user_1',
                       'per_user_1',
                       (('0x7fff', 'B0-B14 of the HE-SIG-B user field as in spec'),
                        ('0x8000', '(reserved)'))),
                      ('per_user_2',
                       'per_user_2',
                       'per_user_2',
                       (('0x003f', 'B15-B20 of the HE-SIG-B user field as in spec'),
                        ('0xffc0', '(reserved)'))),
                      ('per_user_known',
                       'per_user_known',
                       'per_user_known',
                       (('0x01', 'user field position known'),
                        ('0x02', 'STA-ID known (B0-10)'),
                        ('0x04', 'NSTS known (B11-13, only for non-MU-MIMO)'),
                        ('0x08', 'Tx Beamforming known (B14, only for non-MU-MIMO)'),
                        ('0x10', 'Spatial Configuration known (B11-B14, only for MU-MIMO)'),
                        ('0x20', 'MCS known (B15-18)'),
                        ('0x40', 'DCM known (B19)'),
                        ('0x80', 'Coding known (B20)')))),
 'L-SIG': (('data1',
            'data1',
            'data1',
            (('0x0001', 'rate known'), ('0x0002', 'length known'), ('0xfffc', '(reserved)'))),
           ('data2', 'data2', 'data2', (('0x000f', 'rate'), ('0xfff0', 'length')))),
 'MCS': ((None,
          'The known field indicates which information is known:',
          'known',
          (('flag', 'definition'),
           ('0x01', 'bandwidth'),
           ('0x02', 'MCS index known (in mcs part of the field)'),
           ('0x04', 'guard interval'),
           ('0x08', 'HT format'),
           ('0x10', 'FEC type'),
           ('0x20', 'STBC known'),
           ('0x40', 'Ness known (Number of extension spatial streams)'),
           ('0x80', 'Ness data - bit 1 (MSB) of Number of extension spatial streams'))),
         (None,
          'The flags field is any combination of the following:',
          'flags',
          (('flag', 'definition'),
           ('0x03', 'bandwidth - 0: 20, 1: 40, 2: 20L, 3: 20U'),
           ('0x04', 'guard interval - 0: long GI, 1: short GI'),
           ('0x08', 'HT format - 0: mixed, 1: greenfield'),
           ('0x10', 'FEC type - 0: BCC, 1: LDPC'),
           ('0x60', 'Number of STBC streams'),
           ('0x80', 'Ness - bit 0 (LSB) of Number of extension spatial streams')))),
 'RX flags': ((None,
               'The following flags are currently defined:',
               None,
               (('mask', 'meaning'),
                ('0x0001', 'reserved (was FCS failed but this is a regular flag)'),
                ('0x0002', 'PLCP CRC check failed'),
                ('0xfffc', 'reserved for future expansion'))),),
 'S1G': (('known',
          'known',
          'known',
          (('0x0001', 'S1G PPDU Format known'),
           ('0x0002', 'Response indication known'),
           ('0x0004', 'Guard interval known'),
           ('0x0008', 'NSS known'),
           ('0x0010', 'Bandwidth known'),
           ('0x0020', 'MCS known'),
           ('0x0040', 'Color known'),
           ('0x0080', 'uplink indication known'),
           ('0xFF00', 'Reserved'))),
         ('data1',
          'data1',
          'data1',
          (('0x0003', 'S1G PPDU Format: 0=S1G_1M, 1=S1G_SHORT, 2=S1G_LONG'),
           ('0x000C',
            'Response indication: 0=NO_RESPONSE, 1=NDP_RESPONSE, 2=NORMAL_RESPONSE, 3=LONG_RESPONSE'),
           ('0x0010', 'Reserved'),
           ('0x0020', 'Guard interval: 0=Long GI, 1=Short GI'),
           ('0x00C0', 'Number spatial streams: 0=1 Spatial stream, 1=2, .. 3=4 Spatial streams'),
           ('0x0F00', 'Bandwidth: 0=1MHz, 1=2MHz, 2=4MHz, 3=8MHz, 4=16MHz, 5-15 reserved'),
           ('0xF000', 'MCS (MCS rate index, 0-10, 11-15 reserved)')))),
 'TX flags': ((None,
               'Properties of transmitted frames.',
               None,
               (('mask', 'meaning'),
                ('0x0001', 'Transmission failed due to excessive retries'),
                ('0x0002', 'Transmission used CTS-to-self protection'),
                ('0x0004', 'Transmission used RTS/CTS handshake'),
                ('0x0008',
                 'Transmission shall not expect an ACK frame and not retry when no ACK is received'),
                ('0x0010',
                 'Transmission includes a pre-configured sequence number that should not be changed by the '
                 'driver’s TX handlers'),
                ('0x0020',
                 'Transmission should not be reordered relative to other frames that have this flag set'))),),
 'VHT': ((None,
          'The known field indicates which information is known:',
          'known',
          (('flag', 'definition', 'notes'),
           ('0x0001', 'STBC known', 'In flags part of the field.'),
           ('0x0002', 'TXOP_PS_NOT_ALLOWED known', 'In flags part of the field.'),
           ('0x0004', 'Guard interval', 'In flags part of the field.'),
           ('0x0008', 'Short GI NSYM disambiguation known', 'In flags part of the field.'),
           ('0x0010', 'LDPC extra OFDM symbol known', 'In flags part of the field.'),
           ('0x0020',
            'Beamformed known/applicable',
            'In flags part of the field. This flag should be set to zero for MU PPDUs.'),
           ('0x0040', 'Bandwidth known', 'In bandwidth part of the field.'),
           ('0x0080', 'Group ID known', 'In group_id part of the field.'),
           ('0x0100',
            'Partial AID known/applicable',
            'In partial_aid part of the field. This flag should be set to zero for MU PPDUs.'),
           ('0xfe00', '(unused)', ''))),
         (None,
          'The flags field is any combination of the following:',
          'flags',
          (('flag', 'definition', 'notes'),
           ('0x01',
            'STBC',
            'Space-time block coding.«BR»Set to 0 if no spatial streams of any user has STBC.«BR»Set to 1 if '
            'all spatial streams of all users have STBC.'),
           ('0x02',
            'TXOP_PS_NOT_ALLOWED',
            'Valid only for AP transmitters.«BR»Set to 0 if STAs may doze during TXOP.«BR»Set to 1 if STAs '
            'may not doze during TXOP or transmitter is non-AP.'),
           ('0x04', 'Guard interval.', 'Set to 0 for long GI.«BR»Set to 1 for short GI.'),
           ('0x08',
            'Short GI NSYM disambiguation',
            'Valid only if short GI is used.«BR»Set to 0 if NSYM mod 10 != 9 or short GI not used.«BR»Set to '
            '1 if NSYM mod 10 = 9.'),
           ('0x10',
            'LDPC Extra OFDM symbol',
            'Set to 1 if one or more users are using LDPC and the encoding process resulted in extra OFDM '
            'symbol(s).«BR»Set to 0 otherwise.'),
           ('0x20', 'Beamformed', 'Valid for SU PPDUs only.'),
           ('0xc0', '(unused)', ''))),
         (None,
          'The bandwidth field encodes the bandwidth:',
          'bandwidth',
          (('bitmask', 'definition', 'notes'), ('0x1f', 'Bandwidth', ''), ('0xe0', '(unused)', ''))),
         (None,
          'Bandwidth values are:',
          'bandwidth',
          (('value', 'total bandwidth (MHz)', 'sideband', 'sideband index'),
           ('0', '20', '', ''),
           ('1', '40', '', ''),
           ('2', '40', '20L', '0'),
           ('3', '40', '20U', '1'),
           ('4', '80', '', ''),
           ('5', '80', '40L', '0'),
           ('6', '80', '40U', '1'),
           ('7', '80', '20LL', '0'),
           ('8', '80', '20LU', '1'),
           ('9', '80', '20UL', '2'),
           ('10', '80', '20UU', '3'),
           ('11', '160', '', ''),
           ('12', '160', '80L', '0'),
           ('13', '160', '80U', '1'),
           ('14', '160', '40LL', '0'),
           ('15', '160', '40LU', '1'),
           ('16', '160', '40UL', '2'),
           ('17', '160', '40UU', '3'),
           ('18', '160', '20LLL', '0'),
           ('19', '160', '20LLU', '1'),
           ('20', '160', '20LUL', '2'),
           ('21', '160', '20LUU', '3'),
           ('22', '160', '20ULL', '4'),
           ('23', '160', '20ULU', '5'),
           ('24', '160', '20UUL', '6'),
           ('25', '160', '20UUU', '7'))),
         (None,
          'The four mcs_nss fields encode MCS and NSS for up to four users:',
          'bandwidth',
          (('bitmask', 'definition', 'notes'),
           ('0x0f', 'NSS', 'Number of spatial streams, range 1-8.'),
           ('0xf0', 'MCS', 'MCS rate index, range 0-9.'))),
         (None,
          'The coding field encodes the FEC for up to four users:',
          'coding',
          (('bitmask', 'definition', 'notes'),
           ('0x01', 'Coding for user 0', 'Set to 0 for BCC.«BR»Set to 1 for LDPC.'),
           ('0x02', 'Coding for user 1', 'Set to 0 for BCC.«BR»Set to 1 for LDPC.'),
           ('0x04', 'Coding for user 2', 'Set to 0 for BCC.«BR»Set to 1 for LDPC.'),
           ('0x08', 'Coding for user 3', 'Set to 0 for BCC.«BR»Set to 1 for LDPC.'),
           ('0xf0', '(unused)', '')))),
 'timestamp': (('unit/position',
                'unit/position',
                'unit/position',
                (('flag', 'meaning'),
                 ('0x000F', 'unit - see below'),
                 ('0x00F0', 'sampling position - see below'))),
               ('unit/position',
                'unit/position',
                'unit/position',
                (('value', 'unit'),
                 ('0', 'milliseconds'),
                 ('1', 'microseconds'),
                 ('2', 'nanoseconds'),
                 ('3-15', 'reserved'))),
               ('unit/position',
                'unit/position',
                'unit/position',
                (('value', 'sampling position'),
                 ('0', 'first bit (or symbol containing it) of MPDU - matches TSFT field'),
                 ('1', 'signal acquisition at start of PLCP'),
                 ('2', 'end of PPDU'),
                 ('3', 'end of MPDU (after FCS)'),
                 ('4-14', 'reserved'),
                 ('15', 'unknown or vendor/OOB defined'))),
               ('flags',
                'flags',
                'flags',
                (('0x01', '32-bit counter (high 32 bits are unused)'),
                 ('0x02', 'accuracy known'),
                 ('0xFC', 'reserved'))))}


def _page(name: 'str') -> 'str':
    """Render the fixture of a field page, in the shape the live one has."""
    parts = [f'<!DOCTYPE html><html><head><title>Radiotap - {name}</title></head><body><h1>{name}</h1>']
    for heading, paragraph, subfield, rows in PAGES[name]:
        if heading is not None:
            parts.append(f'<h2 id="{heading}">{heading}</h2>')
        if subfield is not None and heading is None:
            rest = paragraph[len(f'The {subfield}'):]
            parts.append(f'<p>The <code>{subfield}</code>{html.escape(rest)}</p>')
        else:
            parts.append(f'<p>{html.escape(paragraph)}</p>')
        parts.append('<table><tbody>')
        parts.extend('<tr>' + ''.join(f'<td>{html.escape(cell)}</td>' for cell in row) + '</tr>' for row in rows)
        parts.append('</tbody></table>')
    parts.append('</body></html>')
    return ''.join(parts)


def _normalize(context: 'str') -> 'str':
    """Apply the whitespace normalisation the generator writes files through,
    as ``test_ipx_packet_unit.py`` does."""
    lines = []  # type: list[str]
    for line in context.splitlines():
        if line:
            if line.strip():
                lines.append(line.rstrip())
        else:
            lines.append(line)
    return '\n'.join(lines) + '\n'


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class RadiotapCrawlerTests(unittest.TestCase):
    """The scraped radiotap.org tables, and the registries they generate."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _crawler(self, module: 'str', name: 'str') -> 'Any':
        """The crawler class, skipping when it was imported from another tree."""
        vendor_module = importlib.import_module(f'pcapkit.vendor.radiotap.{module}')
        const_module = importlib.import_module(f'pcapkit.const.radiotap.{module}')
        for found in (vendor_module, const_module):
            resolved = pathlib.Path(found.__file__).resolve()
            if ROOT not in resolved.parents:
                self.skipTest(f'{found.__name__} was imported from {resolved}, which is outside '
                              f'{ROOT}; install this checkout with `pip install -e .`')
        return getattr(vendor_module, name)

    def _assert_regenerates(self, module: 'str', name: 'str', *pages: 'str') -> None:
        """Rendering ``pages`` through the crawler reproduces the committed module."""
        klass = self._crawler(module, name)
        vendor = klass.__new__(klass)
        vendor.NAME = klass.__name__
        vendor.DOCS = klass.__doc__
        data = [item for page in pages for item in vendor.request(page)]
        vendor.record = vendor.count(data)
        generated = _normalize(vendor.context(data))
        path = ROOT / 'pcapkit' / 'const' / 'radiotap' / f'{module}.py'
        self.assertEqual(generated, path.read_text(encoding='utf-8'),
                         f'regenerating {path.relative_to(ROOT)} would change it; run '
                         '`pcapkit-vendor radiotap` and commit the result')

    def test_field_types_regenerate(self) -> None:
        self._assert_regenerates('field_type', 'FieldType', FIXTURE, UNOFFICIAL)

    def test_flag_registries_regenerate(self) -> None:
        for module, name, page in FLAG_CRAWLERS:
            with self.subTest(crawler=name):
                self._assert_regenerates(module, name, _page(page))

    def test_the_crawlers_scrape_radiotap_org(self) -> None:
        klass = self._crawler('field_type', 'FieldType')
        self.assertEqual(klass.LINK, 'https://www.radiotap.org/fields/defined')
        self.assertEqual(importlib.import_module(klass.__module__).UNOFFICIAL_LINK,
                         'https://www.radiotap.org/fields/unofficial')
        rows = klass.__new__(klass).request(FIXTURE)
        self.assertEqual([int(row.select('td')[0].text) for row in rows], [bit for bit, _, _ in ROWS])
        for module, name, page in FLAG_CRAWLERS:
            with self.subTest(crawler=name):
                klass = self._crawler(module, name)
                self.assertEqual(klass.LINK, f'https://www.radiotap.org/fields/{page.replace(" ", "%20")}.html')

    def test_a_crawler_takes_its_subfield_alone(self) -> None:
        """A page tabulating several subfields gives each crawler its own table."""
        for module, name, page, count in (('mcs_known', 'MCSKnown', 'MCS', 1), ('vht_known', 'VHTKnown', 'VHT', 1),
                                          ('vht_flags', 'VHTFlags', 'VHT', 1), ('vht_coding', 'VHTCoding', 'VHT', 1),
                                          ('timestamp_flags', 'TimestampFlags', 'timestamp', 1),
                                          ('lsig_data1', 'LSIGData1', 'L-SIG', 1), ('s1g_known', 'S1GKnown', 'S1G', 1),
                                          ('he_mu_other_user_known', 'HEMUOtherUserKnown', 'HE-MU-other-user', 1),
                                          ('flags', 'Flags', 'Flags', 2)):
            with self.subTest(crawler=name):
                klass = self._crawler(module, name)
                tables = klass.__new__(klass).request(_page(page))
                self.assertEqual(len(tables), count)

    def test_members_take_the_name_maps(self) -> None:
        """Every member is named after its map's macro, less the prefix, and no map name is unused."""
        for module, name, _ in FLAG_CRAWLERS:
            with self.subTest(crawler=name):
                klass = self._crawler(module, name)
                registry = getattr(importlib.import_module(f'pcapkit.const.radiotap.{module}'), name)
                members = {int(member): member.name for member in registry}
                self.assertTrue(set(klass.NAMES) <= set(members), 'a map names a bit the page does not')
                for mask, macro in klass.NAMES.items():
                    prefix = next(prefix for prefix in PREFIXES if macro.startswith(prefix))
                    self.assertEqual(members[mask], macro[len(prefix):])
                if module == 'he_mu_other_user_known':
                    # neither Linux nor Wireshark names these bits
                    self.assertEqual((klass.NAMES, members[0x01]), ({}, 'user_field_position_known'))
                else:
                    self.assertEqual(set(klass.NAMES), set(members), 'a member falls back to radiotap.org wording')

    def test_every_row_is_a_member(self) -> None:
        """Every defined field, and RTS retries and data retries from the unofficial table."""
        from pcapkit.const.radiotap.field_type import FieldType

        self.assertEqual([member.value for member in FieldType], sorted([bit for bit, _, _ in ROWS] + [16, 17]))
        self.assertEqual(FieldType(26).name, 'FieldType_0_length_PSDU')
        self.assertEqual((FieldType(16).name, FieldType(17).name), ('RTS_retries', 'data_retries'))
        # the unofficial rows the registry leaves out
        self.assertEqual((FieldType(14).name, FieldType(18).name), ('RX_flags', 'Unassigned'))

    def test_values_the_table_leaves_out(self) -> None:
        """Bits 29 to 31 of every word are reserved; the rest are unassigned, up to the TLV type's width."""
        from pcapkit.const.radiotap.field_type import FieldType

        for value, name in ((31, 'Reserved'), (61, 'Reserved'), (62, 'Reserved'), (63, 'Reserved'),
                            (18, 'Unassigned'), (35, 'Unassigned'), (0xFFFF, 'Reserved')):
            with self.subTest(value=value):
                self.assertEqual(FieldType(value).name, name)
                self.assertEqual(FieldType.get(value), value)
        for value in (-1, 0x10000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                FieldType(value)

    def test_flag_registries_keep_the_bits_they_do_not_name(self) -> None:
        """An undefined bit stays in the value; a value past the field's width is refused."""
        from pcapkit.const.radiotap.channel_flags import ChannelFlags
        from pcapkit.const.radiotap.eht_known import EHTKnown
        from pcapkit.const.radiotap.rx_flags import RXFlags

        cck_2ghz = ChannelFlags.get(0x00A0)
        self.assertEqual(cck_2ghz, ChannelFlags.CHAN_CCK | ChannelFlags.CHAN_2GHZ)
        for registry, value in ((ChannelFlags, 0x0008), (ChannelFlags, 0x80A8), (RXFlags, 0x0003),
                                (EHTKnown, 0x00000001), (EHTKnown, 0xFC000002)):
            with self.subTest(registry=registry.__name__, value=hex(value)):
                member = registry.get(value)
                self.assertIsInstance(member, registry)
                self.assertEqual(int(member), value)
        self.assertIn(RXFlags.F_RX_BADPLCP, RXFlags.get(0x0003))
        for registry, value in ((ChannelFlags, 0x10000), (RXFlags, -1), (EHTKnown, 1 << 32)):
            with self.subTest(registry=registry.__name__, value=value), self.assertRaises(ValueError):
                registry(value)


if __name__ == '__main__':
    unittest.main()
