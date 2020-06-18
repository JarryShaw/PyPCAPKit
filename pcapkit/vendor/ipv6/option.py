# -*- coding: utf-8 -*-
"""IPv6 Destination Options and Hop-by-Hop Options"""

import collections
import csv
import re

from pcapkit.vendor.default import Vendor

__all__ = ['Option']

#: IPv6 option registry.
DATA = {
    # [RFC 8200] 0
    0x00: ('pad', 'Pad1'),
    0x01: ('padn', 'PadN'),                                        # [RFC 8200]
    # [RFC 2473] 1
    0x04: ('tun', 'Tunnel Encapsulation Limit'),
    # [RFC 2711] 2
    0x05: ('ra', 'Router Alert'),
    0x07: ('calipso', 'Common Architecture Label IPv6 Security Option'),
    # [RFC 5570]
    0x08: ('smf_dpd', 'Simplified Multicast Forwarding'),          # [RFC 6621]
    # [RFC 8250] 10
    0x0F: ('pdm', 'Performance and Diagnostic Metrics'),
    # [RFC 4782][RFC Errata 2034] 6
    0x26: ('qs', 'Quick-Start'),
    0x63: ('rpl', 'Routing Protocol for Low-Power and Lossy Networks'),
    # [RFC 6553]
    0x6D: ('mpl', 'Multicast Protocol for Low-Power and Lossy Networks'),
    # [RFC 7731]
    0x8B: ('ilnp', 'Identifier-Locator Network Protocol Nonce'),   # [RFC 6744]
    0x8C: ('lio', 'Line-Identification Option'),                   # [RFC 6788]
    0xC2: ('jumbo', 'Jumbo Payload'),                              # [RFC 2675]
    0xC9: ('home', 'Home Address'),                                # [RFC 6275]
    0xEE: ('ip_dff', 'Depth-First Forwarding'),                    # [RFC 6971]
}


class Option(Vendor):
    """Destination Options and Hop-by-Hop Options"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters-2.csv'

    def count(self, data):
        """Count field records.

        Args:
            data (List[str]): CSV data.

        Returns:
            Counter: Field recordings.

        """
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: self.safe_name(item[4]), reader))  # pylint: disable=map-builtin-not-iterating

    def process(self, data):
        """Process CSV data.

        Args:
            data (List[str]): CSV data.

        Returns:
            List[str]: Enumeration fields.
            List[str]: Missing fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = list()
        miss = [
            "extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(2), value)",
            'return cls(value)'
        ]
        for item in reader:
            if not item[0]:
                continue

            code = item[0]
            dscp = item[4]
            rfcs = item[5]

            temp = list()
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
                if re.match(r'\d+', rfc):
                    continue
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            tmp1 = f" {''.join(temp)}" if rfcs else ''

            splt = re.split(r' \[\d+\]', dscp)[0]
            subn = re.sub(r'.* \((.*)\)', r'\1', splt)
            name = DATA.get(int(code, base=16), (str(),))[0].upper() or subn

            desc = self.wrap_comment(re.sub(r'\r*\n', ' ', f'{name}{tmp1}', re.MULTILINE))
            renm = self.rename(name or 'Unassigned', code, original=dscp)

            pres = f"{renm} = {code}"
            sufs = f'#: {desc}'

            #if len(pres) > 74:
            #    sufs = f"\n{' '*80}{sufs}"

            #enum.append(f'{pres.ljust(76)}{sufs}')
            enum.append(f'{sufs}\n    {pres}')
        return enum, miss


if __name__ == "__main__":
    Option()
