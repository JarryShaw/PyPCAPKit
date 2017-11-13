#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Internet Layer Protocols
# Table of corresponding protocols


from ..protocol import Protocol


class Internet(Protocol):

    __layer__ = 'Internet'


# Internet laywer protocols
INTERNET = {
    '0800': 'IPv4',
    '0806': 'ARP',
    '8137': 'IPX',
    '86dd': 'IPv6',
}
