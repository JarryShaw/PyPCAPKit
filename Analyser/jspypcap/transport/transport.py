#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Transport Layer Protocols
# Table of corresponding protocols


from ..protocol import Protocol


class Transport(Protocol):

    __layer__ = 'Transport'


# Transport laywer protocols
TP_PROTO = {
    1:   'ICMP',
    2:   'IGMP',
    6:   'TCP',
    17:  'UDP',
    41:  'ENCAP',
    89:  'OSPF',
    132: 'SCTP',
}
