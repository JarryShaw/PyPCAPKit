#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Link Layer Protocols
# Table of corresponding protocols


from ..protocol import Protocol


class Link(Protocol):

    __layer__ = 'Link'


# Link laywer protocols
LINKTYPE = {
    0: 'Null',
    1: 'Eithernet',
}
