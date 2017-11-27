#!/usr/bin/python3
# -*- coding: utf-8 -*-


if __name__ == '__main__':
    from jspcap.analyser import Analyser
    a = Analyser(fmt='plist')
    a = Analyser(fmt='json')
    a = Analyser(fmt='html')
    a = Analyser(fmt='tree')
    a = Analyser(fmt='xml')
