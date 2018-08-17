# -*- coding: utf-8 -*-


# IPv6 Extension Header Types
EXT_HDR = (
	'HOPOPT',                                                                      # [RFC 8200] IPv6 Hop-by-Hop Option
	'IPv6-Route',                                                                  # [Steve_Deering] Routing Header for IPv6
	'IPv6-Frag',                                                                   # [Steve_Deering] Fragment Header for IPv6
	'ESP',                                                                         # [RFC 4303] Encap Security Payload
	'AH',                                                                          # [RFC 4302] Authentication Header
	'IPv6-Opts',                                                                   # [RFC 8200] Destination Options for IPv6
	'Mobility Header',                                                             # [RFC 6275]
	'HIP',                                                                         # [RFC 7401] Host Identity Protocol
	'Shim6',                                                                       # [RFC 5533] Shim6 Protocol
	'Use for experimentation and testing [253]',                                   # [RFC 3692]
	'Use for experimentation and testing [254]',                                   # [RFC 3692]
)
