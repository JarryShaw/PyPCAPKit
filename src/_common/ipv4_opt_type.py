# -*- coding: utf-8 -*-


# IP Option Numbers
OPT_TYPE = {
    0 : 'EOOL',                                                                 # [RFC 791][Jon_Postel] End of Options List
    1 : 'NOP',                                                                  # [RFC 791][Jon_Postel] No Operation
  130 : 'SEC',                                                                  # [RFC 1108] Security
  131 : 'LSR',                                                                  # [RFC 791][Jon_Postel] Loose Source Route
   68 : 'TS',                                                                   # [RFC 791][Jon_Postel] Time Stamp
  133 : 'E-SEC',                                                                # [RFC 1108] Extended Security
  134 : 'CIPSO',                                                                # [draft-ietf-cipso-ipsecurity-01] Commercial Security
    7 : 'RR',                                                                   # [RFC 791][Jon_Postel] Record Route
  136 : 'SID',                                                                  # [RFC 791][Jon_Postel][RFC 6814] Stream ID
  137 : 'SSR',                                                                  # [RFC 791][Jon_Postel] Strict Source Route
   10 : 'ZSU',                                                                  # [ZSu] Experimental Measurement
   11 : 'MTUP',                                                                 # [RFC 1063][RFC 1191] MTU Probe
   12 : 'MTUR',                                                                 # [RFC 1063][RFC 1191] MTU Reply
  205 : 'FINN',                                                                 # [Greg_Finn] Experimental Flow Control
  142 : 'VISA',                                                                 # [Deborah_Estrin][RFC 6814] Experimental Access Control
   15 : 'ENCODE',                                                               # [VerSteeg][RFC 6814]
  144 : 'IMITD',                                                                # [Lee] IMI Traffic Descriptor
  145 : 'EIP',                                                                  # [RFC 1385][RFC 6814] Extended Internet Protocol
   82 : 'TR',                                                                   # [RFC 1393][RFC 6814] Traceroute
  147 : 'ADDEXT',                                                               # [Ullmann IPv7][RFC 6814] Address Extension
  148 : 'RTRALT',                                                               # [RFC 2113] Router Alert
  149 : 'SDB',                                                                  # [Charles_Bud_Graff][RFC 6814] Selective Directed Broadcast
  150 : 'Unassigned [150]',                                                     # Unassigned (Released 18 October 2005)
  151 : 'DPS',                                                                  # [Andy_Malis][RFC 6814] Dynamic Packet State
  152 : 'UMP',                                                                  # [Dino_Farinacci][RFC 6814] Upstream Multicast Pkt.
   25 : 'QS',                                                                   # [RFC 4782] Quick-Start
   30 : 'EXP',                                                                  # [RFC 4727] RFC3692-style Experiment
   94 : 'EXP',                                                                  # [RFC 4727] RFC3692-style Experiment
  158 : 'EXP',                                                                  # [RFC 4727] RFC3692-style Experiment
  222 : 'EXP',                                                                  # [RFC 4727] RFC3692-style Experiment
}
