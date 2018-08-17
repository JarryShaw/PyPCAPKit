# -*- coding: utf-8 -*-


# Mobility Header Types - for the MH Type field in the Mobility Header
_MOBILITY_TYPE = {
    0 : 'Binding Refresh Request',                                              #  [RFC 6275]
    1 : 'Home Test Init',                                                       #  [RFC 6275]
    2 : 'Care-of Test Init',                                                    #  [RFC 6275]
    3 : 'Home Test',                                                            #  [RFC 6275]
    4 : 'Care-of Test',                                                         #  [RFC 6275]
    5 : 'Binding Update',                                                       #  [RFC 6275]
    6 : 'Binding Acknowledgement',                                              #  [RFC 6275]
    7 : 'Binding Error',                                                        #  [RFC 6275]
    8 : 'Fast Binding Update',                                                  #  [RFC 5568]
    9 : 'Fast Binding Acknowledgment',                                          #  [RFC 5568]
   10 : 'Fast Neighbor Advertisement',                                          #  [RFC 5568] (Deprecated)
   11 : 'Experimental Mobility Header [11]',                                    #  [RFC 5096]
   12 : 'Home Agent Switch Message',                                            #  [RFC 5142]
   13 : 'Heartbeat Message',                                                    #  [RFC 5847]
   14 : 'Handover Initiate Message',                                            #  [RFC 5568]
   15 : 'Handover Acknowledge Message',                                         #  [RFC 5568]
   16 : 'Binding Revocation Message',                                           #  [RFC 5846]
   17 : 'Localized Routing Initiation',                                         #  [RFC 6705]
   18 : 'Localized Routing Acknowledgment',                                     #  [RFC 6705]
   19 : 'Update Notification',                                                  #  [RFC 7077]
   20 : 'Update Notification Acknowledgement',                                  #  [RFC 7077]
   21 : 'Flow Binding Message',                                                 #  [RFC 7109]
   22 : 'Subscription Query',                                                   #  [RFC 7161]
   23 : 'Subscription Response',                                                #  [RFC 7161]
}
