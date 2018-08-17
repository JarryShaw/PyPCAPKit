# -*- coding: utf-8 -*-


# priority levels defined in IEEE 802.1p
_PCP = {
	'001' : 'BK',                                                                  # 0 - Background (lowest)
	'000' : 'BE',                                                                  # 1 - Best effort (default)
	'010' : 'EE',                                                                  # 2 - Excellent effort
	'011' : 'CA',                                                                  # 3 - Critical applications
	'100' : 'VI',                                                                  # 4 - Video, < 100 ms latency and jitter
	'101' : 'VO',                                                                  # 5 - Voice, < 10 ms latency and jitter
	'110' : 'IC',                                                                  # 6 - Internetwork control
	'111' : 'NC',                                                                  # 7 - Network control (highest)
}
