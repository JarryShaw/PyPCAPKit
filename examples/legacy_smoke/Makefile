.PHONY:

profile:
	mkdir -p temp
	python test_profile.py
	gprof2dot -f pstats temp/parse_pcap.pstats | dot -Tpng -o temp/parse_pcap.png
	snakeviz temp/parse_pcap.pstats
