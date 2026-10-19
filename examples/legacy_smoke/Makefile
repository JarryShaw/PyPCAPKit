.PHONY: fixtures profile

#: Interpreter to run the demos with. Override for a virtualenv, e.g.
#: `make fixtures PYTHON=../../.venv/bin/python`.
PYTHON ?= python

#: Timezone the reference reports are generated in. pcapkit renders timestamps in
#: UTC, or in a PCAP-NG interface's own `if_tzone`, never in the host's zone (#357,
#: #361), so the reports come out the same without it; the pin is belt-and-braces
#: -- see the README.
FIXTURE_TZ ?= UTC

## Build the reference reports in ../captures/. Git tracks none of them -- they
## are generated output, so a fresh clone has to run this before it has them (#685).
##   out.json, out.plist, out.txt  <- test_extractor.py, from ../captures/in.pcap
##   pcapng.txt                    <- test_pcapng.py,    from ../captures/dhcp.pcapng
## Both inputs *are* committed, so this needs no `make samples` first.
fixtures:
	TZ=$(FIXTURE_TZ) $(PYTHON) test_extractor.py
	TZ=$(FIXTURE_TZ) $(PYTHON) test_pcapng.py
	@echo 'regenerated ../captures/{out.json,out.plist,out.txt,pcapng.txt}'

## Profile one extraction and render the call graph.
profile:
	mkdir -p temp
	$(PYTHON) test_profile.py
	gprof2dot -f pstats temp/parse_pcap.pstats | dot -Tpng -o temp/parse_pcap.png
	snakeviz temp/parse_pcap.pstats
