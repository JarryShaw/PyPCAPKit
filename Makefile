.PHONY: clean const date dist release pipenv pypi update

export PIPENV_VENV_IN_PROJECT=1

SHELL := /usr/local/bin/bash
DIR   ?= .

# get version string
version  = $(shell cat setup.py | grep "^__version__" | sed "s/__version__ = '\(.*\)'/\1/")
# commit message
message  ?= ""

profile:
	pipenv run python -m cProfile -o /tmp/parse_pcap.pstats $@
	gprof2dot -f pstats /tmp/parse_pcap.pstats | dot -Tpng -o /tmp/parse_pcap.png
	open /tmp/parse_pcap.png

clean: clean-pyc clean-misc clean-pypi
const: update-const
#dist: dist-pypi dist-upload
release: release-master
pipenv: update-pipenv
# update: update-const update-date
update: update-const

dist:
	mkdir -p dist sdist eggs wheels
	find dist -iname '*.egg' -exec mv {} eggs \;
	find dist -iname '*.whl' -exec mv {} wheels \;
	find dist -iname '*.tar.gz' -exec mv {} sdist \;
	rm -rf build dist *.egg-info
	pipenv run python setup.py sdist bdist_wheel
	twine check dist/* || true
	twine upload dist/* -r pypi --skip-existing
	twine upload dist/* -r pypitest --skip-existing

docs:
	PCAPKIT_SPHINX=1 pipenv run $(MAKE) -C doc/sphinx html

pypi:
	DIR=release $(MAKE) dist-prep dist

.ONESHELL:
update-date:
	set -ex
	cd $(DIR)/docker
	sed "s/LABEL version.*/LABEL version $(shell date +%Y.%m.%d)/" Dockerfile > Dockerfile.tmp
	mv Dockerfile.tmp Dockerfile

# setup pipenv
setup-pipenv: clean-pipenv
	pipenv install --dev

# remove *.pyc
clean-pyc:
	find $(DIR) -iname __pycache__ | xargs rm -rf
	find $(DIR) -iname '*.pyc' | xargs rm -f

# remove devel files
clean-misc: clean-pyc
	find $(DIR) -iname .DS_Store | xargs rm -f
	find $(DIR) -iname NotImplemented | xargs rm -rf

# remove pipenv
clean-pipenv:
	pipenv --rm

# prepare for PyPI distribution
.ONESHELL:
clean-pypi:
	cd $(DIR)
	mkdir -p sdist eggs wheels
	[ -d dist ] && find dist -iname '*.egg' -exec mv {} eggs \; || true
	[ -d dist ] && find dist -iname '*.whl' -exec mv {} wheels \; || true
	[ -d dist ] && find dist -iname '*.tar.gz' -exec mv {} sdist \; || true
	rm -rf build dist *.egg-info

# update pipenv
update-pipenv:
	pipenv update
	pipenv install --dev
	pipenv clean

# update const scripts
.ONESHELL:
update-const:
	for file in pcapkit/vendor/*/*.py ; do \
		echo "+ $${file}"; \
	    pipenv run python3 $${file} ; \
	done

# update maintenance information
update-maintainer:
	go run github.com/gaocegege/maintainer changelog
	go run github.com/gaocegege/maintainer contributor
	go run github.com/gaocegege/maintainer contributing

# make PyPI distribution
# dist-pypi: clean-pypi dist-pypi-new dist-pypi-old dist-linux
dist-pypi: clean-pypi dist-pypi-new dist-pypi-old

# make Python >=3.6 distribution
.ONESHELL:
dist-pypi-new:
	set -ex
	cd $(DIR)
	~/.pyenv/versions/3.8.0/bin/python3.8 setup.py bdist_egg bdist_wheel --python-tag='cp38'
	~/.pyenv/versions/3.7.4/bin/python3.7 setup.py bdist_egg bdist_wheel --python-tag='cp37'
	~/.pyenv/versions/3.6.9/bin/python3.6 setup.py bdist_egg bdist_wheel --python-tag='cp36'
	~/.pyenv/versions/pypy3.6-7.1.1/bin/pypy3 setup.py bdist_egg bdist_wheel --python-tag='pp36'

# perform f2format
dist-f2format:
	pipenv run f2format -n $(DIR)/pcapkit

# make Python <3.6 distribution
.ONESHELL:
dist-pypi-old: dist-f2format
	set -ex
	cd $(DIR)
	~/.pyenv/versions/3.5.7/bin/python3.5 setup.py bdist_egg bdist_wheel --python-tag='cp35'
	~/.pyenv/versions/3.4.10/bin/python3.4 setup.py bdist_egg bdist_wheel --python-tag='cp34'
	~/.pyenv/versions/pypy3.5-7.0.0/bin/pypy3 setup.py bdist_egg bdist_wheel --python-tag='pp35'
	pipenv run python setup.py sdist

# # make Linux distribution
# .ONESHELL:
# dist-linux:
# 	set -ex
# 	cd $(DIR)/docker
# 	docker-compose up --build

# upload PyPI distribution
.ONESHELL:
dist-upload:
	set -ex
	cd $(DIR)
	twine check dist/*
	twine upload dist/* -r pypi --skip-existing
	twine upload dist/* -r pypitest --skip-existing

# duplicate distribution files
dist-prep:
	mkdir -p release
	rm -rf release/src \
	       release/pcapkit
	cp -r .gitattributes \
	      .gitignore \
	      LICENSE \
	      MANIFEST.in \
	      README.rst \
	      src \
	      setup.py \
	      setup.cfg release/
	mv release/src release/pcapkit

# add tag
.ONESHELL:
git-tag:
	set -ex
	cd $(DIR)
	git tag "v$(version)"

# upload to GitHub
.ONESHELL:
git-upload:
	set -ex
	cd $(DIR)
	git pull
	git add .
	if [[ -z "$(message)" ]] ; then \
	    git commit -a -S ; \
	else \
	    git commit -a -S -m "$(message)" ; \
	fi
	git push

# upload after distro
git-aftermath:
	git pull
	git add .
	git commit -a -S -m "Regular update after distribution"
	git push

# file new release on master
release-master:
	go run github.com/aktau/github-release release \
	    --user JarryShaw \
	    --repo PyPCAPKit \
	    --tag "v$(version)" \
	    --name "PyPCAPKit v$(version)" \
	    --description "$$(git log -1 --pretty=%B)"

# run pre-distribution process
dist-pre: update

# run post-distribution process
dist-post:
	$(MAKE) message="$(message)" DIR=release \
	    clean dist git-tag git-upload
	$(MAKE) message="$(message)" \
	    git-upload release update-maintainer git-aftermath

# run full distribution process
dist-all: dist-pre dist-prep dist-post

# run distro process in devel
dist-devel: dist-pre git-upload

# run distro process in master
dist-master: dist-prep dist-post

isort:
	pipenv run isort -l100 -ppcapkit --skip-glob '**/__init__.py' pcapkit temp/sort.py

vermin:
	vermin pcapkit --backport argparse --backport enum --backport importlib --backport ipaddress --backport typing --no-parse-comments pcapkit -v

pylint:
	pipenv run pylint --load-plugins=pylint.extensions.check_elif,pylint.extensions.docstyle,pylint.extensions.emptystring,pylint.extensions.overlapping_exceptions --disable=all --enable=F,E,W,R,basic,classes,format,imports,refactoring,else_if_used,docstyle,compare-to-empty-string,overlapping-except --disable=blacklisted-name,invalid-name,missing-class-docstring,missing-function-docstring,missing-module-docstring,design,too-many-lines,eq-without-hash,old-division,no-absolute-import,input-builtin,too-many-nested-blocks,broad-except,singleton-comparison,ungrouped-imports --max-line-length=120 --init-import=yes pcapkit

mypy:
	pipenv run mypy --follow-imports=silent --ignore-missing-imports --show-column-numbers --show-error-codes pcapkit

bandit:
	pipenv run bandit pcapkit
