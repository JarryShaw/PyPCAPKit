SHELL := /usr/local/bin/bash
DIR   ?= .

# fetch platform spec
platform = $(shell python3 -c "import distutils.util; print(distutils.util.get_platform().replace('-', '_').replace('.', '_'))")
# get version string
version  = $(shell cat setup.py | grep "^__version__" | sed "s/__version__ = '\(.*\)'/\1/")
# commit message
message  =

clean: clean-pyc clean-misc clean-pypi
const: update-const
release: release-master
pipenv: update-pipenv
pypi: dist-upload

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
	find dist -iname '*.egg' -exec mv {} eggs \;
	find dist -iname '*.whl' -exec mv {} wheels \;
	find dist -iname '*.tar.gz' -exec mv {} sdist \;
	rm -rf build dist *.egg-info

# update pipenv
update-pipenv:
	pipenv update
	pipenv install --dev
	pipenv clean

# update const scripts
.ONESHELL:
update-const:
	set -x
	for file in src/vendor/*/*.py ; do \
		pipenv run python3 $${file} ; \
	done

# update maintenance information
update-maintainer:
	go run github.com/gaocegege/maintainer changelog
	go run github.com/gaocegege/maintainer contributor
	go run github.com/gaocegege/maintainer contributing

# make PyPI distribution
dist-pypi: clean-pypi dist-pypi-new dist-pypi-old dist-linux

# make Python >=3.6 distribution
.ONESHELL:
dist-pypi-new:
	cd $(DIR)
	python3.7 setup.py bdist_egg bdist_wheel --plat-name="$(platform)" --python-tag='cp37'
	python3.6 setup.py bdist_egg bdist_wheel --plat-name="$(platform)" --python-tag='cp36'

# perform f2format
dist-f2format:
	f2format -n $(DIR)/pcapkit

# make Python <3.6 distribution
.ONESHELL:
dist-pypi-old: dist-f2format
	cd $(DIR)
	python3.5 setup.py bdist_egg bdist_wheel --plat-name="$(platform)" --python-tag='cp35'
	python3.4 setup.py bdist_egg bdist_wheel --plat-name="$(platform)" --python-tag='cp34'
	pypy3 setup.py bdist_wheel --plat-name="$(platform)" --python-tag='pp35'
	python3 setup.py sdist

# make Linux distribution
.ONESHELL:
dist-linux:
	cd $(DIR)/docker
	sed "s/LABEL version.*/LABEL version $(shell date +%Y.%m.%d)/" Dockerfile > Dockerfile.tmp
	mv Dockerfile.tmp Dockerfile
	docker-compose up --build

# upload PyPI distribution
.ONESHELL:
dist-upload: dist-pypi
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
		  README.md \
                  docker \
		  src \
		  setup.py \
		  setup.cfg release/
	mv release/src release/pcapkit

# add tag
.ONESHELL:
git-tag:
	cd $(DIR)
	git tag "v$(version)"

# upload to GitHub
.ONESHELL:
git-upload:
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
		--description "$(message)"

# run pre-distribution process
dist-pre: const

# run post-distribution process
dist-post:
	$(MAKE) message="$(message)" DIR=release \
		clean pypi git-tag git-upload
	$(MAKE) message="$(message)" \
		git-upload release update-maintainer git-aftermath

# run full distribution process
dist-all: dist-pre dist-prep dist-post

# run distro process in devel
dist-devel: dist-pre git-upload

# run distro process in master
dist-master: dist-prep dist-post
