.PHONY: bootstrap setup dist release docs samples test test-all coverage bench bench-quick bench-test

export PIPENV_VENV_IN_PROJECT=1
export PIPENV_CACHE_DIR ?= $(CURDIR)/.pipenv-cache
export PIP_CACHE_DIR ?= $(CURDIR)/.pip-cache
export all_proxy=

# Recipes below use bash features (brace expansion), so bash is required; take it
# from PATH rather than a fixed prefix, as Homebrew, Linuxbrew and system installs
# all put it somewhere different.
SHELL  := $(shell command -v bash 2>/dev/null || echo /bin/bash)
VERSION = $(shell cat pcapkit/__init__.py | grep "^__version__" | sed "s/__version__ = '\(.*\)'/\1/")

# ``lxml`` needs libxml2/libxslt; on a brewed system they live under the brew
# prefix, which differs between macOS (/opt/homebrew, /usr/local) and Linuxbrew.
BREW ?= $(shell command -v brew 2>/dev/null)
ifneq ($(BREW),)
BREW_PREFIX ?= $(shell $(BREW) --prefix)/opt
else
BREW_PREFIX ?= /opt/homebrew/opt
endif

LIBXML2_PREFIX := $(BREW_PREFIX)/libxml2
LIBXSLT_PREFIX := $(BREW_PREFIX)/libxslt

ifneq ($(wildcard $(LIBXML2_PREFIX)/bin/xml2-config),)
export PATH := $(LIBXML2_PREFIX)/bin:$(PATH)
export CPPFLAGS := -I$(LIBXML2_PREFIX)/include $(CPPFLAGS)
export LDFLAGS := -L$(LIBXML2_PREFIX)/lib $(LDFLAGS)
export PKG_CONFIG_PATH := $(LIBXML2_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
export XML2_CONFIG := $(LIBXML2_PREFIX)/bin/xml2-config
endif

ifneq ($(wildcard $(LIBXSLT_PREFIX)/bin/xslt-config),)
export PATH := $(LIBXSLT_PREFIX)/bin:$(PATH)
export CPPFLAGS := -I$(LIBXSLT_PREFIX)/include $(CPPFLAGS)
export LDFLAGS := -L$(LIBXSLT_PREFIX)/lib $(LDFLAGS)
export PKG_CONFIG_PATH := $(LIBXSLT_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
export XSLT_CONFIG := $(LIBXSLT_PREFIX)/bin/xslt-config
endif

bootstrap: pipenv
setup: pipenv

update: pipenv vendor
dist: update isort dist-clean dist-build dist-upload

dist-clean:
	mkdir -p sdist eggs wheels
	[ -d dist ] && find dist -iname '*.egg' -exec mv {} eggs \; || true
	[ -d dist ] && find dist -iname '*.whl' -exec mv {} wheels \; || true
	[ -d dist ] && find dist -iname '*.tar.gz' -exec mv {} sdist \; || true

dist-build:
	pipenv run python -m build

dist-upload:
	pipenv run twine check dist/*
	pipenv run twine upload dist/* -r pypi --skip-existing
	pipenv run twine upload dist/* -r testpypi --skip-existing

git-tag:
	git tag --sign "v$(VERSION)"
	git push --tags

pipenv:
	pipenv install --skip-lock --dev

vendor:
	pipenv run pcapkit-vendor

# Sample captures under examples/captures/ are not tracked (see .gitignore);
# regenerate the ones the runtime, regression and integration tests read.
samples:
	pipenv run python examples/generators/make_samples.py

# Mirrors the selection run by .github/workflows/unit-tests.yml, i.e. the tests
# that need no sample captures beyond the committed ones.
test:
	pipenv run python -m pytest -q --ignore=tests/integration --ignore-glob='*_runtime.py' --ignore-glob='*_regression.py'

# Everything, including the fixture-dependent runtime/regression/integration tests.
test-all: samples
	pipenv run python -m pytest -q

coverage: samples
	pipenv run coverage run -m pytest -q
	pipenv run coverage report

# The engine speed table in docs/source/index.rst -- every supported Python
# version, one image each, measured in containers so the host does not affect the
# result. Needs docker, and nothing else: deliberately not run through pipenv,
# since the whole point is that the measuring environments are the pinned ones
# inside the images rather than whatever is installed here.
#
# Expect around two hours at the defaults: five interpreters, seven environments,
# and almost all of the measuring time is pyshark, which spawns a tshark process
# per extraction. Cut it with --engines, --pythons, or --quick.
bench:
	examples/benchmark/run.sh

# A smoke check that the harness works end to end, not a measurement -- two
# interpreters and the two cheapest engines, which is enough to exercise both
# virtualenvs, the matrix loop and both emitted tables. The full matrix at --quick
# would still build five images, and building is most of a quick run's cost.
bench-quick:
	examples/benchmark/run.sh --quick --pythons 3.11,3.12 --engines default,dpkt

# The harness's own tests: ratio arithmetic, environment stitching, the per-version
# grid, and that the emitted reStructuredText parses under plain docutils. No
# docker needed.
bench-test:
	pipenv run python -m pytest -q examples/benchmark/test_harness.py

docs:
	PCAPKIT_SPHINX=1 pipenv run $(MAKE) -C docs html

docs-clean:
	PCAPKIT_SPHINX=1 pipenv run $(MAKE) -C docs clean

docs-autobuild:
	PCAPKIT_SPHINX=1 SPHINXOPTS="--watch ../pcapkit" pipenv run $(MAKE) -C docs livehtml

isort:
	pipenv run isort -l100 -ppcapkit --skip-glob '**/__init__.py' pcapkit $(wildcard temp/sort.py)
	pipenv run isort -l100 -ppcapkit pcapkit/{const,vendor}/*/*.py
	pipenv run isort -l100 -ppcapkit util/*.py examples/generators/*.py

# The command prefix that puts the lint tools on PATH. Locally that is pipenv, as
# everywhere else in this file. The lint workflow installs the tools into the
# job's own interpreter instead and overrides this to empty (`make pylint RUN=`),
# which is the whole point of the variable: CI runs these recipes rather than
# restating their flags, so there is exactly one definition of each tool's flag
# set and "clean locally, red in CI" cannot start from the two drifting apart.
RUN ?= pipenv run

# Flag sets are variables rather than literals for the same reason -- `vermin`
# needs two recipes (see below) and would otherwise carry two copies of its
# flags. Note the `pcapkit` before the flags as well as after: that is how this
# recipe has always read, and vermin de-duplicates the paths (it reports 496
# files analyzed either way), so it is preserved verbatim rather than tidied.
VERMIN_FLAGS = --backport argparse --backport enum --backport importlib --backport ipaddress --backport typing --backport typing_extensions --no-parse-comments --eval-annotations -vv
PYLINT_FLAGS = --load-plugins=pylint.extensions.check_elif,pylint.extensions.docstyle,pylint.extensions.emptystring,pylint.extensions.overlapping_exceptions --disable=all --enable=F,E,W,R,basic,classes,format,imports,refactoring,else_if_used,docstyle,compare-to-empty-string,overlapping-except --disable=blacklisted-name,invalid-name,missing-class-docstring,missing-function-docstring,missing-module-docstring,design,too-many-lines,eq-without-hash,old-division,no-absolute-import,input-builtin,too-many-nested-blocks,broad-except,singleton-comparison,ungrouped-imports --max-line-length=120 --init-import=yes
MYPY_FLAGS = --follow-imports=silent --ignore-missing-imports --show-column-numbers --show-error-codes
BANDIT_FLAGS = -r

vermin:
	mkdir -p temp
	$(RUN) vermin pcapkit $(VERMIN_FLAGS) pcapkit > temp/vermin.txt
	command -v code >/dev/null && code temp/vermin.txt || cat temp/vermin.txt

# What CI runs. The `vermin` target above redirects into temp/ and then hands the
# file to an editor, so its exit status is the editor's (or `cat`'s) and a run
# that found violations still succeeds -- fine at a desk, useless as a check.
# This one writes to stdout and lets vermin's failure propagate, which is what
# `targets = 3.6` in vermin.ini is for: vermin exits non-zero when the target is
# not met, and the code's real floor is 3.11.
vermin-ci:
	$(RUN) vermin pcapkit $(VERMIN_FLAGS) pcapkit

pylint:
	$(RUN) pylint $(PYLINT_FLAGS) pcapkit

mypy:
	$(RUN) mypy $(MYPY_FLAGS) pcapkit

bandit:
	$(RUN) bandit $(BANDIT_FLAGS) pcapkit

profile:
	$(MAKE) -C test profile

mypy-types:
	pipenv run mypy --install-types
