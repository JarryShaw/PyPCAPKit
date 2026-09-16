# syntax=docker/dockerfile:1
#
# The benchmark image: one interpreter, one or two virtualenvs, every engine that
# the interpreter can hold.
#
# One image per Python version, selected by `PYTHON_IMAGE`. The versions and their
# digests live in `python-images.txt`, which is the matrix `run.sh` reads; the
# reasoning behind pinning by digest rather than by tag is there too, next to the
# digests it applies to, rather than duplicated here. The default below is 3.11
# because it is the *last* interpreter on which every engine can run -- 3.10 is the
# only other one -- which makes it the right thing to get from a bare `docker build`
# with no `--build-arg`. It has to stay equal to the 3.11 row of the pins file, and a
# self-test asserts that it does: one digest written in two places is one that drifts.
#
# Two virtualenvs where two are needed, one where they are not. `pypcap` and
# `pcap-ct` both install a top-level `pcap` module, and with both present
# `import pcap` resolves to `pcap-ct` -- upstream's extension module is shadowed and
# unreachable -- so no single environment can hold every engine. On 3.12 and newer,
# though, `pypcap` cannot be installed at all, and a second virtualenv there would
# be minutes of compiling to produce nothing. `WITH_PYPCAP=0` skips it and records
# why, so the report can say the engine is unsupported on this interpreter rather
# than that it failed here.
ARG PYTHON_IMAGE=python:3.11-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84
FROM ${PYTHON_IMAGE}

# Redeclared: an ARG consumed by `FROM` is out of scope for the build stage, so
# without this the reference the image was built from could not be recorded in it.
ARG PYTHON_IMAGE

# Whether to build the `pypcap` virtualenv. See the header, and `python-images.txt`
# for which interpreters can hold it.
ARG WITH_PYPCAP=1

# Recorded in the report so a table can be traced back to the code that produced
# it. `pcapkit` is installed from the working tree, not from PyPI, so its git
# revision is the only version number that means anything.
ARG PCAPKIT_REVISION=unknown

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PCAPKIT_REVISION=${PCAPKIT_REVISION} \
    PCAPKIT_BASE_IMAGE=${PYTHON_IMAGE} \
    VENV_PYPCAP=/opt/venv-pypcap \
    VENV_PCAP_CT=/opt/venv-pcap_ct

# Three things beyond the base image, each needed by exactly one engine:
#
#   build-essential + libpcap-dev -- `pypcap` is an sdist with a C extension, and
#       its setup.py hard-fails unless it can find both `pcap.h` and an
#       unversioned `libpcap.so`. The runtime-only libpcap0.8 package is not
#       enough for it, though it would be enough for `pcap-ct`, which resolves the
#       versioned soname through ctypes instead.
#   tshark -- `pyshark` does no parsing of its own; it shells out to Wireshark's
#       command-line tool once per extraction, so without the binary the Python
#       package is inert. Preseeded to *not* install setuid dumpcap: this image
#       only ever reads a file from disk, and live capture privileges would be a
#       liability for nothing.
#
# Installed unconditionally, including on the interpreters that get no `pypcap`
# virtualenv and therefore never invoke a compiler. That is deliberate: the
# per-version table's columns are compared with each other in absolute
# milliseconds, so every image has to differ from the others in the interpreter and
# nothing else. Installing a smaller apt set on 3.12+ would save a little build
# time and buy a difference between columns that could not be attributed.
#
# Debian package versions are deliberately not pinned -- the archive drops old
# versions, so a pinned apt line breaks rather than reproduces. The resolved
# `tshark` and libpcap versions are recorded in the report instead, which is the
# honest form of reproducibility here.
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections; \
    apt-get update; \
    apt-get install --yes --no-install-recommends \
        build-essential \
        libpcap-dev \
        tshark; \
    rm -rf /var/lib/apt/lists/*; \
    tshark --version | head -n 1

WORKDIR /src

# Copied file by file rather than as a whole tree, so that editing the harness
# does not invalidate the layer that compiles `pypcap`, and so that nothing from
# the host's checkout (a virtualenv, build output, captures generated locally)
# can leak into the image and change what is measured.
COPY examples/benchmark/requirements-common.txt \
     examples/benchmark/requirements-pypcap.txt \
     examples/benchmark/requirements-pcap_ct.txt \
     ./examples/benchmark/

# The shared engines first, into every environment this image will hold. Everything
# here is a wheel on every architecture and every interpreter in the matrix --
# checked on 3.10, 3.12, 3.13 and 3.14 as well as 3.11 -- so a failure is a real
# failure and stays fatal.
#
# `$VENV_PYPCAP` is created only where it can be filled. Nothing downstream is told
# which of the two happened: each step asks the filesystem instead, so the image
# cannot end up claiming an environment it does not have.
RUN set -eux; \
    mkdir -p /opt/locks /opt/install-failures /opt/not-attempted; \
    venvs="$VENV_PCAP_CT"; \
    if [ "$WITH_PYPCAP" = 1 ]; then venvs="$venvs $VENV_PYPCAP"; fi; \
    for venv in $venvs; do \
        python -m venv "$venv"; \
        "$venv/bin/pip" install --quiet --upgrade pip setuptools wheel; \
        "$venv/bin/pip" install --quiet --requirement examples/benchmark/requirements-common.txt; \
    done

# `pcap-ct` and `libpcap` are py3-none-any wheels with nothing to compile, so this
# too is fatal on failure.
RUN set -eux; \
    "$VENV_PCAP_CT/bin/pip" install --quiet --requirement examples/benchmark/requirements-pcap_ct.txt; \
    "$VENV_PCAP_CT/bin/pip" freeze > /opt/locks/pcap_ct.txt

# `pypcap` is the only package in the set that compiles, which makes it the only
# one whose install can fail for reasons outside these pins -- a toolchain change,
# a libpcap header that moved, an architecture whose library path its setup.py does
# not name. So its failure is recorded rather than fatal.
#
# The alternative is worse: a fatal failure here means `run.sh` produces no table at
# all, and the six engines that do work go unreported because the seventh did not
# build. Recording it keeps the promise that a missing engine is an explained row
# rather than an absent one -- benchmark.py reads this file and reports the build
# error as the reason `pypcap` was not measured.
#
# On an interpreter with no `pypcap` virtualenv the failure is not a failure but a
# ceiling, and the two must not be reported as the same thing: a note in
# `/opt/not-attempted/` says the engine cannot be installed on this interpreter at
# all, which is a fact about `pypcap` and 3.12+ rather than about this build.
RUN set -eux; \
    if [ ! -d "$VENV_PYPCAP" ]; then \
        { echo 'pypcap is not installable on this interpreter, so it was not built into this'; \
          echo 'image: pypcap 1.3.0 ships a pcap.c pre-generated by Cython 0.29.32, which does'; \
          echo 'not compile against the Python 3.12+ C API. The engine is unsupported here'; \
          echo 'rather than broken here.'; } > /opt/not-attempted/pypcap.txt; \
        cat /opt/not-attempted/pypcap.txt >&2; \
    elif "$VENV_PYPCAP/bin/pip" install --requirement examples/benchmark/requirements-pypcap.txt \
            > /tmp/pypcap-install.log 2>&1; then \
        "$VENV_PYPCAP/bin/python" -c 'import pcap; print("pypcap", pcap.__version__)'; \
        "$VENV_PYPCAP/bin/pip" freeze > /opt/locks/pypcap.txt; \
    else \
        echo 'WARNING: pypcap failed to install; it will be reported as not measured.' >&2; \
        { echo 'pypcap failed to build in this image, so it could not be measured.'; \
          echo 'The tail of the pip output was:'; \
          tail -n 12 /tmp/pypcap-install.log; } > /opt/install-failures/pypcap.txt; \
        cat /opt/install-failures/pypcap.txt >&2; \
        "$VENV_PYPCAP/bin/pip" freeze > /opt/locks/pypcap.txt; \
    fi; \
    rm -f /tmp/pypcap-install.log

# `pcapkit` last, because it is the thing under test and changes on every commit.
COPY pyproject.toml setup.py MANIFEST.in README.rst ./
COPY pcapkit ./pcapkit

# --no-deps so the pinned requirements above stay authoritative: `pcapkit`
# declares unpinned ranges, and letting them resolve here would quietly move the
# baseline the whole report is normalised against.
RUN set -eux; \
    for venv in /opt/venv-*; do \
        "$venv/bin/pip" install --quiet --no-deps .; \
        "$venv/bin/python" -c 'import pcapkit; print(pcapkit.__version__)'; \
    done

# What this image can measure, as three whitespace-separated fields per line: the
# environment label the report will use, the virtualenv to run it in, and the lock
# file recording what that virtualenv resolved to.
#
# Written here rather than assembled by `entrypoint.sh` from build arguments,
# because the label has to name the interpreter that actually ran. Asking the
# interpreter for its own version makes that unfalsifiable; deriving it from a
# `--build-arg` would let a mislabelled build put 3.11 numbers in the 3.12 column,
# which is a silent error of exactly the kind the rest of this harness refuses to
# leave open. The `pypcap` line is likewise conditioned on the virtualenv existing
# rather than on `WITH_PYPCAP`.
RUN set -eux; \
    series="$(python -c 'import sys; print("%d.%d" % sys.version_info[:2])')"; \
    { printf '%s-pcap_ct %s /opt/locks/pcap_ct.txt\n' "$series" "$VENV_PCAP_CT"; \
      if [ -d "$VENV_PYPCAP" ]; then \
          printf '%s-pypcap %s /opt/locks/pypcap.txt\n' "$series" "$VENV_PYPCAP"; \
      fi; } > /opt/environments; \
    cat /opt/environments

COPY examples/captures/in.pcap ./examples/captures/in.pcap
COPY examples/benchmark/benchmark.py \
     examples/benchmark/report.py \
     examples/benchmark/entrypoint.sh \
     ./examples/benchmark/

# Run as an ordinary user. `tshark` prints a "Running as user root ... could be
# dangerous" banner on every start, and `pyshark` starts it once per extraction --
# a thousand times per repeat -- so this is not only hygiene, it keeps that
# warning out of the measured path. A real HOME is needed because `pyshark`
# resolves its config through appdirs.
#
# `/in` is where the reporting pass receives the JSON documents from the other
# versions' containers, since one interpreter has to report on a matrix none of them
# measured alone. It is a plain directory rather than a second volume: `docker cp`
# into a stopped container is what fills it, and keeping inputs and outputs in
# separate directories means the reporting pass cannot mistake a file it was handed
# for one it produced.
RUN set -eux; \
    useradd --create-home --shell /bin/bash bench; \
    mkdir -p /out /in; \
    chown bench:bench /out /in
USER bench
ENV HOME=/home/bench

VOLUME ["/out"]
ENTRYPOINT ["/src/examples/benchmark/entrypoint.sh"]
