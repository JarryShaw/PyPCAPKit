@ECHO OFF
SETLOCAL EnableDelayedExpansion

REM build.sh's two calls, for Windows (#2060). cmd does not expand the glob in
REM build.sh's `pip install conda/wheels/*`, so collect what Setup Conda
REM Distribution downloaded and install it in one call, letting pip resolve the
REM files together. In a batch file a FOR variable takes two percent signs; the
REM loop this replaces had one, a syntax error, and likely why no win-64 package
REM was ever built.
SET WHEELS=
FOR %%W IN (conda\wheels\*) DO SET WHEELS=!WHEELS! "%%W"
IF NOT DEFINED WHEELS (
    ECHO bld.bat: conda\wheels holds nothing to install 1>&2
    EXIT 1
)

"%PYTHON%" -m pip install !WHEELS! --target pcapkit\_extern -vv
IF ERRORLEVEL 1 EXIT 1

"%PYTHON%" -m pip install . -vv
IF ERRORLEVEL 1 EXIT 1
