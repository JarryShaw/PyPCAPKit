"%PYTHON%" -m pip install conda\wheels\* --target pcapkit\_extern -vv
"%PYTHON%" -m pip install . -vv
if errorlevel 1 exit 1
