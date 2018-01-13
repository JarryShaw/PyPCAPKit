import sys
import platform
from setuptools import setup


system = platform.system()

if system == 'Windows':
	# build on windows
	from cx_Freeze import setup, Executable

	build_exe_options = {'packages': ['queue'], 'excludes': [], 'include_files':['bitmaps\\']}

	executables = [Executable(script='main.py',
	base='win32gui',
	targetName="SniffingCats.exe",
	icon="search_cat.ico",
	)]

	setup(  name = 'SniffingCats',
			version = '0.1',
			description = 'Traffic Sniffer',
			options = {'build_exe': build_exe_options},
			executables = executables)

elif system == 'Darwin':
	from setuptools import setup

	APP = ['main.py']
	APP_NAME = 'SniffingCats'
	DATA_FILES = ['bitmaps']
	OPTIONS = {
        'argv_emulation': True,
        'iconfile': 'search_cat.ico',
        'plist': {
            'CFBundleName': APP_NAME,
            'CFBundleDisplayName': APP_NAME,
            'CFBundleGetInfoString': "Network sniffer",
            'CFBundleIdentifier': "com.github",
            'CFBundleVersion': "0.1.0",
            'CFBundleShortVersionString': "0.1.0",
            'NSHumanReadableCopyright': u"Copyright © 2017, SniffingCats, All Rights Reserved"
        }
    }

	setup(
		app=APP,
		data_files=DATA_FILES,
		options={'py2app': OPTIONS},
		setup_requires=['py2app'],
	)
