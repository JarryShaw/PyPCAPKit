#!/usr/bin/python3
# -*- coding: utf-8 -*-


import setuptools


# README
with open('./README.md', 'r') as file:
    long_desc = file.read()


# version string
__version__ = '0.7.5.post1'


# set-up script for pip distribution
setuptools.setup(
    name = 'jspcap',
    version = __version__,
    author = 'Jarry Shaw',
    author_email = 'jarryshaw@icloud.com',
    url = 'https://github.com/JarryShaw/jspcap',
    license = 'GNU General Public License v3 (GPLv3)',
    keywords = 'computer-networking pcap-analyzer pcap-parser',
    description = 'A stream PCAP file extractor.',
    long_description = long_desc,
    long_description_content_type='text/markdown',
    python_requires = '>=3.6',
    install_requires = ['jsformat', 'chardet'],
    py_modules = ['jspcap'],
    entry_points = {
        'console_scripts': [
            'jspcapy = jspcap.__main__:main',
        ]
    },
    packages = [
        'jspcap',
        'jspcap.protocols',
        'jspcap.protocols.application',
        'jspcap.protocols.internet',
        'jspcap.protocols.link',
        'jspcap.protocols.transport',
        'jspcap.reassembly',
    ],
    package_data = {
        '': [
            'LICENSE.txt',
            'README.md',
            'README.rst',
        ],
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: MacOS X',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: System :: Networking',
        'Topic :: Utilities',
    ]
)
