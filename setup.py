# -*- coding: utf-8 -*-

import setuptools

# version string
__version__ = '0.12.2'

# README
with open('./README.md', 'r') as file:
    long_desc = file.read()

# set-up script for pip distribution
setuptools.setup(
    name='pypcapkit',
    version=__version__,
    author='Jarry Shaw',
    author_email='jarryshaw@icloud.com',
    url='https://github.com/JarryShaw/pypcapkit',
    license='GNU General Public License v3 (GPLv3)',
    keywords='computer-networking pcap-analyzer pcap-parser',
    description='Python multi-engine PCAP analyse kit.',
    long_description=long_desc,
    long_description_content_type='text/markdown',
    python_requires='>=3.4',
    install_requires=['setuptools', 'dictdumper', 'chardet', 'aenum', 'emoji'],
    extras_require={
        'all': ['dpkt', 'scapy', 'pyshark'],
        'DPKT': ['dpkt'],
        'Scapy': ['scapy'],
        'PyShark': ['pyshark'],
    },
    # py_modules = ['pcapkit'],
    entry_points={
        'console_scripts': [
            'pcapkit = pcapkit.__main__:main',
        ]
    },
    packages=[
        'pcapkit',
        'pcapkit._common',
        'pcapkit.corekit',
        'pcapkit.dumpkit',
        'pcapkit.foundation',
        'pcapkit.interface',
        'pcapkit.ipsuite',
        'pcapkit.ipsuite.pcap',
        'pcapkit.ipsuite.application',
        'pcapkit.ipsuite.internet',
        'pcapkit.ipsuite.link',
        'pcapkit.ipsuite.transport',
        'pcapkit.protocols',
        'pcapkit.protocols.pcap',
        'pcapkit.protocols.application',
        'pcapkit.protocols.internet',
        'pcapkit.protocols.link',
        'pcapkit.protocols.transport',
        'pcapkit.reassembly',
        'pcapkit.toolkit',
        'pcapkit.utilities',
    ],
    package_data={
        '': [
            'LICENSE',
            'README.md',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: MacOS X',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: System :: Networking',
        'Topic :: Utilities',
    ]
)
