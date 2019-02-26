# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# version string
__version__ = '0.13.3'

# README
with open('README.md', encoding='utf-8') as file:
    long_description = file.read()

# set-up script for pip distribution
setup(
    name='pypcapkit',
    version=__version__,
    author='Jarry Shaw',
    author_email='jarryshaw@icloud.com',
    url='https://github.com/JarryShaw/pypcapkit',
    license='Mozilla Public License 2.0 (MPL 2.0)',
    keywords='computer-networking pcap-analyser pcap-parser',
    description='Python multi-engine PCAP analyse kit.',
    long_description=long_description,
    # long_description=pkg_resources.resource_string(__name__, 'README.md').decode(),
    long_description_content_type='text/markdown',
    python_requires='>=3.4',
    include_package_data=True,
    zip_safe=True,
    install_requires=[
        'dictdumper',       # for formatted output
        'chardet',          # for bytes decode
        'aenum',            # for const types
        'emoji',            # for CLI display
        'tbtrim>=0.2.0',    # for refined exceptions
    ],
    extras_require={
        'all': ['dpkt', 'scapy', 'pyshark'],
        'DPKT': ['dpkt'],
        'Scapy': ['scapy'],
        'PyShark': ['pyshark'],
        ':python_version == "3.4"': ['pathlib2>=2.3.2'],
    },
    # py_modules = ['pcapkit'],
    entry_points={
        'console_scripts': [
            'pcapkit = pcapkit.__main__:main',
        ]
    },
    # packages=setuptools.find_namespace_packages(
    #     include=['pcapkit', 'pcapkit.*'],
    #     exclude=['pcapkit.vendor.*', 'pcapkit.vendor', '*.NotImplemented'],
    # ),
    packages=[
        'pcapkit',
        'pcapkit.const',
        'pcapkit.const.arp',
        'pcapkit.const.ftp',
        'pcapkit.const.hip',
        'pcapkit.const.http',
        'pcapkit.const.ipv4',
        'pcapkit.const.ipv6',
        'pcapkit.const.ipx',
        'pcapkit.const.mh',
        'pcapkit.const.misc',
        'pcapkit.const.ospf',
        'pcapkit.const.tcp',
        'pcapkit.const.vlan',
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
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
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
