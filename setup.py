# -*- coding: utf-8 -*-

import subprocess  # nosec
import sys

# version string
__version__ = '0.15.5'

# README
with open('README.md', encoding='utf-8') as file:
    long_description = file.read()

# setup attributes
attrs = dict(
    name='pypcapkit',
    version=__version__,
    description='Python multi-engine PCAP analyse kit.',
    long_description=long_description,
    author='Jarry Shaw',
    author_email='jarryshaw@icloud.com',
    maintainer='Jarry Shaw',
    maintainer_email='jarryshaw@icloud.com',
    url='https://github.com/JarryShaw/PyPCAPKit',
    download_url='https://github.com/JarryShaw/PyPCAPKit/archive/v%s.tar.gz' % __version__,
    # py_modules
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
        'pcapkit.const.ospf',
        'pcapkit.const.reg',
        'pcapkit.const.tcp',
        'pcapkit.const.vlan',
        'pcapkit.corekit',
        'pcapkit.dumpkit',
        'pcapkit.foundation',
        'pcapkit.interface',
        'pcapkit.protocols',
        'pcapkit.protocols.pcap',
        'pcapkit.protocols.application',
        'pcapkit.protocols.internet',
        'pcapkit.protocols.link',
        'pcapkit.protocols.transport',
        'pcapkit.reassembly',
        'pcapkit.toolkit',
        'pcapkit.utilities',
        'pcapkit.vendor',
        'pcapkit.vendor.arp',
        'pcapkit.vendor.ftp',
        'pcapkit.vendor.hip',
        'pcapkit.vendor.http',
        'pcapkit.vendor.ipv4',
        'pcapkit.vendor.ipv6',
        'pcapkit.vendor.ipx',
        'pcapkit.vendor.mh',
        'pcapkit.vendor.ospf',
        'pcapkit.vendor.reg',
        'pcapkit.vendor.tcp',
        'pcapkit.vendor.vlan',
    ],
    # scripts
    # ext_modules
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: MacOS X',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: System :: Networking',
        'Topic :: Utilities',
    ],
    # distclass
    # script_name
    # script_args
    # options
    license='BSD 3-Clause License',
    keywords=[
        'computer-networking',
        'pcap-analyser',
        'pcap-parser',
    ],
    platforms=[
        'any'
    ],
    # cmdclass
    # data_files
    # package_dir
    # obsoletes
    # provides
    # requires
    # command_packages
    # command_options
    package_data={
        '': [
            'LICENSE',
            'README.md',
        ],
    },
    # include_package_data
    # libraries
    # headers
    # ext_package
    # include_dirs
    # password
    # fullname
    # long_description_content_type
    # python_requires
    # zip_safe
    install_requires=[
        'dictdumper~=0.8.0',        # for formatted output
        'chardet',                  # for bytes decode
        'aenum',                    # for const types
        'tbtrim>=0.2.1',            # for refined exceptions
        # version compatibility
        'f2format; python_version < "3.6"',
        'pathlib2>=2.3.2; python_version == "3.4"',
    ],
    entry_points={
        'console_scripts': [
            'pcapkit-cli = pcapkit.__main__:main',
            'pcapkit-vendor = pcapkit.vendor.__main__:main',
        ]
    },
    extras_require={
        'all': [
            'emoji',
            'dpkt', 'scapy', 'pyshark',
            'requests[socks]', 'beautifulsoup4[html5lib]',
        ],
        # for CLI display
        'cli': ['emoji'],
        # for normal users
        'DPKT': ['dpkt'],
        'Scapy': ['scapy'],
        'PyShark': ['pyshark'],
        # for developers
        'vendor': ['requests[socks]', 'beautifulsoup4[html5lib]'],
    },
    setup_requires=[
        'f2format; python_version < "3.6"',
        'pathlib2>=2.3.2; python_version == "3.4"',
    ]
)

try:
    from setuptools import setup
    from setuptools.command.build_py import build_py

    version_info = sys.version_info[:2]

    attrs.update(dict(
        include_package_data=True,  # type: ignore
        # libraries
        # headers
        # ext_package
        # include_dirs
        # password
        # fullname
        long_description_content_type='text/markdown',
        python_requires='>=3.4',
        zip_safe=True,  # type: ignore
    ))
except ImportError:
    from distutils.core import setup
    from distutils.command.build_py import build_py


class build(build_py):
    """Add on-build backport code conversion."""

    def run(self):
        if version_info < (3, 6):
            try:
                subprocess.check_call(  # nosec
                    [sys.executable, '-m', 'f2format', '--no-archive', 'pcapkit']
                )
            except subprocess.CalledProcessError as error:
                print('Failed to perform assignment expression backport compiling.'
                      'Please consider manually install `f2format` and try again.', file=sys.stderr)
                sys.exit(error.returncode)
        build_py.run(self)


# set-up script for pip distribution
setup(cmdclass={
    'build_py': build,
}, **attrs)
