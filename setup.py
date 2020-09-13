# -*- coding: UTF-8 -*-
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="napalm-ros",
    version="1.0.0",
    packages=find_packages(),
    author="Łukasz Kostka",
    author_email="lukasz.kostka@netng.pl",
    description="Network Automation and Programmability Abstraction Layer driver for Mikrotik ROS",
    long_description_content_type="text/markdown",
    long_description=long_description,
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation-community/napalm-ros",
    include_package_data=True,
    install_requires=(
        'napalm==3.*',
        'librouteros==3.*',
    ),
)
