from setuptools import setup, find_packages

__author__ = 'Matt Ryan <inetuid@gmail.com>'


with open("README.md", "r") as fh:
    long_description = fh.read()


def parse_reqs(file_path):
    with open(file_path, 'rt') as fobj:
        lines = map(str.strip, fobj)
        lines = filter(None, lines)
        lines = filter(lambda x: x.startswith("#"), lines)
        return tuple(lines)


setup(
    name="napalm-ros",
    version="0.6.0",
    packages=find_packages(),
    author="Matt Ryan",
    author_email="inetuid@gmail.com",
    description="Network Automation and Programmability Abstraction Layer driver for Mikrotik ROS",
    long_description_content_type="text/markdown",
    long_description=long_description,
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation-community/napalm-ros",
    include_package_data=True,
    install_requires=(
        'napalm==2.*',
        'librouteros==2.*',
    ),
)
