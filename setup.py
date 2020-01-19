from setuptools import setup, find_packages
from os import path

from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(

    name='tlsprofiler',
    version='1.0',
    description="Library to compare a server's TLS configuration to the Mozilla TLS profiles (old, intermediate, modern).",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/danielfett/tlsprofiler',
    author='Daniel Fett',
    author_email='python@danielfett.de',
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.6',
    install_requires=[
        'requests',
        'sslyze @ git+https://github.com/fabian-hk/sslyze.git@tls_profiler#egg=sslyze',
    ],
)
