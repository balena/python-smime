#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

with open(path.join(here, 'CHANGES.rst'), encoding='utf-8') as f:
    long_description += '\n\n' + f.read()

test_requires = ['pytest','pytest-flake8', 'pytest-cov']
setup(
    name='smime-py23',
    version=__import__('smime').__version__,
    description='Python S/MIME Toolkit',
    long_description=long_description,
    url='https://github.com/balena/python-smime',
    author='G. B. Versiani',
    author_email='guibv@yahoo.com',
    license='Apache License (2.0)',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries',
        'Topic :: Communications :: Email',
        'Topic :: Security :: Cryptography',
    ],
    keywords='smime cryptography email',
    packages=find_packages(exclude=['smime/test', 'smime/crypto/testdata',
        'smime/crypto/tools', '*_test.py']),
    platforms=["all"],
    install_requires=['cryptography', 'asn1crypto', 'six'],
    setup_requires=['pytest-runner'],
    tests_require=test_requires,
    test_suite='tests',
    extras_require={
        'test': test_requires
    },
    zip_safe=False,
)
