#!/usr/bin/env python

from setuptools import setup, find_packages

setup(  name='ds3-standalone-downloader',
        version='0.0.1',
        description='Simple DS3 download script with no external non-pip modules',
        author='Joe Sislow',
        author_email='madopal@uchicago.edu',
        packages=find_packages(),
        install_requires=[
            'requests', 
            'hmac',
            'hashlib',
            'lxml'
        ],
)
