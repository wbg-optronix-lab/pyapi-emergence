#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


setup(
    name='pyapi-emergence',
    url='',
    author='Neil Newman, Jonathan Marini',
    author_email='nnewman2@albany.edu, jmarini@ieee.org',
    packages=['emergence'],
    install_requires=['requests'],
)
