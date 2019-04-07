#!/usr/bin/python
# -*- coding: utf-8 -*-

import io
import os
import re

from setuptools import setup

name = 'solidwebpush'
description = """
This package lets your server send Web Push Notifications to your clients.
NOTE: No particular web framework are required (e.g. Django, Flask, Pyramid,
etc.), since it was originally designed to run on a Raspberry Pi with no web
server installed (only a bare Python program listening on a port for HTTP
requests).
"""

CWD = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(CWD, '%s/__init__.py' % name), encoding='utf8') as __init__py:
    __init__src = __init__py.read()

    RE = r"%s\s*=\s*['\"]([^'\"]+)['\"]"

    package = {
        '__version__': re.search(RE % '__version__', __init__src).group(1),
        '__license__': re.search(RE % '__license__', __init__src).group(1)
    }

with io.open(os.path.join(CWD, 'README.md'), encoding='utf8') as README:
    long_description = README.read()

setup(
    name=name,
    version=package['__version__'],
    description=description,
    author='Sergio Burdisso',
    author_email='sergio.burdisso@gmail.com',
    url='https://github.com/sergioburdisso/%s' % name,
    packages=[name],
    long_description=long_description,
    license=package['__license__'],
    download_url='https://github.com/sergioburdisso/%s/tarball/v%s'
                 % (name, package['__version__']),
    keywords=[
        'web push notifications', 'notifications',
        'web notifications', 'push', "webpush",
        'raspberry pi'
    ],
    classifiers=[
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: Implementation :: PyPy",
        'Programming Language :: Python',
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ],
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'future',
        'py-vapid==0.7.1',
        'http_ece==0.7.0',
        'pyelliptic==1.5.7',
        'requests==2.20.0'
    ]
)
