#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re

from setuptools import setup

name = 'solidwebpush'
description="""
This package lets you integrate Web Push Notifications in your application's server.
NOTE: No Web framework are required (e.g. Django, Flask, Pyramid, etc.), because
it was originally designed to run on a Raspberry Pi with no web server installed,
only a bare Python program listening on a port for HTTP requests.
"""

with open(os.path.join(name, '__init__.py'), 'rb') as __init__py:
    __init__src = __init__py.read().decode('utf-8')

    RE = r"%s\s*=\s*['\"]([^'\"]+)['\"]"

    package = {
        '__version__' : re.search(RE % '__version__', __init__src).group(1),
        '__license__' : re.search(RE % '__license__', __init__src).group(1)
    }

setup(
    name = name,
    packages = [ name ],
    version = package['__version__'],
    description = description,
    author = 'Sergio Burdisso',
    author_email = 'sergio.burdisso@gmail.com',
    license = package['__license__'],
    url='https://github.com/sergioburdisso/solidwebpush',
    download_url = 'https://github.com/sergioburdisso/solidwebpush/tarball/v1.0',#https://github.com/{username}/{module_name}/tarball/{tag}
    keywords = ['web push notifications', 'notifications', 'web notifications', 'raspberry pi'],
    classifiers = [],
    install_requires = ['ecdsa <1.0', 'python-jose <2.0', 'http_ece', 'pyelliptic <2.0', 'cryptography <1']
)