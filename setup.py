#!/usr/bin/env python

from distutils.core import setup

setup(
    name = "fxa-python-client",
    version = "0",
    description = "python sample code to access Firefox Account (FxA) APIs",
    author = "Brian Warner",
    author_email = "warner-fxa-python-client@lothar.com",
    url = "https://github.com/mozilla/fxa-python-client",
    packages = ["fxa_client"],
    scripts = ["bin/fxa-client"],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        ],
    )
