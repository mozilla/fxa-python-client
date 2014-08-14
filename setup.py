#!/usr/bin/env python

from setuptools import setup

setup(
    name = "fxa-python-client",
    version = "1.2.0",
    description = "python sample code to access Firefox Account (FxA) APIs",
    author = "Brian Warner",
    author_email = "warner-fxa-python-client@lothar.com",
    maintainer = "Ryan Kelly",
    maintainer_email = "rfkelly@mozilla.com",
    url = "https://github.com/mozilla/fxa-python-client",
    install_requires = ["cryptography",
                        "requests",
                        "PyBrowserID",
                        "PyHawk",
                        "scrypt",
                        "six",
                        ],
    packages = ["fxa_client"],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        ],
    entry_points = {"console_scripts":
                    ["fxa-client = fxa_client.fxa_client:main",
                     "fxa-vectors = fxa_client.fxa_vectors:main"
                     ]},
)
