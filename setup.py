# coding: utf-8

import setuptools


setuptools.setup(
    name="stbt_rig",
    version="2.0.0",
    author="Stb-tester.com Ltd.",
    author_email="support@stb-tester.com",
    description="Library for interacting with the Stb-tester Portal's REST API",
    url="https://github.com/stb-tester/stbt-rig",
    py_modules=["stbt_rig"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Testing",
    ],
    # I have only tested Python 2.7 & 3.6
    python_requires=">=2.7",
    install_requires=[
        "keyring",
        "requests",
    ],
)
