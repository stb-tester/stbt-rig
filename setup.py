# coding: utf-8

import setuptools


long_description = """\
# stbt_rig

Command-line tool & library for interacting with the Stb-tester Portal's [REST
API].

For more details see [IDE Configuration] in the Stb-tester manual.

[IDE Configuration]: https://stb-tester.com/manual/ide-configuration
[REST API]: https://stb-tester.com/manual/rest-api-v2
"""

setuptools.setup(
    name="stbt_rig",
    version="2.0.1",
    author="Stb-tester.com Ltd.",
    author_email="support@stb-tester.com",
    description="Library for interacting with the Stb-tester Portal's REST API",
    long_description=long_description,
    long_description_content_type="text/markdown",
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
