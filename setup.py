# coding: utf-8

import setuptools


long_description = """\
# stbt_rig

Command-line tool & library for interacting with the Stb-tester Portal's [REST
API].

* Copyright © 2017-2022 Stb-tester.com Ltd.
* License: MIT License (see [LICENSE])

For more details see [stbt_rig CLI] and [IDE Integration] in the Stb-tester
manual.

[IDE Integration]: https://stb-tester.com/manual/ide
[LICENSE]: https://github.com/stb-tester/stbt-rig/blob/main/LICENSE
[REST API]: https://stb-tester.com/manual/rest-api-v2
[stbt_rig CLI]: https://stb-tester.com/manual/stbt-rig
"""

setuptools.setup(
    name="stbt_rig",
    version="33.0.0",
    author="Stb-tester.com Ltd.",
    author_email="support@stb-tester.com",
    description="Library for interacting with the Stb-tester Portal's REST API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/stb-tester/stbt-rig",
    py_modules=["stbt_rig"],
    entry_points={
        "console_scripts": [
            "stbt_rig=stbt_rig:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=2.7",
    install_requires=[
        "keyring",
        "requests",
        "tzlocal; python_version>='3'",
    ],
)
