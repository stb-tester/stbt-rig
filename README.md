# stbt_rig.py

Command-line tool for interacting with the Stb-tester Portal's [REST API].

[REST API]: https://stb-tester.com/manual/rest-api-v2

<a href="https://travis-ci.org/stb-tester/stbt-rig">
  <img src="https://travis-ci.org/stb-tester/stbt-rig.png?branch=master">
</a>

## Interactive use

stbt-rig makes it easier to do test-script development by testing your local
code-changes on an Stb-tester node without having to make git commits or
clicking in the web portal. It is a command-line application that runs on your
development PC.

For example run this on your PC from your test-pack directory:

    ./stbt_rig.py --node-id=stb-tester-e5a091e40de1 run tests/file.py::test_name

This will:

1. Commit your changes to a temporary git branch and push them to github;
2. Run the test via the Stb-tester Portal's REST API;
3. Grab the result and print the output locally.

This saves you a multi-step manual process, and it removes the need to make
lots of tiny git commits while iterating on test-scripts.

stbt-rig will run on Windows, Mac OS or Linux. It depends on Python, git,
python-requests, and optionally python-keyring for storing your access token.
See "Installation" below for information on installing these dependencies.

## Jenkins integration

The above command will detect if it is running inside a Jenkins job. If so, it
will automatically read authentication credentials from the Jenkins Credentials
Binding plugin, and it will record test results in the XML format expected by
the Jenkins JUnit plugin.

For instructions on setting up your Jenkins job see
https://stb-tester.com/manual/continuous-integration

## Installation

Copy `stbt_rig.py` into your test-pack, then install the necessary dependencies:

#### Windows

1. Install Python
2. Install git
3. Install stbt-rig dependencies with pip:

        python -m pip install requests keyring

#### MacOS X

1. Install stbt-rig dependencies with Python setuptools:

        easy_install requests keyring

#### Linux Debian/Ubuntu

1. Install stbt-rig dependencies with apt:

        sudo apt-get install python-requests python-keyring

## Configuration

Configuration:

1. Specify portal to use in `.stbt.conf`:

        [test-pack]
        portal_url = https://COMPANYNAME.stb-tester.com

2. Generate access token. See [Authentication] in the Stb-tester REST API
   documentation. You will need to enter this the first time you run the
   program.

[Authentication]: https://stb-tester.com/manual/rest-api-v2#authentication

## Design

#### Command-line Client Goals

* Convenience for test-script development
* Simple and robust CI system integration

#### Python API Goals

Note: The Python API exposed by this module isn't stable; for now the only
public API is the command-line interface.

* Portability - The library and command line client are intended to be portable
  to any Python version
* Ease of deployment - it should be possible to `pip install` this or to just
  copy-and-paste it into other repos for reuse
    * All the code should be in a single file (stbt_rig.py).
    * Liberal MIT licence to remove any barriers to deployment.
    * It should have as few required dependencies as possible.  Currently it
      only requires `requests` and a `git` installation, with an
      optional dependency on `keyring` for persisting the access token.
* Completeness - The whole of the stb-tester HTTP REST API should be exposed
* Transparency - The Python API is intended to roughly have a 1 to 1
  correspondence with the REST API
* Robustness - The library should help with mitigate common network problems
    * Should include retries for HTTP failures
