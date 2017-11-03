# stbt_rig.py

Command-line tool for interacting with the Stb-tester Portal's [REST API].

[REST API]: https://stb-tester.com/manual/rest-api-v2

<a href="https://travis-ci.org/stb-tester/stbt-rig">
  <img src="https://travis-ci.org/stb-tester/stbt-rig.png?branch=master">
</a>

## Interactive use

`./stbt_rig.py --node-id=stb-tester-e5a091e40de1 run tests/file.py::test_name`
will submit your local test-pack directory to run on an Stb-tester node. This
saves you having to make lots of temporary git commits to debug your test
scripts.

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

#### Command-line Client Goals

* Convenience for test-script development
* Simple and robust CI system integration

## TODO

* [ ] Grab thumbnail - `/api/v2/nodes/(node_id)/thumbnail.jpg`
* [ ] List test cases - `/api/v2/test_pack/<test_pack_sha>/test_case_names`
* Run tests - `/api/v2/run_tests`
    * [x] Single test-case
    * [ ] Multiple test cases
    * [ ] Specify remote control
    * [ ] Specify category
    * [x] Run tests in soak
    * [ ] Shuffle
    * [ ] Tags
    * [x] Wait for completion
    * [x] Set exit status
* [ ] List results `/api/v2/results`
    * [x] Get result of job we started
    * [ ] Get result of other jobs/other search filters
    * [ ] Save results in xUnit format
* Get detailed information about a test run `/api/v2/results/(result_id)/`
    * [ ] Download artifacts
    * [ ] Artifact cache based on git sha headers?
- [ ] Ensure that every REST API endpoint is covered
- [ ] Add and publish API documentation
- [ ] Decide on the best place to store REST API tokens
- [ ] Add `requirements.txt` and publish on PyPI
- [ ] Don't let `requests` leak though the API
- [ ] Raise appropriate exceptions for REST API errors
- [ ] Retry logic
- [ ] API stability
