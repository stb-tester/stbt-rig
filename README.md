# This is a work-in-progress.  The API is not yet stable and will change in future revisions.

# stbt-rig
Python and command-line wrapper to the stb-tester REST API

## Installation

Copy `stbt_rig.py` into your test-pack.

## Setup

Configuration:

1. Specify portal to use in `stbt.conf`:

        [test-pack]
        portal_url = https://example.stb-tester.com

2. Generate auth token.  See [Authentication] in the stb-tester REST API
   documentation.  You will need to enter this the first time you run the
   program.

[Authentication]: https://stb-tester.com/manual/rest-api-v2#authentication

# Usage

## Commandline Example

Run a test:

    $ stbt_rig.py --node-id stb-tester-e5a091e40de1 run tests/example.py::test_example

## Python API Example

Run a test:

    import stbt_rig
    
    portal = stbt_rig.Portal("https://example.stb-tester.com", auth_token="abcdefghijklmnop")
    node = stbt_rig.Node(portal, "stb-tester-e5a091e40de1")

    job = node.run_tests(
        test_pack_revision="master",
        test_cases=["tests/example.py::test_example"],
        await_completion=True)
    if job.list_results()[0].is_ok():
        print "SUCCESS"

# Design

## Python API Goals

* Portability - The library and command line client are intended to be portable
  to any Python version
* Ease of deployment - it should be possible to `pip install` this or to just
  copy-and-paste it into other repos for reuse
    * All the code should appear in a single stbt_rig.py should be a single
      file.
    * It's distributed under the liberal MIT licence to remove any barriers to
      entry
    * It should have as few required dependencies as possible.  Currently it
      only requires `requests`, `enum` and a `git` installation, with an
      optional dependency on `keyring` for persisting the auth token.
* Completeness - The whole of the stb-tester HTTP REST API should be exposed
* Transparency - The Python API is intended to roughly have a 1 to 1
  correspondence with the REST API
* Robustness - The library should help with mitigate common network problems
    * Should include retries for HTTP failures

## Commandline Client Goals

* Convenience for test-script development
* Simple and robust CI system integration

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

# TODO

- [ ] Ensure that every REST API endpoint is covered
- [ ] Add and publish API documentation
- [ ] Decide on the best place to store REST API tokens
- [ ] Add `requirements.txt` and publish on `pip`
- [ ] Don't let `requests` leak though the API
- [ ] Raise appropriate exceptions for REST API errors
- [ ] Retry logic
- [ ] API stability
