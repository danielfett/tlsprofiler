# TLS Profiler #
The `TLS Profiler` class provided in this library can be used to
compare the configuration of a TLS server to the [Mozilla TLS
configuration
recommendations](https://wiki.mozilla.org/Security/Server_Side_TLS).

The Mozilla TLS recommendations are three profiles (old, intermediate, modern)
containing values for the following properties:
  * TLS 1.3 cipher suites
  * TLS 1.0 - 1.2 cipher suites
  * Protocol versions
  * Certificate types
  * TLS curves for the key exchange
  * DH parameter size for the key exchange
  * HSTS max age
  * Maximum certificate lifespan
  * cipher preference (client or server choose)

`TLS Profiler` uses the `sslyze` library under the hood. This library
retrieves a wide range of information about a TLS server remotely. For
example, `sslyze` can retrieve the list of supported TLS versions.
`sslyze` does not, however, rate the results (like Qualy's SSLLabs
test does) or provide information whether the server fulfills certain
criteria.

`TLS Profiler` is initialized with a domain (host) name and a target
profile name (`old`, `intermediate`, or `modern`). When the `run()`
method is called, it returns a `TLS Profiler Result` with the following
attributes:

  * `validation_errors`: A list of strings describing errors that
    occured while validating the certificate.
  * `certificate_warnings`: A list of strings describing warnings
  concerning the certificate.
  * `profile_errors`: A list of strings describing deviations from the
    target Mozilla profile.
  * `vulnerability_errors`: Further vulnerabilities (like Heartbleet)
    that can be detected by `sslyze`.
  * `validated`: Boolean indicating whether the certificate is valid.
  * `profile_matched`: Boolean indicating whether the target profile's requirements are fulfilled.
  * `vulnerable`: Boolean indicating whether any vulnerabilities were discovered.
  * `all_ok`: Boolean indicating whether the certificate is valid, the
    profile was matched, no certificate warnings were issued and no vulnerabilities were detected.
 
**Limitations:**
1. Currently, if a server has multiple certificates only one certificate will
be recognized. This is a limitation of the ``sslyze`` library (see issue 
[#326](https://github.com/nabla-c0d3/sslyze/issues/326)).

# Usage
To use the TLS Profiler you currently need the ``tls_profiler`` branch of the following 
forks: [sslyze](https://github.com/fabian-hk/sslyze/tree/tls_profiler)
and [nassl](https://github.com/fabian-hk/nassl/tree/tls_profiler).

## API usage
Basic usage of the TLS Profiler:

```python
from tlsprofiler import TLSProfiler, PROFILE

profiler = TLSProfiler("www.example.com")
profiler.scan_server()
tls_profiler_result = profiler.compare_to_profile(PROFILE.MODERN)
```

## Command-line usage
Help text for the command-line interface:
```shell script
usage: run.py [-h] [-c CA_FILE] [-w CERT_EXPIRE_WARNING] domain [profile]

Scans the TLS settings of a server and compares them with a Mozilla TLS profile.

positional arguments:
  domain                Domain name of the server to be scanned
  profile               The Mozilla TLS profile to scan for [old|intermediate|modern]. If no profile is specified, 
                        the server's TLS settings will be compared to all profiles.

optional arguments:
  -h, --help            show this help message and exit
  -c CA_FILE, --ca-file CA_FILE
                        Path to a trusted custom root certificates in PEM format
  -w CERT_EXPIRE_WARNING, --cert-expire-warning CERT_EXPIRE_WARNING
                        A warning is issued if the certificate expires in less days than specified (default 15 days)

Example usage: python3 run.py www.example.com intermediate
```
To make the usage easier just build a docker container with
the Dockerfile in the root directory of this repository.
You have to use the following commands:
  * ``docker build -t tlsprofiler .``
  * ``docker run tlsprofiler www.example.com intermediate``
  
# Tests
To run all tests the script ``./tests/run_tests.sh`` from the root
directory of this repository. You can call it with the argument 
``--no-cache`` to rebuild the test environment from scratch.
