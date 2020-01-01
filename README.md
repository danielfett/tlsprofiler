# TLS Profiler #

## Dependencies
- [Nassl fork](https://github.com/fabian-hk/nassl/tree/tls_profiler)
(You can download a prebuilt wheel from [here](https://drive.google.com/open?id=10MCanCfoaBiT5GJ0Ckg8aExAfigrpvud))

## Description
The `TLSProfiler` class provided in this library can be used to
compare the configuration of a TLS server to the [Mozilla TLS
configuration
recommendations](https://wiki.mozilla.org/Security/Server_Side_TLS).

`TLS Profiler` uses the `sslyze` library under the hood. This library
retrieves a wide range of information about a TLS server remotely. For
example, `sslyze` can retrieve the list of supported TLS versions.
`sslyze` does not, however, rate the results (like Qualy's SSLLabs
test does) or provide information whether the server fulfills certain
criteria.

`TLSProfiler` is initialized with a domain (host) name and a target
profile name (`old`, `intermediate`, or `modern`). When the `run()`
method is called, it returns a `TLSProfilerResult` with the following
attributes:

  * `validation_errors`: A list of strings describing errors that
    occured while validating the certificate.
  * `profile_errors`: A list of strings describing deviations from the
    target Mozilla profile.
  * `vulnerability_errors`: Further vulnerabilities (like Heartbleet)
    that can be detected by `sslyze`.
  * `validated`: Boolean indicating whether the certificate is valid.
  * `profile_matched`: Boolean indicating whether the target profile's requirements are fulfilled.
  * `vulnerable`: Boolean indicating whether any vulnerabilities were discovered.
  * `all_ok`: Boolean indicating whether the certificate is valid, the
    profile was matched, and no vulnerabilities were detected.
    
As of now, `TLSProfiler` only compares the list of supported cipher
suites and the supported TLS versions in Mozilla's profiles (not key
lengths, certificate algorithms, etc.).


