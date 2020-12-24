import unittest

from tlsprofiler import TLSProfiler, PROFILE


class ProfileTests(unittest.TestCase):
    ECDSA_CA_FILE = "tests/certificates/ecdsa_ca_cert.pem"
    RSA_CA_FILE = "tests/certificates/rsa_ca_cert.pem"

    VALIDATION_ERRORS = [
        "Validation not successful: unable to get local issuer certificate (trust store Android)",
        "Validation not successful: unable to get local issuer certificate (trust store Apple)",
        "Validation not successful: unable to get local issuer certificate (trust store Java)",
        "Validation not successful: unable to get local issuer certificate (trust store Mozilla)",
        "Validation not successful: unable to get local issuer certificate (trust store Windows)",
        "Certificates issued on or after 2018-04-01 need certificate transparency, i.e., two signed SCTs in certificate. Leaf certificate only has 0.",
    ]

    def test_modern_profile(self):
        profiler = TLSProfiler("modern.dev.intranet", self.ECDSA_CA_FILE)
        profiler.scan_server()
        result = profiler.compare_to_profile(PROFILE.MODERN)

        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "OCSP stapling must be supported",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_intermediate_profile(self):
        profiler = TLSProfiler("intermediate.dev.intranet", self.ECDSA_CA_FILE)
        profiler.scan_server()
        result = profiler.compare_to_profile(PROFILE.INTERMEDIATE)

        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual(["Certificate expires in 12 days"], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "Client must choose the cipher suite, not the server (Protocol TLSv1.2)",
                "Client must choose the cipher suite, not the server (Protocol TLSv1.3)",
                "OCSP stapling must be supported",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_old_profile(self):
        profiler = TLSProfiler("old.dev.intranet", self.RSA_CA_FILE)
        profiler.scan_server()
        result = profiler.compare_to_profile(PROFILE.OLD)

        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual(
            [
                "Certificate lifespan is 366 days but the recommended lifespan is 90 days."
            ],
            result.cert_warnings,
        )
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "Server has the wrong cipher suites order (Protocol TLSv1.3)",
                "Must support DES-CBC3-SHA",
                "OCSP stapling must be supported",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_none_server_old_profile(self):
        profiler = TLSProfiler("none.dev.intranet", self.ECDSA_CA_FILE)
        profiler.scan_server()
        result = profiler.compare_to_profile(PROFILE.OLD)

        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "Server must choose the cipher suite, not the client (Protocol TLSv1)",
                "Server must choose the cipher suite, not the client (Protocol TLSv1.1)",
                "Server must choose the cipher suite, not the client (Protocol TLSv1.2)",
                "Server must choose the cipher suite, not the client (Protocol TLSv1.3)",
                "Must support ECDHE-ECDSA-AES128-GCM-SHA256",
                "Must not support ECDH curve secp521r1 for key exchange",
                "Must not support ECDH curve X448 for key exchange",
                "Certificate lifespan too long (is 1000, should be less than 366)",
                "Wrong certificate type (is ECDSA), should be one of ['rsa']",
                "OCSP stapling must be supported",
                "Certificate has a wrong signature (is ecdsa-with-SHA384), should be one of ['sha256WithRSAEncryption']",
                "ECDSA certificate uses wrong curve (is secp521r1, should be one of ['prime256v1', 'secp384r1'])",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_none_server_intermediate_profile(self):
        profiler = TLSProfiler("none.dev.intranet", self.ECDSA_CA_FILE)
        profiler.scan_server()
        result = profiler.compare_to_profile(PROFILE.INTERMEDIATE)

        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "Must not support TLSv1.1",
                "Must not support TLSv1",
                "Must not support ECDHE-ECDSA-AES256-SHA",
                "Must not support ECDHE-ECDSA-AES128-SHA256",
                "Must not support ECDHE-ECDSA-AES128-SHA",
                "Must not support ECDHE-ECDSA-AES256-SHA384",
                "Must support ECDHE-ECDSA-AES128-GCM-SHA256",
                "Must not support ECDH curve secp521r1 for key exchange",
                "Must not support ECDH curve X448 for key exchange",
                "Certificate lifespan too long (is 1000, should be less than 366)",
                "OCSP stapling must be supported",
                "ECDSA certificate uses wrong curve (is secp521r1, should be one of ['prime256v1', 'secp384r1'])",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_none_server_modern_profile(self):
        profiler = TLSProfiler("none.dev.intranet", self.ECDSA_CA_FILE)
        profiler.scan_server()
        result = profiler.compare_to_profile(PROFILE.MODERN)

        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "Must not support TLSv1.2",
                "Must not support TLSv1.1",
                "Must not support TLSv1",
                "Must not support ECDHE-ECDSA-AES256-SHA",
                "Must not support ECDHE-ECDSA-AES128-SHA256",
                "Must not support ECDHE-ECDSA-AES256-GCM-SHA384",
                "Must not support ECDHE-ECDSA-CHACHA20-POLY1305",
                "Must not support ECDHE-ECDSA-AES128-SHA",
                "Must not support ECDHE-ECDSA-AES256-SHA384",
                "Must not support ECDH curve secp521r1 for key exchange",
                "Must not support ECDH curve X448 for key exchange",
                "Certificate lifespan too long (is 1000, should be less than 90)",
                "ECDSA certificate uses wrong curve (is secp521r1, should be one of ['prime256v1', 'secp384r1'])",
                "OCSP stapling must be supported",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)
