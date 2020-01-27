import unittest

from tlsprofiler import TLSProfiler, PROFILE


class ProfileTests(unittest.TestCase):
    ECDSA_CA_FILE = "tests/certificates/ecdsa_ca_cert.pem"
    RSA_CA_FILE = "tests/certificates/rsa_ca_cert.pem"

    VALIDATION_ERRORS = [
        "validation not successful: unable to get local issuer certificate (trust store Android)",
        "validation not successful: unable to get local issuer certificate (trust store Apple)",
        "validation not successful: unable to get local issuer certificate (trust store Java)",
        "validation not successful: unable to get local issuer certificate (trust store Mozilla)",
        "validation not successful: unable to get local issuer certificate (trust store Windows)",
        "Not enought SCTs in certificate, only found 0.",
    ]

    def test_modern_profile(self):
        profiler = TLSProfiler(
            "modern.dev.intranet", PROFILE.MODERN, self.ECDSA_CA_FILE
        )
        result = profiler.run()
        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "client must choose the cipher suite, not the server (Protocol TLSv1.3)",
                "OCSP stapling must be supported",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_intermediate_profile(self):
        profiler = TLSProfiler(
            "intermediate.dev.intranet", PROFILE.INTERMEDIATE, self.ECDSA_CA_FILE
        )
        result = profiler.run()
        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual(["Certificate expires in 12 days"], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "client must choose the cipher suite, not the server (Protocol TLSv1.3)",
                "OCSP stapling must be supported",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_old_profile(self):
        profiler = TLSProfiler("old.dev.intranet", PROFILE.OLD, self.RSA_CA_FILE)
        result = profiler.run()
        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "server has the wrong cipher suites order (Protocol TLSv1.3)",
                "must support DES-CBC3-SHA",
                "OCSP stapling must be supported",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_none_server_old_profile(self):
        profiler = TLSProfiler("none.dev.intranet", PROFILE.OLD, self.ECDSA_CA_FILE)
        result = profiler.run()
        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "server must choose the cipher suite, not the client (Protocol TLSv1)",
                "server must choose the cipher suite, not the client (Protocol TLSv1.1)",
                "server must choose the cipher suite, not the client (Protocol TLSv1.2)",
                "server has the wrong cipher suites order (Protocol TLSv1.3)",
                "must support ECDHE-ECDSA-AES128-GCM-SHA256",
                "must not support ECDH curve secp521r1 for key exchange",
                "must not support ECDH curve X448 for key exchange",
                "certificate lifespan to long",
                "wrong certificate type (ECDSA)",
                "certificate has a wrong signature",
                "OCSP stapling must be supported",
                "ECDSA certificate uses wrong curve",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_none_server_intermediate_profile(self):
        profiler = TLSProfiler(
            "none.dev.intranet", PROFILE.INTERMEDIATE, self.ECDSA_CA_FILE
        )
        result = profiler.run()
        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "must not support TLSv1.1",
                "must not support TLSv1",
                "client must choose the cipher suite, not the server (Protocol TLSv1.3)",
                "must not support ECDHE-ECDSA-AES256-SHA",
                "must not support ECDHE-ECDSA-AES128-SHA256",
                "must not support ECDHE-ECDSA-AES128-SHA",
                "must not support ECDHE-ECDSA-AES256-SHA384",
                "must support ECDHE-ECDSA-AES128-GCM-SHA256",
                "must not support ECDH curve secp521r1 for key exchange",
                "must not support ECDH curve X448 for key exchange",
                "certificate lifespan to long",
                "OCSP stapling must be supported",
                "ECDSA certificate uses wrong curve",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_none_server_modern_profile(self):
        profiler = TLSProfiler("none.dev.intranet", PROFILE.MODERN, self.ECDSA_CA_FILE)
        result = profiler.run()
        self.assertCountEqual(self.VALIDATION_ERRORS, result.validation_errors)
        self.assertCountEqual([], result.cert_warnings)
        self.assertFalse(result.validated)
        self.assertCountEqual(
            [
                "must not support TLSv1.2",
                "must not support TLSv1.1",
                "must not support TLSv1",
                "client must choose the cipher suite, not the server (Protocol TLSv1.3)",
                "must not support ECDHE-ECDSA-AES256-SHA",
                "must not support ECDHE-ECDSA-AES128-SHA256",
                "must not support ECDHE-ECDSA-AES256-GCM-SHA384",
                "must not support ECDHE-ECDSA-CHACHA20-POLY1305",
                "must not support ECDHE-ECDSA-AES128-SHA",
                "must not support ECDHE-ECDSA-AES256-SHA384",
                "must not support ECDH curve secp521r1 for key exchange",
                "must not support ECDH curve X448 for key exchange",
                "certificate lifespan to long",
                "ECDSA certificate uses wrong curve",
                "OCSP stapling must be supported",
            ],
            result.profile_errors,
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)
