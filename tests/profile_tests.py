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
        self.assertEqual(result.validation_errors, self.VALIDATION_ERRORS)
        self.assertFalse(result.validated)
        self.assertEqual(
            result.profile_errors,
            [
                "client must choose the cipher suite, not the server (Protocol TLSv1.3)",
                "OCSP stapling must be supported",
            ],
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_intermediate_profile(self):
        profiler = TLSProfiler(
            "intermediate.dev.intranet", PROFILE.INTERMEDIATE, self.RSA_CA_FILE
        )
        result = profiler.run()
        self.assertEqual(result.validation_errors, self.VALIDATION_ERRORS)
        self.assertFalse(result.validated)
        self.assertEqual(
            result.profile_errors,
            [
                "client must choose the cipher suite, not the server (Protocol TLSv1.3)",
                "OCSP stapling must be supported",
            ],
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)

    def test_old_profile(self):
        profiler = TLSProfiler("old.dev.intranet", PROFILE.OLD, self.RSA_CA_FILE)
        result = profiler.run()
        self.assertEqual(result.validation_errors, self.VALIDATION_ERRORS)
        self.assertFalse(result.validated)
        self.assertEqual(
            result.profile_errors,
            [
                "server has the wrong cipher suites order (Protocol TLSv1.3)",
                "must support DES-CBC3-SHA",
                "OCSP stapling must be supported",
            ],
        )
        self.assertFalse(result.profile_matched)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertFalse(result.vulnerable)
        self.assertFalse(result.all_ok)
