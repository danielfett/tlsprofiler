import unittest

from tlsprofiler import TLSProfiler


class ProfileTests(unittest.TestCase):

    CA_FILE = "tests/certificates/ecdsa_ca_cert.pem"

    def test_modern_profile(self):
        profiler = TLSProfiler("modern.dev.intranet", "modern")
        result = profiler.run()
        self.assertEqual(result.profile_errors, [])
        self.assertEqual(result.profile_matched, True)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertEqual(result.vulnerable, False)

    def test_intermediate_profile(self):
        profiler = TLSProfiler("intermediate.dev.intranet", "intermediate")
        result = profiler.run()
        self.assertEqual(result.profile_errors, [])
        self.assertEqual(result.profile_matched, True)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertEqual(result.vulnerable, False)

    def test_old_profile(self):
        profiler = TLSProfiler("old.dev.intranet", "old")
        result = profiler.run()
        self.assertEqual(result.profile_errors, ["must support DES-CBC3-SHA"])
        self.assertEqual(result.profile_matched, False)
        self.assertEqual(result.vulnerability_errors, [])
        self.assertEqual(result.vulnerable, False)