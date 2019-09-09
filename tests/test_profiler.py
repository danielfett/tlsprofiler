from tlsprofiler import TLSProfiler
import unittest

class TLSTestCase(unittest.TestCase):
    def run_tls_profiler(self, domain, expect, profile='old'):
        tp = TLSProfiler(domain, profile)
        self.assertEqual(tp.server_error, None)
        self.assertNotEqual(tp.server_info, None)
        result = tp.run()
        
        if 'certificate_valid' in expect:
            if expect['certificate_valid']:
                self.assertListEqual(result.validation_errors, [])
            else:
                self.assertGreater(len(result.validation_errors), 0)
        if 'vulnerabilities' in expect:
            if expect['vulnerabilities']:
                self.assertGreater(len(result.vulnerability_errors), 0)
            else:
                self.assertListEqual(result.vulnerability_errors, [])
        if 'profile_matched' in expect:
            if expect['profile_matched']:
                self.assertListEqual(result.profile_errors, [])
            else:
                self.assertGreater(len(result.profile_errors), 0)

    def test_expired(self):
        self.run_tls_profiler(
            domain='expired.badssl.com',
            expect={
                'certificate_valid': False,
                'vulnerabilities': False,
            }
        )

    def test_wrong_host(self):
        self.run_tls_profiler(
            domain='wrong.host.badssl.com',
            expect={
                'certificate_valid': False,
                'vulnerabilities': False,
            }
        )

    def test_self_signed(self):
        self.run_tls_profiler(
            domain='self-signed.badssl.com',
            expect={
                'certificate_valid': False,
                'vulnerabilities': False,
            }
        )

    def test_untrusted_root(self):
        self.run_tls_profiler(
            domain='untrusted-root.badssl.com',
            expect={
                'certificate_valid': False,
                'vulnerabilities': False,
            }
        )

    @unittest.skip("badssl's profiles are not up-to-date with the mozilla 5.0 TLS profiles.")
    def test_mozilla_old(self):
        self.run_tls_profiler(
            domain='mozilla-old.badssl.com',
            profile='old',
            expect={
                'certificate_valid': True,
                'vulnerabilities': False,
                'profile_matched': True,
            }
        )

    @unittest.skip("badssl's profiles are not up-to-date with the mozilla 5.0 TLS profiles.")
    def test_mozilla_intermediate(self):
        self.run_tls_profiler(
            domain='mozilla-intermediate.badssl.com',
            profile='intermediate',
            expect={
                'certificate_valid': True,
                'vulnerabilities': False,
                'profile_matched': True,
            }
        )

    @unittest.skip("badssl's profiles are not up-to-date with the mozilla 5.0 TLS profiles.")
    def test_mozilla_modern(self):
        self.run_tls_profiler(
            domain='mozilla-modern.badssl.com',
            profile='modern',
            expect={
                'certificate_valid': True,
                'vulnerabilities': False,
                'profile_matched': True,
            }
        )

    def test_invalid_expected_sct(self):
        self.run_tls_profiler(
            domain='invalid-expected-sct.badssl.com',
            expect={
                'certificate_valid': False,
            }
        )
