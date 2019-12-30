from nassl.key_exchange_info import DhKeyExchangeInfo, NistEcDhKeyExchangeInfo, EcDhKeyExchangeInfo, KeyExchangeInfo
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.plugins.openssl_cipher_suites_plugin import *
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand, CertificateInfoScanResult
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.robot_plugin import RobotScanResultEnum, RobotScanCommand, RobotScanResult
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand, HeartbleedScanResult
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand, OpenSslCcsInjectionScanResult

import requests
import logging

log = logging.getLogger('tlsprofiler')


class TLSProfilerResult:
    def __init__(self, validation_errors, profile_errors, vulnerability_errors):
        self.validation_errors = validation_errors
        self.profile_errors = profile_errors
        self.vulnerability_errors = vulnerability_errors

        self.validated = len(self.validation_errors) == 0
        self.profile_matched = len(self.profile_errors) == 0
        self.vulnerable = len(self.vulnerability_errors) > 0

        self.all_ok = self.validated and self.profile_matched and not self.vulnerable

    def __str__(self):
        return f"Validation Errors: {self.validation_errors}\n\nProfile Errors: {self.profile_errors}\n\n" \
               f"Vulnerability Errors: {self.vulnerability_errors}\n\nValidated: {self.validated}\n\n" \
               f"Profile Matched: {self.profile_matched}\n\nVulnerable: {self.vulnerable}\n\nAll ok: {self.all_ok}"


class TLSProfiler:
    PROFILES_URL = 'https://statics.tls.security.mozilla.org/server-side-tls-conf-5.0.json'
    PROFILES = None

    SCAN_COMMANDS = {
        "SSLv2": Sslv20ScanCommand,
        "SSLv3": Sslv30ScanCommand,
        "TLSv1": Tlsv10ScanCommand,
        "TLSv1.1": Tlsv11ScanCommand,
        "TLSv1.2": Tlsv12ScanCommand,
        "TLSv1.3": Tlsv13ScanCommand,
    }

    def __init__(self, domain: str, target_profile_name: str, ca_file: Optional[str] = None) -> None:
        """
        :param domain:
        :param target_profile_name: One of [old|intermediate|modern]
        :param ca_file: Path to trusted custom root certificates in PEM format.
        """
        self.ca_file = ca_file

        if TLSProfiler.PROFILES is None:
            TLSProfiler.PROFILES = requests.get(self.PROFILES_URL).json()
            log.info(
                f"Loaded version {TLSProfiler.PROFILES['version']} of the Mozilla TLS configuration recommendations.")

        self.target_profile = TLSProfiler.PROFILES['configurations'][target_profile_name]

        self.scanner = SynchronousScanner()
        try:
            server_tester = ServerConnectivityTester(
                hostname=domain,
            )
            log.info(f'Testing connectivity with {server_tester.hostname}:{server_tester.port}...')
            self.server_info = server_tester.perform()
            self.server_error = None
        except ServerConnectivityError as e:
            # Could not establish an SSL connection to the server
            log.warning(f'Could not connect to {e.server_info.hostname}: {e.error_message}')
            self.server_error = e.error_message
            self.server_info = None

    def run(self) -> TLSProfilerResult:
        if self.server_info is None:
            return

        certificate_validation_errors = self.check_certificate()
        self.scan_supported_ciphers_and_protocols()
        profile_errors = self.check_server_matches_profile()
        vulnerability_errors = self.check_vulnerabilities()

        return TLSProfilerResult(
            certificate_validation_errors,
            profile_errors,
            vulnerability_errors,
        )

    def scan(self, command: PluginScanCommand):
        return self.scanner.run_scan_command(self.server_info, command)

    def scan_supported_ciphers_and_protocols(self):
        supported_ciphers = dict()
        supported_protocols = []
        supported_key_exchange = []
        supported_curves = []
        server_preferred_order = dict()
        for name, command in self.SCAN_COMMANDS.items():
            log.debug(f"Testing protocol {name}")
            result = self.scan(command())  # type: CipherSuiteScanResult
            ciphers = [cipher.openssl_name for cipher in result.accepted_cipher_list]
            supported_ciphers[name] = ciphers
            key_exchange = [(cipher.dh_info, cipher.openssl_name) for cipher in result.accepted_cipher_list
                            if cipher.dh_info]
            supported_key_exchange.extend(key_exchange)
            supported_curves.extend(result.supported_curves)
            if ciphers:
                server_preferred_order[name] = result.server_cipher_preference
            else:
                server_preferred_order[name] = True
            if len(ciphers):
                supported_protocols.append(name)

        self.supported_ciphers = supported_ciphers
        self.supported_protocols = set(supported_protocols)
        self.supported_key_exchange = supported_key_exchange  # type: List[(KeyExchangeInfo, str)]
        self.supported_curves = set(supported_curves)
        self.server_preferred_order = server_preferred_order

    def _check_cipher_order_rec(self, allowed_ciphers: iter, supported_ciphers: iter) -> bool:
        a_item = next(allowed_ciphers, None)
        if not a_item:
            return False
        s_item = next(supported_ciphers, None)
        if not s_item:
            return True
        while a_item != s_item:
            a_item = next(allowed_ciphers, None)
            if not a_item:
                return False
        return self._check_cipher_order_rec(allowed_ciphers, supported_ciphers)

    def _check_cipher_order(self, allowed_ciphers: List[str], supported_ciphers: List[str]) -> bool:
        a_iter = iter(allowed_ciphers)
        s_iter = iter(supported_ciphers)
        return self._check_cipher_order_rec(a_iter, s_iter)

    def check_server_matches_profile(self):
        errors = []

        # match supported TLS versions
        allowed_protocols = set(self.target_profile['tls_versions'])
        illegal_protocols = self.supported_protocols - allowed_protocols
        missing_protocols = allowed_protocols - self.supported_protocols

        for protocol in illegal_protocols:
            errors.append(f'must not support "{protocol}"')

        for protocol in missing_protocols:
            errors.append(f'must support "{protocol}"')

        # match supported cipher suites and the order
        for protocol, supported_ciphers in self.supported_ciphers.items():
            if protocol == "TLSv1.3":
                allowed_ciphers = self.target_profile['openssl_ciphersuites']
            else:
                allowed_ciphers = self.target_profile['openssl_ciphers']

            # find cipher suites that should not be supported
            illegal_ciphers = set(supported_ciphers) - set(allowed_ciphers)
            for cipher in illegal_ciphers:
                errors.append(f'must not support "{cipher}"')

            if protocol != "TLSv1.3":
                # check if the server chooses the cipher suite
                if self.target_profile["server_preferred_order"] and not self.server_preferred_order[protocol]:
                    errors.append(f"server must choose the cipher suite, not the client (Protocol {protocol})")

                # check whether the servers preferred cipher suite preference is correct
                if self.target_profile["server_preferred_order"] and \
                        not self._check_cipher_order(allowed_ciphers, supported_ciphers):
                    errors.append(f"server has the wrong cipher suites order (Protocol {protocol})")

        # match DHE and ECDHE parameters
        for (key_info, cipher) in self.supported_key_exchange:
            if isinstance(key_info, DhKeyExchangeInfo) and key_info.key_size != self.target_profile['dh_param_size']:
                errors.append(f"wrong DHE parameter size {key_info.key_size} for cipher {cipher}"
                              f", should be {self.target_profile['dh_param_size']}")

        # match ECDH curves used for key exchange
        # The extra item "prime256v1" is needed because the curve is specified as "secp256r1" in the
        # intermediate and old profile. I opend an issue for this (https://github.com/mozilla/server-side-tls/issues/265)
        allowed_curves = set(self.target_profile["tls_curves"] + ["prime256v1"])
        for curve in self.supported_curves:
            if curve not in allowed_curves:
                errors.append(f"must not support ECDH curve {curve} for key exchange")

        return errors

    def check_certificate(self):
        result = self.scan(CertificateInfoScanCommand(ca_file=self.ca_file))  # type: CertificateInfoScanResult

        errors = []

        for r in result.path_validation_result_list:
            if not r.was_validation_successful:
                errors.append(f"validation not successful: {r.verify_string} (trust store {r.trust_store.name})")

        if result.path_validation_error_list:
            validation_errors = (fail.error_message for fail in result.path_validation_error_list)
            errors.append(f'Validation failed: {", ".join(validation_errors)}')

        if not result.leaf_certificate_subject_matches_hostname:
            errors.append(f'Leaf certificate subject does not match hostname!')

        if not result.received_chain_has_valid_order:
            errors.append(f'Certificate chain has wrong order.')

        if result.verified_chain_has_sha1_signature:
            errors.append(f'SHA1 signature found in chain.')

        if result.verified_chain_has_legacy_symantec_anchor:
            errors.append(f'Symantec legacy certificate found in chain.')

        if result.leaf_certificate_signed_certificate_timestamps_count < 2:
            errors.append(
                f'Not enought SCTs in certificate, only found {result.leaf_certificate_signed_certificate_timestamps_count}.')

        if len(errors) == 0:
            log.debug(f"Certificate is ok")
        else:
            log.debug(f"Error validating certificate")
            for error in errors:
                log.debug(f"  → {error}")

        return errors

    def check_vulnerabilities(self):
        errors = []

        result = self.scan(HeartbleedScanCommand())  # type: HeartbleedScanResult

        if result.is_vulnerable_to_heartbleed:
            errors.append(f'Server is vulnerable to Heartbleed attack')

        result = self.scan(OpenSslCcsInjectionScanCommand())  # type: OpenSslCcsInjectionScanResult

        if result.is_vulnerable_to_ccs_injection:
            errors.append(f'Server is vulnerable to OpenSSL CCS Injection (CVE-2014-0224)')

        result = self.scan(RobotScanCommand())  # type: RobotScanResult

        if result.robot_result_enum in [
            RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
            RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
        ]:
            errors.append(f"Server is vulnerable to ROBOT attack.")

        return errors


if __name__ == "__main__":
    ca_file = "/home/fabian/Documents/docker/tls/certificates/ca_cert.pem"
    profiler = TLSProfiler('old.dev.intranet', 'old', ca_file)
    print(profiler.run())
