from typing import Tuple, List, Optional, Dict, Set
from pathlib import Path
import requests
import logging
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import Certificate

from nassl.ephemeral_key_info import EphemeralKeyInfo, OpenSslEvpPkeyEnum

from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from sslyze.scanner import Scanner, ServerScanRequest, ServerScanResult
from sslyze.errors import ConnectionToServerFailed

from sslyze.plugins.scan_commands import ScanCommand, ScanCommandType
from sslyze.plugins.openssl_cipher_suites.implementation import (
    CipherSuitesScanResult,
    CipherSuiteAcceptedByServer,
)
from sslyze.plugins.elliptic_curves_plugin import (
    SupportedEllipticCurvesScanResult,
)
from sslyze.plugins.certificate_info.implementation import (
    CertificateInfoScanResult,
    CertificateInfoExtraArguments,
    CertificateDeploymentAnalysisResult,
)
from sslyze.plugins.certificate_info._cert_chain_analyzer import PathValidationResult
from sslyze.plugins.http_headers_plugin import (
    HttpHeadersScanResult,
    StrictTransportSecurityHeader,
)
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanResult
from sslyze.plugins.robot.implementation import RobotScanResultEnum, RobotScanResult

from tlsprofiler import utils
from tlsprofiler.utils import TLSProfilerResult
from tlsprofiler.comparator import Comparator

log = logging.getLogger("tlsprofiler")


class PROFILE:
    MODERN = "modern"
    INTERMEDIATE = "intermediate"
    OLD = "old"


class TLSProfiler:

    SCT_REQUIRED_DATE = datetime(
        year=2018, month=4, day=1
    )  # SCTs are required after this date, see https://groups.google.com/a/chromium.org/forum/#!msg/ct-policy/sz_3W_xKBNY/6jq2ghJXBAAJ

    SSL_SCAN_COMMANDS = {
        "SSLv2": ScanCommand.SSL_2_0_CIPHER_SUITES,
        "SSLv3": ScanCommand.SSL_3_0_CIPHER_SUITES,
        "TLSv1": ScanCommand.TLS_1_0_CIPHER_SUITES,
        "TLSv1.1": ScanCommand.TLS_1_1_CIPHER_SUITES,
        "TLSv1.2": ScanCommand.TLS_1_2_CIPHER_SUITES,
        "TLSv1.3": ScanCommand.TLS_1_3_CIPHER_SUITES,
    }

    ALL_SCAN_COMMANDS = {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.ELLIPTIC_CURVES,
        ScanCommand.HTTP_HEADERS,
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT,
        ScanCommand.OPENSSL_CCS_INJECTION,
    }

    def __init__(
        self,
        domain: str,
        target_profile_name: str,
        ca_file: Optional[str] = None,
        cert_expire_warning: int = 15,
    ) -> None:
        """
        :param domain:
        :param target_profile: One of [old|intermediate|modern]
        :param ca_file: Path to a trusted custom root certificates in PEM format.
        :param cert_expire_warning: A warning is issued if the certificate expires in less days than specified.
        """
        self.target_profile_name = target_profile_name

        self.scan_commands_extra_args = {}
        if ca_file:
            ca_path = Path(ca_file)
            self.scan_commands_extra_args[
                ScanCommand.CERTIFICATE_INFO
            ] = CertificateInfoExtraArguments(ca_path)

        self.cert_expire_warning = cert_expire_warning

        server_location = (
            ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(domain, 443)
        )
        self.scanner = Scanner()
        try:
            log.info(
                f"Testing connectivity with {server_location.hostname}:{server_location.port}..."
            )
            self.server_info = ServerConnectivityTester().perform(server_location)
            self.server_error = None
        except ConnectionToServerFailed as e:
            # Could not establish an SSL connection to the server
            log.warning(
                f"Could not connect to {e.server_location.hostname}: {e.error_message}"
            )
            self.server_error = e.error_message
            self.server_info = None

    def run(self) -> TLSProfilerResult:
        if self.server_info is None:
            return

        # run all scans together
        server_scan_req = ServerScanRequest(
            server_info=self.server_info,
            scan_commands=self.ALL_SCAN_COMMANDS,
            scan_commands_extra_arguments=self.scan_commands_extra_args,
        )
        self.scanner.queue_scan(server_scan_req)

        # We take the first result because only one server was queued
        self.server_scan_result = next(
            self.scanner.get_results()
        )  # type: ServerScanResult

        # preprocess scan results
        certificate_obj = self._preprocess_certificate()
        (
            supported_ciphers,
            supported_protocols,
            supported_key_exchange,
            server_preferred_order,
        ) = self._preprocess_ciphers_and_protocols()
        hsts_header = self._preprocess_hsts_header()
        supported_ecdh_curves = self._preprocess_ecdh_curves()

        comparator = Comparator(
            supported_ciphers,
            supported_protocols,
            supported_key_exchange,
            supported_ecdh_curves,
            server_preferred_order,
            certificate_obj,
            self.cert_expire_warning,
            hsts_header,
        )

        # Compare the preprocessed scan results to
        # each Mozilla TLS profile.
        profile_deviations = {}
        for profile in ["modern", "intermediate", "old"]:
            profile_deviations[profile] = comparator.compare(profile)

        validation_errors = self._validate_certificate(certificate_obj)
        vulnerability_errors = self._check_vulnerabilities()

        return TLSProfilerResult(
            self.target_profile_name,
            validation_errors,
            profile_deviations,
            vulnerability_errors,
        )

    def _get_result(self, command: ScanCommandType):
        return self.server_scan_result.scan_commands_results[command]

    def _preprocess_ciphers_and_protocols(
        self,
    ) -> Tuple[
        Dict[str, List[str]],
        Set[str],
        List[Tuple[EphemeralKeyInfo, str]],
        Dict[str, CipherSuiteAcceptedByServer],
    ]:
        supported_ciphers = dict()
        supported_protocols = []
        supported_key_exchange = []
        server_preferred_order = dict()
        for name, command in self.SSL_SCAN_COMMANDS.items():
            log.debug(f"Testing protocol {name}")
            result = self._get_result(command)  # type: CipherSuitesScanResult
            ciphers = [
                cipher.cipher_suite.openssl_name
                for cipher in result.accepted_cipher_suites
            ]
            supported_ciphers[name] = ciphers
            # NOTE: In the newest sslyze version we only get the key
            # exchange parameters for ephemeral key exchanges.
            # We do not get any parameters for finite field DH with
            # static parameters.
            key_exchange = [
                (cipher.ephemeral_key, cipher.cipher_suite.openssl_name)
                for cipher in result.accepted_cipher_suites
                if cipher.ephemeral_key
            ]
            supported_key_exchange.extend(key_exchange)
            server_preferred_order[name] = result.cipher_suite_preferred_by_server
            if result.is_tls_protocol_version_supported:
                supported_protocols.append(name)

        return (
            supported_ciphers,
            set(supported_protocols),
            supported_key_exchange,
            server_preferred_order,
        )

    def _preprocess_ecdh_curves(self) -> Set[str]:
        # get all supported curves
        ecdh_scan_result = self._get_result(
            ScanCommand.ELLIPTIC_CURVES
        )  # type: SupportedEllipticCurvesScanResult
        supported_curves = {}
        if ecdh_scan_result.supported_curves:
            supported_curves = [
                curve.name for curve in ecdh_scan_result.supported_curves
            ]
            supported_curves = set(utils.get_equivalent_curves(supported_curves))

        return supported_curves

    def _preprocess_certificate(self) -> CertificateDeploymentAnalysisResult:
        result = self._get_result(
            ScanCommand.CERTIFICATE_INFO
        )  # type: CertificateInfoScanResult

        # TODO if there are multiple certificates analyze all of them
        certificate_obj = result.certificate_deployments[0]

        return certificate_obj

    def _preprocess_hsts_header(self) -> StrictTransportSecurityHeader:
        result = self._get_result(
            ScanCommand.HTTP_HEADERS
        )  # type: HttpHeadersScanResult

        return result.strict_transport_security_header

    def _validate_certificate(
        self, certificate_obj: CertificateDeploymentAnalysisResult
    ) -> List[str]:

        certificate = certificate_obj.received_certificate_chain[0]

        validation_errors = []

        for r in certificate_obj.path_validation_results:  # type: PathValidationResult
            if not r.was_validation_successful:
                validation_errors.append(
                    f"Validation not successful: {r.openssl_error_string} (trust store {r.trust_store.name})"
                )

        # TODO check how to implement this with sslyze 3.1.0
        """
        if certificate0.path_validation_error_list:
            validation_errors = (
                fail.error_message for fail in certificate0.path_validation_error_list
            )
            validation_errors.append(
                f'Validation failed: {", ".join(validation_errors)}'
            )
        """

        if not certificate_obj.leaf_certificate_subject_matches_hostname:
            validation_errors.append(
                f"Leaf certificate subject does not match hostname!"
            )

        if not certificate_obj.received_chain_has_valid_order:
            validation_errors.append(f"Certificate chain has wrong order.")

        if certificate_obj.verified_chain_has_sha1_signature:
            validation_errors.append(f"SHA1 signature found in chain.")

        if certificate_obj.verified_chain_has_legacy_symantec_anchor:
            validation_errors.append(f"Symantec legacy certificate found in chain.")

        sct_count = certificate_obj.leaf_certificate_signed_certificate_timestamps_count
        if sct_count < 2 and certificate.not_valid_before >= self.SCT_REQUIRED_DATE:
            validation_errors.append(
                f"Certificates issued on or after 2018-04-01 need certificate transparency, "
                f"i.e., two signed SCTs in certificate. Leaf certificate only has {sct_count}."
            )

        if len(validation_errors) == 0:
            log.debug(f"Certificate is ok")
        else:
            log.debug(f"Error validating certificate")
            for error in validation_errors:
                log.debug(f"  → {error}")

        return validation_errors

    def _check_vulnerabilities(self):
        errors = []

        result = self._get_result(ScanCommand.HEARTBLEED)  # type: HeartbleedScanResult

        if result.is_vulnerable_to_heartbleed:
            errors.append(f"Server is vulnerable to Heartbleed attack")

        result = self._get_result(
            ScanCommand.OPENSSL_CCS_INJECTION
        )  # type: OpenSslCcsInjectionScanResult

        if result.is_vulnerable_to_ccs_injection:
            errors.append(
                f"Server is vulnerable to OpenSSL CCS Injection (CVE-2014-0224)"
            )

        result = self._get_result(ScanCommand.ROBOT)  # type: RobotScanResult

        if result.robot_result in [
            RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
            RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
        ]:
            errors.append(f"Server is vulnerable to ROBOT attack.")

        return errors
