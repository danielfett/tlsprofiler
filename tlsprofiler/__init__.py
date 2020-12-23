from typing import Tuple, List, Optional
from pathlib import Path
import requests
import logging
from datetime import datetime
from dataclasses import dataclass
from textwrap import TextWrapper
from tabulate import tabulate

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from cryptography.x509 import Certificate

from nassl.ephemeral_key_info import EphemeralKeyInfo, OpenSslEvpPkeyEnum

from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from sslyze.scanner import Scanner, ServerScanRequest, ServerScanResult
from sslyze.errors import ConnectionToServerFailed

from sslyze.plugins.scan_commands import ScanCommand, ScanCommandType
from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult
from sslyze.plugins.elliptic_curves_plugin import (
    SupportedEllipticCurvesScanResult,
)
from sslyze.plugins.certificate_info.implementation import (
    CertificateInfoScanResult,
    CertificateInfoExtraArguments,
)
from sslyze.plugins.certificate_info._cert_chain_analyzer import PathValidationResult
from sslyze.plugins.http_headers_plugin import HttpHeadersScanResult
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanResult
from sslyze.plugins.robot.implementation import RobotScanResultEnum, RobotScanResult

from tlsprofiler import utils

log = logging.getLogger("tlsprofiler")

_EQUIVALENT_CURVES = [
    ("secp192r1", "prime192v1"),
    ("secp256r1", "prime256v1"),
]


class PROFILE:
    MODERN = "modern"
    INTERMEDIATE = "intermediate"
    OLD = "old"


@dataclass
class TLSProfilerResult:
    validation_errors: List[str]
    cert_warnings: List[str]
    profile_errors: List[str]
    vulnerability_errors: List[str]

    validated: bool
    no_warnings: bool
    profile_matched: bool
    vulnerable: bool

    all_ok: bool

    def __init__(
        self,
        validation_errors: List[str],
        cert_warnings: List[str],
        profile_errors: List[str],
        vulnerability_errors: List[str],
    ):
        self.validation_errors = validation_errors
        self.cert_warnings = cert_warnings
        self.profile_errors = profile_errors
        self.vulnerability_errors = vulnerability_errors

        self.validated = len(self.validation_errors) == 0
        self.no_warnings = len(self.cert_warnings) == 0
        self.profile_matched = len(self.profile_errors) == 0
        self.vulnerable = len(self.vulnerability_errors) > 0

        self.all_ok = (
            self.validated
            and self.profile_matched
            and not self.vulnerable
            and self.no_warnings
        )

    def __str__(self):
        width = 80
        wrapper = TextWrapper(width=width, replace_whitespace=False)

        tmp_val = (
            [wrapper.fill(el) for el in self.validation_errors]
            if self.validation_errors
            else ["All good ;)"]
        )
        tmp_cert = (
            [wrapper.fill(el) for el in self.cert_warnings]
            if self.cert_warnings
            else ["All good ;)"]
        )
        tmp_prof = (
            [wrapper.fill(el) for el in self.profile_errors]
            if self.profile_errors
            else ["All good ;)"]
        )
        tmp_vul = (
            [wrapper.fill(el) for el in self.vulnerability_errors]
            if self.vulnerability_errors
            else ["All good ;)"]
        )

        val = {utils.expand_string("Validation Errors", width): tmp_val}
        cert = {utils.expand_string("Certification Warnings", width): tmp_cert}
        prof = {utils.expand_string("Profile Errors", width): tmp_prof}
        vul = {utils.expand_string("Vulnerability Errors", width): tmp_vul}

        return (
            f"\n{tabulate(val, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{tabulate(cert, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{tabulate(prof, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{tabulate(vul, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"\nValidated: {self.validated}; Profile Matched: {self.profile_matched}; "
            f"Vulnerable: {self.vulnerable}; All ok: {self.all_ok}\n"
        )


class TLSProfiler:
    PROFILES_URL = "https://ssl-config.mozilla.org/guidelines/5.6.json"
    PROFILES = None
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
        target_profile: str,
        ca_file: Optional[str] = None,
        cert_expire_warning: int = 15,
    ) -> None:
        """
        :param domain:
        :param target_profile: One of [old|intermediate|modern]
        :param ca_file: Path to a trusted custom root certificates in PEM format.
        :param cert_expire_warning: A warning is issued if the certificate expires in less days than specified.
        """
        self.scan_commands_extra_args = {}
        if ca_file:
            ca_path = Path(ca_file)
            self.scan_commands_extra_args[
                ScanCommand.CERTIFICATE_INFO
            ] = CertificateInfoExtraArguments(ca_path)

        self.cert_expire_warning = cert_expire_warning

        if TLSProfiler.PROFILES is None:
            TLSProfiler.PROFILES = requests.get(self.PROFILES_URL).json()
            log.info(
                f"Loaded version {TLSProfiler.PROFILES['version']} of the Mozilla TLS configuration recommendations."
            )

        self.target_profile = TLSProfiler.PROFILES["configurations"][target_profile]
        self.target_profile["tls_curves"] = self._get_equivalent_curves(
            self.target_profile["tls_curves"]
        )
        self.target_profile[
            "certificate_curves_preprocessed"
        ] = self._get_equivalent_curves(self.target_profile["certificate_curves"])

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

    def _get_equivalent_curves(self, curves: List[str]) -> Optional[List[str]]:
        if not curves:
            return None

        curves_tmp = curves.copy()
        for curve in curves:
            for curve_tuple in _EQUIVALENT_CURVES:
                if curve == curve_tuple[0]:
                    curves_tmp.append(curve_tuple[1])
                elif curve == curve_tuple[1]:
                    curves_tmp.append(curve_tuple[0])
        return curves_tmp

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

        (
            validation_errors,
            cert_profile_error,
            cert_warnings,
            pub_key_type,
        ) = self._check_certificate()
        hsts_errors = self._check_hsts_age()
        self._preprocess_ciphers_and_protocols()
        profile_errors = self._check_server_matches_profile(pub_key_type)
        vulnerability_errors = self._check_vulnerabilities()

        return TLSProfilerResult(
            validation_errors,
            cert_warnings,
            profile_errors + hsts_errors + cert_profile_error,
            vulnerability_errors,
        )

    def _get_result(self, command: ScanCommandType):
        return self.server_scan_result.scan_commands_results[command]

    def _preprocess_ciphers_and_protocols(self):
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

        self.supported_ciphers = supported_ciphers
        self.supported_protocols = set(supported_protocols)
        self.supported_key_exchange = (
            supported_key_exchange
        )  # type: List[(Optional[EphemeralKeyInfo], str)]
        self.server_preferred_order = server_preferred_order

    def _check_pub_key_supports_cipher(self, cipher: str, pub_key_type: str) -> bool:
        """
        Checks if cipher suite works with the servers certificate (for TLS 1.2 and older).
        Source: https://wiki.mozilla.org/Security/Server_Side_TLS, https://tools.ietf.org/html/rfc5246#appendix-A.5
        :param cipher: OpenSSL cipher name
        :param pub_key_type:
        :return:
        """
        if "anon" in cipher:
            return True
        elif pub_key_type in cipher:
            return True
        elif pub_key_type == "RSA" and "ECDSA" not in cipher and "DSS" not in cipher:
            return True

        return False

    def _check_protocols(self) -> List[str]:
        errors = []

        # match supported TLS versions
        allowed_protocols = set(self.target_profile["tls_versions"])
        illegal_protocols = self.supported_protocols - allowed_protocols
        missing_protocols = allowed_protocols - self.supported_protocols

        for protocol in illegal_protocols:
            errors.append(f"Must not support {protocol}")

        for protocol in missing_protocols:
            errors.append(f"Must support {protocol}")

        return errors

    def _check_cipher_suites_and_order(self, pub_key_type: str) -> List[str]:
        errors = []

        # match supported cipher suite order for each supported protocol
        all_supported_ciphers = []
        for protocol, supported_ciphers in self.supported_ciphers.items():
            all_supported_ciphers.extend(supported_ciphers)

            if protocol in self.supported_protocols:
                allowed_ciphers = self.target_profile["ciphers"]["openssl"]

                # check if the server chooses the cipher suite
                if (
                    self.target_profile["server_preferred_order"]
                    and not self.server_preferred_order[protocol]
                ):
                    errors.append(
                        f"Server must choose the cipher suite, not the client (Protocol {protocol})"
                    )

                # check if the client chooses the cipher suite
                if (
                    not self.target_profile["server_preferred_order"]
                    and self.server_preferred_order[protocol]
                ):
                    errors.append(
                        f"Client must choose the cipher suite, not the server (Protocol {protocol})"
                    )

                # check whether the servers preferred cipher suite preference is correct
                if (
                    self.target_profile["server_preferred_order"]
                    and self.server_preferred_order[protocol]
                    and not utils.check_cipher_order(allowed_ciphers, supported_ciphers)
                ):
                    # TODO wait for sslyze 3.1.1
                    errors.append(
                        f"Server has the wrong cipher suites order (Protocol {protocol})"
                    )

        # find cipher suites that should not be supported
        allowed_ciphers = (
            self.target_profile["ciphersuites"]
            + self.target_profile["ciphers"]["openssl"]
        )
        illegal_ciphers = set(all_supported_ciphers) - set(allowed_ciphers)
        for cipher in illegal_ciphers:
            errors.append(f"Must not support {cipher}")

        # find missing cipher suites
        missing_ciphers = set(allowed_ciphers) - set(all_supported_ciphers)
        for cipher in missing_ciphers:
            if self._check_pub_key_supports_cipher(cipher, pub_key_type):
                errors.append(f"Must support {cipher}")

        return errors

    def _check_dh_parameters(self) -> List[str]:
        errors = []

        # match DHE parameters
        for (
            key_info,
            cipher,
        ) in self.supported_key_exchange:  # type: (Optional[EphemeralKeyInfo], str)
            if (
                key_info.type == OpenSslEvpPkeyEnum.DH
                and not self.target_profile["dh_param_size"]
            ):
                errors.append(f"Must not support finite field DH key exchange")
                break
            elif (
                key_info.type == OpenSslEvpPkeyEnum.DH
                and key_info.size != self.target_profile["dh_param_size"]
            ):
                errors.append(
                    f"Wrong DHE parameter size {key_info.size} for cipher {cipher}"
                    f", should be {self.target_profile['dh_param_size']}"
                )

        return errors

    def _check_ecdh_curves(self) -> List[str]:
        errors = []

        # get all supported curves
        ecdh_scan_result = self._get_result(
            ScanCommand.ELLIPTIC_CURVES
        )  # type: SupportedEllipticCurvesScanResult
        supported_curves = []
        if ecdh_scan_result.supported_curves:
            supported_curves = [
                curve.name for curve in ecdh_scan_result.supported_curves
            ]
            supported_curves = set(self._get_equivalent_curves(supported_curves))

        # get allowed curves
        allowed_curves = self.target_profile["tls_curves"]
        allowed_curves = set(self._get_equivalent_curves(allowed_curves))

        not_allowed_curves = supported_curves - allowed_curves
        missing_curves = allowed_curves - supported_curves

        # report errors
        for curve in not_allowed_curves:
            errors.append(f"Must not support ECDH curve {curve} for key exchange")

        for curve in missing_curves:
            errors.append(f"Must support ECDH curve {curve} for key exchange")

        return errors

    def _check_server_matches_profile(self, pub_key_type: str):
        errors = []

        errors.extend(self._check_protocols())

        errors.extend(self._check_cipher_suites_and_order(pub_key_type))

        errors.extend(self._check_dh_parameters())

        errors.extend(self._check_ecdh_curves())

        return errors

    def _cert_type_string(self, pub_key) -> str:
        if isinstance(pub_key, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            return "ECDSA"
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            return "ED25519"
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            return "ED448"
        elif isinstance(pub_key, dsa.DSAPublicKey):
            return "DSA"

        return ""

    def _check_certificate_properties(
        self, certificate: Certificate, ocsp_stapling: bool
    ) -> Tuple[List[str], List[str], str]:
        errors = []
        warnings = []

        # check certificate lifespan
        lifespan = certificate.not_valid_after - certificate.not_valid_before
        if self.target_profile["maximum_certificate_lifespan"] < lifespan.days:
            errors.append(
                f"Certificate lifespan too long (is {lifespan.days}, "
                f"should be less than {self.target_profile['maximum_certificate_lifespan']})"
            )
        elif (
            self.target_profile["recommended_certificate_lifespan"]
            and self.target_profile["recommended_certificate_lifespan"] < lifespan.days
        ):
            warnings.append(
                f"Certificate lifespan is {lifespan.days} days but the recommended lifespan is {self.target_profile['recommended_certificate_lifespan']} days."
            )

        current_time = datetime.now()
        days_before_expire = certificate.not_valid_after - current_time
        if days_before_expire.days < self.cert_expire_warning:
            warnings.append(f"Certificate expires in {days_before_expire.days} days")

        # check certificate public key type
        pub_key_type = self._cert_type_string(certificate.public_key())
        if pub_key_type.lower() not in self.target_profile["certificate_types"]:
            errors.append(
                f"Wrong certificate type (is {pub_key_type}), "
                f"should be one of {self.target_profile['certificate_types']}"
            )

        # check key property
        pub_key = certificate.public_key()
        if (
            isinstance(pub_key, rsa.RSAPublicKey)
            and self.target_profile["rsa_key_size"]
            and pub_key.key_size != self.target_profile["rsa_key_size"]
        ):
            errors.append(
                f"RSA certificate has wrong key size (is {pub_key.key_size}, "
                f"should be {self.target_profile['rsa_key_size']})"
            )
        elif (
            isinstance(pub_key, ec.EllipticCurvePublicKey)
            and self.target_profile["certificate_curves"]
            and pub_key.curve.name
            not in self.target_profile["certificate_curves_preprocessed"]
        ):
            errors.append(
                f"ECDSA certificate uses wrong curve "
                f"(is {pub_key.curve.name}, should be one of {self.target_profile['certificate_curves']})"
            )

        # check certificate signature
        if (
            certificate.signature_algorithm_oid._name
            not in self.target_profile["certificate_signatures"]
        ):
            errors.append(
                f"Certificate has a wrong signature (is {certificate.signature_algorithm_oid._name}), "
                f"should be one of {self.target_profile['certificate_signatures']}"
            )

        # check if ocsp stabling is supported
        if ocsp_stapling != self.target_profile["ocsp_staple"]:
            if self.target_profile["ocsp_staple"]:
                errors.append(f"OCSP stapling must be supported")
            else:
                errors.append(f"OCSP stapling should not be supported")

        return errors, warnings, pub_key_type

    def _check_certificate(self) -> Tuple[List[str], List[str], List[str], str]:
        result = self._get_result(
            ScanCommand.CERTIFICATE_INFO
        )  # type: CertificateInfoScanResult

        # TODO if there are multiple certificates analyze all of them
        certificate0 = result.certificate_deployments[0]

        validation_errors = []

        certificate = certificate0.received_certificate_chain[0]
        (
            profile_errors,
            cert_warnings,
            pub_key_type,
        ) = self._check_certificate_properties(
            certificate, certificate0.ocsp_response_is_trusted
        )

        for r in certificate0.path_validation_results:  # type: PathValidationResult
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

        if not certificate0.leaf_certificate_subject_matches_hostname:
            validation_errors.append(
                f"Leaf certificate subject does not match hostname!"
            )

        if not certificate0.received_chain_has_valid_order:
            validation_errors.append(f"Certificate chain has wrong order.")

        if certificate0.verified_chain_has_sha1_signature:
            validation_errors.append(f"SHA1 signature found in chain.")

        if certificate0.verified_chain_has_legacy_symantec_anchor:
            validation_errors.append(f"Symantec legacy certificate found in chain.")

        sct_count = certificate0.leaf_certificate_signed_certificate_timestamps_count
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

        return validation_errors, profile_errors, cert_warnings, pub_key_type

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

    def _check_hsts_age(self) -> List[str]:
        result = self._get_result(
            ScanCommand.HTTP_HEADERS
        )  # type: HttpHeadersScanResult

        errors = []

        if result.strict_transport_security_header:
            if (
                result.strict_transport_security_header.max_age
                < self.target_profile["hsts_min_age"]
            ):
                errors.append(
                    f"wrong HSTS age (is {result.strict_transport_security_header.max_age}, "
                    f"should be at least {self.target_profile['hsts_min_age']})"
                )
        else:
            errors.append(f"HSTS header not set")

        return errors
