from typing import List, Dict, Set, Tuple
from datetime import datetime
import logging
import requests

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from nassl.ephemeral_key_info import EphemeralKeyInfo, OpenSslEvpPkeyEnum

from sslyze.plugins.openssl_cipher_suites.implementation import (
    CipherSuiteAcceptedByServer,
)
from sslyze.plugins.certificate_info.implementation import (
    CertificateDeploymentAnalysisResult,
)
from sslyze.plugins.http_headers_plugin import StrictTransportSecurityHeader

from tlsprofiler import utils

log = logging.getLogger("tlsprofiler")


class Comparator:
    PROFILES_URL = "https://ssl-config.mozilla.org/guidelines/5.6.json"
    PROFILES = None

    def __init__(
        self,
        supported_ciphers: Dict[str, List[str]],
        supported_protocols: Set[str],
        supported_key_exchange: List[Tuple[EphemeralKeyInfo, str]],
        supported_ecdh_curves: Set[str],
        server_preferred_order: Dict[str, CipherSuiteAcceptedByServer],
        certificate_obj: CertificateDeploymentAnalysisResult,
        cert_expire_warning: int,
        hsts_header: StrictTransportSecurityHeader,
    ):
        self.supported_ciphers = supported_ciphers
        self.supported_protocols = supported_protocols
        self.supported_key_exchange = supported_key_exchange
        self.supported_ecdh_curves = supported_ecdh_curves
        self.server_preferred_order = server_preferred_order
        self.certificate_obj = certificate_obj
        self.cert_expire_warning = cert_expire_warning
        self.hsts_header = hsts_header

        if self.PROFILES is None:
            self.PROFILES = requests.get(self.PROFILES_URL).json()
            log.info(
                f"Loaded version {self.PROFILES['version']} of the Mozilla TLS configuration recommendations."
            )

    def _get_target_profile(self, target_profile_name: str) -> Dict:
        target_profile = self.PROFILES["configurations"][target_profile_name]
        target_profile["tls_curves"] = utils.get_equivalent_curves(
            target_profile["tls_curves"]
        )
        target_profile["certificate_curves_preprocessed"] = utils.get_equivalent_curves(
            target_profile["certificate_curves"]
        )
        return target_profile

    def compare(self, target_profile_name: str) -> Tuple[List[str], List[str]]:
        target_profile = self._get_target_profile(target_profile_name)

        protocol_errors = self._check_protocols(target_profile)
        cipher_errors = self._check_cipher_suites_and_order(target_profile)
        dh_parameter_errors = self._check_dh_parameters(target_profile)
        ecdh_curves_errors = self._check_ecdh_curves(target_profile)
        hsts_parameter_errors = self._check_hsts_age(target_profile)
        certificate_errors, certificate_warnings = self._check_certificate_properties(
            target_profile
        )

        profile_errors = (
            protocol_errors
            + cipher_errors
            + dh_parameter_errors
            + ecdh_curves_errors
            + hsts_parameter_errors
            + certificate_errors
        )

        return profile_errors, certificate_warnings

    def _check_protocols(self, target_profile: Dict) -> List[str]:
        errors = []

        # match supported TLS versions
        allowed_protocols = set(target_profile["tls_versions"])
        illegal_protocols = self.supported_protocols - allowed_protocols
        missing_protocols = allowed_protocols - self.supported_protocols

        for protocol in illegal_protocols:
            errors.append(f"Must not support {protocol}")

        for protocol in missing_protocols:
            errors.append(f"Must support {protocol}")

        return errors

    def _check_cipher_suites_and_order(self, target_profile: Dict) -> List[str]:
        errors = []

        # match supported cipher suite order for each supported protocol
        all_supported_ciphers = []
        for protocol, supported_ciphers in self.supported_ciphers.items():
            all_supported_ciphers.extend(supported_ciphers)

            if protocol in self.supported_protocols:
                allowed_ciphers = target_profile["ciphers"]["openssl"]

                # check if the server chooses the cipher suite
                if (
                    target_profile["server_preferred_order"]
                    and not self.server_preferred_order[protocol]
                ):
                    errors.append(
                        f"Server must choose the cipher suite, not the client (Protocol {protocol})"
                    )

                # check if the client chooses the cipher suite
                if (
                    not target_profile["server_preferred_order"]
                    and self.server_preferred_order[protocol]
                ):
                    errors.append(
                        f"Client must choose the cipher suite, not the server (Protocol {protocol})"
                    )

                # check whether the servers preferred cipher suite preference is correct
                if (
                    target_profile["server_preferred_order"]
                    and self.server_preferred_order[protocol]
                    and not utils.check_cipher_order(allowed_ciphers, supported_ciphers)
                ):
                    # TODO wait for sslyze 3.1.1
                    errors.append(
                        f"Server has the wrong cipher suites order (Protocol {protocol})"
                    )

        # find cipher suites that should not be supported
        allowed_ciphers = (
            target_profile["ciphersuites"] + target_profile["ciphers"]["openssl"]
        )
        illegal_ciphers = set(all_supported_ciphers) - set(allowed_ciphers)
        for cipher in illegal_ciphers:
            errors.append(f"Must not support {cipher}")

        # Determine the certificate type to check which
        # ciphers can be supported.
        certificate = self.certificate_obj.received_certificate_chain[0]
        pub_key_type = utils.cert_type_string(certificate.public_key())

        # find missing cipher suites
        missing_ciphers = set(allowed_ciphers) - set(all_supported_ciphers)
        for cipher in missing_ciphers:
            if utils.check_pub_key_supports_cipher(cipher, pub_key_type):
                errors.append(f"Must support {cipher}")

        return errors

    def _check_dh_parameters(self, target_profile: Dict) -> List[str]:
        errors = []

        # match DHE parameters
        for (
            key_info,
            cipher,
        ) in self.supported_key_exchange:  # type: (EphemeralKeyInfo, str)
            if (
                key_info.type == OpenSslEvpPkeyEnum.DH
                and not target_profile["dh_param_size"]
            ):
                errors.append(f"Must not support finite field DH key exchange")
                break
            elif (
                key_info.type == OpenSslEvpPkeyEnum.DH
                and key_info.size != target_profile["dh_param_size"]
            ):
                errors.append(
                    f"Wrong DHE parameter size {key_info.size} for cipher {cipher}"
                    f", should be {target_profile['dh_param_size']}"
                )

        return errors

    def _check_ecdh_curves(self, target_profile: Dict) -> List[str]:
        errors = []

        # get allowed curves
        allowed_curves = target_profile["tls_curves"]
        allowed_curves = set(utils.get_equivalent_curves(allowed_curves))

        not_allowed_curves = self.supported_ecdh_curves - allowed_curves
        missing_curves = allowed_curves - self.supported_ecdh_curves

        # report errors
        for curve in not_allowed_curves:
            errors.append(f"Must not support ECDH curve {curve} for key exchange")

        for curve in missing_curves:
            errors.append(f"Must support ECDH curve {curve} for key exchange")

        return errors

    def _check_hsts_age(self, target_profile: Dict) -> List[str]:
        errors = []

        if self.hsts_header:
            if self.hsts_header.max_age < target_profile["hsts_min_age"]:
                errors.append(
                    f"Wrong HSTS age (is {self.hsts_header.max_age}, "
                    f"should be at least {target_profile['hsts_min_age']})"
                )
        else:
            errors.append(f"HSTS header not set")

        return errors

    def _check_certificate_properties(
        self, target_profile: Dict
    ) -> Tuple[List[str], List[str]]:
        errors = []
        warnings = []

        certificate = self.certificate_obj.received_certificate_chain[0]

        # check certificate lifespan
        lifespan = certificate.not_valid_after - certificate.not_valid_before
        if target_profile["maximum_certificate_lifespan"] < lifespan.days:
            errors.append(
                f"Certificate lifespan too long (is {lifespan.days}, "
                f"should be less than {target_profile['maximum_certificate_lifespan']})"
            )
        elif (
            target_profile["recommended_certificate_lifespan"]
            and target_profile["recommended_certificate_lifespan"] < lifespan.days
        ):
            warnings.append(
                f"Certificate lifespan is {lifespan.days} days but the recommended lifespan is {target_profile['recommended_certificate_lifespan']} days."
            )

        current_time = datetime.now()
        days_before_expire = certificate.not_valid_after - current_time
        if days_before_expire.days < self.cert_expire_warning:
            warnings.append(f"Certificate expires in {days_before_expire.days} days")

        # check certificate public key type
        pub_key_type = utils.cert_type_string(certificate.public_key())
        if pub_key_type.lower() not in target_profile["certificate_types"]:
            errors.append(
                f"Wrong certificate type (is {pub_key_type}), "
                f"should be one of {target_profile['certificate_types']}"
            )

        # check key property
        pub_key = certificate.public_key()
        if (
            isinstance(pub_key, rsa.RSAPublicKey)
            and target_profile["rsa_key_size"]
            and pub_key.key_size != target_profile["rsa_key_size"]
        ):
            errors.append(
                f"RSA certificate has wrong key size (is {pub_key.key_size}, "
                f"should be {target_profile['rsa_key_size']})"
            )
        elif (
            isinstance(pub_key, ec.EllipticCurvePublicKey)
            and target_profile["certificate_curves"]
            and pub_key.curve.name
            not in target_profile["certificate_curves_preprocessed"]
        ):
            errors.append(
                f"ECDSA certificate uses wrong curve "
                f"(is {pub_key.curve.name}, should be one of {target_profile['certificate_curves']})"
            )

        # check certificate signature
        if (
            certificate.signature_algorithm_oid._name
            not in target_profile["certificate_signatures"]
        ):
            errors.append(
                f"Certificate has a wrong signature (is {certificate.signature_algorithm_oid._name}), "
                f"should be one of {target_profile['certificate_signatures']}"
            )

        # check if ocsp stabling is supported
        ocsp_stapling = self.certificate_obj.ocsp_response_is_trusted
        if ocsp_stapling != target_profile["ocsp_staple"]:
            if target_profile["ocsp_staple"]:
                errors.append(f"OCSP stapling must be supported")
            else:
                errors.append(f"OCSP stapling should not be supported")

        return errors, warnings
