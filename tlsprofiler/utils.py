from typing import List, Optional, Dict
from dataclasses import dataclass
from textwrap import TextWrapper
from tabulate import tabulate

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

from tlsprofiler.comparator import ProfileDeviations

EQUIVALENT_CURVES = [
    ("secp192r1", "prime192v1"),
    ("secp256r1", "prime256v1"),
]


def get_equivalent_curves(curves: List[str]) -> Optional[List[str]]:
    if not curves:
        return None

    curves_tmp = curves.copy()
    for curve in curves:
        for curve_tuple in EQUIVALENT_CURVES:
            if curve == curve_tuple[0]:
                curves_tmp.append(curve_tuple[1])
            elif curve == curve_tuple[1]:
                curves_tmp.append(curve_tuple[0])
    return curves_tmp


def cert_type_string(pub_key) -> str:
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


def check_pub_key_supports_cipher(cipher: str, pub_key_type: str) -> bool:
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


def check_cipher_order(
    allowed_ciphers: List[str], supported_ciphers: List[str]
) -> bool:
    a_iter = iter(allowed_ciphers)
    a_item = next(a_iter, None)
    for sc in supported_ciphers:
        while a_item != sc:
            a_item = next(a_iter, None)
            if not a_item:
                return False

        a_item = next(a_iter, None)

    return True


def expand_string(s: str, width: int) -> str:
    l = width - len(s)
    for _ in range(l):
        s += " "
    return s


@dataclass
class TLSProfilerResult:
    validation_errors: List[str]
    profile_deviations: Dict[str, ProfileDeviations]
    vulnerability_errors: List[str]

    validated: bool
    no_warnings: bool
    profile_matched: bool
    vulnerable: bool

    all_ok: bool

    def __init__(
        self,
        target_profile_name: str,
        validation_errors: List[str],
        profile_deviations: Dict[str, ProfileDeviations],
        vulnerability_errors: List[str],
    ):
        self.target_profile_name = target_profile_name

        self.validation_errors = validation_errors
        self.profile_deviations = profile_deviations
        self.vulnerability_errors = vulnerability_errors

        self.validated = len(self.validation_errors) == 0
        self.no_warnings = (
            len(self.profile_deviations[self.target_profile_name].cert_warnings) == 0
        )
        self.profile_matched = (
            len(self.profile_deviations[self.target_profile_name].profile_errors) == 0
        )
        self.vulnerable = len(self.vulnerability_errors) > 0

        self.all_ok = (
            self.validated
            and self.profile_matched
            and not self.vulnerable
            and self.no_warnings
        )

        self.verbose_print = False

    @property
    def profile_errors(self):
        return self.profile_deviations[self.target_profile_name].profile_errors

    @property
    def cert_warnings(self):
        return self.profile_deviations[self.target_profile_name].cert_warnings

    def __str__(self):
        width = 80
        wrapper = TextWrapper(width=width, replace_whitespace=False)

        tmp_val = (
            [wrapper.fill(el) for el in self.validation_errors]
            if self.validation_errors
            else ["All good ;)"]
        )

        tmp_vul = (
            [wrapper.fill(el) for el in self.vulnerability_errors]
            if self.vulnerability_errors
            else ["All good ;)"]
        )

        val = {expand_string("Validation Errors", width): tmp_val}
        vul = {expand_string("Vulnerability Errors", width): tmp_vul}

        profile_deviations_str = ""
        if self.verbose_print:
            for key, value in self.profile_deviations.items():
                if key != self.target_profile_name:
                    profile_deviations_str += f"{value}"

        return (
            f"{profile_deviations_str}"
            f"\nResults for the {self.target_profile_name.title()} Profile:\n"
            f"\n{tabulate(val, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{self.profile_deviations[self.target_profile_name]}"
            f"{tabulate(vul, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"\nValidated: {self.validated}; Profile Matched: {self.profile_matched}; "
            f"Vulnerable: {self.vulnerable}; All ok: {self.all_ok}\n"
        )
