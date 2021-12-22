from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa


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


def expand_string(s: str, width: int, char: str = " ") -> str:
    l = width - len(s)
    for _ in range(l):
        s += char
    return s
