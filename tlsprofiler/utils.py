from typing import List


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
