import unittest

from tlsprofiler import utils


class CipherOrderCheck(unittest.TestCase):
    def test_right_order(self):
        a = ["a", "b", "c", "d"]
        s = ["a", "b", "c", "d"]
        res = utils.check_cipher_order(a, s)
        self.assertTrue(res)

    def test_right_order_2(self):
        a = ["a", "b", "c", "d"]
        s = ["a", "c"]
        res = utils.check_cipher_order(a, s)
        self.assertTrue(res)

        res = utils.check_cipher_order(s, a)
        self.assertFalse(res)

    def test_wrong_order(self):
        a = ["a", "b", "c", "d"]
        s = ["a", "b", "d", "c"]
        res = utils.check_cipher_order(a, s)
        self.assertFalse(res)

    def test_wrong_order_2(self):
        a = ["a", "b", "c", "d"]
        s = ["a", "d", "c"]
        res = utils.check_cipher_order(a, s)
        self.assertFalse(res)

    def test_empty_s_list(self):
        a = ["a", "b", "c", "d"]
        s = []
        res = utils.check_cipher_order(a, s)
        self.assertTrue(res)

    def test_empty_input(self):
        a = []
        s = []
        res = utils.check_cipher_order(a, s)
        self.assertTrue(res)
