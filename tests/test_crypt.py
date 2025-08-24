import re
import sys
import json
import unittest
import pathlib

import pyxcrypt


class Test_Crypt(unittest.TestCase):
    with open(pathlib.Path(__file__).parent.joinpath("ka_table.json"), "rb") as f:
        pref_salt_hash_pass = json.load(f)

    def _test_crypt(self, prefix, crypt=pyxcrypt.pyxcrypt._crypt):
        with self.subTest(f"Testing crypt for {prefix} ({len(self.pref_salt_hash_pass[prefix])} tests):"):
            for phrase, salt, hsh in self.pref_salt_hash_pass[prefix]:
                got = crypt(phrase.encode("iso_8859_1"), salt)
                self.assertEqual(got, hsh,
                                 msg=f"Test crypt({phrase}, {salt} failed.")

    def test_yescrypt(self):
        self._test_crypt("$y$")

    def test_gost_yescrypt(self):
        self._test_crypt("$gy$")

    def test_descrypt(self):
        self._test_crypt("")

    @unittest.skip("Not supported")
    def test_bigcrypt(self):
        self._test_crypt("")

    @unittest.skip("Not supported")
    def test_bsdicrypt(self):
        self._test_crypt("_")

    def test_md5crypt(self):
        self._test_crypt("$1$")

    @unittest.skip("Not supported")
    def test_sunmd5crypt(self):
        self._test_crypt("$md5")

    @unittest.skip("Not supported")
    def test_sm3crypt(self):
        self._test_crypt("$sm3$")

    @unittest.skip("Not supported")
    def test_sha1crypt(self):
        self._test_crypt("$sha1")

    def test_sha256crypt(self):
        self._test_crypt("$5$")

    def test_sha512crypt(self):
        self._test_crypt("$6$")

    def test_sscrypt(self):
        self._test_crypt("$7$")

    def test_bcrypt(self):
        self._test_crypt("$2b$")

    def test_bcrypt_a(self):
        self._test_crypt("$2a$")

    def test_bcrypt_y(self):
        self._test_crypt("$2y$")

    def test_bcrypt_x(self):
        self._test_crypt("$2x$")


class TestCrypt(Test_Crypt):
    def test_yescrypt(self):
        self._test_crypt("$y$", pyxcrypt.crypt)

    def test_gost_yescrypt(self):
        self._test_crypt("$gy$", pyxcrypt.crypt)

    def test_descrypt(self):
        self._test_crypt("", pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_bigcrypt(self):
        self._test_crypt("", pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_bsdicrypt(self):
        self._test_crypt("_", pyxcrypt.crypt)

    def test_md5crypt(self):
        self._test_crypt("$1$", pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_sunmd5crypt(self):
        self._test_crypt("$md5", pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_sm3crypt(self):
        self._test_crypt("$sm3$", pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_sha1crypt(self):
        self._test_crypt("$sha1", pyxcrypt.crypt)

    def test_sha256crypt(self):
        self._test_crypt("$5$", pyxcrypt.crypt)

    def test_sha512crypt(self):
        self._test_crypt("$6$", pyxcrypt.crypt)

    def test_sscrypt(self):
        self._test_crypt("$7$", pyxcrypt.crypt)

    def test_bcrypt(self):
        self._test_crypt("$2b$", pyxcrypt.crypt)

    def test_bcrypt_a(self):
        self._test_crypt("$2a$", pyxcrypt.crypt)

    def test_bcrypt_y(self):
        self._test_crypt("$2y$", pyxcrypt.crypt)

    def test_bcrypt_x(self):
        self._test_crypt("$2x$", pyxcrypt.crypt)


if __name__ == "__main__":
    unittest.main()
