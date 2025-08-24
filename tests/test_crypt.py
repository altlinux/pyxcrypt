"""
The data for these tests was taken from libxcrypt.

Copyright (C) 2018-2021 Björn Esser <besser82@fedoraproject.org>
Copyright (C) 2025   Daniel Zagaynov <kotopesutility@altlinux.org>

Redistribution and use in source and binary forms, with or without
modification, are permitted.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
"""
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
