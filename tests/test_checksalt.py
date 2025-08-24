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
import unittest

import pyxcrypt


class Test_CheckSalt(unittest.TestCase):
    CRYPT_SALT_OK, CRYPT_SALT_INVALID, CRYPT_SALT_METHOD_LEGACY =\
            pyxcrypt.CRYPT_SALT_OK, pyxcrypt.CRYPT_SALT_INVALID, pyxcrypt.CRYPT_SALT_METHOD_LEGACY
    pref_chck_gen_crypt = {"": [CRYPT_SALT_INVALID, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "..": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "MN": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "_": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "$1$": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "$3$": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "$md5$": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "$sha1$": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "$5$": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "$6$": [CRYPT_SALT_OK, CRYPT_SALT_OK, CRYPT_SALT_OK],
                           "$sm3$": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY],
                           "$2b$": [CRYPT_SALT_OK, CRYPT_SALT_OK, CRYPT_SALT_OK],
                           "$2a$": [CRYPT_SALT_OK, CRYPT_SALT_OK, CRYPT_SALT_OK],
                           "$2x$": [CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "$2y$": [CRYPT_SALT_OK, CRYPT_SALT_OK, CRYPT_SALT_OK],
                           "$y$": [CRYPT_SALT_OK, CRYPT_SALT_OK, CRYPT_SALT_OK],
                           "$7$": [CRYPT_SALT_OK, CRYPT_SALT_OK, CRYPT_SALT_OK],
                           "$gy$": [CRYPT_SALT_OK, CRYPT_SALT_OK, CRYPT_SALT_OK],
                           "$sm3y$": [CRYPT_SALT_OK, CRYPT_SALT_OK, CRYPT_SALT_OK],
                           "$@": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "%A": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "A%": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "$2$": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "*0": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "*1": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "  ": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "!!": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "**": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "::": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           ";;": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "\\\\": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "\x01\x01": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "\x19\x19": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "\x7f\x7f": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "\xfe\xfe": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           "\xff\xff": [CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID],
                           None: [CRYPT_SALT_INVALID, CRYPT_SALT_OK, CRYPT_SALT_OK]
                           }

    def _test_checksalt(self, prefix, crypt_checksalt=pyxcrypt.pyxcrypt._crypt_checksalt,
                        crypt_gensalt=pyxcrypt.pyxcrypt._crypt_gensalt,
                        crypt=pyxcrypt.pyxcrypt._crypt):
        phrase = "police saying freeze"
        with self.subTest(f"Testing checksalt for {prefix}:"):
            exp_prefix, exp_gensalt, exp_crypt = self.pref_chck_gen_crypt[prefix]
            ret_prefix = crypt_checksalt(prefix)
            got_gensalt = crypt_gensalt(prefix, 0, None, 0)
            ret_gensalt = crypt_checksalt(got_gensalt)
            got_crypt = crypt(phrase, got_gensalt)
            ret_crypt = crypt_checksalt(got_crypt)

            self.assertEqual(ret_prefix, exp_prefix,
                             msg=f"Test checksalt(prefix) for prefix={prefix} failed.")
            self.assertEqual(ret_gensalt, exp_gensalt,
                             msg=f"Test checksalt(crypt_gensalt(...)) for prefix={prefix} failed.")
            self.assertEqual(ret_crypt, exp_crypt,
                             msg=f"Test checksalt(crypt(...)) for prefix={prefix} failed.")

    def test_yescrypt(self):
        self._test_checksalt("$y$")

    def test_gost_yescrypt(self):
        self._test_checksalt("$gy$")

    def test_descrypt(self):
        self._test_checksalt("")

    @unittest.skip("Not supported")
    def test_bigcrypt(self):
        self._test_checksalt("")

    @unittest.skip("Not supported")
    def test_bsdicrypt(self):
        self._test_checksalt("_")

    def test_md5crypt(self):
        self._test_checksalt("$1$")

    @unittest.skip("Not supported")
    def test_sunmd5crypt(self):
        self._test_checksalt("$md5")

    @unittest.skip("Not supported")
    def test_sm3crypt(self):
        self._test_checksalt("$sm3$")

    @unittest.skip("Not supported")
    def test_sha1crypt(self):
        self._test_checksalt("$sha1")

    def test_sha256crypt(self):
        self._test_checksalt("$5$")

    def test_sha512crypt(self):
        self._test_checksalt("$6$")

    def test_sscrypt(self):
        self._test_checksalt("$7$")

    def test_bcrypt(self):
        self._test_checksalt("$2b$")

    def test_bcrypt_a(self):
        self._test_checksalt("$2a$")

    def test_bcrypt_y(self):
        self._test_checksalt("$2y$")

    def test_invalid(self):
        for pref in ["$@", "%A", "A%", "$2$", "*0", "*1", "  ", "!!", "**", "::", ";;",
                     "\\\\", "\x01\x01", "\x19\x19", "\x7f\x7f"]:
            with self.subTest(f"Testing checksalt for {pref}:"):
                self.assertEqual(pyxcrypt.pyxcrypt._crypt_checksalt(pref), self.pref_chck_gen_crypt[pref][0],
                                 msg=f"Test checksalt(prefix) for prefix={pref} failed.")


class TestCheckSalt(Test_CheckSalt):
    def test_yescrypt(self):
        self._test_checksalt("$y$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_gost_yescrypt(self):
        self._test_checksalt("$gy$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_descrypt(self):
        self._test_checksalt("", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_bigcrypt(self):
        self._test_checksalt("", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_bsdicrypt(self):
        self._test_checksalt("_", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_md5crypt(self):
        self._test_checksalt("$1$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_sunmd5crypt(self):
        self._test_checksalt("$md5", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_sm3crypt(self):
        self._test_checksalt("$sm3$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    @unittest.skip("Not supported")
    def test_sha1crypt(self):
        self._test_checksalt("$sha1", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_sha256crypt(self):
        self._test_checksalt("$5$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_sha512crypt(self):
        self._test_checksalt("$6$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_sscrypt(self):
        self._test_checksalt("$7$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_bcrypt(self):
        self._test_checksalt("$2b$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_bcrypt_a(self):
        self._test_checksalt("$2a$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_bcrypt_y(self):
        self._test_checksalt("$2y$", pyxcrypt.crypt_checksalt, pyxcrypt.crypt_gensalt, pyxcrypt.crypt)

    def test_invalid(self):
        for pref in ["$@", "%A", "A%", "$2$", "*0", "*1", "  ", "!!", "**", "::", ";;",
                     "\\\\", "\x01\x01", "\x19\x19", "\x7f\x7f"]:
            with self.subTest(f"Testing checksalt for {pref}:"):
                self.assertEqual(pyxcrypt.crypt_checksalt(pref), self.pref_chck_gen_crypt[pref][0],
                                 msg=f"Test checksalt(prefix) for prefix={pref} failed.")


if __name__ == "__main__":
    unittest.main()
