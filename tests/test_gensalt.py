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
import sysconfig

import unittest

import pyxcrypt


class Test_GenSalt(unittest.TestCase):
    MIN_LINEAR_COST = 1
    MAX_LINEAR_COST = 2 ** (8 * sysconfig.get_config_var("SIZEOF_LONG")) - 1
    # Rounds and expected output for descrypt
    des_rounds_expected = {0: ["Mp",
                               "Pp",
                               "ZH",
                               "Uh"]
                           }
    # Rounds and expected output for bigcrypt
    big_rounds_expected = {0: ["Mp............",
                               "Pp............",
                               "ZH............",
                               "Uh............"]
                           }
    # Rounds and expected output for bsdicrypt
    bsdi_rounds_expected = {0: ["_J9..MJHn",
                                "_J9..PKXc",
                                "_J9..ZAFl",
                                "_J9..UqGB"],
                            16384: ["_/.2.MJHn",
                                    "_/.2.PKXc",
                                    "_/.2.ZAFl",
                                    "_/.2.UqGB"],
                            MIN_LINEAR_COST: ["_/...MJHn",
                                              "_/...PKXc",
                                              "_/...ZAFl",
                                              "_/...UqGB"],
                            MAX_LINEAR_COST: ["_zzzzMJHn",
                                              "_zzzzPKXc",
                                              "_zzzzZAFl",
                                              "_zzzzUqGB"]
                            }
    # Rounds and expected output for md5
    md5_rounds_expected = {0: ["$1$MJHnaAke",
                               "$1$PKXc3hCO",
                               "$1$ZAFlICwY",
                               "$1$UqGBkVu0"]
                           }
    # Rounds and expected output for sunmd5
    sunmd5_rounds_expected = {0: ["$md5,rounds=55349$BPm.fm03$",
                                  "$md5,rounds=72501$WKoucttX$",
                                  "$md5,rounds=42259$3HtkHq/x$",
                                  "$md5,rounds=73773$p.5e9AQf$"],
                              MIN_LINEAR_COST: ["$md5,rounds=55349$BPm.fm03$",
                                                "$md5,rounds=72501$WKoucttX$",
                                                "$md5,rounds=42259$3HtkHq/x$",
                                                "$md5,rounds=73773$p.5e9AQf$"],
                              MAX_LINEAR_COST: ["$md5,rounds=4294924340$BPm.fm03$",
                                                "$md5,rounds=4294941492$WKoucttX$",
                                                "$md5,rounds=4294911250$3HtkHq/x$",
                                                "$md5,rounds=4294942764$p.5e9AQf$"]
                              }
    # Rounds and expected output for sunmd5
    sm3_rounds_expected = {0: ["$sm3$MJHnaAkegEVYHsFK",
                               "$sm3$PKXc3hCOSyMqdaEQ",
                               "$sm3$ZAFlICwYRETzIzIj",
                               "$sm3$UqGBkVu01rurVZqg"],
                           10191: ["$sm3$rounds=10191$MJHnaAkegEVYHsFK",
                                   "$sm3$rounds=10191$PKXc3hCOSyMqdaEQ",
                                   "$sm3$rounds=10191$ZAFlICwYRETzIzIj",
                                   "$sm3$rounds=10191$UqGBkVu01rurVZqg"],
                           MIN_LINEAR_COST: ["$sm3$rounds=1000$MJHnaAkegEVYHsFK",
                                             "$sm3$rounds=1000$PKXc3hCOSyMqdaEQ",
                                             "$sm3$rounds=1000$ZAFlICwYRETzIzIj",
                                             "$sm3$rounds=1000$UqGBkVu01rurVZqg"],
                           MAX_LINEAR_COST: ["$sm3$rounds=999999999$MJHnaAkegEVYHsFK",
                                             "$sm3$rounds=999999999$PKXc3hCOSyMqdaEQ",
                                             "$sm3$rounds=999999999$ZAFlICwYRETzIzIj",
                                             "$sm3$rounds=999999999$UqGBkVu01rurVZqg"]
                           }
    # Rounds and expected output for sha1crypt
    sha1_rounds_expected = {0: ["$sha1$248488$ggu.H673kaZ5$",
                                "$sha1$248421$SWqudaxXA5L0$",
                                "$sha1$257243$RAtkIrDxEovH$",
                                "$sha1$250464$1j.eVxRfNAPO$"],
                            MIN_LINEAR_COST: ["$sha1$4$ggu.H673kaZ5$",
                                              "$sha1$4$SWqudaxXA5L0$",
                                              "$sha1$4$RAtkIrDxEovH$",
                                              "$sha1$4$1j.eVxRfNAPO$"],
                            MAX_LINEAR_COST: ["$sha1$3643984551$ggu.H673kaZ5$",
                                              "$sha1$4200450659$SWqudaxXA5L0$",
                                              "$sha1$3946507480$RAtkIrDxEovH$",
                                              "$sha1$3486175838$1j.eVxRfNAPO$"]
                            }
    # Rounds and expected output for sha256crypt
    sha256_rounds_expected = {0: ["$5$MJHnaAkegEVYHsFK",
                                  "$5$PKXc3hCOSyMqdaEQ",
                                  "$5$ZAFlICwYRETzIzIj",
                                  "$5$UqGBkVu01rurVZqg"],
                              10191: ["$5$rounds=10191$MJHnaAkegEVYHsFK",
                                      "$5$rounds=10191$PKXc3hCOSyMqdaEQ",
                                      "$5$rounds=10191$ZAFlICwYRETzIzIj",
                                      "$5$rounds=10191$UqGBkVu01rurVZqg"],
                              MIN_LINEAR_COST: ["$5$rounds=1000$MJHnaAkegEVYHsFK",
                                                "$5$rounds=1000$PKXc3hCOSyMqdaEQ",
                                                "$5$rounds=1000$ZAFlICwYRETzIzIj",
                                                "$5$rounds=1000$UqGBkVu01rurVZqg"],
                              MAX_LINEAR_COST: ["$5$rounds=999999999$MJHnaAkegEVYHsFK",
                                                "$5$rounds=999999999$PKXc3hCOSyMqdaEQ",
                                                "$5$rounds=999999999$ZAFlICwYRETzIzIj",
                                                "$5$rounds=999999999$UqGBkVu01rurVZqg"]
                              }
    # Rounds and expected output for sha512crypt
    sha512_rounds_expected = {0: ["$6$MJHnaAkegEVYHsFK",
                                  "$6$PKXc3hCOSyMqdaEQ",
                                  "$6$ZAFlICwYRETzIzIj",
                                  "$6$UqGBkVu01rurVZqg"],
                              10191: ["$6$rounds=10191$MJHnaAkegEVYHsFK",
                                      "$6$rounds=10191$PKXc3hCOSyMqdaEQ",
                                      "$6$rounds=10191$ZAFlICwYRETzIzIj",
                                      "$6$rounds=10191$UqGBkVu01rurVZqg"],
                              MIN_LINEAR_COST: ["$6$rounds=1000$MJHnaAkegEVYHsFK",
                                                "$6$rounds=1000$PKXc3hCOSyMqdaEQ",
                                                "$6$rounds=1000$ZAFlICwYRETzIzIj",
                                                "$6$rounds=1000$UqGBkVu01rurVZqg"],
                              MAX_LINEAR_COST: ["$6$rounds=999999999$MJHnaAkegEVYHsFK",
                                                "$6$rounds=999999999$PKXc3hCOSyMqdaEQ",
                                                "$6$rounds=999999999$ZAFlICwYRETzIzIj",
                                                "$6$rounds=999999999$UqGBkVu01rurVZqg"]
                              }
    # Rounds and expected output for scrypt
    ss_rounds_expected = {0: ["$7$CU..../....MJHnaAkegEVYHsFKkmfzJ1",
                              "$7$CU..../....PKXc3hCOSyMqdaEQArI62/",
                              "$7$CU..../....ZAFlICwYRETzIzIjEIC86.",
                              "$7$CU..../....UqGBkVu01rurVZqgNchTB0"],
                          6: ["$7$BU..../....MJHnaAkegEVYHsFKkmfzJ1",
                              "$7$BU..../....PKXc3hCOSyMqdaEQArI62/",
                              "$7$BU..../....ZAFlICwYRETzIzIjEIC86.",
                              "$7$BU..../....UqGBkVu01rurVZqgNchTB0"],
                          11: ["$7$GU..../....MJHnaAkegEVYHsFKkmfzJ1",
                               "$7$GU..../....PKXc3hCOSyMqdaEQArI62/",
                               "$7$GU..../....ZAFlICwYRETzIzIjEIC86.",
                               "$7$GU..../....UqGBkVu01rurVZqgNchTB0"]
                          }
    # Rounds and expected output for bcrypt (bcrypt_b)
    bcrypt_rounds_expected = {0: ["$2b$05$UBVLHeMpJ/QQCv3XqJx8zO",
                                  "$2b$05$kxUgPcrmlm9XoOjvxCyfP.",
                                  "$2b$05$HPNDjKMRFdR7zC87CMSmA.",
                                  "$2b$05$mAyzaIeJu41dWUkxEbn8hO"],
                              4: ["$2b$04$UBVLHeMpJ/QQCv3XqJx8zO",
                                  "$2b$04$kxUgPcrmlm9XoOjvxCyfP.",
                                  "$2b$04$HPNDjKMRFdR7zC87CMSmA.",
                                  "$2b$04$mAyzaIeJu41dWUkxEbn8hO"],
                              31: ["$2b$31$UBVLHeMpJ/QQCv3XqJx8zO",
                                   "$2b$31$kxUgPcrmlm9XoOjvxCyfP.",
                                   "$2b$31$HPNDjKMRFdR7zC87CMSmA.",
                                   "$2b$31$mAyzaIeJu41dWUkxEbn8hO"]}
    # Rounds and expected output for bcrypt_a
    bcrypt_a_rounds_expected = {0: ["$2a$05$UBVLHeMpJ/QQCv3XqJx8zO",
                                    "$2a$05$kxUgPcrmlm9XoOjvxCyfP.",
                                    "$2a$05$HPNDjKMRFdR7zC87CMSmA.",
                                    "$2a$05$mAyzaIeJu41dWUkxEbn8hO"]
                                }
    # Rounds and expected output for bcrypt_y
    bcrypt_y_rounds_expected = {0: ["$2y$05$UBVLHeMpJ/QQCv3XqJx8zO",
                                    "$2y$05$kxUgPcrmlm9XoOjvxCyfP.",
                                    "$2y$05$HPNDjKMRFdR7zC87CMSmA.",
                                    "$2y$05$mAyzaIeJu41dWUkxEbn8hO"]
                                }
    # Rounds and expected output for yescrypt
    ys_rounds_expected = {0: ["$y$j9T$MJHnaAkegEVYHsFKkmfzJ1",
                              "$y$j9T$PKXc3hCOSyMqdaEQArI62/",
                              "$y$j9T$ZAFlICwYRETzIzIjEIC86.",
                              "$y$j9T$UqGBkVu01rurVZqgNchTB0"],
                          1: ["$y$j75$MJHnaAkegEVYHsFKkmfzJ1",
                              "$y$j75$PKXc3hCOSyMqdaEQArI62/",
                              "$y$j75$ZAFlICwYRETzIzIjEIC86.",
                              "$y$j75$UqGBkVu01rurVZqgNchTB0"],
                          11: ["$y$jFT$MJHnaAkegEVYHsFKkmfzJ1",
                               "$y$jFT$PKXc3hCOSyMqdaEQArI62/",
                               "$y$jFT$ZAFlICwYRETzIzIjEIC86.",
                               "$y$jFT$UqGBkVu01rurVZqgNchTB0"]
                          }
    # Rounds and expected output for gost_yescrypt
    gs_ys_rounds_expected = {0: ["$gy$j9T$MJHnaAkegEVYHsFKkmfzJ1",
                                 "$gy$j9T$PKXc3hCOSyMqdaEQArI62/",
                                 "$gy$j9T$ZAFlICwYRETzIzIjEIC86.",
                                 "$gy$j9T$UqGBkVu01rurVZqgNchTB0"],
                             1: ["$gy$j75$MJHnaAkegEVYHsFKkmfzJ1",
                                 "$gy$j75$PKXc3hCOSyMqdaEQArI62/",
                                 "$gy$j75$ZAFlICwYRETzIzIjEIC86.",
                                 "$gy$j75$UqGBkVu01rurVZqgNchTB0"],
                             11: ["$gy$jFT$MJHnaAkegEVYHsFKkmfzJ1",
                                  "$gy$jFT$PKXc3hCOSyMqdaEQArI62/",
                                  "$gy$jFT$ZAFlICwYRETzIzIjEIC86.",
                                  "$gy$jFT$UqGBkVu01rurVZqgNchTB0"]
                             }

    def _test_prefix(self, rounds_output, prefix, crypt_gensalt=pyxcrypt.pyxcrypt._crypt_gensalt):
        nrbytes = 16  # This value is hardcoded in libxcrypt gensalt tests
        self.entropy = [b"\x58\x35\xcd\x26\x03\xab\x2c\x14\x92\x13\x1e\x59\xb0\xbc\xfe\xd5",
                        b"\x9b\x35\xa2\x45\xeb\x68\x9e\x8f\xd9\xa9\x09\x71\xcc\x4d\x21\x44",
                        b"\x25\x13\xc5\x94\xc3\x93\x1d\xf4\xfd\xd4\x4f\xbd\x10\xe5\x28\x08",
                        b"\xa0\x2d\x35\x70\xa8\x0b\xc3\xad\xdf\x61\x69\xb3\x19\xda\x7e\x8d",]

        for rounds, outputs in rounds_output.items():
            with self.subTest(f"Testing crypt_gensalt for {prefix}:"):
                for entropy, output in zip(self.entropy, outputs):
                    got = crypt_gensalt(prefix, rounds, entropy, nrbytes)
                    self.assertEqual(got, output,
                                     msg=f"Test crypt_gensalt for prefix={prefix} and entropy={entropy} failed.")

    def test_yescrypt(self):
        self._test_prefix(self.ys_rounds_expected, "$y$")

    def test_gost_yescrypt(self):
        self._test_prefix(self.gs_ys_rounds_expected, "$gy$")

    def test_descrypt(self):
        self._test_prefix(self.des_rounds_expected, "")

    @unittest.skip("Not supported")
    def test_bigcrypt(self):
        self._test_prefix(self.big_rounds_expected, "")

    @unittest.skip("Not supported")
    def test_bsdicrypt(self):
        self._test_prefix(self.bsdi_rounds_expected, "_")

    def test_md5crypt(self):
        self._test_prefix(self.md5_rounds_expected, "$1$")

    @unittest.skip("Not supported")
    def test_sunmd5crypt(self):
        self._test_prefix(self.sunmd5_rounds_expected, "$md5")

    @unittest.skip("Not supported")
    def test_sm3crypt(self):
        self._test_prefix(self.sm3_rounds_expected, "$sm3$")

    @unittest.skip("Not supported")
    def test_sha1crypt(self):
        self._test_prefix(self.sha1_rounds_expected, "$sha1")

    def test_sha256crypt(self):
        self._test_prefix(self.sha256_rounds_expected, "$5$")

    def test_sha512crypt(self):
        self._test_prefix(self.sha512_rounds_expected, "$6$")

    def test_sscrypt(self):
        self._test_prefix(self.ss_rounds_expected, "$7$")

    def test_bcrypt(self):
        self._test_prefix(self.bcrypt_rounds_expected, "$2b$")

    def test_bcrypt_a(self):
        self._test_prefix(self.bcrypt_a_rounds_expected, "$2a$")

    def test_bcrypt_y(self):
        self._test_prefix(self.bcrypt_y_rounds_expected, "$2y$")

    def test_bcrypt_x(self):
        with self.subTest("Testing crypt_gensalt for $2x$:"):
            with self.assertRaises(RuntimeError,
                                   msg="Test crypt_gensalt for prefix=$2x$ failed."):
                pyxcrypt.pyxcrypt._crypt_gensalt("$2x$", 0, None, 0)


class TestGenSalt(Test_GenSalt):
    def test_yescrypt(self):
        self._test_prefix(self.ys_rounds_expected, "yescrypt", pyxcrypt.crypt_gensalt)

    def test_gost_yescrypt(self):
        self._test_prefix(self.gs_ys_rounds_expected, "gost_yescrypt", pyxcrypt.crypt_gensalt)
        self._test_prefix(self.gs_ys_rounds_expected, "gost-yescrypt", pyxcrypt.crypt_gensalt)

    def test_descrypt(self):
        self._test_prefix(self.des_rounds_expected, "descrypt", pyxcrypt.crypt_gensalt)

    def test_md5crypt(self):
        self._test_prefix(self.md5_rounds_expected, "md5crypt", pyxcrypt.crypt_gensalt)

    @unittest.skip("Not supported")
    def test_sunmd5crypt(self):
        self._test_prefix(self.sunmd5_rounds_expected, "sunmd5", pyxcrypt.crypt_gensalt)

    @unittest.skip("Not supported")
    def test_sm3crypt(self):
        self._test_prefix(self.sm3_rounds_expected, "sm3crypt", pyxcrypt.crypt_gensalt)

    @unittest.skip("Not supported")
    def test_sha1crypt(self):
        self._test_prefix(self.sha1_rounds_expected, "sha1crypt", pyxcrypt.crypt_gensalt)

    def test_sha256crypt(self):
        self._test_prefix(self.sha256_rounds_expected, "sha256crypt", pyxcrypt.crypt_gensalt)

    def test_sha512crypt(self):
        self._test_prefix(self.sha512_rounds_expected, "sha512crypt", pyxcrypt.crypt_gensalt)

    def test_sscrypt(self):
        self._test_prefix(self.ss_rounds_expected, "scrypt", pyxcrypt.crypt_gensalt)

    def test_bcrypt(self):
        self._test_prefix(self.bcrypt_rounds_expected, "bcrypt", pyxcrypt.crypt_gensalt)

    def test_bcrypt_a(self):
        self._test_prefix(self.bcrypt_a_rounds_expected, "bcrypt_a", pyxcrypt.crypt_gensalt)

    def test_bcrypt_y(self):
        self._test_prefix(self.bcrypt_y_rounds_expected, "bcrypt_y", pyxcrypt.crypt_gensalt)

    def test_bcrypt_x(self):
        with self.subTest("Testing crypt_gensalt for bcrypt_x:"):
            with self.assertRaises(RuntimeError,
                                   msg="Test crypt_gensalt for prefix=bcrypt_x failed."):
                pyxcrypt.crypt_gensalt("bcrypt_x", 0, None, 0)


if __name__ == "__main__":
    unittest.main()
